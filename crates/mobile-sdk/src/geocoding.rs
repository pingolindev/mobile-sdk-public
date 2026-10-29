// Copyright (c) 2026 Pingolin LLC
//
// This file is part of Pingolin Mobile SDK.
//
// Pingolin Mobile SDK is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Pingolin Mobile SDK is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Pingolin Mobile SDK. If not, see <https://www.gnu.org/licenses/>.

//! Offline geocoding using local SQLite databases
//!
//! Provides forward geocoding (address -> coordinates) and reverse geocoding
//! (coordinates -> address). Every query runs locally on-device for privacy.
//!
//! The data is small geohash tiles auto-downloaded on demand from a CDN, plus
//! a city-name index that resolves a search to the right tile.
//! `purge_retired_region_files` reclaims the whole-region database files that
//! older versions downloaded.

use rusqlite::{Connection, OpenFlags};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::MobileError;

// ============================================================================
// Geohash encoding for tile-based geocoding
// ============================================================================

/// Base32 alphabet used by geohash (excludes a, i, l, o to avoid confusion)
const GEOHASH_ALPHABET: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Encode latitude/longitude to a geohash string.
fn encode_geohash(lat: f64, lng: f64, precision: usize) -> String {
    let mut lat_range = (-90.0_f64, 90.0_f64);
    let mut lng_range = (-180.0_f64, 180.0_f64);
    let mut geohash = Vec::with_capacity(precision);
    let mut bits = 0u8;
    let mut bit_count = 0;
    let mut even = true;

    while geohash.len() < precision {
        if even {
            let mid = (lng_range.0 + lng_range.1) / 2.0;
            if lng >= mid {
                bits = (bits << 1) | 1;
                lng_range = (mid, lng_range.1);
            } else {
                bits <<= 1;
                lng_range = (lng_range.0, mid);
            }
        } else {
            let mid = (lat_range.0 + lat_range.1) / 2.0;
            if lat >= mid {
                bits = (bits << 1) | 1;
                lat_range = (mid, lat_range.1);
            } else {
                bits <<= 1;
                lat_range = (lat_range.0, mid);
            }
        }

        even = !even;
        bit_count += 1;

        if bit_count == 5 {
            geohash.push(GEOHASH_ALPHABET[bits as usize]);
            bits = 0;
            bit_count = 0;
        }
    }

    String::from_utf8(geohash).unwrap_or_default()
}

/// A geocoding result from a local query
#[derive(Debug, Clone, uniffi::Record)]
pub struct GeocodingResult {
    /// Single-line display text: address rows hold the street line ("900 East
    /// 11th Street"), POI rows hold name + locality ("The White Horse, Austin,
    /// TX"). This is the wire format for callers that render one line; prefer
    /// the structured fields below for a two-line layout.
    pub text: String,
    /// Latitude
    pub lat: f64,
    /// Longitude
    pub lng: f64,
    /// Result type: "address" or "poi"
    pub result_type: String,
    /// Ranking score; higher sorts first. Address rows stay within 0.0-1.0,
    /// POI rows are deliberately boosted above them (see `build_poi_row`).
    pub confidence: f64,
    /// POI name only (not present on address rows). Lets the UI render
    /// "The White Horse" as primary + "Austin, TX" as secondary
    /// without splitting `text` on commas.
    pub name: Option<String>,
    /// Locality fields, populated when the underlying tile schema carries
    /// them. Same shape the web client returns, so a client can render
    /// two-line results (street/POI primary, "City, State" secondary).
    pub city: Option<String>,
    pub state: Option<String>,
    pub postcode: Option<String>,
    pub country: Option<String>,
    /// Street line for POI rows ("1500 McHenry Avenue").
    ///
    /// Preferred source is the POI's OWN housenumber/street, which newer tile
    /// generations carry on the `pois` table for Overture-sourced rows.
    /// Anything without one — OSM-sourced rows, and every row from an older
    /// tile — falls back to the nearest address in the same cell, which is an
    /// approximation: the venue's real house number may differ.
    ///
    /// None on address rows (their `text` already is the street) and when
    /// neither source has anything. Lets the UI show a POI's address to
    /// disambiguate same-named places (e.g. multiple "Togo's").
    pub address: Option<String>,
}




// ============================================================================
// Query normalization (ordinal + street-type OR-expansion)
// ============================================================================
//
// Address data is indexed with NUMERIC ordinals ("6th Street") and a mix of
// full / abbreviated street types. A user who types "sixth street" or
// "6th st" should still match. We OR-expand each query token to its known
// equivalents so the search matches whichever form the data happens to use,
// without rewriting the query (which would break POIs like "Second Cup").

/// (spelled-out ordinal, numeric ordinal) pairs for single-token ordinals.
/// Covers 1–20 plus the round tens through 100 — the forms that stay a single
/// token in both search paths (FTS unicode61 and the tile LIKE tokenizer both
/// split on '-', so compound spelled-out ordinals like "twenty-third" wouldn't
/// survive as one token anyway; those are nearly always typed numerically).
const ORDINAL_PAIRS: &[(&str, &str)] = &[
    ("first", "1st"),
    ("second", "2nd"),
    ("third", "3rd"),
    ("fourth", "4th"),
    ("fifth", "5th"),
    ("sixth", "6th"),
    ("seventh", "7th"),
    ("eighth", "8th"),
    ("ninth", "9th"),
    ("tenth", "10th"),
    ("eleventh", "11th"),
    ("twelfth", "12th"),
    ("thirteenth", "13th"),
    ("fourteenth", "14th"),
    ("fifteenth", "15th"),
    ("sixteenth", "16th"),
    ("seventeenth", "17th"),
    ("eighteenth", "18th"),
    ("nineteenth", "19th"),
    ("twentieth", "20th"),
    ("thirtieth", "30th"),
    ("fortieth", "40th"),
    ("fiftieth", "50th"),
    ("sixtieth", "60th"),
    ("seventieth", "70th"),
    ("eightieth", "80th"),
    ("ninetieth", "90th"),
    ("hundredth", "100th"),
];

/// (full street type, abbreviation) pairs. Bidirectional so "6th st" finds
/// "6th Street" and vice-versa.
const STREET_TYPE_PAIRS: &[(&str, &str)] = &[
    ("street", "st"),
    ("avenue", "ave"),
    ("boulevard", "blvd"),
    ("road", "rd"),
    ("drive", "dr"),
    ("lane", "ln"),
    ("court", "ct"),
    ("place", "pl"),
    ("terrace", "ter"),
    ("parkway", "pkwy"),
    ("highway", "hwy"),
    ("circle", "cir"),
    ("square", "sq"),
];

/// All equivalent forms of a single lowercased token, always including the
/// token itself first. A token is at most one of {ordinal, street-type}, so
/// the result is 1 or 2 entries.
fn token_equivalents(token: &str) -> Vec<String> {
    let mut out = vec![token.to_string()];
    for &(word, num) in ORDINAL_PAIRS {
        if token == word {
            out.push(num.to_string());
        } else if token == num {
            out.push(word.to_string());
        }
    }
    for &(full, abbr) in STREET_TYPE_PAIRS {
        if token == full {
            out.push(abbr.to_string());
        } else if token == abbr {
            out.push(full.to_string());
        }
    }
    out
}

/// True for a numeric ordinal token ("6th", "1st", "21st") whose bare
/// `%substring%` match would be noisy — "6th" is a substring of "16th",
/// "26th", "106th". Such tokens get word-boundary LIKE patterns instead so a
/// search for 6th Street doesn't also pull 16th/26th. Spelled-out ordinals
/// ("sixth") aren't substrings of larger ordinals, so they don't need this.
fn needs_word_boundary(token: &str) -> bool {
    let suffix_len = if token.ends_with("st")
        || token.ends_with("nd")
        || token.ends_with("rd")
        || token.ends_with("th")
    {
        2
    } else {
        return false;
    };
    let digits = &token[..token.len() - suffix_len];
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}


/// Column expression for word-boundary matching: the stored text with hyphens
/// folded to spaces.
///
/// Word boundaries are matched with space-delimited LIKE patterns (`% n %`),
/// but plenty of names separate their words with hyphens instead. Without the
/// fold, "in n out" finds nothing: the indexed "in-n-out burger" has no SPACE
/// around the `n` — while typing "in-n-out" does match, since that stays one
/// token and matches as a substring. Folding the separator at match time
/// leaves the stored index alone, so tiles already on a device match too.
fn wb_col(col: &str) -> String {
    format!("REPLACE({}, '-', ' ')", col)
}

/// Delete leftover whole-region databases that older versions downloaded.
///
/// Regions were written FLAT into the geocoding root as `{region_id}.sqlite`
/// (mean 2.25 GB, `us-ca` 4.5 GB). Nothing else in the SDK reclaims that
/// space on a device that used the feature.
///
/// Deliberately narrow so it can never eat live data. It looks only at files
/// directly in the root (tiles live in a `tiles/` subdirectory and are named
/// `tile_*.sqlite`), and only at names shaped like a region id — two letters,
/// optionally `-` plus more, e.g. "de", "gb", "us-ca".
fn purge_retired_region_files(storage_path: &str) {
    fn looks_like_region_id(stem: &str) -> bool {
        let (head, tail) = match stem.split_once('-') {
            Some((h, t)) => (h, Some(t)),
            None => (stem, None),
        };
        if head.len() != 2 || !head.chars().all(|c| c.is_ascii_lowercase()) {
            return false;
        }
        match tail {
            None => true,
            Some(t) => {
                !t.is_empty() && t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            }
        }
    }

    let dir = Path::new(storage_path);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut freed: u64 = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let stem = match name.strip_suffix(".sqlite") {
            Some(s) => s,
            None => match name.strip_suffix(".sqlite.zst") {
                Some(s) => s,
                None => continue,
            },
        };
        if name.starts_with("tile_") || !looks_like_region_id(stem) {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if std::fs::remove_file(&path).is_ok() {
            freed += size;
        }
    }
    if freed > 0 {
        tracing::info!(
            "reclaimed {} MB from retired region databases",
            freed / 1_000_000
        );
    }
}




/// Owns the geocoding storage root.
///
/// Clients need a handle on the storage path; constructing it also triggers
/// the one-time reclaim of leftover region databases (see
/// `purge_retired_region_files`).
#[derive(uniffi::Object)]
pub struct GeocodingDownloader {
    storage_path: String,
}

#[uniffi::export]
impl GeocodingDownloader {
    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Self {
        // Best-effort and idempotent — after the first run it is a directory
        // scan. See `purge_retired_region_files`.
        purge_retired_region_files(&storage_path);
        Self { storage_path }
    }


    pub fn get_storage_path(&self) -> String {
        self.storage_path.clone()
    }






}

// ============================================================================
// Tile-based geocoding (auto-download on demand)
// ============================================================================

/// Slim manifest format (v3.0): the precision plus the sorted list of tile
/// IDs that exist on the CDN, and nothing else. It carries no per-tile
/// filename or size — the URL is always `tiles/<tile_id>.sqlite.zst` so the
/// client derives it, and the size comes from HTTP Content-Length on the
/// actual GET. That is ~14 MB smaller over the wire than listing them.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ManifestV3 {
    pub version: String,
    #[serde(default)]
    pub updated_at: String,
    pub precision: u32,
    pub tiles: Vec<String>,
    // v4 additions (absent in v3 → default empty). The `pois` family is the
    // Overture-enriched POI tiles; `pois_version` is its per-family cache key.
    // (v4 also carries `tiles_version`; address-tile invalidation keys off
    // `updated_at`, so it is not read here.)
    #[serde(default)]
    pub pois: Vec<String>,
    #[serde(default)]
    pub pois_version: String,
}

/// In-memory tile manifest. Owns a HashSet for O(1) tile-existence
/// checks rather than a Vec scan. Cache invalidation rides on the
/// top-level `updated_at` field — see `ensure_tile_loaded`.
#[derive(Debug, Clone)]
pub struct TileManifest {
    // Manifest schema version; retained for diagnostics. Cache invalidation uses
    // `updated_at`, not this, so it isn't read.
    #[allow(dead_code)]
    pub version: String,
    pub updated_at: String,
    pub precision: u32,
    pub tiles: std::collections::HashSet<String>,
    /// Enriched POI tile ids (the `pois/` family). Empty under a v3 manifest.
    pub pois: std::collections::HashSet<String>,
    /// Per-family cache key for `pois/` — a POI refresh bumps only this, so
    /// cached address tiles survive (see `ensure_pois_tile_loaded`).
    pub pois_version: String,
}

// ============================================================================
// On-disk manifest cache
// ============================================================================
//
// `fetch_manifest` runs on every app launch (iOS `GeocodingService.bootstrap`,
// Android `MainViewModel.initialize`), and the manifest is 3.4 MB of JSON —
// 1.15 MB over the wire with gzip. It changes a few times a year and the CDN
// already says how long it may be reused (`cache-control: max-age=86400`) and
// how to revalidate it (`etag`, `last-modified`); without a cache the SDK
// would ignore all three and download it whole every time. The cache below
// keeps the last body and its validators beside the tiles: a launch inside
// max-age touches no network, a later one asks "changed?" and usually gets an
// empty 304, and an offline launch still has a manifest.

/// The cached manifest body, verbatim as the CDN served it.
const MANIFEST_CACHE_BODY: &str = "manifest-cache.json";
/// Validators and freshness for `MANIFEST_CACHE_BODY`.
const MANIFEST_CACHE_META: &str = "manifest-cache.meta.json";
/// Reuse window when the CDN names no `max-age`. Revalidation keeps a stale
/// copy cheap, so this only decides how often a launch asks.
const MANIFEST_DEFAULT_FRESH_SECS: u64 = 3_600;
/// Upper bound on the reuse window, whatever the CDN says: a new manifest (and
/// with it new or refreshed tiles) reaches every device within a day.
const MANIFEST_MAX_FRESH_SECS: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct ManifestCacheMeta {
    /// The file the body came from (`manifest-v4.json` / `manifest-v3.json`).
    /// Validators are only ever sent to that same URL.
    source: String,
    etag: Option<String>,
    last_modified: Option<String>,
    /// Wall-clock ms when the body was last confirmed current: fetched, or
    /// revalidated with a 304.
    confirmed_at_ms: i64,
    /// How long after `confirmed_at_ms` the body may be used without asking.
    fresh_for_secs: u64,
}

impl ManifestCacheMeta {
    fn is_fresh(&self, now_ms: i64) -> bool {
        let age_ms = now_ms.saturating_sub(self.confirmed_at_ms);
        // A clock that stepped backwards reads as "not fresh": the cost is one
        // conditional request, not a wrong manifest.
        age_ms >= 0 && (age_ms as u64) < self.fresh_for_secs.saturating_mul(1_000)
    }
}

/// Seconds a manifest response may be reused without revalidation: its
/// `max-age`, less the `Age` it already spent in a shared cache, capped at
/// [`MANIFEST_MAX_FRESH_SECS`]. `no-cache`/`no-store` mean "ask every time".
fn manifest_fresh_secs(cache_control: Option<&str>, age: Option<&str>) -> u64 {
    let cc = cache_control.unwrap_or("").to_ascii_lowercase();
    let directives: Vec<&str> = cc.split(',').map(str::trim).collect();
    if directives.iter().any(|d| *d == "no-cache" || *d == "no-store") {
        return 0;
    }
    let max_age = directives
        .iter()
        .find_map(|d| d.strip_prefix("max-age=")?.trim_matches('"').parse::<u64>().ok());
    let Some(max_age) = max_age else {
        return MANIFEST_DEFAULT_FRESH_SECS;
    };
    let spent = age.and_then(|a| a.trim().parse::<u64>().ok()).unwrap_or(0);
    max_age.saturating_sub(spent).min(MANIFEST_MAX_FRESH_SECS)
}

/// The cached manifest, parsed. `None` when either file is missing or does not
/// parse — a damaged cache is simply no cache.
fn load_cached_manifest(dir: &Path) -> Option<(ManifestCacheMeta, ManifestV3)> {
    let meta: ManifestCacheMeta =
        serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_CACHE_META)).ok()?).ok()?;
    let manifest: ManifestV3 =
        serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_CACHE_BODY)).ok()?).ok()?;
    Some((meta, manifest))
}

/// Persist the cache. The body (when there is a new one) is written before
/// the meta, each atomically, so an interrupted write can leave a NEWER body
/// behind old validators — which the next revalidation corrects — but never
/// new validators on an old body.
fn store_cached_manifest(
    dir: &Path,
    meta: &ManifestCacheMeta,
    body: Option<&[u8]>,
) -> std::io::Result<()> {
    fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    }
    std::fs::create_dir_all(dir)?;
    if let Some(body) = body {
        write_atomically(&dir.join(MANIFEST_CACHE_BODY), body)?;
    }
    let meta_bytes = serde_json::to_vec(meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_atomically(&dir.join(MANIFEST_CACHE_META), &meta_bytes)
}

/// One manifest request's outcome.
enum ManifestFetch {
    /// 304 to a conditional request: the cached body is current.
    NotModified { fresh_for_secs: u64 },
    /// A full body, with the validators to revalidate it next time.
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
        fresh_for_secs: u64,
    },
}

/// GET one manifest file, conditionally when `validators` (etag,
/// last-modified) are given.
async fn fetch_manifest_file(
    client: &reqwest::Client,
    url: &str,
    validators: Option<(Option<&str>, Option<&str>)>,
) -> Result<ManifestFetch, MobileError> {
    use reqwest::header::{AGE, CACHE_CONTROL, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};

    let mut request = client.get(url);
    if let Some((etag, last_modified)) = validators {
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
    }
    let resp = request
        .send()
        .await
        .map_err(|e| MobileError::NetworkError(format!("{:?}", e)))?;

    let header = |name: reqwest::header::HeaderName| {
        resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
    };
    let fresh_for_secs = manifest_fresh_secs(header(CACHE_CONTROL).as_deref(), header(AGE).as_deref());

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        if validators.is_none() {
            return Err(MobileError::NetworkError(
                "HTTP 304 to an unconditional manifest request".to_string(),
            ));
        }
        return Ok(ManifestFetch::NotModified { fresh_for_secs });
    }
    if !resp.status().is_success() {
        return Err(MobileError::NetworkError(format!("HTTP {}", resp.status())));
    }
    let etag = header(ETAG);
    let last_modified = header(LAST_MODIFIED);
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| MobileError::NetworkError(e.to_string()))?
        .to_vec();
    Ok(ManifestFetch::Body { bytes, etag, last_modified, fresh_for_secs })
}

/// Tile-based geocoder that auto-downloads tiles on demand from CDN.
///
/// Tiles are small (~40km x 20km) and cached locally, so geocoding costs no
/// large up-front download.
#[derive(uniffi::Object)]
pub struct TileGeocoder {
    base_url: String,
    storage_path: String,
    manifest: Arc<Mutex<Option<TileManifest>>>,
    /// Loaded tile DBs. Each entry carries a monotonic `last_used`
    /// tick used by the LRU cap below — when the map exceeds
    /// `MAX_LOADED_TILES`, the entry with the smallest tick gets
    /// evicted. Without the cap, long sessions across many cities
    /// would accumulate dozens of decompressed SQLite handles
    /// (~3 MB each) until the process gets memory-killed.
    loaded_tiles: Arc<Mutex<HashMap<String, (Connection, u64)>>>,
    /// Loaded POI tile DBs (the enriched `pois/` family — Overture+OSM,
    /// deduped). Parallel to `loaded_tiles`, keyed by the same tile id, same
    /// LRU-tick eviction. Forward search reads POIs from here where present.
    loaded_pois: Arc<Mutex<HashMap<String, (Connection, u64)>>>,
    /// Monotonic counter that stamps each tile-access as it happens.
    /// Sub-second clock resolution would let two ops collide; this
    /// is just a tick.
    tile_lru_tick: Arc<Mutex<u64>>,
    /// Shared HTTP client — reuses connection pool and TLS sessions across requests
    client: reqwest::Client,
}

/// SQL `ORDER BY` that sorts rows by distance from a focus point, or empty
/// when there is none.
///
/// Longitude is scaled by cos(latitude) so a degree of longitude is weighted
/// the way it actually measures — without it the ordering skews east-west the
/// further you are from the equator. Coordinates are formatted rather than
/// bound because they are f64 we produced, and threading two more binds
/// through every caller's parameter list is where an off-by-one would live.
fn order_by_distance(focus: Option<(f64, f64)>) -> String {
    match focus {
        None => String::new(),
        Some((lat, lng)) => {
            let coslat = lat.to_radians().cos().abs().max(0.01);
            format!(
                " ORDER BY ((lat - {lat:.6}) * (lat - {lat:.6}) \
                   + ((lng - {lng:.6}) * {coslat:.6}) * ((lng - {lng:.6}) * {coslat:.6}))"
            )
        }
    }
}

/// Run one POI SELECT shape and push its rows. Returns false when the tile's
/// schema does not support that shape, so the caller can try an older one.
///
/// Every variant must expose the same nine columns in the same order; the
/// older ones pad with NULL literals.
fn run_poi_query(
    conn: &Connection,
    sql: &str,
    binds: &[&dyn rusqlite::ToSql],
    results: &mut Vec<GeocodingResult>,
    seen: &mut std::collections::HashSet<String>,
) -> bool {
    let Ok(mut stmt) = conn.prepare(sql) else { return false };
    let Ok(rows) = stmt.query_map(binds, |row| {
        let hn: Option<String> = row.get::<_, Option<String>>(6).unwrap_or(None);
        let st: Option<String> = row.get::<_, Option<String>>(7).unwrap_or(None);
        Ok(build_poi_row(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            join_street(hn, st),
            row.get::<_, Option<String>>(8).unwrap_or(None),
        ))
    }) else { return false };
    for row in rows.flatten() {
        let key = row_dedup_key(&row);
        if seen.insert(key) {
            results.push(row);
        }
    }
    true
}

/// Run one POI lookup against a combined tile or a `pois/` tile and push its
/// deduped rows. Shared by `forward_near`'s combined-tile pass and its
/// enriched `pois/` pass.
fn query_pois_table(
    conn: &Connection,
    poi_where: &str,
    poi_bind_refs: &[&dyn rusqlite::ToSql],
    results: &mut Vec<GeocodingResult>,
    seen: &mut std::collections::HashSet<String>,
    focus: Option<(f64, f64)>,
) {
    // Newer tiles carry the POI's own housenumber/street for Overture-sourced
    // rows. A row that comes back without one (OSM-sourced, or anything from
    // the oldest generation) leaves `address` as None, which is what
    // forward_near()'s post-pass keys off to fill it from the cell's nearest
    // address.
    let order = order_by_distance(focus);
    // THREE tile generations are in the wild and all must work. They differ
    // only in which POI columns exist (numbered as in `tile_generation_tests`):
    //   generation 3: housenumber/street + postcode  (widest, tried first)
    //   generation 2: housenumber/street, no postcode
    //   generation 1: neither
    //
    // Naming a column a tile lacks makes `prepare` fail, and a failed prepare
    // here is swallowed -- which silently drops EVERY POI for that tile. So
    // try the widest shape and step down. The NULL literals keep the column
    // positions identical so one mapper serves all three.
    let poi_sql_full = format!(
        "SELECT name, lat, lng, city, state, country, housenumber, street, postcode \
         FROM pois WHERE {}{} LIMIT ?",
        poi_where, order
    );
    let poi_sql_mid = format!(
        "SELECT name, lat, lng, city, state, country, housenumber, street, NULL \
         FROM pois WHERE {}{} LIMIT ?",
        poi_where, order
    );
    let loaded = if let Ok(mut stmt) = conn.prepare(&poi_sql_full) {
        if let Ok(rows) = stmt.query_map(poi_bind_refs, |row| {
            let hn: Option<String> = row.get::<_, Option<String>>(6).unwrap_or(None);
            let st: Option<String> = row.get::<_, Option<String>>(7).unwrap_or(None);
            Ok(build_poi_row(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, Option<String>>(3).unwrap_or(None),
                row.get::<_, Option<String>>(4).unwrap_or(None),
                row.get::<_, Option<String>>(5).unwrap_or(None),
                join_street(hn, st),
                row.get::<_, Option<String>>(8).unwrap_or(None),
            ))
        }) {
            for row in rows.flatten() {
                let key = row_dedup_key(&row);
                if seen.insert(key) {
                    results.push(row);
                }
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    if loaded {
        return;
    }
    // Generation 2: has the street columns but no postcode.
    if run_poi_query(conn, &poi_sql_mid, poi_bind_refs, results, seen) {
        return;
    }

    // Generation 1: no street columns at all. A tile may also lack the `pois`
    // table or the city/state columns entirely; that prepare error is
    // swallowed too and POIs are skipped for the DB.
    let poi_sql = format!(
        "SELECT name, lat, lng, city, state, country FROM pois WHERE {}{} LIMIT ?",
        poi_where, order
    );
    if let Ok(mut stmt) = conn.prepare(&poi_sql) {
        if let Ok(rows) = stmt.query_map(poi_bind_refs, |row| {
            Ok(build_poi_row(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, Option<String>>(3).unwrap_or(None),
                row.get::<_, Option<String>>(4).unwrap_or(None),
                row.get::<_, Option<String>>(5).unwrap_or(None),
                None,
                None,
            ))
        }) {
            for row in rows.flatten() {
                let key = row_dedup_key(&row);
                if seen.insert(key) {
                    results.push(row);
                }
            }
        }
    }
}

/// Zero-result fallback for POI names in one tile.
///
/// Same contract as the city version: only reached when the normal query
/// found nothing, so it can never displace a real match. A tile holds ~10k
/// POIs, so a bounded OSA pass over the names costs microseconds and needs no
/// index — which is the whole reason this is worth doing without a tile
/// rebuild.
fn fuzzy_pois_in_tile(
    conn: &Connection,
    query: &str,
    limit: u32,
    results: &mut Vec<GeocodingResult>,
    seen: &mut std::collections::HashSet<String>,
    focus: Option<(f64, f64)>,
) {
    let q = query.trim().to_lowercase();
    let budget = typo_budget(q.chars().count());
    if budget == 0 {
        return;
    }
    let mut stmt = match conn.prepare(
        "SELECT id, name FROM pois WHERE name IS NOT NULL AND name <> ''",
    ) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = match stmt.query_map([], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    }) {
        Ok(it) => it,
        Err(_) => return,
    };
    // Compare against the SAME normalisation the exact path uses -- apostrophes
    // deleted, not split -- so "togos" is one edit from "Togo's", not three.
    let mut hits: Vec<(usize, i64)> = Vec::new();
    for row in rows.flatten() {
        let (id, name) = row;
        let norm = name.to_lowercase().replace('\'', "").replace('\u{2019}', "");
        if let Some(d) = osa_distance_within(&q, &norm, budget) {
            hits.push((d, id));
        }
    }
    if hits.is_empty() {
        return;
    }
    hits.sort_by_key(|(d, _)| *d);
    hits.truncate(limit as usize);
    let ids: Vec<String> = hits.iter().map(|(_, id)| id.to_string()).collect();
    // Order by distance, not by edit distance alone. Without this the fallback
    // returns an arbitrary slice of equally-close spellings and the caller's
    // viewport clamp can delete all of them, leaving a far-away match while a
    // nearby branch goes unmentioned.
    let sql = format!(
        "SELECT name, lat, lng, city, state, country FROM pois WHERE id IN ({}){}",
        ids.join(","),
        order_by_distance(focus)
    );
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return,
    };
    let rows = match stmt.query_map([], |row| {
        Ok(build_poi_row(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            None,
            None,
        ))
    }) {
        Ok(it) => it,
        Err(_) => return,
    };
    {
        for mut r in rows.flatten() {
            // Rank below anything exact. Nothing exact exists here, but
            // these rows are merged with server rows upstream, which may.
            r.confidence = 0.4;
            if seen.insert(row_dedup_key(&r)) {
                results.push(r);
            }
        }
    }
}

/// Bounded optimal-string-alignment distance, abandoned once it exceeds `max`.
///
/// OSA rather than plain Levenshtein because a transposition is one of the most
/// common typos and plain Levenshtein charges two for it: "modseto" -> "modesto"
/// scores 2, which would need a budget loose enough to also match unrelated
/// words. OSA scores it 1.
///
/// Returns None as soon as the distance is known to exceed `max`, so the common
/// case (two unrelated words) costs a length check and one row of the matrix.
fn osa_distance_within(a: &str, b: &str, max: usize) -> Option<usize> {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let (n, m) = (a.len(), b.len());
    if n.abs_diff(m) > max {
        return None;
    }
    if n == 0 {
        return (m <= max).then_some(m);
    }
    if m == 0 {
        return (n <= max).then_some(n);
    }
    let mut prev2: Vec<usize> = vec![0; m + 1];
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur: Vec<usize> = vec![0; m + 1];
    for i in 1..=n {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            // adjacent transposition
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(prev2[j - 2] + 1);
            }
            cur[j] = v;
            row_min = row_min.min(v);
        }
        // Every remaining path goes through this row; if all of it already
        // exceeds the budget the answer cannot come back under it.
        if row_min > max {
            return None;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    let d = prev[m];
    (d <= max).then_some(d)
}

/// How many edits to forgive for a query of this length.
///
/// Zero below four characters: at that length almost everything is within one
/// edit of something ("mart" -> "cart", "mars", "part"), and a fallback that
/// fires on short input would answer noise instead of nothing.
fn typo_budget(len: usize) -> usize {
    match len {
        0..=3 => 0,
        4..=6 => 1,
        _ => 2,
    }
}

/// Shortest token that still gets a trailing `*` in the cities MATCH.
///
/// Four, because that is where [`typo_budget`] already draws the same line and
/// for the same reason: below it, almost everything is close to something.
const CITY_PREFIX_MIN_LEN: usize = 4;

/// One FTS5 term for one word of a city query.
///
/// A prefix wildcard is what makes typeahead work ("san fran" → San Francisco),
/// but on a SHORT token it stops discriminating. The cities FTS indexes
/// `alt_names`, which is full of transliterations and exonyms, so a three-letter
/// prefix reaches deep into names the user never sees — and the caller then sorts
/// by population, which guarantees the biggest city carrying such an alt name wins.
///
/// Examples from the tier-1 index:
///
/// | query | as `tok*` | as `"tok"` |
/// |-------|-----------|------------|
/// | `hot` | **Hohhot**, pop 2,350,000 — via the alt name "hoter"; neither `name` nor `ascii_name` contains "hot" | Ulanhot |
/// | `ely` | Zielona Góra | **Ely** |
/// | `rye` | Lleida | **Rye** |
///
/// "hot" is a realistic case: the caller's smart-fallback peels the
/// second-to-last token of "pinks hot dogs" as a city hint, so a prefix match
/// resolves Hohhot, downloads its tiles and heads the results "In Hohhot, 20".
///
/// Tokens of four characters or more keep the wildcard, so typeahead is untouched.
///
/// EVERY TERM IS QUOTED, so no user text can form FTS5 syntax: not `AND`, `OR`,
/// `NOT` or `NEAR`, not a column filter, not a stray `-` or `.`. `word` holds
/// letters, digits and combining accents only (`city_query_words`), never a `"`,
/// so the quotes need no escaping. A prefix term is the quoted word with `*`.
///
/// A word ending in "s" may be a possessive typed without its apostrophe:
/// "Johns" for "John's", which unicode61 indexes as john + s. It also matches as
/// that pair.
fn city_match_term(word: &str) -> String {
    if word.chars().count() < CITY_PREFIX_MIN_LEN {
        // Exact term.
        return format!("\"{}\"", word);
    }
    let prefix = format!("\"{}\"*", word);
    match word.strip_suffix('s') {
        Some(stem) if !stem.is_empty() => format!("({} OR \"{} s\")", prefix, stem),
        _ => prefix,
    }
}

/// The words of a city query: letters, digits and combining accents only,
/// lower-cased.
///
/// Everything else becomes a space first. An apostrophe, a period, a comma or a
/// hyphen sits INSIDE the names people type ("St. John's", "Coeur d'Alene",
/// "Winston-Salem", "Austin, TX"), and unicode61 indexes those names as separate
/// tokens (john + s, winston + salem). Dropped, the apostrophe would glue
/// "John's" into "johns", a token nothing indexed starts with; kept, the
/// period, comma and hyphen would make bare terms ("st.*", "austin,*",
/// "winston-salem*") that FTS5 rejects as a syntax error, and the whole town
/// search would come back empty.
///
/// A combining accent stays in its word: a decomposed "Zürich" is z u U+0308 r
/// i c h, and unicode61 folds the accent away INSIDE the token, so as a space it
/// would split the word into "zu" + "rich" and find nothing. A word with no
/// letter or digit (a stray accent) is dropped: as a term it holds no token, and
/// an empty term matches no row.
fn city_query_words(query: &str) -> Vec<String> {
    query
        .chars()
        .map(|c| if c.is_alphanumeric() || is_combining_accent(c) { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .map(str::to_lowercase)
        .collect()
}

/// The Combining Diacritical Marks block, which holds every accent unicode61
/// keeps inside a token.
fn is_combining_accent(c: char) -> bool {
    ('\u{0300}'..='\u{036F}').contains(&c)
}

/// The MATCH expression for a city query, or `None` when it holds no word. The
/// terms are joined with an explicit `AND`: FTS5 does not take a bare phrase
/// next to a parenthesised group, which `city_match_term` can produce.
fn city_match_expr(query: &str) -> Option<String> {
    let words = city_query_words(query);
    if words.is_empty() {
        return None;
    }
    Some(words.iter().map(|w| city_match_term(w)).collect::<Vec<_>>().join(" AND "))
}

/// Dedup key for a result row: its display text PLUS its position.
///
/// Keying on `text` alone collapses every branch of a chain within one city to
/// a single row, because `text` is "{name}, {city}, {state}" and is therefore
/// identical for all of them. The Modesto tile, for one, holds 36 "Starbucks",
/// and a text-keyed search returns exactly ONE — widening the scope still
/// returns one per city. The street that would tell them apart is computed
/// and then thrown away with the row.
///
/// Address rows have the same exposure for the same reason: their `text` is
/// the street line alone, so "100 Main St" in two different towns collides.
///
/// Coordinates are what actually distinguish two rows, so they belong in the
/// key. Rounded to 4 decimal places (~11 m) so that the case the dedup exists
/// for — the SAME place reached through two sources, e.g. two overlapping
/// tiles, or a combined tile and the enriched `pois/` family — still
/// collapses, since both carry the same coordinates from the same upstream
/// data.
fn row_dedup_key(r: &GeocodingResult) -> String {
    format!("{}|{:.4}|{:.4}", r.text.trim().to_lowercase(), r.lat, r.lng)
}

/// "709" + "N La Brea Ave" -> "709 N La Brea Ave".
///
/// A blank street discards the number with it: a bare house number is not an
/// address line, and the build never emits one (its splitter only yields a
/// number when a street follows it).
fn join_street(housenumber: Option<String>, street: Option<String>) -> Option<String> {
    let st = street.filter(|s| !s.trim().is_empty())?;
    match housenumber.filter(|h| !h.trim().is_empty()) {
        Some(h) => Some(format!("{} {}", h.trim(), st.trim())),
        None => Some(st.trim().to_string()),
    }
}

/// Shared row builder for both POI schemas, so the two paths can't drift.
#[allow(clippy::too_many_arguments)]
fn build_poi_row(
    name: String,
    lat: f64,
    lng: f64,
    city: Option<String>,
    state: Option<String>,
    country: Option<String>,
    address: Option<String>,
    postcode: Option<String>,
) -> GeocodingResult {
    // Single-line `text` is "Name, City, State" for callers that render it
    // directly — see `GeocodingResult::text`.
    let locality = match (city.as_deref(), state.as_deref()) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => format!(", {}, {}", c, s),
        (Some(c), _) if !c.is_empty() => format!(", {}", c),
        _ => String::new(),
    };
    GeocodingResult {
        text: format!("{}{}", name, locality),
        lat,
        lng,
        result_type: "poi".to_string(),
        // Boost POIs above address matches with the same query.
        confidence: 1.5,
        name: Some(name),
        city: city.filter(|s| !s.is_empty()),
        state: state.filter(|s| !s.is_empty()),
        // Older tiles have no postcode column; those rows pass None.
        postcode: postcode.filter(|s| !s.is_empty()),
        country: country.filter(|s| !s.is_empty()),
        // None here means "not known from the tile" — forward()'s post-pass
        // then derives it from the cell's combined-tile addresses.
        address,
    }
}

/// Nearest address street line to (lat,lng), from a combined tile's `addresses`
/// table. Used to attach a street to POI rows that carry none of their own, so
/// the UI can show a POI's address + disambiguate same-named places. ~165 m cap
/// so a POI in a mapped area gets its building's street without grabbing a far
/// one in sparse areas (None then → the UI hides the line). Returns `text`.
fn nearest_address_text(conn: &Connection, lat: f64, lng: f64) -> Option<String> {
    let delta = 0.0015_f64; // ~165 m
    conn.query_row(
        "SELECT text FROM addresses \
         WHERE lat BETWEEN ?1 - ?3 AND ?1 + ?3 AND lng BETWEEN ?2 - ?3 AND ?2 + ?3 \
         ORDER BY ((lat - ?1) * (lat - ?1) + (lng - ?2) * (lng - ?2)) LIMIT 1",
        rusqlite::params![lat, lng, delta],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

// Private implementation methods (not exported via UniFFI)
impl TileGeocoder {
    /// Materialise a parsed manifest into the in-memory shape (HashSets for
    /// O(1) membership) and make it the current one.
    fn install_manifest(&self, parsed: ManifestV3) {
        let tile_set: std::collections::HashSet<String> = parsed.tiles.into_iter().collect();
        let poi_set: std::collections::HashSet<String> = parsed.pois.into_iter().collect();
        let manifest = TileManifest {
            version: parsed.version,
            updated_at: parsed.updated_at,
            precision: parsed.precision,
            tiles: tile_set,
            pois: poi_set,
            pois_version: parsed.pois_version,
        };
        tracing::info!(
            "Loaded tile manifest: {} address tiles, {} poi tiles, precision={}",
            manifest.tiles.len(),
            manifest.pois.len(),
            manifest.precision
        );

        *self.manifest.lock().unwrap_or_else(|e| e.into_inner()) = Some(manifest);
    }

    /// Find tile ID for coordinates using geohash
    fn find_tile_for_coords(&self, lat: f64, lng: f64) -> Option<String> {
        let manifest = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
        let manifest = manifest.as_ref()?;

        Self::resolve_tile_id(manifest, lat, lng)
    }

    /// The manifest's tile id covering (lat,lng), at whatever precision it is
    /// held at. `None` when no tile covers the point.
    ///
    /// The manifest is VARIABLE-PRECISION and all three cases are real:
    ///
    /// * base     - the ordinary case.
    /// * base + 1 - a DENSE cell the export subdivided. A precision-4 cell is
    ///   ~40x20 km and in a metro reached 746 MB raw, which no phone can
    ///   inflate; the pipeline re-exports any tile over 20 MB as its 32
    ///   children and deletes the parent, so the parent id is absent.
    /// * base - 1 - a SPARSE region collapsed into its parent. 64.8% of tiles
    ///   are exactly the 77,824-byte empty schema, so merging a rural parent's
    ///   children removes 31 redundant copies of that floor (-72.3% raw,
    ///   32 objects to 1).
    ///
    /// Most specific first. The cases are mutually exclusive in practice, so
    /// the order only affects how many lookups a miss costs.
    fn resolve_tile_id(manifest: &TileManifest, lat: f64, lng: f64) -> Option<String> {
        let base = manifest.precision as i64;
        for p in [base, base + 1, base - 1] {
            if p < 1 {
                continue;
            }
            let id = encode_geohash(lat, lng, p as usize);
            if manifest.tiles.contains(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Tile IDs for `(lat, lng)` plus its 8 geohash neighbors that exist
    /// in the manifest. Used by the smart-fallback address-search path:
    /// a city centroid often sits far from the user's actual street, so
    /// loading just the centroid tile leaves "900 East 11th Street in
    /// Austin" undiscoverable when 11th Street happens to fall in the
    /// neighbor tile. Mirrors the web client's centroid+neighbors
    /// fallback for when the per-city addr+POI shard isn't available.
    fn find_tile_and_neighbors_for_coords(&self, lat: f64, lng: f64) -> Vec<String> {
        let manifest_guard = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
        let Some(manifest) = manifest_guard.as_ref() else {
            return Vec::new();
        };
        let precision = manifest.precision as usize;

        // Geohash interleaves lng then lat per pair of bits. For total
        // bits = 5*precision, lng gets ceil(5p/2) and lat gets floor(5p/2).
        // Cell sizes follow from that: lat_cell = 180/2^lat_bits,
        // lng_cell = 360/2^lng_bits.
        let total_bits = (precision as u32) * 5;
        let lng_bits = (total_bits + 1) / 2;
        let lat_bits = total_bits / 2;
        let lat_cell = 180.0_f64 / (1u64 << lat_bits) as f64;
        let lng_cell = 360.0_f64 / (1u64 << lng_bits) as f64;

        let mut out: Vec<String> = Vec::with_capacity(9);
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for dlat in [-1i32, 0, 1] {
            for dlng in [-1i32, 0, 1] {
                let n_lat = (lat + dlat as f64 * lat_cell).clamp(-90.0, 90.0);
                let raw_lng = lng + dlng as f64 * lng_cell;
                let n_lng = if raw_lng > 180.0 {
                    raw_lng - 360.0
                } else if raw_lng < -180.0 {
                    raw_lng + 360.0
                } else {
                    raw_lng
                };
                // Same variable-precision lookup as the centre tile, so a
                // neighbour that was SPLIT (no entry at base precision, 32
                // children instead) or COLLAPSED (held by its parent) still
                // resolves. Trying base and base+1 only would silently drop
                // a collapsed neighbour from the fan-out.
                if let Some(id) = Self::resolve_tile_id(manifest, n_lat, n_lng) {
                    if seen.insert(id.clone()) {
                        out.push(id);
                    }
                }
            }
        }
        out
    }

    /// Ensure a tile is loaded, downloading if necessary.
    ///
    /// The on-disk copy is valid only while its `tile_<id>.meta` sidecar,
    /// written at download time, still matches the manifest's `updated_at`;
    /// anything else is stale and re-downloaded. Coarse — a pipeline rerun
    /// bumps that timestamp, so even unchanged tiles are refetched — but it
    /// keeps the manifest slim (no per-tile fingerprint over the wire).
    fn ensure_tile_loaded(&self, tile_id: &str, rt: &tokio::runtime::Runtime) -> Result<(), MobileError> {
        if self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner()).contains_key(tile_id) {
            // The address tile is resident, but its enriched POI tile may not
            // be — e.g. the address tile came from a cache written before the
            // pois/ family existed. Ensure the POI tile before returning, or
            // the enriched POIs never load.
            self.ensure_pois_best_effort(tile_id, rt);
            return Ok(());
        }

        let storage_dir = Path::new(&self.storage_path);
        let tile_path = storage_dir.join(format!("tile_{}.sqlite", tile_id));
        let meta_path = storage_dir.join(format!("tile_{}.meta", tile_id));

        if tile_path.exists() {
            let expected = {
                let manifest = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
                manifest.as_ref().map(|m| m.updated_at.clone())
            };
            let cached_version = std::fs::read_to_string(&meta_path)
                .ok()
                .map(|s| s.trim().to_string());
            match (&expected, &cached_version) {
                (Some(exp), Some(c)) if !exp.is_empty() && exp == c => {
                    self.load_tile_from_disk(tile_id, tile_path.to_str().unwrap_or_default())?;
                    self.ensure_pois_best_effort(tile_id, rt);
                    return Ok(());
                }
                _ => {
                    tracing::debug!(
                        "Tile {} cache invalid (manifest.updated_at={:?}, cached.updated_at={:?}), re-downloading",
                        tile_id, expected, cached_version
                    );
                    let _ = std::fs::remove_file(&tile_path);
                    let _ = std::fs::remove_file(&meta_path);
                }
            }
        }

        self.download_tile(tile_id, rt)?;
        self.load_tile_from_disk(tile_id, tile_path.to_str().unwrap_or_default())?;
        self.ensure_pois_best_effort(tile_id, rt);
        Ok(())
    }

    /// Download a tile from CDN
    fn download_tile(&self, tile_id: &str, rt: &tokio::runtime::Runtime) -> Result<(), MobileError> {
        // Extract URL before any async operations to avoid holding lock across await
        let url = {
            let manifest = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let manifest = manifest.as_ref().ok_or_else(|| {
                MobileError::StorageError("Tile manifest not loaded".to_string())
            })?;

            if !manifest.tiles.contains(tile_id) {
                return Err(MobileError::StorageError(format!("Unknown tile: {}", tile_id)));
            }

            // Tile URL is always `<base>/tiles/<tile_id>.sqlite.zst` —
            // no per-tile filename map needed.
            format!("{}/tiles/{}.sqlite.zst", self.base_url, tile_id)
        }; // Lock is released here

        tracing::debug!("Downloading tile {} from {}", tile_id, url);

        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            std::fs::create_dir_all(storage_dir)
                .map_err(|e| MobileError::StorageError(e.to_string()))?;
        }

        let client = &self.client;
        let mut last_err = None;
        let bytes = rt.block_on(async {
            for attempt in 1..=3 {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.bytes().await {
                            Ok(b) => return Ok(b),
                            Err(e) => {
                                tracing::debug!(
                                    "Tile {} attempt {}/3: body read failed: {:?}",
                                    tile_id, attempt, e
                                );
                                last_err = Some(format!("{:?}", e));
                            }
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::debug!(
                            "Tile {} attempt {}/3: HTTP {}",
                            tile_id, attempt, status
                        );
                        last_err = Some(format!("HTTP {}", status));
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Tile {} attempt {}/3: request failed: {:?}",
                            tile_id, attempt, e
                        );
                        last_err = Some(format!("{:?}", e));
                    }
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                }
            }
            Err(MobileError::NetworkError(
                last_err.unwrap_or_else(|| "unknown error".to_string()),
            ))
        })?;

        let decompressed = zstd::decode_all(bytes.as_ref())
            .map_err(|e| MobileError::StorageError(format!("Decompression failed: {}", e)))?;

        let tile_path = storage_dir.join(format!("tile_{}.sqlite", tile_id));
        std::fs::write(&tile_path, &decompressed)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;

        // Cache-validation sidecar: holds the manifest's `updated_at`
        // value at the time of download. `ensure_tile_loaded` and the
        // prewarm path compare it to the current manifest's value —
        // a mismatch flags the tile as stale and forces a re-download.
        let manifest_version = {
            let manifest = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            manifest.as_ref().map(|m| m.updated_at.clone()).unwrap_or_default()
        };
        let meta_path = storage_dir.join(format!("tile_{}.meta", tile_id));
        if let Err(e) = std::fs::write(&meta_path, &manifest_version) {
            tracing::debug!("Failed to write meta sidecar for tile {}: {}", tile_id, e);
        }

        tracing::debug!(
            "Downloaded tile {} ({} bytes compressed, {} bytes decompressed)",
            tile_id,
            bytes.len(),
            decompressed.len()
        );

        Ok(())
    }

    /// Soft cap on tile DB handles kept in memory. Each ~3 MB
    /// decompressed; a long cross-city session can otherwise grow
    /// unbounded. 30 covers ~90 MB worst case which both phones and
    /// browser workers can handle without GC pressure.
    const MAX_LOADED_TILES: usize = 30;

    /// Bump and return the next LRU tick.
    fn next_lru_tick(&self) -> u64 {
        let mut t = self.tile_lru_tick.lock().unwrap_or_else(|e| e.into_inner());
        *t = t.wrapping_add(1);
        *t
    }

    /// Evict tile DBs with the smallest last-used tick until the map
    /// is under [`Self::MAX_LOADED_TILES`]. Must be called with no
    /// outer lock on `loaded_tiles` held.
    fn evict_excess_tiles(&self) {
        let mut tiles = self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner());
        while tiles.len() > Self::MAX_LOADED_TILES {
            let oldest = tiles
                .iter()
                .min_by_key(|(_, (_, tick))| *tick)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                tiles.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Load a tile from disk into memory.
    fn load_tile_from_disk(&self, tile_id: &str, path: &str) -> Result<(), MobileError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;

        let tick = self.next_lru_tick();
        self.loaded_tiles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tile_id.to_string(), (conn, tick));
        // Drop the outer lock before evict (it locks too).
        self.evict_excess_tiles();

        tracing::debug!("Loaded tile {} from disk", tile_id);
        Ok(())
    }

    /// Shared download core: GET (3× retry) → zstd-decompress → write the
    /// sqlite file + a `.meta` sidecar holding `version` for cache validation.
    fn fetch_decompress_to(
        &self,
        url: &str,
        sqlite_path: &Path,
        meta_path: &Path,
        version: &str,
        label: &str,
        rt: &tokio::runtime::Runtime,
    ) -> Result<(), MobileError> {
        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            std::fs::create_dir_all(storage_dir)
                .map_err(|e| MobileError::StorageError(e.to_string()))?;
        }
        let client = &self.client;
        let mut last_err = None;
        let bytes = rt.block_on(async {
            for attempt in 1..=3 {
                match client.get(url).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                        Ok(b) => return Ok(b),
                        Err(e) => last_err = Some(format!("{:?}", e)),
                    },
                    Ok(resp) => last_err = Some(format!("HTTP {}", resp.status())),
                    Err(e) => last_err = Some(format!("{:?}", e)),
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                }
            }
            Err(MobileError::NetworkError(
                last_err.unwrap_or_else(|| "unknown error".to_string()),
            ))
        })?;
        let decompressed = zstd::decode_all(bytes.as_ref())
            .map_err(|e| MobileError::StorageError(format!("Decompression failed: {}", e)))?;
        std::fs::write(sqlite_path, &decompressed)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        if let Err(e) = std::fs::write(meta_path, version) {
            tracing::debug!("Failed to write meta sidecar for {}: {}", label, e);
        }
        tracing::debug!(
            "Downloaded {} ({} bytes compressed, {} bytes decompressed)",
            label, bytes.len(), decompressed.len()
        );
        Ok(())
    }

    /// Ensure the enriched POI tile (`pois/<id>`) is loaded, downloading if the
    /// on-disk copy is missing or stale vs the manifest's `pois_version`.
    /// Parallel to `ensure_tile_loaded` but keyed off the pois family, so a POI
    /// refresh never invalidates cached address tiles.
    fn ensure_pois_tile_loaded(&self, tile_id: &str, rt: &tokio::runtime::Runtime) -> Result<(), MobileError> {
        if self.loaded_pois.lock().unwrap_or_else(|e| e.into_inner()).contains_key(tile_id) {
            return Ok(());
        }
        let storage_dir = Path::new(&self.storage_path);
        let tile_path = storage_dir.join(format!("poi_{}.sqlite", tile_id));
        let meta_path = storage_dir.join(format!("poi_{}.meta", tile_id));

        if tile_path.exists() {
            let expected = { self.manifest.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|m| m.pois_version.clone()) };
            let cached = std::fs::read_to_string(&meta_path).ok().map(|s| s.trim().to_string());
            match (&expected, &cached) {
                (Some(exp), Some(c)) if !exp.is_empty() && exp == c => {
                    return self.load_pois_from_disk(tile_id, tile_path.to_str().unwrap_or_default());
                }
                _ => {
                    let _ = std::fs::remove_file(&tile_path);
                    let _ = std::fs::remove_file(&meta_path);
                }
            }
        }

        // Resolve URL + version under the lock, then download outside it.
        let (url, version) = {
            let m = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let m = m.as_ref().ok_or_else(|| {
                MobileError::StorageError("Tile manifest not loaded".to_string())
            })?;
            if !m.pois.contains(tile_id) {
                return Err(MobileError::StorageError(format!("No POI tile: {}", tile_id)));
            }
            (format!("{}/pois/{}.sqlite.zst", self.base_url, tile_id), m.pois_version.clone())
        };
        self.fetch_decompress_to(&url, &tile_path, &meta_path, &version, &format!("poi tile {}", tile_id), rt)?;
        self.load_pois_from_disk(tile_id, tile_path.to_str().unwrap_or_default())
    }

    /// Load a POI tile from disk into the `loaded_pois` map (LRU-capped).
    fn load_pois_from_disk(&self, tile_id: &str, path: &str) -> Result<(), MobileError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        let tick = self.next_lru_tick();
        self.loaded_pois
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tile_id.to_string(), (conn, tick));
        self.evict_excess_pois();
        Ok(())
    }

    /// LRU eviction for the POI tile map (mirrors `evict_excess_tiles`).
    fn evict_excess_pois(&self) {
        let mut tiles = self.loaded_pois.lock().unwrap_or_else(|e| e.into_inner());
        while tiles.len() > Self::MAX_LOADED_TILES {
            let oldest = tiles
                .iter()
                .min_by_key(|(_, (_, tick))| *tick)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                tiles.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Best-effort: load the enriched POI tile alongside the address tile when
    /// the manifest advertises one for this cell. Failures are logged, not
    /// fatal — the combined tile's own (OSM) pois remain a fallback.
    fn ensure_pois_best_effort(&self, tile_id: &str, rt: &tokio::runtime::Runtime) {
        let has = self
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|m| m.pois.contains(tile_id))
            .unwrap_or(false);
        if has {
            if let Err(e) = self.ensure_pois_tile_loaded(tile_id, rt) {
                tracing::warn!("POI tile load failed: {}", e);
            }
        }
    }

    /// Disk path for a per-city shard, regardless of whether it's
    /// downloaded yet.
    fn city_shard_path(&self, geoname_id: i64) -> std::path::PathBuf {
        Path::new(&self.storage_path)
            .join("addr")
            .join(format!("{}.sqlite", geoname_id))
    }

    /// Ensure a per-city addr+POI shard exists on disk; download +
    /// decompress on first use. Returns the on-disk path on success,
    /// `Ok(None)` on a 404 (city has no shard — small cities without
    /// OpenAddresses coverage) so the caller can soft-fall-back.
    fn ensure_city_shard_on_disk(
        &self,
        geoname_id: i64,
    ) -> Result<Option<std::path::PathBuf>, MobileError> {
        let path = self.city_shard_path(geoname_id);
        if path.exists() {
            return Ok(Some(path));
        }
        let shard_dir = path.parent().ok_or_else(|| {
            MobileError::StorageError("city shard path has no parent".to_string())
        })?;
        if !shard_dir.exists() {
            std::fs::create_dir_all(shard_dir)
                .map_err(|e| MobileError::StorageError(e.to_string()))?;
        }

        let url = format!("{}/addr/{}.sqlite.zst", self.base_url, geoname_id);
        tracing::debug!("Downloading city shard {} from {}", geoname_id, url);
        let rt = crate::location::get_shared_runtime();
        let client = &self.client;

        let mut last_err: Option<String> = None;
        let bytes_or_404: Option<Vec<u8>> = rt.block_on(async {
            for attempt in 1..=3 {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                        // Soft miss — not every city in the cities tiers has
                        // OpenAddresses coverage.
                        tracing::debug!(
                            "city shard {} returned 404, treating as soft miss",
                            geoname_id
                        );
                        return Ok::<Option<Vec<u8>>, MobileError>(None);
                    }
                    Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                        Ok(b) => return Ok(Some(b.to_vec())),
                        Err(e) => {
                            tracing::debug!(
                                "city shard {} attempt {}/3: body read failed: {:?}",
                                geoname_id,
                                attempt,
                                e
                            );
                            last_err = Some(format!("{:?}", e));
                        }
                    },
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::debug!(
                            "city shard {} attempt {}/3: HTTP {}",
                            geoname_id,
                            attempt,
                            status
                        );
                        last_err = Some(format!("HTTP {}", status));
                    }
                    Err(e) => {
                        tracing::debug!(
                            "city shard {} attempt {}/3: request failed: {:?}",
                            geoname_id,
                            attempt,
                            e
                        );
                        last_err = Some(format!("{:?}", e));
                    }
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64))
                        .await;
                }
            }
            Err(MobileError::NetworkError(
                last_err.unwrap_or_else(|| "unknown error".to_string()),
            ))
        })?;

        let Some(bytes) = bytes_or_404 else {
            return Ok(None);
        };

        let decompressed = zstd::decode_all(bytes.as_slice())
            .map_err(|e| MobileError::StorageError(format!("Decompression failed: {}", e)))?;
        std::fs::write(&path, &decompressed)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        tracing::debug!(
            "Downloaded city shard {} ({} bytes decompressed)",
            geoname_id,
            decompressed.len()
        );
        Ok(Some(path))
    }

    /// Open every tile_*.sqlite under storage_path that isn't already in
    /// `loaded_tiles`. Idempotent — cheap to call repeatedly.
    ///
    /// Forward search iterates over `loaded_tiles.values()` only, so without
    /// this every app launch starts with an empty in-memory map and forward
    /// queries return nothing until reverse-geocoding repopulates it. Calling
    /// this from `forward()` (and exposing `prewarm_tile_cache()` for explicit
    /// warmup) makes forward search "free" across everywhere the user has
    /// ever reverse-geocoded.
    fn load_all_cached_tiles(&self) {
        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            return;
        }

        // Snapshot the already-loaded set so we don't hold the mutex across IO.
        let already_loaded: std::collections::HashSet<String> = self
            .loaded_tiles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        let already_loaded_pois: std::collections::HashSet<String> = self
            .loaded_pois
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();

        let entries = match std::fs::read_dir(storage_dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Could not list tile cache dir: {}", e);
                return;
            }
        };

        // When the manifest is loaded, we can validate each on-disk
        // tile's `tile_<id>.meta` sidecar against the manifest's
        // `updated_at`. A stale tile from a prior pipeline run gets
        // skipped here (and will be replaced on the next
        // ensure_tile_loaded call). Without a manifest (cold start
        // before fetch), we trust the cache and let ensure_tile_loaded
        // validate later.
        let manifest_version: Option<String> = self
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|m| m.updated_at.clone())
            .filter(|s| !s.is_empty());
        let pois_version: Option<String> = self
            .manifest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|m| m.pois_version.clone())
            .filter(|s| !s.is_empty());

        let mut loaded = 0usize;
        let mut failed = 0usize;
        let mut stale = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(path_str) = path.to_str() else { continue };
            // Address tiles `tile_<id>.sqlite`, POI tiles `poi_<id>.sqlite`
            // (see download_tile / ensure_pois_tile_loaded). Each validates its
            // own `.meta` sidecar against the matching manifest version.
            if let Some(tile_id) = name.strip_prefix("tile_").and_then(|s| s.strip_suffix(".sqlite")) {
                if already_loaded.contains(tile_id) {
                    continue;
                }
                // STOP AT THE CAP INSTEAD OF CHURNING THROUGH IT.
                //
                // Every load inserts with a fresh (higher) LRU tick and then
                // evicts the smallest, so a scan of N > MAX_LOADED_TILES files
                // does not "load N" — it loads N and throws away all but the last
                // MAX_LOADED_TILES it happened to touch, in readdir order.
                //
                // Without the stop that silently destroys the smart-fallback:
                // it resolves a city, deliberately loads THAT city's tile, then
                // searches; `forward_near` opens by calling this function, which
                // evicts the tile it was just handed — its tick is lower than
                // everything the scan touches afterwards. With more tiles cached
                // than the cap (say 140 against 30), the search then reports no
                // match for an address that sits on disk, in a tile the app had
                // just loaded for exactly that query.
                //
                // Stopping here keeps the memory bound and makes an explicit
                // load stick: whatever the caller asked for stays resident, and
                // a bulk scan arriving afterwards cannot displace it.
                if self
                    .loaded_tiles
                    .lock()
                    .map(|t| t.len() >= Self::MAX_LOADED_TILES)
                    .unwrap_or(false)
                {
                    continue;
                }
                if let Some(ref expected) = manifest_version {
                    let meta_path = path.with_file_name(format!("tile_{}.meta", tile_id));
                    let cached = std::fs::read_to_string(&meta_path).ok().map(|s| s.trim().to_string());
                    if cached.as_deref() != Some(expected.as_str()) {
                        stale += 1;
                        continue;
                    }
                }
                match self.load_tile_from_disk(tile_id, path_str) {
                    Ok(()) => loaded += 1,
                    Err(e) => {
                        failed += 1;
                        tracing::warn!("Skipping unreadable tile: {}", e);
                    }
                }
            } else if let Some(tile_id) = name.strip_prefix("poi_").and_then(|s| s.strip_suffix(".sqlite")) {
                if already_loaded_pois.contains(tile_id) {
                    continue;
                }
                if let Some(ref expected) = pois_version {
                    let meta_path = path.with_file_name(format!("poi_{}.meta", tile_id));
                    let cached = std::fs::read_to_string(&meta_path).ok().map(|s| s.trim().to_string());
                    if cached.as_deref() != Some(expected.as_str()) {
                        stale += 1;
                        continue;
                    }
                }
                match self.load_pois_from_disk(tile_id, path_str) {
                    Ok(()) => loaded += 1,
                    Err(e) => {
                        failed += 1;
                        tracing::warn!("Skipping unreadable poi tile: {}", e);
                    }
                }
            }
        }

        if loaded > 0 || failed > 0 || stale > 0 {
            tracing::info!(
                "Tile cache prewarm: {} loaded, {} stale (skipped), {} unreadable",
                loaded, stale, failed
            );
        }
    }
}

#[uniffi::export]
impl TileGeocoder {
    /// Create a new tile geocoder with the default CDN URL
    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Self {
        Self {
            base_url: "https://geocoding.pingolin.com".to_string(),
            storage_path,
            manifest: Arc::new(Mutex::new(None)),
            loaded_tiles: Arc::new(Mutex::new(HashMap::new())),
            loaded_pois: Arc::new(Mutex::new(HashMap::new())),
            tile_lru_tick: Arc::new(Mutex::new(0)),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create a new tile geocoder with a custom base URL
    #[uniffi::constructor]
    pub fn with_base_url(storage_path: String, base_url: String) -> Self {
        Self {
            base_url,
            storage_path,
            manifest: Arc::new(Mutex::new(None)),
            loaded_tiles: Arc::new(Mutex::new(HashMap::new())),
            loaded_pois: Arc::new(Mutex::new(HashMap::new())),
            tile_lru_tick: Arc::new(Mutex::new(0)),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fetch the tile manifest from CDN. Call this once at startup.
    pub fn fetch_manifest(&self) -> Result<bool, MobileError> {
        // Served from the on-disk cache when it is inside its max-age,
        // revalidated with its ETag / Last-Modified when it is not, and used
        // stale when the CDN cannot be reached at all — see the manifest
        // cache section above for why.
        let dir = Path::new(&self.storage_path);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cached = load_cached_manifest(dir);

        if let Some((meta, manifest)) = &cached {
            if meta.is_fresh(now_ms) {
                tracing::info!("Using the cached tile manifest ({}), still inside its max-age", meta.source);
                self.install_manifest(manifest.clone());
                return Ok(true);
            }
        }

        let rt = crate::location::get_shared_runtime();
        let client = &self.client;

        // Prefer manifest-v4.json (per-family versioning + the pois/ family);
        // fall back to manifest-v3.json so this client still works against a
        // CDN that only publishes v3. The same struct parses both — v4
        // fields default to empty under v3.
        let mut parsed: Option<ManifestV3> = None;
        for fname in ["manifest-v4.json", "manifest-v3.json"] {
            let url = format!("{}/{}", self.base_url, fname);
            // Validators belong to the URL they came from.
            let validators = cached
                .as_ref()
                .filter(|(meta, _)| meta.source == fname)
                .map(|(meta, _)| (meta.etag.as_deref(), meta.last_modified.as_deref()));
            tracing::info!(
                "fetch_manifest trying {}{}",
                url,
                if validators.is_some() { " (revalidating the cached copy)" } else { "" }
            );
            match rt.block_on(fetch_manifest_file(client, &url, validators)) {
                Ok(ManifestFetch::NotModified { fresh_for_secs }) => {
                    // A 304 only ever answers a request that carried this
                    // file's validators, so the cached copy is this file.
                    if let Some((meta, manifest)) = &cached {
                        let meta = ManifestCacheMeta {
                            confirmed_at_ms: now_ms,
                            fresh_for_secs,
                            ..meta.clone()
                        };
                        if let Err(e) = store_cached_manifest(dir, &meta, None) {
                            tracing::warn!("Could not update the manifest cache: {}", e);
                        }
                        tracing::info!("{} not modified; reusing the cached copy", fname);
                        parsed = Some(manifest.clone());
                        break;
                    }
                }
                Ok(ManifestFetch::Body { bytes, etag, last_modified, fresh_for_secs }) => {
                    match serde_json::from_slice::<ManifestV3>(&bytes) {
                        Ok(manifest) => {
                            let meta = ManifestCacheMeta {
                                source: fname.to_string(),
                                etag,
                                last_modified,
                                confirmed_at_ms: now_ms,
                                fresh_for_secs,
                            };
                            if let Err(e) = store_cached_manifest(dir, &meta, Some(&bytes)) {
                                tracing::warn!("Could not write the manifest cache: {}", e);
                            }
                            parsed = Some(manifest);
                            break;
                        }
                        Err(e) => tracing::warn!("{} did not parse: {}", fname, e),
                    }
                }
                Err(e) => tracing::warn!("{} unavailable: {}", fname, e),
            }
        }

        let parsed = match parsed {
            Some(parsed) => parsed,
            // Offline, or the CDN is failing. An out-of-date manifest still
            // names every tile this device has cached, which beats none.
            None => match cached {
                Some((_, manifest)) => {
                    tracing::warn!("Tile manifest unreachable; using the cached copy");
                    manifest
                }
                None => {
                    return Err(MobileError::NetworkError(
                        "no manifest (v4 or v3) available".to_string(),
                    ))
                }
            },
        };

        self.install_manifest(parsed);
        Ok(true)
    }

    /// Check if the manifest is loaded
    pub fn has_manifest(&self) -> bool {
        self.manifest.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Reverse geocoding: coordinates -> nearest address
    /// Automatically downloads required tiles on demand.
    pub fn reverse(&self, lat: f64, lng: f64) -> Option<GeocodingResult> {
        tracing::debug!("TileGeocoder.reverse called for ({}, {})", lat, lng);

        if !self.has_manifest() {
            tracing::warn!("TileGeocoder: No manifest loaded, cannot reverse geocode");
            return None;
        }

        let tile_id = match self.find_tile_for_coords(lat, lng) {
            Some(id) => {
                tracing::debug!("Found tile {} for coordinates ({}, {})", id, lat, lng);
                id
            }
            None => {
                tracing::warn!("No tile available for reverse-geocode request");
                return None;
            }
        };

        // Any tile download runs on the SDK's shared runtime. A fresh
        // multi-thread runtime per call would also kill the pooled connections
        // of `self.client` with each one, so every call would pay a new TLS
        // handshake.
        let rt = crate::location::get_shared_runtime();

        // Ensure tile is loaded (this also best-effort loads the cell's
        // enriched POI tile via the ensure_tile_loaded hook).
        if let Err(e) = self.ensure_tile_loaded(&tile_id, rt) {
            tracing::error!("Failed to load tile: {}", e);
            return None;
        }

        // Prefer a POI when the point lands essentially on one (≤ ~44 m) — the
        // "tap a place, get the place" behavior. Reads the enriched pois/ family
        // loaded alongside the address tile, falling back to the combined tile's
        // own pois. Outside that tight radius we return the nearest address.
        {
            let poi_delta = 0.0004_f64; // ~44 m
            let pois = self.loaded_pois.lock().unwrap_or_else(|e| e.into_inner());
            let tiles = self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner());
            let poi_conn = pois
                .get(&tile_id)
                .map(|e| &e.0)
                .or_else(|| tiles.get(&tile_id).map(|e| &e.0));
            // The combined tile always carries the addresses table; use it to
            // attach a street to any POI the pois tile has none for.
            let addr_conn = tiles.get(&tile_id).map(|e| &e.0);
            if let Some(conn) = poi_conn {
                // Two spellings of the same query: newer tiles carry the POI's
                // own street, older ones do not and would fail to prepare.
                // Column order matches so one mapper serves both.
                let q_full = r#"
                    SELECT name, lat, lng, COALESCE(city, ''), COALESCE(state, ''), COALESCE(country, ''),
                           housenumber, street
                    FROM pois
                    WHERE lat BETWEEN ?1 - ?3 AND ?1 + ?3
                      AND lng BETWEEN ?2 - ?3 AND ?2 + ?3
                    ORDER BY ((lat - ?1) * (lat - ?1) + (lng - ?2) * (lng - ?2))
                    LIMIT 1
                "#;
                let q_old = r#"
                    SELECT name, lat, lng, COALESCE(city, ''), COALESCE(state, ''), COALESCE(country, ''),
                           NULL, NULL
                    FROM pois
                    WHERE lat BETWEEN ?1 - ?3 AND ?1 + ?3
                      AND lng BETWEEN ?2 - ?3 AND ?2 + ?3
                    ORDER BY ((lat - ?1) * (lat - ?1) + (lng - ?2) * (lng - ?2))
                    LIMIT 1
                "#;
                let map_row = |row: &rusqlite::Row| -> rusqlite::Result<GeocodingResult> {
                    let name: String = row.get(0)?;
                    let city: String = row.get(3)?;
                    let state: String = row.get(4)?;
                    let country: String = row.get(5)?;
                    let hn: Option<String> = row.get::<_, Option<String>>(6).unwrap_or(None);
                    let st: Option<String> = row.get::<_, Option<String>>(7).unwrap_or(None);
                    let locality = match (city.is_empty(), state.is_empty()) {
                        (false, false) => format!(", {}, {}", city, state),
                        (false, true) => format!(", {}", city),
                        _ => String::new(),
                    };
                    Ok(GeocodingResult {
                        text: format!("{}{}", name, locality),
                        lat: row.get(1)?,
                        lng: row.get(2)?,
                        result_type: "poi".to_string(),
                        confidence: 1.0,
                        name: Some(name),
                        city: if city.is_empty() { None } else { Some(city) },
                        state: if state.is_empty() { None } else { Some(state) },
                        postcode: None,
                        country: if country.is_empty() { None } else { Some(country) },
                        // Falls back to the cell's addresses below when absent.
                        address: join_street(hn, st),
                    })
                };
                let found = conn
                    .query_row(q_full, rusqlite::params![lat, lng, poi_delta], map_row)
                    .or_else(|_| conn.query_row(q_old, rusqlite::params![lat, lng, poi_delta], map_row));
                if let Ok(mut r) = found {
                    if r.address.is_none() {
                        if let Some(ac) = addr_conn {
                            r.address = nearest_address_text(ac, r.lat, r.lng);
                        }
                    }
                    return Some(r);
                }
            }
        }

        // Query the tile. Bump the LRU tick on access so this entry
        // doesn't become eviction bait just because some other tile
        // was loaded after it.
        let new_tick = self.next_lru_tick();
        let mut tiles = self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = tiles.get_mut(&tile_id) {
            entry.1 = new_tick;
        }
        let conn = &tiles.get(&tile_id)?.0;

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(addresses)")
            .ok()
            .and_then(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(1))
                    .ok()
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            })
            .unwrap_or_default();
        tracing::debug!("Tile {} addresses columns: {:?}", tile_id, columns);

        // Try expanding radius: 500m, 1km, 2km
        for delta in [0.005, 0.01, 0.02] {
            let has_city = columns.iter().any(|c| c == "city");
            let has_state = columns.iter().any(|c| c == "state");

            let query = if has_city && has_state {
                r#"
                SELECT text, lat, lng,
                       COALESCE(city, ''), COALESCE(state, ''),
                       COALESCE(postcode, ''), COALESCE(country, '')
                FROM addresses
                WHERE lat BETWEEN ?1 - ?3 AND ?1 + ?3
                  AND lng BETWEEN ?2 - ?3 AND ?2 + ?3
                ORDER BY ((lat - ?1) * (lat - ?1) + (lng - ?2) * (lng - ?2))
                LIMIT 1
                "#
            } else {
                // Fallback for tiles without city/state columns
                r#"
                SELECT text, lat, lng, '', '', '', ''
                FROM addresses
                WHERE lat BETWEEN ?1 - ?3 AND ?1 + ?3
                  AND lng BETWEEN ?2 - ?3 AND ?2 + ?3
                ORDER BY ((lat - ?1) * (lat - ?1) + (lng - ?2) * (lng - ?2))
                LIMIT 1
                "#
            };

            if let Ok(result) = conn.query_row(
                query,
                rusqlite::params![lat, lng, delta],
                |row| {
                    let text: String = row.get(0)?;
                    let city: String = row.get(3)?;
                    let state: String = row.get(4)?;
                    let postcode: String = row.get(5).unwrap_or_default();
                    let country: String = row.get(6).unwrap_or_default();

                    tracing::debug!(
                        "Geocoding result - text: '{}', city: '{}', state: '{}'",
                        text, city, state
                    );

                    // Single-line `text` for callers that render it directly —
                    // see `GeocodingResult::text`.
                    let mut formatted = text.clone();
                    if !city.is_empty() && !formatted.contains(&city) {
                        formatted = format!("{}, {}", formatted, city);
                    }
                    if !state.is_empty() && !formatted.contains(&state) {
                        formatted = format!("{}, {}", formatted, state);
                    }

                    Ok(GeocodingResult {
                        text: formatted,
                        lat: row.get(1)?,
                        lng: row.get(2)?,
                        result_type: "address".to_string(),
                        confidence: 1.0 - (delta * 10.0), // Higher confidence at smaller radius
                        name: None,
                        city: if city.is_empty() { None } else { Some(city) },
                        state: if state.is_empty() { None } else { Some(state) },
                        postcode: if postcode.is_empty() { None } else { Some(postcode) },
                        country: if country.is_empty() { None } else { Some(country) },
                        address: None,
                    })
                },
            ) {
                return Some(result);
            }
        }

        None
    }

    /// Forward geocoding with no proximity context: text query -> locations.
    /// Prefer [`Self::forward_near`], which can order matches by distance.
    ///
    /// Searches every tile cached on disk. Auto-loads any disk-cached tiles
    /// not yet in memory before searching, so forward results cover
    /// everywhere the user has ever reverse-geocoded — not just tiles
    /// touched in the current app session.
    pub fn forward(&self, query: &str, limit: u32) -> Vec<GeocodingResult> {
        self.forward_near(query, limit, None, None)
    }

    /// Forward search that knows where the user is looking.
    ///
    /// The focus point is used to ORDER the per-tile SQL by distance.
    /// Without it the tile query returns rowid order, so `limit` takes an
    /// ARBITRARY slice of the matches and the caller's viewport clamp then
    /// discards whatever of that slice is off-screen — "starbucks" from
    /// Modesto can return a town in Minnesota because none of the fetched
    /// rows were the 36 branches nearby.
    ///
    /// With an ordering, the nearest rows arrive first, so `limit` keeps
    /// the nearest matches.
    pub fn forward_near(
        &self,
        query: &str,
        limit: u32,
        focus_lat: Option<f64>,
        focus_lng: Option<f64>,
    ) -> Vec<GeocodingResult> {
        // Prewarm: pulls in any tile_*.sqlite under storage_path that isn't
        // already loaded. Idempotent and free after the first call.
        self.load_all_cached_tiles();

        // Per-search diagnostics for the "the city resolved but nothing was
        // found in it" failure: how many tiles were actually searchable is the
        // state nobody can reconstruct afterwards. The query text is
        // deliberately NOT logged — it is user content. See the no-match log
        // at the end of this function for why the level matters.
        tracing::debug!(
            addr_tiles = self.loaded_tiles.lock().map(|m| m.len()).unwrap_or(0),
            poi_tiles = self.loaded_pois.lock().map(|m| m.len()).unwrap_or(0),
            tokens = query.split_whitespace().count(),
            "forward_near: searching"
        );

        // Tile precision (usually 4), used to map a POI back to its cell when
        // attaching a street address below.
        let precision = self
            .manifest
            .lock()
            .ok()
            .and_then(|m| m.as_ref().map(|mm| mm.precision))
            .unwrap_or(4);

        // Tokenize the way the web client does: split on whitespace+commas,
        // lowercase, keep every non-empty token. Single-character tokens get
        // matched with word-boundary patterns ('% X %' / 'X %' / '% X') so a
        // stray "I" doesn't pull in every street containing the letter — they
        // are kept rather than dropped so "854 I St" can specifically demand
        // the "I" street as a separate token.
        // Apostrophes are stripped (straight ' and curly ’) so "togos"
        // matches indexed "Togo's"; the LIKE columns are REPLACE()'d to
        // strip them on the stored side too.
        let tokens: Vec<(String, bool)> = query
            .split(|c: char| c.is_whitespace() || c == ',')
            .map(|t| {
                t.trim()
                    .to_lowercase()
                    .replace(|c: char| c == '\'' || c == '\u{2019}', "")
            })
            .filter(|t| !t.is_empty())
            .map(|t| {
                let wb = t.chars().count() == 1;
                (t, wb)
            })
            .collect();
        if tokens.is_empty() {
            return Vec::new();
        }

        // Build the column-specific LIKE clause + bind list. Each
        // token contributes either 1 placeholder (regular `%token%`)
        // or 3 placeholders (single-char word-boundary).
        fn build_clause(column: &str, tokens: &[(String, bool)]) -> (String, Vec<String>) {
            let mut where_parts = Vec::new();
            let mut binds = Vec::new();
            for (text, wb) in tokens {
                if *wb {
                    where_parts.push(format!(
                        "({col} LIKE ? OR {col} LIKE ? OR {col} LIKE ?)",
                        col = wb_col(column)
                    ));
                    binds.push(format!("% {} %", text));
                    binds.push(format!("{} %", text));
                    binds.push(format!("% {}", text));
                } else {
                    // OR-expand ordinals / street-type abbreviations so e.g.
                    // "sixth" also matches indexed "6th" and "st" matches
                    // "street". `token_equivalents` always includes the
                    // original token first, so the expansion is purely
                    // additive. Numeric-ordinal forms ("6th") use word-boundary
                    // patterns so they don't match inside "16th"/"26th";
                    // everything else stays a substring.
                    let equivs = token_equivalents(text);
                    let mut ors: Vec<String> = Vec::new();
                    for e in &equivs {
                        if needs_word_boundary(e) {
                            ors.push(format!(
                                "{col} LIKE ? OR {col} LIKE ? OR {col} LIKE ?",
                                col = wb_col(column)
                            ));
                            binds.push(format!("% {} %", e));
                            binds.push(format!("{} %", e));
                            binds.push(format!("% {}", e));
                        } else {
                            ors.push(format!("{} LIKE ?", column));
                            binds.push(format!("%{}%", e));
                        }
                    }
                    where_parts.push(format!("({})", ors.join(" OR ")));
                }
            }
            (where_parts.join(" AND "), binds)
        }
        // REPLACE() strips apostrophes from the stored value so an
        // apostrophe-free query token ("togos") matches a name/street that
        // contains one ("Togo's"). LIKE '%...%' is already a scan, so wrapping
        // the column adds no index cost.
        let (address_where, address_binds) =
            build_clause("REPLACE(REPLACE(text, '''', ''), '’', '')", &tokens);
        let (poi_where, poi_binds) =
            build_clause("REPLACE(REPLACE(name, '''', ''), '’', '')", &tokens);

        let mut results = Vec::new();
        // Dedup key is the trimmed lowercased text PLUS coordinates rounded to
        // ~11 m — see `row_dedup_key`. OpenAddresses + OSM POI extracts often
        // carry the same place from several sources at slightly different
        // coordinates, which is what this collapses; two same-named branches
        // at different addresses stay two rows.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let focus = match (focus_lat, focus_lng) {
            (Some(la), Some(ln)) => Some((la, ln)),
            _ => None,
        };
        // Bump LRU recency on every tile we're about to search — keeps
        // tiles the user is actively querying out of the eviction
        // path. Done outside the inner lock to avoid contention.
        let new_tick = self.next_lru_tick();
        // Bind lists are identical for every tile: token patterns then LIMIT.
        let mut addr_binds_full: Vec<String> = address_binds.clone();
        addr_binds_full.push(limit.to_string());
        let addr_bind_refs: Vec<&dyn rusqlite::ToSql> = addr_binds_full
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        let mut poi_binds_full: Vec<String> = poi_binds.clone();
        poi_binds_full.push(limit.to_string());
        let poi_bind_refs: Vec<&dyn rusqlite::ToSql> = poi_binds_full
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();

        // The enriched pois/ family takes precedence over a combined tile's own
        // pois for the same cell. Snapshot which cells have an enriched tile so
        // we skip their combined pois (the pois/ set is the deduped superset).
        let mut pois = self.loaded_pois.lock().unwrap_or_else(|e| e.into_inner());
        for entry in pois.values_mut() {
            entry.1 = new_tick;
        }
        let pois_keys: std::collections::HashSet<String> = pois.keys().cloned().collect();

        let mut tiles = self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner());
        for entry in tiles.values_mut() {
            entry.1 = new_tick;
        }

        for (tile_id, (conn, _)) in tiles.iter() {
            // -------- addresses --------
            // Try the wider schema first (with locality columns); fall back to
            // text-only for older tiles. The locality columns are what
            // populate the structured city/state/etc. fields, so a client can
            // render two-line results.
            let addr_sql_full = format!(
                "SELECT text, lat, lng, city, state, postcode, country \
                 FROM addresses WHERE {} LIMIT ?",
                address_where
            );
            let addr_loaded = if let Ok(mut stmt) = conn.prepare(&addr_sql_full) {
                if let Ok(rows) = stmt.query_map(&addr_bind_refs[..], |row| {
                    let city: Option<String> = row.get::<_, Option<String>>(3).unwrap_or(None);
                    let state: Option<String> = row.get::<_, Option<String>>(4).unwrap_or(None);
                    let postcode: Option<String> = row.get::<_, Option<String>>(5).unwrap_or(None);
                    let country: Option<String> = row.get::<_, Option<String>>(6).unwrap_or(None);
                    Ok(GeocodingResult {
                        text: row.get(0)?,
                        lat: row.get(1)?,
                        lng: row.get(2)?,
                        result_type: "address".to_string(),
                        confidence: 0.8,
                        name: None,
                        city: city.filter(|s| !s.is_empty()),
                        state: state.filter(|s| !s.is_empty()),
                        postcode: postcode.filter(|s| !s.is_empty()),
                        country: country.filter(|s| !s.is_empty()),
                        address: None,
                    })
                }) {
                    for row in rows.flatten() {
                        let key = row_dedup_key(&row);
                        if seen.insert(key) {
                            results.push(row);
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !addr_loaded {
                // Old schema fallback — text-only. Locality fields stay
                // None which the UI handles by hiding the secondary
                // line for that row.
                let addr_sql = format!(
                    "SELECT text, lat, lng FROM addresses WHERE {} LIMIT ?",
                    address_where
                );
                if let Ok(mut stmt) = conn.prepare(&addr_sql) {
                    if let Ok(rows) = stmt.query_map(&addr_bind_refs[..], |row| {
                        Ok(GeocodingResult {
                            text: row.get(0)?,
                            lat: row.get(1)?,
                            lng: row.get(2)?,
                            result_type: "address".to_string(),
                            confidence: 0.8,
                            name: None,
                            city: None,
                            state: None,
                            postcode: None,
                            country: None,
                            address: None,
                        })
                    }) {
                        for row in rows.flatten() {
                            let key = row_dedup_key(&row);
                            if seen.insert(key) {
                                results.push(row);
                            }
                        }
                    }
                }
            }

            // -------- pois (combined tile) --------
            // Only when this cell has no enriched pois/ tile loaded — the
            // pois/ family is the deduped superset, so querying both would
            // double-count.
            if !pois_keys.contains(tile_id) {
                query_pois_table(conn, &poi_where, &poi_bind_refs, &mut results, &mut seen, focus);
            }
        }

        // -------- pois (enriched pois/ family) --------
        for (conn, _) in pois.values() {
            query_pois_table(conn, &poi_where, &poi_bind_refs, &mut results, &mut seen, focus);
        }

        // A POI row that brought no street of its own gets one from the
        // combined tile covering its cell, so the UI can show an address per
        // POI and disambiguate same-named places. Falls back to precision+1
        // for the dense cells that ship at higher precision.
        for r in results.iter_mut() {
            if r.result_type == "poi" && r.address.is_none() {
                let conn = tiles.get(&encode_geohash(r.lat, r.lng, precision as usize)).or_else(|| {
                    tiles.get(&encode_geohash(r.lat, r.lng, (precision + 1) as usize))
                });
                if let Some((c, _)) = conn {
                    r.address = nearest_address_text(c, r.lat, r.lng);
                }
            }
        }

        // Typo fallback: only when the exact pass found nothing anywhere, so a
        // real match is never displaced. Nothing else tolerates a typo --
        // neither the tile queries nor the server path -- so without this
        // "starbcks" returns an empty list.
        //
        // (The sort below ranks POIs above addresses by confidence, so
        // "Starbucks austin" surfaces the POI rather than a street whose name
        // happens to contain "Starbucks".)
        if results.is_empty() {
            for (conn, _) in pois.values() {
                fuzzy_pois_in_tile(conn, &query, limit, &mut results, &mut seen, focus);
            }
            if results.is_empty() {
                for (conn, _) in tiles.values() {
                    fuzzy_pois_in_tile(conn, &query, limit, &mut results, &mut seen, focus);
                }
            }
        }
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit as usize);

        // A SEARCH THAT FOUND NOTHING IS THE INTERESTING ONE, so it logs at INFO
        // and a productive search does not. Two reasons the level matters rather
        // than being a style choice:
        //   * `tracing` here carries `release_max_level_info`, so `debug!` is
        //     statically compiled OUT of the release builds both apps ship — a
        //     debug-level diagnostic is invisible exactly where it is needed.
        //   * forward_near runs per debounced keystroke; logging every call at
        //     INFO would bury the failure it is meant to expose.
        //
        // What it captures is the state nobody can reconstruct afterwards: how
        // many ADDRESS vs POI tiles were searchable at that moment. "0 addr
        // tiles" and "40 addr tiles, no match" are entirely different faults and
        // look identical from the UI. The query text is deliberately absent — it
        // is user content.
        //
        // COUNT THROUGH THE GUARDS WE ALREADY HOLD — never re-lock here.
        //
        // `tiles` and `pois` above are `MutexGuard`s, and a guard lives until the
        // END OF THIS FUNCTION, not until its last use. Calling
        // `self.loaded_tiles.lock()` on this line therefore asks the same thread
        // for a mutex it is already holding, and `std::sync::Mutex` is not
        // reentrant: it blocks forever. Because the block is gated on
        // `results.is_empty()`, that hangs EVERY tile search that finds nothing
        // — the call never returns, and this very log line never prints, so the
        // instrumentation erases the failure it exists to expose. Pinned by
        // `a_search_that_matches_nothing_returns_instead_of_deadlocking`.
        if results.is_empty() {
            tracing::info!(
                addr_tiles = tiles.len(),
                poi_tiles = pois.len(),
                tokens = query.split_whitespace().count(),
                "forward_near: no matches"
            );
        }
        results
    }

    /// Open every disk-cached tile into memory so the very first forward
    /// search returns results without paying for an implicit prewarm. Safe
    /// to call from app startup; idempotent if called more than once.
    pub fn prewarm_tile_cache(&self) {
        self.load_all_cached_tiles();
    }

    /// Download + load the tile containing `(lat, lng)` *plus* its 8
    /// geohash neighbors. Used as the *fallback* path of the smart-
    /// fallback address-search when a per-city shard isn't available
    /// or didn't match the term. Per-neighbor failures are logged but
    /// don't fail the whole call.
    pub fn ensure_tile_and_neighbors_loaded(
        &self,
        lat: f64,
        lng: f64,
    ) -> Result<u32, MobileError> {
        if !self.has_manifest() {
            return Err(MobileError::StorageError(
                "Tile manifest not loaded".to_string(),
            ));
        }
        let tile_ids = self.find_tile_and_neighbors_for_coords(lat, lng);
        if tile_ids.is_empty() {
            return Ok(0);
        }
        let rt = crate::location::get_shared_runtime();
        let mut loaded = 0u32;
        for tile_id in &tile_ids {
            match self.ensure_tile_loaded(tile_id, rt) {
                Ok(()) => loaded += 1,
                Err(e) => tracing::warn!("Skipping neighbor tile: {}", e),
            }
        }
        Ok(loaded)
    }

    /// Download + load ONLY the single tile containing `(lat, lng)` — no
    /// neighbor fan-out. Surgical primitive for the "default the search scope
    /// to the current city/viewport" path: one precision-4 tile (~760 km²)
    /// covers the user's whole city, so this makes cross-town addresses in
    /// their own city searchable while downloading exactly one tile instead of
    /// the 9 that `ensure_tile_and_neighbors_loaded` pulls (each tile can be
    /// tens of MB in a dense metro). Returns true if a tile was loaded, false
    /// if the coordinates map to no tile in the manifest.
    pub fn ensure_tile_for_coords_loaded(&self, lat: f64, lng: f64) -> Result<bool, MobileError> {
        if !self.has_manifest() {
            return Err(MobileError::StorageError(
                "Tile manifest not loaded".to_string(),
            ));
        }
        let tile_id = match self.find_tile_for_coords(lat, lng) {
            Some(t) => t,
            None => return Ok(false),
        };
        let rt = crate::location::get_shared_runtime();
        self.ensure_tile_loaded(&tile_id, rt)?;
        Ok(true)
    }

    /// Download + load a single tile by its manifest tile ID. Public
    /// counterpart of the private `ensure_tile_loaded`, used by the
    /// city-shard surgical path: the shard returns exact tile IDs that
    /// contain the user's term, the caller loads only those (often 1).
    /// Returns true if the tile is loaded into memory after the call.
    pub fn ensure_tile_loaded_by_id(&self, tile_id: String) -> Result<bool, MobileError> {
        if !self.has_manifest() {
            return Err(MobileError::StorageError(
                "Tile manifest not loaded".to_string(),
            ));
        }
        // Tile not in the manifest → soft miss rather than an error, matching
        // the web client.
        {
            let manifest = self.manifest.lock().unwrap_or_else(|e| e.into_inner());
            let Some(manifest) = manifest.as_ref() else {
                return Ok(false);
            };
            if !manifest.tiles.contains(&tile_id) {
                tracing::warn!("Tile not in manifest, skipping");
                return Ok(false);
            }
        }
        let rt = crate::location::get_shared_runtime();
        match self.ensure_tile_loaded(&tile_id, rt) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!("ensure_tile_loaded failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Per-city addr+POI shard lookup, the same shape the web client uses:
    /// fetches the shard (`<base_url>/addr/<geoname_id>.sqlite.zst`) on first
    /// use, disk-caches it, then queries token-AND'd LIKE against
    /// `addr_index(street_norm, tile_id)` and `poi_index(poi_norm,
    /// tile_id)`. Returns the deduplicated tile IDs that contain the
    /// term, or empty vec on:
    ///   - empty term
    ///   - shard missing on CDN (404 — small cities w/o OA coverage)
    ///   - shard query returned no rows
    ///   - any I/O failure (logged, not raised)
    /// Caller treats all four cases identically and falls back to the
    /// neighbors-load path.
    pub fn lookup_city_shard_tiles(&self, geoname_id: i64, term: String) -> Vec<String> {
        let term = term.trim().to_string();
        tracing::info!(geoname_id, term_tokens = term.split_whitespace().count(),
                       "lookup_city_shard_tiles: begin");
        if term.is_empty() {
            return Vec::new();
        }

        // Tokenize the same way `forward_near` does so the query rules stay
        // consistent across the address-search call sites, single-letter
        // word-boundary handling included.
        let tokens: Vec<(String, bool)> = term
            .split(|c: char| c.is_whitespace() || c == ',')
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .map(|t| {
                let wb = t.chars().count() == 1;
                (t, wb)
            })
            .collect();
        if tokens.is_empty() {
            return Vec::new();
        }

        let path = match self.ensure_city_shard_on_disk(geoname_id) {
            Ok(Some(p)) => p,
            Ok(None) => return Vec::new(),
            Err(e) => {
                tracing::warn!("city shard ensure failed: {}", e);
                return Vec::new();
            }
        };

        // Open a transient connection — shards are tiny (KB to a few hundred
        // KB) and the open is cheap. A long-lived connection cache wouldn't
        // pay off because the same (geoname, term) tuple rarely repeats.
        let conn = match Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("city shard open failed: {}", e);
                return Vec::new();
            }
        };

        let mut tile_ids: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // (table, column) pairs — the schema diverges across the two
        // index tables. Pre-v2 shards lacked `poi_index`; the prepare
        // error there is swallowed and we keep whatever addr_index
        // produced.
        let queries: [(&str, &str); 2] = [
            ("addr_index", "street_norm"),
            ("poi_index", "poi_norm"),
        ];
        for (table, col) in queries {
            // Build per-token LIKE clause. Single-letter tokens are
            // expanded to a 3-way OR over the word-boundary patterns.
            let mut where_parts: Vec<String> = Vec::new();
            let mut binds: Vec<String> = Vec::new();
            for (text, wb) in &tokens {
                if *wb {
                    where_parts.push(format!(
                        "({col} LIKE ? OR {col} LIKE ? OR {col} LIKE ?)",
                        col = wb_col(col)
                    ));
                    binds.push(format!("% {} %", text));
                    binds.push(format!("{} %", text));
                    binds.push(format!("% {}", text));
                } else {
                    where_parts.push(format!("{} LIKE ?", col));
                    binds.push(format!("%{}%", text));
                }
            }
            let where_clause = where_parts.join(" AND ");
            let sql = format!(
                "SELECT DISTINCT tile_id FROM {} WHERE {}",
                table, where_clause
            );
            let mut stmt = match conn.prepare(&sql) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        "city shard {} prepare skipped (geoname={}): {}",
                        table,
                        geoname_id,
                        e
                    );
                    continue;
                }
            };
            let bind_refs: Vec<&dyn rusqlite::ToSql> =
                binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            let rows = match stmt.query_map(&bind_refs[..], |row| row.get::<_, String>(0)) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("city shard query failed (table={}): {}", table, e);
                    continue;
                }
            };
            for row in rows.flatten() {
                if seen.insert(row.clone()) {
                    tile_ids.push(row);
                }
            }
        }
        let token_texts: Vec<&str> = tokens.iter().map(|(t, _)| t.as_str()).collect();
        tracing::debug!(
            "city shard geoname={} term={:?} tokens={:?} → {} tile(s)",
            geoname_id,
            term,
            token_texts,
            tile_ids.len()
        );
        tile_ids
    }

    /// Get count of cached tiles
    pub fn cached_tile_count(&self) -> u32 {
        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            return 0;
        }

        std::fs::read_dir(storage_dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .path()
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("tile_") && n.ends_with(".sqlite"))
                            .unwrap_or(false)
                    })
                    .count() as u32
            })
            .unwrap_or(0)
    }

    /// Clear every cached tile: the address tiles (`tile_*`), the enriched POI
    /// tiles (`poi_*`) and the per-city addr+POI shards under `addr/`, from
    /// both the in-memory maps and disk.
    pub fn clear_cache(&self) -> Result<(), MobileError> {
        self.loaded_tiles.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.loaded_pois.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let storage_dir = Path::new(&self.storage_path);
        if storage_dir.exists() {
            for entry in std::fs::read_dir(storage_dir).map_err(|e| MobileError::StorageError(e.to_string()))? {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        // The .sqlite blobs, the .meta cache-validation
                        // sidecars, and the .size sidecars that older builds
                        // wrote when the manifest still carried per-tile sizes.
                        // Both tile families live flat in the root: address
                        // tiles as `tile_<id>`, POI tiles as `poi_<id>`.
                        if (name.starts_with("tile_") || name.starts_with("poi_"))
                            && (name.ends_with(".sqlite")
                                || name.ends_with(".meta")
                                || name.ends_with(".size"))
                        {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }

            // Per-city shards are `addr/<geoname_id>.sqlite`, one level down,
            // so the flat scan above never reaches them.
            let shard_dir = storage_dir.join("addr");
            if shard_dir.exists() {
                let _ = std::fs::remove_dir_all(&shard_dir);
            }
        }

        tracing::info!("Cleared tile cache");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Variable-precision tile resolution: a manifest may hold a region at the
    // base precision, SPLIT into base+1 children (dense metros), or COLLAPSED
    // into a base-1 parent (sparse countryside). All three must resolve.
    #[test]
    fn resolve_tile_id_handles_split_and_collapsed_regions() {
        use super::{encode_geohash, TileGeocoder, TileManifest};
        use std::collections::HashSet;

        let mk = |ids: &[&str]| TileManifest {
            version: "4".into(),
            updated_at: "t".into(),
            precision: 4,
            tiles: ids.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            pois: HashSet::new(),
            pois_version: "p".into(),
        };

        // A point whose ids at precision 3/4/5 we derive rather than hardcode,
        // so the test cannot drift from the encoder.
        let (lat, lng) = (37.77, -122.42);
        let p3 = encode_geohash(lat, lng, 3);
        let p4 = encode_geohash(lat, lng, 4);
        let p5 = encode_geohash(lat, lng, 5);
        assert!(p4.starts_with(&p3) && p5.starts_with(&p4), "encoder is prefix-consistent");

        // ordinary: held at base precision
        assert_eq!(
            TileGeocoder::resolve_tile_id(&mk(&[&p4]), lat, lng),
            Some(p4.clone())
        );
        // SPLIT: parent absent, child present
        assert_eq!(
            TileGeocoder::resolve_tile_id(&mk(&[&p5]), lat, lng),
            Some(p5.clone())
        );
        // COLLAPSED: only the parent is published
        assert_eq!(
            TileGeocoder::resolve_tile_id(&mk(&[&p3]), lat, lng),
            Some(p3.clone())
        );
        // nothing covers the point
        assert_eq!(TileGeocoder::resolve_tile_id(&mk(&["zzzz"]), lat, lng), None);
        // most specific wins when several are somehow present
        assert_eq!(
            TileGeocoder::resolve_tile_id(&mk(&[&p3, &p4, &p5]), lat, lng),
            Some(p4.clone())
        );
    }

    use super::*;

    /// Builds a one-row pois table in memory, with or without the
    /// housenumber/street columns, and runs the real query path over it.
    fn poi_tile(with_street_columns: bool) -> Vec<GeocodingResult> {
        let conn = Connection::open_in_memory().expect("open");
        if with_street_columns {
            conn.execute_batch(
                "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                   city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
                   source TEXT, housenumber TEXT, street TEXT);
                 INSERT INTO pois(name,city,state,country,lat,lng,source,housenumber,street)
                   VALUES('Pinks Hot Dogs','Los Angeles','CA','USA',34.0836,-118.3444,
                          'overture','709','N La Brea Ave');
                 INSERT INTO pois(name,city,state,country,lat,lng,source,housenumber,street)
                   VALUES('Some OSM Place','Los Angeles','CA','USA',34.09,-118.35,'osm',NULL,NULL);",
            )
            .expect("create new-schema tile");
        } else {
            conn.execute_batch(
                "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                   city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
                   source TEXT);
                 INSERT INTO pois(name,city,state,country,lat,lng,source)
                   VALUES('Pinks Hot Dogs','Los Angeles','CA','USA',34.0836,-118.3444,'overture');",
            )
            .expect("create old-schema tile");
        }
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let limit: i64 = 10;
        let binds: Vec<&dyn rusqlite::ToSql> = vec![&limit];
        query_pois_table(&conn, "1=1", &binds, &mut results, &mut seen, None);
        results
    }

    /// A POI must use its OWN street when the tile carries one.
    #[test]
    fn poi_rows_use_their_own_street_when_the_tile_has_one() {
        let rows = poi_tile(true);
        let pinks = rows
            .iter()
            .find(|r| r.name.as_deref() == Some("Pinks Hot Dogs"))
            .expect("Pinks row");
        assert_eq!(pinks.address.as_deref(), Some("709 N La Brea Ave"));
    }

    /// OSM rows have no street in the tile; they must stay None so forward()'s
    /// post-pass still fills them from the cell's nearest address.
    #[test]
    fn poi_rows_without_a_street_stay_none_for_the_fallback() {
        let rows = poi_tile(true);
        let osm = rows
            .iter()
            .find(|r| r.name.as_deref() == Some("Some OSM Place"))
            .expect("OSM row");
        assert!(osm.address.is_none(), "must fall through to the derivation");
    }

    /// The compatibility guarantee. Older tiles have no housenumber/street
    /// columns; querying them must still return POIs rather than failing to
    /// prepare and silently dropping every result.
    #[test]
    fn an_old_schema_tile_without_the_street_columns_still_returns_pois() {
        let rows = poi_tile(false);
        assert_eq!(rows.len(), 1, "old-schema tile must still yield its POI");
        assert_eq!(rows[0].name.as_deref(), Some("Pinks Hot Dogs"));
        assert!(rows[0].address.is_none());
        // `text` is the single-line wire format; it must stay "Name, City, State".
        assert_eq!(rows[0].text, "Pinks Hot Dogs, Los Angeles, CA");
    }

    /// Builds N same-named POIs at distinct coordinates in one city — the
    /// Starbucks-in-Modesto shape.
    fn same_name_tile(n: usize) -> Vec<GeocodingResult> {
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch(
            "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
               city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
               source TEXT, housenumber TEXT, street TEXT);",
        )
        .expect("create");
        for i in 0..n {
            conn.execute(
                "INSERT INTO pois(name,city,state,country,lat,lng,source) \
                 VALUES('Starbucks','Modesto','CA','USA',?1,?2,'osm')",
                rusqlite::params![37.60 + (i as f64) * 0.01, -121.00 + (i as f64) * 0.01],
            )
            .expect("insert");
        }
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let limit: i64 = 50;
        let binds: Vec<&dyn rusqlite::ToSql> = vec![&limit];
        query_pois_table(&conn, "1=1", &binds, &mut results, &mut seen, None);
        results
    }

    /// A tile holding 36 "Starbucks, Modesto, CA" must return all 36: keying
    /// dedup on the display string alone collapses them to one.
    #[test]
    fn same_named_branches_in_one_city_are_all_returned() {
        assert_eq!(same_name_tile(36).len(), 36);
    }

    /// The case the dedup exists for must still work: the same place reached
    /// through two sources carries the same coordinates from both.
    #[test]
    fn the_same_place_seen_twice_still_collapses() {
        let a = GeocodingResult {
            text: "Starbucks, Modesto, CA".into(),
            lat: 37.6391,
            lng: -120.9969,
            result_type: "poi".into(),
            confidence: 1.5,
            name: Some("Starbucks".into()),
            city: Some("Modesto".into()),
            state: Some("CA".into()),
            postcode: None,
            country: Some("USA".into()),
            address: None,
        };
        let b = GeocodingResult { ..a.clone() };
        assert_eq!(row_dedup_key(&a), row_dedup_key(&b));

        // ...while a branch 1.5 km away is a different row.
        let far = GeocodingResult { lat: 37.6521, ..a.clone() };
        assert_ne!(row_dedup_key(&a), row_dedup_key(&far));
    }

    /// Jitter below the rounding step must NOT split one place into two.
    #[test]
    fn sub_11m_coordinate_jitter_still_collapses() {
        let a = GeocodingResult {
            text: "Togo's, Modesto, CA".into(),
            lat: 37.639100,
            lng: -120.996900,
            result_type: "poi".into(),
            confidence: 1.5,
            name: Some("Togo's".into()),
            city: None,
            state: None,
            postcode: None,
            country: None,
            address: None,
        };
        let jittered = GeocodingResult { lat: 37.639104, lng: -120.996903, ..a.clone() };
        assert_eq!(row_dedup_key(&a), row_dedup_key(&jittered));
    }

    /// Address rows need the same protection: `text` is the street line alone,
    /// so the same street name in two towns must not collapse to one row.
    #[test]
    fn the_same_street_line_in_two_towns_is_two_rows() {
        let modesto = GeocodingResult {
            text: "100 Main St".into(),
            lat: 37.6391,
            lng: -120.9969,
            result_type: "address".into(),
            confidence: 0.8,
            name: None,
            city: Some("Modesto".into()),
            state: Some("CA".into()),
            postcode: None,
            country: Some("USA".into()),
            address: None,
        };
        let turlock = GeocodingResult {
            lat: 37.4947,
            lng: -120.8466,
            city: Some("Turlock".into()),
            ..modesto.clone()
        };
        assert_ne!(row_dedup_key(&modesto), row_dedup_key(&turlock));
    }

    #[test]
    fn join_street_composes_and_drops_the_bare_number() {
        assert_eq!(
            join_street(Some("709".into()), Some("N La Brea Ave".into())).as_deref(),
            Some("709 N La Brea Ave")
        );
        // Non-US order: the number is already inside the street line.
        assert_eq!(
            join_street(None, Some("Dominicusstrasse 44".into())).as_deref(),
            Some("Dominicusstrasse 44")
        );
        // A number with no street is not an address line.
        assert_eq!(join_street(Some("709".into()), None), None);
        assert_eq!(join_street(Some("709".into()), Some("  ".into())), None);
        assert_eq!(join_street(None, None), None);
    }

    /// Whole-region databases from earlier versions sit FLAT in the geocoding
    /// root, so the purge has to tell them from tiles by name alone.
    #[test]
    fn the_region_purge_takes_regions_and_spares_everything_else() {
        let dir = std::env::temp_dir().join(format!("pgn_purge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mk = |n: &str| std::fs::write(dir.join(n), b"x").unwrap();
        // regions — must go
        for n in ["us-ca.sqlite", "de.sqlite", "gb.sqlite", "us-tx.sqlite.zst"] { mk(n); }
        // everything else — must stay
        for n in ["tile_9q9y.sqlite", "cities-tier1.sqlite", "manifest.json", "notes.sqlite"] { mk(n); }
        std::fs::create_dir_all(dir.join("tiles")).unwrap();
        std::fs::write(dir.join("tiles").join("us-ca.sqlite"), b"x").unwrap();

        purge_retired_region_files(dir.to_str().unwrap());

        let left: std::collections::HashSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(!left.contains("us-ca.sqlite"), "region must be purged");
        assert!(!left.contains("us-tx.sqlite.zst"), "region archive must be purged");
        assert!(left.contains("tile_9q9y.sqlite"), "tiles must survive");
        assert!(left.contains("cities-tier1.sqlite"), "cities must survive");
        assert!(left.contains("notes.sqlite"), "unrelated data must survive");
        // A region-shaped name inside tiles/ is not top-level and must survive.
        assert!(dir.join("tiles").join("us-ca.sqlite").exists(),
                "the purge must not recurse into subdirectories");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ordinal_word_expands_to_numeric_and_back() {
        assert_eq!(token_equivalents("sixth"), vec!["sixth", "6th"]);
        assert_eq!(token_equivalents("6th"), vec!["6th", "sixth"]);
        assert_eq!(token_equivalents("first"), vec!["first", "1st"]);
        assert_eq!(token_equivalents("twentieth"), vec!["twentieth", "20th"]);
        assert_eq!(token_equivalents("hundredth"), vec!["hundredth", "100th"]);
    }

    #[test]
    fn street_type_abbreviation_expands_both_ways() {
        assert_eq!(token_equivalents("st"), vec!["st", "street"]);
        assert_eq!(token_equivalents("street"), vec!["street", "st"]);
        assert_eq!(token_equivalents("ave"), vec!["ave", "avenue"]);
    }

    #[test]
    fn plain_token_has_no_equivalents() {
        assert_eq!(token_equivalents("2122"), vec!["2122"]);
        assert_eq!(token_equivalents("ceres"), vec!["ceres"]);
    }

    #[test]
    fn needs_word_boundary_only_for_numeric_ordinals() {
        assert!(needs_word_boundary("6th"));
        assert!(needs_word_boundary("1st"));
        assert!(needs_word_boundary("21st"));
        assert!(needs_word_boundary("103rd"));
        // spelled-out ordinals aren't substrings of bigger ordinals
        assert!(!needs_word_boundary("sixth"));
        // plain words / numbers / house numbers
        assert!(!needs_word_boundary("street"));
        assert!(!needs_word_boundary("2122"));
        assert!(!needs_word_boundary("st"));
        assert!(!needs_word_boundary("north")); // ends in "th" but no digits
    }

    /// Build an in-memory cities tier holding `rows` of
    /// (geoname_id, name, country_code, population).
    fn city_tier(rows: &[(i64, &str, &str, i64)]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE cities (
                 geoname_id INTEGER PRIMARY KEY, name TEXT, ascii_name TEXT,
                 country_code TEXT, admin1 TEXT, population INTEGER,
                 lat REAL, lng REAL, tile_id TEXT, tile_ids TEXT, has_shard INTEGER);
             CREATE VIRTUAL TABLE cities_fts USING fts5(name, ascii_name);",
        )
        .unwrap();
        for (id, name, cc, pop) in rows {
            conn.execute(
                "INSERT INTO cities (geoname_id, name, ascii_name, country_code, admin1,
                                     population, lat, lng, tile_id, tile_ids, has_shard)
                 VALUES (?1, ?2, ?2, ?3, '', ?4, 0.0, 0.0, 'aaaa', '', 0)",
                rusqlite::params![id, name, cc, pop],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cities_fts (rowid, name, ascii_name) VALUES (?1, ?2, ?2)",
                rusqlite::params![id, name],
            )
            .unwrap();
        }
        conn
    }

    /// Clearing the cache must take every tile family, not only `tile_*`:
    /// the enriched POI tiles and the per-city `addr/` shards are between
    /// them the bulk of the cached bytes, and must not survive a clear that
    /// reports success.
    #[test]
    fn clear_cache_takes_poi_tiles_and_city_shards_too() {
        let dir = std::env::temp_dir().join(format!("pgn_clear_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("addr")).unwrap();
        let mk = |p: std::path::PathBuf| std::fs::write(p, b"x").unwrap();
        // every tile family — must go
        mk(dir.join("tile_9q9y.sqlite"));
        mk(dir.join("tile_9q9y.meta"));
        mk(dir.join("poi_9q9y.sqlite"));
        mk(dir.join("poi_9q9y.meta"));
        mk(dir.join("addr").join("5325738.sqlite"));
        // not tiles — must stay
        mk(dir.join("manifest-v4.json"));
        mk(dir.join("cities-tier1.sqlite"));

        let geocoder = TileGeocoder::new(dir.to_str().unwrap().to_string());
        geocoder.clear_cache().unwrap();

        assert!(!dir.join("tile_9q9y.sqlite").exists(), "address tile must go");
        assert!(!dir.join("tile_9q9y.meta").exists(), "address tile sidecar must go");
        assert!(!dir.join("poi_9q9y.sqlite").exists(), "POI tile must go");
        assert!(!dir.join("poi_9q9y.meta").exists(), "POI tile sidecar must go");
        assert!(
            !dir.join("addr").join("5325738.sqlite").exists(),
            "per-city shard must go"
        );
        assert!(dir.join("manifest-v4.json").exists(), "the manifest is not a tile");
        assert!(
            dir.join("cities-tier1.sqlite").exists(),
            "city tiers belong to CityIndex::clear_cache, not here"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The country tier is consulted BEFORE the global cascade, so leaving it
    /// behind would let a "cleared" index still answer from cached city data:
    /// `clear_cache` takes both its file and its loaded slot.
    #[test]
    fn clear_cache_takes_the_country_tier_too() {
        let dir = std::env::temp_dir().join(format!("pgn_cityclear_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in [
            "cities-tier1.sqlite",
            "cities-tier2.sqlite",
            "cities-tier3.sqlite",
            "cities-country.sqlite",
        ] {
            std::fs::write(dir.join(n), b"x").unwrap();
        }

        let idx = CityIndex::new(dir.to_str().unwrap().to_string());
        *idx.country_tier.lock().unwrap() = Some(city_tier(&[(1, "Delhi", "US", 11_000)]));

        idx.clear_cache().unwrap();

        assert!(
            !dir.join("cities-country.sqlite").exists(),
            "the country tier file must go"
        );
        assert!(!dir.join("cities-tier1.sqlite").exists(), "tier 1 must go");
        assert!(!dir.join("cities-tier3.sqlite").exists(), "tier 3 must go");
        assert!(
            idx.country_tier.lock().unwrap().is_none(),
            "the loaded country slot must be dropped, not just its file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Delhi case: a US-locale device loads the US country tier, which
    /// contains Delhi, CA (pop 11k). Delhi, IN (pop 10M) lives in tier 1.
    /// Filling from the country tier first makes the big city unreachable.
    #[test]
    fn search_ranks_across_tiers_not_country_tier_first() {
        let idx = CityIndex::new("/tmp/pingolin-test-cityindex".to_string());
        *idx.country_tier.lock().unwrap() = Some(city_tier(&[(1, "Delhi", "US", 11_000)]));
        *idx.tier1.lock().unwrap() = Some(city_tier(&[(2, "Delhi", "IN", 10_000_000)]));

        let out = idx.search("delhi".to_string(), 3);
        assert_eq!(out.len(), 2, "both tiers must contribute");
        assert_eq!(out[0].country_code, "IN", "the 10M city must outrank the 11k one");
        assert_eq!(out[1].country_code, "US");
    }

    /// Even at limit=1, the shape where the locale tier can take the only
    /// slot, the ranking has to be able to overrule it.
    #[test]
    fn search_at_limit_one_still_prefers_the_larger_city() {
        let idx = CityIndex::new("/tmp/pingolin-test-cityindex".to_string());
        *idx.country_tier.lock().unwrap() = Some(city_tier(&[(1, "Delhi", "US", 11_000)]));
        *idx.tier1.lock().unwrap() = Some(city_tier(&[(2, "Delhi", "IN", 10_000_000)]));

        let out = idx.search("delhi".to_string(), 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].country_code, "IN");
    }

    /// Locale preference survives a genuine tie: equal population keeps
    /// tier order, and the country tier is queried first.
    #[test]
    fn search_keeps_locale_first_on_a_population_tie() {
        let idx = CityIndex::new("/tmp/pingolin-test-cityindex".to_string());
        *idx.country_tier.lock().unwrap() = Some(city_tier(&[(1, "Springfield", "US", 50_000)]));
        *idx.tier1.lock().unwrap() = Some(city_tier(&[(2, "Springfield", "NZ", 50_000)]));

        let out = idx.search("springfield".to_string(), 5);
        assert_eq!(out[0].country_code, "US", "stable sort must keep the locale tier first");
    }

    /// The country tier duplicates rows that also exist in the globals;
    /// the same city must not appear twice.
    #[test]
    fn search_dedupes_the_same_city_across_tiers() {
        let idx = CityIndex::new("/tmp/pingolin-test-cityindex".to_string());
        *idx.country_tier.lock().unwrap() = Some(city_tier(&[(7, "Austin", "US", 960_000)]));
        *idx.tier1.lock().unwrap() = Some(city_tier(&[(7, "Austin", "US", 960_000)]));

        let out = idx.search("austin".to_string(), 5);
        assert_eq!(out.len(), 1, "same geoname_id must collapse");
    }
}

// ============================================================================
// City index for forward-geocoding hints
// ============================================================================
//
// The TileGeocoder can only forward-search inside tiles already on disk —
// good for "nearby" addresses but useless when the user wants to add a Place
// in a city they've never opened on the map. The CityIndex closes that gap
// without leaking the user's query to the server: small SQLite files of
// city names → (centroid lat/lng, tile_id) ship from the same CDN as the
// tiles. The user types a city name; we look it up locally; the matching
// city's centroid tile_id tells the TileGeocoder exactly which 1 tile to
// fetch. Privacy-equivalent to current reverse-geocoding traffic.
//
// Tiered design:
//   tier 1 — cities5000 (≥5K population, ~50K rows, ~3 MB compressed).
//            Lazy-fetched on the first forward-geocoding search. Covers the
//            vast majority of place-creation queries.
//   tier 2 — cities1000 *delta* over tier 1 (1K–5K population, ~100K rows,
//            ~1 MB compressed). Lazy-fetched only when tier 1 misses on a
//            non-empty query. Stores rows whose geoname_id is NOT in tier 1,
//            so the two databases never overlap.
//   tier 3 — cities500 delta over tiers 1 and 2 (unincorporated communities
//            and small towns, ≥500 population). Lazy-fetched only after a
//            tier 2 miss.
//   country — one file holding the tier 1–3 rows of a single country (the
//            user's locale country), loaded ahead of the global cascade.
//
// Any tier may be missing on disk — `search()` queries whichever tiers
// are loaded and returns whatever's there. Callers (Android / iOS) decide
// when to call `ensure_tier1`/`ensure_tier2`/`ensure_tier3`/
// `ensure_country_tier` based on user activity.

/// Result row for a city/town lookup.
///
/// `tile_id` is the geohash of the city's centroid as known to the matching
/// `TileGeocoder` manifest — callers pass it back into the tile geocoder
/// (which auto-downloads the tile) to refine the search to street level.
#[derive(Clone, Debug, uniffi::Record)]
pub struct CityResult {
    /// GeoNames numeric ID. Stable across cities-tier rebuilds and used
    /// to address per-city addr+POI shards on the CDN
    /// (`<base_url>/addr/<geoname_id>.sqlite.zst`).
    pub geoname_id: i64,
    pub name: String,
    pub ascii_name: String,
    pub country_code: String,
    pub admin1: String,
    pub population: i64,
    pub lat: f64,
    pub lng: f64,
    pub tile_id: String,
    /// Tile IDs that overlap this city's extent, ordered by distance
    /// from the centroid and capped at the build-time max. Lets the
    /// smart-fallback load only the tiles the city actually occupies
    /// instead of the full centroid + 8 geohash neighbors fan-out.
    /// Empty when no manifest tiles intersect the extent (fall back
    /// to centroid + 8 neighbors).
    pub tile_ids: Vec<String>,
    /// True when this city has a per-city addr+POI shard at the CDN
    /// (`addr/<geoname_id>.sqlite.zst`). Lets the smart-fallback skip
    /// the shard-fetch round-trip for cities that wouldn't have one
    /// anyway and go straight to the tile_ids fallback.
    pub has_shard: bool,
}

/// Local city-name → coordinates index, used as a privacy-preserving "where
/// is this address?" hint before pulling a street-level tile.
///
/// Privacy guarantee: the actual address query never touches the network.
/// The only network traffic is static, version-pinned file downloads from
/// the geocoding CDN, indistinguishable across users. Once the tiers are
/// cached, address search is fully offline.
#[derive(uniffi::Object)]
pub struct CityIndex {
    storage_path: String,
    tier1: Arc<Mutex<Option<Connection>>>,
    tier2: Arc<Mutex<Option<Connection>>>,
    /// Tier 3 = unincorporated communities & small towns (≥500 pop)
    /// not in tier 1 or tier 2. Lazy-fetched only after a tier 2 miss.
    /// Lets queries like "Hickman, CA" (pop ~700) resolve to the right
    /// city instead of the larger same-name Hickmans in KY / NE.
    tier3: Arc<Mutex<Option<Connection>>>,
    /// Per-country fast-path slot — contains tier1+2+3 rows for ONE
    /// country (the user's locale country) in a single SQLite. Loaded
    /// before the global cascade so a typical "user searches their
    /// own country" query resolves with one ~500 KB-2 MB download
    /// instead of cascading through ~15 MB of global tiers.
    country_tier: Arc<Mutex<Option<Connection>>>,
    /// Shared HTTP client — same connection pool across tier downloads.
    client: reqwest::Client,
}

// Private impl
impl CityIndex {
    fn tier_filename(tier: u8) -> &'static str {
        match tier {
            1 => "cities-tier1.sqlite",
            2 => "cities-tier2.sqlite",
            3 => "cities-tier3.sqlite",
            _ => unreachable!("tier must be 1, 2, or 3"),
        }
    }

    fn tier_path(&self, tier: u8) -> std::path::PathBuf {
        Path::new(&self.storage_path).join(Self::tier_filename(tier))
    }

    /// Disk path for the per-country fast-path file. It is not part of the
    /// numbered tier family — `tier_path` panics on anything but 1/2/3 — so it
    /// needs its own accessor, shared by the loader and the cache clear so the
    /// two can't name different files.
    fn country_tier_path(&self) -> std::path::PathBuf {
        Path::new(&self.storage_path).join("cities-country.sqlite")
    }

    /// Open a tier's SQLite if its file is on disk. Idempotent — if already
    /// loaded into the slot, returns true without reopening.
    fn try_load_tier(&self, tier: u8) -> bool {
        let slot = match tier {
            1 => &self.tier1,
            2 => &self.tier2,
            3 => &self.tier3,
            _ => return false,
        };
        if slot.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            return true;
        }
        let path = self.tier_path(tier);
        if !path.exists() {
            return false;
        }
        match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => {
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn);
                tracing::debug!("CityIndex tier {} loaded from disk", tier);
                true
            }
            Err(e) => {
                tracing::warn!("CityIndex tier {} load failed: {}", tier, e);
                false
            }
        }
    }

    /// Download a tier blob from the given URL and decompress into the on-
    /// disk slot. zstd-compressed to match the tile pipeline.
    fn download_tier(
        &self,
        tier: u8,
        url: &str,
        rt: &tokio::runtime::Runtime,
    ) -> Result<(), MobileError> {
        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            std::fs::create_dir_all(storage_dir)
                .map_err(|e| MobileError::StorageError(e.to_string()))?;
        }

        let client = &self.client;
        let mut last_err = None;
        let bytes = rt.block_on(async {
            for attempt in 1..=3 {
                match client.get(url).send().await {
                    Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                        Ok(b) => return Ok(b),
                        Err(e) => {
                            tracing::warn!(
                                "CityIndex tier {} attempt {}/3: body read failed: {:?}",
                                tier, attempt, e
                            );
                            last_err = Some(format!("{:?}", e));
                        }
                    },
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::warn!(
                            "CityIndex tier {} attempt {}/3: HTTP {}",
                            tier, attempt, status
                        );
                        last_err = Some(format!("HTTP {}", status));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "CityIndex tier {} attempt {}/3: request failed: {:?}",
                            tier, attempt, e
                        );
                        last_err = Some(format!("{:?}", e));
                    }
                }
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64))
                        .await;
                }
            }
            Err(MobileError::NetworkError(
                last_err.unwrap_or_else(|| "unknown error".to_string()),
            ))
        })?;

        let decompressed = zstd::decode_all(bytes.as_ref())
            .map_err(|e| MobileError::StorageError(format!("Decompression failed: {}", e)))?;

        let path = self.tier_path(tier);
        // Write to a `.tmp` then rename so a partial failure doesn't leave a
        // half-written file the next try_load_tier would happily open and
        // then fail every query against.
        let tmp = path.with_extension("sqlite.tmp");
        std::fs::write(&tmp, &decompressed)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        tracing::info!(
            "CityIndex tier {} downloaded: {} bytes",
            tier,
            decompressed.len()
        );
        Ok(())
    }

    fn ensure_tier(&self, tier: u8, url: &str) -> Result<(), MobileError> {
        if self.try_load_tier(tier) {
            return Ok(());
        }
        let rt = crate::location::get_shared_runtime();
        self.download_tier(tier, url, rt)?;
        if !self.try_load_tier(tier) {
            return Err(MobileError::StorageError(format!(
                "Tier {} downloaded but failed to open",
                tier
            )));
        }
        Ok(())
    }

    /// Zero-result fallback: scan a tier's names for close spellings.
    ///
    /// Only ever called when the FTS query returned nothing, so it cannot
    /// displace a real match — it turns "no results" into "probably this".
    /// A tier is tens of thousands of rows (52,440 across all of them), so a
    /// bounded OSA pass over the names is milliseconds and needs no index.
    ///
    /// Compared against `ascii_name` as well as `name`, because the query has
    /// already been folded to ASCII by the caller and "Zurich" must reach
    /// "Zürich".
    fn search_tier_fuzzy(conn: &Connection, query: &str, limit: u32) -> Vec<CityResult> {
        let q = query.trim().to_lowercase();
        let budget = typo_budget(q.chars().count());
        if budget == 0 {
            return Vec::new();
        }
        let mut stmt = match conn.prepare("SELECT geoname_id, name, ascii_name FROM cities") {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("CityIndex fuzzy prepare failed: {}", e);
                return Vec::new();
            }
        };
        let rows = match stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        }) {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!("CityIndex fuzzy query failed: {}", e);
                return Vec::new();
            }
        };
        // (distance, id) — keep the closest few, then fetch them in full.
        let mut hits: Vec<(usize, i64)> = Vec::new();
        for row in rows.flatten() {
            let (id, name, ascii) = row;
            let d = osa_distance_within(&q, &name.to_lowercase(), budget)
                .into_iter()
                .chain(osa_distance_within(&q, &ascii.to_lowercase(), budget))
                .min();
            if let Some(d) = d {
                hits.push((d, id));
            }
        }
        if hits.is_empty() {
            return Vec::new();
        }
        // Closest first; population breaks ties once the rows are loaded.
        hits.sort_by_key(|(d, _)| *d);
        hits.truncate(limit as usize * 4);
        let ids: Vec<String> = hits.iter().map(|(_, id)| id.to_string()).collect();
        let sql = format!(
            "SELECT c.geoname_id, c.name, c.ascii_name, c.country_code, c.admin1, \
                    c.population, c.lat, c.lng, c.tile_id, COALESCE(c.tile_ids, ''), \
                    COALESCE(c.has_shard, 0) \
             FROM cities c WHERE c.geoname_id IN ({}) \
             ORDER BY c.population DESC LIMIT {}",
            ids.join(","),
            limit
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("CityIndex fuzzy fetch failed: {}", e);
                return Vec::new();
            }
        };
        let out = stmt.query_map([], |row| {
            let tile_ids_csv: String = row.get(9).unwrap_or_default();
            let has_shard_int: i64 = row.get(10).unwrap_or(0);
            Ok(CityResult {
                geoname_id: row.get(0)?,
                name: row.get(1)?,
                ascii_name: row.get(2)?,
                country_code: row.get(3)?,
                admin1: row.get(4)?,
                population: row.get(5)?,
                lat: row.get(6)?,
                lng: row.get(7)?,
                tile_id: row.get(8)?,
                tile_ids: if tile_ids_csv.is_empty() {
                    Vec::new()
                } else {
                    tile_ids_csv.split(',').map(str::to_string).collect()
                },
                has_shard: has_shard_int != 0,
            })
        });
        match out {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Run a city query against a single tier connection. The FTS5 table is
    /// `cities_fts(name, ascii_name, alt_names, admin1, country_code)`; each
    /// word of the query is one quoted term (`city_match_expr`). Results sort
    /// by population so "Paris, France" beats "Paris, TX" for an unqualified
    /// query.
    fn search_tier(conn: &Connection, query: &str, limit: u32) -> Vec<CityResult> {
        let Some(match_expr) = city_match_expr(query) else {
            return Vec::new();
        };

        let mut stmt = match conn.prepare(
            r#"
            SELECT c.geoname_id, c.name, c.ascii_name, c.country_code,
                   c.admin1, c.population, c.lat, c.lng, c.tile_id,
                   COALESCE(c.tile_ids, ''),
                   COALESCE(c.has_shard, 0)
            FROM cities_fts f
            JOIN cities c ON c.geoname_id = f.rowid
            WHERE cities_fts MATCH ?1
            ORDER BY c.population DESC
            LIMIT ?2
            "#,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("CityIndex search prepare failed: {}", e);
                return Vec::new();
            }
        };

        let rows = stmt.query_map(rusqlite::params![match_expr, limit], |row| {
            let tile_ids_csv: String = row.get(9).unwrap_or_default();
            let has_shard_int: i64 = row.get(10).unwrap_or(0);
            Ok(CityResult {
                geoname_id: row.get(0)?,
                name: row.get(1)?,
                ascii_name: row.get(2)?,
                country_code: row.get(3)?,
                admin1: row.get(4)?,
                population: row.get(5)?,
                lat: row.get(6)?,
                lng: row.get(7)?,
                tile_id: row.get(8)?,
                tile_ids: if tile_ids_csv.is_empty() {
                    Vec::new()
                } else {
                    tile_ids_csv.split(',').map(str::to_string).collect()
                },
                has_shard: has_shard_int != 0,
            })
        });

        match rows {
            Ok(it) => it.filter_map(Result::ok).collect(),
            Err(e) => {
                tracing::warn!("CityIndex search failed: {}", e);
                Vec::new()
            }
        }
    }
}

#[uniffi::export]
impl CityIndex {
    /// Create a new city index rooted at `storage_path`. Files persist
    /// across launches, so subsequent constructions reuse downloaded data.
    #[uniffi::constructor]
    pub fn new(storage_path: String) -> Self {
        let me = Self {
            storage_path,
            tier1: Arc::new(Mutex::new(None)),
            tier2: Arc::new(Mutex::new(None)),
            tier3: Arc::new(Mutex::new(None)),
            country_tier: Arc::new(Mutex::new(None)),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        };
        // Warm every slot from disk if its file is already cached. Free.
        me.try_load_tier(1);
        me.try_load_tier(2);
        me.try_load_tier(3);
        // Country slot is fed only via ensure_country_tier — its file
        // path is locale-dependent so we can't blind-load it here.
        me
    }

    /// Whether tier 1 (cities5000) is currently available locally.
    pub fn is_tier1_loaded(&self) -> bool {
        self.tier1.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Whether tier 2 (cities1000-delta) is currently available locally.
    pub fn is_tier2_loaded(&self) -> bool {
        self.tier2.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Whether tier 3 (cities500-delta over tier 1+2) is loaded.
    pub fn is_tier3_loaded(&self) -> bool {
        self.tier3.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Ensure tier 1 is on disk and loaded. Downloads from `url` if not.
    /// Call this lazily when the user first opens the address-search UI.
    pub fn ensure_tier1(&self, url: String) -> Result<(), MobileError> {
        self.ensure_tier(1, &url)
    }

    /// Ensure tier 2 is on disk and loaded. Call this only after tier 1
    /// has returned no matches for a non-empty query — paying for tier 2
    /// when most users will never need it would waste bandwidth.
    pub fn ensure_tier2(&self, url: String) -> Result<(), MobileError> {
        self.ensure_tier(2, &url)
    }

    /// Ensure tier 3 is on disk and loaded. Call this only after tier 2
    /// has returned no matches for a non-empty query — small-community
    /// data is the rarest miss path, so the bandwidth cost should land
    /// on the few users who actually type one in.
    pub fn ensure_tier3(&self, url: String) -> Result<(), MobileError> {
        self.ensure_tier(3, &url)
    }

    /// Whether the per-country fast-path tier is loaded.
    pub fn is_country_tier_loaded(&self) -> bool {
        self.country_tier.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Ensure the per-country fast-path file is on disk and loaded.
    /// `url` is `<base>/cities/by-country/<cc>.sqlite.zst`. Returns
    /// `Ok(false)` on a soft miss (404 — country has no file) so the
    /// caller can fall through to the global tier cascade. Idempotent.
    pub fn ensure_country_tier(&self, url: String) -> Result<bool, MobileError> {
        if self.is_country_tier_loaded() {
            return Ok(true);
        }
        tracing::info!("ensure_country_tier: not loaded, resolving");
        let path = self.country_tier_path();
        if path.exists() {
            // Already on disk from a prior session.
            match Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
                Ok(conn) => {
                    *self.country_tier.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn);
                    return Ok(true);
                }
                Err(e) => {
                    tracing::warn!("country tier load failed: {}", e);
                    // Fall through to re-download.
                    let _ = std::fs::remove_file(&path);
                }
            }
        }

        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            std::fs::create_dir_all(storage_dir)
                .map_err(|e| MobileError::StorageError(e.to_string()))?;
        }
        let rt = crate::location::get_shared_runtime();
        let client = &self.client;
        let resp_or_404: Option<Vec<u8>> = rt.block_on(async {
            match client.get(&url).send().await {
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    Ok::<Option<Vec<u8>>, MobileError>(None)
                }
                Ok(r) if r.status().is_success() => r
                    .bytes()
                    .await
                    .map(|b| Some(b.to_vec()))
                    .map_err(|e| MobileError::NetworkError(format!("{:?}", e))),
                Ok(r) => Err(MobileError::NetworkError(format!("HTTP {}", r.status()))),
                Err(e) => Err(MobileError::NetworkError(format!("{:?}", e))),
            }
        })?;
        let Some(bytes) = resp_or_404 else {
            tracing::debug!("country tier 404 at {}, soft miss", url);
            return Ok(false);
        };
        let decompressed = zstd::decode_all(bytes.as_slice())
            .map_err(|e| MobileError::StorageError(format!("Decompression failed: {}", e)))?;
        std::fs::write(&path, &decompressed)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MobileError::StorageError(e.to_string()))?;
        *self.country_tier.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn);
        tracing::debug!(
            "country tier loaded ({} bytes decompressed) from {}",
            decompressed.len(),
            url
        );
        Ok(true)
    }

    /// Search every loaded tier for cities matching `query`. Returns up
    /// to `limit` results, ranked by population ACROSS tiers. De-duped by
    /// geoname_id (each global tier excludes higher tiers' IDs at build
    /// time, but the country tier's rows overlap with the globals).
    ///
    /// Every loaded tier is queried in full and the union is ranked. The
    /// obvious cheaper shape — fill from the country tier, then top up
    /// from tier 1 only if slots remain — is what makes `"delhi"` from a
    /// US device return Delhi, CA and never Delhi, IN: the locale tier
    /// fills every slot, so the population ordering `search_tier`
    /// carefully applies cannot see across tiers to overrule it.
    ///
    /// The sort is stable, so cities with equal population keep tier
    /// order — the locale's own file still wins a genuine tie.
    pub fn search(&self, query: String, limit: u32) -> Vec<CityResult> {
        let mut combined = Vec::new();
        // Which tiers are actually open. A city hint that resolves nowhere looks
        // identical from the UI whether the index had NO tier loaded or simply
        // held no match — and those are opposite faults (a load/plumbing failure
        // versus a data one). Logged once per city lookup, without the query text.
        let tiers_open = |slot: &Mutex<Option<Connection>>| -> bool {
            slot.lock().map(|g| g.is_some()).unwrap_or(false)
        };
        tracing::info!(
            country = tiers_open(&self.country_tier),
            tier1 = tiers_open(&self.tier1),
            tier2 = tiers_open(&self.tier2),
            tier3 = tiers_open(&self.tier3),
            tokens = query.split_whitespace().count(),
            "CityIndex::search"
        );
        let mut seen_ids: std::collections::HashSet<i64> =
            std::collections::HashSet::new();
        // Country tier first so it wins ties; the others still get asked.
        let slots = [&self.country_tier, &self.tier1, &self.tier2, &self.tier3];
        for slot in slots {
            if let Some(conn) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                // Ask each tier for a full page, not just the shortfall —
                // a tier's best row has to be able to outrank one already
                // collected from an earlier tier.
                for r in Self::search_tier(conn, &query, limit) {
                    if seen_ids.insert(r.geoname_id) {
                        combined.push(r);
                    }
                }
            }
        }
        // A qualifier the index does not hold must not empty the list: "Paris,
        // France" asks for a row carrying "france", and none does (the country
        // is "FR"). Then the part before the first comma is the place, but only
        // when it names a bigger town than the part after it does:
        // - "Portland, Oregon": Portland is bigger than Oregon City, so
        //   "Oregon" qualifies it.
        // - "Hollywood, Los Angeles": Los Angeles is bigger than Hollywood, FL,
        //   so Hollywood is a place IN Los Angeles. The list stays empty and the
        //   apps go on to search Los Angeles's own tiles for it; a town row
        //   would stop them, since their SmartSearch returns as soon as the
        //   town index answers.
        // Decided over all tiers together, so "Paris, TX" found in the country
        // tier is never joined by the Paris, France that tier 1 would fall back
        // to.
        if combined.is_empty() {
            if let Some((place, qualifier)) = query.split_once(',') {
                let mut places = Vec::new();
                let mut qualifier_top = 0;
                for slot in slots {
                    if let Some(conn) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                        places.extend(Self::search_tier(conn, place, limit));
                        // Sorted by population: the first row is the biggest.
                        if let Some(top) = Self::search_tier(conn, qualifier, 1).first() {
                            qualifier_top = qualifier_top.max(top.population);
                        }
                    }
                }
                if places.iter().any(|r| r.population > qualifier_top) {
                    for r in places {
                        if seen_ids.insert(r.geoname_id) {
                            combined.push(r);
                        }
                    }
                }
            }
        }
        // Typo fallback, and ONLY that: it runs when the exact pass found
        // nothing at all, so a real match is never displaced by a guess.
        // "modseto" is a transposition away from Modesto and would otherwise
        // return an empty list.
        if combined.is_empty() {
            for slot in slots {
                if let Some(conn) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                    for r in Self::search_tier_fuzzy(conn, &query, limit) {
                        if seen_ids.insert(r.geoname_id) {
                            combined.push(r);
                        }
                    }
                }
            }
        }
        combined.sort_by(|a, b| b.population.cmp(&a.population));
        combined.truncate(limit as usize);
        tracing::info!(rows = combined.len(), "CityIndex::search done");
        combined
    }

    /// Drop every tier file from disk and from memory — the three global tiers
    /// AND the per-country fast-path file. Useful for "Clear cache" in
    /// Settings → Storage.
    pub fn clear_cache(&self) -> Result<(), MobileError> {
        *self.tier1.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.tier2.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.tier3.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // The country slot is loaded ahead of the global cascade, so leaving it
        // behind means a "cleared" cache still answers from cached city data.
        *self.country_tier.lock().unwrap_or_else(|e| e.into_inner()) = None;
        for path in [
            self.tier_path(1),
            self.tier_path(2),
            self.tier_path(3),
            self.country_tier_path(),
        ] {
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| MobileError::StorageError(e.to_string()))?;
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod hyphen_boundary_tests {
    use super::*;

    /// "in n out" finds nothing without the fold: the indexed name separates
    /// its words with hyphens, so the space-delimited word-boundary pattern
    /// for the single-letter token never matches.
    #[test]
    fn a_single_letter_token_matches_across_a_hyphen() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE poi_index (tile_id TEXT, poi_norm TEXT);
             INSERT INTO poi_index VALUES ('9q9y','in-n-out burger');
             INSERT INTO poi_index VALUES ('9q9y','burger king');",
        )
        .unwrap();
        let col = wb_col("poi_norm");
        let sql = format!(
            "SELECT count(*) FROM poi_index \
             WHERE poi_norm LIKE ?1 \
               AND ({c} LIKE ?2 OR {c} LIKE ?3 OR {c} LIKE ?4) \
               AND poi_norm LIKE ?5",
            c = col
        );
        let n: i64 = conn
            .query_row(&sql, rusqlite::params!["%in%", "% n %", "n %", "% n", "%out%"], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "in-n-out burger must match the tokens in / n / out");
    }

    /// The fold must not make a boundary token match INSIDE a word, which is
    /// the whole reason boundaries exist.
    #[test]
    fn folding_hyphens_does_not_match_mid_word() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE poi_index (tile_id TEXT, poi_norm TEXT);
             INSERT INTO poi_index VALUES ('x','antinuclear centre');",
        )
        .unwrap();
        let col = wb_col("poi_norm");
        let sql = format!(
            "SELECT count(*) FROM poi_index WHERE ({c} LIKE ?1 OR {c} LIKE ?2 OR {c} LIKE ?3)",
            c = col
        );
        let n: i64 = conn
            .query_row(&sql, rusqlite::params!["% n %", "n %", "% n"], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "'n' must not match inside 'antinuclear'");
    }
}

#[cfg(test)]
mod typo_tests {
    use super::*;

    /// A dropped letter — the common shape. Nothing else tolerates it, so the
    /// fuzzy pass is the only thing that can match it.
    #[test]
    fn a_dropped_letter_is_one_edit() {
        assert_eq!(osa_distance_within("starbcks", "starbucks", 2), Some(1));
    }

    /// Why OSA and not plain Levenshtein: a transposition is one of the most
    /// common typos, and plain Levenshtein charges two for it.
    #[test]
    fn a_transposition_costs_one_not_two() {
        assert_eq!(osa_distance_within("modseto", "modesto", 2), Some(1));
    }

    #[test]
    fn unrelated_words_are_rejected_within_budget() {
        assert_eq!(osa_distance_within("starbcks", "walmart", 2), None);
        assert_eq!(osa_distance_within("modseto", "stockton", 2), None);
    }

    /// The budget must not fire on short input, where almost everything is
    /// one edit from something else.
    #[test]
    fn short_queries_get_no_typo_budget() {
        assert_eq!(typo_budget(3), 0);
        assert_eq!(typo_budget(4), 1);
        assert_eq!(typo_budget(6), 1);
        assert_eq!(typo_budget(7), 2);
        // "mart" -> "cart" is one edit; the budget allows it only because the
        // fallback runs when nothing matched at all.
        assert_eq!(osa_distance_within("mart", "cart", 1), Some(1));
    }

    /// Apostrophes are deleted, not split, matching the exact path's
    /// normalisation — so "togos" is one edit from "Togo's", not three.
    #[test]
    fn apostrophe_normalisation_keeps_possessives_close() {
        let norm = "Togo's".to_lowercase().replace('\'', "");
        assert_eq!(norm, "togos");
        assert_eq!(osa_distance_within("togo", &norm, 1), Some(1));
    }

    /// Early abandonment must not change the answer, only the cost.
    #[test]
    fn a_too_small_budget_returns_none_not_a_wrong_distance() {
        assert_eq!(osa_distance_within("starbcks", "starbucks", 0), None);
        assert_eq!(osa_distance_within("kitten", "sitting", 2), None);
        assert_eq!(osa_distance_within("kitten", "sitting", 3), Some(3));
    }

    #[test]
    fn empty_and_length_mismatch_are_handled() {
        assert_eq!(osa_distance_within("", "", 0), Some(0));
        assert_eq!(osa_distance_within("abc", "", 2), None);
        assert_eq!(osa_distance_within("abc", "", 3), Some(3));
    }
}

#[cfg(test)]
mod proximity_tests {
    use super::*;

    fn tile_with(rows: &[(&str, f64, f64)]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
               city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
               source TEXT, housenumber TEXT, street TEXT);",
        )
        .unwrap();
        for (n, la, ln) in rows {
            conn.execute(
                "INSERT INTO pois(name,city,state,country,lat,lng,source) \
                 VALUES(?1,'Modesto','CA','USA',?2,?3,'osm')",
                rusqlite::params![n, la, ln],
            )
            .unwrap();
        }
        conn
    }

    /// The case this exists for: with a LIMIT smaller than the match count and
    /// no ordering, the rows returned are an arbitrary slice — which the
    /// caller's viewport clamp then throws away.
    #[test]
    fn a_limit_returns_the_nearest_rows_not_an_arbitrary_slice() {
        // Inserted far-first so rowid order is the WRONG order.
        let conn = tile_with(&[
            ("Starbucks", 45.0, -122.0),   // Portland, ~1000 km
            ("Starbucks", 40.0, -120.0),   // ~270 km
            ("Starbucks", 37.6400, -120.9970), // Modesto, ~10 m
        ]);
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let limit: i64 = 1;
        let binds: Vec<&dyn rusqlite::ToSql> = vec![&limit];
        query_pois_table(&conn, "1=1", &binds, &mut results, &mut seen,
                         Some((37.6391, -120.9969)));
        assert_eq!(results.len(), 1);
        assert!((results[0].lat - 37.6400).abs() < 1e-6,
                "expected the Modesto row, got lat {}", results[0].lat);
    }

    /// No focus means no ORDER BY clause at all, so a caller with no proximity
    /// context pays nothing for it.
    #[test]
    fn no_focus_means_no_ordering_clause() {
        assert_eq!(order_by_distance(None), "");
        assert!(order_by_distance(Some((37.6391, -120.9969))).contains("ORDER BY"));
    }

    /// Longitude must be scaled by cos(lat), or the ordering skews east-west
    /// away from the equator.
    #[test]
    fn longitude_is_weighted_by_latitude() {
        // At 60N a degree of longitude is about half a degree of latitude.
        let far_north = order_by_distance(Some((60.0, 0.0)));
        assert!(far_north.contains("0.500000"), "expected cos(60)=0.5 scaling, got {far_north}");
        // At the equator it is unscaled.
        assert!(order_by_distance(Some((0.0, 0.0))).contains("1.000000"));
    }

    /// A pole must not collapse the longitude term to zero and make every
    /// meridian equidistant.
    #[test]
    fn the_pole_does_not_divide_the_world_into_one_column() {
        let polar = order_by_distance(Some((90.0, 0.0)));
        assert!(polar.contains("0.010000"), "expected the clamp, got {polar}");
    }
}

#[cfg(test)]
mod fuzzy_poi_tests {
    use super::*;

    /// The fallback must return the NEAREST close-spelling, not an arbitrary
    /// one: unordered, a far-away match can come back while a nearby branch
    /// goes unmentioned, and the caller's viewport clamp then deletes the
    /// lot.
    #[test]
    fn the_typo_fallback_returns_the_nearest_match_first() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
               city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
               source TEXT, housenumber TEXT, street TEXT);",
        )
        .unwrap();
        // Inserted far-first so rowid order is the wrong order.
        for (la, ln) in [(37.7861, -121.2539), (37.7119, -120.9579), (37.6399, -121.0008)] {
            conn.execute(
                "INSERT INTO pois(name,city,state,country,lat,lng,source) \
                 VALUES('Starbucks','Modesto','CA','USA',?1,?2,'osm')",
                rusqlite::params![la, ln],
            )
            .unwrap();
        }
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        fuzzy_pois_in_tile(&conn, "starbcks", 8, &mut results, &mut seen,
                           Some((37.6391, -120.9969)));
        assert!(!results.is_empty(), "typo must still match");
        assert!((results[0].lat - 37.6399).abs() < 1e-6,
                "nearest must lead, got lat {}", results[0].lat);
    }

    #[test]
    fn a_typo_finds_the_poi_when_the_exact_pass_found_nothing() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
               city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
               source TEXT, housenumber TEXT, street TEXT);
             INSERT INTO pois(name,city,state,country,lat,lng,source)
               VALUES('Starbucks','Modesto','CA','USA',37.64,-121.00,'osm');
             INSERT INTO pois(name,city,state,country,lat,lng,source)
               VALUES('Walmart','Modesto','CA','USA',37.65,-121.01,'osm');",
        )
        .unwrap();
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        fuzzy_pois_in_tile(&conn, "starbcks", 8, &mut results, &mut seen, None);
        assert_eq!(results.len(), 1, "expected the Starbucks row, got {:?}",
                   results.iter().map(|r| r.name.clone()).collect::<Vec<_>>());
        assert_eq!(results[0].name.as_deref(), Some("Starbucks"));
    }
}

#[cfg(test)]
mod tile_generation_tests {
    use super::*;

    /// Three tile generations are in the wild simultaneously. Naming a column a
    /// tile lacks makes `prepare` fail, and a failed prepare in this path is
    /// swallowed — which silently drops EVERY POI for that tile. Adding a
    /// column without extending the fallback ladder breaks the generation that
    /// lacks it; these cases pin all three.
    fn tile(gen: u8) -> Vec<GeocodingResult> {
        let conn = Connection::open_in_memory().unwrap();
        let ddl = match gen {
            3 => "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                    city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
                    source TEXT, housenumber TEXT, street TEXT, postcode TEXT);
                  INSERT INTO pois(name,city,state,country,lat,lng,source,housenumber,street,postcode)
                    VALUES('Starbucks','Modesto','CA','USA',37.64,-121.0,'overture','3401','Dale Rd','95356');",
            2 => "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                    city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
                    source TEXT, housenumber TEXT, street TEXT);
                  INSERT INTO pois(name,city,state,country,lat,lng,source,housenumber,street)
                    VALUES('Starbucks','Modesto','CA','USA',37.64,-121.0,'overture','3401','Dale Rd');",
            _ => "CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                    city TEXT, state TEXT, country TEXT, lat REAL NOT NULL, lng REAL NOT NULL,
                    source TEXT);
                  INSERT INTO pois(name,city,state,country,lat,lng,source)
                    VALUES('Starbucks','Modesto','CA','USA',37.64,-121.0,'osm');",
        };
        conn.execute_batch(ddl).unwrap();
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let limit: i64 = 10;
        let binds: Vec<&dyn rusqlite::ToSql> = vec![&limit];
        query_pois_table(&conn, "1=1", &binds, &mut results, &mut seen, None);
        results
    }

    #[test]
    fn generation_3_gives_street_and_postcode() {
        let r = tile(3);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address.as_deref(), Some("3401 Dale Rd"));
        assert_eq!(r[0].postcode.as_deref(), Some("95356"));
    }

    /// Street columns present, postcode absent. It must still yield the
    /// STREET, not fall through to the oldest shape.
    #[test]
    fn generation_2_still_gives_its_street() {
        let r = tile(2);
        assert_eq!(r.len(), 1, "generation-2 tile must still return its POI");
        assert_eq!(r[0].address.as_deref(), Some("3401 Dale Rd"),
                   "must not fall through past the street columns");
        assert!(r[0].postcode.is_none());
    }

    #[test]
    fn generation_1_still_returns_pois() {
        let r = tile(1);
        assert_eq!(r.len(), 1);
        assert!(r[0].address.is_none());
        assert!(r[0].postcode.is_none());
        assert_eq!(r[0].text, "Starbucks, Modesto, CA");
    }
}

#[cfg(test)]
mod city_short_token_tests {
    use super::*;

    /// The shape to guard against: Hohhot carries an alt name ("hoter") that a
    /// three-letter PREFIX reaches, while its own name and ascii_name contain no
    /// "hot" at all. Ranking is by population, so the 2.35M city then wins
    /// outright over the small ones that are genuinely named "Hot".
    fn index() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE cities (geoname_id INTEGER PRIMARY KEY, name TEXT, ascii_name TEXT,
                                  alt_names TEXT, admin1 TEXT, country_code TEXT, population INTEGER);
             CREATE VIRTUAL TABLE cities_fts USING fts5(
                 name, ascii_name, alt_names, admin1, country_code,
                 content='cities', content_rowid='geoname_id');
             INSERT INTO cities VALUES (1,'Hohhot','Hohhot','hoter,huhehaote','20','CN',2350000);
             -- Carries 'hot' as a WHOLE alt-name token, which is how the real
             -- index has it (Ulanhot / 'Ulan Hot', Xilin Hot, Bayan Hot). This is
             -- the row an exact term legitimately finds.
             INSERT INTO cities VALUES (2,'Ulanhot','Ulanhot','ulan hot','15','CN',165846);
             INSERT INTO cities VALUES (3,'Ely','Ely','','NV','US',19090);
             INSERT INTO cities VALUES (4,'Zielona Gora','Zielona Gora','zielonagora,elyria-ish','LU','PL',118433);
             INSERT INTO cities VALUES (5,'San Francisco','San Francisco','','CA','US',873965);
             INSERT INTO cities VALUES (6,'Austin','Austin','','TX','US',931830);
             INSERT INTO cities_fts(cities_fts) VALUES('rebuild');",
        )
        .unwrap();
        conn
    }

    fn top(conn: &Connection, query: &str) -> Option<String> {
        let expr = city_match_expr(query)?;
        conn.query_row(
            "SELECT c.name FROM cities_fts f JOIN cities c ON c.geoname_id = f.rowid
             WHERE cities_fts MATCH ?1 ORDER BY c.population DESC LIMIT 1",
            rusqlite::params![expr],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    #[test]
    fn a_short_token_does_not_reach_into_alt_names_by_prefix() {
        // As a prefix, "hot" reaches Hohhot through the alt name "hoter".
        assert_eq!(top(&index(), "hot").as_deref(), Some("Ulanhot"),
                   "a 3-letter token must match whole terms only, not alt-name prefixes");
    }

    #[test]
    fn a_short_token_finds_the_city_actually_named_that() {
        // As a prefix, "ely" reaches Zielona Gora through an alt name.
        assert_eq!(top(&index(), "ely").as_deref(), Some("Ely"));
    }

    #[test]
    fn longer_tokens_keep_typeahead() {
        // The wildcard still has to work, or "san fran" stops finding San Francisco
        // while the user is mid-word.
        assert_eq!(top(&index(), "fran").as_deref(), Some("San Francisco"));
        assert_eq!(top(&index(), "aust").as_deref(), Some("Austin"));
    }

    #[test]
    fn a_short_token_paired_with_a_long_one_still_resolves() {
        // "austin tx" is the common hint shape: one long token plus a 2-letter
        // state code, which matches exactly against the admin1 column.
        assert_eq!(top(&index(), "austin tx").as_deref(), Some("Austin"));
    }

    #[test]
    fn terms_are_built_as_expected() {
        assert_eq!(city_match_term("hot"), "\"hot\"");
        assert_eq!(city_match_term("tx"), "\"tx\"");
        assert_eq!(city_match_term("fran"), "\"fran\"*");
        assert_eq!(city_match_term("austin"), "\"austin\"*");
        assert_eq!(city_match_term("johns"), "(\"johns\"* OR \"john s\")");
        // Punctuation never reaches a term: it is a space.
        assert_eq!(city_match_expr("St. John's").as_deref(), Some("\"st\" AND \"john\"* AND \"s\""));
        assert_eq!(city_match_expr("in-n").as_deref(), Some("\"in\" AND \"n\""));
        assert_eq!(city_match_expr("  ,.- ").as_deref(), None);
        assert_eq!(city_match_expr("Zu\u{0308}rich").as_deref(), Some("\"zu\u{0308}rich\"*"));
    }
}

#[cfg(test)]
mod city_query_syntax_tests {
    use super::*;

    /// One tier exactly as the index build produces it: the same columns, and
    /// the same `unicode61 remove_diacritics 2` tokenizer.
    fn tier(rows: &[(i64, &str, &str, &str, &str, i64)]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE cities (
                 geoname_id INTEGER PRIMARY KEY, name TEXT NOT NULL, ascii_name TEXT NOT NULL,
                 alt_names TEXT NOT NULL DEFAULT '', country_code TEXT NOT NULL,
                 admin1 TEXT NOT NULL, lat REAL NOT NULL, lng REAL NOT NULL,
                 population INTEGER NOT NULL, tile_id TEXT NOT NULL,
                 tile_ids TEXT NOT NULL DEFAULT '', has_shard INTEGER NOT NULL DEFAULT 0);
             CREATE VIRTUAL TABLE cities_fts USING fts5(
                 name, ascii_name, alt_names, admin1, country_code,
                 content='cities', content_rowid='geoname_id',
                 tokenize='unicode61 remove_diacritics 2');",
        )
        .unwrap();
        for (id, name, ascii_name, cc, admin1, pop) in rows {
            conn.execute(
                "INSERT INTO cities (geoname_id, name, ascii_name, alt_names, country_code,
                                     admin1, lat, lng, population, tile_id)
                 VALUES (?1, ?2, ?3, '', ?4, ?5, 0.0, 0.0, ?6, 'aaaa')",
                rusqlite::params![id, name, ascii_name, cc, admin1, pop],
            )
            .unwrap();
        }
        conn.execute_batch("INSERT INTO cities_fts(cities_fts) VALUES('rebuild');").unwrap();
        conn
    }

    fn index() -> Connection {
        tier(&[
            (1, "St. John's", "St. John's", "CA", "05", 108_860),
            (2, "Coeur d'Alene", "Coeur d'Alene", "US", "ID", 54_628),
            (3, "Winston-Salem", "Winston-Salem", "US", "NC", 249_545),
            (4, "St. Louis", "St. Louis", "US", "MO", 301_578),
            (5, "Paris", "Paris", "FR", "11", 2_138_551),
            (6, "Paris", "Paris", "US", "TX", 24_171),
            (7, "Austin", "Austin", "US", "TX", 961_855),
            (8, "Zürich", "Zurich", "CH", "25", 341_730),
        ])
    }

    fn names(rows: Vec<CityResult>) -> Vec<String> {
        rows.into_iter().map(|c| format!("{}, {}", c.name, c.country_code)).collect()
    }

    /// One tier, one query: what `search_tier` answers.
    fn found(query: &str) -> Vec<String> {
        names(CityIndex::search_tier(&index(), query, 10))
    }

    #[test]
    fn an_apostrophe_in_a_town_name_is_found_with_or_without_it() {
        assert_eq!(found("St. John's"), ["St. John's, CA"]);
        assert_eq!(found("St Johns"), ["St. John's, CA"], "typed without the apostrophe");
        assert_eq!(found("Johns"), ["St. John's, CA"]);
        assert_eq!(found("ST JOHNS"), ["St. John's, CA"], "in capitals too");
        assert_eq!(found("st john’s"), ["St. John's, CA"], "the curly apostrophe too");
        assert_eq!(found("Coeur d'Alene"), ["Coeur d'Alene, US"]);
    }

    #[test]
    fn periods_commas_and_hyphens_are_spaces() {
        assert_eq!(found("Winston-Salem"), ["Winston-Salem, US"]);
        assert_eq!(found("St. Louis"), ["St. Louis, US"]);
        assert_eq!(found("st. louis, mo"), ["St. Louis, US"]);
        assert_eq!(found("Austin,"), ["Austin, US"]);
        assert_eq!(found("Austin, TX"), ["Austin, US"]);
        assert_eq!(found("Paris ("), ["Paris, FR", "Paris, US"], "any other symbol is a space too");
    }

    #[test]
    fn an_accent_stays_in_its_word() {
        assert_eq!(found("Zürich"), ["Zürich, CH"]);
        assert_eq!(found("zurich"), ["Zürich, CH"]);
        assert_eq!(found("Zu\u{0308}rich"), ["Zürich, CH"], "decomposed: u + U+0308");
        assert_eq!(found("Paris \u{0301}"), ["Paris, FR", "Paris, US"],
                   "a stray accent is no word, and no term that matches nothing");
    }

    /// The comma fallback, which `search` decides over every tier together.
    fn two_tiers() -> CityIndex {
        let idx = CityIndex::new("/tmp/pingolin-test-cityindex".to_string());
        *idx.country_tier.lock().unwrap() = Some(tier(&[
            (6, "Paris", "Paris", "US", "TX", 24_171),
            (7, "Austin", "Austin", "US", "TX", 961_855),
            (9, "Portland", "Portland", "US", "OR", 652_503),
            (10, "Oregon City", "Oregon City", "US", "OR", 37_572),
            (11, "Hollywood", "Hollywood", "US", "FL", 153_067),
        ]));
        *idx.tier1.lock().unwrap() = Some(tier(&[
            (5, "Paris", "Paris", "FR", "11", 2_138_551),
            (12, "Los Angeles", "Los Angeles", "US", "CA", 3_898_747),
        ]));
        idx
    }

    fn searched(query: &str) -> Vec<String> {
        names(two_tiers().search(query.to_string(), 10))
    }

    #[test]
    fn a_qualifier_no_row_holds_falls_back_to_the_place() {
        assert_eq!(searched("Paris, France"), ["Paris, FR", "Paris, US"],
                   "nothing carries \"france\": the part before the comma is the place");
        assert_eq!(searched("Portland, Oregon"), ["Portland, US"],
                   "Portland is bigger than Oregon City: \"Oregon\" qualifies it");
    }

    #[test]
    fn a_qualifier_the_index_holds_still_narrows() {
        assert_eq!(searched("Paris, TX"), ["Paris, US"],
                   "found in the country tier: tier 1's Paris, France must not join it");
        assert_eq!(searched("Austin,"), ["Austin, US"]);
    }

    #[test]
    fn a_place_in_a_bigger_town_is_not_a_town_row() {
        // Empty, so the apps go on to search Los Angeles's own tiles.
        assert_eq!(searched("Hollywood, Los Angeles"), Vec::<String>::new(),
                   "Los Angeles is bigger than Hollywood, FL: Hollywood is a place in it");
    }

    /// No input may produce an FTS5 syntax error, which `search_tier` would
    /// turn into an empty list.
    #[test]
    fn no_input_is_fts5_syntax() {
        let conn = index();
        let long_words = "st john ".repeat(200);
        let long_possessives = "johns ".repeat(200);
        let inputs = [
            "St. John's", "Coeur d'Alene", "Winston-Salem", "St. Louis", "Paris, France", "Austin,",
            "Paris AND", "NOT Paris", "paris OR austin", "NEAR(paris austin)", "name:paris", "-paris",
            "\"paris", "paris\"", "\"\"", "paris*", "*", "^paris", "(paris", "paris)", "+-*", "a.b.c",
            "St..Louis", "O'Fallon", "l’Aquila", "Zürich", "Zu\u{0308}rich", "\u{0301}", "\u{0301}abc",
            "Ⓐ", "\u{093E}", "😀 paris", "AND", "OR", "NOT", "NEAR", "a", ",,,", "   ", "",
            "1 main st, austin tx", "paris\u{0}austin", long_words.as_str(), long_possessives.as_str(),
        ];
        for input in inputs {
            let Some(expr) = city_match_expr(input) else { continue };
            let result: rusqlite::Result<i64> = conn.query_row(
                "SELECT count(*) FROM cities_fts WHERE cities_fts MATCH ?1",
                rusqlite::params![expr],
                |r| r.get(0),
            );
            assert!(result.is_ok(), "{input:?} became {expr:?}, which FTS5 rejected: {result:?}");
        }
    }
}

#[cfg(test)]
mod tile_residency_tests {
    use super::*;

    /// Minimal stand-in for `tempfile::TempDir` — this crate has no dev-dependency
    /// on tempfile and the test does not warrant adding one.
    struct TempGuard(std::path::PathBuf);
    impl TempGuard {
        fn path(&self) -> &std::path::Path { &self.0 }
    }
    impl Drop for TempGuard {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    /// Write a minimal but REAL tile: same schema the CDN ships, one address.
    fn write_tile(dir: &std::path::Path, tile_id: &str, street: &str, lat: f64, lng: f64) {
        let p = dir.join(format!("tile_{}.sqlite", tile_id));
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch(
            "CREATE TABLE addresses (id INTEGER PRIMARY KEY, text TEXT, house_number TEXT,
                street TEXT, city TEXT, state TEXT, postcode TEXT, country TEXT,
                lat REAL, lng REAL, source TEXT, confidence REAL);
             CREATE TABLE pois (id INTEGER PRIMARY KEY, name TEXT, lat REAL, lng REAL,
                city TEXT, state TEXT, country TEXT);
             CREATE VIRTUAL TABLE addresses_fts USING fts5(text, content='addresses',
                content_rowid='id');",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO addresses (text, house_number, street, city, state, lat, lng, confidence)
             VALUES (?1, '267', ?2, 'Oakdale', 'CA', ?3, ?4, 1.0)",
            rusqlite::params![format!("267 {}", street), street, lat, lng],
        )
        .unwrap();
        conn.execute_batch("INSERT INTO addresses_fts(addresses_fts) VALUES('rebuild');")
            .unwrap();
    }

    /// The case this pins: the smart-fallback resolves a city, downloads that
    /// city's tile, and then searches. `forward_near` opens with
    /// `load_all_cached_tiles()`, which walks EVERY tile on disk and inserts each
    /// one with a fresh, higher LRU tick — evicting the smallest each time it
    /// passes `MAX_LOADED_TILES`. The tile the caller deliberately loaded a moment
    /// earlier has a LOWER tick than anything the scan touches, so the search
    /// would evict its own target before reading it.
    ///
    /// With 140 tiles cached and a cap of 30, 110 tiles are unsearchable at any
    /// instant and which 110 is down to readdir order: the user would see
    /// "Couldn't find that address in Oakdale, CA" for an address that is sitting
    /// on disk, in a tile the engine matches correctly the moment it is actually
    /// resident.
    #[test]
    fn a_deliberately_loaded_tile_survives_the_search_that_follows() {
        let dir = std::env::temp_dir().join(format!("pgn_resident_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = TempGuard(dir);
        // The tile the fallback wants, plus enough others to exceed the cap.
        write_tile(dir.path(), "9qdn", "Pinkston Avenue", 37.7666, -120.8471);
        for i in 0..(TileGeocoder::MAX_LOADED_TILES + 10) {
            write_tile(dir.path(), &format!("zz{:03}", i), "Nowhere Road", 10.0, 10.0);
        }

        let g = TileGeocoder::new(dir.path().to_string_lossy().to_string());
        // Step 1: what the caller does once a city resolves — see
        // `ensure_tile_loaded_by_id`.
        g.load_tile_from_disk("9qdn", dir.path().join("tile_9qdn.sqlite").to_str().unwrap())
            .unwrap();
        assert!(g.loaded_tiles.lock().unwrap().contains_key("9qdn"));

        // Step 2: the search itself.
        let rows = g.forward_near("pinkston avenue", 10, Some(37.7666), Some(-120.8471));

        assert!(
            g.loaded_tiles.lock().unwrap().contains_key("9qdn"),
            "the search evicted the very tile the caller had just loaded for it"
        );
        assert!(
            !rows.is_empty(),
            "an address on disk, in the tile the caller loaded, must be findable"
        );
    }

    /// A SEARCH THAT FINDS NOTHING MUST STILL RETURN.
    ///
    /// `forward_near` holds the `loaded_tiles` and `loaded_pois` guards from the
    /// point it starts querying tiles to the end of the function — a `MutexGuard`
    /// is dropped at end of SCOPE, not at last use. A "no matches" diagnostic that
    /// asks for those same two mutexes again blocks forever on itself, because
    /// `std::sync::Mutex` is not reentrant.
    ///
    /// Such a hang is invisible from the outside in the worst way: it is gated on
    /// `results.is_empty()`, so a query that MATCHES returns normally and only a
    /// miss hangs — and the log line that would name the problem is the thing
    /// deadlocking, so the SDK log just stops. A search sheet that keeps rendering
    /// its previous empty state, which interpolates the LIVE query, then shows a
    /// permanently-stuck search as a confident "No matches for <query> on this
    /// part of the map".
    ///
    /// Run on its own thread with a join deadline: asserting on a deadlock is
    /// otherwise indistinguishable from the suite hanging.
    ///
    /// A SUBSCRIBER IS PART OF THE TEST, NOT SETUP NOISE. `tracing` does not
    /// evaluate a macro's field expressions unless the callsite is enabled, so
    /// with no subscriber installed an offending `self.loaded_tiles.lock()` in
    /// those fields never runs and the hang cannot be reproduced: without the
    /// subscriber this test would pass against deadlocking code.
    #[test]
    fn a_search_that_matches_nothing_returns_instead_of_deadlocking() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
        assert!(
            tracing::enabled!(tracing::Level::INFO),
            "no INFO subscriber: the log line under test would be skipped and this \
             test would pass against the broken code"
        );

        let dir = std::env::temp_dir().join(format!("pgn_nomatch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = TempGuard(dir);
        // A real tile, so the guards below are held over a non-empty map — the
        // same state as the device, not a degenerate empty one.
        write_tile(dir.path(), "9qdn", "Pinkston Avenue", 37.7666, -120.8471);

        let path = dir.path().to_string_lossy().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let g = TileGeocoder::new(path);
            // Matches nothing in the tile, which is the whole point.
            let rows = g.forward_near("qqzzxw nowherestreet", 10, Some(37.7666), Some(-120.8471));
            let _ = tx.send(rows.len());
        });

        match rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(n) => assert_eq!(n, 0, "a query matching nothing must return no rows"),
            Err(_) => panic!(
                "forward_near never returned for a query with no matches — the \
                 empty-result path re-locked a mutex the same thread already held"
            ),
        }
    }
}

#[cfg(test)]
mod manifest_cache_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BODY: &str = r#"{"version":"4.0","updated_at":"2026-09-13T23:21:11Z","precision":4,"tiles":["9q9y","9q9z","dr5r"],"pois":["9q9y"],"pois_version":"p1"}"#;

    /// A throwaway geocoding root per test, removed on drop.
    struct Root(std::path::PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "pgn_manifest_{}_{}_{}",
                tag,
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Root(dir)
        }
        fn path(&self) -> String {
            self.0.to_string_lossy().to_string()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A minimal HTTP/1.1 CDN stand-in on loopback. `respond` gets the request
    /// head (lowercased) and returns the full raw response. Every head is
    /// recorded, so a test can assert what went over the wire — or that
    /// nothing did.
    fn start_cdn(respond: impl Fn(&str) -> String + Send + 'static) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                seen.lock().unwrap().push(head.clone());
                let _ = stream.write_all(respond(&head).as_bytes());
            }
        });
        (format!("http://{}", addr), requests)
    }

    fn ok_response(max_age: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"etag-1\"\r\nLast-Modified: Sun, 13 Sep 2026 23:21:11 GMT\r\nCache-Control: public, {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            max_age,
            BODY.len(),
            BODY
        )
    }

    fn not_found() -> String {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    }

    /// A port nothing listens on: bind, note it, release it.
    fn dead_url() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        url
    }

    fn tile_count(g: &TileGeocoder) -> usize {
        g.manifest.lock().unwrap().as_ref().map(|m| m.tiles.len()).unwrap_or(0)
    }

    #[test]
    fn freshness_comes_from_max_age_less_age_and_is_capped() {
        assert_eq!(manifest_fresh_secs(Some("public, max-age=86400"), None), 86_400);
        assert_eq!(manifest_fresh_secs(Some("public, max-age=86400"), Some("80000")), 6_400);
        assert_eq!(manifest_fresh_secs(Some("max-age=999999"), None), MANIFEST_MAX_FRESH_SECS);
        assert_eq!(manifest_fresh_secs(Some("public, max-age=60"), Some("120")), 0, "already spent");
        assert_eq!(manifest_fresh_secs(Some("no-cache"), None), 0);
        assert_eq!(manifest_fresh_secs(Some("public, no-store, max-age=600"), None), 0);
        assert_eq!(manifest_fresh_secs(Some("s-maxage=600"), None), MANIFEST_DEFAULT_FRESH_SECS, "s-maxage is for shared caches");
        assert_eq!(manifest_fresh_secs(None, None), MANIFEST_DEFAULT_FRESH_SECS);
        assert_eq!(manifest_fresh_secs(Some("MAX-AGE=10"), None), 10, "directives are case-insensitive");
    }

    #[test]
    fn a_cache_entry_is_fresh_only_inside_its_window() {
        let meta = ManifestCacheMeta {
            source: "manifest-v4.json".into(),
            etag: None,
            last_modified: None,
            confirmed_at_ms: 1_000_000,
            fresh_for_secs: 60,
        };
        assert!(meta.is_fresh(1_000_000));
        assert!(meta.is_fresh(1_059_999));
        assert!(!meta.is_fresh(1_060_000));
        assert!(!meta.is_fresh(999_999), "a clock that went backwards revalidates");
    }

    /// THE SAVING. A second launch inside max-age touches no network.
    #[test]
    fn a_manifest_inside_its_max_age_is_served_from_disk_without_asking() {
        let root = Root::new("fresh");
        let (url, requests) = start_cdn(|head| {
            if head.starts_with("get /manifest-v4.json") { ok_response("max-age=3600") } else { not_found() }
        });

        let first = TileGeocoder::with_base_url(root.path(), url.clone());
        assert!(first.fetch_manifest().expect("first fetch"));
        assert_eq!(requests.lock().unwrap().len(), 1);

        // A new process: a new geocoder over the same root.
        let second = TileGeocoder::with_base_url(root.path(), url);
        assert!(second.fetch_manifest().expect("second fetch"));
        assert!(second.has_manifest());
        assert_eq!(tile_count(&second), 3, "the cached copy is the whole manifest");
        assert_eq!(requests.lock().unwrap().len(), 1, "a fresh cached manifest must not be re-downloaded");
    }

    /// Past max-age the cached copy is revalidated, not re-downloaded: the
    /// request carries its ETag and Last-Modified, and a 304 reuses the body
    /// and restarts the clock.
    #[test]
    fn a_stale_manifest_is_revalidated_and_a_304_reuses_the_cached_copy() {
        let root = Root::new("revalidate");
        let (url, requests) = start_cdn(|head| {
            if !head.starts_with("get /manifest-v4.json") {
                return not_found();
            }
            if head.contains("if-none-match: \"etag-1\"") {
                "HTTP/1.1 304 Not Modified\r\nETag: \"etag-1\"\r\nCache-Control: public, max-age=3600\r\nConnection: close\r\n\r\n".to_string()
            } else {
                ok_response("max-age=0")
            }
        });

        let first = TileGeocoder::with_base_url(root.path(), url.clone());
        assert!(first.fetch_manifest().expect("first fetch"));

        let second = TileGeocoder::with_base_url(root.path(), url.clone());
        assert!(second.fetch_manifest().expect("revalidating fetch"));
        assert_eq!(tile_count(&second), 3, "the 304 served the cached body");
        {
            let seen = requests.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert!(!seen[0].contains("if-none-match"), "nothing to revalidate the first time");
            assert!(seen[1].contains("if-none-match: \"etag-1\""), "{}", seen[1]);
            assert!(seen[1].contains("if-modified-since: sun, 13 sep 2026 23:21:11 gmt"), "{}", seen[1]);
        }

        // The 304's max-age now covers the next launch.
        let third = TileGeocoder::with_base_url(root.path(), url);
        assert!(third.fetch_manifest().expect("third fetch"));
        assert_eq!(requests.lock().unwrap().len(), 2, "revalidated recently, so no request");
    }

    /// Offline launch: a stale cached manifest still beats having none.
    #[test]
    fn an_unreachable_cdn_falls_back_to_the_cached_manifest() {
        let root = Root::new("offline");
        let (url, _requests) = start_cdn(|head| {
            if head.starts_with("get /manifest-v4.json") { ok_response("max-age=0") } else { not_found() }
        });
        assert!(TileGeocoder::with_base_url(root.path(), url).fetch_manifest().expect("seed the cache"));

        let offline = TileGeocoder::with_base_url(root.path(), dead_url());
        assert!(offline.fetch_manifest().expect("the cached copy must be used"));
        assert!(offline.has_manifest());
        assert_eq!(tile_count(&offline), 3);
    }

    /// And with no cache the failure is still reported — the fallback must not
    /// turn "no manifest anywhere" into a success.
    #[test]
    fn no_cache_and_no_cdn_is_still_an_error() {
        let root = Root::new("nothing");
        let g = TileGeocoder::with_base_url(root.path(), dead_url());
        assert!(g.fetch_manifest().is_err());
        assert!(!g.has_manifest());
    }

    /// v4 absent, v3 served: the cache records WHICH file it holds, so the
    /// validators go back to v3 and never to v4.
    #[test]
    fn validators_only_go_to_the_file_they_came_from() {
        let root = Root::new("v3");
        let (url, requests) = start_cdn(|head| {
            if head.starts_with("get /manifest-v3.json") { ok_response("max-age=0") } else { not_found() }
        });
        assert!(TileGeocoder::with_base_url(root.path(), url.clone()).fetch_manifest().expect("v3 fetch"));
        assert!(TileGeocoder::with_base_url(root.path(), url).fetch_manifest().expect("second"));
        let seen = requests.lock().unwrap().clone();
        let v4: Vec<&String> = seen.iter().filter(|h| h.starts_with("get /manifest-v4.json")).collect();
        let v3: Vec<&String> = seen.iter().filter(|h| h.starts_with("get /manifest-v3.json")).collect();
        assert!(v4.iter().all(|h| !h.contains("if-none-match")), "v3's etag must not be sent to v4");
        assert!(v3.last().unwrap().contains("if-none-match: \"etag-1\""));
    }
}
