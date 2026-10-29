// Copyright (c) 2025 Pingolin LLC
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

use crate::location_codec::{decode_location, encode_location};
use crate::types::{AlertConditions, AlertEvaluationResult, BoundLocation, CircleCreationData, DeletionPseudonym, EncryptedData, EnvelopeEncryptedLocation, KeyChainLinkData, KeyPair, KdfParams, KeyRotationBundle, KeyStorageCallback, KeyStoreLoad, KeyStoreStatus, KeyWrap, Location, MemberKeyBundle, OpenedLocation, OpenedText, MemberKeyRotationEntry, MobileError, PersonalKeyVerdict, PinRecord, PublishablePersonalKey, PublishedCopyStatus, PinResult, PinState, PublishSessionKeyData, PseudonymPair, SessionEncryptedData, SignWrapParams, SigningKeyPair, StoredKeyData};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use crypto_secretbox::{XSalsa20Poly1305, Nonce as SalsaNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};
use rand::rngs::OsRng;
use rand::RngCore as _;

/// Generate a cryptographically secure random nonce using thread-local RNG.
///
/// SECURITY: `thread_rng()` uses a thread-local CSPRNG (ChaCha12) seeded from OsRng.
/// Each thread gets its own RNG instance, so there is no lock contention.
/// XChaCha20-Poly1305 with a 24-byte nonce has a collision probability of ~2^-96
/// after 2^48 encryptions, making random nonces safe.
fn generate_secure_nonce<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut nonce = [0u8; N];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Insert a circle key version into the version map, capping the number of
/// retained versions per circle at MAX_CIRCLE_KEY_VERSIONS. The oldest
/// (lowest version number) entry is dropped — its `Zeroizing<Vec<u8>>` wipes
/// the key bytes on Drop. Idempotent if the key is already at the cap and
/// we're inserting an existing version (replace, no eviction).
fn insert_capped_circle_version(
    version_map: &mut HashMap<i32, Zeroizing<Vec<u8>>>,
    new_version: i32,
    new_key: Zeroizing<Vec<u8>>,
) {
    let already_present = version_map.contains_key(&new_version);
    version_map.insert(new_version, new_key);
    if !already_present {
        while version_map.len() > MAX_CIRCLE_KEY_VERSIONS {
            if let Some(oldest) = version_map.keys().min().copied() {
                if oldest == new_version {
                    break;
                }
                // Removing the entry drops the Zeroizing<Vec<u8>>, wiping bytes.
                version_map.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

/// Stable hash of the Argon2id KDF parameter set used by the password-key
/// session cache to detect when params change (and a re-derive is required).
/// Includes memory and iterations, but NOT parallelism: derivation forces
/// p=1 to match libsodium's crypto_pwhash regardless of what the field says
/// (see derive_or_cache_password_key), so two param sets differing only in
/// parallelism derive the identical key. Folding parallelism into the key
/// would therefore only cause spurious cache misses and a needless ~1-5s
/// Argon2 re-derive. The salt is not included either — it is compared
/// separately. Algorithm is fixed to Argon2id throughout this crate.
fn hash_kdf_params(p: &KdfParams) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"pingolin.kdf_params.v1|argon2id|");
    h.update(&p.memory_kib.to_le_bytes());
    h.update(b"|");
    h.update(&p.iterations.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Reject X25519 small-order (malicious) public keys that would yield an
/// all-zero shared secret, bypassing the confidentiality of ECDH.
///
/// SECURITY: x25519-dalek does not clear the cofactor, so small-order points
/// produce predictable (often zero) shared secrets. A single-scalar probe misses
/// some points (e.g. the mixed-order point `p-1`). We probe with several
/// independent non-identity scalars: if ANY of them yields all-zeros the point
/// is small-order (since a non-small-order base would need the scalar to be a
/// multiple of the group order, which is astronomically unlikely for these
/// fixed probes).
fn reject_small_order_public(pk: &PublicKey) -> Result<(), MobileError> {
    // Four fixed, distinct, non-trivial scalars. Using multiple probes catches
    // the known small-order points (order 1, 2, 4, 8) that a single probe may
    // miss depending on which scalar is chosen.
    const PROBES: [[u8; 32]; 4] = [
        [1u8; 32],
        [2u8; 32],
        [
            0x5a, 0xc1, 0x7b, 0x93, 0x42, 0x08, 0xff, 0xe1,
            0x6d, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        ],
        [
            0xa3, 0x11, 0x5c, 0x7e, 0xf0, 0x92, 0x04, 0x16,
            0x28, 0x3a, 0x4c, 0x5e, 0x70, 0x82, 0x94, 0xa6,
            0xb8, 0xca, 0xdc, 0xee, 0x01, 0x13, 0x25, 0x37,
            0x49, 0x5b, 0x6d, 0x7f, 0x91, 0xa3, 0xb5, 0xc7,
        ],
    ];
    for probe in &PROBES {
        let probe_secret = StaticSecret::from(*probe);
        let shared = probe_secret.diffie_hellman(pk);
        if shared.as_bytes() == &[0u8; 32] {
            return Err(MobileError::InvalidKey);
        }
    }
    Ok(())
}

/// Internal state for an active sender session key
struct SenderSessionState {
    session_key_id: String,
    key: Zeroizing<Vec<u8>>,
    // Circle-key version this session key was published under. The send path
    // uses the session key only while this is still the circle's ACTIVE version:
    // a session key minted before a rotation is sealed under the OLD circle key,
    // so a member removed by that rotation could keep reading every location sent
    // under it until it expired.
    key_version: i32,
    expires_at: i64,
}

/// Cached peer session key with expiry and access timestamp for LRU eviction.
///
/// SECURITY: `last_used_at` uses `AtomicI64` so readers holding only a read lock
/// on the outer map can still bump the access time without upgrading to a write
/// lock. When the cache is full and no expired entry is available, we evict the
/// least-recently-used entry rather than the next-to-expire one, which avoids
/// knocking out in-use keys.
struct CachedPeerSessionKey {
    key: Zeroizing<Vec<u8>>,
    expires_at: i64,
    last_used_at: AtomicI64,
    /// The circle-key version it was opened under (or, for our own, sealed
    /// under): the version its rows report.
    key_version: i32,
}

/// The peer session keys, each under the circle it was opened under and its id:
/// a row's "s:{id}" opens only with the key its OWN circle holds under that id,
/// so a personal row never opens with a co-member's session key, and the same
/// id in two circles is two entries, neither evicting the other.
type PeerSessionKeys = HashMap<(String, String), CachedPeerSessionKey>;

/// Where a session key is cached: the circle in its one spelling when it is a
/// UUID (else as given), every personal slot as one, and the bare id ("s:"
/// stripped, as rows carry it; the server's bare id is the same entry).
fn session_cache_key(circle_id: &str, session_key_id: &str) -> (String, String) {
    // The personal slots are ONE namespace, in every spelling: a key opened
    // under "self" is the nil id's, and neither is a circle's.
    let circle = if names_a_personal_slot(circle_id) {
        PERSONAL_KEY_ID.to_string()
    } else {
        canonical_id("circle_id", circle_id).unwrap_or_else(|_| circle_id.to_string())
    };
    let bare = session_key_id.strip_prefix("s:").unwrap_or(session_key_id);
    (circle, bare.to_string())
}

fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Maximum number of peer session keys to cache
const MAX_PEER_SESSION_KEYS: usize = 500;
/// Grace period after expiry before eviction (1 hour in seconds)
const PEER_KEY_EXPIRY_GRACE_SECS: i64 = 3600;

/// Locked domain strings for the `pingolin.sig.v1.*` wrap-signature scheme.
/// These MUST match the web TypeScript implementation exactly — the sig_input
/// is keyed by `blake3::derive_key("pingolin.sig.v1.context_key", DOMAIN)` so a
/// typo here would split the verification namespace silently.
const DOMAIN_CIRCLE_MEMBER_WRAP: &str = "pingolin.sig.v1.circle_member_wrap";
#[allow(dead_code)] // Invite-flow wrap domain; this crate does not use it.
const DOMAIN_CIRCLE_INVITE_WRAP: &str = "pingolin.sig.v1.circle_invite_wrap";
const DOMAIN_PLACE_OWNER_WRAP: &str = "pingolin.sig.v1.place_owner_wrap";
const DOMAIN_PLACE_SHARE_WRAP: &str = "pingolin.sig.v1.place_share_wrap";
const DOMAIN_ROTATION_MEMBER_WRAP: &str = "pingolin.sig.v1.rotation_member_wrap";

/// SAS (safety number) derivation key context.
const SAS_CONTEXT_KEY: &str = "pingolin.sas.v1";

/// Maximum circle key versions retained per circle. Older versions beyond
/// this cap are dropped (Zeroize-wiped) on insert to bound memory usage.
const MAX_CIRCLE_KEY_VERSIONS: usize = 5;

/// The personal ("self") key lives under the nil UUID — the id the server keys
/// it by and the only one a signature can bind — and track-android keeps a
/// second copy of the same key under the legacy slot name "self". The two are
/// ONE key for every trust decision in `store_circle_key`: a key held in either
/// slot means the personal key is not first contact, and a wrap carrying the
/// key already held in the other slot may realign a slot (track-android's
/// `copySelfKeySlot`).
const PERSONAL_KEY_ID: &str = "00000000-0000-0000-0000-000000000000";
const ANDROID_PERSONAL_KEY_SLOT: &str = "self";

fn personal_key_alias(circle_id: &str) -> Option<&'static str> {
    match circle_id {
        PERSONAL_KEY_ID => Some(ANDROID_PERSONAL_KEY_SLOT),
        ANDROID_PERSONAL_KEY_SLOT => Some(PERSONAL_KEY_ID),
        _ => None,
    }
}

/// Reserved key prefixes inside `StoredKeyData.pinned_keys_json`. The blob is a
/// JSON map of `"{circle_id}:{user_id}" -> PinRecord`; these entries ride in the
/// same map, with `PinRecord`-shaped values, so an older SDK still parses the
/// whole map (and never matches them: no circle id is "*" or "~rot"). No app
/// callback changes are needed to persist them — the apps store the string
/// opaquely.
///   `*:{user_id}`       identity pin (the keys last trusted for that user in
///                       any circle; kept when a circle pin is retired)
///   `~rot:{circle_id}`  this device's own unconfirmed rotation of that circle;
///                       the version is in `first_pinned_at`
///   `~trust:{fingerprint}` a personal key this device took ON TRUST (an
///                       unauthenticated first contact): never signed here
///   `~adopted:personal` when this device last adopted the server's copy of
///                       the personal key (`first_pinned_at`, unix seconds)
///   `~ctrust:{circle_id}:{version}` a circle key this device took ON TRUST
///                       (an unauthenticated first contact): never signed here
///   `~prev:{circle_id}:{version}` a circle key that opened ONLY with an
///                       identity from before a password reset
const IDENTITY_PIN_PREFIX: &str = "*:";
const UNCONFIRMED_ROTATION_PREFIX: &str = "~rot:";
const TRUST_MARK_PREFIX: &str = "~trust:";
const PERSONAL_ADOPTION_MARK: &str = "~adopted:personal";
const CIRCLE_TRUST_MARK_PREFIX: &str = "~ctrust:";
const VIA_PREVIOUS_MARK_PREFIX: &str = "~prev:";
/// At most one adoption of the server's personal key per this many seconds.
const PERSONAL_ADOPTION_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// Where this device's personal keys came from.
#[derive(Default, Clone)]
struct PersonalKeyProvenance {
    /// Fingerprints of personal keys taken on trust. Such a key is never
    /// signed here, by any route, until a copy signed by this account opens to
    /// it; otherwise one device's signature would launder a key the server
    /// chose onto every other device of the account.
    taken_on_trust: HashSet<String>,
    /// When the server's copy was last adopted (unix seconds).
    last_adoption: Option<i64>,
}

/// Where this device's circle keys came from, by (circle, version).
#[derive(Default, Clone)]
struct CircleKeyProvenance {
    /// Keys stored by an unauthenticated first contact. Never signed here, by
    /// any route, until a copy signed by this account (its current key, or a
    /// restored identity's bound key) opens to the same key: otherwise our
    /// signature would launder a key the server chose.
    taken_on_trust: HashSet<(CircleKey, i32)>,
    /// Keys that opened ONLY with an identity from before a password reset,
    /// whoever signed them: whoever holds that identity knows them.
    via_previous_identity: HashSet<(CircleKey, i32)>,
    /// Stored marks that didn't read here, exactly as stored; each marks
    /// every version its circle held at the load that read it (in the sets
    /// above).
    unread: Vec<UnreadMark>,
}

/// A circle mark that didn't read here. It names no version, so it marks
/// every version its circle held when it was read, and goes back exactly as
/// stored until that circle holds a newer one (which it could never name):
/// then its marks stay, as well-formed ones, and it goes.
#[derive(Clone)]
struct UnreadMark {
    key: String,
    record: PinRecord,
    /// A previous-identity mark; otherwise a taken-on-trust one.
    via_previous: bool,
    /// What follows the prefix, up to its first ':', as its circle's key.
    circle_id: CircleKey,
    /// The newest version (>= 1) that circle held when the mark was read.
    newest: Option<i32>,
}

impl UnreadMark {
    fn read(key: &str, record: &PinRecord, rest: &str, via_previous: bool) -> Self {
        let circle_id = CircleKey::of(rest.split_once(':').map_or(rest, |(circle_id, _)| circle_id));
        UnreadMark { key: key.to_string(), record: record.clone(), via_previous, circle_id, newest: None }
    }

    /// Whether it still goes back as stored, `newest_held` being what its
    /// circle holds now.
    fn still_stored(&self, newest_held: Option<i32>) -> bool {
        newest_held <= self.newest
    }
}

/// `{circle_id}:{version}` from a persisted circle mark.
fn parse_circle_version_mark(rest: &str) -> Option<(CircleKey, i32)> {
    let (circle_id, version) = rest.rsplit_once(':')?;
    let version: i32 = version.parse().ok()?;
    ((1..=1_000_000).contains(&version) && !circle_id.is_empty()).then(|| (CircleKey::of(circle_id), version))
}

/// The two slots a personal key is held under: the nil UUID, and track-android's
/// legacy "self" slot. By the circle's key: the nil id in any spelling is the
/// one slot, which every per-circle store files it under.
fn is_personal_slot(circle_id: &str) -> bool {
    let key = CircleKey::of(circle_id);
    key.as_str() == PERSONAL_KEY_ID || key.as_str() == ANDROID_PERSONAL_KEY_SLOT
}

/// Whether `id` names a personal key slot in any spelling: the nil UUID however
/// it is written (32 hex digits, braced, `urn:uuid:`), or "self". A personal key
/// is no circle's, whoever lists it as one: it is never wrapped for another
/// account, rotated, linked or given records. The stores agree:
/// `is_personal_slot` is the same test.
pub(crate) fn names_a_personal_slot(id: &str) -> bool {
    id == ANDROID_PERSONAL_KEY_SLOT || uuid::Uuid::parse_str(id).map_or(false, |uuid| uuid.is_nil())
}

/// The copies to file for one circle whose keys were stored under several
/// spellings of its id. The reference spelling is the one spelling itself if
/// it was stored, else the only spelling; a version is filed if the reference
/// holds it and every other copy of it is the same, or, with no reference, if
/// every spelling holds the same copy. Every other copy is kept AS STORED in
/// `unreadable`, as `{version}~{n}`, so that version "didn't read here":
/// nothing is taken at a first contact, and nothing is sealed below it; and
/// the next load, under the one spelling, keeps them apart.
fn fold_circle_key_spellings(
    circle: &CircleKey,
    spellings: Vec<(String, HashMap<String, String>)>,
    unreadable: &mut HashMap<CircleKey, HashMap<String, Zeroizing<String>>>,
) -> HashMap<String, String> {
    if spellings.len() == 1 {
        return spellings.into_iter().next().map(|(_, versions)| versions).unwrap_or_default();
    }
    let holding = spellings.iter().filter(|(_, versions)| !versions.is_empty()).count();
    let reference = spellings
        .iter()
        .find(|(spelled, versions)| spelled == circle.as_str() && !versions.is_empty())
        .map(|(spelled, _)| spelled.clone());
    let mut by_version: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (spelled, versions) in spellings {
        for (version, stored) in versions {
            by_version.entry(version).or_default().push((spelled.clone(), stored));
        }
    }
    let mut filed = HashMap::new();
    for (version, copies) in by_version {
        let same = copies.windows(2).all(|pair| pair[0].1 == pair[1].1);
        let held_by_reference = match &reference {
            Some(reference) => copies.iter().any(|(spelled, _)| spelled == reference),
            None => copies.len() == holding,
        };
        if same && held_by_reference {
            filed.insert(version, copies.into_iter().next().map(|(_, stored)| stored).unwrap_or_default());
            continue;
        }
        tracing::warn!(
            "circle {} v{} was stored under several spellings of its id, and they don't agree: kept as stored, never filed",
            circle, version
        );
        let kept = unreadable.entry(circle.clone()).or_default();
        for (_, stored) in copies {
            // Never under the version itself: a copy stored so would be filed at
            // the next load. `unreadable_version` reads the version back.
            keep_unreadable_copy(kept, &format!("{version}~0"), stored);
        }
    }
    filed
}

/// The version an entry of `unreadable_circle_keys` stands for: its name, or
/// the part before `~` of a copy a load kept apart. A name that reads as
/// neither stands for no version.
fn unreadable_version(name: &str) -> Option<i32> {
    name.split_once('~').map_or(name, |(version, _)| version).parse::<i32>().ok()
}

/// Keep a stored copy that didn't read among its circle's: under `name` if
/// that is free, else under the first free `{v}~{n}` of the same version, so
/// a copy never replaces another; the same copy of one version is kept once.
fn keep_unreadable_copy(kept: &mut HashMap<String, Zeroizing<String>>, name: &str, stored: String) {
    let base = name.split_once('~').map_or(name, |(version, _)| version);
    let same_version = |held: &str| held.split_once('~').map_or(held, |(version, _)| version) == base;
    if kept.iter().any(|(held, copy)| same_version(held) && copy.as_str() == stored) {
        return;
    }
    let mut free = name.to_owned();
    let mut n = 0usize;
    while kept.contains_key(&free) {
        free = format!("{base}~{n}");
        n += 1;
    }
    kept.insert(free, Zeroizing::new(stored));
}

/// A circle's key in every per-circle store: the UUID in its one spelling
/// when the id is one, so every spelling of the nil id is the personal slot's;
/// else the id as given ("self", "temp_…"). No store takes a raw string, so
/// another spelling never opens a second namespace for one circle (no chain,
/// no marks, a first contact again).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct CircleKey(String);

impl CircleKey {
    pub(crate) fn of(id: &str) -> Self {
        CircleKey(uuid::Uuid::parse_str(id).map(|uuid| uuid.hyphenated().to_string()).unwrap_or_else(|_| id.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CircleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a member pin's key, `{circle_id}:{user_id}` in whatever spelling it
/// was kept under, names a personal key slot: one has no members.
fn pin_under_a_personal_slot(key: &str) -> bool {
    key.split_once(':').map_or(false, |(circle_id, _)| names_a_personal_slot(circle_id))
        || key.rsplit_once(':').map_or(false, |(circle_id, _)| names_a_personal_slot(circle_id))
}

/// A personal key's name in the provenance record (a keyed hash, never the key).
fn personal_key_fingerprint(key: &[u8]) -> String {
    hex::encode(blake3::derive_key("pingolin.sdk.v1.personal_key_fingerprint", key))
}

/// Personal keys are never evicted (a replaced one is RETIRED, kept at a
/// version <= 0, so history under it stays readable); every other circle keeps
/// at most MAX_CIRCLE_KEY_VERSIONS.
fn insert_circle_version(
    circle_id: &str,
    version_map: &mut HashMap<i32, Zeroizing<Vec<u8>>>,
    version: i32,
    key: Zeroizing<Vec<u8>>,
) {
    if is_personal_slot(circle_id) {
        version_map.insert(version, key);
    } else {
        insert_capped_circle_version(version_map, version, key);
    }
}

/// The version a newly retired personal key is kept under: below 1 and below
/// every key retired before it, so the key in use stays the highest.
fn next_retired_version(version_map: &HashMap<i32, Zeroizing<Vec<u8>>>) -> i32 {
    version_map.keys().copied().filter(|v| *v <= 0).min().map_or(0, |lowest| lowest - 1)
}

/// Format tag of `export_member_pins` blobs.
const MEMBER_PINS_EXPORT_FORMAT: &str = "pingolin.member_pins.v1";

// `load_state` values: what this process knows about the persisted key store.
//
// A store that could not be READ must never be overwritten by a process that
// only knows an empty in-memory key set — that write replaces every stored
// circle key, TOFU pin and the signing seed with nothing.
/// Never loaded in this process.
const LOAD_NOT_ATTEMPTED: u8 = 0;
/// The last load reported "nothing stored" (a first launch — or a platform
/// callback that reports a transient read error as nothing stored).
const LOAD_NOTHING_STORED: u8 = 1;
/// The store's contents are known: loaded, merged, written by us, or cleared.
const LOAD_KNOWN: u8 = 2;
/// The platform's read failed at the last load (or at the first write's
/// re-read); writes are refused until a load succeeds or the keys are cleared.
const LOAD_FAILED: u8 = 3;
/// The store was read but doesn't decode (its identity key, its pins or its
/// circle keys); writes are refused as for LOAD_FAILED.
const LOAD_UNDECODABLE: u8 = 4;
/// `clear_all_keys` cleared memory, but the platform's delete failed: the store
/// may still hold the keys it held. Nothing is written or loaded until a clear
/// succeeds (the app owes a wipe).
const LOAD_DELETE_FAILED: u8 = 5;

/// Compare two secrets without an early exit on the first differing byte.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The one spelling every pin is kept and looked up under: the UUID,
/// lower-case and hyphenated. Any other spelling of an id (upper case, 32 hex
/// digits, braced, `urn:uuid:`) is the same id; a non-UUID is an error, never
/// "no pin".
pub(crate) fn canonical_id(what: &str, id: &str) -> Result<String, MobileError> {
    uuid::Uuid::parse_str(id)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| MobileError::InvalidInput(format!("{what} is not a UUID")))
}

/// A member pin's key: `{circle_id}:{user_id}`, both in their one spelling.
fn member_pin_key(circle_id: &str, user_id: &str) -> Result<String, MobileError> {
    Ok(format!("{}:{}", canonical_id("circle_id", circle_id)?, canonical_id("user_id", user_id)?))
}

/// An id a pin is WRITTEN under: its one spelling only. Any other spelling is
/// refused, so nothing is ever pinned under a spelling: a re-spelled SELF entry
/// an app took for a stranger would otherwise file the server's key under this
/// account's own id. Lookups and equalities read any.
fn strict_id(what: &str, id: &str) -> Result<String, MobileError> {
    let canonical = canonical_id(what, id)?;
    if canonical != id {
        return Err(MobileError::InvalidInput(format!("{what} must be a lower-case hyphenated UUID")));
    }
    Ok(canonical)
}

/// Two stored pins for one member under two spellings of an id, read at load:
/// one pin. When they hold the same keys, the earlier first contact and the
/// later check. When they don't, keys that nothing matches (all zeros), from
/// the earlier first contact: the member's keys read as changed, never as
/// matched or new, until the person approves one.
fn merge_spellings(a: PinRecord, b: PinRecord) -> PinRecord {
    let first_pinned_at = a.first_pinned_at.min(b.first_pinned_at);
    let last_verified_at = a.last_verified_at.max(b.last_verified_at);
    if a.sharing_pubkey_hex.eq_ignore_ascii_case(&b.sharing_pubkey_hex) && a.signing_pubkey_hex.eq_ignore_ascii_case(&b.signing_pubkey_hex) {
        let user_approved_change_at = a.user_approved_change_at.max(b.user_approved_change_at);
        PinRecord { first_pinned_at, last_verified_at, user_approved_change_at, ..a }
    } else {
        PinRecord {
            sharing_pubkey_hex: "0".repeat(64),
            signing_pubkey_hex: "0".repeat(64),
            first_pinned_at,
            last_verified_at,
            user_approved_change_at: None,
        }
    }
}

/// Keep `record` under `key` in `pins`, merged with one held there already.
/// True: the two disagreed (a conflict).
fn keep_pin(pins: &mut HashMap<String, PinRecord>, key: String, record: PinRecord) -> bool {
    let (merged, conflict) = match pins.remove(&key) {
        Some(held) => {
            let differ = !held.sharing_pubkey_hex.eq_ignore_ascii_case(&record.sharing_pubkey_hex)
                || !held.signing_pubkey_hex.eq_ignore_ascii_case(&record.signing_pubkey_hex);
            (merge_spellings(held, record), differ)
        }
        None => (record, false),
    };
    pins.insert(key, merged);
    conflict
}

/// The record to compare a user's keys against when a circle has no pin for
/// them yet: their identity pin, or — on an install that predates identity pins
/// — their most recently approved/verified pin in any circle.
fn identity_reference(
    pins: &HashMap<String, PinRecord>,
    identity_pins: &HashMap<String, PinRecord>,
    user_id: &str,
) -> Option<PinRecord> {
    if let Some(record) = identity_pins.get(&user_id.to_ascii_lowercase()) {
        return Some(record.clone());
    }
    pins.iter()
        .filter(|(key, _)| {
            key.split_once(':')
                .and_then(|(_, user)| canonical_id("user_id", user).ok())
                .map_or(false, |user| user == user_id)
        })
        .map(|(_, record)| record)
        .max_by_key(|r| (r.user_approved_change_at.unwrap_or(r.first_pinned_at), r.last_verified_at))
        .cloned()
}

fn pin_state_against(reference: &PinRecord, sharing_pubkey_hex: &str, signing_pubkey_hex: &str) -> PinState {
    let sharing_match = reference.sharing_pubkey_hex.eq_ignore_ascii_case(sharing_pubkey_hex);
    let signing_match = reference.signing_pubkey_hex.eq_ignore_ascii_case(signing_pubkey_hex);
    match (sharing_match, signing_match) {
        (true, true) => PinState::Matched,
        (false, true) => PinState::ChangedSharing,
        (true, false) => PinState::ChangedSigning,
        (false, false) => PinState::ChangedBoth,
    }
}

/// Split a persisted `pinned_keys_json` map into circle pins, identity pins,
/// unconfirmed-rotation markers, provenance marks and refresh-record entries
/// (see IDENTITY_PIN_PREFIX, and `refresh::is_refresh_key`).
#[allow(clippy::type_complexity)]
fn split_persisted_pins(
    all: HashMap<String, PinRecord>,
) -> (
    HashMap<String, PinRecord>,
    HashMap<String, PinRecord>,
    HashMap<CircleKey, i32>,
    PersonalKeyProvenance,
    CircleKeyProvenance,
    Vec<(String, PinRecord)>,
) {
    let mut pins = HashMap::new();
    let mut identity = HashMap::new();
    let mut rotations: HashMap<CircleKey, i32> = HashMap::new();
    // Two spellings of one circle with different unconfirmed rotations: neither
    // stands: no replacement is allowed on either's word.
    let mut rotation_conflicts: HashSet<CircleKey> = HashSet::new();
    let mut provenance = PersonalKeyProvenance::default();
    let mut circle_provenance = CircleKeyProvenance::default();
    let mut refresh = Vec::new();
    let mut conflicts = 0usize;
    for (key, record) in all {
        if crate::refresh::is_refresh_key(&key) {
            refresh.push((key, record));
        } else if let Some(fingerprint) = key.strip_prefix(TRUST_MARK_PREFIX) {
            provenance.taken_on_trust.insert(fingerprint.to_string());
        } else if let Some(rest) = key.strip_prefix(CIRCLE_TRUST_MARK_PREFIX) {
            match parse_circle_version_mark(rest) {
                Some(mark) => {
                    circle_provenance.taken_on_trust.insert(mark);
                }
                None => {
                    tracing::warn!("A malformed circle trust marker: kept as stored; its circle's keys count as taken on trust");
                    circle_provenance.unread.push(UnreadMark::read(&key, &record, rest, false));
                }
            }
        } else if let Some(rest) = key.strip_prefix(VIA_PREVIOUS_MARK_PREFIX) {
            match parse_circle_version_mark(rest) {
                Some(mark) => {
                    circle_provenance.via_previous_identity.insert(mark);
                }
                None => {
                    tracing::warn!("A malformed previous-identity marker: kept as stored; its circle's keys count as known to it");
                    circle_provenance.unread.push(UnreadMark::read(&key, &record, rest, true));
                }
            }
        } else if key == PERSONAL_ADOPTION_MARK {
            provenance.last_adoption = Some(record.first_pinned_at);
        } else if let Some(user_id) = key.strip_prefix(IDENTITY_PIN_PREFIX) {
            // Under the one spelling of the id.
            let user = canonical_id("user_id", user_id).unwrap_or_else(|_| user_id.to_ascii_lowercase());
            conflicts += usize::from(keep_pin(&mut identity, user, record));
        } else if let Some(circle_id) = key.strip_prefix(UNCONFIRMED_ROTATION_PREFIX) {
            match i32::try_from(record.first_pinned_at) {
                Ok(version) if (1..=1_000_000).contains(&version) => {
                    let circle = CircleKey::of(circle_id);
                    if rotations.get(&circle).map_or(false, |held| *held != version) {
                        rotation_conflicts.insert(circle.clone());
                    }
                    rotations.insert(circle, version);
                }
                _ => tracing::warn!("Ignoring a malformed unconfirmed-rotation marker for {}", circle_id),
            }
        } else if pin_under_a_personal_slot(&key) {
            // A personal key slot has no members: a pin an older SDK kept under
            // one is dropped. No key is part of it.
            tracing::warn!("Dropping a stored member pin kept under a personal key slot");
        } else {
            // A member pin, under the one spelling of both ids; a key that isn't
            // one stays as stored.
            let key = key.split_once(':').and_then(|(circle_id, user_id)| member_pin_key(circle_id, user_id).ok()).unwrap_or(key);
            conflicts += usize::from(keep_pin(&mut pins, key, record));
        }
    }
    if conflicts > 0 {
        tracing::warn!("{} stored pins held one member under two spellings with different keys: each reads as changed until approved", conflicts);
    }
    for circle in rotation_conflicts {
        tracing::warn!("Two spellings of circle {} held different unconfirmed rotations: neither stands", circle);
        rotations.remove(&circle);
    }
    (pins, identity, rotations, provenance, circle_provenance, refresh)
}

/// Inverse of `split_persisted_pins`. `newest_held`: the newest version
/// (>= 1) held per circle, for the marks that didn't read.
fn join_persisted_pins(
    pins: &HashMap<String, PinRecord>,
    identity: &HashMap<String, PinRecord>,
    rotations: &HashMap<CircleKey, i32>,
    provenance: &PersonalKeyProvenance,
    circle_provenance: &CircleKeyProvenance,
    refresh: Vec<(String, PinRecord)>,
    newest_held: &HashMap<CircleKey, i32>,
) -> HashMap<String, PinRecord> {
    let marker = |at: i64| PinRecord {
        sharing_pubkey_hex: String::new(),
        signing_pubkey_hex: String::new(),
        first_pinned_at: at,
        last_verified_at: 0,
        user_approved_change_at: None,
    };
    let mut all = pins.clone();
    for (user_id, record) in identity {
        all.insert(format!("{}{}", IDENTITY_PIN_PREFIX, user_id), record.clone());
    }
    for (circle_id, version) in rotations {
        all.insert(
            format!("{}{}", UNCONFIRMED_ROTATION_PREFIX, circle_id),
            marker(i64::from(*version)),
        );
    }
    for fingerprint in &provenance.taken_on_trust {
        all.insert(format!("{}{}", TRUST_MARK_PREFIX, fingerprint), marker(0));
    }
    if let Some(at) = provenance.last_adoption {
        all.insert(PERSONAL_ADOPTION_MARK.to_string(), marker(at));
    }
    for (circle_id, version) in &circle_provenance.taken_on_trust {
        all.insert(format!("{}{}:{}", CIRCLE_TRUST_MARK_PREFIX, circle_id, version), marker(0));
    }
    for (circle_id, version) in &circle_provenance.via_previous_identity {
        all.insert(format!("{}{}:{}", VIA_PREVIOUS_MARK_PREFIX, circle_id, version), marker(0));
    }
    for mark in &circle_provenance.unread {
        if mark.still_stored(newest_held.get(&mark.circle_id).copied()) {
            all.insert(mark.key.clone(), mark.record.clone());
        }
    }
    for (key, record) in refresh {
        all.insert(key, record);
    }
    all
}

/// A pin record carries two 32-byte keys as 64 hex chars each.
fn pin_record_is_well_formed(record: &PinRecord) -> bool {
    let is_key = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    is_key(&record.sharing_pubkey_hex) && is_key(&record.signing_pubkey_hex)
}

/// Body of an `export_member_pins` blob.
#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedMemberPins {
    format: String,
    owner_user_id: String,
    pins: HashMap<String, PinRecord>,
    identity_pins: HashMap<String, PinRecord>,
}

/// What `store_circle_key` does with a wrap it has authenticated (or not) and
/// opened.
enum StoreDecision {
    /// The same key is already held at this version: nothing to change.
    AlreadyHeld,
    /// Store the key under a version this circle does not hold yet.
    /// `first_contact`: no key of any version was held for it.
    StoreNew { first_contact: bool },
    /// Overwrite the key held at this version (see `store_circle_key`).
    Replace,
    /// Refuse: the wrap would overwrite a key held at this version.
    RefuseConflict,
    /// Refuse: an unauthenticated wrap for a circle whose key we already hold.
    RefuseUnauthenticated,
    /// Keep a personal key RETIRED (below version 1), never in use: one that
    /// came only through an identity from before a password reset.
    StoreRetired,
}

/// Cached Argon2id-derived password key for the current app session.
/// Lives only in RAM, never persisted; cleared on logout via clear_all_keys().
/// Keyed by (raw_salt_bytes, kdf_params_hash) so a change to either forces a re-derive.
struct CachedPasswordKey {
    salt: Vec<u8>,
    params_hash: [u8; 32],
    // Domain-separated BLAKE3 fingerprint of the password this key was derived
    // from. Binds the cache entry to the exact password so a key derived from
    // one password is never returned for a different password sharing the same
    // (salt, params). Not the password itself; RAM-only, wiped with the cache.
    password_fingerprint: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}

/// A recovered pre-reset private key, sealed for this app by the account portal.
///
/// Both fields are base64 exactly as `GET /api/v1/auth/previous-identities`
/// returns them in `app_sealed_private_key`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SealedPreviousIdentity {
    pub nonce: String,
    pub ciphertext: String,
}

/// Keyed BLAKE2b-256 — byte-identical to libsodium's
/// `crypto_generichash(32, message, key)`, which is what the account portal and
/// both web clients use. The LABEL is the key and the private key is the
/// message; getting those the wrong way round produces a plausible-looking
/// value that opens nothing.
fn blake2b_keyed_32(message: &[u8], label: &[u8]) -> Vec<u8> {
    use blake2::digest::{KeyInit, Update, FixedOutput};
    let mut mac = blake2::Blake2bMac::<blake2::digest::consts::U32>::new_from_slice(label)
        .expect("label is a valid BLAKE2b key length");
    mac.update(message);
    mac.finalize_fixed().to_vec()
}

/// Open a libsodium `crypto_secretbox_easy` blob (XSalsa20-Poly1305), which is
/// what the portal seals with.
fn open_secretbox(ciphertext_b64: &str, nonce_b64: &str, key: &[u8]) -> Result<Vec<u8>, MobileError> {
    use base64::Engine as _;
    use crypto_secretbox::aead::{Aead, KeyInit};
    let engine = base64::engine::general_purpose::STANDARD;
    let ciphertext = engine.decode(ciphertext_b64)?;
    let nonce_bytes = engine.decode(nonce_b64)?;
    if nonce_bytes.len() != 24 || key.len() != 32 {
        return Err(MobileError::DecryptionFailed);
    }
    let cipher = XSalsa20Poly1305::new_from_slice(key).map_err(|_| MobileError::DecryptionFailed)?;
    cipher
        .decrypt(SalsaNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| MobileError::DecryptionFailed)
}

/// Manages all cryptographic operations for the mobile SDK.
#[derive(uniffi::Object)]
pub struct CryptoManager {
    /// User's X25519 private key for circle key exchange
    private_key: Arc<RwLock<Option<StaticSecret>>>,
    /// User's X25519 public key
    public_key: Arc<RwLock<Option<PublicKey>>>,
    /// Circle keys: circle_id -> (key_version -> XChaCha20-Poly1305 key)
    /// SECURITY: Keys are wrapped in Zeroizing to ensure they're cleared from memory on drop
    circle_keys: Arc<RwLock<HashMap<CircleKey, HashMap<i32, Zeroizing<Vec<u8>>>>>>,
    /// Stored circle keys that didn't read here:
    /// circle_id -> (version as stored -> the entry as stored). Never filed
    /// under a version, and written back unchanged while that version isn't
    /// held. A version held so is never taken from a copy on a circle without
    /// records, only from one its record's tag vouches for on a circle with
    /// them; and a circle without records seals under nothing older.
    unreadable_circle_keys: Arc<RwLock<HashMap<CircleKey, HashMap<String, Zeroizing<String>>>>>,
    /// Active key version per circle (highest version)
    active_key_version: Arc<RwLock<HashMap<CircleKey, i32>>>,
    /// Sender session keys: circle_id -> this device's current session key state
    sender_session_keys: Arc<RwLock<HashMap<CircleKey, SenderSessionState>>>,
    /// Peer session keys: session_key_id -> decrypted session key + expiry (bounded cache)
    peer_session_keys: Arc<RwLock<PeerSessionKeys>>,
    /// Platform-specific secure storage callback for key persistence
    secure_storage: Arc<RwLock<Option<Box<dyn KeyStorageCallback>>>>,
    /// Session-only cache of the most recent Argon2id-derived password key.
    /// Avoids paying the 1–5s derivation cost on every encrypt/decrypt during
    /// rapid back-to-back operations (e.g. unlocking many secrets at startup).
    /// Cleared on clear_all_keys() / logout.
    password_key_cache: Arc<RwLock<Option<CachedPasswordKey>>>,
    /// User's Ed25519 signing keypair.
    /// `None` until `import_signing_private_key` has been called.
    /// When `None`, `wrap_signature` outputs are empty strings (unsigned wraps).
    signing_keypair: Arc<RwLock<Option<SigningKey>>>,
    /// A stored signing seed that doesn't install (not base64, or not 32 or 64
    /// bytes), exactly as stored, with the X25519 public key of the identity
    /// whose store held it. While no seed is held, `persist_keys` writes it
    /// back unchanged for that identity: writing none would delete the stored
    /// copy (the platforms' callbacks remove the entry). A seed imported or
    /// generated here replaces it; `clear_all_keys` drops it.
    unreadable_signing_seed: Arc<RwLock<Option<(Zeroizing<String>, [u8; 32])>>>,
    /// X25519 private keys from BEFORE a password reset, recovered by the user in
    /// the account portal. Read-only fallbacks — see `import_previous_identities`.
    /// Held apart from `private_key` so nothing can ever WRAP with one.
    previous_private_keys: Arc<RwLock<Vec<StaticSecret>>>,
    /// The signing PUBLIC key of each recovered identity, by its X25519 public
    /// key, from the portal's v2 blob (see `import_previous_identities_v2`).
    /// Verify-only, and never persisted, like `previous_private_keys`.
    previous_signing_keys: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    /// TOFU-pinned member keys, keyed by `format!("{circle_id}:{user_id}")`.
    /// Persisted via StoredKeyData.pinned_keys_json.
    pinned_keys: Arc<RwLock<HashMap<String, PinRecord>>>,
    /// Identity-level pins, keyed by lower-cased user id: the keys last trusted
    /// for that user in ANY circle. They decide what a first sighting in a NEW
    /// circle means (Matched / Changed rather than NewPinning) and survive
    /// `retain_member_pins`. Never consulted to accept a wrap — only circle pins
    /// are. Persisted inside pinned_keys_json under `IDENTITY_PIN_PREFIX`.
    identity_pins: Arc<RwLock<HashMap<String, PinRecord>>>,
    /// circle_id -> the version THIS device minted in `prepare_key_rotation` that
    /// the server has not served back yet. Only such a version may be replaced by
    /// an authenticated wrap (the device lost the rotation race); every other
    /// held version is immutable. Persisted inside pinned_keys_json under
    /// `UNCONFIRMED_ROTATION_PREFIX`, so a process killed mid-rotation still
    /// converges.
    unconfirmed_rotations: Arc<RwLock<HashMap<CircleKey, i32>>>,
    /// Personal keys taken on trust, and the last adoption.
    /// Persisted inside pinned_keys_json (`TRUST_MARK_PREFIX`,
    /// `PERSONAL_ADOPTION_MARK`).
    personal_provenance: Arc<RwLock<PersonalKeyProvenance>>,
    /// Circle keys taken on trust, and those that came only through a previous
    /// identity. Persisted inside pinned_keys_json
    /// (`CIRCLE_TRUST_MARK_PREFIX`, `VIA_PREVIOUS_MARK_PREFIX`).
    circle_provenance: Arc<RwLock<CircleKeyProvenance>>,
    /// Each circle's chain of refresh records as this device knows it: its
    /// head, the version it may seal under and the facts per member code,
    /// persisted inside pinned_keys_json (`~rrh:`, `~rrm:`, `~rra:`); the
    /// circle's secret, persisted inside circle_keys_json (`~rrs:`); the
    /// records seen, in memory only.
    /// Lock order: this lock may be held while taking `circle_keys`,
    /// `unconfirmed_rotations`, `active_key_version` or `sender_session_keys`,
    /// never the other way round; and `persist_keys` reads it, so it is never
    /// held across a persist.
    pub(crate) refresh: Arc<RwLock<HashMap<CircleKey, crate::refresh::CircleChain>>>,
    /// What this process knows about the persisted store (`LOAD_*`).
    load_state: AtomicU8,
    /// Deferred-persist gate. While `true`, `persist_keys` records that
    /// a flush is owed (via `persist_dirty`) and returns WITHOUT writing, so a
    /// bulk key import (login/sync) coalesces the O(N+M) full-blob encrypted disk
    /// writes into a single flush at `end_bulk_key_import`. A DEPTH COUNTER (not a
    /// bool) so begin/end are re-entrant AND safe under the concurrent per-circle
    /// refresh fan-out: overlapping/nested windows coalesce to one flush at the
    /// last end. `> 0` = a bulk import is in progress. Default `0`, so callers
    /// that never opt in keep the exact immediate-write behavior.
    persist_depth: AtomicI64,
    /// Set by `persist_keys` while a bulk window is open, so the outermost
    /// `end_bulk_key_import` knows at least one persist was owed and performs one
    /// real write. Consumed (swapped back to `false`) at that flush. NOT reset by
    /// `begin` — a nested/concurrent inner begin must not wipe an owed flush.
    persist_dirty: AtomicBool,
}

#[uniffi::export]
impl CryptoManager {
    /// Create a new crypto manager
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            private_key: Arc::new(RwLock::new(None)),
            previous_private_keys: Arc::new(RwLock::new(Vec::new())),
            previous_signing_keys: Arc::new(RwLock::new(HashMap::new())),
            public_key: Arc::new(RwLock::new(None)),
            circle_keys: Arc::new(RwLock::new(HashMap::new())),
            unreadable_circle_keys: Arc::new(RwLock::new(HashMap::new())),
            active_key_version: Arc::new(RwLock::new(HashMap::new())),
            sender_session_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_session_keys: Arc::new(RwLock::new(HashMap::new())),
            secure_storage: Arc::new(RwLock::new(None)),
            password_key_cache: Arc::new(RwLock::new(None)),
            signing_keypair: Arc::new(RwLock::new(None)),
            unreadable_signing_seed: Arc::new(RwLock::new(None)),
            pinned_keys: Arc::new(RwLock::new(HashMap::new())),
            identity_pins: Arc::new(RwLock::new(HashMap::new())),
            unconfirmed_rotations: Arc::new(RwLock::new(HashMap::new())),
            personal_provenance: Arc::new(RwLock::new(PersonalKeyProvenance::default())),
            circle_provenance: Arc::new(RwLock::new(CircleKeyProvenance::default())),
            refresh: Arc::new(RwLock::new(HashMap::new())),
            load_state: AtomicU8::new(LOAD_NOT_ATTEMPTED),
            persist_depth: AtomicI64::new(0),
            persist_dirty: AtomicBool::new(false),
        })
    }

    /// Register platform-specific secure storage for key persistence
    ///
    /// Call this immediately after creating the CryptoManager to enable
    /// automatic key persistence across app restarts.
    ///
    /// Platform implementations:
    /// - Android: Use EncryptedSharedPreferences or Android Keystore
    /// - iOS: Use iOS Keychain Services with kSecAttrAccessibleAfterFirstUnlock
    pub fn register_secure_storage(&self, storage: Box<dyn KeyStorageCallback>) {
        *self.secure_storage.write().unwrap_or_else(|e| e.into_inner()) = Some(storage);
        tracing::info!("Secure storage registered for key persistence");
    }

    /// Load persisted keys from secure storage
    ///
    /// Call this on app startup after registering secure storage.
    /// Returns true if keys were successfully loaded, false if no keys exist.
    pub fn load_persisted_keys(&self) -> Result<bool, MobileError> {
        // The keys were cleared here and the store's delete failed: what it
        // holds is what was cleared (another account's, perhaps). Never loaded
        // back; the app clears again first.
        if self.load_state.load(Ordering::Acquire) == LOAD_DELETE_FAILED {
            tracing::warn!("load_persisted_keys: the last clear's delete failed; clear the keys again before loading");
            return Err(MobileError::StorageError(
                "the key store's last delete failed: clear the keys again before loading".to_string(),
            ));
        }
        // Nothing is WRITTEN while loading. The two private keys are not
        // installed through `import_private_key` / `import_signing_private_key`:
        // both persist, so a load would write the store twice, with an EMPTY
        // circle-key map and an EMPTY pin set, before the rest of the blob had
        // been read back — and a process that died before its next persist
        // (track-android loads on every process start) would leave the device
        // with no circle keys and no TOFU pins on disk. The installs below do
        // not persist.
        //
        // The outcome is recorded in `load_state`: a store that could not be
        // read is never overwritten afterwards (see `persist_keys`).
        let storage = self.secure_storage.read().unwrap_or_else(|e| e.into_inner());
        let storage = match storage.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("No secure storage registered, cannot load persisted keys");
                return Ok(false);
            }
        };

        let loaded = match storage.load_keys() {
            Ok(loaded) => loaded,
            Err(e) => {
                self.load_state.store(LOAD_FAILED, Ordering::Release);
                tracing::warn!(
                    "Persisted keys could not be read ({}); key writes are suspended until a load succeeds",
                    e
                );
                return Err(e.into());
            }
        };

        match loaded {
            Some(data) => {
                // A blob that doesn't decode (its identity key, its pins or its
                // circle keys) is an error, never an empty state: writes stay
                // refused until a load succeeds or the keys are cleared, so no
                // later persist replaces the stored copy with what this process
                // happens to hold.
                match self.load_stored_data(&data) {
                    Ok(loaded) => {
                        self.load_state.store(LOAD_KNOWN, Ordering::Release);
                        Ok(loaded)
                    }
                    Err(e) => {
                        self.load_state.store(LOAD_UNDECODABLE, Ordering::Release);
                        tracing::warn!("Persisted keys could not be decoded ({}); key writes are suspended until a load succeeds", e);
                        Err(e)
                    }
                }
            }
            None => {
                self.load_state.store(LOAD_NOTHING_STORED, Ordering::Release);
                tracing::debug!("No persisted keys found in secure storage");
                Ok(false)
            }
        }
    }

    /// The key store's state: what the last load found, and whether
    /// a signing seed or other entries that didn't read are kept as stored.
    /// The apps decide from it, never from an error's text: `ReadFailed`, load
    /// again later; `DoesNotDecode`, clear the keys at an explicit sign-in;
    /// `DeleteFailed`, remember a wipe is owed and clear again before any load;
    /// a seed or entries that didn't read, ask the person to sign in again.
    ///
    /// While the load is `ReadFailed` or `DoesNotDecode`, this device doesn't
    /// know what it holds, and until a load succeeds or the keys are cleared:
    /// nothing is written; nobody is taken on first contact (`pin_member_keys`
    /// refuses a first sight, `store_circle_key` an unauthenticated first
    /// copy); every circle counts as having records (`circle_has_refresh_records`
    /// is true, `get_active_version` and `refresh_eligibility` throw for one
    /// with none held here, `import_refresh_records` leaves one waiting rather
    /// than read it at first sight, and a record-less rotation or link, a new
    /// circle and `finalize_circle_creation` are refused); and
    /// `export_member_pins` is refused. The refusals are StorageError.
    pub fn key_store_status(&self) -> KeyStoreStatus {
        let load = match self.load_state.load(Ordering::Acquire) {
            LOAD_NOTHING_STORED => KeyStoreLoad::NothingStored,
            LOAD_KNOWN => KeyStoreLoad::Loaded,
            LOAD_FAILED => KeyStoreLoad::ReadFailed,
            LOAD_UNDECODABLE => KeyStoreLoad::DoesNotDecode,
            LOAD_DELETE_FAILED => KeyStoreLoad::DeleteFailed,
            _ => KeyStoreLoad::NotLoaded,
        };
        KeyStoreStatus {
            load,
            signing_seed_unreadable: self.signing_seed_unreadable(),
            entries_unreadable: self.entries_unreadable(),
        }
    }

    /// Drop the stored entries that didn't read here, and only those, for the
    /// explicit sign-in after `key_store_status` said `entries_unreadable`: a
    /// circle whose record state didn't read keeps its latch and nothing else,
    /// so it is read again at first sight with this account's own heads; a
    /// circle mark or a circle key that didn't read goes (what it marked stays
    /// marked; that version's key can come again). Everything else is written
    /// back as it was. Returns how many stored entries went. Throws
    /// StorageError while the store can't be read (`ReadFailed`,
    /// `DoesNotDecode`: nothing was read to drop) or when the write fails. A
    /// kept signing seed is not touched: the sign-in's
    /// `import_signing_private_key` replaces it.
    pub fn drop_unreadable_entries(&self) -> Result<u32, MobileError> {
        if self.store_unreadable() {
            return Err(MobileError::StorageError(
                "the key store can't be read: nothing was read to drop".to_string(),
            ));
        }
        // `refresh` first and alone (its lock order).
        let circles: usize = {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            let mut dropped = 0;
            for chain in chains.values_mut().filter(|chain| !chain.as_stored.is_empty()) {
                dropped += chain.as_stored.len();
                *chain = crate::refresh::CircleChain::latched_only();
            }
            dropped
        };
        let marks = std::mem::take(&mut self.circle_provenance.write().unwrap_or_else(|e| e.into_inner()).unread).len();
        let keys: usize = std::mem::take(&mut *self.unreadable_circle_keys.write().unwrap_or_else(|e| e.into_inner()))
            .values()
            .map(|entries| entries.len())
            .sum();
        let dropped = circles + marks + keys;
        if dropped > 0 {
            tracing::info!("Dropped {} stored entries that didn't read", dropped);
            self.persist_keys()?;
        }
        Ok(u32::try_from(dropped).unwrap_or(u32::MAX))
    }

    /// Persist current keys to secure storage
    ///
    /// Called automatically after key changes if secure storage is registered.
    /// Can also be called manually to force persistence.
    pub fn persist_keys(&self) -> Result<(), MobileError> {
        // While a bulk key import is in progress, defer the (synchronous,
        // full-blob, encrypted) disk write — just record that a flush is owed and
        // return. `end_bulk_key_import` performs a single write at the end,
        // collapsing O(N+M) growing writes into one. Callers that never open a
        // bulk window fall straight through to the immediate write below.
        if self.persist_depth.load(Ordering::Acquire) > 0 {
            self.persist_dirty.store(true, Ordering::Release);
            return Ok(());
        }

        let storage = self.secure_storage.read().unwrap_or_else(|e| e.into_inner());
        let storage = match storage.as_ref() {
            Some(s) => s,
            None => {
                tracing::debug!("No secure storage registered, skipping key persistence");
                return Ok(());
            }
        };

        // Nothing is written without a private key (checked again below, where
        // it is encoded); checked first so an early call never re-reads the store.
        if self.private_key.read().unwrap_or_else(|e| e.into_inner()).is_none() {
            tracing::warn!("No private key to persist");
            return Ok(());
        }

        // Every write replaces the WHOLE stored blob, so it must never come from a
        // process that does not know what the store holds.
        match self.load_state.load(Ordering::Acquire) {
            LOAD_KNOWN => {}
            LOAD_DELETE_FAILED => {
                tracing::warn!("persist_keys: the last clear's delete failed; refusing to write until a clear succeeds");
                return Err(MobileError::StorageError(
                    "the key store's last delete failed: not writing until a clear succeeds".to_string(),
                ));
            }
            LOAD_FAILED | LOAD_UNDECODABLE => {
                // The load failed: the store may hold every circle key, pin and
                // the signing seed, and this process holds whatever it imported
                // since. Writing now would replace the former with the latter.
                tracing::warn!("persist_keys: the key store could not be read at load; refusing to overwrite it");
                return Err(MobileError::StorageError(
                    "key store could not be read at load; not overwriting it".to_string(),
                ));
            }
            _ => {
                // Loaded nothing (or never loaded). Platform callbacks can report
                // a read error as "nothing stored" (iOS Keychain before first
                // unlock), so read once more before the first write and keep
                // whatever is there.
                match storage.load_keys() {
                    Ok(Some(stored)) => {
                        if let Err(e) = self.merge_stored_keys(stored) {
                            self.load_state.store(LOAD_UNDECODABLE, Ordering::Release);
                            tracing::warn!("persist_keys: the key store doesn't decode ({}); refusing to overwrite it", e);
                            return Err(MobileError::StorageError(format!(
                                "key store doesn't decode; not overwriting it: {}",
                                e
                            )));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.load_state.store(LOAD_FAILED, Ordering::Release);
                        tracing::warn!("persist_keys: the key store cannot be read ({}); refusing to overwrite it", e);
                        return Err(MobileError::StorageError(format!(
                            "key store cannot be read; not overwriting it: {}",
                            e
                        )));
                    }
                }
            }
        }

        // The refresh-record state and the circles' secrets, read first and
        // alone: `refresh` is taken before any other lock, never while one is
        // held (see its field).
        let (refresh_entries, secrets) = {
            let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
            (crate::refresh::persisted_entries(&chains), crate::refresh::persisted_secrets(&chains))
        };

        let private_key = self.private_key.read().unwrap_or_else(|e| e.into_inner());
        let private_key_base64 = match private_key.as_ref() {
            Some(key) => {
                // SECURITY: bind the raw 32-byte X25519 secret so the stack copy
                // can be zeroized after encoding (matching generate_keypair). A
                // bare `key.to_bytes()` would drop the temporary [u8;32] un-wiped.
                let mut b = key.to_bytes();
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &b,
                );
                b.zeroize();
                encoded
            }
            None => {
                tracing::warn!("No private key to persist");
                return Ok(());
            }
        };

        // On-disk layout: circle_id -> { version_str -> base64_key }, plus each
        // circle's secret under its reserved id (`refresh::SECRET_PREFIX`).
        let mut versioned_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut total_count = 0usize;
        // The newest version in use per circle, for the marks that didn't read.
        let mut newest_held: HashMap<CircleKey, i32> = HashMap::new();
        {
            let circle_keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            for (circle_id, versions) in circle_keys.iter() {
                if let Some(newest) = versions.keys().copied().filter(|v| *v >= 1).max() {
                    newest_held.insert(circle_id.clone(), newest);
                }
                let mut version_entries = HashMap::new();
                for (version, key) in versions.iter() {
                    version_entries.insert(
                        version.to_string(),
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_slice()),
                    );
                    total_count += 1;
                }
                versioned_map.insert(circle_id.as_str().to_owned(), version_entries);
            }
        }
        // Stored keys that didn't read go back as stored, unless their version
        // is held here since.
        {
            let unreadable = self.unreadable_circle_keys.read().unwrap_or_else(|e| e.into_inner());
            for (circle_id, entries) in unreadable.iter() {
                let written = versioned_map.entry(circle_id.as_str().to_owned()).or_default();
                // The versions held here; a copy kept apart (`{v}~{n}`) is its
                // version's too.
                let held: HashSet<String> = written.keys().cloned().collect();
                for (version, stored) in entries {
                    if unreadable_version(version).map_or(false, |v| held.contains(&v.to_string())) {
                        continue;
                    }
                    written.entry(version.clone()).or_insert_with(|| stored.as_str().to_owned());
                }
            }
        }
        versioned_map.extend(secrets);
        let circle_keys_json = serde_json::to_string(&versioned_map)
            .map_err(|e| MobileError::StorageError(format!("Failed to serialize circle keys: {}", e)))?;

        // Always emit Some(_) — an empty pin set serializes as "{}" and round-trips,
        // whereas `None` on load means "this install has never persisted pins".
        // Identity pins and unconfirmed rotations ride in the same map under
        // reserved keys (see IDENTITY_PIN_PREFIX).
        let pinned_keys_json = {
            let pins = self.pinned_keys.read().unwrap_or_else(|e| e.into_inner());
            let identity = self.identity_pins.read().unwrap_or_else(|e| e.into_inner());
            let rotations = self.unconfirmed_rotations.read().unwrap_or_else(|e| e.into_inner());
            let provenance = self.personal_provenance.read().unwrap_or_else(|e| e.into_inner());
            let circle_provenance = self.circle_provenance.read().unwrap_or_else(|e| e.into_inner());
            let all = join_persisted_pins(&pins, &identity, &rotations, &provenance, &circle_provenance, refresh_entries, &newest_held);
            Some(serde_json::to_string(&all).map_err(|e| {
                MobileError::StorageError(format!("Failed to serialize pinned keys: {}", e))
            })?)
        };

        // Base64 of the Ed25519 signing key's 32-byte secret seed. With none
        // held, a stored one that doesn't install goes back as it was stored,
        // for the identity it was stored with. Read before the held seed: an
        // import installs its seed before it drops the kept one.
        let kept_unreadable = self.unreadable_signing_seed.read().unwrap_or_else(|e| e.into_inner()).clone();
        let signing_private_key_b64 = {
            let guard = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|sk| {
                // SECURITY: bind the raw seed so the stack copy can be zeroized
                // after encoding (same reason as the X25519 secret above).
                let mut b = sk.to_bytes();
                let encoded =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b);
                b.zeroize();
                encoded
            })
        };
        let signing_private_key_b64 = signing_private_key_b64.or_else(|| {
            let identity = self.public_key.read().unwrap_or_else(|e| e.into_inner()).map(|k| k.to_bytes());
            kept_unreadable
                .filter(|(_, stored_with)| Some(*stored_with) == identity)
                .map(|(seed, _)| seed.as_str().to_owned())
        });

        storage.store_keys(StoredKeyData {
            private_key: private_key_base64,
            circle_keys_json,
            pinned_keys_json,
            signing_private_key_b64,
        })?;
        // What is on disk is now exactly what we just wrote.
        self.load_state.store(LOAD_KNOWN, Ordering::Release);

        tracing::debug!("Persisted {} circle key versions to secure storage", total_count);
        Ok(())
    }

    /// Begin a bulk key-import window.
    ///
    /// While open, every implicit `persist_keys` triggered by `store_circle_key`,
    /// `pin_member_keys`, etc. is deferred: it records that a flush is owed instead
    /// of doing a synchronous, full-blob, encrypted disk write. Call this before
    /// importing many circle-key versions / member pins during login or a sync
    /// pass, then `end_bulk_key_import` once to flush a single write.
    ///
    /// Purely an optimization: if you never call this, persistence is immediate.
    /// The pair is re-entrant and concurrency-safe via a depth
    /// counter (`persist_depth`): each `begin` increments the depth, and a nested
    /// or concurrent inner `begin` does NOT touch the owed-flush marker
    /// (`persist_dirty`) — it will not wipe a flush already owed by an outer or
    /// overlapping window. Only the outermost `end` (the one that returns the depth
    /// to 0) performs the single coalesced flush. begin/end calls must be balanced.
    pub fn begin_bulk_key_import(&self) {
        // Enter a bulk-import window (re-entrant/concurrency-safe depth counter).
        // Do NOT touch persist_dirty here — a nested or concurrent inner begin must
        // not wipe a flush already owed by an outer/overlapping window.
        self.persist_depth.fetch_add(1, Ordering::AcqRel);
        tracing::debug!("Bulk key import started; key persistence deferred");
    }

    /// End a bulk key-import window and flush once if any persist was deferred.
    ///
    /// Disarms deferral first (so the flush below runs as a real write) and then,
    /// iff at least one `persist_keys` was requested during the window, performs a
    /// single `persist_keys`. Safe to call without a matching `begin` (no-op).
    pub fn end_bulk_key_import(&self) -> Result<(), MobileError> {
        // Leave the window. Only the outermost/last close (depth returning to 0)
        // performs the single coalesced write, and only if a persist was owed.
        // fetch_sub returns the PREVIOUS depth: `<= 1` means we just brought it to
        // 0 (or below — defensive against an unbalanced end). persist_keys then
        // takes the real write path because depth is now 0. If a concurrent begin
        // races the counter back above 0 before the write, persist_keys re-defers
        // and re-sets dirty, so that window's own end flushes it — the final state
        // is always persisted.
        if self.persist_depth.fetch_sub(1, Ordering::AcqRel) <= 1 {
            if self.persist_dirty.swap(false, Ordering::AcqRel) {
                tracing::debug!("Bulk key import ended; flushing deferred key persistence");
                // Clear the owed-flush marker only for a SUCCESSFUL flush. On error,
                // re-arm it (dirty=true) and propagate so a later persist/end retries
                // instead of silently dropping the deferred write. The up-front
                // swap(false) preserves the concurrency design: if a racing begin
                // re-entered the window, persist_keys re-defers and re-sets dirty
                // (returning Ok), so that window's own end still flushes.
                if let Err(e) = self.persist_keys() {
                    self.persist_dirty.store(true, Ordering::Release);
                    // A store this process could not read is deliberately left
                    // alone (see persist_keys); that is not a failed flush, and
                    // callers close this window in a `finally` — throwing would
                    // turn every key import into a failure until a load succeeds.
                    if self.store_unreadable() || self.load_state.load(Ordering::Acquire) == LOAD_DELETE_FAILED {
                        tracing::warn!("Bulk key import ended; the key store can't be written now, so nothing was written");
                        return Ok(());
                    }
                    return Err(e);
                }
            } else {
                tracing::debug!("Bulk key import ended; nothing to flush");
            }
        }
        Ok(())
    }

    /// Generate a new X25519 keypair for the user
    pub fn generate_keypair(&self) -> KeyPair {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let mut private_bytes = secret.to_bytes();
        let public_bytes = public.to_bytes();

        // Store the keypair
        *self.private_key.write().unwrap_or_else(|e| e.into_inner()) = Some(secret);
        *self.public_key.write().unwrap_or_else(|e| e.into_inner()) = Some(public);

        // Auto-persist if secure storage is registered
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after keypair generation: {}", e);
        }

        let keypair = KeyPair {
            private_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &private_bytes),
            public_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public_bytes),
        };

        // SECURITY: Zeroize private key bytes after encoding to base64
        private_bytes.zeroize();

        keypair
    }

    /// Import a private key from base64
    pub fn import_private_key(&self, private_key_base64: String) -> Result<(), MobileError> {
        self.install_private_key(&private_key_base64)?;

        // Auto-persist if secure storage is registered. Without this the imported
        // key lives only in process memory and is lost on the next process kill,
        // leaving circle decryption (and circle name rendering) broken until the
        // user logs in again. `generate_keypair` already persists — this mirrors it.
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after import_private_key: {}", e);
        }

        Ok(())
    }

    /// Export public key as base64
    pub fn export_public_key(&self) -> Result<String, MobileError> {
        let public_key = self
            .public_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MobileError::KeyNotFound("No keypair generated".to_string()))?;

        Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public_key.as_bytes()))
    }

    /// Take in identities recovered from before a password reset.
    ///
    /// An email password reset replaces the account keypair. Every circle key was
    /// ECDH-wrapped to the OLD public key, and note's vault key is DERIVED from
    /// that keypair — so after a reset a device holds a valid session and cannot
    /// read a single thing it stored before. None of that data is lost; the key
    /// that opens it is simply gone until the user recovers it with their
    /// recovery key in the account portal.
    ///
    /// The portal seals each recovered key under a value this SDK can derive from
    /// the key it already holds:
    ///
    /// ```text
    /// wrap = BLAKE2b-256(current private key, "pingolin.previous-identity")
    /// ```
    ///
    /// which is the only way it could reach us: mobile never sees the auth master
    /// key the portal's own copy is wrapped under. Pass the sealed blobs from
    /// `GET /api/v1/auth/previous-identities` (`app_sealed_private_key`) exactly as
    /// received; this opens what it can and ignores the rest.
    ///
    /// Returns how many were imported. Zero is the normal answer.
    pub fn import_previous_identities(
        &self,
        sealed: Vec<SealedPreviousIdentity>,
    ) -> Result<u32, MobileError> {
        let guard = self.private_key.read().unwrap_or_else(|e| e.into_inner());
        let current = guard.as_ref().ok_or(MobileError::KeyNotFound(
            "no private key loaded; cannot open a recovered identity".into(),
        ))?;

        let wrap = Zeroizing::new(
            blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity"),
        );
        drop(guard);

        let mut opened: Vec<StaticSecret> = Vec::new();
        for blob in sealed {
            match open_secretbox(&blob.ciphertext, &blob.nonce, wrap.as_slice()) {
                Ok(plain) if plain.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&plain);
                    opened.push(StaticSecret::from(key));
                }
                _ => {
                    // Sealed under a key we no longer hold — another reset since.
                    // It opens nothing, so skipping is right and reporting it
                    // would be noise on every startup.
                    tracing::debug!("import_previous_identities: skipping a blob we cannot open");
                }
            }
        }

        let count = opened.len() as u32;
        *self
            .previous_private_keys
            .write()
            .unwrap_or_else(|e| e.into_inner()) = opened;
        if count > 0 {
            tracing::info!("{} recovered pre-reset identity(ies) available", count);
        }
        Ok(count)
    }

    /// Vault keys for each recovered identity, base64, newest first.
    ///
    /// note derives its vault key from the account keypair —
    /// `BLAKE2b-256(private key, "pingolin-note-vault")` — so a password reset
    /// changes it and EVERY note stops opening at once. Each recovered identity
    /// yields the vault key of its era; a note client tries these only after the
    /// current vault key has failed.
    ///
    /// Returns keys rather than doing the decrypt here because note content is
    /// decrypted through several paths (sync, import, attachments) that already
    /// take a vault key — this slots in beside them instead of duplicating each.
    pub fn previous_vault_keys(&self) -> Vec<String> {
        use base64::Engine as _;
        let guard = self
            .previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .map(|k| {
                let vault = blake2b_keyed_32(k.to_bytes().as_ref(), b"pingolin-note-vault");
                base64::engine::general_purpose::STANDARD.encode(vault)
            })
            .collect()
    }

    /// Take in identities recovered from before a password reset, with the
    /// signing key each one had. Pass, per identity, the blob from
    /// `GET /api/v1/auth/previous-identities` `app_sealed_private_key_v2` when
    /// the entry has one, else its `app_sealed_private_key`, exactly as
    /// received.
    ///
    /// Both are sealed like `import_previous_identities`' blobs. A v2 blob holds
    /// 64 bytes: the recovered X25519 private key, then that identity's Ed25519
    /// signing PUBLIC key, which lets `store_circle_key` accept this account's
    /// own wrap signed before the reset, but only when that identity's key opens
    /// the wrap. A 32-byte blob (v1) brings the private key alone. The server's
    /// plaintext `signing_public_key` is never used.
    ///
    /// Replaces the identities held before, as `import_previous_identities`
    /// does; call one or the other. Returns how many identities were imported.
    pub fn import_previous_identities_v2(
        &self,
        sealed: Vec<SealedPreviousIdentity>,
    ) -> Result<u32, MobileError> {
        let (wrap, current_sharing) = {
            let guard = self.private_key.read().unwrap_or_else(|e| e.into_inner());
            let current = guard.as_ref().ok_or(MobileError::KeyNotFound(
                "no private key loaded; cannot open a recovered identity".into(),
            ))?;
            (
                Zeroizing::new(blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity")),
                PublicKey::from(current).to_bytes(),
            )
        };
        let current_signing: Option<Vec<u8>> =
            self.signing_public_key_hex().ok().and_then(|h| hex::decode(h).ok());

        // Every identity once, by its public key; a v2 blob's signing key wins
        // over a v1 blob of the same identity.
        let mut identities: Vec<(StaticSecret, [u8; 32])> = Vec::new();
        let mut signing_claims: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for blob in sealed {
            let Ok(plain) = open_secretbox(&blob.ciphertext, &blob.nonce, wrap.as_slice()) else {
                // Sealed under a key we no longer hold: another reset since.
                tracing::debug!("import_previous_identities_v2: skipping a blob we cannot open");
                continue;
            };
            let plain = Zeroizing::new(plain);
            if plain.len() != 32 && plain.len() != 64 {
                tracing::warn!("import_previous_identities_v2: skipping a blob of the wrong length");
                continue;
            }
            let mut private = [0u8; 32];
            private.copy_from_slice(&plain[..32]);
            let secret = StaticSecret::from(private);
            private.zeroize();
            let sharing = PublicKey::from(&secret).to_bytes();
            if sharing == current_sharing {
                tracing::warn!("import_previous_identities_v2: skipping a blob that names the current identity");
                continue;
            }
            if !identities.iter().any(|(_, known)| *known == sharing) {
                identities.push((secret, sharing));
            }
            if plain.len() == 64 {
                let mut signing = [0u8; 32];
                signing.copy_from_slice(&plain[32..]);
                if VerifyingKey::from_bytes(&signing).is_err() || current_signing.as_deref() == Some(signing.as_slice()) {
                    tracing::warn!("import_previous_identities_v2: a recovered identity's signing key is not trusted");
                } else {
                    signing_claims.push((sharing, signing));
                }
            }
        }
        // A signing key claimed for two identities, or two signing keys claimed
        // for one identity, is trusted for neither.
        let signing: HashMap<[u8; 32], [u8; 32]> = signing_claims
            .iter()
            .filter(|(sharing, key)| !signing_claims.iter().any(|(s, k)| (s == sharing) != (k == key)))
            .copied()
            .collect();

        let count = identities.len() as u32;
        *self.previous_private_keys.write().unwrap_or_else(|e| e.into_inner()) =
            identities.into_iter().map(|(secret, _)| secret).collect();
        *self.previous_signing_keys.write().unwrap_or_else(|e| e.into_inner()) = signing;
        if count > 0 {
            tracing::info!("{} recovered pre-reset identity(ies) available", count);
        }
        Ok(count)
    }

    /// The signing public keys (hex) of the recovered identities this device
    /// holds, from their portal bindings. For an app checking a membership
    /// statement this account signed before a password reset: try these after
    /// its current key. Never the server's word.
    pub fn previous_signing_public_keys(&self) -> Vec<String> {
        let held: Vec<[u8; 32]> = self
            .previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|k| PublicKey::from(k).to_bytes())
            .collect();
        let bindings = self.previous_signing_keys.read().unwrap_or_else(|e| e.into_inner());
        held.iter().filter_map(|sharing| bindings.get(sharing)).map(hex::encode).collect()
    }

    /// Whether the key held for `circle_id` at `key_version` was taken ON TRUST:
    /// stored from an unauthenticated first contact, and not yet seen in a copy
    /// this account signed. Such a key is never signed or delivered here
    /// (`sign_own_circle_key_wrap` and `wrap_circle_key_for_member_full` refuse
    /// it), so a pass that signs this account's unsigned own wraps skips it.
    pub fn circle_key_taken_on_trust(&self, circle_id: String, key_version: i32) -> bool {
        self.circle_key_is_taken_on_trust(&circle_id, key_version)
    }

    /// Whether the key in use for `circle_id` was taken on trust (see
    /// `circle_key_taken_on_trust`). A device that may rotate the circle
    /// rotates it before it seals or delivers anything under that key.
    pub fn active_key_taken_on_trust(&self, circle_id: String) -> bool {
        let Some(version) = self.sealing_version(&circle_id) else {
            return false;
        };
        self.circle_key_is_taken_on_trust(&circle_id, version)
    }

    /// Whether the key in use for `circle_id` came only through an identity
    /// from before a password reset: whoever holds that old identity knows it.
    /// A device that may rotate the circle rotates it before it seals anything
    /// new under that key.
    pub fn active_key_came_via_previous_identity(&self, circle_id: String) -> bool {
        let Some(version) = self.sealing_version(&circle_id) else {
            return false;
        };
        self.circle_provenance
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .via_previous_identity
            .contains(&(CircleKey::of(&circle_id), version))
    }

    /// Whether the server's published copy of the personal key was superseded by
    /// a password reset: this device holds no personal key IN USE, the copy opens
    /// ONLY with an identity from before the reset, and the key inside is held
    /// here, retired. Nothing is lost by minting a new one: mint and publish it
    /// through the usual path (`prepare_circle_creation`,
    /// `publishable_personal_key`, the self-key PUT, `finalize_circle_creation`),
    /// asking nobody; the old one stays retired. Stores nothing.
    pub fn personal_copy_superseded_by_reset(&self, encrypted_key: String, sender_public_key: String) -> bool {
        if self.personal_key_in_use().is_some() {
            return false;
        }
        let (Ok(sender), Ok(encrypted)) = (decode_flexible(&sender_public_key), hex::decode(&encrypted_key)) else {
            return false;
        };
        if sender.len() != 32 || encrypted.len() < 24 {
            return false;
        }
        // A wrap made for the current identity never opens with a restored one:
        // `import_previous_identities_v2` never takes the current identity in.
        let (nonce, ciphertext) = encrypted.split_at(24);
        let Ok(nonce) = <[u8; 24]>::try_from(nonce) else {
            return false;
        };
        let Ok(sender) = <[u8; 32]>::try_from(sender.as_slice()) else {
            return false;
        };
        let Some((key, _)) = self.unwrap_with_previous_identity(&PublicKey::from(sender), &nonce, ciphertext) else {
            return false;
        };
        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT]
            .iter()
            .filter_map(|slot| keys.get(&CircleKey::of(slot)))
            .flat_map(|versions| versions.values())
            .any(|held| ct_eq(held, &key))
    }

    /// How many recovered identities are loaded. For a client that wants to tell
    /// the user why older data became readable again.
    pub fn previous_identity_count(&self) -> u32 {
        self.previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len() as u32
    }

    /// Whether this device holds the private key of a recovered identity whose
    /// X25519 public key is `sharing_public_key_hex` (hex or base64): one that
    /// `import_previous_identities` opened. A public key the server lists proves
    /// nothing; this is how an app tells that a membership statement binding a
    /// pre-reset identity was made for THIS account.
    pub fn holds_previous_identity(&self, sharing_public_key_hex: String) -> bool {
        let Ok(bytes) = decode_flexible(&sharing_public_key_hex) else {
            return false;
        };
        let Ok(wanted) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            return false;
        };
        self.previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|held| PublicKey::from(held).as_bytes() == &wanted)
    }

    /// Store a circle key that `sender_public_key` wrapped for this account
    /// (`encrypted_key`), as version `key_version`. Versions coexist, so data
    /// sealed under an older one stays readable.
    ///
    /// The wrap's signature is checked before the key is opened: a signer pinned
    /// for this circle must sign under its pinned key, and on a circle that holds
    /// pins, a signer never pinned is refused, signed or not. Only first contact
    /// with a circle trusts the signer key sent with the wrap. A refused wrap
    /// returns `MobileError::SignatureInvalid` and stores nothing.
    pub fn store_circle_key(
        &self,
        circle_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        sender_user_id: String,
        recipient_user_id: String,
        wrap_signature_hex: Option<String>,
        sender_signing_pubkey_hex: Option<String>,
    ) -> Result<(), MobileError> {
        self.store_circle_key_inner(
            circle_id,
            encrypted_key,
            sender_public_key,
            key_version,
            sender_user_id,
            recipient_user_id,
            wrap_signature_hex,
            sender_signing_pubkey_hex,
            false,
        )
    }

    /// Store a circle's FIRST key only from a member this app has confirmed.
    /// `store_circle_key` takes an unauthenticated first key on trust; this
    /// refuses one unless
    ///   (1) the wrap carries a signature that verifies under
    ///       `confirmed_sender_signing_pubkey_hex` — the confirmed sender's
    ///       PINNED signing key (`pinned_signing_key`), or ours for our own
    ///       wrap — and
    ///   (2) when `sealed_circle_name` is given (the circle's name as sealed
    ///       under `key_version`), the key opens it: verify before adopting, so
    ///       a wrong key delivered first is never held.
    /// On any refusal nothing is stored and the app asks for a fresh copy. For
    /// a circle this device already holds a key for, use `store_circle_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn store_first_circle_key(
        &self,
        circle_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        sender_user_id: String,
        recipient_user_id: String,
        wrap_signature_hex: String,
        confirmed_sender_signing_pubkey_hex: String,
        sealed_circle_name: Option<EncryptedData>,
    ) -> Result<(), MobileError> {
        // Any spelling of a personal key slot.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput("the personal key has no first key to take".to_string()));
        }
        if self.has_circle_key(circle_id.clone()) {
            return Err(MobileError::InvalidInput(format!(
                "this device already holds a key for circle {circle_id}; use store_circle_key"
            )));
        }
        if !(1..=1_000_000).contains(&key_version) {
            return Err(MobileError::InvalidInput(format!("implausible circle key version: {key_version}")));
        }
        if wrap_signature_hex.is_empty() || sender_user_id.is_empty() || recipient_user_id.is_empty() {
            tracing::warn!("store_first_circle_key: unsigned first key for circle {} v{} — refusing", circle_id, key_version);
            return Err(MobileError::SignatureInvalid);
        }
        let sender_public_bytes = decode_flexible(&sender_public_key)?;
        if sender_public_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let encrypted_bytes = hex::decode(&encrypted_key)
            .map_err(|e| MobileError::CryptoError(format!("Hex decode failed: {}", e)))?;
        if encrypted_bytes.len() < 24 {
            return Err(MobileError::DecryptionFailed);
        }
        let (nonce, ciphertext) = encrypted_bytes.split_at(24);

        if !self.wrap_sig_verifies_either_domain(
            &confirmed_sender_signing_pubkey_hex, &wrap_signature_hex, &sender_user_id, &recipient_user_id,
            &circle_id, key_version as u32, &hex::encode(&sender_public_bytes), &hex::encode(nonce),
            &hex::encode(ciphertext),
        )? {
            tracing::warn!(
                "store_first_circle_key: first key for circle {} v{} is not signed by the confirmed sender — refusing",
                circle_id, key_version
            );
            return Err(MobileError::SignatureInvalid);
        }

        if let Some(sealed) = &sealed_circle_name {
            let key = self.open_circle_key_wrap(&sender_public_bytes, nonce, ciphertext, true)?;
            if !key_opens_circle_name(&key, &circle_id, sealed) {
                tracing::warn!(
                    "store_first_circle_key: first key for circle {} v{} does not open the circle's name — refusing",
                    circle_id, key_version
                );
                return Err(MobileError::DecryptionFailed);
            }
        }

        // Stored through the one path every key takes: version rules, active
        // version, persistence. It checks the signature again, under this
        // circle's pin for the sender when there is one.
        self.store_circle_key(
            circle_id,
            encrypted_key,
            sender_public_key,
            key_version,
            sender_user_id,
            recipient_user_id,
            Some(wrap_signature_hex),
            Some(confirmed_sender_signing_pubkey_hex),
        )
    }

    /// Should this device adopt the SERVER's copy of the account's personal
    /// key? `Adopt` only when all of these hold:
    ///   (a) no personal key this device holds (either slot, any version,
    ///       retired ones included, so a retired key is never adopted again)
    ///       derives `recorded_pseudonym`;
    ///   (b) the server's copy does;
    ///   (c) the copy's wrap signature verifies under this account's OWN
    ///       signing key, the one this device holds. The server echoes no
    ///       signer key; sender and recipient are `user_id`.
    /// Otherwise the first check that failed (see `PersonalKeyVerdict`).
    /// Stores nothing; `adopt_personal_key` stores. The copy's fields are the
    /// self-key bundle's, as passed to `store_circle_key`; `user_id` is this
    /// account's.
    pub fn check_personal_key_adoption(
        &self,
        user_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        wrap_signature_hex: Option<String>,
        recorded_pseudonym: String,
    ) -> PersonalKeyVerdict {
        self.personal_key_verdict(
            &user_id,
            &encrypted_key,
            &sender_public_key,
            key_version,
            wrap_signature_hex.as_deref().unwrap_or(""),
            &recorded_pseudonym,
        )
    }

    /// Adopt the server's copy of the personal key: re-runs
    /// `check_personal_key_adoption` and stores the copy only on `Adopt`, under
    /// the personal key's id (the signature is checked again as it is stored).
    /// It ADDS: the key held before is retired, kept read-only below version 1,
    /// so history under it stays readable; the adopted key is the one in use
    /// for new rows. At most one adoption per 24 hours (`TooSoon`). Any other
    /// verdict comes back with nothing stored. `Err` only when storing a copy
    /// that passed fails.
    pub fn adopt_personal_key(
        &self,
        user_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        wrap_signature_hex: Option<String>,
        recorded_pseudonym: String,
    ) -> Result<PersonalKeyVerdict, MobileError> {
        let verdict = self.personal_key_verdict(
            &user_id,
            &encrypted_key,
            &sender_public_key,
            key_version,
            wrap_signature_hex.as_deref().unwrap_or(""),
            &recorded_pseudonym,
        );
        if verdict != PersonalKeyVerdict::Adopt {
            return Ok(verdict);
        }
        // The only path that may replace a held personal key; the replaced one
        // is retired (kept, read-only), never dropped.
        self.store_circle_key_inner(
            PERSONAL_KEY_ID.to_string(),
            encrypted_key,
            sender_public_key,
            key_version,
            user_id.clone(),
            user_id.clone(),
            wrap_signature_hex,
            None,
            true,
        )?;
        self.personal_provenance.write().unwrap_or_else(|e| e.into_inner()).last_adoption =
            Some(current_unix_secs());
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after adopting the personal key: {}", e);
        }
        // It must now be the personal key in use, or nothing was repaired.
        let in_use = self
            .derive_user_pseudonym(PERSONAL_KEY_ID.to_string(), user_id)
            .map(|p| p.eq_ignore_ascii_case(recorded_pseudonym.trim()))
            .unwrap_or(false);
        if !in_use {
            return Err(MobileError::CryptoError(
                "the adopted personal key is not the one in use".to_string(),
            ));
        }
        tracing::info!("adopt_personal_key: adopted the server's copy of the personal key (v{})", key_version);
        Ok(PersonalKeyVerdict::Adopt)
    }

    /// Copy the personal key in use from one personal slot to the other (the
    /// nil UUID and track-android's legacy "self"), on this device only. It
    /// produces nothing to publish, so it also works for a key taken on trust
    /// (the mark follows the key). A different key already in `to_slot` at
    /// that version is RETIRED, not lost.
    pub fn copy_personal_key(&self, from_slot: String, to_slot: String) -> Result<(), MobileError> {
        // Two slots, by their keys: two spellings of the nil id are one.
        if !is_personal_slot(&from_slot) || !is_personal_slot(&to_slot) || CircleKey::of(&from_slot) == CircleKey::of(&to_slot) {
            return Err(MobileError::InvalidInput(
                "a personal key is copied between the two personal slots only".to_string(),
            ));
        }
        let (version, key) = self.get_active_circle_key_with_version(&from_slot)?;
        let changed = {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let map = keys.entry(CircleKey::of(&to_slot)).or_insert_with(HashMap::new);
            if map.keys().any(|v| *v > version) {
                return Err(MobileError::InvalidInput(
                    "the other personal slot holds a newer version".to_string(),
                ));
            }
            match map.get(&version) {
                Some(held) if ct_eq(held, &key) => false,
                Some(_) => {
                    if let Some(previous) = map.remove(&version) {
                        let retired_at = next_retired_version(map);
                        map.insert(retired_at, previous);
                    }
                    map.insert(version, key);
                    true
                }
                None => {
                    map.insert(version, key);
                    true
                }
            }
        };
        if changed {
            {
                let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
                let current = active.get(&CircleKey::of(&to_slot)).copied().unwrap_or(version);
                active.insert(CircleKey::of(&to_slot), current.max(version));
            }
            self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&to_slot));
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after copying the personal key: {}", e);
            }
        }
        Ok(())
    }

    /// A copy of the personal key held under `held_under` (the nil UUID, "self",
    /// or a creation's temp id) to PUBLISH: wrapped to this account, signed by it
    /// for the nil UUID, with `user_id`'s pseudonym under exactly this key so the
    /// server stores both in one write. Refuses a key taken on trust (never
    /// published, signed or not); needs the signing key.
    pub fn publishable_personal_key(
        &self,
        held_under: String,
        user_id: String,
    ) -> Result<PublishablePersonalKey, MobileError> {
        if user_id.is_empty() || !(is_personal_slot(&held_under) || held_under.starts_with("temp_")) {
            return Err(MobileError::InvalidInput(
                "publish from a personal slot or a creation's temp id, for this account".to_string(),
            ));
        }
        let (key_version, key) = self.get_active_circle_key_with_version(&held_under)?;
        if self.is_taken_on_trust(&key) {
            tracing::warn!("Refusing to publish a personal key this device took on trust");
            return Err(MobileError::InvalidInput(
                "this personal key was taken on trust; it is never published".to_string(),
            ));
        }
        let (nonce, ciphertext, ephemeral) = self.wrap_key_to_own_identity(&key)?;
        let wrap_signature = self.sign_wrap_internal(
            DOMAIN_CIRCLE_MEMBER_WRAP,
            &user_id,
            &user_id,
            PERSONAL_KEY_ID,
            "",
            key_version as u32,
            Some(&ephemeral),
            &nonce,
            &ciphertext,
        )?;
        let symmetric = pingolin_crypto::keys::SymmetricKey::try_from_slice(&key)
            .map_err(|e| MobileError::CryptoError(format!("Invalid personal key: {}", e)))?;
        Ok(PublishablePersonalKey {
            encrypted_key: EncryptedData {
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(&ciphertext),
            },
            ephemeral_public_key: hex::encode(ephemeral),
            key_version,
            wrap_signature,
            user_pseudonym: pingolin_crypto::privacy::derive_user_pseudonym(&symmetric, &user_id),
        })
    }

    /// For the device whose personal key IS the recorded one (its adoption
    /// check says `OwnCopyMatches`): does the server's PUBLISHED copy still
    /// open, with this account's CURRENT keys, to the key in use here? Stores
    /// nothing. Only `CannotOpen` and `Unsigned` may lead to a republish
    /// (`publishable_personal_key`) or a signature, and never of a key taken on
    /// trust; `OpensToDifferentKey` is repaired by adoption, never by
    /// republishing.
    pub fn check_published_personal_copy(
        &self,
        user_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        wrap_signature_hex: Option<String>,
    ) -> PublishedCopyStatus {
        use PublishedCopyStatus as P;
        if user_id.is_empty() || !(1..=1_000_000).contains(&key_version) {
            return P::Malformed;
        }
        let Ok(sender_public_bytes) = decode_flexible(&sender_public_key) else {
            return P::Malformed;
        };
        let Ok(encrypted_bytes) = hex::decode(&encrypted_key) else {
            return P::Malformed;
        };
        if sender_public_bytes.len() != 32 || encrypted_bytes.len() < 24 {
            return P::Malformed;
        }
        let (nonce, ciphertext) = encrypted_bytes.split_at(24);
        let Some(in_use) = self.personal_key_in_use() else {
            return P::NoKeyHere;
        };
        // Current keys only: a copy only a recovered identity opens is one the
        // account's other devices cannot open.
        let Ok(opened) = self.open_circle_key_wrap(&sender_public_bytes, nonce, ciphertext, false) else {
            return P::CannotOpen;
        };
        if !ct_eq(&opened, &in_use) {
            return P::OpensToDifferentKey;
        }
        let Ok(own_signing_hex) = self.signing_public_key_hex() else {
            return P::NoSigningKey;
        };
        let signature = wrap_signature_hex.unwrap_or_default();
        let signed = !signature.is_empty()
            && matches!(
                self.wrap_sig_verifies_either_domain(
                    &own_signing_hex,
                    &signature,
                    &user_id,
                    &user_id,
                    PERSONAL_KEY_ID,
                    key_version as u32,
                    &hex::encode(&sender_public_bytes),
                    &hex::encode(nonce),
                    &hex::encode(ciphertext),
                ),
                Ok(true)
            );
        if !signed {
            return P::Unsigned;
        }
        P::Opens
    }

    /// Whether the personal key in use here was taken on trust: such a key
    /// is never published or signed here, so skip republishing it.
    pub fn personal_key_taken_on_trust(&self) -> bool {
        self.personal_key_in_use().map_or(false, |key| self.is_taken_on_trust(&key))
    }

    /// Encrypt location data for a circle
    pub fn encrypt_location(
        &self,
        circle_id: String,
        location: Location,
    ) -> Result<EncryptedData, MobileError> {
        // Packed plaintext (see location_codec) under the v1 empty AAD — the same
        // key, nonce and AAD that `encrypt_data` uses.
        let plaintext = location_plaintext(&location)?;
        let circle_key = self.get_active_circle_key(&circle_id)?;
        encrypt_with_raw_key(&circle_key, &plaintext)
    }

    /// Decrypt location data from a circle member
    pub fn decrypt_location(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
    ) -> Result<Location, MobileError> {
        // Some senders write "location" fields (e.g. a shared place's
        // coordinates) with the bound circle-field AAD (v2), while
        // encrypt_location itself and older senders write v1 empty-AAD.
        // decrypt_data_v2 tries the v2 "location" AAD first, then falls back to
        // the v1 ciphertext, so both decode. (decrypt_data alone reads only v1
        // and would silently fail on a v2-written location.)
        let plaintext = self.decrypt_data_v2_bytes(&circle_id, &encrypted_location, "location")?;

        // Packed or legacy JSON — `decode_location` accepts both. The JSON branch
        // is load-bearing beyond old location rows: PLACES are sealed as
        // hand-written JSON by the apps and read back through this very method.
        decode_location(&plaintext)
    }

    /// `decrypt_location`, with the circle-key version that opened it. A live
    /// position (SOS, a check-in) is CURRENT only if `is_current_key_version`
    /// says so; else it is history: never live, never a "last seen", never
    /// place-alert input.
    pub fn decrypt_location_opened(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
    ) -> Result<OpenedLocation, MobileError> {
        let (key_version, location) = self.decrypt_location_opened_inner(&circle_id, &encrypted_location)?;
        Ok(OpenedLocation { location, key_version })
    }

    /// Encrypt a location for a circle, binding the SENDER's per-circle
    /// USER pseudonym into the AEAD (AAD v3). Additive sibling of
    /// `encrypt_location` — identical except the ciphertext seals under
    /// `location_aad_v3(sender_pseudonym)` instead of the v1 empty AAD, so a
    /// malicious server cannot serve this ciphertext under another member's
    /// pseudonym without failing the tag. Read back with `decrypt_location_bound`,
    /// which verifies the claimed pseudonym.
    ///
    /// Clients pass `derive_user_pseudonym(circle_id, user_id)` — the sender's own
    /// user_id on encrypt, the user_id the reader resolves for attribution (from
    /// user_id / decrypted encrypted_user_id) on decrypt. A server relabel fails
    /// the AEAD tag. Attribution is by USER, not device: the device pseudonym is
    /// not even present in the client location response, so binding the USER
    /// pseudonym is what ties a row to the member it is displayed as.
    pub fn encrypt_location_bound(
        &self,
        circle_id: String,
        location: Location,
        sender_pseudonym: String,
    ) -> Result<EncryptedData, MobileError> {
        let plaintext = location_plaintext(&location)?;
        let circle_key = self.get_active_circle_key(&circle_id)?;
        encrypt_with_raw_key_aad(
            &circle_key,
            &plaintext,
            &location_aad_v3(&sender_pseudonym),
        )
    }

    /// Decrypt a circle-key location and report whether the sender's
    /// per-circle USER pseudonym was cryptographically verified.
    ///
    /// First tries the v3 sender-bound AAD with `claimed_pseudonym` — the
    /// pseudonym the reader DERIVES for the user_id it resolves this row to —
    /// across every held circle-key version. If the AEAD tag verifies, the server
    /// did NOT relabel it and `sender_verified = true`; the plaintext is then
    /// committed (a JSON error at that point is a real error, not a reason to
    /// retry under a weaker AAD). Otherwise falls back to the legacy unbound
    /// v2-then-v1 decrypt (`decrypt_location`) with `sender_verified = false`.
    /// NEVER returns plaintext on total failure — the error propagates.
    ///
    /// Clients pass `derive_user_pseudonym(circle_id, user_id)` — the sender's own
    /// user_id on encrypt, the user_id the reader resolves for attribution (from
    /// user_id / decrypted encrypted_user_id) on decrypt. A server relabel fails
    /// the AEAD tag.
    #[deprecated(
        note = "use the *_for_user variant; the active-only pseudonym silently drops post-rotation v3 rows"
    )]
    pub fn decrypt_location_bound(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
        claimed_pseudonym: String,
    ) -> Result<BoundLocation, MobileError> {
        // v3: sender-bound AAD, tried across every held circle-key version.
        // The version that opened it is reported.
        if let Ok((key_version, bytes)) = open_with_versions(
            &self.circle_keys,
            &circle_id,
            &encrypted_location,
            &location_aad_v3(&claimed_pseudonym),
        ) {
            let location = decode_location(&bytes)?;
            return Ok(BoundLocation { location, sender_verified: true, key_version });
        }

        // Legacy fallback: unbound v2-then-v1 (propagates the error on total
        // failure — never surfaces plaintext).
        let (key_version, location) = self.decrypt_location_opened_inner(&circle_id, &encrypted_location)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    /// Cross-rotation variant of `decrypt_location_bound`. The active-only
    /// `derive_user_pseudonym` binds the sender pseudonym to the ACTIVE circle-key
    /// version, so a v3 row sealed under a now-superseded version fails the tag
    /// after any rotation (P_active ≠ P_vN) and is silently dropped. This variant
    /// takes the raw `user_id` and re-derives the claimed pseudonym PER held
    /// circle-key version at read time: for each version it derives the pseudonym
    /// from THAT version's key and opens the payload under the same key, so a row
    /// written under any retained version verifies. A tag match ⇒
    /// `sender_verified = true` (a JSON error at that point is a real error, not a
    /// reason to retry a weaker AAD). If no version verifies, falls back to the
    /// legacy unbound v2-then-v1 `decrypt_location` with `sender_verified = false`;
    /// total failure propagates (never surfaces plaintext).
    ///
    /// `user_id` is the user this row is attributed to — the SAME id the sender's
    /// `derive_user_pseudonym` bound at encrypt time.
    pub fn decrypt_location_bound_for_user(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
        user_id: String,
    ) -> Result<BoundLocation, MobileError> {
        // v3 sender-bound: derive the claimed pseudonym per held circle-key version
        // (newest first) and open the payload under that same version. Scope the
        // read guard to this loop — the legacy fallback below re-locks.
        {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            if let Some(versions) = keys.get(&CircleKey::of(&circle_id)) {
                let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
                sorted.sort_by(|a, b| b.0.cmp(a.0));
                for (version, key) in sorted {
                    if let Some(res) =
                        try_v3_location_payload(key, &encrypted_location, key, &user_id)
                    {
                        // The version that opened it.
                        let key_version = *version;
                        return res.map(|location| BoundLocation { location, sender_verified: true, key_version });
                    }
                }
            }
        }

        // Legacy fallback: unbound v2-then-v1 (propagates the error on total
        // failure — never surfaces plaintext).
        let (key_version, location) = self.decrypt_location_opened_inner(&circle_id, &encrypted_location)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    /// Encrypt arbitrary data with circle key (uses active/highest version)
    pub fn encrypt_data(
        &self,
        circle_id: String,
        plaintext: String,
    ) -> Result<EncryptedData, MobileError> {
        let circle_key = self.get_active_circle_key(&circle_id)?;
        encrypt_with_raw_key(&circle_key, plaintext.as_bytes())
    }

    /// AAD v2 circle-field encrypt. `field_tag` is the immutable
    /// field name (e.g. "name", "timestamp", "user_id", "device_id",
    /// "event_type") and MUST match the reader's tag + the web client. Writes
    /// the v2 AAD while AAD_V2_WRITE_ENABLED is set and the v1 empty AAD
    /// otherwise; decrypt_data_v2 reads both.
    pub fn encrypt_data_v2(
        &self,
        circle_id: String,
        plaintext: String,
        field_tag: String,
    ) -> Result<EncryptedData, MobileError> {
        let circle_key = self.get_active_circle_key(&circle_id)?;
        let v2 = circle_field_write_aad_v2(&circle_id, &field_tag);
        let aad: &[u8] = if AAD_V2_WRITE_ENABLED { &v2 } else { b"" };
        encrypt_with_raw_key_aad(&circle_key, plaintext.as_bytes(), aad)
    }

    /// AAD v2 circle-field decrypt: try the v2 circle+field AAD across
    /// every key version, then fall back to the v1 empty AAD so legacy
    /// ciphertext still reads. A relabelled/field-swapped v2 ciphertext fails
    /// both → rejected.
    pub fn decrypt_data_v2(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
        field_tag: String,
    ) -> Result<String, MobileError> {
        let bytes = self.decrypt_data_v2_bytes(&circle_id, &encrypted_data, &field_tag)?;
        String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)
    }

    /// `decrypt_data_v2`, with the circle-key version that opened it. Live data
    /// (the live timestamp, a row's user id) is CURRENT only if
    /// `is_current_key_version` says so; durable config keeps its own policy.
    pub fn decrypt_data_v2_opened(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
        field_tag: String,
    ) -> Result<OpenedText, MobileError> {
        let (key_version, bytes) = self.decrypt_data_v2_bytes_opened(&circle_id, &encrypted_data, &field_tag)?;
        let text = String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)?;
        Ok(OpenedText { text, key_version })
    }


    /// Decrypt arbitrary data with a circle key.
    ///
    /// Tries each known circle-key version, newest first — trying only the ACTIVE
    /// version silently loses older data (e.g. the encrypted userId on a
    /// pre-rotation location, an older encrypted circle name). Any version stored
    /// on-device (native or derived via import_key_chain_link) is tried in turn;
    /// AEAD tag verification guarantees only the correct version succeeds.
    pub fn decrypt_data(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
    ) -> Result<String, MobileError> {
        // Iterate the circle's key versions newest-first under a single read
        // lock, WITHOUT cloning the version vec — matches the AAD path in
        // decrypt_raw_bytes_aad_with_versions. HashMap has no defined order, so
        // we collect (&version, &key) refs and sort by version desc; this
        // allocates only a Vec of references, never copies of the live keys.
        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        let versions = match keys.get(&CircleKey::of(&circle_id)) {
            Some(v) if !v.is_empty() => v,
            _ => return Err(MobileError::KeyNotFound(format!("No circle keys for: {}", circle_id))),
        };
        let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
        sorted.sort_by(|a, b| b.0.cmp(a.0));
        for (_version, key) in sorted {
            if let Ok(s) = decrypt_with_raw_key(key, &encrypted_data) {
                return Ok(s);
            }
        }
        Err(MobileError::DecryptionFailed)
    }

    /// `decrypt_data` (the v1 empty AAD), with the circle-key version that
    /// opened it. Live data is CURRENT only if `is_current_key_version` says
    /// so; durable config (alert rules, inactivity alerts) keeps its own
    /// policy.
    pub fn decrypt_data_opened(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
    ) -> Result<OpenedText, MobileError> {
        let (key_version, bytes) = open_with_versions(&self.circle_keys, &circle_id, &encrypted_data, b"")?;
        let text = String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)?;
        Ok(OpenedText { text, key_version })
    }

    /// Decrypt data with a specific circle key version
    pub fn decrypt_data_with_version(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
        key_version: i32,
    ) -> Result<String, MobileError> {
        let circle_key = self.get_circle_key_version(&circle_id, key_version)?;
        decrypt_with_raw_key(&circle_key, &encrypted_data)
    }

    // ========================================================================
    // Per-place key envelope encryption
    //
    // Each place has its own random 256-bit `place_key`. Encrypted_*
    // fields on the place are encrypted under the place_key. The
    // place_key itself is wrapped (envelope-encrypted) under the
    // owner's personal/self key for ownership AND under each circle's
    // key for sharing. The same place row is decryptable by the owner
    // via their self-key wrap and by any sharing circle's members via
    // the per-circle wrap. Edits to the encrypted_* fields propagate
    // to all viewers automatically — there's only one ciphertext.
    //
    // Lifecycle:
    //   1. generate_place_key() — fresh 32-byte random key
    //   2. encrypt_with_place_key() — encrypt each field under it
    //   3. wrap_place_key(self_target) — owner's wrap (stored on places)
    //   4. wrap_place_key(circle_target) — share wrap (stored in place_shares)
    //   5. unwrap_place_key() + decrypt_with_place_key() — read back
    // ========================================================================

    /// Generate a fresh 256-bit symmetric key for a place. Returned as
    /// a 64-char lowercase hex string. The caller is responsible for
    /// passing this through the rest of the envelope flow without
    /// logging it.
    pub fn generate_place_key(&self) -> String {
        let mut key: [u8; 32] = generate_secure_nonce();
        let encoded = hex::encode(&key);
        // SECURITY: wipe the raw stack copy; the returned hex string is the only retained form.
        key.zeroize();
        encoded
    }

    /// Wrap a place key for the OWNER's self-key (the owner-side wrap).
    ///
    /// `target_id` is the owner's self-tracking circle id (or the nil UUID).
    /// The returned KeyWrap is what gets stored in the `places.wrapped_key`
    /// column.
    ///
    /// The wrap context is signed here under DOMAIN
    /// `pingolin.sig.v1.place_owner_wrap` only so that a signing failure
    /// surfaces at the wrap call site; the signature itself is DISCARDED,
    /// because `KeyWrap` carries no signature field and its wire shape has to
    /// stay readable by the web and iOS clients. A caller that wants the
    /// signature calls `sign_wrap` with the same context and attaches it
    /// alongside the row. Signature inputs: `place_id`, `sender_user_id`,
    /// `key_version = 0`, no recipient, no ephemeral pubkey.
    pub fn wrap_place_key(
        &self,
        target_id: String,
        place_key_hex: String,
        sender_user_id: String,
        place_id: String,
    ) -> Result<KeyWrap, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        // AAD-bound to the place_key wrap context, so the AEAD tag
        // authenticates "this is a place_key wrap" — an attacker who
        // tries to substitute a wrap-from-another-context (e.g. a
        // location msg_key wrap) will fail unwrap with a tag-verify
        // error rather than yielding a 32-byte secret that's then used
        // out of context.
        let circle_key = self.get_active_circle_key(&target_id)?;
        if circle_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let encrypted = encrypt_with_raw_key_aad(&circle_key, &place_key, AAD_PLACE_KEY_WRAP)?;

        // Compute the owner signature (DOMAIN place_owner_wrap) eagerly and
        // discard it: `KeyWrap` has no field to carry it, but computing it here
        // surfaces a signing failure at the wrap call site rather than later.
        let wrap_nonce_bytes = decode_flexible(&encrypted.nonce)?;
        let wrap_ct_bytes = decode_flexible(&encrypted.ciphertext)?;
        let _owner_sig = self.sign_wrap_internal(
            DOMAIN_PLACE_OWNER_WRAP,
            &sender_user_id,
            "",
            "",
            &place_id,
            0,
            None,
            &wrap_nonce_bytes,
            &wrap_ct_bytes,
        ).unwrap_or_else(|e| {
            tracing::warn!("place_owner_wrap signature emission failed: {}", e);
            String::new()
        });

        Ok(KeyWrap {
            target_id,
            wrapped_key_nonce: encrypted.nonce,
            wrapped_key: encrypted.ciphertext,
        })
    }

    /// Wrap a place key for a SHARED circle (the per-circle share wrap).
    ///
    /// Counterpart to `wrap_place_key`, but for the per-circle entries that
    /// live in `place_shares`. Signs the wrap context under DOMAIN
    /// `pingolin.sig.v1.place_share_wrap`. Inputs to the signature:
    /// `circle_id`, `place_id`, `sender_user_id`, `key_version=0`, no
    /// recipient, no ephemeral pubkey.
    pub fn wrap_place_key_for_circle(
        &self,
        circle_id: String,
        place_key_hex: String,
        sender_user_id: String,
        place_id: String,
    ) -> Result<KeyWrap, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let circle_key = self.get_active_circle_key(&circle_id)?;
        if circle_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let encrypted = encrypt_with_raw_key_aad(&circle_key, &place_key, AAD_PLACE_KEY_WRAP)?;

        // Compute the share-wrap signature (DOMAIN place_share_wrap); see
        // `wrap_place_key` for why it is computed and then discarded.
        let wrap_nonce_bytes = decode_flexible(&encrypted.nonce)?;
        let wrap_ct_bytes = decode_flexible(&encrypted.ciphertext)?;
        let _share_sig = self.sign_wrap_internal(
            DOMAIN_PLACE_SHARE_WRAP,
            &sender_user_id,
            "",
            &circle_id,
            &place_id,
            0,
            None,
            &wrap_nonce_bytes,
            &wrap_ct_bytes,
        ).unwrap_or_else(|e| {
            tracing::warn!("place_share_wrap signature emission failed: {}", e);
            String::new()
        });

        Ok(KeyWrap {
            target_id: circle_id,
            wrapped_key_nonce: encrypted.nonce,
            wrapped_key: encrypted.ciphertext,
        })
    }

    /// Unwrap a place key. Tries each known circle-key version newest-
    /// first, the same way decrypt_data does — pre-rotation places
    /// that were wrapped under an older key version still decrypt.
    /// Returns the place_key as a 64-char hex string.
    pub fn unwrap_place_key(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
    ) -> Result<String, MobileError> {
        let encrypted = EncryptedData {
            nonce: wrapped_key_nonce,
            ciphertext: wrapped_key,
        };
        // AAD-bound to the place_key wrap context — same constant used
        // by wrap_place_key. The AEAD verify rejects any wrap that
        // wasn't issued with this exact AAD, even if the underlying
        // circle key is correct.
        // SECURITY: Zeroizing so the unwrapped place key is wiped on drop (the
        // hex String returned across FFI is the caller's to manage).
        let plain = Zeroizing::new(decrypt_raw_bytes_aad_with_versions(
            &self.circle_keys,
            &target_id,
            &encrypted,
            AAD_PLACE_KEY_WRAP,
        )?);
        if plain.len() != 32 {
            return Err(MobileError::DecryptionFailed);
        }
        Ok(hex::encode(plain.as_slice()))
    }

    /// `unwrap_place_key`, with the circle-key version that unwrapped it: the
    /// place key hex. A place is durable config, never re-wrapped at a
    /// rotation, so it keeps its own app policy.
    pub fn unwrap_place_key_opened(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
    ) -> Result<OpenedText, MobileError> {
        let encrypted = EncryptedData { nonce: wrapped_key_nonce, ciphertext: wrapped_key };
        // SECURITY: Zeroizing so the unwrapped place key is wiped on drop (the
        // hex String returned across FFI is the caller's to manage).
        let (key_version, plain) = open_with_versions(&self.circle_keys, &target_id, &encrypted, AAD_PLACE_KEY_WRAP)?;
        let plain = Zeroizing::new(plain);
        if plain.len() != 32 {
            return Err(MobileError::DecryptionFailed);
        }
        Ok(OpenedText { text: hex::encode(plain.as_slice()), key_version })
    }

    /// Encrypt arbitrary plaintext under a place key (rather than a
    /// circle key). Returned EncryptedData is what gets stored in the
    /// `encrypted_*` columns of a place that carries its own place
    /// key.
    pub fn encrypt_with_place_key(
        &self,
        place_key_hex: String,
        plaintext: String,
    ) -> Result<EncryptedData, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        // AAD = place-field domain tag. Bound into authentication so a
        // ciphertext encrypted under this place_key for one purpose
        // (e.g. encrypted_name) can't be reinterpreted as a different
        // shape if an attacker were to swap blobs across rows.
        encrypt_with_raw_key_aad(&place_key, plaintext.as_bytes(), AAD_PLACE_FIELD)
    }

    /// Decrypt EncryptedData under a place key. Used by the read path
    /// for any place that carries its own place key, once the place
    /// key has been unwrapped via `unwrap_place_key`.
    pub fn decrypt_with_place_key(
        &self,
        place_key_hex: String,
        encrypted_data: EncryptedData,
    ) -> Result<String, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let bytes = decrypt_raw_bytes_aad(&place_key, &encrypted_data, AAD_PLACE_FIELD)?;
        String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)
    }

    /// AAD v2 place-field encrypt. `field_tag` is the immutable
    /// field name (e.g. "name", "location", "address", "notes") and MUST
    /// match the tag the reader passes. Writes the v2 AAD while
    /// AAD_V2_WRITE_ENABLED is set and the static v1 AAD_PLACE_FIELD
    /// otherwise; `decrypt_with_place_key_v2` reads
    /// both. Bind the field, not place_id (unassigned at create; the per-place
    /// key already separates places — field confusion is the residual gap).
    pub fn encrypt_with_place_key_v2(
        &self,
        place_key_hex: String,
        plaintext: String,
        field_tag: String,
    ) -> Result<EncryptedData, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let v2 = place_field_aad_v2(&field_tag);
        let aad: &[u8] = if AAD_V2_WRITE_ENABLED { &v2 } else { AAD_PLACE_FIELD };
        encrypt_with_raw_key_aad(&place_key, plaintext.as_bytes(), aad)
    }

    /// AAD v2 place-field decrypt: try the v2 field-bound AAD, then
    /// fall back to the v1 static AAD so legacy ciphertext still reads. A
    /// field-swapped v2 ciphertext fails BOTH (v2 = wrong tag, v1 = it was
    /// sealed with a v2 AAD) → rejected, which is the point.
    pub fn decrypt_with_place_key_v2(
        &self,
        place_key_hex: String,
        encrypted_data: EncryptedData,
        field_tag: String,
    ) -> Result<String, MobileError> {
        // SECURITY: Zeroizing so the decoded 32-byte place key is wiped on drop.
        let place_key = Zeroizing::new(
            hex::decode(&place_key_hex)
                .map_err(|_| MobileError::InvalidInput("Invalid place_key hex".to_string()))?,
        );
        if place_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let v2 = place_field_aad_v2(&field_tag);
        let bytes = match decrypt_raw_bytes_aad(&place_key, &encrypted_data, &v2) {
            Ok(b) => b,
            Err(_) => decrypt_raw_bytes_aad(&place_key, &encrypted_data, AAD_PLACE_FIELD)?,
        };
        String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)
    }

    /// Decrypt data by key_id string (routes to session key or circle key version)
    ///
    /// key_id format:
    /// - "s:{uuid}" → session key
    /// - "c:{version}" → circle key version (current format)
    /// - integer string (e.g. "3") → circle key version 3 (backward compat)
    /// - "v1" → legacy, treated as circle key version 1
    pub fn decrypt_data_by_key_id(
        &self,
        circle_id: String,
        encrypted_data: EncryptedData,
        key_id: String,
    ) -> Result<String, MobileError> {
        let key = self.resolve_decryption_key(&circle_id, &key_id)?;
        decrypt_with_raw_key(&key, &encrypted_data)
    }

    // ========================================================================
    // Envelope Encryption Methods
    // ========================================================================

    /// Envelope-encrypt a location for multiple targets (circles + self).
    ///
    /// Instead of encrypting the location N times (once per circle), this:
    /// 1. Generates a random 32-byte msg_key
    /// 2. Encrypts the location ONCE with msg_key (XChaCha20-Poly1305)
    /// 3. Wraps msg_key separately for each target_id (circle key or self key)
    ///
    /// This is more efficient: one ~200 byte ciphertext + N ~80 byte key wraps,
    /// instead of N ~200 byte ciphertexts. `target_ids` are circle IDs and/or
    /// self-tracking IDs.
    ///
    /// # Security
    /// - msg_key is generated fresh per call (never reused)
    /// - msg_key is zeroized after all wraps complete
    /// - Each key wrap uses a unique random nonce
    pub fn envelope_encrypt_location(
        &self,
        location: Location,
        target_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedLocation, MobileError> {
        if target_ids.is_empty() {
            return Err(MobileError::InvalidInput("No target IDs provided for envelope encryption".to_string()));
        }

        // Packed plaintext (see location_codec); the envelope's keys, nonces and
        // AADs are untouched.
        let plaintext = location_plaintext(&location)?;
        let timestamp = location.timestamp;

        // Step 1: Generate random msg_key (32 bytes). Born inside Zeroizing so it
        // wipes on EVERY return path — including the `?` early-returns below.
        let msg_key_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());

        // Step 2: Encrypt location ONCE with msg_key
        let cipher = XChaCha20Poly1305::new_from_slice(msg_key_zeroizing.as_slice()).expect("32-byte key");
        let ciphertext_nonce: [u8; 24] = generate_secure_nonce();
        let ciphertext = cipher
            .encrypt(&XNonce::from(ciphertext_nonce), plaintext.as_slice())
            .map_err(|_| MobileError::EncryptionFailed)?;

        // Step 3: Wrap msg_key for each target
        let mut key_wraps = Vec::with_capacity(target_ids.len());

        for target_id in &target_ids {
            let wrapped = self.wrap_msg_key(target_id.clone(), &*msg_key_zeroizing)?;
            key_wraps.push(wrapped);
        }

        // msg_key_zeroizing wipes on drop here (and on every `?` above).
        Ok(EnvelopeEncryptedLocation {
            ciphertext: hex::encode(&ciphertext),
            ciphertext_nonce: hex::encode(ciphertext_nonce),
            timestamp,
            key_wraps,
        })
    }

    /// Unwrap a msg_key and decrypt a location from envelope encryption.
    ///
    /// This is the decryption counterpart to envelope_encrypt_location:
    /// 1. Unwrap the msg_key using the circle/self key named by `target_id`
    /// 2. Decrypt the location ciphertext using the unwrapped msg_key
    ///
    /// The wrapped key, both nonces and the ciphertext are hex-encoded.
    pub fn unwrap_and_decrypt_location(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
    ) -> Result<Location, MobileError> {
        // Parse nonces/ciphertext once, before the version loop.
        let wrap_nonce_bytes = decode_flexible(&wrapped_key_nonce)?;
        if wrap_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid wrapped key nonce length".to_string()));
        }
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);
        let wrapped_key_bytes = decode_flexible(&wrapped_key)?;

        // Step 1: Try to unwrap msg_key against each known circle-key version, newest
        // first. The msg_key was wrapped with whatever circle-key version was active
        // at encryption time — after a rotation, that's often older than the current
        // active version. Older versions are still on-device if the key chain was
        // imported (see import_key_chain_link), so this loop is what keeps
        // pre-rotation data readable.
        let mut unwrapped: Option<Vec<u8>> = None;
        {
            // Iterate key versions newest-first under a single read lock, WITHOUT
            // cloning the version vec — matches decrypt_raw_bytes_aad_with_versions.
            // The lock is dropped at the end of this block, before the msg_key
            // decrypt below (which uses the unwrapped msg_key, not a circle key).
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let versions = match keys.get(&CircleKey::of(&target_id)) {
                Some(v) if !v.is_empty() => v,
                _ => return Err(MobileError::KeyNotFound(
                    format!("No circle keys for target: {}", target_id)
                )),
            };
            let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
            sorted.sort_by(|a, b| b.0.cmp(a.0));
            for (_version, circle_key) in sorted {
                if circle_key.len() != 32 {
                    continue;
                }
                let mut ck = Zeroizing::new([0u8; 32]);
                ck.copy_from_slice(circle_key);
                let unwrap_cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice()).expect("32-byte key");
                if let Ok(bytes) = unwrap_cipher
                    .decrypt(&XNonce::from(wrap_nonce), wrapped_key_bytes.as_ref())
                {
                    unwrapped = Some(bytes);
                    break;
                }
            }
        }
        // SECURITY: Zeroizing so the unwrapped msg_key heap Vec is wiped on drop.
        let msg_key_bytes = Zeroizing::new(unwrapped.ok_or(MobileError::DecryptionFailed)?);

        if msg_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Unwrapped msg_key has invalid length".to_string()));
        }

        let mut msg_key = Zeroizing::new([0u8; 32]);
        msg_key.copy_from_slice(&msg_key_bytes);

        // Step 2: Decrypt location ciphertext with msg_key
        let decrypt_cipher = XChaCha20Poly1305::new_from_slice(msg_key.as_slice()).expect("32-byte key");

        let ct_nonce_bytes = decode_flexible(&ciphertext_nonce)?;
        if ct_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid ciphertext nonce length".to_string()));
        }
        let mut ct_nonce = [0u8; 24];
        ct_nonce.copy_from_slice(&ct_nonce_bytes);

        let ct_bytes = decode_flexible(&ciphertext)?;

        let plaintext_bytes = decrypt_cipher
            .decrypt(&XNonce::from(ct_nonce), ct_bytes.as_ref())
            .map_err(|_| MobileError::DecryptionFailed)?;

        decode_location(&plaintext_bytes)
    }

    /// AAD-v2 variant of `envelope_encrypt_location`. Binds the location payload
    /// to the location domain and each msg_key wrap to its target. Gated on
    /// `AAD_V2_WRITE_ENABLED`: with the flag clear, writes stay byte-identical to
    /// `envelope_encrypt_location` (empty AAD) so pre-v2 clients can still read.
    pub fn envelope_encrypt_location_v2(
        &self,
        location: Location,
        target_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedLocation, MobileError> {
        if target_ids.is_empty() {
            return Err(MobileError::InvalidInput("No target IDs provided for envelope encryption".to_string()));
        }

        let plaintext = location_plaintext(&location)?;
        let timestamp = location.timestamp;

        // Fresh per-call msg_key (never reused). Born inside Zeroizing so it wipes
        // on EVERY return path — including the `?` early-returns below.
        let msg_key_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());

        // Payload: bind to the location domain when writing v2.
        let payload_v2 = location_aad_v2();
        let payload_aad: &[u8] = if AAD_V2_WRITE_ENABLED { &payload_v2 } else { b"" };
        let enc = encrypt_with_raw_key_aad(&*msg_key_zeroizing, &plaintext, payload_aad)?;

        // Wraps: bind each to its target when writing v2.
        let mut key_wraps = Vec::with_capacity(target_ids.len());
        for target_id in &target_ids {
            let wrap_v2 = msg_key_wrap_aad_v2(target_id);
            let wrap_aad: &[u8] = if AAD_V2_WRITE_ENABLED { &wrap_v2 } else { b"" };
            let wrapped = self.wrap_msg_key_aad(target_id.clone(), &*msg_key_zeroizing, wrap_aad)?;
            key_wraps.push(wrapped);
        }

        // msg_key_zeroizing wipes on drop here (and on every `?` above).
        Ok(EnvelopeEncryptedLocation {
            ciphertext: enc.ciphertext,
            ciphertext_nonce: enc.nonce,
            timestamp,
            key_wraps,
        })
    }

    /// AAD-v2 variant of `unwrap_and_decrypt_location`. Tries the v2 AADs
    /// (per-target wrap + location payload domain) first, then falls back to v1
    /// (empty AAD) so ciphertext written with the v1 AAD still decrypts.
    pub fn unwrap_and_decrypt_location_v2(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
    ) -> Result<Location, MobileError> {
        let wrap_nonce_bytes = decode_flexible(&wrapped_key_nonce)?;
        if wrap_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid wrapped key nonce length".to_string()));
        }
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);
        let wrapped_key_bytes = decode_flexible(&wrapped_key)?;

        // Unwrap the msg_key against each known circle-key version (newest
        // first) under one read lock, for a given wrap AAD. Returns the first
        // version that verifies. See unwrap_and_decrypt_location for why older
        // versions must be tried (pre-rotation data).
        let try_unwrap = |aad: &[u8]| -> Option<Vec<u8>> {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let versions = keys.get(&CircleKey::of(&target_id))?;
            if versions.is_empty() {
                return None;
            }
            let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
            sorted.sort_by(|a, b| b.0.cmp(a.0));
            for (_version, circle_key) in sorted {
                if circle_key.len() != 32 {
                    continue;
                }
                let mut ck = Zeroizing::new([0u8; 32]);
                ck.copy_from_slice(circle_key);
                let cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice()).expect("32-byte key");
                let payload = chacha20poly1305::aead::Payload {
                    msg: wrapped_key_bytes.as_ref(),
                    aad,
                };
                if let Ok(bytes) = cipher.decrypt(&XNonce::from(wrap_nonce), payload) {
                    return Some(bytes);
                }
            }
            None
        };

        // v2 wrap AAD first, then v1 empty AAD.
        let wrap_v2 = msg_key_wrap_aad_v2(&target_id);
        // SECURITY: the unwrapped msg_key heap Vec must be Zeroizing too — the
        // [u8;32] copy below is already wiped on drop, but this Vec holds the
        // same raw key bytes.
        let msg_key_bytes = Zeroizing::new(
            try_unwrap(&wrap_v2)
                .or_else(|| try_unwrap(b""))
                .ok_or(MobileError::DecryptionFailed)?,
        );

        if msg_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Unwrapped msg_key has invalid length".to_string()));
        }
        let mut msg_key = Zeroizing::new([0u8; 32]);
        msg_key.copy_from_slice(&msg_key_bytes);

        // Decrypt the payload: v2 location AAD first, then v1 empty AAD.
        let enc = EncryptedData {
            nonce: ciphertext_nonce,
            ciphertext,
        };
        let payload_v2 = location_aad_v2();
        let plaintext_bytes = decrypt_raw_bytes_aad(&*msg_key, &enc, &payload_v2)
            .or_else(|_| decrypt_raw_bytes_aad(&*msg_key, &enc, b""))?;

        decode_location(&plaintext_bytes)
    }

    /// Sender-bound variant of `envelope_encrypt_location_v2`. Seals the shared
    /// payload under `location_aad_v3(sender_pseudonym)` and binds each msg_key
    /// wrap to its target with `msg_key_wrap_aad_v2(target_id)`. Read back with
    /// `unwrap_and_decrypt_location_bound`, which verifies the claimed pseudonym; a
    /// server relabel (serving this payload under another member's pseudonym) fails
    /// the payload AEAD tag.
    ///
    /// `sender_pseudonym` is the sender's own `derive_user_pseudonym(circle_id,
    /// user_id)`. The payload is ALWAYS v3-bound here (NOT gated on
    /// AAD_V2_WRITE_ENABLED, unlike the v2 writer) because a v3 envelope is only
    /// meant to be read by the bound reader.
    ///
    /// NOTE: the sender path in use is the session-key
    /// `encrypt_location_with_session_key_bound`; this exists so an envelope
    /// sender can bind its own pseudonym.
    pub fn envelope_encrypt_location_bound(
        &self,
        location: Location,
        target_ids: Vec<String>,
        sender_pseudonym: String,
    ) -> Result<EnvelopeEncryptedLocation, MobileError> {
        // A bound envelope carries exactly ONE `sender_pseudonym`, but pseudonyms
        // are per-circle: a multi-target envelope would only verify in the single
        // circle whose pseudonym was supplied. Require exactly one target so the
        // per-circle sender binding can never be silently wrong; the
        // len != 1 guard also subsumes the empty case. Callers pass a single id.
        if target_ids.len() != 1 {
            return Err(MobileError::InvalidInput(
                "envelope_encrypt_location_bound requires exactly one target_id (sender_pseudonym is per-circle)".to_string(),
            ));
        }

        let plaintext = location_plaintext(&location)?;
        let timestamp = location.timestamp;

        // Fresh per-call msg_key (never reused). Born inside Zeroizing so it wipes
        // on EVERY return path — including the `?` early-returns below.
        let msg_key_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());

        // Payload: sender-bound v3 AAD (always, since this is the bound writer).
        let payload_v3 = location_aad_v3(&sender_pseudonym);
        let enc = encrypt_with_raw_key_aad(&*msg_key_zeroizing, &plaintext, &payload_v3)?;

        // Wraps: bind each to its target (v2 wrap AAD) — matches the bound reader's
        // v2-then-v1 unwrap.
        let mut key_wraps = Vec::with_capacity(target_ids.len());
        for target_id in &target_ids {
            let wrap_v2 = msg_key_wrap_aad_v2(target_id);
            let wrapped = self.wrap_msg_key_aad(target_id.clone(), &*msg_key_zeroizing, &wrap_v2)?;
            key_wraps.push(wrapped);
        }

        // msg_key_zeroizing wipes on drop here (and on every `?` above).
        Ok(EnvelopeEncryptedLocation {
            ciphertext: enc.ciphertext,
            ciphertext_nonce: enc.nonce,
            timestamp,
            key_wraps,
        })
    }

    /// Sender-bound variant of `unwrap_and_decrypt_location_v2` (the envelope /
    /// wrapped-msg-key path — the iOS client reads member locations exclusively
    /// through this path, and Android reads wrappedMsgKey rows through it). The msg_key
    /// unwrap is UNCHANGED (try `msg_key_wrap_aad_v2(target_id)` then v1 empty — the
    /// wrap is target-bound, never pseudonym-bound); only the PAYLOAD AEAD carries
    /// the sender binding.
    ///
    /// Payload decrypt order: v3 `location_aad_v3(claimed_pseudonym)` FIRST — a tag
    /// match proves the server did NOT relabel this row, so `sender_verified = true`
    /// (a JSON error at that point is a real error, not a reason to retry a weaker
    /// AAD). Otherwise falls back to the legacy v2 (`location_aad_v2()`) then v1
    /// (empty) payload AAD with `sender_verified = false`. A relabelled v3 envelope
    /// (wrong pseudonym) fails v3 AND the v2/v1 fallback (different AAD) ⇒ the error
    /// propagates (never plaintext), matching the circle-key/session-key bound
    /// decrypts.
    ///
    /// `claimed_pseudonym` is the reader's `derive_user_pseudonym(circle_id,
    /// user_id)` for the user this row is attributed to.
    #[deprecated(
        note = "use the *_for_user variant; the active-only pseudonym silently drops post-rotation v3 rows"
    )]
    pub fn unwrap_and_decrypt_location_bound(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
        claimed_pseudonym: String,
    ) -> Result<BoundLocation, MobileError> {
        let wrap_nonce_bytes = decode_flexible(&wrapped_key_nonce)?;
        if wrap_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid wrapped key nonce length".to_string()));
        }
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);
        let wrapped_key_bytes = decode_flexible(&wrapped_key)?;

        // Unwrap the msg_key against each known circle-key version (newest first)
        // under one read lock, for a given wrap AAD. Identical to
        // unwrap_and_decrypt_location_v2 — the wrap binding is orthogonal to the
        // payload sender-binding.
        let try_unwrap = |aad: &[u8]| -> Option<(i32, Vec<u8>)> {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let versions = keys.get(&CircleKey::of(&target_id))?;
            if versions.is_empty() {
                return None;
            }
            let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
            sorted.sort_by(|a, b| b.0.cmp(a.0));
            for (version, circle_key) in sorted {
                if circle_key.len() != 32 {
                    continue;
                }
                let mut ck = Zeroizing::new([0u8; 32]);
                ck.copy_from_slice(circle_key);
                let cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice()).expect("32-byte key");
                let payload = chacha20poly1305::aead::Payload {
                    msg: wrapped_key_bytes.as_ref(),
                    aad,
                };
                if let Ok(bytes) = cipher.decrypt(&XNonce::from(wrap_nonce), payload) {
                    return Some((*version, bytes));
                }
            }
            None
        };

        // v2 wrap AAD first, then v1 empty AAD.
        let wrap_v2 = msg_key_wrap_aad_v2(&target_id);
        // SECURITY: the unwrapped msg_key heap Vec must be Zeroizing too — the
        // [u8;32] copy below is already wiped on drop, but this Vec holds the
        // same raw key bytes.
        // The version that unwrapped it is the row's.
        let (key_version, msg_key_bytes) = try_unwrap(&wrap_v2)
            .or_else(|| try_unwrap(b""))
            .ok_or(MobileError::DecryptionFailed)?;
        let msg_key_bytes = Zeroizing::new(msg_key_bytes);

        if msg_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Unwrapped msg_key has invalid length".to_string()));
        }
        let mut msg_key = Zeroizing::new([0u8; 32]);
        msg_key.copy_from_slice(&msg_key_bytes);

        let enc = EncryptedData {
            nonce: ciphertext_nonce,
            ciphertext,
        };

        // Payload v3 (sender-bound) FIRST: a tag match ⇒ no relabel ⇒ verified.
        let payload_v3 = location_aad_v3(&claimed_pseudonym);
        if let Ok(bytes) = decrypt_raw_bytes_aad(&*msg_key, &enc, &payload_v3) {
            let location = decode_location(&bytes)?;
            return Ok(BoundLocation { location, sender_verified: true, key_version });
        }

        // Legacy fallback: v2 location AAD then v1 empty AAD (unbound sender).
        // Total failure propagates — never surfaces plaintext.
        let payload_v2 = location_aad_v2();
        let plaintext_bytes = decrypt_raw_bytes_aad(&*msg_key, &enc, &payload_v2)
            .or_else(|_| decrypt_raw_bytes_aad(&*msg_key, &enc, b""))?;
        let location = decode_location(&plaintext_bytes)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    /// Cross-rotation variant of `unwrap_and_decrypt_location_bound` (the envelope /
    /// wrapped-msg-key path). The msg_key unwrap is UNCHANGED (target-bound wrap,
    /// tried `msg_key_wrap_aad_v2(target_id)` then v1 empty across circle-key
    /// versions). Only the PAYLOAD attribution changes: instead of a single
    /// caller-supplied `claimed_pseudonym` (bound to the ACTIVE circle-key
    /// version), this variant re-derives the claimed pseudonym PER held circle-key
    /// version and opens the v3 payload under the FIXED unwrapped msg_key, so an
    /// envelope written under a now-superseded version still verifies after a
    /// rotation. A tag match ⇒ `sender_verified = true`; otherwise falls back to
    /// the legacy v2 (`location_aad_v2()`) then v1 (empty) payload AAD with
    /// `sender_verified = false`. Total failure propagates (never surfaces
    /// plaintext).
    ///
    /// `user_id` is the user this row is attributed to — the id the sender's
    /// `derive_user_pseudonym` bound at encrypt time.
    pub fn unwrap_and_decrypt_location_bound_for_user(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
        user_id: String,
    ) -> Result<BoundLocation, MobileError> {
        let wrap_nonce_bytes = decode_flexible(&wrapped_key_nonce)?;
        if wrap_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid wrapped key nonce length".to_string()));
        }
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);
        let wrapped_key_bytes = decode_flexible(&wrapped_key)?;

        // Unwrap the msg_key against each known circle-key version (newest first)
        // under one read lock, for a given wrap AAD. Identical to
        // unwrap_and_decrypt_location_bound — the wrap binding is orthogonal to the
        // payload sender-binding.
        let try_unwrap = |aad: &[u8]| -> Option<(i32, Vec<u8>)> {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let versions = keys.get(&CircleKey::of(&target_id))?;
            if versions.is_empty() {
                return None;
            }
            let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
            sorted.sort_by(|a, b| b.0.cmp(a.0));
            for (version, circle_key) in sorted {
                if circle_key.len() != 32 {
                    continue;
                }
                let mut ck = Zeroizing::new([0u8; 32]);
                ck.copy_from_slice(circle_key);
                let cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice()).expect("32-byte key");
                let payload = chacha20poly1305::aead::Payload {
                    msg: wrapped_key_bytes.as_ref(),
                    aad,
                };
                if let Ok(bytes) = cipher.decrypt(&XNonce::from(wrap_nonce), payload) {
                    return Some((*version, bytes));
                }
            }
            None
        };

        // v2 wrap AAD first, then v1 empty AAD.
        let wrap_v2 = msg_key_wrap_aad_v2(&target_id);
        // SECURITY: the unwrapped msg_key heap Vec must be Zeroizing too — the
        // [u8;32] copy below is already wiped on drop, but this Vec holds the
        // same raw key bytes.
        // The version that unwrapped it is the row's.
        let (key_version, msg_key_bytes) = try_unwrap(&wrap_v2)
            .or_else(|| try_unwrap(b""))
            .ok_or(MobileError::DecryptionFailed)?;
        let msg_key_bytes = Zeroizing::new(msg_key_bytes);

        if msg_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Unwrapped msg_key has invalid length".to_string()));
        }
        let mut msg_key = Zeroizing::new([0u8; 32]);
        msg_key.copy_from_slice(&msg_key_bytes);

        let enc = EncryptedData {
            nonce: ciphertext_nonce,
            ciphertext,
        };

        // Payload v3 (sender-bound): re-derive the claimed pseudonym PER held
        // circle-key version and open under the FIXED unwrapped msg_key. A tag
        // match ⇒ no relabel ⇒ verified. Fresh read lock — try_unwrap's guards
        // are already released.
        {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            if let Some(versions) = keys.get(&CircleKey::of(&target_id)) {
                let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
                sorted.sort_by(|a, b| b.0.cmp(a.0));
                for (_version, ck) in sorted {
                    if let Some(res) = try_v3_location_payload(&*msg_key, &enc, ck, &user_id) {
                        return res.map(|location| BoundLocation { location, sender_verified: true, key_version });
                    }
                }
            }
        }

        // Legacy fallback: v2 location AAD then v1 empty AAD (unbound sender).
        // Total failure propagates — never surfaces plaintext.
        let payload_v2 = location_aad_v2();
        let plaintext_bytes = decrypt_raw_bytes_aad(&*msg_key, &enc, &payload_v2)
            .or_else(|_| decrypt_raw_bytes_aad(&*msg_key, &enc, b""))?;
        let location = decode_location(&plaintext_bytes)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    // ========================================================================
    // Place Envelope Encryption (sharing places with circles)
    // ========================================================================

    /// Envelope-encrypt arbitrary place data for multiple targets (circles + self).
    ///
    /// 1. Generates a random 32-byte per-place key
    /// 2. Encrypts the plaintext data ONCE with the per-place key (XChaCha20-Poly1305)
    /// 3. Wraps the per-place key separately for each target_id (circle key or self key)
    ///
    /// `plaintext` is a JSON string of place data; `target_ids` are circle IDs
    /// and/or self-tracking IDs. Returns one ciphertext plus per-target key
    /// wraps: the caller stores the ciphertext and distributes the wraps.
    ///
    /// # Security
    /// - per-place key is generated fresh per call (never reused)
    /// - per-place key is zeroized after all wraps complete
    /// - Each key wrap uses a unique random nonce
    /// - AAD v2 (gated on `AAD_V2_WRITE_ENABLED`): payload bound to
    ///   `place_aad_v2()` (place-envelope domain) and each wrap to
    ///   `msg_key_wrap_aad_v2(target)`; `unwrap_and_decrypt_place` reads v2 then
    ///   falls back to the v1 empty AAD, so rows written with v1 still decrypt.
    pub fn envelope_encrypt_place(
        &self,
        plaintext: String,
        target_ids: Vec<String>,
    ) -> Result<EnvelopeEncryptedLocation, MobileError> {
        if target_ids.is_empty() {
            return Err(MobileError::InvalidInput("No target IDs provided for envelope encryption".to_string()));
        }

        // Step 1: Generate random per-place key (32 bytes). Born inside Zeroizing so
        // it wipes on EVERY return path — including the `?` early-returns below.
        let place_key_zeroizing: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());

        // Step 2: Encrypt data ONCE with the per-place key. Bind the payload to
        // the place-envelope domain when writing v2 (gated on AAD_V2_WRITE_ENABLED
        // so readers that only know v1 still work); empty AAD keeps v1
        // byte-identical. Mirrors envelope_encrypt_location_v2 — hex
        // EncryptedData{nonce,ciphertext}.
        let payload_v2 = place_aad_v2();
        let payload_aad: &[u8] = if AAD_V2_WRITE_ENABLED { &payload_v2 } else { b"" };
        let enc = encrypt_with_raw_key_aad(&*place_key_zeroizing, plaintext.as_bytes(), payload_aad)?;

        // Step 3: Wrap the per-place key for each target, binding each wrap to its
        // target when writing v2 (reusing the location envelope's wrap helper so
        // places get the same target-bound wraps).
        let mut key_wraps = Vec::with_capacity(target_ids.len());
        for target_id in &target_ids {
            let wrap_v2 = msg_key_wrap_aad_v2(target_id);
            let wrap_aad: &[u8] = if AAD_V2_WRITE_ENABLED { &wrap_v2 } else { b"" };
            let wrapped = self.wrap_msg_key_aad(target_id.clone(), &*place_key_zeroizing, wrap_aad)?;
            key_wraps.push(wrapped);
        }

        // place_key_zeroizing wipes on drop here (and on every `?` above).
        Ok(EnvelopeEncryptedLocation {
            ciphertext: enc.ciphertext,
            ciphertext_nonce: enc.nonce,
            timestamp: 0, // Not used for places, but required by the struct
            key_wraps,
        })
    }

    /// Unwrap a per-place key and decrypt place data from envelope encryption.
    ///
    /// 1. Unwrap the per-place key using the circle/self key
    /// 2. Decrypt the ciphertext using the unwrapped per-place key
    ///
    /// AAD v2 (mirrors `unwrap_and_decrypt_location_v2`): tries the v2 AADs first
    /// (`msg_key_wrap_aad_v2(target)` for the wrap, `place_aad_v2()` for the
    /// payload), then falls back to the v1 empty AAD so places written with v1
    /// still decrypt. A total failure propagates (never plaintext).
    ///
    /// `target_id` names the circle/self key that unwraps the per-place key; the
    /// wrapped key, both nonces and the ciphertext are hex-encoded.
    pub fn unwrap_and_decrypt_place(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
    ) -> Result<String, MobileError> {
        self.unwrap_and_decrypt_place_opened_inner(&target_id, &wrapped_key, &wrapped_key_nonce, ciphertext, ciphertext_nonce)
            .map(|(_version, plaintext)| plaintext)
    }

    /// `unwrap_and_decrypt_place`, with the circle-key version that unwrapped
    /// the place key. A place is durable config, never re-wrapped at a
    /// rotation, so it keeps its own app policy.
    pub fn unwrap_and_decrypt_place_opened(
        &self,
        target_id: String,
        wrapped_key: String,
        wrapped_key_nonce: String,
        ciphertext: String,
        ciphertext_nonce: String,
    ) -> Result<OpenedText, MobileError> {
        let (key_version, text) =
            self.unwrap_and_decrypt_place_opened_inner(&target_id, &wrapped_key, &wrapped_key_nonce, ciphertext, ciphertext_nonce)?;
        Ok(OpenedText { text, key_version })
    }

    /// Clear all keys (logout)
    ///
    /// Clears all in-memory keys and deletes persisted keys from secure storage.
    pub fn clear_all_keys(&self) {
        *self.private_key.write().unwrap_or_else(|e| e.into_inner()) = None;
        // Recovered pre-reset keys go with everything else: they are account key
        // material, and leaving them behind would let the next user of this
        // device decrypt the previous one's older data.
        self.previous_private_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.previous_signing_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        *self.public_key.write().unwrap_or_else(|e| e.into_inner()) = None;
        self.circle_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.unreadable_circle_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.active_key_version.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.peer_session_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        // Drop the cached Argon2-derived password key (Zeroizing wipes the bytes).
        *self.password_key_cache.write().unwrap_or_else(|e| e.into_inner()) = None;
        // Drop the Ed25519 signing keypair and the TOFU pin set on logout
        // (an app that keeps pins across a same-account sign-out exports them
        // with `export_member_pins` first).
        *self.signing_keypair.write().unwrap_or_else(|e| e.into_inner()) = None;
        *self.unreadable_signing_seed.write().unwrap_or_else(|e| e.into_inner()) = None;
        self.pinned_keys.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.identity_pins.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner()).clear();
        *self.personal_provenance.write().unwrap_or_else(|e| e.into_inner()) = PersonalKeyProvenance::default();
        *self.circle_provenance.write().unwrap_or_else(|e| e.into_inner()) = CircleKeyProvenance::default();
        // Refresh-record state, the circles' secrets with it (zeroized on drop).
        self.refresh.write().unwrap_or_else(|e| e.into_inner()).clear();
        // The store is deleted below: its contents are known (none), so the next
        // sign-in writes without re-reading, and a failed earlier load no longer
        // blocks writes.
        self.load_state.store(LOAD_KNOWN, Ordering::Release);

        // Delete persisted keys from secure storage
        let storage = self.secure_storage.read().unwrap_or_else(|e| e.into_inner());
        if let Some(storage) = storage.as_ref() {
            if let Err(e) = storage.delete_keys() {
                // The store may still hold what was just cleared: nothing is
                // written or loaded until a clear succeeds.
                self.load_state.store(LOAD_DELETE_FAILED, Ordering::Release);
                tracing::warn!("Failed to delete persisted keys from secure storage: {}", e);
            } else {
                tracing::info!("Deleted persisted keys from secure storage");
            }
        }
    }

    /// Clear only the cached Argon2-derived password key.
    ///
    /// Use this when the user logs out a single secret context but keeps the
    /// rest of the manager state (rare). For full logout, prefer clear_all_keys().
    pub fn clear_password_key_cache(&self) {
        *self.password_key_cache.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Whether this device holds ANY key for `circle_id`, a RETIRED personal key
    /// included: the gate for READING, since whatever was sealed under a held
    /// key can still be opened. Gates that SEAL, WRAP, MINT or PUBLISH ask
    /// `has_circle_key_in_use` instead: after an email reset and a restore, a
    /// personal slot can hold only retired keys, and then has none in use.
    pub fn has_circle_key(&self, circle_id: String) -> bool {
        self.circle_keys.read().unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .map_or(false, |v| !v.is_empty())
    }

    /// Whether this device holds a key IN USE for `circle_id`: the one
    /// `get_active_version` names, which is what sealing uses. The gate for
    /// SEALING, WRAPPING, MINTING and PUBLISHING. It is false where every key
    /// held is for reading only, like a personal slot that holds only RETIRED
    /// keys after an email reset and a restore, where `has_circle_key` is true.
    pub fn has_circle_key_in_use(&self, circle_id: String) -> bool {
        self.get_active_circle_key_with_version(&circle_id).is_ok()
    }

    /// Get the active (highest) key version for a circle
    pub fn get_active_version(&self, circle_id: String) -> Result<i32, MobileError> {
        // The version this device SEALS under: on a circle with refresh
        // records, the highest one whose record it accepted (or its own
        // unconfirmed rotation); on any other circle, the highest held.
        self.sealing_version(&circle_id)
            .ok_or_else(|| MobileError::KeyNotFound(format!("No key version for circle: {}", circle_id)))
    }

    // ========================================================================
    // Session Key Methods
    // ========================================================================

    /// Create a new session key for a circle and return data to publish to server.
    ///
    /// The session key is encrypted with the circle's active key and stored locally.
    /// The returned PublishSessionKeyData should be POSTed to the server.
    pub fn create_session_key(
        &self,
        circle_id: String,
        session_duration_secs: i64,
    ) -> Result<PublishSessionKeyData, MobileError> {
        // Validate session duration (5 minutes to 24 hours)
        if session_duration_secs < 300 || session_duration_secs > 86400 {
            return Err(MobileError::InvalidInput(
                "Session duration must be between 300 and 86400 seconds (5 min to 24 hours)".to_string()
            ));
        }

        let active_version = self
            .sealing_version(&circle_id)
            .ok_or_else(|| MobileError::KeyNotFound(format!("No circle key for: {}", circle_id)))?;

        let circle_key = self.get_circle_key_version(&circle_id, active_version)?;

        // Generate random 32-byte session key. Born inside Zeroizing so it wipes on
        // EVERY return path — including the `?` early-return on encrypt below.
        let session_key: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());
        let session_key_id = uuid::Uuid::new_v4().to_string();

        // Encrypt session key with circle key
        let encrypted = encrypt_raw_bytes(&circle_key, session_key.as_slice())?;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expires_at = now_secs + session_duration_secs;

        // Store locally as our sender session key
        {
            let mut sender_keys = self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner());
            sender_keys.insert(CircleKey::of(&circle_id), SenderSessionState {
                session_key_id: session_key_id.clone(),
                key: Zeroizing::new(session_key.to_vec()),
                key_version: active_version,
                expires_at,
            });
        }

        // Also store in peer cache so we can decrypt our own locations
        {
            let mut peer_keys = self.peer_session_keys.write().unwrap_or_else(|e| e.into_inner());
            Self::evict_expired_peer_keys(&mut peer_keys);
            Self::enforce_peer_cache_bound(&mut peer_keys);
            // Under this circle and its id.
            peer_keys.insert(session_cache_key(&circle_id, &session_key_id), CachedPeerSessionKey {
                key: Zeroizing::new(session_key.to_vec()),
                expires_at,
                last_used_at: AtomicI64::new(current_unix_secs()),
                key_version: active_version,
            });
        }

        // Both retained copies are Zeroizing<Vec<u8>>; the staging session_key is
        // itself Zeroizing and wipes on drop here (and on every `?` above).
        tracing::info!("Created session key {} for circle {}", session_key_id, circle_id);

        Ok(PublishSessionKeyData {
            session_key_id,
            encrypted_session_key: encrypted.ciphertext,
            key_nonce: encrypted.nonce,
            key_version: active_version,
            expires_at,
        })
    }

    /// Import a peer's session key from the server (decrypt with circle key, cache locally)
    ///
    /// expires_at_secs is the Unix timestamp (seconds) when this session key expires.
    pub fn import_peer_session_key(
        &self,
        circle_id: String,
        session_key_id: String,
        encrypted_session_key: String,
        key_nonce: String,
        key_version: i32,
        expires_at_secs: i64,
    ) -> Result<(), MobileError> {
        // Reject already-expired session keys
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if expires_at_secs <= now {
            tracing::debug!("Skipping import of expired session key {}", session_key_id);
            return Ok(()); // Not an error — just stale data from server
        }

        let circle_key = self.get_circle_key_version(&circle_id, key_version)?;

        let encrypted = EncryptedData {
            nonce: key_nonce,
            ciphertext: encrypted_session_key,
        };
        let decrypted_bytes = Zeroizing::new(decrypt_raw_bytes(&circle_key, &encrypted)?);

        if decrypted_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Session key must be 32 bytes".to_string()));
        }

        // Kept under the circle whose key opened it, at that version. An id
        // names one key in its circle: the same key again changes nothing, and
        // another takes its place only if it was opened under a HIGHER
        // circle-key version: a key squatted under an old version, which a
        // removed member holds, never keeps the current one out. Same or
        // lower: refused.
        let cache_key = session_cache_key(&circle_id, &session_key_id);
        let mut peer_keys = self.peer_session_keys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(held) = peer_keys.get(&cache_key) {
            if ct_eq(&held.key, &decrypted_bytes) {
                return Ok(());
            }
            if key_version <= held.key_version {
                tracing::warn!("Refusing another session key under an id this circle holds at the same or a newer version: {}", session_key_id);
                return Err(MobileError::InvalidInput(
                    "this circle holds another session key under that id, at the same or a newer version".to_string(),
                ));
            }
            peer_keys.remove(&cache_key);
        }
        // Evict expired keys and enforce cache bound
        Self::evict_expired_peer_keys(&mut peer_keys);
        Self::enforce_peer_cache_bound(&mut peer_keys);
        peer_keys.insert(cache_key, CachedPeerSessionKey {
            key: decrypted_bytes,
            expires_at: expires_at_secs,
            last_used_at: AtomicI64::new(current_unix_secs()),
            key_version,
        });

        tracing::debug!("Imported peer session key {}", session_key_id);
        Ok(())
    }

    /// Check if this device has an active (non-expired) session key for a circle
    pub fn has_active_session_key(&self, circle_id: String) -> bool {
        // "Active" includes "published under the circle's CURRENT key version":
        // one minted before a rotation is no longer used for sending (see
        // `encrypt_with_session_or_circle_key_aad`), so the app should mint anew.
        let active_version = self.sealing_version(&circle_id);
        let sender_keys = self.sender_session_keys.read().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = sender_keys.get(&CircleKey::of(&circle_id)) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            state.expires_at > now && Some(state.key_version) == active_version
        } else {
            false
        }
    }

    /// Get the current session key ID for a circle (if active)
    pub fn get_sender_session_key_id(&self, circle_id: String) -> Result<String, MobileError> {
        let sender_keys = self.sender_session_keys.read().unwrap_or_else(|e| e.into_inner());
        sender_keys.get(&CircleKey::of(&circle_id))
            .map(|s| s.session_key_id.clone())
            .ok_or_else(|| MobileError::SessionKeyNotFound(format!("No session key for circle: {}", circle_id)))
    }

    /// Check if a peer session key is cached locally and not expired
    // NOTE: the doc comment above is deliberately kept short. A `///` on a
    // method in this `#[uniffi::export]` block feeds the UniFFI method
    // CHECKSUM: changing it moves
    // `checksum_method_cryptomanager_has_peer_session_key`, and a moved
    // checksum invalidates every committed Kotlin/Swift binding — an
    // incremental iOS build against the old xcframework then dies with
    // `apiChecksumMismatch` at launch. The body is invisible to the checksum,
    // so the explanation lives down here.
    //
    // Accepts EITHER id form: a row's routing `key_id` ("s:{uuid}") or the
    // server's bare uuid. `with_peer_session_key` — the one reader of the
    // cache, shared with `resolve_decryption_key` — normalises the prefix, so
    // this pre-check and the decrypt that follows it can never disagree about
    // the format. track-ios GATES the decrypt on this, so a disagreement would
    // drop every session-key row as "key missing".
    pub fn has_peer_session_key(&self, session_key_id: String) -> bool {
        // Session keys are held per circle, and this call names none, so it
        // answers for ANY circle; a row opens only with its own circle's key
        // (`has_peer_session_key_for`, which apps gate on).
        let bare = session_key_id.strip_prefix("s:").unwrap_or(&session_key_id);
        let now = current_unix_secs();
        self.peer_session_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            // Allow grace period after expiry for in-flight decryptions
            .any(|((_, id), cached)| id == bare && cached.expires_at + PEER_KEY_EXPIRY_GRACE_SECS > now)
    }

    /// Whether this device holds a live session key for `circle_id` under
    /// `session_key_id` (a row's "s:{id}" or the bare id): the one key a row of
    /// that circle naming it opens with. A key held for another circle under
    /// the same id does not count. Expired keys count for an hour.
    pub fn has_peer_session_key_for(&self, circle_id: String, session_key_id: String) -> bool {
        self.with_peer_session_key(&circle_id, &session_key_id, |cached| {
            // Allow grace period after expiry for in-flight decryptions
            cached.expires_at + PEER_KEY_EXPIRY_GRACE_SECS > current_unix_secs()
        })
        .unwrap_or(false)
    }

    /// Whether `key_version` is the one this device seals `circle_id` under, the
    /// version `get_active_version` names: the one test of CURRENT for LIVE data
    /// (positions, the live timestamp, SOS and check-in positions). A version
    /// below it is retired, and one above it is held while its record waits or
    /// was refused: both are history, never live, never a "last seen", never
    /// place-alert input. Durable config (place keys, alert rules, inactivity
    /// alerts, names) is not re-sealed at a rotation: it keeps its own app policy.
    pub fn is_current_key_version(&self, circle_id: String, key_version: i32) -> bool {
        self.sealing_version(&circle_id) == Some(key_version)
    }

    /// Encrypt location with session key (falls back to circle key if no session key)
    ///
    /// Returns SessionEncryptedData with key_id:
    /// - "s:{session_key_id}" if session key used
    /// - "c:{version}" if circle key fallback
    pub fn encrypt_location_with_session_key(
        &self,
        circle_id: String,
        location: Location,
    ) -> Result<SessionEncryptedData, MobileError> {
        let plaintext = location_plaintext(&location)?;
        self.encrypt_with_session_or_circle_key(&circle_id, &plaintext)
    }

    /// Session-key variant of `encrypt_location_bound`. Encrypts with the
    /// active session key (or circle-key fallback, exactly like
    /// `encrypt_location_with_session_key`) but seals under
    /// `location_aad_v3(sender_pseudonym)`. The returned `key_id`
    /// ("s:{uuid}" or "c:{version}") routes decryption; `key_id` is unchanged
    /// from the unbound method — only the AAD differs. `sender_pseudonym` is the
    /// sender's own `derive_user_pseudonym(circle_id, user_id)`.
    pub fn encrypt_location_with_session_key_bound(
        &self,
        circle_id: String,
        location: Location,
        sender_pseudonym: String,
    ) -> Result<SessionEncryptedData, MobileError> {
        let plaintext = location_plaintext(&location)?;
        self.encrypt_with_session_or_circle_key_aad(
            &circle_id,
            &plaintext,
            &location_aad_v3(&sender_pseudonym),
        )
    }

    /// Session-key variant of `decrypt_location_bound`. Resolves the key by
    /// `key_id` ("s:{uuid}" session key or "c:{version}" circle-key fallback),
    /// tries the v3 sender-bound AAD with `claimed_pseudonym`
    /// (`sender_verified = true` on a tag match), then falls back to the legacy
    /// empty-AAD (v1) decrypt under the SAME resolved key — matching how
    /// `decrypt_data_by_key_id` reads session-encrypted rows
    /// (`sender_verified = false`). NEVER surfaces plaintext on total failure —
    /// the error propagates. `claimed_pseudonym` is the reader's
    /// `derive_user_pseudonym(circle_id, user_id)` for the attributed user.
    #[deprecated(
        note = "use the *_for_user variant; the active-only pseudonym silently drops post-rotation v3 rows"
    )]
    pub fn decrypt_location_with_session_key_bound(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
        key_id: String,
        claimed_pseudonym: String,
    ) -> Result<BoundLocation, MobileError> {
        // With the version it came under: a session key's, or "c:N".
        let (key_version, key) = self.resolve_decryption_key_opened(&circle_id, &key_id)?;

        // v3: sender-bound AAD under the resolved (session or circle) key.
        if let Ok(bytes) = decrypt_raw_bytes_aad(
            &key,
            &encrypted_location,
            &location_aad_v3(&claimed_pseudonym),
        ) {
            let location = decode_location(&bytes)?;
            return Ok(BoundLocation { location, sender_verified: true, key_version });
        }

        // Legacy fallback: empty-AAD (v1) decrypt under the same resolved key.
        let plaintext = decrypt_raw_bytes(&key, &encrypted_location)?;
        let location = decode_location(&plaintext)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    /// Cross-rotation variant of `decrypt_location_with_session_key_bound`.
    /// Resolves the decrypt key ONCE by `key_id` (session "s:{uuid}" or circle
    /// "c:{version}"), then re-derives the claimed pseudonym PER held circle-key
    /// version and tries the v3 payload under the FIXED resolved key. The
    /// pseudonym is always a function of the CIRCLE key (never the session key),
    /// so after a rotation a row bound under a superseded version still verifies
    /// here even though its data is sealed under the resolved session/circle key.
    /// A tag match ⇒ `sender_verified = true`. Falls back to the legacy empty-AAD
    /// (v1) decrypt under the same resolved key with `sender_verified = false`;
    /// total failure propagates (never surfaces plaintext).
    ///
    /// `user_id` is the user this row is attributed to — the id the sender's
    /// `derive_user_pseudonym` bound at encrypt time.
    pub fn decrypt_location_with_session_key_bound_for_user(
        &self,
        circle_id: String,
        encrypted_location: EncryptedData,
        key_id: String,
        user_id: String,
    ) -> Result<BoundLocation, MobileError> {
        // Resolve the decrypt key BEFORE taking the circle-keys read lock —
        // resolve_decryption_key re-locks peer_session_keys / circle_keys.
        // With the version it came under: a session key's, or "c:N".
        let (key_version, key) = self.resolve_decryption_key_opened(&circle_id, &key_id)?;

        // v3 sender-bound: FIXED decrypt key, pseudonym re-derived per circle-key
        // version (newest first). Scope the read guard to this loop.
        {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            if let Some(versions) = keys.get(&CircleKey::of(&circle_id)) {
                let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
                sorted.sort_by(|a, b| b.0.cmp(a.0));
                for (_version, ck) in sorted {
                    if let Some(res) =
                        try_v3_location_payload(&key, &encrypted_location, ck, &user_id)
                    {
                        return res.map(|location| BoundLocation { location, sender_verified: true, key_version });
                    }
                }
            }
        }

        // Legacy fallback: empty-AAD (v1) decrypt under the same resolved key.
        let plaintext = decrypt_raw_bytes(&key, &encrypted_location)?;
        let location = decode_location(&plaintext)?;
        Ok(BoundLocation { location, sender_verified: false, key_version })
    }

    /// Encrypt timestamp with session key (falls back to circle key)
    pub fn encrypt_timestamp_with_session_key(
        &self,
        circle_id: String,
        timestamp_ms: i64,
    ) -> Result<SessionEncryptedData, MobileError> {
        let plaintext = timestamp_ms.to_string();
        self.encrypt_with_session_or_circle_key(&circle_id, plaintext.as_bytes())
    }

    /// Create a key chain link: encrypt the OLD circle key with the NEW circle key.
    /// Called during key rotation BEFORE the old key is replaced.
    /// Returns (encrypted_key_hex, nonce_hex, from_version, to_version).
    pub fn create_key_chain_link(
        &self,
        circle_id: String,
    ) -> Result<KeyChainLinkData, MobileError> {
        // A personal key slot is no circle: no link seals one personal key
        // under another for anyone.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput(
                "a personal key slot is no circle: no key chain link is made for it".to_string(),
            ));
        }
        // A circle with refresh records gets its link from the record
        // builder, down to the version its record names.
        if self.latched_until_the_store_reads(&circle_id) {
            return Err(MobileError::StorageError("the key store can't be read: this circle waits".to_string()));
        }
        if self.circle_is_recorded_here(&circle_id) {
            return Err(MobileError::InvalidInput(
                "this circle has refresh records: its link comes with prepare_recorded_rotation".to_string(),
            ));
        }
        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        let version_map = keys.get(&CircleKey::of(&circle_id))
            .ok_or_else(|| MobileError::KeyNotFound(format!("No keys for circle: {}", circle_id)))?;

        let active = self.active_key_version.read().unwrap_or_else(|e| e.into_inner());
        let current_version = active.get(&CircleKey::of(&circle_id)).copied().unwrap_or(1);
        let previous_version = current_version - 1;

        if previous_version < 1 {
            return Err(MobileError::InvalidInput("No previous key version to chain".to_string()));
        }

        let new_key = version_map.get(&current_version)
            .ok_or_else(|| MobileError::KeyNotFound(format!("Key v{} not found", current_version)))?;
        let old_key = version_map.get(&previous_version)
            .ok_or_else(|| MobileError::KeyNotFound(format!("Key v{} not found", previous_version)))?;

        // SECURITY: defence in depth against a wrong-length key. store_circle_key
        // rejects one at ingest, but guard here too: copy_from_slice into a
        // [0u8; 32] PANICS on a length mismatch, and a panic crossing the UniFFI
        // boundary is a hard app crash rather than a catchable error. Checking
        // old_key as well means we never mint a chain link carrying a corrupt key.
        if new_key.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid key length for v{}: {}", current_version, new_key.len()
            )));
        }
        if old_key.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid key length for v{}: {}", previous_version, old_key.len()
            )));
        }

        // Encrypt old key with new key
        let nonce: [u8; 24] = generate_secure_nonce();
        let mut new_key_arr = [0u8; 32];
        new_key_arr.copy_from_slice(new_key.as_ref());
        let cipher = XChaCha20Poly1305::new_from_slice(new_key_arr.as_slice()).expect("32-byte key");
        new_key_arr.zeroize();
        let encrypted = cipher.encrypt(&XNonce::from(nonce), old_key.as_ref())
            .map_err(|_| MobileError::EncryptionFailed)?;

        Ok(KeyChainLinkData {
            from_version: current_version,
            to_version: previous_version,
            encrypted_key: hex::encode(&encrypted),
            nonce: hex::encode(&nonce),
        })
    }

    /// Import a key chain link: decrypt a previous key using the current key.
    /// This allows the client to derive older key versions for historical data.
    pub fn import_key_chain_link(
        &self,
        circle_id: String,
        from_version: i32,
        to_version: i32,
        encrypted_key_hex: String,
        nonce_hex: String,
    ) -> Result<(), MobileError> {
        // A personal key slot is no circle: no link files a key there.
        // The server serves none for it.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it takes no key chain link".to_string()));
        }
        // On a circle with refresh records, a link into a version that has a
        // record may step further down only where the record it comes from
        // names that step (`link_to`), and the key it yields is stored only if
        // it verifies that version's record tag. Links into versions from
        // before the first record keep the rule below.
        let expected_tag = match self.chain_link_rule(&circle_id, from_version, to_version) {
            crate::refresh::LinkRule::Legacy => None,
            crate::refresh::LinkRule::Refuse(why) => {
                tracing::warn!(
                    "import_key_chain_link: REFUSING link v{}->v{} for circle {}: {}",
                    from_version, to_version, circle_id, why
                );
                return Err(MobileError::InvalidInput(format!(
                    "key chain link v{} -> v{}: {}",
                    from_version, to_version, why
                )));
            }
            crate::refresh::LinkRule::Checked(check) => Some(check),
        };
        // Both version labels are the server's, and nothing inside the link binds
        // them (the AEAD has no AAD). A link is only ever minted for the step
        // from the active version to the one below it (`create_key_chain_link`),
        // so anything else is a relabelled link: the genuine v2->v1 link replayed
        // as 2->2 would overwrite the ACTIVE key with the revoked v1 key.
        if expected_tag.is_none() && (to_version < 1 || from_version.checked_sub(1) != Some(to_version)) {
            tracing::warn!(
                "import_key_chain_link: REFUSING link v{}->v{} for circle {} (a link steps exactly one version down)",
                from_version, to_version, circle_id
            );
            return Err(MobileError::InvalidInput(format!(
                "key chain link must step one version down (got v{} -> v{})",
                from_version, to_version
            )));
        }

        // Get the "from" key (must already be stored)
        let from_key = {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            keys.get(&CircleKey::of(&circle_id))
                .and_then(|vm| vm.get(&from_version))
                .cloned()
                .ok_or_else(|| MobileError::KeyNotFound(format!("Key v{} not found for chain import", from_version)))?
        };

        let nonce_bytes = hex::decode(&nonce_hex)
            .map_err(|e| MobileError::CryptoError(format!("Invalid nonce hex: {}", e)))?;
        let encrypted_bytes = hex::decode(&encrypted_key_hex)
            .map_err(|e| MobileError::CryptoError(format!("Invalid key hex: {}", e)))?;

        if nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid nonce length".to_string()));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        // SECURITY: same guard as create_key_chain_link — copy_from_slice into a
        // [0u8; 32] PANICS on a length mismatch (hard app crash across UniFFI).
        // This checks the INPUT key; the decrypted OUTPUT is checked below.
        if from_key.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid key length for v{}: {}", from_version, from_key.len()
            )));
        }

        let mut from_key_arr = [0u8; 32];
        from_key_arr.copy_from_slice(from_key.as_ref());
        let cipher = XChaCha20Poly1305::new_from_slice(from_key_arr.as_slice()).expect("32-byte key");
        from_key_arr.zeroize();
        let decrypted = Zeroizing::new(cipher.decrypt(&XNonce::from(nonce), encrypted_bytes.as_ref())
            .map_err(|_| MobileError::DecryptionFailed)?);

        if decrypted.len() != 32 {
            return Err(MobileError::CryptoError(format!("Invalid key length: {}", decrypted.len())));
        }
        if let Some(check) = &expected_tag {
            if !check.verifies(&decrypted) {
                tracing::warn!(
                    "import_key_chain_link: REFUSING link v{}->v{} for circle {}: its key does not verify v{}'s record",
                    from_version, to_version, circle_id, to_version
                );
                return Err(MobileError::InvalidInput(format!(
                    "key chain link v{} -> v{} carries a key that does not verify v{}'s record",
                    from_version, to_version, to_version
                )));
            }
        }

        // Store the derived key — only into a version we do not hold yet. A
        // re-walk of the same chain yields the same bytes (a no-op); different
        // bytes for a held version are refused, except over our own UNCONFIRMED
        // rotation: the server's chain then carries the key that won the race.
        // `to_version` is below `from_version`, which is held, so a link can
        // never touch the active (highest) version. Lock order: circle_keys,
        // then unconfirmed_rotations.
        {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut unconfirmed = self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner());
            let version_map = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
            match version_map.get(&to_version) {
                Some(held) if ct_eq(held, &decrypted) => {
                    if unconfirmed.get(&CircleKey::of(&circle_id)) == Some(&to_version) {
                        unconfirmed.remove(&CircleKey::of(&circle_id));
                    }
                    return Ok(());
                }
                Some(_) if unconfirmed.get(&CircleKey::of(&circle_id)) == Some(&to_version) => {
                    tracing::warn!(
                        "import_key_chain_link: replacing our unconfirmed rotation of circle {} v{} with the chain's key",
                        circle_id, to_version
                    );
                    unconfirmed.remove(&CircleKey::of(&circle_id));
                }
                Some(_) => {
                    tracing::warn!(
                        "import_key_chain_link: REFUSING link v{}->v{} for circle {}: it carries a different key than the one held for v{}",
                        from_version, to_version, circle_id, to_version
                    );
                    return Err(MobileError::InvalidInput(format!(
                        "key chain link v{} -> v{} conflicts with the key held for v{}",
                        from_version, to_version, to_version
                    )));
                }
                None => {}
            }
            insert_capped_circle_version(version_map, to_version, decrypted);
        }

        // Persist the derived version explicitly: the `store_circle_key` before
        // it writes nothing for a byte-identical re-import, so it cannot be
        // relied on to persist this. Inside a bulk import window this is
        // deferred to the single flush at its end.
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after importing a key chain link: {}", e);
        }

        tracing::debug!("Imported key chain link for circle {}: v{} → v{}", circle_id, from_version, to_version);
        Ok(())
    }

    /// Forget this device's sender session key for a circle.
    pub fn invalidate_session_keys_for_circle(&self, circle_id: String) {
        // Remove our sender session key
        self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner())
            .remove(&CircleKey::of(&circle_id));

        // Note: peer_session_keys are keyed by session_key_id, not circle_id.
        // They'll naturally expire or be replaced when new session keys arrive.
        // We don't need to purge them — they just won't match new key_ids.

        tracing::info!("Invalidated session keys for circle {}", circle_id);
    }

    // ========================================================================
    // Auto Key Rotation Methods
    // ========================================================================

    /// Prepare a key rotation: generate new circle key and wrap for all members.
    ///
    /// Returns the new key version and wrapped keys for each member.
    /// The caller should POST this to /circles/:id/rotate-keys.
    ///
    /// Each per-member wrap is signed with our Ed25519 signing key under DOMAIN
    /// `pingolin.sig.v1.rotation_member_wrap`. Signatures are emitted as the
    /// empty string when no signing key is loaded (legacy install grace period).
    ///
    /// `member_signing_pubkeys_hex` is parallel to `member_user_ids` /
    /// `member_public_keys_hex`. It's reserved for caller-side TOFU pinning and
    /// is NOT bound into the signature input (the signed context is locked).
    pub fn prepare_key_rotation(
        &self,
        circle_id: String,
        sender_user_id: String,
        member_user_ids: Vec<String>,
        member_public_keys_hex: Vec<String>,
        member_signing_pubkeys_hex: Vec<String>,
        current_circle_name_plaintext: String,
    ) -> Result<KeyRotationBundle, MobileError> {
        // A personal key slot is no circle: rotated as one, its members would
        // get the new key, the link down to the old personal key, and every
        // personal row after it. Nothing is changed first.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it is never rotated as one".to_string()));
        }
        // A circle with refresh records is rotated only with its record
        // (`prepare_recorded_rotation`), whose version is the chain head's + 1.
        // The server refuses a record-less change there anyway.
        if self.latched_until_the_store_reads(&circle_id) {
            return Err(MobileError::StorageError("the key store can't be read: this circle waits".to_string()));
        }
        if self.circle_is_recorded_here(&circle_id) {
            return Err(MobileError::InvalidInput(
                "this circle has refresh records: rotate it with prepare_recorded_rotation".to_string(),
            ));
        }
        if member_user_ids.len() != member_public_keys_hex.len() {
            return Err(MobileError::InvalidInput("member_user_ids and member_public_keys_hex must have same length".to_string()));
        }
        if member_user_ids.len() != member_signing_pubkeys_hex.len() {
            return Err(MobileError::InvalidInput("member_user_ids and member_signing_pubkeys_hex must have same length".to_string()));
        }
        // `member_signing_pubkeys_hex` is reserved for caller-side TOFU pinning;
        // not bound into sig_input (wire format locked).
        let _ = &member_signing_pubkeys_hex;
        let member_public_keys: Vec<(String, String)> = member_user_ids.into_iter()
            .zip(member_public_keys_hex.into_iter()).collect();
        // Generate new circle key. Born inside Zeroizing so it wipes on EVERY return
        // path — including the many `?` early-returns below (version overflow, name
        // encrypt, and the per-member wrap loop).
        let new_key: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());
        let new_key_zeroizing = Zeroizing::new(new_key.to_vec());

        // Get current version and compute new version: above a version whose
        // stored copy didn't read here, too.
        let unreadable_above = self.newest_unreadable_copy(&circle_id).unwrap_or(0);
        let current_version = self.active_key_version.read().unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id)).copied().unwrap_or(1)
            .max(unreadable_above);
        // Never wrap i32 on +1 (store_circle_key bounds ingested versions, but keep
        // rotation self-contained and fail-safe).
        let new_version = current_version.checked_add(1).ok_or_else(|| {
            MobileError::InvalidInput("circle key version overflow".to_string())
        })?;

        // Encrypt circle name with new key
        let encrypted_name = encrypt_with_raw_key(&new_key_zeroizing, current_circle_name_plaintext.as_bytes())?;

        // Wrap new key for each member.
        //
        // SECURITY (rotation ordering): build the FULL member bundle set FIRST and
        // only mutate local key state (insert the new version + bump
        // active_key_version, below) AFTER this whole loop succeeds. A
        // server-supplied small-order / malformed member key errors mid-loop;
        // mutating key state up front would leave an orphaned new key version and a
        // bumped active_key_version behind on that error. `new_key` /
        // `new_key_zeroizing` are generated above (not read back from the map), so
        // the loop does not depend on the deferred insert.
        let mut member_bundles = Vec::with_capacity(member_public_keys.len());
        for (user_id, public_key_hex) in member_public_keys {
            member_bundles.push(self.wrap_rotation_key(
                &circle_id,
                &sender_user_id,
                new_version,
                &new_key,
                user_id,
                &public_key_hex,
            )?);
        }

        // All member wraps succeeded — NOW commit the new key locally. Cap retained
        // versions per circle. Deferred to here (after the fallible loop) so a bad
        // server-supplied member key can't leave an orphaned key version / bumped
        // active_key_version behind.
        {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let version_map = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
            insert_capped_circle_version(version_map, new_version, Zeroizing::new(new_key.to_vec()));
        }
        // new_key (Zeroizing) wipes on drop at end of scope, on every path.
        {
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            active.insert(CircleKey::of(&circle_id), new_version);
        }
        // Ours until the server serves it back (store_circle_key confirms it), an
        // authenticated wrap for the same version replaces it (we lost the race),
        // or the app reports the rotation failed (discard_unconfirmed_rotation).
        // NOT "failed" meanwhile: a successful rotation stays unconfirmed until
        // the next key import, so nothing here may assume the server lacks it.
        self.unconfirmed_rotations
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(CircleKey::of(&circle_id), new_version);

        // Seal the OUTGOING key under the new one, so a member holding only the
        // latest key can still walk back and read everything written under the
        // older versions. Reuses create_key_chain_link rather than re-deriving
        // the format here: two implementations of one wire format drift, and a
        // link readers cannot parse is worse than none.
        //
        // Safe AFTER the commit above: the cap evicts the OLDEST version
        // (`keys().min()`, never the new one) and retains 5, so the
        // immediately-previous key is still present. Called outside the lock
        // scopes above — it takes its own read locks.
        let key_chain_link = match self.create_key_chain_link(circle_id.clone()) {
            Ok(link) => Some(link),
            Err(e) => {
                // A rotation from v1 has no previous key; anything else here
                // means we could not build the link and must say so rather than
                // emit a broken one.
                tracing::warn!("no key chain link for rotation of {}: {}", circle_id, e);
                None
            }
        };

        // Invalidate session keys since they were encrypted with the old circle key
        self.invalidate_session_keys_for_circle(circle_id.clone());

        // Auto-persist
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after rotation: {}", e);
        }

        Ok(KeyRotationBundle {
            new_key_version: new_version,
            encrypted_name,
            member_keys: member_bundles,
            key_chain_link,
        })
    }

    /// Prepare circle creation by generating a circle key and encrypting it for the creator
    ///
    /// Returns the encrypted circle key and ephemeral public key for the server.
    /// The circle key is stored locally for immediate use (to encrypt the circle name).
    ///
    /// Returns: (encrypted_circle_key, ephemeral_public_key, temp_circle_id)
    /// - encrypted_circle_key: hex-encoded (nonce || ciphertext)
    /// - ephemeral_public_key: hex-encoded 32-byte X25519 public key
    /// - temp_circle_id: temporary ID to reference the stored key until server returns real ID
    pub fn prepare_circle_creation(&self) -> Result<CircleCreationData, MobileError> {
        let our_public_key = self
            .public_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MobileError::KeyNotFound("No public key available".to_string()))?;

        // Generate random circle key (32 bytes for XChaCha20-Poly1305)
        // SECURITY: Uses thread-safe key generation. Born inside Zeroizing so it
        // wipes on EVERY return path — including the `?` early-return on encrypt below.
        let circle_key: Zeroizing<[u8; 32]> = Zeroizing::new(generate_secure_nonce());

        // Generate ephemeral keypair for ECDH
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let shared_secret = ephemeral_secret.diffie_hellman(&our_public_key);
        drop(ephemeral_secret); // Explicit drop triggers Zeroize

        let mut wrapping_key = blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes());

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        // SECURITY: Zeroize wrapping key after cipher construction consumes it
        wrapping_key.zeroize();
        // SECURITY: Uses thread-safe nonce generation
        let nonce: [u8; 24] = generate_secure_nonce();

        let encrypted = cipher
            .encrypt(&XNonce::from(nonce), circle_key.as_slice())
            .map_err(|_| MobileError::EncryptionFailed)?;

        // Generate temporary circle ID for local storage
        let temp_circle_id = format!("temp_{}", hex::encode(&nonce[..8]));

        // Store the circle key locally for immediate use (version 1, wrapped in Zeroizing for security)
        {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut version_map = HashMap::new();
            version_map.insert(1i32, Zeroizing::new(circle_key.to_vec()));
            keys.insert(CircleKey::of(&temp_circle_id), version_map);
        }
        // circle_key (Zeroizing) wipes on drop at end of scope, on every path.
        self.active_key_version.write().unwrap_or_else(|e| e.into_inner()).insert(CircleKey::of(&temp_circle_id), 1);

        Ok(CircleCreationData {
            encrypted_circle_key: EncryptedData {
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(encrypted),
            },
            ephemeral_public_key: hex::encode(ephemeral_public.as_bytes()),
            temp_circle_id,
        })
    }

    /// Finalize circle creation by remapping the temporary ID to the real circle ID
    pub fn finalize_circle_creation(&self, temp_circle_id: String, real_circle_id: String) -> Result<(), MobileError> {
        // Every spelling of the nil id is the personal slot: a key never goes
        // FROM a slot to a circle, and into one only by the slot's own id, as
        // for a stored key.
        if names_a_personal_slot(&temp_circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is never a new circle's".to_string()));
        }
        if names_a_personal_slot(&real_circle_id) && real_circle_id != PERSONAL_KEY_ID && real_circle_id != ANDROID_PERSONAL_KEY_SLOT {
            return Err(MobileError::InvalidInput("a personal key slot is named by its own id only".to_string()));
        }
        // A circle id this device already knows is never a new circle: nothing
        // is installed over it (its held keys, its records). The personal slot
        // merges below. Lock order: `refresh` alone, first.
        let known = |keys: &HashMap<CircleKey, HashMap<i32, Zeroizing<Vec<u8>>>>| keys.get(&CircleKey::of(&real_circle_id)).map_or(false, |held| !held.is_empty());
        if self.latched_until_the_store_reads(&real_circle_id) {
            return Err(MobileError::StorageError(
                "the key store can't be read: whether this device knows that circle id can't be told".into(),
            ));
        }
        if !is_personal_slot(&real_circle_id) && self.circle_is_recorded_here(&real_circle_id) {
            return Err(MobileError::InvalidInput("this device already knows that circle id".into()));
        }
        {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            if !is_personal_slot(&real_circle_id) && known(&keys) {
                return Err(MobileError::InvalidInput("this device already knows that circle id".into()));
            }

            let version_map = keys
                .remove(&CircleKey::of(&temp_circle_id))
                .ok_or_else(|| MobileError::KeyNotFound(format!("Temp circle key not found: {}", temp_circle_id)))?;

            // A personal key is never dropped: the slot may hold retired keys,
            // or one restored from before a reset, and they are the only keys for
            // the rows sealed under them. A new one joins them; a different key
            // at its version is retired.
            match keys.get_mut(&CircleKey::of(&real_circle_id)) {
                Some(held) if is_personal_slot(&real_circle_id) => {
                    for (version, key) in version_map {
                        if let Some(previous) = held.remove(&version) {
                            if !ct_eq(&previous, &key) {
                                let retired_at = next_retired_version(held);
                                held.insert(retired_at, previous);
                            }
                        }
                        held.insert(version, key);
                    }
                }
                _ => {
                    keys.insert(CircleKey::of(&real_circle_id), version_map);
                }
            }
        }
        {
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            active.remove(&CircleKey::of(&temp_circle_id));
            active.insert(CircleKey::of(&real_circle_id), 1);
        }

        // Auto-persist if secure storage is registered
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after finalizing circle creation: {}", e);
        }

        Ok(())
    }

    /// Wrap a circle key for a specific member's public key.
    ///
    /// Used during key rotation: wraps the circle key for a member using ECDH.
    /// Returns encrypted_circle_key and the ephemeral_public_key needed to decrypt it.
    ///
    /// Also signs the wrap context with our Ed25519 signing key (DOMAIN
    /// `pingolin.sig.v1.circle_member_wrap`). If no signing key is loaded
    /// (legacy install), `wrap_signature` is set to the empty string and a
    /// warning is logged — this is the legacy grace path; recipients fall
    /// back to "unsigned" handling.
    ///
    /// `recipient_signing_pubkey_hex` is accepted as a parameter so callers can
    /// pin the recipient identity at the call site (via `pin_member_keys`); it
    /// is NOT bound into the signature input (the signed context is locked).
    pub fn wrap_circle_key_for_member_full(
        &self,
        circle_id: String,
        member_public_key_hex: String,
        sender_user_id: String,
        recipient_user_id: String,
        recipient_signing_pubkey_hex: String,
    ) -> Result<MemberKeyBundle, MobileError> {
        // `recipient_signing_pubkey_hex` is accepted and ignored: it is not
        // bound into the signature input (the wire format for sig_input is
        // locked). Explicitly underscore-bound to keep the parameter name in
        // the signature.
        let _ = recipient_signing_pubkey_hex;
        // The ids the signature binds, read first: a non-UUID wraps nothing, and
        // another spelling of our own id is us.
        // Every signing failure but the one above is an error (below). The one
        // slot that is no UUID, the Android personal key's ("self"), is copied
        // to this account's own key only, unsigned: its context can't bind it
        // (copySelfKeySlot, to the nil-UUID slot).
        let sender = canonical_id("sender_user_id", &sender_user_id)?;
        let recipient = canonical_id("recipient_user_id", &recipient_user_id)?;
        // A personal key slot, the nil id in any spelling or "self", goes to
        // this account only, and so to this device's own key (below), whoever
        // lists it as a circle: a server's nil-id "circle" never hands the
        // personal key to a member.
        if names_a_personal_slot(&circle_id) && recipient != sender {
            return Err(MobileError::InvalidInput("a personal key is wrapped for this account only".to_string()));
        }
        let personal_self_copy = circle_id == ANDROID_PERSONAL_KEY_SLOT;
        if !personal_self_copy {
            canonical_id("circle_id", &circle_id)?;
        }

        // Get the active circle key + version (used for sig context)
        let (key_version, circle_key) = self.get_active_circle_key_with_version(&circle_id)?;

        // SECURITY (self-wrap key substitution, defense-in-depth): mirror
        // prepare_key_rotation. If this wrap is for our OWN entry (recipient ==
        // sender), IGNORE the server-supplied `member_public_key_hex` and wrap to
        // our OWN trusted public key, so a server that substitutes an attacker key
        // for our self entry cannot learn the circle key. Our own key is already
        // trusted, so skip the decode / length / small-order checks for it.
        let member_public = if recipient == sender {
            self.public_key
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .ok_or_else(|| MobileError::KeyNotFound(
                    "No own public key available to wrap self's circle-key entry".to_string(),
                ))?
        } else {
            let member_public_bytes = decode_flexible(&member_public_key_hex)?;
            if member_public_bytes.len() != 32 {
                return Err(MobileError::InvalidKey);
            }
            let mut member_public_array = [0u8; 32];
            member_public_array.copy_from_slice(&member_public_bytes);
            let member_public = PublicKey::from(member_public_array);

            // SECURITY: Reject small-order points that would produce an all-zero shared secret
            reject_small_order_public(&member_public)?;
            member_public
        };

        // Generate ephemeral keypair for ECDH
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let shared_secret = ephemeral_secret.diffie_hellman(&member_public);
        drop(ephemeral_secret); // Explicit drop triggers Zeroize
        let mut wrapping_key = blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes());

        let nonce: [u8; 24] = generate_secure_nonce();
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        // SECURITY: Zeroize wrapping key after cipher construction consumes it
        wrapping_key.zeroize();
        let encrypted = cipher
            .encrypt(&XNonce::from(nonce), circle_key.as_ref())
            .map_err(|_| MobileError::EncryptionFailed)?;

        let ephemeral_pubkey_bytes = ephemeral_public.to_bytes();

        // A personal key taken on trust is never PUBLISHED, signed or not, so
        // no copy of it is produced at all (copy_personal_key moves it between
        // this device's own slots).
        if self.is_taken_on_trust(&circle_key) {
            tracing::warn!("Refusing to wrap a personal key this device took on trust");
            return Err(MobileError::InvalidInput(
                "this personal key was taken on trust; it is never published".to_string(),
            ));
        }
        // Nor is a circle key taken on trust delivered under our signature; a
        // member who pins us would store it as authentic. Rotating the circle
        // (`active_key_taken_on_trust`) gives a key to deliver.
        if self.circle_key_is_taken_on_trust(&circle_id, key_version) {
            tracing::warn!("Refusing to wrap a circle key this device took on trust");
            return Err(MobileError::InvalidInput(
                "this circle key was taken on trust; it is delivered only after a copy signed by this account arrives, or a rotation"
                    .to_string(),
            ));
        }

        // Sign the wrap context with our Ed25519 signing key. Only with none
        // installed does it go unsigned; any other failure sends nothing.
        let no_signing_key = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner()).is_none();
        let wrap_signature = match self.sign_wrap_internal(
            DOMAIN_CIRCLE_MEMBER_WRAP,
            &sender_user_id,
            &recipient_user_id,
            &circle_id,
            "",
            key_version as u32,
            Some(&ephemeral_pubkey_bytes),
            &nonce,
            &encrypted,
        ) {
            Ok(signature) => signature,
            Err(e @ MobileError::KeyNotFound(_)) if no_signing_key => {
                tracing::warn!("circle_member_wrap signature emission failed: {}", e);
                String::new()
            }
            Err(MobileError::InvalidInput(_)) if personal_self_copy => String::new(),
            Err(e) => return Err(e),
        };

        Ok(MemberKeyBundle {
            encrypted_circle_key: EncryptedData {
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(encrypted),
            },
            ephemeral_public_key: hex::encode(ephemeral_pubkey_bytes),
            wrap_signature,
        })
    }

    /// Derive a per-circle pseudonym for a user ID
    ///
    /// The pseudonym is deterministic but cannot be reversed.
    /// Different circles produce different pseudonyms for the same user.
    /// Delegates to pingolin_crypto::privacy::derive_user_pseudonym for consistency.
    pub fn derive_user_pseudonym(
        &self,
        circle_id: String,
        user_id: String,
    ) -> Result<String, MobileError> {
        let circle_key_bytes = self.get_active_circle_key(&circle_id)?;

        let key = pingolin_crypto::keys::SymmetricKey::try_from_slice(&circle_key_bytes)
            .map_err(|e| MobileError::CryptoError(format!("Invalid circle key: {}", e)))?;
        Ok(pingolin_crypto::privacy::derive_user_pseudonym(&key, &user_id))
    }

    /// Derive a per-circle pseudonym for a device ID
    /// Delegates to pingolin_crypto::privacy::derive_device_pseudonym for consistency.
    pub fn derive_device_pseudonym(
        &self,
        circle_id: String,
        device_id: String,
    ) -> Result<String, MobileError> {
        let circle_key_bytes = self.get_active_circle_key(&circle_id)?;

        let key = pingolin_crypto::keys::SymmetricKey::try_from_slice(&circle_key_bytes)
            .map_err(|e| MobileError::CryptoError(format!("Invalid circle key: {}", e)))?;
        Ok(pingolin_crypto::privacy::derive_device_pseudonym(&key, &device_id))
    }

    /// Derive both user and device pseudonyms at once
    pub fn derive_pseudonyms(
        &self,
        circle_id: String,
        user_id: String,
        device_id: String,
    ) -> Result<PseudonymPair, MobileError> {
        Ok(PseudonymPair {
            user_pseudonym: self.derive_user_pseudonym(circle_id.clone(), user_id)?,
            device_pseudonym: self.derive_device_pseudonym(circle_id, device_id)?,
        })
    }

    /// Derive the user's per-circle pseudonym for every key version we hold
    /// for that circle (including versions walked from the encrypted key
    /// chain). Used by the client to backfill `circle_member_pseudonyms`
    /// server-side so history queries can resolve ClickHouse rows tagged
    /// with pseudonyms that predate the latest circle-key rotation.
    ///
    /// Each derived value is stable for a given (circle_key_version, user_id)
    /// pair, so the caller can dedup them against any they've already sent.
    pub fn derive_user_pseudonyms_all_versions(
        &self,
        circle_id: String,
        user_id: String,
    ) -> Result<Vec<String>, MobileError> {
        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        let versions = match keys.get(&CircleKey::of(&circle_id)) {
            Some(v) => v,
            None => return Err(MobileError::KeyNotFound(
                format!("No circle key for: {}", circle_id)
            )),
        };

        let mut pseudonyms: Vec<String> = Vec::with_capacity(versions.len());
        for key_bytes in versions.values() {
            let key = pingolin_crypto::keys::SymmetricKey::try_from_slice(key_bytes.as_slice())
                .map_err(|e| MobileError::CryptoError(format!("Invalid circle key: {}", e)))?;
            pseudonyms.push(pingolin_crypto::privacy::derive_user_pseudonym(&key, &user_id));
        }
        // Dedup — versions are per-key-rotation, so normally produce distinct
        // pseudonyms, but a duplicate slot is harmless and not worth an error.
        pseudonyms.sort();
        pseudonyms.dedup();
        Ok(pseudonyms)
    }

    /// Collect all pseudonyms for GDPR-compliant account deletion.
    ///
    /// Returns a list of (circle_id, user_pseudonym) pairs for all circles
    /// the user has keys for. This enables the server to delete location data
    /// from ClickHouse without ever storing the pseudonym mapping.
    pub fn collect_deletion_pseudonyms(
        &self,
        user_id: String,
    ) -> Result<Vec<DeletionPseudonym>, MobileError> {
        let mut pseudonyms = Vec::new();

        // Use active version for each circle
        let active = self.active_key_version.read().unwrap_or_else(|e| e.into_inner());
        for (circle_key, &version) in active.iter() {
            let circle_id = circle_key.as_str();
            if circle_id.starts_with("temp_") {
                continue;
            }

            match self.get_circle_key_version(circle_id, version) {
                Ok(key_bytes) => {
                    match pingolin_crypto::keys::SymmetricKey::try_from_slice(&key_bytes) {
                        Ok(key) => {
                            let user_pseudonym = pingolin_crypto::privacy::derive_user_pseudonym(&key, &user_id);
                            pseudonyms.push(DeletionPseudonym {
                                circle_id: circle_id.to_owned(),
                                user_pseudonym,
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Failed to derive pseudonym for circle {}: {}", circle_id, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get key for circle {}: {}", circle_id, e);
                }
            }
        }

        drop(active);

        // On a circle with refresh records, the version this device seals
        // under can be below the newest held one, and its rows carry that
        // version's pseudonym: it is collected too.
        let recorded: Vec<String> = self
            .refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, chain)| chain.is_recorded())
            .map(|(circle_id, _)| circle_id.as_str().to_owned())
            .collect();
        for circle_id in recorded {
            let (Some(sealing), held) = (self.sealing_version(&circle_id), self.held_version(&circle_id)) else {
                continue;
            };
            if Some(sealing) == held {
                continue;
            }
            if let Ok(key_bytes) = self.get_circle_key_version(&circle_id, sealing) {
                if let Some(user_pseudonym) = user_pseudonym_for_key(&key_bytes, &user_id) {
                    pseudonyms.push(DeletionPseudonym { circle_id, user_pseudonym });
                }
            }
        }

        // A personal slot also holds RETIRED keys, each the only key for the
        // rows sealed under it: those rows must go too.
        {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
                for key_bytes in keys.get(&CircleKey::of(&slot)).map(|m| m.values().collect::<Vec<_>>()).unwrap_or_default() {
                    if let Some(user_pseudonym) = user_pseudonym_for_key(key_bytes, &user_id) {
                        let known = pseudonyms.iter().any(|p: &DeletionPseudonym| {
                            p.circle_id == slot && p.user_pseudonym.eq_ignore_ascii_case(&user_pseudonym)
                        });
                        if !known {
                            pseudonyms.push(DeletionPseudonym { circle_id: slot.to_string(), user_pseudonym });
                        }
                    }
                }
            }
        }

        tracing::info!("Collected {} deletion pseudonyms for user {}", pseudonyms.len(), user_id);
        Ok(pseudonyms)
    }

    /// Encrypt a timestamp with the circle key for E2EE activity metadata
    ///
    /// The server only sees day_bucket (coarse); precise time requires decryption.
    /// Returns EncryptedData with hex-encoded nonce and ciphertext.
    pub fn encrypt_timestamp(
        &self,
        circle_id: String,
        timestamp_ms: i64,
    ) -> Result<EncryptedData, MobileError> {
        let timestamp_str = timestamp_ms.to_string();
        self.encrypt_data(circle_id, timestamp_str)
    }

    /// Decrypt an encrypted timestamp from another circle member
    ///
    /// Returns the precise millisecond timestamp.
    pub fn decrypt_timestamp(
        &self,
        circle_id: String,
        encrypted_timestamp: EncryptedData,
    ) -> Result<i64, MobileError> {
        let plaintext = self.decrypt_data(circle_id, encrypted_timestamp)?;
        plaintext
            .parse::<i64>()
            .map_err(|_| MobileError::DecryptionFailed)
    }

    /// Compute an event type hash for E2EE boundary monitoring.
    ///
    /// Uses BLAKE3 to compute: hash(circle_key || event_type)
    /// This allows the server to route notifications without knowing the actual event type.
    /// The hash is deterministic for the same circle and event type.
    /// `event_type` is "enter" or "exit"; the result is a 64-character hex string.
    pub fn compute_event_type_hash(
        &self,
        circle_id: String,
        event_type: String,
    ) -> Result<String, MobileError> {
        let circle_key_bytes = self.get_active_circle_key(&circle_id)?;

        if circle_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError(
                "Circle key must be 32 bytes for keyed BLAKE3 hash".to_string(),
            ));
        }
        let mut circle_key_array = [0u8; 32];
        circle_key_array.copy_from_slice(&circle_key_bytes);
        let hash = blake3::keyed_hash(&circle_key_array, event_type.as_bytes());
        circle_key_array.zeroize();

        Ok(hash.to_hex().to_string())
    }

    /// Encrypt data using Argon2id key derivation and XSalsa20-Poly1305.
    ///
    /// This is used to encrypt the user's master key during registration.
    /// The password is used to derive a key via Argon2id, which is then used
    /// to encrypt the plaintext using XSalsa20-Poly1305 (libsodium crypto_secretbox).
    ///
    /// IMPORTANT: libsodium's crypto_pwhash always uses parallelism=1, regardless of
    /// what's stored in kdf_params. We must match this behavior for compatibility.
    ///
    /// **IMPORTANT**: This function performs Argon2id key derivation which is CPU-intensive
    /// and may block for 1-5 seconds. Callers MUST invoke this from a background thread
    /// (e.g., `tokio::task::spawn_blocking` or Android's `Dispatchers.IO`).
    ///
    /// `plaintext` is base64-encoded; the returned nonce and ciphertext are base64.
    pub fn encrypt_with_password(
        &self,
        plaintext: String,
        password: String,
        kdf_params: KdfParams,
    ) -> Result<EncryptedData, MobileError> {
        // SECURITY: Wrap password in Zeroizing for automatic cleanup when dropped
        let password = Zeroizing::new(password);

        // SECURITY: Validate KDF parameters meet minimum security requirements
        kdf_params.validate()?;

        let salt = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &kdf_params.salt,
        )?;

        // Derive (or reuse) the Argon2id key for these (salt, params).
        let derived_key = self.derive_or_cache_password_key(&password, &salt, &kdf_params)?;

        // Decode plaintext from base64 (zeroized: encrypt_with_password wraps the
        // user's master key during registration, so this decoded plaintext is
        // itself secret material — mirror encrypt_with_key).
        let plaintext_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &plaintext,
        )?);

        // Generate random nonce (24 bytes for XSalsa20) using thread-safe generator
        let nonce: [u8; 24] = generate_secure_nonce();

        // Encrypt using XSalsa20-Poly1305 (matches libsodium crypto_secretbox)
        let cipher = XSalsa20Poly1305::new_from_slice(derived_key.as_slice()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(&SalsaNonce::from(nonce), plaintext_bytes.as_slice())
            .map_err(|_| MobileError::EncryptionFailed)?;

        Ok(EncryptedData {
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
            ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        })
    }


    /// Encrypt data using a raw key (not password-derived).
    ///
    /// This is used for two-level encryption where the master key encrypts
    /// the private keys, and the master key itself is encrypted with the password.
    /// Uses XSalsa20-Poly1305 to match libsodium crypto_secretbox.
    ///
    /// `plaintext` and the 32-byte `key_base64` are base64-encoded; the returned
    /// nonce and ciphertext are base64.
    pub fn encrypt_with_key(
        &self,
        plaintext: String,
        key_base64: String,
    ) -> Result<EncryptedData, MobileError> {
        // SECURITY: the decoded Vec holds the raw key, so it must be Zeroizing
        // too — wiping only the [u8;32] copy below leaves the heap copy behind.
        let key_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &key_base64,
        )?);

        if key_bytes.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid key length: {} (expected 32)",
                key_bytes.len()
            )));
        }

        // Born inside Zeroizing so the staged key wipes on EVERY return path —
        // including the plaintext-decode `?` below.
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_bytes);

        // Decode plaintext from base64 (zeroized: encrypt_with_key wraps private
        // keys, so this decoded plaintext is itself secret material).
        let plaintext_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &plaintext,
        )?);

        // Generate random nonce (24 bytes for XSalsa20) using thread-safe generator
        let nonce: [u8; 24] = generate_secure_nonce();

        // Encrypt using XSalsa20-Poly1305 (matches libsodium crypto_secretbox)
        let cipher = XSalsa20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key");
        // `key` (Zeroizing) wipes on drop at end of scope, on every path.
        let ciphertext = cipher
            .encrypt(&SalsaNonce::from(nonce), plaintext_bytes.as_slice())
            .map_err(|_| MobileError::EncryptionFailed)?;

        Ok(EncryptedData {
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
            ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        })
    }

    /// Generate a random 32-byte master key and return as base64.
    ///
    /// This is used during registration to create a master key that will
    /// encrypt the user's private keys.
    pub fn generate_master_key(&self) -> String {
        // SECURITY: Uses thread-safe key generation
        let mut key: [u8; 32] = generate_secure_nonce();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key);
        // SECURITY: wipe the raw stack copy; the returned base64 string is the only retained form.
        key.zeroize();
        encoded
    }

    /// Decrypt data using a raw key (not password-derived).
    ///
    /// This is used for two-level decryption where the master key is first
    /// decrypted with the password, then used to decrypt other keys.
    /// Uses XSalsa20-Poly1305 to match libsodium crypto_secretbox.
    ///
    /// The nonce and ciphertext may be hex OR base64; `key_base64` is the 32-byte
    /// key as base64. The plaintext is returned base64-encoded.
    pub fn decrypt_with_key(
        &self,
        encrypted_data: EncryptedData,
        key_base64: String,
    ) -> Result<String, MobileError> {
        // Decode key from base64 (zeroized: the decoded Vec holds the raw master
        // key used to unwrap every other private key; wipe the heap copy too).
        let key_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &key_base64,
        )?);

        if key_bytes.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid key length: {} (expected 32)",
                key_bytes.len()
            )));
        }

        // Born inside Zeroizing so the staged key wipes on EVERY return path —
        // including the nonce/ciphertext decode `?`s below.
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_bytes);

        // Decode nonce and ciphertext - try hex first, then base64
        let nonce_bytes = decode_flexible(&encrypted_data.nonce)?;
        let ciphertext_bytes = decode_flexible(&encrypted_data.ciphertext)?;

        if nonce_bytes.len() != 24 {
            // `key` (Zeroizing) wipes on drop at this early return.
            return Err(MobileError::CryptoError(format!(
                "Invalid nonce length: {} (expected 24)",
                nonce_bytes.len()
            )));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        // Decrypt using XSalsa20-Poly1305 (matches libsodium crypto_secretbox)
        let cipher = XSalsa20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key");
        // `key` (Zeroizing) wipes on drop at end of scope, on every path.
        // SECURITY: this decrypted plaintext IS a long-term secret in the
        // two-level unwrap (master key -> X25519 sharing key / Ed25519 signing
        // seed), so the heap copy must be wiped on drop — same as
        // decrypt_with_password's plaintext.
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&SalsaNonce::from(nonce), ciphertext_bytes.as_ref())
                .map_err(|_| MobileError::DecryptionFailed)?,
        );

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plaintext.as_slice(),
        ))
    }

    /// Encrypt note content with a vault key using XChaCha20-Poly1305.
    ///
    /// This matches the web UI's note encryption exactly:
    /// - Algorithm: XChaCha20-Poly1305 AEAD (same as encrypt_data/circle keys)
    /// - Input: raw plaintext string (NOT base64-encoded)
    /// - Output: EncryptedData with base64-encoded nonce and ciphertext
    /// - Key: vault key (derived via BLAKE2b from private key + "pingolin-note-vault")
    ///
    /// Use this instead of encrypt_with_key for note content, as encrypt_with_key
    /// uses XSalsa20-Poly1305 which is incompatible with the web UI.
    pub fn encrypt_note(
        &self,
        plaintext: String,
        vault_key_base64: String,
    ) -> Result<EncryptedData, MobileError> {
        let key_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &vault_key_base64,
        )?);
        if key_bytes.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid vault key length: {} (expected 32)",
                key_bytes.len()
            )));
        }
        let mut zk = Zeroizing::new([0u8; 32]);
        zk.copy_from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(zk.as_slice()).expect("32-byte key");
        let nonce: [u8; 24] = generate_secure_nonce();
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), plaintext.as_bytes())
            .map_err(|_| MobileError::EncryptionFailed)?;
        Ok(EncryptedData {
            nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce),
            ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        })
    }

    /// Decrypt note content with a vault key using XChaCha20-Poly1305.
    ///
    /// Counterpart to encrypt_note. Handles both base64 and hex encoded
    /// nonce/ciphertext via decode_flexible (web uses base64, server may use hex).
    ///
    /// Returns the decrypted plaintext as a UTF-8 string (raw JSON, not base64).
    pub fn decrypt_note(
        &self,
        encrypted_data: EncryptedData,
        vault_key_base64: String,
    ) -> Result<String, MobileError> {
        let key_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &vault_key_base64,
        )?);
        if key_bytes.len() != 32 {
            return Err(MobileError::CryptoError(format!(
                "Invalid vault key length: {} (expected 32)",
                key_bytes.len()
            )));
        }
        let mut zk = Zeroizing::new([0u8; 32]);
        zk.copy_from_slice(&key_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(zk.as_slice()).expect("32-byte key");
        let nonce_bytes = decode_flexible(&encrypted_data.nonce)?;
        let ciphertext_bytes = decode_flexible(&encrypted_data.ciphertext)?;
        if nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError(format!(
                "Invalid nonce length: {} (expected 24)",
                nonce_bytes.len()
            )));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(&XNonce::from(nonce), ciphertext_bytes.as_ref())
            .map_err(|_| MobileError::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| MobileError::DecryptionFailed)
    }

    /// Decrypt password-encrypted data using Argon2id key derivation and XSalsa20-Poly1305.
    ///
    /// This is used to decrypt the user's master key during login.
    /// The password is used to derive a key via Argon2id, which is then used
    /// to decrypt the ciphertext using XSalsa20-Poly1305 (libsodium crypto_secretbox).
    ///
    /// IMPORTANT: libsodium's crypto_pwhash always uses parallelism=1, regardless of
    /// what's stored in kdf_params. We must match this behavior for compatibility.
    ///
    /// **IMPORTANT**: This function performs Argon2id key derivation which is CPU-intensive
    /// and may block for 1-5 seconds. Callers MUST invoke this from a background thread
    /// (e.g., `tokio::task::spawn_blocking` or Android's `Dispatchers.IO`).
    ///
    /// The nonce and ciphertext may be hex OR base64; `kdf_params` must be the
    /// parameters used at encrypt time. The plaintext is returned base64-encoded.
    pub fn decrypt_with_password(
        &self,
        encrypted_data: EncryptedData,
        password: String,
        kdf_params: KdfParams,
    ) -> Result<String, MobileError> {
        // SECURITY: Wrap password in Zeroizing for automatic cleanup when dropped
        let password = Zeroizing::new(password);

        // SECURITY: Validate KDF parameters meet minimum security requirements
        kdf_params.validate()?;

        // Decode the salt - try hex first, then base64
        let salt = decode_flexible(&kdf_params.salt)?;

        // Derive (or reuse) the Argon2id key for these (salt, params).
        let derived_key = self.derive_or_cache_password_key(&password, &salt, &kdf_params)?;

        // Decode nonce and ciphertext - try hex first, then base64
        let nonce_bytes = decode_flexible(&encrypted_data.nonce)?;
        let ciphertext_bytes = decode_flexible(&encrypted_data.ciphertext)?;

        if nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError(format!(
                "Invalid nonce length: {} (expected 24)",
                nonce_bytes.len()
            )));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        // Decrypt using XSalsa20-Poly1305 (matches libsodium crypto_secretbox)
        let cipher = XSalsa20Poly1305::new_from_slice(derived_key.as_slice()).expect("32-byte key");
        // Zeroized: this plaintext is the decrypted master key.
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&SalsaNonce::from(nonce), ciphertext_bytes.as_ref())
                .map_err(|_| MobileError::DecryptionFailed)?,
        );

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plaintext.as_slice(),
        ))
    }

    // ========================================================================
    // Alert Conditions E2EE Methods
    // ========================================================================

    /// Encrypt alert conditions for server storage
    ///
    /// The conditions contain schedule and trigger parameters that only
    /// circle members should be able to read. This enables client-side
    /// alert evaluation without the server knowing the conditions.
    pub fn encrypt_alert_conditions(
        &self,
        circle_id: String,
        conditions: AlertConditions,
    ) -> Result<EncryptedData, MobileError> {
        let plaintext = serde_json::to_string(&conditions)
            .map_err(|e| MobileError::CryptoError(format!("Failed to serialize conditions: {}", e)))?;

        self.encrypt_data(circle_id, plaintext)
    }

    /// Decrypt alert conditions from server
    ///
    /// Decrypts conditions that were encrypted with encrypt_alert_conditions.
    /// Only clients with the circle key can decrypt.
    pub fn decrypt_alert_conditions(
        &self,
        circle_id: String,
        encrypted_conditions: EncryptedData,
    ) -> Result<AlertConditions, MobileError> {
        let plaintext = self.decrypt_data(circle_id, encrypted_conditions)?;

        serde_json::from_str(&plaintext)
            .map_err(|e| MobileError::CryptoError(format!("Failed to parse conditions: {}", e)))
    }

    /// Evaluate place alert conditions client-side
    ///
    /// Determines if a place alert should fire based on decrypted conditions
    /// and current state. `is_arrival = false` means a departure event;
    /// `current_time_ms` is milliseconds since the Unix epoch.
    ///
    /// ⚠️ The Pingolin apps do not call this: each client evaluates place alerts
    /// with its own rules (`PlaceAlertRules` in the Track Android and iOS apps,
    /// and a TypeScript copy in the web client). Do not wire new rules in here
    /// expecting the clients to pick them up — they will not.
    ///
    /// This crate cannot reach the web client at all: there is no `wasm32`
    /// target and no `wasm-bindgen` (see `Cargo.toml`: `crate-type` is
    /// lib/staticlib/cdylib, and the crate pulls `tokio` with `rt-multi-thread`
    /// plus `tonic`). A shared implementation would therefore still leave a
    /// hand-written TypeScript copy, kept in agreement across an FFI and a hand
    /// port, which needs locked test vectors to stay honest, like the
    /// `location_codec` pair.
    ///
    /// Removing this export changes the FFI checksums, so it means regenerating
    /// the bindings in every app that links this SDK.
    pub fn evaluate_place_alert(
        &self,
        conditions: AlertConditions,
        is_arrival: bool,
        current_time_ms: i64,
    ) -> Result<AlertEvaluationResult, MobileError> {
        // Check if event type matches alert configuration
        let event_matches = if is_arrival {
            conditions.alert_on_arrival.unwrap_or(false)
        } else {
            conditions.alert_on_departure.unwrap_or(false)
        };

        if !event_matches {
            return Ok(AlertEvaluationResult {
                should_fire: false,
                reason: format!(
                    "Alert not configured for {} events",
                    if is_arrival { "arrival" } else { "departure" }
                ),
            });
        }

        // Check day of week if configured
        if let Some(ref active_days) = conditions.active_days {
            if !active_days.is_empty() {
                let day_of_week = get_day_of_week(current_time_ms, conditions.timezone.as_deref());
                if !active_days.iter().any(|d| d.to_lowercase() == day_of_week.to_lowercase()) {
                    return Ok(AlertEvaluationResult {
                        should_fire: false,
                        reason: format!("Alert not active on {}", day_of_week),
                    });
                }
            }
        }

        // Check time window if configured
        if let (Some(ref start), Some(ref end)) = (&conditions.active_start_time, &conditions.active_end_time) {
            if !is_within_time_window(current_time_ms, start, end, conditions.timezone.as_deref()) {
                return Ok(AlertEvaluationResult {
                    should_fire: false,
                    reason: format!("Current time not within active window ({} - {})", start, end),
                });
            }
        }

        Ok(AlertEvaluationResult {
            should_fire: true,
            reason: "All conditions met".to_string(),
        })
    }

    /// Evaluate inactivity alert conditions client-side
    ///
    /// Determines if an inactivity alert should fire based on decrypted
    /// conditions and last activity timestamp. Both timestamps are
    /// milliseconds since the Unix epoch.
    pub fn evaluate_inactivity_alert(
        &self,
        conditions: AlertConditions,
        last_activity_ms: i64,
        current_time_ms: i64,
    ) -> Result<AlertEvaluationResult, MobileError> {
        let timeout_minutes = conditions.timeout_minutes.unwrap_or(30);
        let timeout_ms = (timeout_minutes as i64) * 60 * 1000;

        let inactive_duration_ms = current_time_ms - last_activity_ms;
        let inactive_minutes = inactive_duration_ms / 60000;

        if inactive_duration_ms < timeout_ms {
            return Ok(AlertEvaluationResult {
                should_fire: false,
                reason: format!(
                    "User active within threshold ({} min inactive, {} min timeout)",
                    inactive_minutes, timeout_minutes
                ),
            });
        }

        Ok(AlertEvaluationResult {
            should_fire: true,
            reason: format!(
                "User inactive for {} minutes (threshold: {} minutes)",
                inactive_minutes, timeout_minutes
            ),
        })
    }

    // ========================================================================
    // Wrap signatures (Ed25519 over the locked sig_input scheme)
    // ========================================================================

    /// Generate a fresh Ed25519 signing keypair and store it in memory.
    ///
    /// Used at registration to mint the user's identity signing key, and
    /// by the migration flow for accounts whose signing seed is their
    /// X25519 sharing key (such a key matches no real Ed25519 public
    /// point, so `verify_wrap` fails until this regeneration runs).
    ///
    /// Returns the 32-byte secret seed (base64) and 32-byte verifying key
    /// (base64). The seed is what callers should encrypt under the master
    /// key and send to the auth server as `encrypted_signing_private_key`;
    /// the verifying key is what gets stored as `signing_public_key`.
    ///
    /// The seed itself is auto-persisted via `KeyStorageCallback` so it
    /// survives process restarts (same path as `import_signing_private_key`).
    pub fn generate_signing_keypair(&self) -> SigningKeyPair {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let secret_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &seed,
        );
        let public_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            verifying_key.to_bytes(),
        );

        // Install in memory + persist. It replaces a stored seed that didn't
        // install.
        *self.signing_keypair.write().unwrap_or_else(|e| e.into_inner()) = Some(signing_key);
        *self.unreadable_signing_seed.write().unwrap_or_else(|e| e.into_inner()) = None;
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after generate_signing_keypair: {}", e);
        }

        // Zeroize the stack copy of the seed; the SigningKey owns its own
        // private material now.
        seed.zeroize();

        SigningKeyPair {
            secret_seed_b64: secret_b64,
            verifying_key_b64: public_b64,
        }
    }

    /// Import the user's Ed25519 signing private key from a 32-byte secret seed
    /// (base64-encoded). Called by clients right after `import_private_key` on
    /// login, with the seed decrypted from the auth backend's
    /// `encrypted_signing_private_key` blob.
    pub fn import_signing_private_key(&self, secret_seed_b64: String) -> Result<(), MobileError> {
        self.install_signing_private_key(&secret_seed_b64)?;
        // It replaces a stored seed that didn't install.
        *self.unreadable_signing_seed.write().unwrap_or_else(|e| e.into_inner()) = None;

        // Auto-persist so the signing key survives process restarts (mirrors
        // import_private_key's auto-persist behaviour).
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after import_signing_private_key: {}", e);
        }

        tracing::debug!("import_signing_private_key: signing key loaded");
        Ok(())
    }

    /// Return our Ed25519 verifying-key (public) as a 64-char lowercase hex
    /// string. Useful for debugging, exporting to backups, or echoing back to
    /// the auth backend during key-rotation flows.
    pub fn signing_public_key_hex(&self) -> Result<String, MobileError> {
        let guard = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner());
        let sk = guard.as_ref().ok_or_else(|| {
            MobileError::KeyNotFound("No signing keypair loaded".to_string())
        })?;
        Ok(hex::encode(sk.verifying_key().to_bytes()))
    }

    /// Sign a wrap context with our Ed25519 signing key, returning the 64-byte
    /// signature as a 128-char lowercase hex string.
    ///
    /// Returns `MobileError::KeyNotFound` if no signing key is loaded — callers
    /// that want graceful degradation (e.g. wrap_circle_key_for_member_full
    /// on the legacy grace path) should catch this.
    pub fn sign_wrap(&self, params: SignWrapParams) -> Result<String, MobileError> {
        // Never a personal-key wrap from here. This signs whatever bytes it
        // is handed, so it cannot tell a key this device made from one it
        // took on trust; sign_own_circle_key_wrap checks, this cannot.
        if uuid::Uuid::parse_str(&params.circle_id).map_or(false, |id| id.is_nil()) {
            return Err(MobileError::InvalidInput(
                "a personal-key wrap is signed with sign_own_circle_key_wrap".to_string(),
            ));
        }
        self.sign_wrap_unchecked(params)
    }

    /// Verify a wrap-context signature against an Ed25519 public key.
    ///
    /// Returns `Ok(true)` on a valid signature, `Ok(false)` on a structurally-
    /// well-formed but mathematically-invalid signature, and an error only when
    /// the inputs themselves can't be parsed (invalid hex, wrong lengths).
    pub fn verify_wrap(
        &self,
        signing_pubkey_hex: String,
        signature_hex: String,
        params: SignWrapParams,
    ) -> Result<bool, MobileError> {
        let pk_bytes = hex::decode(&signing_pubkey_hex)?;
        if pk_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pk_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| MobileError::InvalidKey)?;

        let sig_bytes = hex::decode(&signature_hex)?;
        if sig_bytes.len() != 64 {
            return Err(MobileError::InvalidInput(format!(
                "Invalid signature length: {} (expected 64)",
                sig_bytes.len()
            )));
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        let sig_input = compute_sig_input(&params)?;
        // verify_strict rejects non-canonical R/A encodings, closing the
        // Ed25519 signature-malleability window that the permissive `verify`
        // leaves open.
        Ok(verifying_key.verify_strict(sig_input.as_bytes().as_slice(), &signature).is_ok())
    }

    // ========================================================================
    // TOFU pinning of member keys
    // ========================================================================

    /// Record (or compare) a member's sharing+signing public keys for a circle.
    ///
    /// On first sight (no existing pin): records the pair and returns `NewPinning`.
    /// On exact match: bumps `last_verified_at` and returns `Matched`.
    /// On mismatch: leaves the existing pin untouched and returns `Changed*`. The
    /// caller is expected to surface a UI prompt and call
    /// `approve_member_key_change` only after the user has confirmed via SAS.
    pub fn pin_member_keys(
        &self,
        circle_id: String,
        user_id: String,
        sharing_pubkey_hex: String,
        signing_pubkey_hex: String,
    ) -> Result<PinResult, MobileError> {
        // A personal key slot has no members, so nobody is pinned as one: a
        // pin there would make a server's puppet a trusted signer of the
        // personal key.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it has no members".to_string()));
        }
        // Both ids in their one spelling only; anything else pins nothing.
        let key = format!("{}:{}", strict_id("circle_id", &circle_id)?, strict_id("user_id", &user_id)?);
        // Validate inputs are 32-byte hex.
        let sharing_decoded = hex::decode(&sharing_pubkey_hex)?;
        if sharing_decoded.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let signing_decoded = hex::decode(&signing_pubkey_hex)?;
        if signing_decoded.len() != 32 {
            return Err(MobileError::InvalidKey);
        }

        let now = current_unix_secs();
        let fresh_record = PinRecord {
            sharing_pubkey_hex: sharing_pubkey_hex.to_lowercase(),
            signing_pubkey_hex: signing_pubkey_hex.to_lowercase(),
            first_pinned_at: now,
            last_verified_at: now,
            user_approved_change_at: None,
        };

        // IDENTITY-LEVEL: a user is one person across circles. Whether their keys
        // are "new" is decided against everything this device has trusted for
        // them anywhere — not per circle, which would make a peer verified for
        // years first contact again in every new circle. Lock order:
        // pinned_keys, then identity_pins.
        let result = {
            let mut pins = self.pinned_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut identity = self.identity_pins.write().unwrap_or_else(|e| e.into_inner());
            let identity_key = user_id.clone();
            match pins.get(&key).cloned() {
                None => match identity_reference(&pins, &identity, &user_id) {
                    // Never seen anywhere — record both keys. Not while the
                    // store can't be read: a pin for them may be in it.
                    None if self.store_unreadable() => {
                        return Err(MobileError::StorageError(
                            "the key store can't be read: nobody is taken on first contact until it is".to_string(),
                        ));
                    }
                    None => {
                        pins.insert(key.clone(), fresh_record.clone());
                        identity.insert(identity_key, fresh_record);
                        PinResult {
                            state: PinState::NewPinning,
                            previous_pinned_at: 0,
                        }
                    }
                    Some(reference) => {
                        let state =
                            pin_state_against(&reference, &sharing_pubkey_hex, &signing_pubkey_hex);
                        if matches!(state, PinState::Matched) {
                            // Known keys in a new circle: pin them here too.
                            pins.insert(key.clone(), fresh_record);
                            identity.entry(identity_key).or_insert(reference.clone());
                        }
                        // Changed* in a circle with no pin of its own: record
                        // nothing — the caller raises the key-change alert and
                        // `approve_member_key_change` pins after the user confirms.
                        PinResult {
                            state,
                            previous_pinned_at: reference.first_pinned_at,
                        }
                    }
                },
                Some(existing) => {
                    let state = pin_state_against(&existing, &sharing_pubkey_hex, &signing_pubkey_hex);
                    if matches!(state, PinState::Matched) {
                        // Bump last_verified_at; preserve everything else.
                        let mut updated = existing.clone();
                        updated.last_verified_at = now;
                        pins.insert(key.clone(), updated.clone());
                        // Installs that predate identity pins build them here.
                        identity.entry(identity_key).or_insert(updated);
                    }
                    // For Changed* we deliberately leave the pin untouched.
                    PinResult {
                        state,
                        previous_pinned_at: existing.first_pinned_at,
                    }
                }
            }
        };

        // Persist after any state change. NewPinning and Matched both modify
        // the record; Changed* leaves it untouched but persisting is a no-op
        // in that case, so it's safe to always persist.
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after pin_member_keys: {}", e);
        }

        Ok(result)
    }

    /// Return the pinned **sharing** public key (hex) for `(circle_id, user_id)`,
    /// or `None` when no pin exists.
    ///
    /// The returned hex matches the exact storage encoding used by
    /// `pin_member_keys` (lowercase, 64 chars / 32 bytes), so callers can compare
    /// it DIRECTLY against the server-supplied `sharing_public_key` hex to catch a
    /// signing-strip / key-substitution downgrade on an already-pinned member.
    pub fn pinned_sharing_key(&self, circle_id: String, user_id: String) -> Option<String> {
        // Falls back to the user's IDENTITY pin when this circle has none, so a
        // caller comparing a server-supplied key against it (invite, rotation
        // gate) also catches a known user's substituted key in a NEW circle.
        // Any spelling of the ids finds the pin; a non-UUID has none, and every
        // call that pins, approves or wraps refuses one.
        let (Ok(key), Ok(user_id)) = (member_pin_key(&circle_id, &user_id), canonical_id("user_id", &user_id)) else {
            return None;
        };
        let pins = self.pinned_keys.read().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = pins.get(&key) {
            return Some(record.sharing_pubkey_hex.clone());
        }
        let identity = self.identity_pins.read().unwrap_or_else(|e| e.into_inner());
        identity_reference(&pins, &identity, &user_id).map(|r| r.sharing_pubkey_hex)
    }

    /// Return the pinned **signing** public key (hex) for `(circle_id, user_id)`,
    /// or `None` when this device has never pinned that user.
    ///
    /// A KEY LOOKUP, not trust. Same lookup as `pinned_sharing_key`: the
    /// circle's own pin first, then the user's identity pin, so the subject keys
    /// a membership statement binds can be compared with what this device knew.
    /// Verify a signer's statement under it only after the signer passed the
    /// caller's confirmed-member check: an identity pin exists for everyone this
    /// device ever pinned, confirmed or not (`pin_member_keys` records one, and
    /// `retain_member_pins` keeps one for every pin it retires). Circle-key
    /// wraps never use the identity pin.
    pub fn pinned_signing_key(&self, circle_id: String, user_id: String) -> Option<String> {
        let (Ok(key), Ok(user_id)) = (member_pin_key(&circle_id, &user_id), canonical_id("user_id", &user_id)) else {
            return None;
        };
        let pins = self.pinned_keys.read().unwrap_or_else(|e| e.into_inner());
        if let Some(record) = pins.get(&key) {
            return Some(record.signing_pubkey_hex.clone());
        }
        let identity = self.identity_pins.read().unwrap_or_else(|e| e.into_inner());
        identity_reference(&pins, &identity, &user_id).map(|r| r.signing_pubkey_hex)
    }

    /// Overwrite a TOFU pin after the user has confirmed via the safety-number
    /// SAS UI. Stamps `user_approved_change_at = now()` so audit logs can
    /// distinguish a fresh pin from a rotation.
    pub fn approve_member_key_change(
        &self,
        circle_id: String,
        user_id: String,
        new_sharing_pubkey_hex: String,
        new_signing_pubkey_hex: String,
    ) -> Result<(), MobileError> {
        // A personal key slot has no members.
        if names_a_personal_slot(&circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it has no members".to_string()));
        }
        let key = format!("{}:{}", strict_id("circle_id", &circle_id)?, strict_id("user_id", &user_id)?);
        let sharing_decoded = hex::decode(&new_sharing_pubkey_hex)?;
        if sharing_decoded.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let signing_decoded = hex::decode(&new_signing_pubkey_hex)?;
        if signing_decoded.len() != 32 {
            return Err(MobileError::InvalidKey);
        }

        let now = current_unix_secs();
        {
            let mut pins = self.pinned_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut identity = self.identity_pins.write().unwrap_or_else(|e| e.into_inner());
            // Preserve first_pinned_at if a record already existed; otherwise
            // treat this as both first-pin and approved-change at the same
            // moment (degenerate but harmless).
            let first_pinned_at = pins.get(&key).map(|p| p.first_pinned_at).unwrap_or(now);
            pins.insert(
                key,
                PinRecord {
                    sharing_pubkey_hex: new_sharing_pubkey_hex.to_lowercase(),
                    signing_pubkey_hex: new_signing_pubkey_hex.to_lowercase(),
                    first_pinned_at,
                    last_verified_at: now,
                    user_approved_change_at: Some(now),
                },
            );
            // The user approved these keys for the PERSON, so a new circle with
            // them is Matched from now on. Other circles keep their own pins and
            // prompt on their own.
            let identity_key = user_id;
            let identity_first = identity.get(&identity_key).map(|p| p.first_pinned_at).unwrap_or(first_pinned_at);
            identity.insert(
                identity_key,
                PinRecord {
                    sharing_pubkey_hex: new_sharing_pubkey_hex.to_lowercase(),
                    signing_pubkey_hex: new_signing_pubkey_hex.to_lowercase(),
                    first_pinned_at: identity_first,
                    last_verified_at: now,
                    user_approved_change_at: Some(now),
                },
            );
        }

        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after approve_member_key_change: {}", e);
        }
        Ok(())
    }

    // ========================================================================
    // Safety numbers (Signal-style SAS for out-of-band verification)
    // ========================================================================

    /// Compute the 60-decimal-digit safety number for an out-of-band
    /// verification with a peer (12 groups of 5 digits, single ASCII space
    /// between groups).
    ///
    /// Symmetric: peer.compute_safety_number(self) === self.compute_safety_number(peer)
    /// thanks to lex-min ordering of the two material blobs.
    ///
    /// `self_user_id` is taken as a parameter rather than read from the
    /// CryptoManager because the manager doesn't currently track the user's
    /// own UUID — it lives in `SessionManager`. Callers should pass their own
    /// user_id verbatim.
    pub fn compute_safety_number(
        &self,
        self_user_id: String,
        peer_user_id: String,
        peer_sharing_pubkey_hex: String,
        peer_signing_pubkey_hex: String,
    ) -> Result<String, MobileError> {
        // Our own X25519 sharing public key.
        let our_sharing_pk = self
            .public_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MobileError::KeyNotFound("No sharing public key loaded".to_string()))?;
        let our_sharing_pk_bytes = our_sharing_pk.to_bytes();

        // Our Ed25519 signing public key.
        let our_signing_pk_hex = self.signing_public_key_hex()?;
        let our_signing_pk_bytes = hex::decode(&our_signing_pk_hex)?;
        if our_signing_pk_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }

        // Self user_id → 16 bytes UUID
        let self_uuid_bytes = uuid_to_16_bytes(&self_user_id)?;
        let peer_uuid_bytes = uuid_to_16_bytes(&peer_user_id)?;

        let peer_sharing_bytes = hex::decode(&peer_sharing_pubkey_hex)?;
        if peer_sharing_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let peer_signing_bytes = hex::decode(&peer_signing_pubkey_hex)?;
        if peer_signing_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }

        // material_a = self.user_id_bytes  || self.sharing_pk  || self.signing_pk     // 80 bytes
        // material_b = peer.user_id_bytes  || peer.sharing_pk  || peer.signing_pk     // 80 bytes
        let mut material_self = Vec::with_capacity(80);
        material_self.extend_from_slice(&self_uuid_bytes);
        material_self.extend_from_slice(&our_sharing_pk_bytes);
        material_self.extend_from_slice(&our_signing_pk_bytes);

        let mut material_peer = Vec::with_capacity(80);
        material_peer.extend_from_slice(&peer_uuid_bytes);
        material_peer.extend_from_slice(&peer_sharing_bytes);
        material_peer.extend_from_slice(&peer_signing_bytes);

        // combined = lex-smaller || lex-larger (160 bytes total)
        let combined: Vec<u8> = if material_self < material_peer {
            let mut v = Vec::with_capacity(160);
            v.extend_from_slice(&material_self);
            v.extend_from_slice(&material_peer);
            v
        } else {
            let mut v = Vec::with_capacity(160);
            v.extend_from_slice(&material_peer);
            v.extend_from_slice(&material_self);
            v
        };

        // sas_key   = blake3::derive_key("pingolin.sas.v1", b"safety_number")
        // sas_bytes = blake3::keyed_hash(sas_key, combined)[..30]
        let sas_key = blake3::derive_key(SAS_CONTEXT_KEY, b"safety_number");
        let full_hash = blake3::keyed_hash(&sas_key, &combined);
        let sas_bytes = &full_hash.as_bytes()[..30];

        // 30 bytes → 60-digit safety number (12 groups of 5). The exact string
        // layout is a locked cross-platform contract — see
        // `safety_number_from_sas_bytes`.
        Ok(safety_number_from_sas_bytes(sas_bytes))
    }

    // ========================================================================
    // Signing our own wraps
    // ========================================================================

    /// Sign the creator wrap that `prepare_circle_creation` returned, as OUR
    /// OWN wrap for `circle_id` (sender = recipient = `user_id`, key version 1),
    /// so other devices of this account can verify it instead of trusting an
    /// unsigned self-labelled wrap. Works before `finalize_circle_creation` (key
    /// still under the temp id) and after it. For the personal key pass the nil
    /// UUID. Returns the hex signature to upload as the wrap's `wrap_signature`.
    pub fn sign_circle_creation_wrap(
        &self,
        creation: CircleCreationData,
        circle_id: String,
        user_id: String,
    ) -> Result<String, MobileError> {
        // The temp id is unique to this creation, so while it exists it is the
        // key to check; after `finalize_circle_creation` the key lives under the
        // real id.
        let held_under = if self.get_circle_key_version(&creation.temp_circle_id, 1).is_ok() {
            creation.temp_circle_id.clone()
        } else {
            circle_id.clone()
        };
        let encrypted_key = format!(
            "{}{}",
            creation.encrypted_circle_key.nonce, creation.encrypted_circle_key.ciphertext
        );
        self.sign_own_wrap_of_held_key(
            &held_under,
            &circle_id,
            &user_id,
            1,
            &encrypted_key,
            &creation.ephemeral_public_key,
        )
    }

    /// Sign an existing wrap of OUR OWN key for `circle_id` at `key_version`
    /// (arguments shaped like `store_circle_key`'s), e.g. the server's unsigned
    /// copy of our personal key or of our own circle slot. Signs only if the
    /// wrap opens to the key this device already holds for that version, so a
    /// server can never obtain our signature over a key it chose.
    pub fn sign_own_circle_key_wrap(
        &self,
        circle_id: String,
        user_id: String,
        key_version: i32,
        encrypted_key: String,
        sender_public_key: String,
    ) -> Result<String, MobileError> {
        self.sign_own_wrap_of_held_key(
            &circle_id,
            &circle_id,
            &user_id,
            key_version,
            &encrypted_key,
            &sender_public_key,
        )
    }

    // ========================================================================
    // Pin lifecycle
    // ========================================================================

    /// Retire the pins of `circle_id` members that are not in `member_user_ids`
    /// (the circle's complete current roster). A retired user can no longer sign
    /// circle keys for this circle; their identity pin is kept, so if they come
    /// back their keys are Matched or Changed, never new. Returns how many pins
    /// were retired. Call after every successful full roster fetch.
    pub fn retain_member_pins(
        &self,
        circle_id: String,
        member_user_ids: Vec<String>,
    ) -> Result<u32, MobileError> {
        if member_user_ids.is_empty() {
            return Err(MobileError::InvalidInput(
                "retain_member_pins needs the circle's full roster; got an empty list".to_string(),
            ));
        }
        let circle_id = strict_id("circle_id", &circle_id)?;
        let keep: HashSet<String> = member_user_ids.iter().map(|id| strict_id("user_id", id)).collect::<Result<_, _>>()?;
        let prefix = format!("{}:", circle_id);
        let mut retired = 0u32;
        {
            let mut pins = self.pinned_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut identity = self.identity_pins.write().unwrap_or_else(|e| e.into_inner());
            let doomed: Vec<String> = pins
                .keys()
                .filter(|k| {
                    k.strip_prefix(&prefix)
                        .map_or(false, |user| !keep.contains(&user.to_ascii_lowercase()))
                })
                .cloned()
                .collect();
            for key in doomed {
                if let Some(record) = pins.remove(&key) {
                    let user = key[prefix.len()..].to_ascii_lowercase();
                    identity.entry(user).or_insert(record);
                    retired += 1;
                }
            }
        }
        if retired > 0 {
            tracing::info!("Retired {} pin(s) of former members of circle {}", retired, circle_id);
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after retain_member_pins: {}", e);
            }
        }
        Ok(retired)
    }

    /// Export this device's member pins (public keys and timestamps, no
    /// secrets) so an app can keep them across a sign-out of the SAME account:
    /// export before `clear_all_keys`, store under `owner_user_id`, and
    /// `import_member_pins` on that user's next sign-in.
    pub fn export_member_pins(&self, owner_user_id: String) -> Result<String, MobileError> {
        if owner_user_id.is_empty() {
            return Err(MobileError::InvalidInput("owner_user_id is required".to_string()));
        }
        if self.store_unreadable() {
            return Err(MobileError::StorageError(
                "the key store can't be read: the pins held now are not this device's".to_string(),
            ));
        }
        let export = ExportedMemberPins {
            format: MEMBER_PINS_EXPORT_FORMAT.to_string(),
            owner_user_id: canonical_id("owner_user_id", &owner_user_id)?,
            pins: self.pinned_keys.read().unwrap_or_else(|e| e.into_inner()).clone(),
            identity_pins: self.identity_pins.read().unwrap_or_else(|e| e.into_inner()).clone(),
        };
        Ok(serde_json::to_string(&export)?)
    }

    /// Restore pins exported by `export_member_pins` for the same account. A
    /// blob exported for another account is refused. Imported records win over
    /// any held for the same member: they are what this device trusted before
    /// the sign-out. Returns how many records were imported.
    pub fn import_member_pins(
        &self,
        owner_user_id: String,
        exported_pins: String,
    ) -> Result<u32, MobileError> {
        let export: ExportedMemberPins = serde_json::from_str(&exported_pins)?;
        if export.format != MEMBER_PINS_EXPORT_FORMAT {
            return Err(MobileError::InvalidInput(format!(
                "unknown member pin export format: {}",
                export.format
            )));
        }
        let owner = canonical_id("owner_user_id", &owner_user_id)?;
        if canonical_id("owner_user_id", &export.owner_user_id).ok().as_ref() != Some(&owner) {
            return Err(MobileError::InvalidInput(
                "member pins were exported for a different account".to_string(),
            ));
        }
        let mut imported = 0u32;
        // Two spellings of one member in the blob are one pin (a conflict reads
        // as changed until approved); an imported pin then replaces a held one.
        let (mut blob_pins, mut blob_identity) = (HashMap::new(), HashMap::new());
        {
            let (pins, identity) = (&mut blob_pins, &mut blob_identity);
            for (key, record) in export.pins {
                // Only "{circle_id}:{user_id}" keys with well-formed keys. Every
                // reserved key (`*:` identity pins, and every `~` marker: the
                // unconfirmed rotation, the trust and adoption marks and the
                // refresh-record state) is this device's own, never imported:
                // a well-formed one would otherwise come back as a real mark
                // after the next load.
                // Under the one spelling of both ids; any other key is skipped,
                // and so is a pin under a personal key slot, which has no
                // members.
                if pin_under_a_personal_slot(&key) {
                    continue;
                }
                let key = key.split_once(':').and_then(|(c, u)| member_pin_key(c, u).ok());
                if let (Some(key), true) = (key, pin_record_is_well_formed(&record)) {
                    keep_pin(pins, key, record);
                    imported += 1;
                }
            }
            for (user_id, record) in export.identity_pins {
                if let (Ok(user_id), true) = (canonical_id("user_id", &user_id), pin_record_is_well_formed(&record)) {
                    keep_pin(identity, user_id, record);
                    imported += 1;
                }
            }
        }
        {
            let mut pins = self.pinned_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut identity = self.identity_pins.write().unwrap_or_else(|e| e.into_inner());
            pins.extend(blob_pins);
            identity.extend(blob_identity);
        }
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after import_member_pins: {}", e);
        }
        Ok(imported)
    }

    // ========================================================================
    // Rotation bookkeeping
    // ========================================================================

    /// Drop this device's own rotation of `circle_id` if the server has not
    /// taken it: the circle goes back to the previous version, so nothing more is
    /// sealed under a key no other member will ever receive. Call when
    /// rotate-keys or eject-and-rotate fails. Returns whether anything was
    /// dropped. Safe when the outcome is unknown: a rotation the server did take
    /// comes back with the next key import (it is signed by us).
    pub fn discard_unconfirmed_rotation(&self, circle_id: String) -> bool {
        // A personal key slot is never rotated, so it has no rotation to
        // discard: nothing here drops a personal key.
        if names_a_personal_slot(&circle_id) {
            return false;
        }
        // Lock order: circle_keys, unconfirmed_rotations, active_key_version.
        let discarded = {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut unconfirmed = self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner());
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            match unconfirmed.get(&CircleKey::of(&circle_id)).copied() {
                Some(version) if active.get(&CircleKey::of(&circle_id)) == Some(&version) => {
                    unconfirmed.remove(&CircleKey::of(&circle_id));
                    if let Some(version_map) = keys.get_mut(&CircleKey::of(&circle_id)) {
                        // Removing the entry drops the Zeroizing<Vec<u8>>, wiping bytes.
                        version_map.remove(&version);
                        match version_map.keys().max().copied() {
                            Some(previous) => {
                                active.insert(CircleKey::of(&circle_id), previous);
                            }
                            None => {
                                keys.remove(&CircleKey::of(&circle_id));
                                active.remove(&CircleKey::of(&circle_id));
                            }
                        }
                    }
                    true
                }
                _ => false,
            }
        };
        if discarded {
            self.sender_session_keys
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&CircleKey::of(&circle_id));
            // Our own record for that rotation goes with it; the circle's secret
            // goes with its last key.
            {
                let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
                if let Some(chain) = chains.get_mut(&CircleKey::of(&circle_id)) {
                    chain.own = None;
                    if !self.has_circle_key(circle_id.clone()) {
                        chain.secret = None;
                    }
                }
            }
            tracing::warn!("Discarded our unconfirmed rotation of circle {}", circle_id);
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after discarding a rotation: {}", e);
            }
        }
        discarded
    }

    /// Generate an Ed25519 signing keypair WITHOUT installing or persisting it.
    /// For replacing the account's signing key: publish the new public key first
    /// and install the seed with `import_signing_private_key` only once the
    /// server has accepted it.
    pub fn generate_signing_keypair_detached(&self) -> SigningKeyPair {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        SigningKeyPair {
            secret_seed_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, seed.as_ref()),
            verifying_key_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                verifying_key.to_bytes(),
            ),
        }
    }

}

/// Convert 30 SAS bytes to the canonical 60-decimal-digit safety number,
/// formatted as 12 space-separated groups of 5 digits (the most-significant
/// 60 digits of the big-endian 240-bit integer, left-zero-padded). This exact
/// string layout is a locked cross-platform contract: note-collab-sdk's
/// `safety_number_from_sas_bytes` and the web `computeSafetyNumber` must
/// produce byte-identical output for the same 30 bytes.
fn safety_number_from_sas_bytes(sas_bytes: &[u8]) -> String {
    let big = num_bigint::BigUint::from_bytes_be(sas_bytes);
    let sas_digits = format!("{:0>60}", big.to_str_radix(10));
    let groups: Vec<&str> = (0..12).map(|i| &sas_digits[i * 5..(i + 1) * 5]).collect();
    groups.join(" ")
}

#[cfg(test)]
mod safety_number_vectors {
    // LOCKED cross-language SAS vector. note-collab-sdk asserts these SAME
    // strings for the SAME 30 input bytes (see its `safety_number_vectors`
    // test), guaranteeing Track mobile-sdk and note-collab-sdk produce
    // byte-identical out-of-band safety numbers.
    #[test]
    fn safety_number_from_sas_bytes_is_locked() {
        // Vector A: 1..=30 ramp (70-digit integer).
        let ramp: [u8; 30] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ];
        assert_eq!(
            super::safety_number_from_sas_bytes(&ramp),
            "69559 83830 57695 33006 27822 53272 10632 84149 72514 57156 24041 20155",
        );

        // Vector B: all 0xFF (2^240 - 1, a 73-digit integer — exercises the
        // most-significant-60 truncation that drops the low ~13 digits).
        let max: [u8; 30] = [0xFF; 30];
        assert_eq!(
            super::safety_number_from_sas_bytes(&max),
            "17668 47064 77838 43295 83297 50074 29185 15827 48389 68756 18958 12160",
        );
    }

    /// The property every verification UI depends on: two devices holding
    /// different keys must land on the SAME string. note-collab-sdk covers this
    /// for notes (`safety_number_is_symmetric_and_60_digits` in its roundtrip
    /// tests); this test exercises `compute_safety_number` end to end through
    /// two real CryptoManagers, beyond the byte-vector test above.
    #[test]
    fn compute_safety_number_agrees_between_two_managers() {
        use crate::crypto::CryptoManager;
        use base64::Engine;

        let b64_to_hex = |b64: &str| {
            hex::encode(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .expect("export_public_key returns valid base64"),
            )
        };

        let alice = CryptoManager::new();
        alice.generate_keypair();
        alice.generate_signing_keypair();
        let alice_id = "11111111-2222-3333-4444-555555555555".to_string();
        let alice_sharing = b64_to_hex(&alice.export_public_key().unwrap());
        let alice_signing = alice.signing_public_key_hex().unwrap();

        let bob = CryptoManager::new();
        bob.generate_keypair();
        bob.generate_signing_keypair();
        let bob_id = "66666666-7777-8888-9999-aaaaaaaaaaaa".to_string();
        let bob_sharing = b64_to_hex(&bob.export_public_key().unwrap());
        let bob_signing = bob.signing_public_key_hex().unwrap();

        let from_alice = alice
            .compute_safety_number(alice_id.clone(), bob_id.clone(), bob_sharing, bob_signing)
            .unwrap();
        let from_bob = bob
            .compute_safety_number(bob_id, alice_id, alice_sharing, alice_signing)
            .unwrap();

        assert_eq!(
            from_alice, from_bob,
            "each side must read the same safety number for the pair",
        );

        // Shape is part of the contract, not a display concern: the SDK emits
        // the final human-readable layout, so a client that re-groups this
        // string is what makes two devices disagree on screen while agreeing
        // underneath. 60 digits + 11 single spaces = 71 chars.
        assert_eq!(from_alice.len(), 71, "60 digits + 11 spaces");
        let groups: Vec<&str> = from_alice.split(' ').collect();
        assert_eq!(groups.len(), 12, "12 groups");
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())),
            "every group is exactly 5 ASCII digits: {from_alice}",
        );
    }
}

/// Private helper methods for CryptoManager (not exposed via UniFFI)
impl CryptoManager {
    /// The version this device seals under for `circle_id`.
    /// On a circle with refresh records: while this device's own record above
    /// its head is kept, that version with its key (its unconfirmed rotation)
    /// or nothing, never the version before it, which a member it removes
    /// knows; else the highest version whose record it ACCEPTED; and nothing
    /// while its chain is forked.
    /// On any other circle, and the personal slot: the highest version held.
    /// Each lock is taken and released on its own.
    pub(crate) fn sealing_version(&self, circle_id: &str) -> Option<i32> {
        let recorded = {
            let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
            chains
                .get(&CircleKey::of(&circle_id))
                .filter(|chain| chain.is_recorded())
                .map(|chain| {
                    // Our own record ABOVE the head: a rotation not served back
                    // yet (a new circle's genesis is its head already).
                    let own = chain.own.as_ref().map(|own| own.wire.body.version).filter(|version| {
                        chain.head.as_ref().map_or(true, |head| *version > head.version)
                    });
                    (chain.forked, chain.sealing, own)
                })
        };
        let Some((forked, sealing, own)) = recorded else {
            if self.latched_until_the_store_reads(circle_id) {
                return None;
            }
            // The newest version held, and never one below a version whose
            // stored copy didn't read here.
            let active = self.active_key_version.read().unwrap_or_else(|e| e.into_inner()).get(&CircleKey::of(&circle_id)).copied();
            return active.filter(|active| self.newest_unreadable_copy(circle_id).map_or(true, |newest| newest <= *active));
        };
        if forked {
            return None;
        }
        let held = |version: i32| {
            self.circle_keys
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&CircleKey::of(&circle_id))
                .map_or(false, |versions| versions.contains_key(&version))
        };
        if let Some(own) = own {
            let own = i32::try_from(own).ok()?;
            let unconfirmed = self.unconfirmed_rotations.read().unwrap_or_else(|e| e.into_inner()).get(&CircleKey::of(&circle_id)).copied();
            return (unconfirmed == Some(own) && held(own)).then_some(own);
        }
        let sealing = i32::try_from(sealing).ok().filter(|v| *v >= 1)?;
        held(sealing).then_some(sealing)
    }

    /// Wrap `new_key`, a rotation's new key at `new_version`, for `user_id`,
    /// signed as a rotation member wrap: the body of `prepare_key_rotation`'s
    /// loop, shared with the refresh-record builder.
    pub(crate) fn wrap_rotation_key(
        &self,
        circle_id: &str,
        sender_user_id: &str,
        new_version: i32,
        new_key: &[u8; 32],
        user_id: String,
        public_key_hex: &str,
    ) -> Result<MemberKeyRotationEntry, MobileError> {
        // SECURITY (self-wrap key substitution): the server returns self in
        // the member roster, so a malicious server can substitute an attacker
        // key for ONLY our own entry; if we wrapped the new circle key to it,
        // the server would learn the new key. For the self entry, IGNORE the
        // server-supplied `public_key_hex` and wrap to our OWN public key
        // instead. Our own key is already trusted, so we skip the decode /
        // length / small-order checks for it. Fail-SAFE: a substituted self
        // key is simply never used and rotation still succeeds. The ids are read
        // first and compared in their one spelling: our own id in another
        // spelling is still us.
        canonical_id("circle_id", circle_id)?;
        let is_self = canonical_id("sender_user_id", sender_user_id)? == canonical_id("user_id", &user_id)?;
        let member_public = if is_self {
            self.public_key
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .ok_or_else(|| MobileError::KeyNotFound(
                    "No own public key available to wrap self's circle-key entry".to_string(),
                ))?
        } else {
            let member_public_bytes = decode_flexible(public_key_hex)?;
            if member_public_bytes.len() != 32 {
                return Err(MobileError::InvalidKey);
            }
            let mut member_public_array = [0u8; 32];
            member_public_array.copy_from_slice(&member_public_bytes);
            let member_public = PublicKey::from(member_public_array);

            // SECURITY: Reject small-order points that would produce an all-zero shared secret
            reject_small_order_public(&member_public)?;
            member_public
        };

        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(&member_public);
        drop(ephemeral_secret); // Explicit drop triggers Zeroize
        let mut wrapping_key = blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes());

        let nonce: [u8; 24] = generate_secure_nonce();
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        wrapping_key.zeroize();
        let encrypted = cipher.encrypt(&XNonce::from(nonce), new_key.as_slice())
            .map_err(|_| MobileError::EncryptionFailed)?;

        let ephemeral_pubkey_bytes = ephemeral_public.to_bytes();

        // Sign the rotation wrap context (DOMAIN rotation_member_wrap). Only
        // with no signing key installed does it go unsigned.
        let no_signing_key = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner()).is_none();
        let wrap_signature = match self.sign_wrap_internal(
            DOMAIN_ROTATION_MEMBER_WRAP,
            sender_user_id,
            &user_id,
            circle_id,
            "",
            new_version as u32,
            Some(&ephemeral_pubkey_bytes),
            &nonce,
            &encrypted,
        ) {
            Ok(signature) => signature,
            Err(e @ MobileError::KeyNotFound(_)) if no_signing_key => {
                tracing::warn!("rotation_member_wrap signature emission failed: {}", e);
                String::new()
            }
            Err(e) => return Err(e),
        };

        Ok(MemberKeyRotationEntry {
            user_id,
            bundle: MemberKeyBundle {
                encrypted_circle_key: EncryptedData {
                    nonce: hex::encode(nonce),
                    ciphertext: hex::encode(encrypted),
                },
                ephemeral_public_key: hex::encode(ephemeral_pubkey_bytes),
                wrap_signature,
            },
        })
    }

    /// Take this device's own rotation of `circle_id` to `version` into the key
    /// store, as `prepare_key_rotation` does after its wraps: the key held,
    /// the newest version, the unconfirmed-rotation marker, and the old session
    /// key gone. Does not persist.
    pub(crate) fn commit_own_rotation(&self, circle_id: &str, version: i32, key: &[u8; 32]) {
        {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let version_map = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
            insert_capped_circle_version(version_map, version, Zeroizing::new(key.to_vec()));
        }
        {
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            if active.get(&CircleKey::of(&circle_id)).map_or(true, |current| version > *current) {
                active.insert(CircleKey::of(&circle_id), version);
            }
        }
        self.unconfirmed_rotations
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(CircleKey::of(&circle_id), version);
        self.invalidate_session_keys_for_circle(circle_id.to_string());
    }

    /// The circle name sealed under a rotation's new key, as `prepare_key_rotation` does.
    pub(crate) fn seal_circle_name(&self, key: &[u8; 32], plaintext: &str) -> Result<EncryptedData, MobileError> {
        encrypt_with_raw_key(key, plaintext.as_bytes())
    }

    /// This account's X25519 public key.
    pub(crate) fn own_sharing_public_key(&self) -> Option<[u8; 32]> {
        self.public_key.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|pk| pk.to_bytes())
    }

    /// Each recovered identity's (sharing, signing) public keys, paired by the
    /// portal's v2 binding: `previous_signing_public_keys`' set, kept in pairs.
    /// An identity with no binding gives none. Like the identities, never
    /// persisted: refresh records read them for the recovered pre-reset pairs
    /// (`OwnRestored`).
    pub(crate) fn previous_key_pairs(&self) -> Vec<([u8; 32], [u8; 32])> {
        let held: Vec<[u8; 32]> = self
            .previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|k| PublicKey::from(k).to_bytes())
            .collect();
        let bindings = self.previous_signing_keys.read().unwrap_or_else(|e| e.into_inner());
        held.iter().filter_map(|sharing| bindings.get(sharing).map(|signing| (*sharing, *signing))).collect()
    }

    /// Forget every key held for a circle: its versions, its active version,
    /// an unconfirmed rotation and the session key. Does not persist.
    pub(crate) fn forget_circle_keys(&self, circle_id: &str) {
        self.circle_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&circle_id));
        self.unreadable_circle_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&circle_id));
        self.active_key_version.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&circle_id));
        self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&circle_id));
        self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner()).remove(&CircleKey::of(&circle_id));
    }

    /// `forget_circle`: a circle this user is no longer in. Its keys, the
    /// provenance marks of those keys, its refresh-record state and its secret
    /// go, and the store is written. Its members' pins stay.
    /// A circle that had records here keeps its LATCHED mark and nothing else:
    /// re-joined, it counts as having records whatever the server serves, so
    /// nothing is sealed or delivered until one of its records is accepted
    /// here. Never the personal key slot. Returns whether anything was held
    /// (the mark alone is not).
    pub(crate) fn forget_circle_entirely(&self, circle_id: &str) -> bool {
        if is_personal_slot(circle_id) {
            tracing::warn!("forget_circle: refusing the personal key slot");
            return false;
        }
        // Lock order: `refresh` alone, first.
        let had_chain = {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            match chains.remove(&CircleKey::of(&circle_id)) {
                Some(chain) => {
                    if chain.is_recorded() {
                        chains.insert(CircleKey::of(&circle_id), crate::refresh::CircleChain::latched_only());
                    }
                    !chain.is_latched_only()
                }
                None => false,
            }
        };
        let had_keys = self.has_circle_key(circle_id.to_string())
            || self.unconfirmed_rotations.read().unwrap_or_else(|e| e.into_inner()).contains_key(&CircleKey::of(&circle_id))
            || self.unreadable_circle_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&CircleKey::of(&circle_id));
        self.forget_circle_keys(circle_id);
        let had_marks = {
            let mut marks = self.circle_provenance.write().unwrap_or_else(|e| e.into_inner());
            let before = marks.taken_on_trust.len() + marks.via_previous_identity.len() + marks.unread.len();
            let circle = CircleKey::of(circle_id);
            marks.taken_on_trust.retain(|(c, _)| *c != circle);
            marks.via_previous_identity.retain(|(c, _)| *c != circle);
            marks.unread.retain(|mark| mark.circle_id != circle);
            before != marks.taken_on_trust.len() + marks.via_previous_identity.len() + marks.unread.len()
        };
        let forgot = had_chain || had_keys || had_marks;
        if forgot {
            tracing::info!("Forgot circle {} on this device", circle_id);
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after forgetting a circle: {}", e);
            }
        }
        forgot
    }

    /// The newest version held for `circle_id` (>= 1), whatever its record says.
    pub(crate) fn held_version(&self, circle_id: &str) -> Option<i32> {
        self.active_key_version.read().unwrap_or_else(|e| e.into_inner()).get(&CircleKey::of(&circle_id)).copied()
    }

    /// Every key held for `circle_id` at a version >= 1.
    pub(crate) fn held_keys(&self, circle_id: &str) -> Vec<(u32, Zeroizing<Vec<u8>>)> {
        self.circle_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .map(|versions| {
                versions
                    .iter()
                    .filter_map(|(v, key)| u32::try_from(*v).ok().filter(|v| *v >= 1).map(|v| (v, key.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drop the key held for (`circle_id`, `version`): a copy whose record's tag
    /// it fails is never used again, to seal or to read. A session key sealed
    /// under it goes with it. Returns whether a key was dropped. Does not
    /// persist.
    pub(crate) fn drop_held_key(&self, circle_id: &str, version: u32) -> bool {
        let Ok(version) = i32::try_from(version) else {
            return false;
        };
        let dropped = {
            // Lock order: circle_keys, then active_key_version.
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            let dropped = keys.get_mut(&CircleKey::of(&circle_id)).and_then(|versions| versions.remove(&version)).is_some();
            if dropped {
                match keys.get(&CircleKey::of(&circle_id)).and_then(|versions| versions.keys().copied().filter(|v| *v >= 1).max()) {
                    Some(newest) => {
                        active.insert(CircleKey::of(&circle_id), newest);
                    }
                    None => {
                        active.remove(&CircleKey::of(&circle_id));
                    }
                }
                if keys.get(&CircleKey::of(&circle_id)).map_or(false, |versions| versions.is_empty()) {
                    keys.remove(&CircleKey::of(&circle_id));
                }
            }
            dropped
        };
        if dropped {
            let mut sessions = self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner());
            if sessions.get(&CircleKey::of(&circle_id)).map_or(false, |state| state.key_version == version) {
                sessions.remove(&CircleKey::of(&circle_id));
            }
        }
        dropped
    }

    /// Forget the marker of this device's unconfirmed rotation of `circle_id`
    /// when it is at `version`, whose key was dropped. Does not persist.
    pub(crate) fn forget_unconfirmed_rotation_at(&self, circle_id: &str, version: u32) {
        let mut unconfirmed = self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner());
        if unconfirmed.get(&CircleKey::of(&circle_id)).map_or(false, |v| i32::try_from(version) == Ok(*v)) {
            unconfirmed.remove(&CircleKey::of(&circle_id));
        }
    }

    /// Store a key the chain walk verified against its record's tag, for a
    /// version not held yet. A held version is never overwritten. Returns
    /// whether it was stored. Does not persist.
    pub(crate) fn add_verified_key(&self, circle_id: &str, version: u32, key: &[u8]) -> bool {
        let (Ok(version), true) = (i32::try_from(version), key.len() == 32) else {
            return false;
        };
        let stored = {
            // Lock order: circle_keys, then active_key_version.
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            let versions = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
            match versions.get(&version) {
                Some(held) => {
                    if !ct_eq(held, key) {
                        tracing::warn!(
                            "refresh records: a verified key for circle {} v{} differs from the one held; keeping the held one",
                            circle_id, version
                        );
                    }
                    false
                }
                None => {
                    insert_circle_version(circle_id, versions, version, Zeroizing::new(key.to_vec()));
                    if active.get(&CircleKey::of(&circle_id)).map_or(true, |current| version > *current) && versions.contains_key(&version) {
                        active.insert(CircleKey::of(&circle_id), version);
                    }
                    true
                }
            }
        };
        // Verified against its record: it takes the place of a stored copy
        // that didn't read.
        if stored {
            self.drop_unreadable_copy(circle_id, version);
        }
        stored
    }

    /// The newest version whose stored copy of `circle_id` didn't read here.
    fn newest_unreadable_copy(&self, circle_id: &str) -> Option<i32> {
        self.unreadable_circle_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .and_then(|entries| entries.keys().filter_map(|stored| unreadable_version(stored)).max())
    }

    /// Whether `circle_id`'s stored copy of `version` didn't read here.
    pub(crate) fn holds_unreadable_copy(&self, circle_id: &str, version: i32) -> bool {
        self.unreadable_circle_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .map_or(false, |entries| entries.keys().any(|stored| unreadable_version(stored) == Some(version)))
    }

    /// A key of `version` is held now: the stored copies that didn't read go
    /// (every copy of it a load kept apart).
    fn drop_unreadable_copy(&self, circle_id: &str, version: i32) {
        let mut unreadable = self.unreadable_circle_keys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entries) = unreadable.get_mut(&CircleKey::of(&circle_id)) {
            entries.retain(|stored, _| unreadable_version(stored) != Some(version));
            if entries.is_empty() {
                unreadable.remove(&CircleKey::of(&circle_id));
            }
        }
    }

    /// Whether `circle_id` has refresh records here (or was latched by a head):
    /// then it is never legacy again.
    pub(crate) fn circle_is_recorded_here(&self, circle_id: &str) -> bool {
        self.refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .map_or(false, |chain| chain.is_recorded())
    }

    /// While the store can't be read, every circle counts as having records:
    /// this device doesn't know which ones it latched, so nothing is sealed,
    /// delivered or rotated under a legacy decision. A lookup rule, never a
    /// stored chain, so a later successful load is never overridden. Not the
    /// personal key slots: they are no circles.
    pub(crate) fn latched_until_the_store_reads(&self, circle_id: &str) -> bool {
        self.store_unreadable() && !is_personal_slot(circle_id)
    }

    /// Ed25519-sign `message` with this account's identity signing key. For
    /// membership statements (membership.rs); wraps go through `sign_wrap`.
    pub(crate) fn sign_with_identity_key(&self, message: &[u8]) -> Result<[u8; 64], MobileError> {
        let guard = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner());
        let signing_key = guard
            .as_ref()
            .ok_or_else(|| MobileError::KeyNotFound("No signing keypair loaded".to_string()))?;
        Ok(signing_key.sign(message).to_bytes())
    }

    /// Install the X25519 identity from base64 WITHOUT persisting. Shared by
    /// `import_private_key` (which then persists) and `load_persisted_keys`
    /// (which must not write while it is still reading).
    fn install_private_key(&self, private_key_base64: &str) -> Result<(), MobileError> {
        // SECURITY: Wrap decoded bytes in Zeroizing for automatic cleanup
        let private_bytes = Zeroizing::new(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, private_key_base64)?);

        if private_bytes.len() != 32 {
            tracing::error!("import_private_key: invalid key length");
            tracing::debug!("import_private_key: invalid key length {} (expected 32)", private_bytes.len());
            return Err(MobileError::InvalidKey);
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&private_bytes);

        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);

        // SECURITY: Zeroize intermediate key bytes
        bytes.zeroize();

        // SECURITY: Do NOT log keys, even public keys, at info level
        // This prevents correlation attacks and timing analysis
        tracing::debug!("import_private_key: Key pair imported successfully");

        *self.private_key.write().unwrap_or_else(|e| e.into_inner()) = Some(secret);
        *self.public_key.write().unwrap_or_else(|e| e.into_inner()) = Some(public);
        Ok(())
    }

    /// Install the Ed25519 signing seed WITHOUT persisting (see
    /// `install_private_key`).
    fn install_signing_private_key(&self, secret_seed_b64: &str) -> Result<(), MobileError> {
        // Zeroized: the decoded Vec holds the Ed25519 identity seed; the
        // seed_array stack copy below is wiped, so wipe this heap copy too.
        let seed_bytes = Zeroizing::new(base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            secret_seed_b64,
        )?);
        // Accept two formats:
        //   - 32 bytes: the RFC 8032 seed (what `generate_signing_keypair`
        //     emits and what ed25519-dalek prefers).
        //   - 64 bytes: libsodium's expanded `secretKey` shape
        //     (32-byte seed || 32-byte public key). Accounts registered
        //     via the web/account app or older Android builds that called
        //     `sodium.crypto_sign_keypair()` directly land here — the
        //     first 32 bytes are the seed, the rest is the public key
        //     glued on for libsodium's API convenience. Strip the
        //     redundant suffix and treat as a normal seed.
        let mut seed_array = [0u8; 32];
        match seed_bytes.len() {
            32 => seed_array.copy_from_slice(&seed_bytes),
            64 => seed_array.copy_from_slice(&seed_bytes[..32]),
            n => {
                tracing::error!(
                    "import_signing_private_key: invalid seed length {} (expected 32 or 64)",
                    n
                );
                return Err(MobileError::InvalidKey);
            }
        }
        let signing_key = SigningKey::from_bytes(&seed_array);
        // Zeroize the local stack copy after constructing the SigningKey.
        seed_array.zeroize();

        *self.signing_keypair.write().unwrap_or_else(|e| e.into_inner()) = Some(signing_key);
        Ok(())
    }

    /// Merge a stored `circle_keys_json` + `pinned_keys_json` into memory. The
    /// STORED copy wins wherever both sides hold the same circle-key version or
    /// the same pin: it is the trust this device established earlier, whereas
    /// anything memory holds instead was accepted while the process did not know
    /// its own keys (a failed read, then a first-contact import). Everything only
    /// one side holds is kept. On a fresh manager this is a plain load.
    ///
    /// Returns the number of circle-key versions taken from the store. Errors on
    /// unparseable circle keys JSON, or a key that is not base64.
    fn merge_stored_circle_keys_and_pins(
        &self,
        circle_keys_json: &str,
        pinned_keys_json: Option<&str>,
    ) -> Result<usize, MobileError> {
        // Both blobs decode before anything is merged. One that doesn't is an
        // error, never an empty set: the caller keeps writes refused, so no
        // persist replaces the stored pins or keys (a missing pins blob is an
        // install that predates pinning, and reads as none).
        let stored_pins = pinned_keys_json
            .map(|pins_json| serde_json::from_str::<HashMap<String, PinRecord>>(pins_json))
            .transpose()
            .map_err(|e| MobileError::StorageError(format!("Invalid pinned keys JSON: {}", e)))?;
        // On-disk layout: circle_id -> { version -> base64_key }
        let versioned_keys: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(circle_keys_json)
                .map_err(|e| MobileError::StorageError(format!("Invalid circle keys JSON: {}", e)))?;
        let mut unread_marks = Vec::new();
        if let Some(all) = stored_pins {
            {
                {
                    let (pins, identity, rotations, provenance, circle_provenance, refresh) = split_persisted_pins(all);
                    unread_marks = circle_provenance.unread;
                    self.pinned_keys.write().unwrap_or_else(|e| e.into_inner()).extend(pins);
                    self.identity_pins.write().unwrap_or_else(|e| e.into_inner()).extend(identity);
                    self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner()).extend(rotations);
                    {
                        let mut held = self.personal_provenance.write().unwrap_or_else(|e| e.into_inner());
                        held.taken_on_trust.extend(provenance.taken_on_trust);
                        held.last_adoption = held.last_adoption.max(provenance.last_adoption);
                        let mut held_circles = self.circle_provenance.write().unwrap_or_else(|e| e.into_inner());
                        held_circles.taken_on_trust.extend(circle_provenance.taken_on_trust);
                        held_circles.via_previous_identity.extend(circle_provenance.via_previous_identity);
                    }
                    // Refresh-record state: a circle this process already
                    // tracks keeps its own (it verified it here); every other
                    // circle takes the stored one.
                    let stored_chains = crate::refresh::load_persisted(refresh);
                    let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
                    for (circle_id, chain) in stored_chains {
                        chains.entry(circle_id).or_insert(chain);
                    }
                }
            }
        }

        // The circles' secrets go to their chains, never among the circle
        // keys. `refresh` is taken alone, before the key locks.
        let (secrets, versioned_keys): (HashMap<_, _>, HashMap<_, _>) = versioned_keys
            .into_iter()
            .partition(|(circle_id, _)| circle_id.starts_with(crate::refresh::SECRET_PREFIX));
        if !secrets.is_empty() {
            // A circle's secret stored under several spellings of its id is
            // taken only if they are the same secret; else S is derived again.
            let mut by_circle: HashMap<CircleKey, Vec<(&String, &HashMap<String, String>)>> = HashMap::new();
            for (key, versions) in &secrets {
                let circle = key.strip_prefix(crate::refresh::SECRET_PREFIX).unwrap_or(key);
                by_circle.entry(CircleKey::of(circle)).or_default().push((key, versions));
            }
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            for (circle, stored) in by_circle {
                if stored.windows(2).any(|pair| pair[0].1 != pair[1].1) {
                    tracing::warn!("Two spellings of circle {} keep different secrets: neither is taken, and it is derived again", circle);
                    continue;
                }
                let (key, versions) = stored[0];
                crate::refresh::absorb_secret(&mut chains, key, versions);
            }
        }

        let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
        let mut active_versions = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
        let mut total_count = 0usize;

        // Entries that don't read: kept as stored, never filed under a version
        // (see `unreadable_circle_keys`).
        let mut unreadable: HashMap<CircleKey, HashMap<String, Zeroizing<String>>> = HashMap::new();
        // By circle, in its one spelling, with the spelling each copy was
        // stored under.
        let mut by_circle: HashMap<CircleKey, Vec<(String, HashMap<String, String>)>> = HashMap::new();
        for (circle_id, versions) in versioned_keys {
            by_circle.entry(CircleKey::of(&circle_id)).or_default().push((circle_id, versions));
        }
        for (circle_key, spellings) in by_circle {
            let circle_id = circle_key.as_str().to_owned();
            let versions = fold_circle_key_spellings(&circle_key, spellings, &mut unreadable);
            let mut version_map = keys.remove(&circle_key).unwrap_or_default();
            for (version_str, key_base64) in versions {
                let Ok(version) = version_str.parse::<i32>() else {
                    tracing::warn!("A stored circle key for {} under a version that doesn't read: kept as stored", circle_id);
                    keep_unreadable_copy(unreadable.entry(circle_key.clone()).or_default(), &version_str, key_base64);
                    continue;
                };
                let key_bytes = Zeroizing::new(base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &key_base64,
                ).map_err(|_| MobileError::InvalidKey)?);
                // SECURITY: Validate key length — XChaCha20-Poly1305 requires exactly 32 bytes
                if key_bytes.len() != 32 {
                    tracing::warn!(
                        "A stored circle key for {} v{} that isn't 32 bytes: kept as stored, and that version is never taken from another copy but by its record's tag",
                        circle_id, version
                    );
                    keep_unreadable_copy(unreadable.entry(circle_key.clone()).or_default(), &version_str, key_base64);
                    continue;
                }
                insert_circle_version(&circle_id, &mut version_map, version, key_bytes);
                total_count += 1;
            }
            // The active version is the highest one held (`store_circle_key`
            // keeps the same invariant). A RETIRED personal key (version <= 0)
            // is never in use, so a slot holding only retired keys has none.
            if let Some(max_version) = version_map.keys().copied().filter(|v| *v >= 1).max() {
                active_versions.insert(circle_key.clone(), max_version);
            }
            if !version_map.is_empty() {
                keys.insert(circle_key, version_map);
            }
        }

        // A mark that didn't read marks every version its circle holds now
        // (taken on trust / via a previous identity).
        let unread_marks: Vec<(UnreadMark, Vec<i32>)> = unread_marks
            .into_iter()
            .map(|mut mark| {
                let held: Vec<i32> =
                    keys.get(&mark.circle_id).map(|m| m.keys().copied().filter(|v| *v >= 1).collect()).unwrap_or_default();
                mark.newest = held.iter().copied().max();
                (mark, held)
            })
            .collect();
        drop(active_versions);
        drop(keys);
        if !unreadable.is_empty() {
            let mut held = self.unreadable_circle_keys.write().unwrap_or_else(|e| e.into_inner());
            for (circle_id, entries) in unreadable {
                let kept = held.entry(circle_id).or_default();
                for (name, stored) in entries {
                    keep_unreadable_copy(kept, &name, stored.as_str().to_owned());
                }
            }
        }
        if !unread_marks.is_empty() {
            let mut provenance = self.circle_provenance.write().unwrap_or_else(|e| e.into_inner());
            for (mark, held) in unread_marks {
                let marks = if mark.via_previous { &mut provenance.via_previous_identity } else { &mut provenance.taken_on_trust };
                marks.extend(held.into_iter().map(|version| (mark.circle_id.clone(), version)));
                provenance.unread.retain(|kept| kept.key != mark.key);
                provenance.unread.push(mark);
            }
        }

        Ok(total_count)
    }

    /// Shared body of `sign_circle_creation_wrap` / `sign_own_circle_key_wrap`:
    /// open `encrypted_key_hex` (a wrap to OUR public key), require the key
    /// inside to be exactly the one held under `held_under` at `key_version`, and
    /// only then sign it as our own wrap for `sign_circle_id`
    /// (sender = recipient = `user_id`, domain `circle_member_wrap`).
    fn sign_own_wrap_of_held_key(
        &self,
        held_under: &str,
        sign_circle_id: &str,
        user_id: &str,
        key_version: i32,
        encrypted_key_hex: &str,
        ephemeral_public_key: &str,
    ) -> Result<String, MobileError> {
        if !(1..=1_000_000).contains(&key_version) {
            return Err(MobileError::InvalidInput(format!(
                "implausible circle key version: {key_version}"
            )));
        }
        let held = self.get_circle_key_version(held_under, key_version)?;
        // A personal key taken on trust is never signed here.
        if self.is_taken_on_trust(&held) {
            tracing::warn!("Refusing to sign a wrap of a personal key this device took on trust");
            return Err(MobileError::InvalidInput(
                "this personal key was taken on trust; it is signed only after a copy signed by this account arrives"
                    .to_string(),
            ));
        }
        // Nor a circle key taken on trust.
        if self.circle_key_is_taken_on_trust(held_under, key_version) {
            tracing::warn!("Refusing to sign a wrap of a circle key this device took on trust");
            return Err(MobileError::InvalidInput(
                "this circle key was taken on trust; it is signed only after a copy signed by this account arrives"
                    .to_string(),
            ));
        }

        let eph_bytes = decode_flexible(ephemeral_public_key)?;
        if eph_bytes.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        let mut eph_array = [0u8; 32];
        eph_array.copy_from_slice(&eph_bytes);
        let eph_public = PublicKey::from(eph_array);
        reject_small_order_public(&eph_public)?;

        let wrap = hex::decode(encrypted_key_hex)?;
        if wrap.len() != 24 + 48 {
            return Err(MobileError::InvalidInput(
                "a circle-key wrap is a 24-byte nonce and a 48-byte ciphertext".to_string(),
            ));
        }
        let (nonce_bytes, ciphertext) = wrap.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let opened = {
            let guard = self.private_key.read().unwrap_or_else(|e| e.into_inner());
            let private_key = guard.as_ref().ok_or_else(|| {
                MobileError::KeyNotFound("No private key available".to_string())
            })?;
            let shared_secret = private_key.diffie_hellman(&eph_public);
            let wrapping_key =
                Zeroizing::new(blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes()));
            let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
            Zeroizing::new(
                cipher
                    .decrypt(&XNonce::from(nonce), ciphertext)
                    .map_err(|_| MobileError::DecryptionFailed)?,
            )
        };
        if !ct_eq(opened.as_slice(), held.as_slice()) {
            tracing::warn!(
                "Refusing to sign a wrap for circle {} v{}: it does not carry the key this device holds",
                sign_circle_id, key_version
            );
            return Err(MobileError::SignatureInvalid);
        }

        self.sign_wrap_internal(
            DOMAIN_CIRCLE_MEMBER_WRAP,
            user_id,
            user_id,
            sign_circle_id,
            "",
            key_version as u32,
            Some(&eph_array),
            &nonce,
            ciphertext,
        )
    }

    /// `load_persisted_keys`' reading of a stored blob. Ok(false): it belongs to
    /// another identity (the next write replaces it). Private, in this block:
    /// UniFFI exports every fn of the exported block, private or not.
    fn load_stored_data(&self, data: &StoredKeyData) -> Result<bool, MobileError> {
        // A RELOAD (the app retrying after a failed load, with keys it
        // imported at sign-in meanwhile): the identity in memory is the
        // newer one. A store written for a different identity is not
        // merged into it at all — the next write replaces it.
        let held_identity = self
            .private_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|k| Zeroizing::new(k.to_bytes()));
        match held_identity {
            None => self.install_private_key(&data.private_key)?,
            Some(current) => {
                let stored = Zeroizing::new(base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &data.private_key,
                )?);
                // A stored key that isn't a key (a half-written store) is no
                // other identity: it doesn't decode.
                if stored.len() != 32 {
                    return Err(MobileError::InvalidKey);
                }
                if !ct_eq(current.as_slice(), stored.as_slice()) {
                    tracing::warn!(
                        "Persisted keys belong to another identity; keeping the one in memory (the next write replaces them)"
                    );
                    return Ok(false);
                }
            }
        }

        // `None` = an install that predates signing keys; not an error.
        // A signing key already in memory (imported at sign-in) is newer
        // than a stored one and is kept.
        let holds_signing_key =
            self.signing_keypair.read().unwrap_or_else(|e| e.into_inner()).is_some();
        if holds_signing_key {
            tracing::debug!("Keeping the signing key already loaded");
        } else {
            // Don't hard-fail on a seed that doesn't install: a corrupt signing
            // key blob shouldn't lock the user out of their X25519 private key.
            // It is kept as stored instead (see `take_stored_signing_seed`).
            self.take_stored_signing_seed(data.signing_private_key_b64.as_deref());
        }

        // Pins (a missing blob = an install that predates TOFU pinning)
        // and circle keys. On a fresh manager this is a plain load; on one
        // that already holds keys the stored copy wins every conflict.
        let total_count = self.merge_stored_circle_keys_and_pins(
            &data.circle_keys_json,
            data.pinned_keys_json.as_deref(),
        )?;

        tracing::info!("Loaded {} circle key versions from secure storage", total_count);
        Ok(true)
    }

    /// The first write of a process that never saw the stored contents (its
    /// load reported "nothing stored"): fold what the store actually holds into
    /// memory first, so the write cannot replace it with less. A blob written
    /// for a DIFFERENT X25519 identity is not ours to keep and is overwritten.
    /// A stored blob that doesn't decode is an error (the caller refuses to
    /// write), never "another identity" or an empty set to write over.
    fn merge_stored_keys(&self, stored: StoredKeyData) -> Result<(), MobileError> {
        let stored_bytes = Zeroizing::new(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &stored.private_key)
                .map_err(|e| MobileError::StorageError(format!("the stored identity key doesn't decode: {}", e)))?,
        );
        // Nor one that isn't 32 bytes (a half-written store): no other identity.
        if stored_bytes.len() != 32 {
            return Err(MobileError::StorageError("the stored identity key is not a key".to_string()));
        }
        let same_identity = self
            .private_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(false, |current| ct_eq(Zeroizing::new(current.to_bytes()).as_slice(), stored_bytes.as_slice()));
        if !same_identity {
            tracing::warn!("persist_keys: the stored keys belong to another identity; replacing them");
            return Ok(());
        }

        let count = self.merge_stored_circle_keys_and_pins(
            &stored.circle_keys_json,
            stored.pinned_keys_json.as_deref(),
        )?;
        tracing::warn!(
            "persist_keys: the store held keys this process had not loaded; kept {} circle key versions and the stored pins",
            count
        );

        let has_signing_key = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner()).is_some();
        if !has_signing_key {
            self.take_stored_signing_seed(stored.signing_private_key_b64.as_deref());
        }
        Ok(())
    }

    /// The stored signing seed, read while no seed is held (after the
    /// identity it is stored with is installed or matched): installed without
    /// persisting. One that doesn't install is kept exactly as stored, for
    /// this identity, and `persist_keys` writes it back unchanged until a seed
    /// is imported or generated here; the device runs without a signing key
    /// meanwhile. None stored: nothing is kept.
    fn take_stored_signing_seed(&self, stored: Option<&str>) {
        let unreadable = match stored {
            None => {
                tracing::debug!("No persisted signing key (legacy install)");
                None
            }
            Some(seed) => match self.install_signing_private_key(seed) {
                Ok(()) => None,
                Err(e) => {
                    tracing::warn!(
                        "The persisted signing key doesn't install ({}); continuing without it and keeping it as stored",
                        e
                    );
                    let identity = self.public_key.read().unwrap_or_else(|e| e.into_inner()).map(|k| k.to_bytes());
                    identity.map(|identity| (Zeroizing::new(seed.to_string()), identity))
                }
            },
        };
        *self.unreadable_signing_seed.write().unwrap_or_else(|e| e.into_inner()) = unreadable;
    }

    /// Whether the last load (or the first write's re-read) could not read or
    /// decode the store: until a load succeeds or the keys are cleared, this
    /// process doesn't know what it holds.
    pub(crate) fn store_unreadable(&self) -> bool {
        matches!(self.load_state.load(Ordering::Acquire), LOAD_FAILED | LOAD_UNDECODABLE)
    }

    /// Whether a stored signing seed that doesn't install is kept.
    pub(crate) fn signing_seed_unreadable(&self) -> bool {
        self.unreadable_signing_seed.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Whether any stored entry that didn't read is kept: a circle's record
    /// state, a circle mark, or a circle key.
    fn entries_unreadable(&self) -> bool {
        // `refresh` first and alone (its lock order).
        let circles = self.refresh.read().unwrap_or_else(|e| e.into_inner()).values().any(|chain| !chain.as_stored.is_empty());
        circles
            || !self.circle_provenance.read().unwrap_or_else(|e| e.into_inner()).unread.is_empty()
            || !self.unreadable_circle_keys.read().unwrap_or_else(|e| e.into_inner()).is_empty()
    }
    /// Byte-level core of `decrypt_data_v2`. Identical key, AAD and key-version
    /// logic — it just stops short of the UTF-8 conversion, so a caller reading a
    /// PACKED location plaintext (binary, not text) can get the bytes.
    ///
    /// DELIBERATELY PRIVATE: it lives in this block, not the `#[uniffi::export]`
    /// one, so UniFFI does not put it on the FFI surface. An exported
    /// "decrypt anything under a circle key and hand me raw bytes" is a sharper
    /// tool than the apps need, and every app path already has a typed method.
    fn decrypt_data_v2_bytes(
        &self,
        circle_id: &str,
        encrypted_data: &EncryptedData,
        field_tag: &str,
    ) -> Result<Vec<u8>, MobileError> {
        self.decrypt_data_v2_bytes_opened(circle_id, encrypted_data, field_tag).map(|(_version, bytes)| bytes)
    }

    /// `decrypt_data_v2_bytes`, with the version whose key opened it.
    fn decrypt_data_v2_bytes_opened(
        &self,
        circle_id: &str,
        encrypted_data: &EncryptedData,
        field_tag: &str,
    ) -> Result<(i32, Vec<u8>), MobileError> {
        // Try each v2 candidate AAD (field-only + id-bound for "name"; id-bound
        // for other fields) across every key version, then the v1 empty-AAD
        // legacy fallback. A relabelled/field-swapped ciphertext matches none.
        for aad in circle_field_read_aads_v2(circle_id, field_tag) {
            if let Ok(opened) = open_with_versions(&self.circle_keys, circle_id, encrypted_data, &aad) {
                return Ok(opened);
            }
        }
        open_with_versions(&self.circle_keys, circle_id, encrypted_data, b"")
    }

    /// `decrypt_location`, with the version whose key opened it.
    fn decrypt_location_opened_inner(&self, circle_id: &str, encrypted_location: &EncryptedData) -> Result<(i32, Location), MobileError> {
        let (version, plaintext) = self.decrypt_data_v2_bytes_opened(circle_id, encrypted_location, "location")?;
        Ok((version, decode_location(&plaintext)?))
    }

    /// `unwrap_and_decrypt_place`, with the circle-key version that unwrapped
    /// the place key.
    fn unwrap_and_decrypt_place_opened_inner(
        &self,
        target_id: &str,
        wrapped_key: &str,
        wrapped_key_nonce: &str,
        ciphertext: String,
        ciphertext_nonce: String,
    ) -> Result<(i32, String), MobileError> {
        let wrap_nonce_bytes = decode_flexible(wrapped_key_nonce)?;
        if wrap_nonce_bytes.len() != 24 {
            return Err(MobileError::CryptoError("Invalid wrapped key nonce length".to_string()));
        }
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);
        let wrapped_key_bytes = decode_flexible(wrapped_key)?;

        // Step 1: Unwrap the per-place key against each known circle-key version
        // (newest first) for a given wrap AAD. Identical structure to
        // unwrap_and_decrypt_location_v2: pre-rotation places would otherwise fail
        // silently. Iterates under one read lock without cloning the version vec;
        // returns the first version that verifies.
        let try_unwrap = |aad: &[u8]| -> Option<(i32, Vec<u8>)> {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let versions = keys.get(&CircleKey::of(&target_id))?;
            if versions.is_empty() {
                return None;
            }
            let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
            sorted.sort_by(|a, b| b.0.cmp(a.0));
            for (version, circle_key) in sorted {
                if circle_key.len() != 32 {
                    continue;
                }
                let mut ck = Zeroizing::new([0u8; 32]);
                ck.copy_from_slice(circle_key);
                let cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice()).expect("32-byte key");
                let payload = chacha20poly1305::aead::Payload {
                    msg: wrapped_key_bytes.as_ref(),
                    aad,
                };
                if let Ok(bytes) = cipher.decrypt(&XNonce::from(wrap_nonce), payload) {
                    return Some((*version, bytes));
                }
            }
            None
        };

        // v2 wrap AAD (target-bound) first, then v1 empty AAD for rows written
        // without it.
        let wrap_v2 = msg_key_wrap_aad_v2(target_id);
        // SECURITY: Zeroizing so the unwrapped place_key heap Vec is wiped on drop.
        // The version that unwrapped it is the place's.
        let (key_version, place_key_bytes) = try_unwrap(&wrap_v2)
            .or_else(|| try_unwrap(b""))
            .ok_or(MobileError::DecryptionFailed)?;
        let place_key_bytes = Zeroizing::new(place_key_bytes);

        if place_key_bytes.len() != 32 {
            return Err(MobileError::CryptoError("Unwrapped place key has invalid length".to_string()));
        }

        let mut place_key = Zeroizing::new([0u8; 32]);
        place_key.copy_from_slice(&place_key_bytes);

        // Step 2: Decrypt the payload with the per-place key: v2 place-envelope
        // AAD first, then v1 empty AAD so ciphertext written with the v1 AAD
        // still decrypts. A total failure propagates (never surfaces plaintext).
        let enc = EncryptedData {
            nonce: ciphertext_nonce,
            ciphertext,
        };
        let payload_v2 = place_aad_v2();
        let plaintext_bytes = decrypt_raw_bytes_aad(&*place_key, &enc, &payload_v2)
            .or_else(|_| decrypt_raw_bytes_aad(&*place_key, &enc, b""))?;

        let plaintext = String::from_utf8(plaintext_bytes)
            .map_err(|_| MobileError::DecryptionFailed)?;

        Ok((key_version, plaintext))
    }


    /// Verify a circle-key wrap signature under `signer_hex`, trying BOTH signing
    /// domains (a wrap carries no discriminator): `circle_member_wrap`
    /// (create/join/invite) or `rotation_member_wrap` (rotation/member-eject
    /// re-wrap). The signed input binds the exact wrap content (circle, recipient,
    /// key_version, ephemeral, nonce, ciphertext), so a valid signature under
    /// EITHER domain proves `signer_hex` authored THIS wrap. Returns `Ok(true)`
    /// iff one domain verifies; `Ok(false)` on a well-formed-but-invalid signature.
    ///
    /// DELIBERATELY PRIVATE: it lives in this block, not the `#[uniffi::export]`
    /// one, so UniFFI does not put it on the FFI surface. Accepting EITHER domain
    /// is correct for `store_circle_key` (which genuinely cannot tell the two
    /// apart), but as an exported API it is a cross-domain verification oracle —
    /// an external caller reaching for "verify this wrap signature" would get a
    /// strictly weaker guarantee than the single-domain `verify_wrap` they meant.
    /// Keep it here; export `verify_wrap` for callers that know their domain.
    #[allow(clippy::too_many_arguments)]
    fn wrap_sig_verifies_either_domain(
        &self,
        signer_hex: &str,
        sig_hex: &str,
        sender_user_id: &str,
        recipient_user_id: &str,
        circle_id: &str,
        key_version: u32,
        ephemeral_pubkey_hex: &str,
        wrap_nonce_hex: &str,
        wrap_ciphertext_hex: &str,
    ) -> Result<bool, MobileError> {
        for domain in [DOMAIN_CIRCLE_MEMBER_WRAP, DOMAIN_ROTATION_MEMBER_WRAP] {
            let params = SignWrapParams {
                domain: domain.to_string(),
                sender_user_id: sender_user_id.to_string(),
                recipient_user_id: recipient_user_id.to_string(),
                circle_id: circle_id.to_string(),
                place_id: String::new(),
                key_version,
                ephemeral_pubkey_hex: ephemeral_pubkey_hex.to_string(),
                wrap_nonce_hex: wrap_nonce_hex.to_string(),
                wrap_ciphertext_hex: wrap_ciphertext_hex.to_string(),
            };
            if self.verify_wrap(signer_hex.to_string(), sig_hex.to_string(), params)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Derive an Argon2id key from (password, salt, kdf_params), or return a
    /// cached key from a prior call with identical (salt, params_hash).
    ///
    /// SECURITY: The cached key lives only in memory and is wiped on
    /// clear_all_keys() / clear_password_key_cache(). The hash of params
    /// (not the params themselves) is used as a cheap equality check.
    /// The password itself is NEVER cached.
    fn derive_or_cache_password_key(
        &self,
        password: &Zeroizing<String>,
        salt: &[u8],
        kdf_params: &KdfParams,
    ) -> Result<Zeroizing<[u8; 32]>, MobileError> {
        let params_hash = hash_kdf_params(kdf_params);
        // Bind the cache entry to the exact password. Without this, a key derived
        // from a correct password would be returned for a DIFFERENT password
        // sharing the same (salt, params) — making decrypt_with_password wrongly
        // "succeed" for a wrong password. Domain-separated, RAM-only, never the
        // password itself.
        let password_fingerprint =
            blake3::derive_key("pingolin.password_cache_fingerprint.v1", password.as_bytes());

        // Fast path: matching cached key (same password, salt, and params).
        if let Some(cached) = self.password_key_cache.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if cached.salt == salt
                && cached.params_hash == params_hash
                && cached.password_fingerprint == password_fingerprint
            {
                let mut copy = Zeroizing::new([0u8; 32]);
                copy.copy_from_slice(cached.key.as_ref());
                return Ok(copy);
            }
        }

        // Slow path: derive via Argon2id. libsodium's crypto_pwhash always uses
        // parallelism=1, so we must match regardless of what kdf_params says.
        let params = Params::new(
            kdf_params.memory_kib,
            kdf_params.iterations,
            1,
            Some(32),
        )
        .map_err(|e| MobileError::CryptoError(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password.as_bytes(), salt, derived_key.as_mut())
            .map_err(|e| MobileError::CryptoError(format!("Argon2 key derivation failed: {}", e)))?;

        // Update cache with a copy.
        let mut cache_key = Zeroizing::new([0u8; 32]);
        cache_key.copy_from_slice(derived_key.as_ref());
        *self.password_key_cache.write().unwrap_or_else(|e| e.into_inner()) =
            Some(CachedPasswordKey {
                salt: salt.to_vec(),
                params_hash,
                password_fingerprint,
                key: cache_key,
            });

        Ok(derived_key)
    }

    /// Wrap a msg_key with a circle/self key using XChaCha20-Poly1305.
    fn wrap_msg_key(
        &self,
        target_id: String,
        msg_key: &[u8; 32],
    ) -> Result<KeyWrap, MobileError> {
        // v1 path: empty AAD. Only `envelope_encrypt_location` uses this,
        // so its wraps stay byte-identical to the v1 form.
        self.wrap_msg_key_aad(target_id, msg_key, b"")
    }

    /// Wrap a msg_key for a target with an explicit AAD. `wrap_msg_key` passes
    /// an empty AAD (the v1 form, used by `envelope_encrypt_location`);
    /// `envelope_encrypt_location_v2` and `envelope_encrypt_place` pass
    /// `msg_key_wrap_aad_v2(target)` while `AAD_V2_WRITE_ENABLED` is set (else
    /// empty); `envelope_encrypt_location_bound` always passes it.
    fn wrap_msg_key_aad(
        &self,
        target_id: String,
        msg_key: &[u8; 32],
        aad: &[u8],
    ) -> Result<KeyWrap, MobileError> {
        let circle_key = self.get_active_circle_key(&target_id)?;

        if circle_key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&circle_key);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key");

        let nonce: [u8; 24] = generate_secure_nonce();
        let payload = chacha20poly1305::aead::Payload {
            msg: msg_key.as_ref(),
            aad,
        };
        let wrapped = cipher
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|_| MobileError::EncryptionFailed)?;

        Ok(KeyWrap {
            target_id,
            wrapped_key_nonce: hex::encode(nonce),
            wrapped_key: hex::encode(wrapped),
        })
    }

    /// Encrypt data with session key if available, otherwise circle key.
    ///
    /// SECURITY: Reads version and key atomically to prevent TOCTOU race during rotation.
    fn encrypt_with_session_or_circle_key(&self, circle_id: &str, plaintext: &[u8]) -> Result<SessionEncryptedData, MobileError> {
        // Legacy (v1, empty-AAD) form — all existing callers.
        self.encrypt_with_session_or_circle_key_aad(circle_id, plaintext, b"")
    }

    /// Session-or-circle encrypt with an explicit AAD. Shared body for the
    /// sender-bound path (`encrypt_location_with_session_key_bound` passes
    /// `location_aad_v3`); the empty-AAD wrapper above preserves every existing
    /// call site byte-for-byte. Only the AAD threaded into the AEAD differs.
    fn encrypt_with_session_or_circle_key_aad(&self, circle_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<SessionEncryptedData, MobileError> {
        // Try session key first — but only one published under the circle's
        // CURRENT key version. A session key is sealed under the circle key that
        // was active when it was minted, so after a rotation every holder of the
        // OLD key (a member the rotation removed, and the server that keeps the
        // published blob) could read everything this device kept sending under it
        // until it expired. A stale one is dropped here; the send falls back to
        // the circle key and `has_active_session_key` tells the app to mint a
        // fresh one.
        let active_version = self.sealing_version(circle_id);
        let mut stale = false;
        {
            let sender_keys = self.sender_session_keys.read().unwrap_or_else(|e| e.into_inner());
            if let Some(state) = sender_keys.get(&CircleKey::of(&circle_id)) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if Some(state.key_version) != active_version {
                    stale = true;
                } else if state.expires_at > now {
                    let encrypted = encrypt_with_raw_key_aad(&state.key, plaintext, aad)?;
                    let key_id = format!("s:{}", state.session_key_id);
                    return Ok(SessionEncryptedData { encrypted, key_id });
                }
            }
        }
        if stale {
            let mut sender_keys = self.sender_session_keys.write().unwrap_or_else(|e| e.into_inner());
            if sender_keys.get(&CircleKey::of(&circle_id)).map_or(false, |s| Some(s.key_version) != active_version) {
                sender_keys.remove(&CircleKey::of(&circle_id));
                tracing::info!("Dropped a session key minted under an older key version of circle {}", circle_id);
            }
        }

        // Fallback to circle key — read version and key atomically
        let (version, circle_key) = self.get_active_circle_key_with_version(circle_id)?;
        let encrypted = encrypt_with_raw_key_aad(&circle_key, plaintext, aad)?;
        Ok(SessionEncryptedData { encrypted, key_id: format!("c:{}", version) })
    }

    /// Get the active (highest version) circle key for a circle
    fn get_active_circle_key(&self, circle_id: &str) -> Result<Zeroizing<Vec<u8>>, MobileError> {
        let (_version, key) = self.get_active_circle_key_with_version(circle_id)?;
        Ok(key)
    }

    /// Evict expired peer session keys from the cache.
    /// Called during insert operations to keep the cache bounded.
    fn evict_expired_peer_keys(cache: &mut PeerSessionKeys) {
        let now = current_unix_secs();
        let cutoff = now - PEER_KEY_EXPIRY_GRACE_SECS;
        let before = cache.len();
        cache.retain(|_, v| v.expires_at > cutoff);
        let evicted = before - cache.len();
        if evicted > 0 {
            tracing::debug!("Evicted {} expired peer session keys", evicted);
        }
    }

    /// Enforce the bound on the peer session key cache. Prefers evicting an
    /// already-expired entry; otherwise evicts the least-recently-used entry
    /// and logs a warning so the eviction of a non-expired key is observable.
    fn enforce_peer_cache_bound(cache: &mut PeerSessionKeys) {
        if cache.len() < MAX_PEER_SESSION_KEYS {
            return;
        }
        let now = current_unix_secs();
        let expired_id = cache.iter()
            .find(|(_, v)| v.expires_at < now)
            .map(|(k, _)| k.clone());

        if let Some(id) = expired_id {
            cache.remove(&id);
            return;
        }

        // No expired entries — evict the least-recently-used one.
        if let Some(lru_id) = cache.iter()
            .min_by_key(|(_, v)| v.last_used_at.load(Ordering::Relaxed))
            .map(|(k, _)| k.clone())
        {
            tracing::warn!(
                "Peer session key cache full ({} keys), evicting non-expired LRU entry",
                cache.len()
            );
            cache.remove(&lru_id);
        }
    }

    /// Get the active circle key AND its version consistently.
    ///
    /// SAFETY: Two separate locks are acquired (active_key_version then circle_keys).
    /// A rotation between the two reads could bump active_key_version from N to N+1.
    /// Old key versions are retained (capped at MAX_CIRCLE_KEY_VERSIONS, with only the
    /// OLDEST evicted+zeroized on rotation; all cleared on logout), so the version that
    /// was active a moment ago is still present after a rotation — fetching version N
    /// after a rotation to N+1 still succeeds. The returned (version, key) pair is
    /// self-consistent.
    fn get_active_circle_key_with_version(&self, circle_id: &str) -> Result<(i32, Zeroizing<Vec<u8>>), MobileError> {
        let version = self
            .sealing_version(circle_id)
            .ok_or_else(|| MobileError::KeyNotFound(format!("No active key version for circle: {}", circle_id)))?;

        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        let key = keys.get(&CircleKey::of(&circle_id))
            .and_then(|versions| versions.get(&version))
            .cloned()
            .ok_or_else(|| MobileError::KeyNotFound(
                format!("Circle key not found: {} v{}", circle_id, version)
            ))?;
        Ok((version, key))
    }

    /// The single reader of `peer_session_keys`.
    ///
    /// Accepts EITHER id form and resolves both to the same cache entry:
    ///  - the row's routing form `"s:{uuid}"` (what `key_id` carries on the wire —
    ///    see `encrypt_with_session_or_circle_key`), and
    ///  - the server's bare `session_key_id`, which is how the cache is actually
    ///    keyed: `import_peer_session_key` and `create_session_key` both insert
    ///    under whatever id the server issued, verbatim.
    ///
    /// Touches `last_used_at` on a hit (feeding the LRU bound in
    /// `enforce_peer_cache_bound`) before handing the entry to `f`. Expiry is
    /// deliberately NOT applied here: the pre-check wants the grace window,
    /// the decrypt resolver wants whatever survived eviction. Callers decide.
    ///
    /// Both `has_peer_session_key` and `resolve_decryption_key` go through here
    /// so the pre-check and the resolver can never disagree about the prefix: a
    /// pre-check answering false for every row-shaped id would make track-ios —
    /// which GATES the decrypt on it — drop every session-key row as "we never
    /// had the key".
    ///
    /// Only the key held for `circle_id` under that id.
    fn with_peer_session_key<T>(
        &self,
        circle_id: &str,
        session_key_id: &str,
        f: impl FnOnce(&CachedPeerSessionKey) -> T,
    ) -> Option<T> {
        let peer_keys = self.peer_session_keys.read().unwrap_or_else(|e| e.into_inner());
        peer_keys.get(&session_cache_key(circle_id, session_key_id)).map(|cached| {
            cached.last_used_at.store(current_unix_secs(), Ordering::Relaxed);
            f(cached)
        })
    }

    /// Get a specific version of a circle key
    fn get_circle_key_version(&self, circle_id: &str, version: i32) -> Result<Zeroizing<Vec<u8>>, MobileError> {
        let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
        keys.get(&CircleKey::of(&circle_id))
            .and_then(|versions| versions.get(&version))
            .cloned()
            .ok_or_else(|| MobileError::KeyNotFound(
                format!("Circle key not found: {} v{}", circle_id, version)
            ))
    }

    /// Resolve a key_id string to the appropriate decryption key
    ///
    /// "s:{uuid}" → session key from peer cache
    /// "c:{version}" → circle key at that version (current format)
    /// integer → circle key at that version (backward compat)
    /// "v1" → circle key version 1 (legacy)
    fn resolve_decryption_key(&self, circle_id: &str, key_id: &str) -> Result<Zeroizing<Vec<u8>>, MobileError> {
        self.resolve_decryption_key_opened(circle_id, key_id).map(|(_version, key)| key)
    }

    /// `resolve_decryption_key`, with the circle-key version the key stands
    /// for: a session key's, the one it was opened under; else the version the
    /// key id names.
    fn resolve_decryption_key_opened(&self, circle_id: &str, key_id: &str) -> Result<(i32, Zeroizing<Vec<u8>>), MobileError> {
        if let Some(bare_session_key_id) = key_id.strip_prefix("s:") {
            // Session key lookup from peer cache: only the key THIS circle holds
            // under that id. The prefix is stripped here only to ROUTE (and to
            // name the id in the error); the cache read itself goes through the
            // shared `with_peer_session_key`, which normalises again — so this
            // resolver and the `has_peer_session_key_for` pre-check apply one
            // rule, not two copies of it.
            self.with_peer_session_key(circle_id, key_id, |cached| (cached.key_version, cached.key.clone()))
                .ok_or_else(|| MobileError::SessionKeyNotFound(bare_session_key_id.to_string()))
        } else if let Some(version_str) = key_id.strip_prefix("c:") {
            // Circle key with explicit prefix (current format)
            let version: i32 = version_str.parse()
                .map_err(|_| MobileError::InvalidInput(format!("Invalid circle key version in key_id: {}", key_id)))?;
            Ok((version, self.get_circle_key_version(circle_id, version)?))
        } else if key_id == "v1" {
            // Legacy format
            Ok((1, self.get_circle_key_version(circle_id, 1)?))
        } else {
            // Plain integer version — backward compat for existing data
            let version: i32 = key_id.parse()
                .map_err(|_| MobileError::InvalidInput(format!("Invalid key_id format: {}", key_id)))?;
            Ok((version, self.get_circle_key_version(circle_id, version)?))
        }
    }

    /// Internal helper for the wrap-sign call sites: builds the params and
    /// signs them under our Ed25519 signing key, returning the hex signature.
    /// Returns an error (typically `KeyNotFound`) if no signing key is loaded;
    /// callers map that to "" on the legacy grace path.
    ///
    /// Inputs are passed pre-decoded (raw bytes, integer version) to avoid
    /// re-doing hex round-trips on hot paths.
    #[allow(clippy::too_many_arguments)]
    fn sign_wrap_internal(
        &self,
        domain: &str,
        sender_user_id: &str,
        recipient_user_id: &str,
        circle_id: &str,
        place_id: &str,
        key_version: u32,
        ephemeral_pubkey: Option<&[u8]>,
        wrap_nonce: &[u8],
        wrap_ciphertext: &[u8],
    ) -> Result<String, MobileError> {
        let params = SignWrapParams {
            domain: domain.to_string(),
            sender_user_id: sender_user_id.to_string(),
            recipient_user_id: recipient_user_id.to_string(),
            circle_id: circle_id.to_string(),
            place_id: place_id.to_string(),
            key_version,
            ephemeral_pubkey_hex: ephemeral_pubkey.map(hex::encode).unwrap_or_default(),
            wrap_nonce_hex: hex::encode(wrap_nonce),
            wrap_ciphertext_hex: hex::encode(wrap_ciphertext),
        };
        self.sign_wrap_unchecked(params)
    }
}

// ============================================================================
// Standalone encryption helpers (not CryptoManager methods)
// ============================================================================

/// AAD domain-separation tags for place crypto. Bound into the
/// AEAD authentication so a wrap or ciphertext from one context can't
/// be reinterpreted as a different one even if an attacker swaps blobs
/// between table rows or message types.
const AAD_PLACE_KEY_WRAP: &[u8] = b"pingolin/v1/place_key";
const AAD_PLACE_FIELD: &[u8] = b"pingolin/v1/place_field";

// ── AAD v2: context-bound ciphertext ────────────────────────────────────────
// Writes are v2-bound; decrypt tries the v2 AAD and falls back to v1 so v1
// ciphertext still reads. The flag exists because a v2 ciphertext is
// undecryptable by a client that cannot read v2 (silent data loss): it may
// be on only while every client reads v2, and turning it off makes writes
// v1 again.
const AAD_V2_WRITE_ENABLED: bool = true;

// ── Packed location plaintext ───────────────────────────────────────────────
// The bytes sealed on a location write. `false` keeps writing the legacy JSON
// document; `true` writes the packed binary form from `location_codec`. Readers
// accept BOTH regardless of this flag, so flipping it back off is the rollback
// lever — exactly like AAD_V2_WRITE_ENABLED above.
//
// This changes ONLY the plaintext bytes. No key, no nonce, no AAD, and no AEAD
// choice is affected by it.
const PACKED_LOCATION_WRITE_ENABLED: bool = true;

/// The plaintext bytes for a location write: packed when
/// `PACKED_LOCATION_WRITE_ENABLED`, legacy JSON otherwise. Every location
/// encryptor in this file goes through here, so the two forms can never diverge
/// between call sites.
fn location_plaintext(location: &Location) -> Result<Vec<u8>, MobileError> {
    if PACKED_LOCATION_WRITE_ENABLED {
        encode_location(location)
    } else {
        Ok(serde_json::to_vec(location)?)
    }
}

/// Deterministic length-prefixed TLV, hashed to 32 bytes with per-payload
/// domain separation. MUST stay byte-identical to the web client's JavaScript
/// implementation and to note-collab-sdk's note_content variant — a
/// mismatch makes a v2 ciphertext unreadable on the other client. Layout:
///   LP(container) || u32_le(key_version) || LP(id) || LP(extra)
/// where LP(x) = u16_le(len) || bytes.
fn aad_v2_context(domain: &[u8], container: &str, key_version: u32, id: &str, extra: &str) -> [u8; 32] {
    fn lp(buf: &mut Vec<u8>, s: &str) {
        let b = s.as_bytes();
        buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
        buf.extend_from_slice(b);
    }
    let mut input: Vec<u8> = Vec::new();
    lp(&mut input, container);
    input.extend_from_slice(&key_version.to_le_bytes());
    lp(&mut input, id);
    lp(&mut input, extra);
    let context_key = blake3::derive_key("pingolin.aad.v2.context", domain);
    *blake3::keyed_hash(&context_key, &input).as_bytes()
}

/// Place-field AAD v2. The per-place key already separates places, so the
/// exploitable residue under a single place key is FIELD confusion (a server
/// swapping e.g. encrypted_name with encrypted_location). We bind the
/// immutable field tag (name/location/address/notes/…) — NOT place_id, which
/// isn't assigned yet when a new place's fields are first encrypted. container
/// and id stay empty; the field tag goes in `extra`.
fn place_field_aad_v2(field_tag: &str) -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v2.place", "", 0, "", field_tag)
}

/// Circle-field AAD v2 — binds a circle-key ciphertext to its circle and to
/// the immutable field it represents (alert name, timestamp, userId, deviceId,
/// eventType, …). A different circle already uses a different key, so the
/// residual gaps under one circle key are cross-circle relabelling and FIELD
/// confusion; circle_id (container) + field_tag (extra) close both. key_version
/// is fixed at 0: the key is already version-specific, so a per-version AAD
/// would only complicate decrypt (which tries every version with one AAD).
fn circle_field_aad_v2(circle_id: &str, field_tag: &str) -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v2.circle_field", circle_id, 0, "", field_tag)
}

/// WRITE-side AAD for a circle field. The circle NAME is bound FIELD-ONLY
/// (empty circle_id, like `place_field_aad_v2`) ONLY when it is sealed during
/// circle CREATION — i.e. under a throwaway `temp_<nonce>` circle id, before the
/// server assigns the real id (`finalize_circle_creation` remaps the key but
/// can't re-seal, so an id-bound AAD would never match after temp→real).
/// EVERY other write stays id-bound — including PLACE names
/// (tag "name" under a REAL circle id) and circle RENAMES — otherwise existing
/// place names stop decrypting and their geofence alerts stop firing. Real
/// circle UUIDs can never start with "temp_" (not valid hex), so the prefix
/// cleanly distinguishes a circle-create name from everything else. The web
/// client mirrors this routing byte-for-byte.
fn circle_field_write_aad_v2(circle_id: &str, field_tag: &str) -> [u8; 32] {
    if field_tag == "name" && circle_id.starts_with("temp_") {
        circle_field_aad_v2("", field_tag)
    } else {
        circle_field_aad_v2(circle_id, field_tag)
    }
}

/// READ-side candidate AADs, tried in order (then the v1 empty-AAD fallback).
/// For tag "name" we accept BOTH the field-only form (circle names created under
/// a temp id, or any client that wrote field-only) AND the id-bound form (place
/// names, circle renames, and any "name" sealed id-bound by an older client)
/// — so no generation of "name" ciphertext is left unreadable. All other
/// fields are id-bound only.
fn circle_field_read_aads_v2(circle_id: &str, field_tag: &str) -> Vec<[u8; 32]> {
    if field_tag == "name" {
        vec![
            circle_field_aad_v2("", field_tag),
            circle_field_aad_v2(circle_id, field_tag),
        ]
    } else {
        vec![circle_field_aad_v2(circle_id, field_tag)]
    }
}

/// `user_id`'s pseudonym under `key` (lower-case), as `derive_user_pseudonym`
/// computes it for the key in use.
fn user_pseudonym_for_key(key: &[u8], user_id: &str) -> Option<String> {
    let key = pingolin_crypto::keys::SymmetricKey::try_from_slice(key).ok()?;
    Some(pingolin_crypto::privacy::derive_user_pseudonym(&key, user_id).to_ascii_lowercase())
}

/// Whether `key` opens `sealed` the way `decrypt_data_v2(circle_id, _, "name")`
/// reads a circle name: the v2 name AADs, then the v1 empty AAD.
fn key_opens_circle_name(key: &[u8], circle_id: &str, sealed: &EncryptedData) -> bool {
    circle_field_read_aads_v2(circle_id, "name")
        .iter()
        .any(|aad| decrypt_raw_bytes_aad(key, sealed, aad).is_ok())
        || decrypt_raw_bytes_aad(key, sealed, b"").is_ok()
}

/// Location-envelope payload AAD v2. The per-message msg_key is random and
/// never reused (`generate_secure_nonce()` per call), so a swapped
/// (wrap, payload) pair already fails at the payload AEAD — the msg_key won't
/// match. The residual belt-and-suspenders gap is cross-payload-KIND confusion
/// should two payload types ever share a key derivation; a domain-only AAD
/// closes it. No stable per-location id exists at encrypt time (the row id is
/// server-assigned), so container/id/extra stay empty — the domain separation
/// IS the binding.
fn location_aad_v2() -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v2.location", "", 0, "", "")
}

/// Place-envelope payload AAD v2. The monolithic mirror of `location_aad_v2` for
/// the `envelope_encrypt_place` path (a per-place key encrypts the whole place
/// blob ONCE, then is wrapped per target). The per-place key is random and never
/// reused, so a swapped (wrap, payload) pair already fails at the payload AEAD;
/// the residual belt-and-suspenders gap is cross-payload-KIND confusion. A
/// DISTINCT domain — `pingolin.aad.v2.place_envelope`, deliberately NOT the
/// `pingolin.aad.v2.place` used by `place_field_aad_v2` (the per-FIELD place path)
/// and NOT `pingolin.aad.v2.location` — guarantees a place blob can never be
/// opened as a location blob (or a place FIELD, or vice-versa) even if both were
/// ever wrapped under the same circle key. No stable per-place id exists at
/// encrypt time (row id is server-assigned), so container/id/extra stay empty —
/// the domain separation IS the binding. The web/iOS/Android clients mirror this
/// byte-for-byte; the LOCKED vector is asserted in
/// `place_envelope_aad_v2_cross_language_vector`.
fn place_aad_v2() -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v2.place_envelope", "", 0, "", "")
}

/// Location payload AAD v3 (sender-binding). Same framing as `location_aad_v2`
/// but ALSO binds the SENDER's per-circle USER pseudonym into the container
/// slot — mirroring how `msg_key_wrap_aad_v2` binds target_id. The `Location`
/// payload itself carries no sender id, so a malicious server can serve member
/// A's ciphertext under member B's pseudonym and clients mislabel it (under v2
/// confidentiality holds — the tag verifies — but the ATTRIBUTION is
/// forgeable). Attribution is by USER: the reader derives the claimed pseudonym
/// from the user_id it resolves the row to (`derive_user_pseudonym`) and the
/// sender binds its own, so any relabel fails the AEAD tag —
/// `decrypt_location_bound` verifies the claimed pseudonym on read.
/// key_version/id/extra stay 0/empty. The web + mobile clients mirror this
/// byte-for-byte — the LOCKED vector for USER pseudonym "testpseudo123" is
/// asserted (and printed) in `location_aad_v3_cross_language_vector`.
fn location_aad_v3(sender_pseudonym: &str) -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v3.location", sender_pseudonym, 0, "", "")
}

/// Msg-key-wrap AAD v2 — binds a wrapped msg_key to the target it was wrapped
/// for. The wrap is ALREADY target-bound by the circle key (a cross-target
/// relabel fails to unwrap) and the random msg_key already binds wrap↔payload,
/// so this mainly adds domain separation and fails a relabel one step earlier
/// (at unwrap rather than at payload decrypt). target_id goes in the container;
/// key_version stays 0 (decrypt tries every circle-key version with one AAD).
fn msg_key_wrap_aad_v2(target_id: &str) -> [u8; 32] {
    aad_v2_context(b"pingolin.aad.v2.msg_key_wrap", target_id, 0, "", "")
}

/// Convert a UUID string (any canonical hex form: with or without hyphens) to
/// its 16-byte big-endian representation, as required by the sig_input layout.
fn uuid_to_16_bytes(uuid_str: &str) -> Result<[u8; 16], MobileError> {
    // Accept hyphenated, unhyphenated, and braced forms — the standard
    // `uuid::Uuid::parse_str` handles all three.
    let parsed = uuid::Uuid::parse_str(uuid_str)
        .map_err(|e| MobileError::InvalidInput(format!("Invalid UUID '{}': {}", uuid_str, e)))?;
    Ok(*parsed.as_bytes())
}

/// Compute the 32-byte BLAKE3 keyed-hash digest used as Ed25519 input for the
/// `pingolin.sig.v1.*` wrap-signature scheme.
///
/// The wire format is locked: the layout below must match the corresponding
/// TypeScript implementation in the web client. Any change here will silently
/// desync verification across platforms.
///
/// Wire layout (the tag/length-prefixed message that goes into keyed_hash):
/// ```text
///   u8(LEN(sender_user_id))    || sender_user_id_bytes      // 16
///   u8(LEN(recipient_user_id)) || recipient_user_id_bytes   // 16 or 0
///   u8(LEN(circle_id))         || circle_id_bytes           // 16 or 0
///   u8(LEN(place_id))          || place_id_bytes            // 16 or 0
///   u32_le(key_version)                                     // 4 (always)
///   u8(LEN(ephemeral_pubkey))  || ephemeral_pubkey_bytes    // 32 or 0
///   u8(LEN(wrap_nonce))        || wrap_nonce_bytes          // 24
///   u8(LEN(wrap_ciphertext))   || wrap_ciphertext_bytes     // 48
/// ```
fn compute_sig_input(params: &SignWrapParams) -> Result<blake3::Hash, MobileError> {
    // Derive the per-domain context key from the locked DOMAIN string.
    let context_key = blake3::derive_key("pingolin.sig.v1.context_key", params.domain.as_bytes());

    // Required fields.
    let sender_uuid = uuid_to_16_bytes(&params.sender_user_id)?;

    // Optional UUID fields — empty string → length 0, no bytes.
    let recipient_uuid: Option<[u8; 16]> = if params.recipient_user_id.is_empty() {
        None
    } else {
        Some(uuid_to_16_bytes(&params.recipient_user_id)?)
    };
    let circle_uuid: Option<[u8; 16]> = if params.circle_id.is_empty() {
        None
    } else {
        Some(uuid_to_16_bytes(&params.circle_id)?)
    };
    let place_uuid: Option<[u8; 16]> = if params.place_id.is_empty() {
        None
    } else {
        Some(uuid_to_16_bytes(&params.place_id)?)
    };

    let ephemeral_bytes: Option<Vec<u8>> = if params.ephemeral_pubkey_hex.is_empty() {
        None
    } else {
        let bytes = hex::decode(&params.ephemeral_pubkey_hex)?;
        if bytes.len() != 32 {
            return Err(MobileError::InvalidInput(format!(
                "ephemeral_pubkey must be 32 bytes (got {})",
                bytes.len()
            )));
        }
        Some(bytes)
    };

    let wrap_nonce_bytes = hex::decode(&params.wrap_nonce_hex)?;
    if wrap_nonce_bytes.len() != 24 {
        return Err(MobileError::InvalidInput(format!(
            "wrap_nonce must be 24 bytes (got {})",
            wrap_nonce_bytes.len()
        )));
    }

    let wrap_ciphertext_bytes = hex::decode(&params.wrap_ciphertext_hex)?;
    if wrap_ciphertext_bytes.len() != 48 {
        return Err(MobileError::InvalidInput(format!(
            "wrap_ciphertext must be 48 bytes (msg key 32B + AEAD tag 16B; got {})",
            wrap_ciphertext_bytes.len()
        )));
    }

    // Helper: append `u8(len)` then `bytes` (or just `u8(0)` if `None`).
    fn push_lp(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
        match bytes {
            Some(b) => {
                debug_assert!(b.len() <= u8::MAX as usize, "all sig fields must fit in u8 length prefix");
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
            None => out.push(0),
        }
    }

    let mut msg: Vec<u8> = Vec::with_capacity(
        1 + 16   // sender
      + 1 + 16  // recipient
      + 1 + 16  // circle
      + 1 + 16  // place
      + 4       // key_version
      + 1 + 32  // ephemeral
      + 1 + 24  // wrap_nonce
      + 1 + 48, // wrap_ciphertext
    );
    push_lp(&mut msg, Some(&sender_uuid));
    push_lp(&mut msg, recipient_uuid.as_ref().map(|x| &x[..]));
    push_lp(&mut msg, circle_uuid.as_ref().map(|x| &x[..]));
    push_lp(&mut msg, place_uuid.as_ref().map(|x| &x[..]));
    msg.extend_from_slice(&params.key_version.to_le_bytes());
    push_lp(&mut msg, ephemeral_bytes.as_deref());
    push_lp(&mut msg, Some(&wrap_nonce_bytes));
    push_lp(&mut msg, Some(&wrap_ciphertext_bytes));

    Ok(blake3::keyed_hash(&context_key, &msg))
}

/// Encrypt plaintext bytes with a raw 32-byte key, return hex-encoded EncryptedData.
/// Wraps `encrypt_with_raw_key_aad` with empty AAD for backward compatibility
/// with all existing call sites — locations, alerts, session keys, etc.
fn encrypt_with_raw_key(key: &[u8], plaintext: &[u8]) -> Result<EncryptedData, MobileError> {
    encrypt_with_raw_key_aad(key, plaintext, b"")
}

/// Seal under a given circle key as `encrypt_data_v2` does (field "test"): for
/// tests that check which keys a device reads with.
#[cfg(test)]
pub(crate) fn encrypt_for_tests(key: &[u8; 32], circle_id: &str, plaintext: &[u8]) -> EncryptedData {
    encrypt_with_raw_key_aad(key, plaintext, &circle_field_write_aad_v2(circle_id, "test")).unwrap()
}

/// The portal's blob for a recovered identity, sealed for the account's
/// CURRENT identity as the tests in this file seal it: v2 (its private key ‖
/// its signing public key) with `signing`, else v1 (the private key alone).
/// For the refresh-record tests of the recovered pre-reset pairs
/// (`OwnRestored`).
#[cfg(test)]
pub(crate) fn seal_previous_identity_for_tests(identity: &StaticSecret, signing: Option<&[u8; 32]>, current: &StaticSecret) -> SealedPreviousIdentity {
    use crypto_secretbox::aead::{Aead, KeyInit};
    let engine = base64::engine::general_purpose::STANDARD;
    let wrap = blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity");
    let nonce = [9u8; 24];
    let plain = [identity.to_bytes().as_slice(), signing.map_or(&[][..], |s| s.as_slice())].concat();
    let ciphertext = XSalsa20Poly1305::new_from_slice(&wrap)
        .unwrap()
        .encrypt(SalsaNonce::from_slice(&nonce), plain.as_slice())
        .unwrap();
    SealedPreviousIdentity { nonce: base64::Engine::encode(&engine, nonce), ciphertext: base64::Engine::encode(&engine, ciphertext) }
}

/// Encrypt plaintext bytes with a raw 32-byte key + AAD domain-separation tag.
/// AEAD tag verification on decrypt fails if the AAD doesn't match, providing
/// hard cross-context-reuse protection. Used by place_key wraps and
/// place-field encryption to ensure their ciphertexts can't be substituted
/// for one another or for unrelated wraps under the same circle key.
fn encrypt_with_raw_key_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData, MobileError> {
    if key.len() != 32 {
        return Err(MobileError::InvalidKey);
    }
    let mut zk = Zeroizing::new([0u8; 32]);
    zk.copy_from_slice(key);
    let cipher = XChaCha20Poly1305::new_from_slice(zk.as_slice()).expect("32-byte key");
    let nonce: [u8; 24] = generate_secure_nonce();
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), payload)
        .map_err(|_| MobileError::EncryptionFailed)?;
    Ok(EncryptedData {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Decrypt hex-encoded EncryptedData with a raw 32-byte key, return plaintext string
fn decrypt_with_raw_key(key: &[u8], encrypted_data: &EncryptedData) -> Result<String, MobileError> {
    let bytes = decrypt_raw_bytes(key, encrypted_data)?;
    String::from_utf8(bytes).map_err(|_| MobileError::DecryptionFailed)
}

/// Encrypt raw bytes with a 32-byte key, return hex-encoded EncryptedData
fn encrypt_raw_bytes(key: &[u8], plaintext: &[u8]) -> Result<EncryptedData, MobileError> {
    encrypt_with_raw_key(key, plaintext)
}

/// Decrypt hex-encoded EncryptedData with a raw 32-byte key, return raw bytes.
/// Wraps `decrypt_raw_bytes_aad` with empty AAD for backward compatibility.
fn decrypt_raw_bytes(key: &[u8], encrypted_data: &EncryptedData) -> Result<Vec<u8>, MobileError> {
    decrypt_raw_bytes_aad(key, encrypted_data, b"")
}

/// Try-each-version decrypt for AAD-bound payloads. Iterates the
/// requested target's keys under a single read-lock without cloning
/// each one upfront: a clone-per-version widens the zeroization window
/// for the legitimate keys and adds a malloc per decrypt for no benefit,
/// since the lock is held for the same total time either way. Tag
/// verification fails the whole decrypt if the AAD doesn't match the
/// value used at encrypt time.
fn decrypt_raw_bytes_aad_with_versions(
    circle_keys: &std::sync::Arc<
        std::sync::RwLock<
            std::collections::HashMap<CircleKey, std::collections::HashMap<i32, Zeroizing<Vec<u8>>>>,
        >,
    >,
    target_id: &str,
    encrypted_data: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>, MobileError> {
    open_with_versions(circle_keys, target_id, encrypted_data, aad).map(|(_version, plain)| plain)
}

/// `decrypt_raw_bytes_aad_with_versions`, with the version whose key opened
/// it: a retired version opens history only, never anything current.
fn open_with_versions(
    circle_keys: &std::sync::Arc<
        std::sync::RwLock<
            std::collections::HashMap<CircleKey, std::collections::HashMap<i32, Zeroizing<Vec<u8>>>>,
        >,
    >,
    target_id: &str,
    encrypted_data: &EncryptedData,
    aad: &[u8],
) -> Result<(i32, Vec<u8>), MobileError> {
    let nonce_bytes = decode_flexible(&encrypted_data.nonce)?;
    if nonce_bytes.len() != 24 {
        return Err(MobileError::DecryptionFailed);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let ciphertext_bytes = decode_flexible(&encrypted_data.ciphertext)?;

    let keys = circle_keys.read().unwrap_or_else(|e| e.into_inner());
    let versions = match keys.get(&CircleKey::of(target_id)) {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Err(MobileError::KeyNotFound(format!(
                "No keys for target: {}",
                target_id
            )));
        }
    };

    // Iterate newest-first under the read lock — no cloning. Lock
    // hold is bounded by the number of versions and the cipher init
    // cost is trivial. HashMap doesn't iterate in a defined order,
    // so we collect-and-sort by version desc first; this only
    // allocates a Vec of (i32, &Zeroizing) refs, not the keys
    // themselves.
    let mut sorted: Vec<(&i32, &Zeroizing<Vec<u8>>)> = versions.iter().collect();
    sorted.sort_by(|a, b| b.0.cmp(a.0));
    for (version, key) in sorted.iter() {
        if key.len() != 32 {
            continue;
        }
        // Convert &Vec<u8> → &[u8;32] → &Key. Length already checked above.
        let key_array: &[u8; 32] = match (&***key).as_slice().try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let cipher = XChaCha20Poly1305::new(key_array.into());
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext_bytes.as_ref(),
            aad,
        };
        if let Ok(plain) = cipher.decrypt(&XNonce::from(nonce), payload) {
            return Ok((**version, plain));
        }
    }
    Err(MobileError::DecryptionFailed)
}

/// Decrypt hex-encoded EncryptedData with a raw 32-byte key + AAD. AEAD
/// tag verification fails closed if the AAD doesn't match the value used
/// at encrypt time, refusing to surface plaintext.
fn decrypt_raw_bytes_aad(key: &[u8], encrypted_data: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>, MobileError> {
    if key.len() != 32 {
        return Err(MobileError::InvalidKey);
    }
    let mut zk = Zeroizing::new([0u8; 32]);
    zk.copy_from_slice(key);
    let cipher = XChaCha20Poly1305::new_from_slice(zk.as_slice()).expect("32-byte key");

    let nonce_bytes = decode_flexible(&encrypted_data.nonce)?;
    let ciphertext_bytes = decode_flexible(&encrypted_data.ciphertext)?;

    if nonce_bytes.len() != 24 {
        return Err(MobileError::DecryptionFailed);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);

    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext_bytes.as_ref(),
        aad,
    };
    cipher
        .decrypt(&XNonce::from(nonce), payload)
        .map_err(|_| MobileError::DecryptionFailed)
}

/// Cross-rotation helper. Tries the v3 sender-bound payload for ONE
/// (decrypt_key, pseudonym_source_key) pair: derives the user pseudonym from
/// `pseudonym_key`, builds `location_aad_v3(pseudonym)`, and AEAD-opens `enc`
/// under `decrypt_key`. Returns:
///   Some(Ok(location))  — AEAD verified + plaintext decoded (authentic → commit)
///   Some(Err(e))        — AEAD verified but the decode failed (real error → commit)
///   None                — AEAD tag miss under this pseudonym (try next version)
/// Separating decrypt_key from pseudonym_key lets the session-key and envelope
/// paths keep a FIXED decrypt key (resolved session key / unwrapped msg_key)
/// while varying the pseudonym across circle-key versions.
fn try_v3_location_payload(
    decrypt_key: &[u8],
    enc: &EncryptedData,
    pseudonym_key: &[u8],
    user_id: &str,
) -> Option<Result<Location, MobileError>> {
    let sk = pingolin_crypto::keys::SymmetricKey::try_from_slice(pseudonym_key).ok()?;
    let pseudonym = pingolin_crypto::privacy::derive_user_pseudonym(&sk, user_id);
    let aad = location_aad_v3(&pseudonym);
    match decrypt_raw_bytes_aad(decrypt_key, enc, &aad) {
        Ok(bytes) => Some(decode_location(&bytes)),
        Err(_) => None,
    }
}

/// Helper: Get day of week name from timestamp
fn get_day_of_week(timestamp_ms: i64, _timezone: Option<&str>) -> String {
    // UTC day of week: the timezone argument is not applied.
    let secs = timestamp_ms / 1000;
    // Days since Unix epoch (Thursday Jan 1, 1970)
    let days = (secs / 86400 + 4) % 7; // +4 because epoch was Thursday
    match days {
        0 => "sunday",
        1 => "monday",
        2 => "tuesday",
        3 => "wednesday",
        4 => "thursday",
        5 => "friday",
        6 => "saturday",
        _ => "unknown",
    }.to_string()
}

/// Helper: Check if current time is within a time window
fn is_within_time_window(
    current_time_ms: i64,
    start_time: &str,
    end_time: &str,
    _timezone: Option<&str>,
) -> bool {
    // Parse times (HH:MM format)
    let parse_time = |s: &str| -> Option<(u32, u32)> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() >= 2 {
            let hours = parts[0].parse().ok()?;
            let minutes = parts[1].parse().ok()?;
            Some((hours, minutes))
        } else {
            None
        }
    };

    let (start_h, start_m) = match parse_time(start_time) {
        Some(t) => t,
        None => return true, // Invalid format, allow
    };
    let (end_h, end_m) = match parse_time(end_time) {
        Some(t) => t,
        None => return true, // Invalid format, allow
    };

    // Current hour/minute in UTC (the timezone is not applied)
    let secs_since_midnight = (current_time_ms / 1000) % 86400;
    let current_h = (secs_since_midnight / 3600) as u32;
    let current_m = ((secs_since_midnight % 3600) / 60) as u32;

    let current_mins = current_h * 60 + current_m;
    let start_mins = start_h * 60 + start_m;
    let end_mins = end_h * 60 + end_m;

    if start_mins <= end_mins {
        // Normal range (e.g., 08:00 - 17:00)
        current_mins >= start_mins && current_mins <= end_mins
    } else {
        // Overnight range (e.g., 22:00 - 06:00)
        current_mins >= start_mins || current_mins <= end_mins
    }
}

/// Decode a string that might be hex or base64 encoded.
///
/// # Why dual-format support exists
/// The server returns hex-encoded nonces and ciphertexts, while the
/// mobile SDK's own encryption functions produce base64-encoded output. During key
/// wrapping and location decryption, both formats must be accepted. Some hex strings
/// are also valid base64 (e.g. "deadbeef" decodes as both), so we disambiguate by
/// preferring the decoding that produces a cryptographically valid length (24 bytes
/// for XChaCha20-Poly1305 nonces, 32 bytes for keys).
///
/// # Callers must still validate lengths
/// This function only decodes; callers check the returned Vec length against expected
/// crypto sizes (see the `!= 24` / `!= 32` guards at each call site).
fn decode_flexible(input: &str) -> Result<Vec<u8>, MobileError> {
    // Try both decodings and pick the one that produces a crypto-valid length.
    // Server returns hex-encoded data; SDK uses base64. Some hex strings are
    // also valid base64, producing wrong byte counts.
    let is_crypto_len = |n: usize| n == 24 || n == 32;
    let looks_hex = input.len() % 2 == 0
        && input.len() >= 2
        && input.chars().all(|c| c.is_ascii_hexdigit());

    // Hex-looking inputs (server data) are tried first. When hex yields a
    // crypto-valid length we return it directly — no second decode, no clone
    // (this is the common case on the decrypt hot path). Only when hex is
    // absent or the wrong length do we fall back to base64, with the
    // tie-break: prefer a crypto-valid base64, else the hex bytes.
    if looks_hex {
        if let Ok(hex) = hex::decode(input) {
            if is_crypto_len(hex.len()) {
                return Ok(hex);
            }
            return match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input) {
                Ok(b64) if is_crypto_len(b64.len()) => Ok(b64),
                _ => Ok(hex),
            };
        }
    }

    // Not hex-looking (or hex failed to decode) — base64 only.
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input).map_err(|_| {
        MobileError::CryptoError(format!(
            "Failed to decode (tried hex and base64): len={}",
            input.len()
        ))
    })
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self {
            private_key: Arc::new(RwLock::new(None)),
            previous_private_keys: Arc::new(RwLock::new(Vec::new())),
            previous_signing_keys: Arc::new(RwLock::new(HashMap::new())),
            public_key: Arc::new(RwLock::new(None)),
            circle_keys: Arc::new(RwLock::new(HashMap::new())),
            unreadable_circle_keys: Arc::new(RwLock::new(HashMap::new())),
            active_key_version: Arc::new(RwLock::new(HashMap::new())),
            sender_session_keys: Arc::new(RwLock::new(HashMap::new())),
            peer_session_keys: Arc::new(RwLock::new(HashMap::new())),
            secure_storage: Arc::new(RwLock::new(None)),
            password_key_cache: Arc::new(RwLock::new(None)),
            signing_keypair: Arc::new(RwLock::new(None)),
            unreadable_signing_seed: Arc::new(RwLock::new(None)),
            pinned_keys: Arc::new(RwLock::new(HashMap::new())),
            identity_pins: Arc::new(RwLock::new(HashMap::new())),
            unconfirmed_rotations: Arc::new(RwLock::new(HashMap::new())),
            personal_provenance: Arc::new(RwLock::new(PersonalKeyProvenance::default())),
            circle_provenance: Arc::new(RwLock::new(CircleKeyProvenance::default())),
            refresh: Arc::new(RwLock::new(HashMap::new())),
            load_state: AtomicU8::new(LOAD_NOT_ATTEMPTED),
            persist_depth: AtomicI64::new(0),
            persist_dirty: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StorageCallbackError;

    /// A personal slot never evicts (a retired personal key is the only key
    /// for its rows); every other circle keeps its cap.
    #[test]
    fn personal_slots_keep_every_retired_key_other_circles_keep_their_cap() {
        let key = |b: u8| Zeroizing::new(vec![b; 32]);
        for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
            let mut map = HashMap::new();
            insert_circle_version(slot, &mut map, 1, key(1));
            for i in 0..7u8 {
                let at = next_retired_version(&map);
                assert_eq!(at, -(i as i32), "each retired key gets its own place below 1");
                insert_circle_version(slot, &mut map, at, key(10 + i));
            }
            assert_eq!(map.len(), 8, "{slot}: nothing evicted");
            assert_eq!(map.keys().max(), Some(&1), "the key in use stays the highest");
            // A load inserts in any order; lowest first is the one a cap would
            // trim as it goes.
            let mut loaded = HashMap::new();
            for v in -6..=1 {
                insert_circle_version(slot, &mut loaded, v, key(v as u8));
            }
            assert_eq!(loaded.len(), 8, "{slot}: nothing evicted on load");
        }
        let mut map = HashMap::new();
        for v in 1..=7 {
            insert_circle_version("11111111-1111-4111-8111-111111111111", &mut map, v, key(v as u8));
        }
        assert_eq!(map.len(), MAX_CIRCLE_KEY_VERSIONS, "an ordinary circle keeps its cap");
    }
    use base64::Engine;

    /// Test helper: insert a circle key into the versioned map at version 1
    fn insert_test_circle_key(manager: &CryptoManager, circle_id: &str, key: Vec<u8>) {
        let mut keys = manager.circle_keys.write().unwrap();
        let mut version_map = HashMap::new();
        version_map.insert(1i32, Zeroizing::new(key));
        keys.insert(CircleKey::of(&circle_id), version_map);
        manager.active_key_version.write().unwrap().insert(CircleKey::of(&circle_id), 1);
    }

    /// Test helper: add another circle-key VERSION for an existing circle and make
    /// it the active version — simulates a key rotation. Mirrors the direct
    /// map-write style of `insert_test_circle_key`.
    fn rotate_test_circle_key(manager: &CryptoManager, circle_id: &str, version: i32, key: Vec<u8>) {
        let mut keys = manager.circle_keys.write().unwrap();
        keys.entry(CircleKey::of(&circle_id))
            .or_insert_with(HashMap::new)
            .insert(version, Zeroizing::new(key));
        manager.active_key_version.write().unwrap().insert(CircleKey::of(&circle_id), version);
    }

    /// Test storage that counts `store_keys` calls so we can assert how many real
    /// encrypted writes a sequence of `persist_keys` produced.
    struct CountingStorage {
        store_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl KeyStorageCallback for CountingStorage {
        fn store_keys(&self, _data: StoredKeyData) -> Result<(), StorageCallbackError> {
            self.store_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
            Ok(None)
        }
        fn delete_keys(&self) -> Result<(), StorageCallbackError> {
            Ok(())
        }
    }

    #[test]
    fn test_bulk_key_import_coalesces_persist() {
        use std::sync::atomic::AtomicUsize;

        let manager = CryptoManager::new();
        // Need a private key present, otherwise persist_keys short-circuits before
        // reaching store_keys.
        manager.generate_keypair();

        let count = std::sync::Arc::new(AtomicUsize::new(0));
        manager.register_secure_storage(Box::new(CountingStorage {
            store_count: count.clone(),
        }));

        // Immediate mode (no opt-in): every persist_keys writes.
        manager.persist_keys().unwrap();
        manager.persist_keys().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "immediate mode writes once per call");

        // Deferred mode: writes are suppressed until end_bulk_key_import.
        manager.begin_bulk_key_import();
        manager.persist_keys().unwrap();
        manager.persist_keys().unwrap();
        manager.persist_keys().unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "deferred mode must not write during the bulk window"
        );

        manager.end_bulk_key_import().unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            3,
            "end_bulk_key_import flushes exactly one coalesced write"
        );

        // Immediate mode resumes after the window closes.
        manager.persist_keys().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "immediate mode resumes after window");

        // A window with no deferred persist flushes nothing.
        manager.begin_bulk_key_import();
        manager.end_bulk_key_import().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "empty window flushes nothing");

        // Re-entrant/nested windows (the reason for a depth counter, not a bool):
        // the inner end must NOT flush while an outer window is still open; only the
        // outermost end flushes, once, for the whole nest. This models the concurrent
        // per-circle refresh fan-out where begin/end windows overlap on the shared
        // CryptoManager — a bool would flush at the first end and drop the rest.
        manager.begin_bulk_key_import(); // depth 1
        manager.persist_keys().unwrap(); // owed
        manager.begin_bulk_key_import(); // depth 2 (nested/overlapping)
        manager.persist_keys().unwrap(); // still owed
        manager.end_bulk_key_import().unwrap(); // depth 1 — inner end, must NOT flush
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "inner end must not flush while an outer window is open"
        );
        manager.persist_keys().unwrap(); // still deferred at depth 1
        assert_eq!(count.load(Ordering::SeqCst), 4, "persist stays deferred inside the outer window");
        manager.end_bulk_key_import().unwrap(); // depth 0 — outermost end flushes once
        assert_eq!(
            count.load(Ordering::SeqCst),
            5,
            "outermost end flushes exactly one coalesced write for the whole nest"
        );
    }

    /// A seed imported or generated here replaces a stored one that didn't
    /// install: the kept copy goes (wiped) then, not only at the next clear.
    #[test]
    fn an_imported_or_generated_seed_drops_a_kept_seed_that_didnt_install() {
        let import = |manager: &CryptoManager| {
            let seed = CryptoManager::new().generate_signing_keypair().secret_seed_b64;
            manager.import_signing_private_key(seed).unwrap();
        };
        let generate = |manager: &CryptoManager| {
            manager.generate_signing_keypair();
        };
        for replace in [&import as &dyn Fn(&CryptoManager), &generate] {
            let manager = CryptoManager::new();
            manager.generate_keypair();
            manager.take_stored_signing_seed(Some("not base64!"));
            assert!(manager.unreadable_signing_seed.read().unwrap().is_some(), "kept");
            replace(&manager);
            assert!(manager.unreadable_signing_seed.read().unwrap().is_none(), "replaced");
        }
    }

    /// A platform read that fails with an error of the platform's own (lifted
    /// as UniFFI lifts it): the load returns a storage error and records the
    /// failure, so nothing is written over the store until a load succeeds.
    #[test]
    fn a_platform_read_that_fails_is_a_storage_error_and_keeps_writes_away() {
        struct Unreadable;
        impl KeyStorageCallback for Unreadable {
            fn store_keys(&self, _: StoredKeyData) -> Result<(), StorageCallbackError> {
                panic!("written over a store that couldn't be read");
            }
            fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
                // What UniFFI hands the SDK when a Swift or Kotlin callback
                // throws an error of its own (a Keychain status, say).
                <Result<Option<StoredKeyData>, StorageCallbackError> as uniffi::LiftReturn<crate::UniFfiTag>>::handle_callback_unexpected_error(
                    uniffi::UnexpectedUniFFICallbackError::new("osStatus(-25308)"),
                )
            }
            fn delete_keys(&self) -> Result<(), StorageCallbackError> {
                Ok(())
            }
        }
        let manager = CryptoManager::new();
        manager.register_secure_storage(Box::new(Unreadable));
        assert!(matches!(manager.load_persisted_keys(), Err(MobileError::StorageError(_))));
        assert_eq!(manager.load_state.load(Ordering::Acquire), LOAD_FAILED);
        assert_eq!(manager.key_store_status().load, KeyStoreLoad::ReadFailed);
        manager.generate_keypair();
        assert!(manager.persist_keys().is_err());
    }

    /// A write or a delete the platform fails: the write reports it and the
    /// store keeps what it held; a clear still clears memory. Nothing panics.
    #[test]
    fn a_platform_write_or_delete_that_fails_is_reported_never_a_panic() {
        #[derive(Clone, Default)]
        struct Failing(SharedStore);
        impl KeyStorageCallback for Failing {
            fn store_keys(&self, _: StoredKeyData) -> Result<(), StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
            fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
                self.0.load_keys()
            }
            fn delete_keys(&self) -> Result<(), StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
        }
        let store = Failing::default();
        let manager = CryptoManager::new();
        manager.register_secure_storage(Box::new(store.clone()));
        assert!(!manager.load_persisted_keys().unwrap());
        manager.generate_keypair();
        assert!(matches!(manager.persist_keys(), Err(MobileError::StorageError(_))));
        assert!(store.0 .0.lock().unwrap().is_none(), "nothing written");
        // An import still takes its key in memory; its write is only logged.
        manager.import_signing_private_key(CryptoManager::new().generate_signing_keypair().secret_seed_b64).unwrap();
        assert!(manager.signing_public_key_hex().is_ok());
        manager.clear_all_keys();
        assert!(manager.export_public_key().is_err() && manager.signing_public_key_hex().is_err());
    }

    #[derive(Clone, Default)]
    struct SharedStore(Arc<std::sync::Mutex<Option<StoredKeyData>>>);

    impl KeyStorageCallback for SharedStore {
        fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = Some(data);
            Ok(())
        }
        fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn delete_keys(&self) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    impl SharedStore {
        fn pins(&self) -> HashMap<String, PinRecord> {
            serde_json::from_str(self.0.lock().unwrap().as_ref().unwrap().pinned_keys_json.as_deref().unwrap()).unwrap()
        }
        fn set_pins(&self, pins: &HashMap<String, PinRecord>) {
            self.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = Some(serde_json::to_string(pins).unwrap());
        }
        fn loaded(&self) -> Arc<CryptoManager> {
            let manager = CryptoManager::new();
            manager.register_secure_storage(Box::new(self.clone()));
            assert!(manager.load_persisted_keys().unwrap());
            manager
        }
    }

    /// A circle mark that doesn't read marks every version its circle holds,
    /// goes back exactly as stored, and goes once the circle holds a newer
    /// version (which it could never name); the marks it made stay.
    #[test]
    fn a_circle_mark_that_doesnt_read_marks_every_held_version_until_a_newer_one() {
        const C: &str = "33333333-3333-4333-8333-333333333333";
        const OTHER: &str = "44444444-4444-4444-8444-444444444444";
        for (prefix, via_previous) in [(CIRCLE_TRUST_MARK_PREFIX, false), (VIA_PREVIOUS_MARK_PREFIX, true)] {
            let store = SharedStore::default();
            let manager = CryptoManager::new();
            manager.register_secure_storage(Box::new(store.clone()));
            manager.generate_keypair();
            for (circle, version) in [(C, 1), (C, 2), (OTHER, 1)] {
                rotate_test_circle_key(&manager, circle, version, vec![version as u8; 32]);
            }
            manager.persist_keys().unwrap();
            let unread = format!("{prefix}{C}:2:a later format");
            let mut pins = store.pins();
            pins.insert(unread.clone(), PinRecord {
                sharing_pubkey_hex: "as stored".into(),
                signing_pubkey_hex: String::new(),
                first_pinned_at: 7,
                last_verified_at: 0,
                user_approved_change_at: None,
            });
            store.set_pins(&pins);
            let as_stored = serde_json::to_string(&pins[&unread]).unwrap();

            let device = store.loaded();
            let marked = |device: &CryptoManager, circle: &str, version: i32| {
                let marks = device.circle_provenance.read().unwrap();
                let set = if via_previous { &marks.via_previous_identity } else { &marks.taken_on_trust };
                set.contains(&(CircleKey::of(circle), version))
            };
            assert!(marked(&device, C, 1) && marked(&device, C, 2), "{prefix}: every version it holds");
            assert!(!marked(&device, OTHER, 1), "{prefix}: that circle only");
            if via_previous {
                assert!(device.active_key_came_via_previous_identity(C.into()));
            } else {
                assert!(device.circle_key_is_taken_on_trust(C, 2));
            }
            device.persist_keys().unwrap();
            let pins = store.pins();
            assert_eq!(pins.get(&unread).map(|r| serde_json::to_string(r).unwrap()), Some(as_stored.clone()), "{prefix}: as stored");
            assert!(pins.contains_key(&format!("{prefix}{C}:1")) && pins.contains_key(&format!("{prefix}{C}:2")));
            // Again from what was written: the same.
            let again = store.loaded();
            again.persist_keys().unwrap();
            assert!(store.pins().contains_key(&unread), "{prefix}");
            // A newer version: the mark goes, its marks stay, the new one is unmarked.
            rotate_test_circle_key(&again, C, 3, vec![3; 32]);
            again.persist_keys().unwrap();
            let pins = store.pins();
            assert!(!pins.contains_key(&unread), "{prefix}: gone once a newer version is held");
            let after = store.loaded();
            assert!(marked(&after, C, 2) && !marked(&after, C, 3), "{prefix}");
            if via_previous {
                assert!(!after.active_key_came_via_previous_identity(C.into()), "no rotation at every start");
            }
            // Leaving the circle takes it with the rest.
            store.set_pins(&{
                let mut pins = store.pins();
                pins.insert(unread.clone(), serde_json::from_str(&as_stored).unwrap());
                pins
            });
            let device_with_mark = store.loaded();
            assert!(device_with_mark.forget_circle_entirely(C));
            assert!(!store.pins().contains_key(&unread), "{prefix}: forgotten with its circle");
        }
    }

    impl SharedStore {
        fn circle_keys(&self) -> HashMap<String, HashMap<String, String>> {
            serde_json::from_str(&self.0.lock().unwrap().as_ref().unwrap().circle_keys_json).unwrap()
        }
        fn set_circle_keys(&self, keys: &HashMap<String, HashMap<String, String>>) {
            self.0.lock().unwrap().as_mut().unwrap().circle_keys_json = serde_json::to_string(keys).unwrap();
        }
    }

    fn b64_key(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// While the store can't be read, no unauthenticated first copy of a
    /// circle key is taken: this device may hold that circle's key in the
    /// store. After the keys are cleared it is a first contact again.
    #[test]
    fn while_the_store_cant_be_read_no_first_copy_is_taken_on_trust() {
        let (a, _, _) = make_signer_with_circle(WRAP_CIRCLE, vec![4; 32]);
        let store = SharedStore::default();
        let b = CryptoManager::new();
        b.register_secure_storage(Box::new(store.clone()));
        let identity = b.generate_keypair();
        b.persist_keys().unwrap();
        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = Some("{\"cut short".into());
        assert!(b.load_persisted_keys().is_err());
        let unsigned_first_copy = |b: &CryptoManager| {
            let bundle = a
                .wrap_circle_key_for_member_full(
                    WRAP_CIRCLE.to_string(),
                    identity.public_key.clone(),
                    WRAP_A_UID.to_string(),
                    WRAP_B_UID.to_string(),
                    String::new(),
                )
                .unwrap();
            b.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key.clone(),
                1,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                None,
                None,
            )
        };
        assert!(unsigned_first_copy(&b).is_err() && !b.has_circle_key(WRAP_CIRCLE.into()));
        b.clear_all_keys();
        b.import_private_key(identity.private_key.clone()).unwrap();
        unsigned_first_copy(&b).unwrap();
        assert!(b.circle_key_is_taken_on_trust(WRAP_CIRCLE, 1), "a first contact, on trust");
    }

    /// A stored circle key under a version that doesn't read is never filed
    /// under another version, and goes back as stored.
    #[test]
    fn a_stored_circle_key_under_a_version_that_doesnt_read_is_never_filed() {
        const ALONE: &str = "55555555-5555-4555-8555-555555555555";
        const BESIDE: &str = "66666666-6666-4666-8666-666666666666";
        let store = SharedStore::default();
        let manager = CryptoManager::new();
        manager.register_secure_storage(Box::new(store.clone()));
        manager.generate_keypair();
        rotate_test_circle_key(&manager, BESIDE, 1, vec![1; 32]);
        manager.persist_keys().unwrap();
        let mut keys = store.circle_keys();
        keys.insert(ALONE.into(), HashMap::from([("one".to_string(), b64_key(&[9; 32]))]));
        keys.get_mut(BESIDE).unwrap().insert("1.0".into(), b64_key(&[9; 32]));
        store.set_circle_keys(&keys);

        let device = store.loaded();
        assert!(!device.has_circle_key(ALONE.into()), "never filed as v1");
        assert!(device.get_active_version(ALONE.into()).is_err());
        let held = device.circle_keys.read().unwrap()[&CircleKey::of(BESIDE)].clone();
        assert!(held.len() == 1 && held[&1].as_slice() == [1u8; 32].as_slice(), "v1 is the key stored as v1");
        device.persist_keys().unwrap();
        assert!(store.circle_keys() == keys, "written back as stored");
    }

    /// A stored circle key that isn't 32 bytes, on a circle without records:
    /// no other copy of that version is taken, the circle is no first contact,
    /// it seals under no older version, a rotation numbers above it, and it
    /// goes back as stored until it is left.
    #[test]
    fn a_stored_circle_key_that_isnt_32_bytes_keeps_its_version_from_every_copy() {
        let (a, _, a_signing_hex) = make_signer_with_circle(WRAP_CIRCLE, vec![1; 32]);
        rotate_test_circle_key(&a, WRAP_CIRCLE, 2, vec![2; 32]);
        let (b, b_pub) = make_recipient();
        let store = SharedStore::default();
        b.register_secure_storage(Box::new(store.clone()));
        b.generate_signing_keypair();
        rotate_test_circle_key(&b, WRAP_CIRCLE, 1, vec![1; 32]);
        rotate_test_circle_key(&b, WRAP_CIRCLE, 2, vec![2; 32]);
        b.persist_keys().unwrap();
        let mut keys = store.circle_keys();
        keys.get_mut(WRAP_CIRCLE).unwrap().insert("2".into(), b64_key(&[2; 16]));
        store.set_circle_keys(&keys);

        let device = store.loaded();
        assert_eq!(device.held_version(WRAP_CIRCLE), Some(1));
        assert_eq!(device.sealing_version(WRAP_CIRCLE), None, "never under v1 while v2 is out of reach");
        assert!(device.get_active_version(WRAP_CIRCLE.into()).is_err());
        // A signed copy of v2 from a pinned member: refused all the same.
        let store_from_a = |device: &CryptoManager, version: i32| {
            let bundle = a
                .wrap_circle_key_for_member_full(
                    WRAP_CIRCLE.to_string(),
                    b_pub.clone(),
                    WRAP_A_UID.to_string(),
                    WRAP_B_UID.to_string(),
                    String::new(),
                )
                .unwrap();
            device.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key.clone(),
                version,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                Some(bundle.wrap_signature.clone()),
                Some(a_signing_hex.clone()),
            )
        };
        let a_sharing_hex = hex::encode(base64::engine::general_purpose::STANDARD.decode(a.export_public_key().unwrap()).unwrap());
        device
            .pin_member_keys(WRAP_CIRCLE.to_string(), WRAP_A_UID.to_string(), a_sharing_hex, a_signing_hex.clone())
            .unwrap();
        assert!(store_from_a(&device, 2).is_err(), "no other copy of v2");
        assert_eq!(device.held_version(WRAP_CIRCLE), Some(1));
        device.persist_keys().unwrap();
        assert!(store.circle_keys() == keys, "written back as stored");
        // A circle holding nothing but such a copy is no first contact: an
        // unsigned copy of another version is refused, not taken on trust.
        const ONLY: &str = "77777777-7777-4777-8777-777777777777";
        let (only_signer, _, _) = make_signer_with_circle(ONLY, vec![5; 32]);
        rotate_test_circle_key(&only_signer, ONLY, 2, vec![6; 32]);
        let mut with_only = store.circle_keys();
        with_only.insert(ONLY.into(), HashMap::from([("1".to_string(), b64_key(&[5; 16]))]));
        store.set_circle_keys(&with_only);
        let loaded = store.loaded();
        let bundle = only_signer
            .wrap_circle_key_for_member_full(ONLY.to_string(), b_pub.clone(), WRAP_A_UID.to_string(), WRAP_B_UID.to_string(), String::new())
            .unwrap();
        let unsigned = loaded.store_circle_key(
            ONLY.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key.clone(),
            2,
            WRAP_A_UID.to_string(),
            WRAP_B_UID.to_string(),
            None,
            None,
        );
        assert!(unsigned.is_err() && !loaded.has_circle_key(ONLY.into()), "no first contact");
        // A rotation numbers above it, and seals under its own key.
        let rotation = loaded
            .prepare_key_rotation(
                WRAP_CIRCLE.to_string(),
                WRAP_B_UID.to_string(),
                vec![WRAP_B_UID.to_string()],
                vec![hex::encode(base64::engine::general_purpose::STANDARD.decode(b_pub.clone()).unwrap())],
                vec![String::new()],
                String::new(),
            )
            .unwrap();
        assert_eq!(rotation.new_key_version, 3, "above the version kept as stored");
        assert_eq!(loaded.sealing_version(WRAP_CIRCLE), Some(3));
        // Leaving the circle takes it.
        assert!(loaded.forget_circle_entirely(ONLY));
        assert!(!store.circle_keys().contains_key(ONLY));
        // So does clearing the keys, for every circle.
        loaded.clear_all_keys();
        loaded.generate_keypair();
        loaded.persist_keys().unwrap();
        assert!(store.circle_keys().is_empty(), "nothing kept as stored after a clear");
    }

    #[test]
    fn test_generate_keypair() {
        let manager = CryptoManager::new();
        let keypair = manager.generate_keypair();

        // Keys should be valid base64 and correct length
        let private_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.private_key)
            .unwrap();
        let public_bytes = base64::engine::general_purpose::STANDARD
            .decode(&keypair.public_key)
            .unwrap();

        assert_eq!(private_bytes.len(), 32);
        assert_eq!(public_bytes.len(), 32);

        // Public key should be exportable
        let exported = manager.export_public_key().unwrap();
        assert_eq!(exported, keypair.public_key);
    }

    #[test]
    fn test_import_private_key() {
        let manager = CryptoManager::new();

        // Generate a keypair first
        let keypair = manager.generate_keypair();

        // Create new manager and import the key
        let manager2 = CryptoManager::new();
        manager2.import_private_key(keypair.private_key.clone()).unwrap();

        // Public key should match
        let exported = manager2.export_public_key().unwrap();
        assert_eq!(exported, keypair.public_key);
    }

    #[test]
    fn test_import_invalid_key_length() {
        let manager = CryptoManager::new();

        // Try to import a key that's too short
        let short_key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let result = manager.import_private_key(short_key);
        assert!(matches!(result, Err(MobileError::InvalidKey)));
    }

    #[test]
    fn test_encrypt_decrypt_data() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Manually add a circle key for testing
        let circle_id = "test_circle".to_string();
        let circle_key = [42u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.to_vec());

        // Encrypt and decrypt
        let plaintext = "Hello, World!".to_string();
        let encrypted = manager.encrypt_data(circle_id.clone(), plaintext.clone()).unwrap();

        // Encrypted data should be different from plaintext
        assert_ne!(encrypted.ciphertext, plaintext);

        // Decrypt should return original
        let decrypted = manager.decrypt_data(circle_id, encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_location() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Add circle key
        let circle_id = "location_circle".to_string();
        let circle_key = [42u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.to_vec());

        let location = Location {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: Some(10.0),
            speed: Some(5.5),
            heading: Some(180.0),
            accuracy: Some(10.0),
            timestamp: 1704067200000,
            battery_level: Some(85),
            is_charging: Some(false),
        };

        let encrypted = manager.encrypt_location(circle_id.clone(), location.clone()).unwrap();
        let decrypted = manager.decrypt_location(circle_id, encrypted).unwrap();

        assert_eq!(decrypted.latitude, location.latitude);
        assert_eq!(decrypted.longitude, location.longitude);
        assert_eq!(decrypted.altitude, location.altitude);
        assert_eq!(decrypted.battery_level, location.battery_level);
    }

    fn packing_test_location() -> Location {
        Location {
            latitude: 40.7128,
            longitude: -74.006,
            altitude: Some(10.0),
            speed: Some(5.5),
            heading: Some(180.0),
            accuracy: Some(10.0),
            timestamp: 1_704_067_200_000,
            battery_level: Some(85),
            is_charging: Some(false),
        }
    }

    /// The plaintext that actually reaches the AEAD must be the PACKED form.
    /// XChaCha20-Poly1305 ciphertext is plaintext_len + 16 (the Poly1305 tag), so
    /// the hex ciphertext measures the plaintext exactly — an end-to-end size
    /// proof through the real encryptor rather than through the codec alone.
    #[test]
    fn location_write_seals_the_packed_plaintext_not_json() {
        let manager = CryptoManager::new();
        manager.generate_keypair();
        let circle_id = "packed_size_circle".to_string();
        insert_test_circle_key(&manager, &circle_id, [7u8; 32].to_vec());

        let location = packing_test_location();
        let encrypted = manager
            .encrypt_location(circle_id.clone(), location.clone())
            .unwrap();

        let sealed_plaintext_len = encrypted.ciphertext.len() / 2 - 16;
        let json_len = serde_json::to_string(&location).unwrap().len();
        assert_eq!(
            sealed_plaintext_len, 35,
            "expected a 35-byte packed plaintext, got {}",
            sealed_plaintext_len
        );
        assert!(
            json_len > 4 * sealed_plaintext_len,
            "packed {} vs json {}",
            sealed_plaintext_len,
            json_len
        );

        // And it still reads back.
        let decrypted = manager.decrypt_location(circle_id, encrypted).unwrap();
        assert_eq!(decrypted.latitude, location.latitude);
        assert_eq!(decrypted.longitude, location.longitude);
        assert_eq!(decrypted.is_charging, Some(false));
    }

    /// STORED JSON ROWS. Locations written by older clients were sealed as a
    /// JSON document under the v1 empty AAD. Seal one exactly that way and prove
    /// the reader still opens it.
    ///
    /// This also pins the PLACE read path: the apps seal a place's coordinates as
    /// hand-written JSON and read them back through `decrypt_location`, so the
    /// JSON branch must never be removed.
    #[test]
    fn legacy_json_location_ciphertext_still_decrypts() {
        let manager = CryptoManager::new();
        manager.generate_keypair();
        let circle_id = "legacy_json_circle".to_string();
        let circle_key = [11u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.clone());

        let location = packing_test_location();

        // v1 empty AAD — byte-for-byte what a JSON-writing `encrypt_location` produces.
        let json = serde_json::to_string(&location).unwrap();
        let legacy_v1 = encrypt_with_raw_key(&circle_key, json.as_bytes()).unwrap();
        let read_v1 = manager
            .decrypt_location(circle_id.clone(), legacy_v1)
            .unwrap();
        assert_eq!(read_v1.latitude, location.latitude);
        assert_eq!(read_v1.longitude, location.longitude);
        assert_eq!(read_v1.battery_level, location.battery_level);

        // v2 circle-field AAD — a JSON location sealed with the v2 AAD.
        let legacy_v2 = encrypt_with_raw_key_aad(
            &circle_key,
            json.as_bytes(),
            &circle_field_write_aad_v2(&circle_id, "location"),
        )
        .unwrap();
        let read_v2 = manager.decrypt_location(circle_id, legacy_v2).unwrap();
        assert_eq!(read_v2.latitude, location.latitude);
        assert_eq!(read_v2.speed, location.speed);
    }

    /// The envelope path (how iOS reads member locations, and how Android reads
    /// wrappedMsgKey rows) must round-trip the packed plaintext too.
    #[test]
    fn envelope_location_round_trips_packed() {
        let manager = CryptoManager::new();
        manager.generate_keypair();
        let circle_id = "envelope_packed_circle".to_string();
        insert_test_circle_key(&manager, &circle_id, [23u8; 32].to_vec());

        let location = packing_test_location();
        let envelope = manager
            .envelope_encrypt_location_v2(location.clone(), vec![circle_id.clone()])
            .unwrap();
        let wrap = &envelope.key_wraps[0];

        let sealed_plaintext_len = envelope.ciphertext.len() / 2 - 16;
        assert_eq!(sealed_plaintext_len, 35, "envelope payload should be packed");

        let decrypted = manager
            .unwrap_and_decrypt_location_v2(
                circle_id,
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                envelope.ciphertext.clone(),
                envelope.ciphertext_nonce.clone(),
            )
            .unwrap();
        assert_eq!(decrypted.latitude, location.latitude);
        assert_eq!(decrypted.longitude, location.longitude);
        assert_eq!(decrypted.timestamp, location.timestamp);
        assert_eq!(decrypted.heading, location.heading);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Add circle key and encrypt
        let circle_id = "circle1".to_string();
        let circle_key = [42u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.to_vec());

        let encrypted = manager.encrypt_data(circle_id, "secret".to_string()).unwrap();

        // Try to decrypt with different key
        let circle_id2 = "circle2".to_string();
        let wrong_key = [99u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id2, wrong_key.to_vec());

        let result = manager.decrypt_data(circle_id2, encrypted);
        assert!(matches!(result, Err(MobileError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_without_circle_key_fails() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let result = manager.encrypt_data("nonexistent".to_string(), "test".to_string());
        assert!(matches!(result, Err(MobileError::KeyNotFound(_))));
    }

    #[test]
    fn test_has_circle_key() {
        let manager = CryptoManager::new();

        assert!(!manager.has_circle_key("circle1".to_string()));

        insert_test_circle_key(&manager, "circle1", vec![0u8; 32]);

        assert!(manager.has_circle_key("circle1".to_string()));
        assert!(!manager.has_circle_key("circle2".to_string()));
    }

    #[test]
    fn test_clear_all_keys() {
        let manager = CryptoManager::new();
        manager.generate_keypair();
        insert_test_circle_key(&manager, "c1", vec![0u8; 32]);
        insert_test_circle_key(&manager, "c2", vec![0u8; 32]);

        assert!(manager.export_public_key().is_ok());
        assert!(manager.has_circle_key("c1".to_string()));

        manager.clear_all_keys();

        assert!(manager.export_public_key().is_err());
        assert!(!manager.has_circle_key("c1".to_string()));
        assert!(!manager.has_circle_key("c2".to_string()));
    }

    #[test]
    fn test_prepare_and_finalize_circle_creation() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Prepare circle creation
        let creation_data = manager.prepare_circle_creation().unwrap();

        // Should have temp circle key
        assert!(creation_data.temp_circle_id.starts_with("temp_"));
        assert!(manager.has_circle_key(creation_data.temp_circle_id.clone()));

        // Finalize with real ID
        let real_id = "real_circle_123".to_string();
        manager.finalize_circle_creation(
            creation_data.temp_circle_id.clone(),
            real_id.clone(),
        ).unwrap();

        // Temp key should be gone, real key should exist
        assert!(!manager.has_circle_key(creation_data.temp_circle_id));
        assert!(manager.has_circle_key(real_id));
    }

    #[test]
    fn test_derive_user_pseudonym_deterministic() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle1".to_string();
        let circle_key = [42u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.to_vec());

        let user_id = "user123".to_string();

        // Same inputs should produce same pseudonym
        let pseudo1 = manager.derive_user_pseudonym(circle_id.clone(), user_id.clone()).unwrap();
        let pseudo2 = manager.derive_user_pseudonym(circle_id.clone(), user_id.clone()).unwrap();
        assert_eq!(pseudo1, pseudo2);

        // Different user should produce different pseudonym
        let pseudo3 = manager.derive_user_pseudonym(circle_id, "user456".to_string()).unwrap();
        assert_ne!(pseudo1, pseudo3);
    }

    #[test]
    fn test_derive_pseudonyms_different_circles() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Add two different circle keys
        insert_test_circle_key(&manager, "circle1", vec![42u8; 32]);
        insert_test_circle_key(&manager, "circle2", vec![99u8; 32]);

        let user_id = "user123".to_string();

        // Same user in different circles should have different pseudonyms
        let pseudo1 = manager.derive_user_pseudonym("circle1".to_string(), user_id.clone()).unwrap();
        let pseudo2 = manager.derive_user_pseudonym("circle2".to_string(), user_id).unwrap();
        assert_ne!(pseudo1, pseudo2);
    }

    #[test]
    fn test_encrypt_decrypt_timestamp() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle1".to_string();
        insert_test_circle_key(&manager, &circle_id, vec![42u8; 32]);

        let timestamp: i64 = 1704067200000;

        let encrypted = manager.encrypt_timestamp(circle_id.clone(), timestamp).unwrap();
        let decrypted = manager.decrypt_timestamp(circle_id, encrypted).unwrap();

        assert_eq!(decrypted, timestamp);
    }

    #[test]
    fn test_compute_event_type_hash_deterministic() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle1".to_string();
        insert_test_circle_key(&manager, &circle_id, vec![42u8; 32]);

        // Same inputs should produce same hash
        let hash1 = manager.compute_event_type_hash(circle_id.clone(), "enter".to_string()).unwrap();
        let hash2 = manager.compute_event_type_hash(circle_id.clone(), "enter".to_string()).unwrap();
        assert_eq!(hash1, hash2);

        // Different event types should produce different hashes
        let hash3 = manager.compute_event_type_hash(circle_id, "exit".to_string()).unwrap();
        assert_ne!(hash1, hash3);

        // Hash should be 64 hex chars (32 bytes)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_generate_master_key() {
        let manager = CryptoManager::new();

        let key1 = manager.generate_master_key();
        let key2 = manager.generate_master_key();

        // Keys should be valid base64 and correct length
        let bytes1 = base64::engine::general_purpose::STANDARD.decode(&key1).unwrap();
        assert_eq!(bytes1.len(), 32);

        // Keys should be random (different each time)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let manager = CryptoManager::new();

        // Generate a key
        let key = manager.generate_master_key();

        // Encrypt some data
        let plaintext = base64::engine::general_purpose::STANDARD.encode("Hello, World!");
        let encrypted = manager.encrypt_with_key(plaintext.clone(), key.clone()).unwrap();

        // Decrypt
        let decrypted = manager.decrypt_with_key(encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_password() {
        let manager = CryptoManager::new();

        // Create KDF params
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

        let kdf_params = KdfParams {
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
            memory_kib: 65536,  // 64 MiB
            iterations: 3,
            parallelism: 1,
        };

        // Encrypt with password
        let plaintext = base64::engine::general_purpose::STANDARD.encode("Secret data");
        let password = "my_secure_password".to_string();

        let encrypted = manager.encrypt_with_password(
            plaintext.clone(),
            password.clone(),
            kdf_params.clone(),
        ).unwrap();

        // Decrypt with same password
        let decrypted = manager.decrypt_with_password(encrypted, password, kdf_params).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let manager = CryptoManager::new();

        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

        let kdf_params = KdfParams {
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        };

        let plaintext = base64::engine::general_purpose::STANDARD.encode("Secret");
        let encrypted = manager.encrypt_with_password(
            plaintext,
            "correct_password".to_string(),
            kdf_params.clone(),
        ).unwrap();

        // Try to decrypt with wrong password
        let result = manager.decrypt_with_password(encrypted, "wrong_password".to_string(), kdf_params);
        assert!(matches!(result, Err(MobileError::DecryptionFailed)));
    }

    #[test]
    fn test_kdf_params_validation_rejects_weak_params() {
        let manager = CryptoManager::new();
        let salt = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let plaintext = base64::engine::general_purpose::STANDARD.encode("test");

        // Memory too low (below 8 MiB)
        let weak_memory = KdfParams {
            salt: salt.clone(),
            memory_kib: 1024, // 1 MiB - too low
            iterations: 3,
            parallelism: 1,
        };
        let result = manager.encrypt_with_password(plaintext.clone(), "password".to_string(), weak_memory);
        assert!(matches!(result, Err(MobileError::InvalidInput(_))));

        // Iterations too low
        let weak_iterations = KdfParams {
            salt: salt.clone(),
            memory_kib: 65536,
            iterations: 1, // too low
            parallelism: 1,
        };
        let result = manager.encrypt_with_password(plaintext.clone(), "password".to_string(), weak_iterations);
        assert!(matches!(result, Err(MobileError::InvalidInput(_))));

        // Parallelism too high
        let high_parallelism = KdfParams {
            salt: salt.clone(),
            memory_kib: 65536,
            iterations: 3,
            parallelism: 16, // too high
        };
        let result = manager.encrypt_with_password(plaintext, "password".to_string(), high_parallelism);
        assert!(matches!(result, Err(MobileError::InvalidInput(_))));
    }

    #[test]
    fn test_decode_flexible_hex() {
        let hex_input = "48656c6c6f"; // "Hello" in hex
        let result = decode_flexible(hex_input).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_decode_flexible_base64() {
        let base64_input = "SGVsbG8="; // "Hello" in base64
        let result = decode_flexible(base64_input).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_nonce_uniqueness() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle1".to_string();
        insert_test_circle_key(&manager, &circle_id, vec![42u8; 32]);

        // Encrypt same data multiple times
        let plaintext = "Same data".to_string();
        let enc1 = manager.encrypt_data(circle_id.clone(), plaintext.clone()).unwrap();
        let enc2 = manager.encrypt_data(circle_id, plaintext).unwrap();

        // Nonces should be different (random)
        assert_ne!(enc1.nonce, enc2.nonce);

        // Ciphertexts should also be different due to different nonces
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_derive_pseudonyms_pair() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle1".to_string();
        insert_test_circle_key(&manager, &circle_id, vec![42u8; 32]);

        let pair = manager.derive_pseudonyms(
            circle_id.clone(),
            "user123".to_string(),
            "device456".to_string(),
        ).unwrap();

        // Individual methods should match
        let user_pseudo = manager.derive_user_pseudonym(circle_id.clone(), "user123".to_string()).unwrap();
        let device_pseudo = manager.derive_device_pseudonym(circle_id, "device456".to_string()).unwrap();

        assert_eq!(pair.user_pseudonym, user_pseudo);
        assert_eq!(pair.device_pseudonym, device_pseudo);

        // User and device pseudonyms should be different
        assert_ne!(pair.user_pseudonym, pair.device_pseudonym);
    }

    /// Test that nonces are unique even under high concurrency.
    /// This validates the thread-safe nonce generator prevents nonce reuse.
    #[test]
    fn test_concurrent_nonce_uniqueness() {
        use std::collections::HashSet;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        // CryptoManager::new() already returns Arc<CryptoManager>
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "concurrent_test".to_string();
        insert_test_circle_key(&manager, &circle_id, vec![42u8; 32]);

        // Use a thread-safe set to collect all nonces
        let nonces: Arc<std::sync::Mutex<HashSet<String>>> = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let collision_count = Arc::new(AtomicUsize::new(0));

        const NUM_THREADS: usize = 10;
        const ENCRYPTIONS_PER_THREAD: usize = 100;

        let mut handles = vec![];

        for _ in 0..NUM_THREADS {
            let manager = Arc::clone(&manager);
            let circle_id = circle_id.clone();
            let nonces = Arc::clone(&nonces);
            let collision_count = Arc::clone(&collision_count);

            let handle = thread::spawn(move || {
                for i in 0..ENCRYPTIONS_PER_THREAD {
                    let plaintext = format!("test data {}", i);
                    let encrypted = manager.encrypt_data(circle_id.clone(), plaintext).unwrap();

                    let mut nonces_guard = nonces.lock().unwrap();
                    if !nonces_guard.insert(encrypted.nonce.clone()) {
                        // Nonce collision detected!
                        collision_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        let final_collision_count = collision_count.load(Ordering::SeqCst);
        let final_nonce_count = nonces.lock().unwrap().len();

        // Should have exactly NUM_THREADS * ENCRYPTIONS_PER_THREAD unique nonces
        assert_eq!(
            final_nonce_count,
            NUM_THREADS * ENCRYPTIONS_PER_THREAD,
            "Expected {} unique nonces, but got {} (collisions: {})",
            NUM_THREADS * ENCRYPTIONS_PER_THREAD,
            final_nonce_count,
            final_collision_count
        );

        // No collisions should have occurred
        assert_eq!(
            final_collision_count, 0,
            "Nonce collision detected! {} collisions in {} encryptions",
            final_collision_count,
            NUM_THREADS * ENCRYPTIONS_PER_THREAD
        );
    }

    #[test]
    fn test_envelope_encrypt_decrypt_single_target() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Add circle key
        let circle_id = "circle_envelope".to_string();
        let circle_key = [42u8; 32].to_vec();
        insert_test_circle_key(&manager, &circle_id, circle_key.to_vec());

        let location = Location {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: Some(10.0),
            speed: Some(5.5),
            heading: Some(180.0),
            accuracy: Some(10.0),
            timestamp: 1704067200000,
            battery_level: Some(85),
            is_charging: Some(false),
        };

        // Envelope encrypt
        let envelope = manager.envelope_encrypt_location(location.clone(), vec![circle_id.clone()]).unwrap();

        assert_eq!(envelope.key_wraps.len(), 1);
        assert_eq!(envelope.key_wraps[0].target_id, circle_id);
        assert_eq!(envelope.timestamp, location.timestamp);
        assert!(!envelope.ciphertext.is_empty());
        assert!(!envelope.ciphertext_nonce.is_empty());

        // Unwrap and decrypt
        let wrap = &envelope.key_wraps[0];
        let decrypted = manager.unwrap_and_decrypt_location(
            wrap.target_id.clone(),
            wrap.wrapped_key.clone(),
            wrap.wrapped_key_nonce.clone(),
            envelope.ciphertext.clone(),
            envelope.ciphertext_nonce.clone(),
        ).unwrap();

        assert_eq!(decrypted.latitude, location.latitude);
        assert_eq!(decrypted.longitude, location.longitude);
        assert_eq!(decrypted.altitude, location.altitude);
        assert_eq!(decrypted.battery_level, location.battery_level);
        assert_eq!(decrypted.timestamp, location.timestamp);
    }

    #[test]
    fn test_envelope_encrypt_decrypt_multiple_targets() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        // Add multiple circle keys
        let circle1 = "circle_a".to_string();
        let circle2 = "circle_b".to_string();
        let self_id = "self".to_string();
        insert_test_circle_key(&manager, &circle1, [1u8; 32].to_vec());
        insert_test_circle_key(&manager, &circle2, [2u8; 32].to_vec());
        insert_test_circle_key(&manager, &self_id, [3u8; 32].to_vec());

        let location = Location {
            latitude: 51.5074,
            longitude: -0.1278,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: Some(15.0),
            timestamp: 1704067200000,
            battery_level: None,
            is_charging: None,
        };

        // Envelope encrypt for all targets
        let envelope = manager.envelope_encrypt_location(
            location.clone(),
            vec![circle1.clone(), circle2.clone(), self_id.clone()],
        ).unwrap();

        assert_eq!(envelope.key_wraps.len(), 3);

        // ALL wraps use the SAME ciphertext - verify by decrypting each
        for wrap in &envelope.key_wraps {
            let decrypted = manager.unwrap_and_decrypt_location(
                wrap.target_id.clone(),
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                envelope.ciphertext.clone(),
                envelope.ciphertext_nonce.clone(),
            ).unwrap();

            assert_eq!(decrypted.latitude, location.latitude);
            assert_eq!(decrypted.longitude, location.longitude);
        }
    }

    #[test]
    fn test_envelope_decrypt_with_wrong_key_fails() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle_right".to_string();
        let wrong_id = "circle_wrong".to_string();
        insert_test_circle_key(&manager, &circle_id, [42u8; 32].to_vec());
        insert_test_circle_key(&manager, &wrong_id, [99u8; 32].to_vec());

        let location = Location {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: None,
            timestamp: 1704067200000,
            battery_level: None,
            is_charging: None,
        };

        let envelope = manager.envelope_encrypt_location(location, vec![circle_id.clone()]).unwrap();
        let wrap = &envelope.key_wraps[0];

        // Try to unwrap with the wrong circle key
        let result = manager.unwrap_and_decrypt_location(
            wrong_id,
            wrap.wrapped_key.clone(),
            wrap.wrapped_key_nonce.clone(),
            envelope.ciphertext.clone(),
            envelope.ciphertext_nonce.clone(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_encrypt_no_targets_fails() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let location = Location {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: None,
            timestamp: 1704067200000,
            battery_level: None,
            is_charging: None,
        };

        let result = manager.envelope_encrypt_location(location, vec![]);
        assert!(matches!(result, Err(MobileError::InvalidInput(_))));
    }

    #[test]
    fn test_envelope_unique_msg_key_per_call() {
        let manager = CryptoManager::new();
        manager.generate_keypair();

        let circle_id = "circle_unique".to_string();
        insert_test_circle_key(&manager, &circle_id, [42u8; 32].to_vec());

        let location = Location {
            latitude: 40.7128,
            longitude: -74.0060,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: None,
            timestamp: 1704067200000,
            battery_level: None,
            is_charging: None,
        };

        // Encrypt the same location twice - should produce different ciphertexts
        let envelope1 = manager.envelope_encrypt_location(location.clone(), vec![circle_id.clone()]).unwrap();
        let envelope2 = manager.envelope_encrypt_location(location, vec![circle_id]).unwrap();

        // Ciphertexts should differ (different msg_key + nonce each time)
        assert_ne!(envelope1.ciphertext, envelope2.ciphertext);
        // Nonces should also differ
        assert_ne!(envelope1.ciphertext_nonce, envelope2.ciphertext_nonce);
    }

    // ── AAD v2 (place field) ────────────────────────────────────────────────

    #[test]
    fn place_aad_v2_is_deterministic_and_field_scoped() {
        assert_eq!(place_field_aad_v2("name"), place_field_aad_v2("name"));
        assert_ne!(place_field_aad_v2("name"), place_field_aad_v2("location"));
        assert_ne!(place_field_aad_v2("address"), place_field_aad_v2("notes"));
    }

    #[test]
    fn place_aad_v2_cross_language_vector() {
        // Locked byte-parity vector: the web JS placeFieldAadV2("name") MUST
        // produce this exact hex or v2 place ciphertext won't cross-decrypt.
        assert_eq!(
            hex::encode(place_field_aad_v2("name")),
            "dce3922c84d3d8c5b115bab227fe56d391919c00ff693bada9f3812c8c7b5133"
        );
    }

    // SEMANTIC interop with the web client: the byte-parity vector above locks
    // the AAD *input*; this locks the FULL place-field encrypt path — place-key
    // AEAD + hex `EncryptedData{nonce,ciphertext}` framing — so a v2 place
    // ciphertext actually round-trips cross-platform. The web client writes v2
    // too, so a drift here means undecryptable place fields. Its own test suite
    // mirrors this vector.
    #[test]
    fn place_field_v2_cross_language_ciphertext_vector() {
        let key = [0x2au8; 32];
        let nonce_bytes = [0x07u8; 24];
        let plaintext = "pingolin place-v2 interop";
        let field_tag = "name";

        let cipher = XChaCha20Poly1305::new(&key.into());
        let aad = place_field_aad_v2(field_tag);
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce_bytes),
                chacha20poly1305::aead::Payload { msg: plaintext.as_bytes(), aad: &aad },
            )
            .unwrap();
        let nonce_hex = hex::encode(nonce_bytes);
        let ct_hex = hex::encode(&ct);
        // Locked: the web client's decryptWithPlaceKeyV2 MUST decrypt this exact ct.
        assert_eq!(nonce_hex, "070707070707070707070707070707070707070707070707");
        assert_eq!(
            ct_hex,
            "b3853bc39279c15188a15ac2ab53f1d45593731916554f1ac2661f61d67d41b0a139c85506e2891d44"
        );

        // Self-decrypt sanity + relocation (wrong field_tag) rejection.
        let ok = cipher
            .decrypt(&XNonce::from(nonce_bytes), chacha20poly1305::aead::Payload { msg: &ct, aad: &aad })
            .unwrap();
        assert_eq!(String::from_utf8(ok).unwrap(), plaintext);
        assert!(cipher
            .decrypt(
                &XNonce::from(nonce_bytes),
                chacha20poly1305::aead::Payload { msg: &ct, aad: &place_field_aad_v2("other") },
            )
            .is_err());
    }

    #[test]
    fn place_v2_reads_v1_legacy_ciphertext() {
        // encrypt_with_place_key always writes the v1 static AAD; the v2
        // decrypter must still read it via its fallback.
        let mgr = CryptoManager::new();
        let key = mgr.generate_place_key();
        let ct = mgr.encrypt_with_place_key(key.clone(), "hello".into()).unwrap();
        assert_eq!(mgr.decrypt_with_place_key_v2(key, ct, "name".into()).unwrap(), "hello");
    }

    #[test]
    fn place_v2_rejects_field_swap() {
        // Seal directly with the v2 field AAD; the matching tag reads it, a
        // swapped tag is refused (v2 wrong-AAD + v1 fallback also fails since
        // it wasn't sealed with the static AAD).
        let mgr = CryptoManager::new();
        let key = mgr.generate_place_key();
        let raw = hex::decode(&key).unwrap();
        let sealed = encrypt_with_raw_key_aad(&raw, b"secret-loc", &place_field_aad_v2("location")).unwrap();
        assert_eq!(
            mgr.decrypt_with_place_key_v2(key.clone(), sealed.clone(), "location".into()).unwrap(),
            "secret-loc"
        );
        assert!(mgr.decrypt_with_place_key_v2(key, sealed, "name".into()).is_err());
    }

    // ── AAD v2 (circle field) ───────────────────────────────────────────────

    #[test]
    fn circle_field_aad_v2_is_deterministic_and_scoped() {
        assert_eq!(circle_field_aad_v2("c1", "name"), circle_field_aad_v2("c1", "name"));
        assert_ne!(circle_field_aad_v2("c1", "name"), circle_field_aad_v2("c1", "timestamp")); // field
        assert_ne!(circle_field_aad_v2("c1", "name"), circle_field_aad_v2("c2", "name"));      // circle
    }

    #[test]
    fn circle_field_aad_v2_cross_language_vector() {
        // Locked byte-parity vector: the web JS circleFieldAadV2(circle,"name")
        // MUST produce this exact hex or v2 circle-field ciphertext won't
        // cross-decrypt.
        assert_eq!(
            hex::encode(circle_field_aad_v2("11111111-1111-1111-1111-111111111111", "name")),
            "d0deb693043120a8aaf335445338546cd5f9c2e7330fae2881e42bffc020fb04"
        );
    }

    #[test]
    fn circle_field_v2_reads_v1_legacy_ciphertext() {
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![9u8; 32]);
        let ct = mgr.encrypt_data(c1.clone(), "hello".into()).unwrap();
        assert_eq!(mgr.decrypt_data_v2(c1, ct, "name".into()).unwrap(), "hello");
    }

    /// The crossing-time seal, end to end under a KNOWN circle key.
    ///
    /// Every client seals the crossing/arrival time as a decimal epoch-millis
    /// STRING under field tag "occurred_at" (the Android boundary reporter and
    /// the iOS place/destination managers) and the recipient's push handler
    /// opens it with the SAME tag. The tag
    /// is AAD-bound, so if those four sites ever disagree the decrypt fails —
    /// and because the stamp is deliberately best-effort, the failure is SILENT:
    /// the notification just quietly falls back to the server's processing time,
    /// which is exactly what the stamp exists to avoid. Pin the contract so the
    /// drift is caught here instead.
    #[test]
    fn occurred_at_seal_round_trips_and_is_bound_to_its_field_tag() {
        let mgr = CryptoManager::new();
        let circle = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &circle, vec![7u8; 32]);

        // What the reporting client actually sends: epoch millis as a string.
        let occurred_at_ms = "1753862745123";
        let sealed = mgr
            .encrypt_data_v2(circle.clone(), occurred_at_ms.into(), "occurred_at".into())
            .unwrap();

        // The recipient opens it with the same tag and parses it back.
        let opened = mgr
            .decrypt_data_v2(circle.clone(), sealed.clone(), "occurred_at".into())
            .unwrap();
        assert_eq!(opened, occurred_at_ms);
        assert_eq!(
            opened.parse::<i64>().unwrap(),
            1753862745123i64,
            "must survive as an i64 epoch-millis"
        );

        // A tag mismatch must FAIL rather than yield a wrong time.
        assert!(
            mgr.decrypt_data_v2(circle.clone(), sealed.clone(), "timestamp".into()).is_err(),
            "a different field tag must not open the crossing time"
        );

        // And another circle cannot read it even holding identical key bytes.
        let other = "22222222-2222-2222-2222-222222222222".to_string();
        insert_test_circle_key(&mgr, &other, vec![7u8; 32]);
        assert!(
            mgr.decrypt_data_v2(other, sealed, "occurred_at".into()).is_err(),
            "the seal must be bound to the circle, not just the key bytes"
        );
    }

    #[test]
    fn circle_field_v2_rejects_field_and_circle_swap() {
        // Uses an id-bound field ("timestamp"): the circle NAME is
        // field-only (see circle_name_field_only_survives_temp_to_real_remap), so its
        // cross-circle binding is enforced by the per-circle KEY, not the AAD.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let key = vec![9u8; 32];
        insert_test_circle_key(&mgr, &c1, key.clone());
        // Seal directly with the v2 AAD.
        let sealed = encrypt_with_raw_key_aad(&key, b"alice", &circle_field_aad_v2(&c1, "timestamp")).unwrap();
        assert_eq!(mgr.decrypt_data_v2(c1.clone(), sealed.clone(), "timestamp".into()).unwrap(), "alice");
        // wrong field tag → reject
        assert!(mgr.decrypt_data_v2(c1.clone(), sealed.clone(), "user_id".into()).is_err());
        // wrong circle (SAME key bytes, different circle_id in the AAD) → reject
        let c2 = "22222222-2222-2222-2222-222222222222".to_string();
        insert_test_circle_key(&mgr, &c2, key.clone());
        assert!(mgr.decrypt_data_v2(c2, sealed, "timestamp".into()).is_err());
    }

    #[test]
    fn circle_name_field_only_survives_temp_to_real_remap() {
        // The name is sealed under a throwaway temp circle id, then
        // finalize_circle_creation remaps the KEY (not the ciphertext) to the
        // real id. An id-bound AAD therefore never matches again and every
        // circle renders as "Encrypted Circle"; the field-only "name" AAD
        // decrypts regardless of the id. This test fails under id-bound routing.
        let mgr = CryptoManager::new();
        let temp = "temp_abcdef0123456789".to_string();
        insert_test_circle_key(&mgr, &temp, vec![7u8; 32]);
        let ct = mgr.encrypt_data_v2(temp.clone(), "Family".into(), "name".into()).unwrap();
        let real = "33333333-3333-3333-3333-333333333333".to_string();
        mgr.finalize_circle_creation(temp.clone(), real.clone()).unwrap();
        assert_eq!(mgr.decrypt_data_v2(real, ct, "name".into()).unwrap(), "Family");
    }

    #[test]
    fn circle_name_write_is_field_only_only_for_temp_id() {
        // WRITE: field-only ONLY for a circle-create name (temp_ id); id-bound
        // for a real circle id (place names, circle renames) and other fields.
        assert_eq!(circle_field_write_aad_v2("temp_abc", "name"), circle_field_aad_v2("", "name"));
        assert_eq!(circle_field_write_aad_v2("real-id", "name"), circle_field_aad_v2("real-id", "name"));
        assert_ne!(circle_field_write_aad_v2("real-id", "name"), circle_field_aad_v2("", "name"));
        // READ: "name" accepts BOTH field-only and id-bound; others id-bound only.
        let name_aads = circle_field_read_aads_v2("c1", "name");
        assert!(name_aads.contains(&circle_field_aad_v2("", "name")));
        assert!(name_aads.contains(&circle_field_aad_v2("c1", "name")));
        assert_eq!(circle_field_read_aads_v2("c1", "timestamp"), vec![circle_field_aad_v2("c1", "timestamp")]);
        // Locked byte-parity vector: the web client's circleFieldAadV2('', 'name')
        // MUST produce this exact hex.
        assert_eq!(
            hex::encode(circle_field_aad_v2("", "name")),
            "7e7b1066902e1ae6cbcbbe83faaf2e421119d5195af7f86b053bacc112fd2bf0"
        );
    }

    #[test]
    fn place_name_stays_id_bound_and_readable() {
        // A PLACE name uses tag "name" under a REAL circle id (not temp_), so it
        // must stay id-bound — making it field-only would break existing id-bound
        // place names + their geofence alerts. Write id-bound, read via the
        // 3-way "name" fallback; a different circle (different key) can't read it.
        let mgr = CryptoManager::new();
        let circle = "44444444-4444-4444-4444-444444444444".to_string();
        insert_test_circle_key(&mgr, &circle, vec![3u8; 32]);
        let ct = mgr.encrypt_data_v2(circle.clone(), "Home".into(), "name".into()).unwrap();
        assert_eq!(mgr.decrypt_data_v2(circle.clone(), ct.clone(), "name".into()).unwrap(), "Home");
        let other = "55555555-5555-5555-5555-555555555555".to_string();
        insert_test_circle_key(&mgr, &other, vec![9u8; 32]);
        assert!(mgr.decrypt_data_v2(other, ct, "name".into()).is_err());
    }

    #[test]
    fn window_sealed_id_bound_name_still_readable() {
        // A "name" sealed id-bound by an older writer (a place name, or a circle
        // rename) must still decrypt with the field-only routing — the 3-way read
        // recovers it.
        let mgr = CryptoManager::new();
        let circle = "44444444-4444-4444-4444-444444444444".to_string();
        let key = vec![3u8; 32];
        insert_test_circle_key(&mgr, &circle, key.clone());
        let sealed = encrypt_with_raw_key_aad(&key, b"Work", &circle_field_aad_v2(&circle, "name")).unwrap();
        assert_eq!(mgr.decrypt_data_v2(circle, sealed, "name".into()).unwrap(), "Work");
    }

    // ── AAD v2 readers (boundary alerts) ──────────────────────────────────

    #[test]
    fn circle_field_v2_write_is_unreadable_by_v1_reader() {
        // The boundary-alert hazard at the crypto layer: with
        // AAD_V2_WRITE_ENABLED, encrypt_data_v2 seals with the bound circle-field
        // AAD, so a v1-only reader (plain decrypt_data, empty AAD) cannot read
        // it while the v2 reader can. A reader that reaches for decrypt_data
        // here silently skips the place and never arms the geofence.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);

        let v2_ct = mgr
            .encrypt_data_v2(c1.clone(), "place-name".into(), "name".into())
            .unwrap();

        // A v1-only read path fails on it.
        assert!(mgr.decrypt_data(c1.clone(), v2_ct.clone()).is_err());
        // The v2 reader used by boundary_monitor + decrypt_location reads it.
        assert_eq!(
            mgr.decrypt_data_v2(c1.clone(), v2_ct, "name".into()).unwrap(),
            "place-name"
        );

        // Back-compat: a v1-written value still decrypts through the v2 reader.
        let v1_ct = mgr.encrypt_data(c1.clone(), "legacy-name".into()).unwrap();
        assert_eq!(
            mgr.decrypt_data_v2(c1, v1_ct, "name".into()).unwrap(),
            "legacy-name"
        );
    }

    #[test]
    fn decrypt_location_reads_both_v2_and_v1_writes() {
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let loc = test_location();
        let loc_json = serde_json::to_string(&loc).unwrap();

        // v2 write: "location" field sealed with the bound v2 AAD.
        let v2_ct = mgr
            .encrypt_data_v2(c1.clone(), loc_json, "location".into())
            .unwrap();
        let read_v2 = mgr.decrypt_location(c1.clone(), v2_ct).unwrap();
        assert_eq!(read_v2.latitude, loc.latitude);
        assert_eq!(read_v2.longitude, loc.longitude);

        // Legacy v1 write (encrypt_location → encrypt_data, empty AAD) still reads.
        let v1_ct = mgr.encrypt_location(c1.clone(), loc.clone()).unwrap();
        let read_v1 = mgr.decrypt_location(c1, v1_ct).unwrap();
        assert_eq!(read_v1.latitude, loc.latitude);
        assert_eq!(read_v1.longitude, loc.longitude);
    }

    #[tokio::test]
    async fn boundary_monitor_loads_v2_and_v1_place_fields() {
        // End to end: a place whose name/location were written with the v2 field
        // AADs must not be silently skipped by load_encrypted_places — a count of
        // 0 means the geofence is never armed and alerts stop firing, with no
        // error anywhere. A legacy v1 place must still load too.
        use crate::boundary_monitor::{BoundaryMonitor, EncryptedPlace};

        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let loc_json = serde_json::to_string(&test_location()).unwrap();

        let v2_place = EncryptedPlace {
            id: "place-v2".to_string(),
            circle_id: Some(c1.clone()),
            encrypted_name: mgr
                .encrypt_data_v2(c1.clone(), "Home".into(), "name".into())
                .unwrap(),
            encrypted_location: mgr
                .encrypt_data_v2(c1.clone(), loc_json.clone(), "location".into())
                .unwrap(),
            radius_meters: 100,
        };
        let v1_place = EncryptedPlace {
            id: "place-v1".to_string(),
            circle_id: Some(c1.clone()),
            encrypted_name: mgr.encrypt_data(c1.clone(), "Work".into()).unwrap(),
            encrypted_location: mgr.encrypt_data(c1.clone(), loc_json).unwrap(),
            radius_meters: 100,
        };

        // CryptoManager::new() already returns Arc<CryptoManager>.
        let monitor = BoundaryMonitor::new(mgr);
        let count = monitor
            .load_encrypted_places(vec![v2_place, v1_place])
            .await
            .unwrap();
        assert_eq!(count, 2);
    }

    // ── AAD v2 (location envelope + msg_key wrap) ────────────────────────────

    fn test_location() -> Location {
        Location {
            latitude: 51.5074,
            longitude: -0.1278,
            altitude: None,
            speed: None,
            heading: None,
            accuracy: None,
            timestamp: 1_700_000_000_000,
            battery_level: None,
            is_charging: None,
        }
    }

    #[test]
    fn location_and_wrap_aad_v2_are_deterministic_and_scoped() {
        assert_eq!(location_aad_v2(), location_aad_v2());
        assert_eq!(msg_key_wrap_aad_v2("c1"), msg_key_wrap_aad_v2("c1"));
        assert_ne!(msg_key_wrap_aad_v2("c1"), msg_key_wrap_aad_v2("c2")); // target
        // A location payload AAD must never collide with a wrap AAD.
        assert_ne!(location_aad_v2().to_vec(), msg_key_wrap_aad_v2("").to_vec());
    }

    #[test]
    fn location_aad_v2_cross_language_vector() {
        // Locked byte-parity vectors: the web JS locationAadV2() and
        // msgKeyWrapAadV2(circle) MUST produce these exact hex strings or v2
        // envelope ciphertext won't cross-decrypt.
        assert_eq!(
            hex::encode(location_aad_v2()),
            "4924f6d7049bfe7e0b80767e0b68c45a3b54ee0d33612d720c485aede8b17ac6"
        );
        assert_eq!(
            hex::encode(msg_key_wrap_aad_v2("11111111-1111-1111-1111-111111111111")),
            "ef0100b3f0ede73eb6bdc418663db2f49bbd95e1d121b18976565c979fb4bf97"
        );
    }

    #[test]
    fn location_v2_round_trips() {
        // Write path with AAD_V2_WRITE_ENABLED == true → v2 reader.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let env = mgr
            .envelope_encrypt_location_v2(test_location(), vec![c1.clone()])
            .unwrap();
        let wrap = &env.key_wraps[0];
        let loc = mgr
            .unwrap_and_decrypt_location_v2(
                c1,
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                env.ciphertext.clone(),
                env.ciphertext_nonce.clone(),
            )
            .unwrap();
        assert_eq!(loc.latitude, 51.5074);
        assert_eq!(loc.longitude, -0.1278);
    }

    #[test]
    fn location_v2_reads_v1_legacy_envelope() {
        // v1 write (empty AAD, via envelope_encrypt_location) must still decrypt
        // through the v2 reader's fallback.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let env = mgr
            .envelope_encrypt_location(test_location(), vec![c1.clone()])
            .unwrap();
        let wrap = &env.key_wraps[0];
        let loc = mgr
            .unwrap_and_decrypt_location_v2(
                c1,
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                env.ciphertext.clone(),
                env.ciphertext_nonce.clone(),
            )
            .unwrap();
        assert_eq!(loc.latitude, 51.5074);
    }

    // ── AAD v2 (place ENVELOPE) — mirrors the location v2 envelope ───────────

    #[test]
    fn place_envelope_aad_v2_is_deterministic_and_domain_separated() {
        assert_eq!(place_aad_v2(), place_aad_v2());
        // A DISTINCT domain from the location envelope, the per-FIELD place path,
        // and the wrap AAD — so a place blob can never be opened as any of those.
        assert_ne!(place_aad_v2().to_vec(), location_aad_v2().to_vec());
        assert_ne!(place_aad_v2().to_vec(), place_field_aad_v2("").to_vec());
        assert_ne!(place_aad_v2().to_vec(), place_field_aad_v2("name").to_vec());
        assert_ne!(place_aad_v2().to_vec(), msg_key_wrap_aad_v2("").to_vec());
    }

    #[test]
    fn place_envelope_aad_v2_cross_language_vector() {
        // LOCKED byte-parity vector — the web JS placeAadV2() and the iOS/Android
        // clients MUST produce this exact hex, or a v2 place envelope won't
        // cross-decrypt. Framing:
        //   AAD = aad_v2_context("pingolin.aad.v2.place_envelope", "", 0, "", "")
        //       = LP("") || u32_le(0) || LP("") || LP(""), keyed_hash under
        //         derive_key("pingolin.aad.v2.context", "pingolin.aad.v2.place_envelope").
        let vector = hex::encode(place_aad_v2());
        println!("LOCKED place_aad_v2() = {vector}");
        assert_eq!(
            vector,
            "d0f4d5c25a86eeb2130290399c50c71f14aa1a801c7286e37383c7dcc4cc553f"
        );
    }

    #[test]
    fn place_envelope_v2_round_trips() {
        // Write path with AAD_V2_WRITE_ENABLED == true → v2 reader.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let plaintext = "{\"name\":\"Home\",\"lat\":51.5,\"lng\":-0.12}";
        let env = mgr
            .envelope_encrypt_place(plaintext.to_string(), vec![c1.clone()])
            .unwrap();
        let wrap = &env.key_wraps[0];
        let out = mgr
            .unwrap_and_decrypt_place(
                c1,
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                env.ciphertext.clone(),
                env.ciphertext_nonce.clone(),
            )
            .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn place_envelope_v2_reads_v1_legacy() {
        // A legacy (v1, empty-AAD) place envelope — exactly what
        // envelope_encrypt_place produces with the v2 write flag off (empty-AAD
        // wrap + empty-AAD payload) — MUST still decrypt through the v2 reader's
        // fallback.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let circle_key = [7u8; 32];
        insert_test_circle_key(&mgr, &c1, circle_key.to_vec());

        let place_key = [0x2au8; 32];
        let plaintext = "legacy place blob";

        // Empty-AAD wrap of the place key under the circle key (what
        // `wrap_msg_key` produces).
        let wcipher = XChaCha20Poly1305::new(&circle_key.into());
        let wnonce = [0x11u8; 24];
        let wrapped = wcipher
            .encrypt(&XNonce::from(wnonce), place_key.as_ref())
            .unwrap();
        // Empty-AAD payload seal under the place key (plain `cipher.encrypt`).
        let pcipher = XChaCha20Poly1305::new(&place_key.into());
        let pnonce = [0x22u8; 24];
        let ct = pcipher
            .encrypt(&XNonce::from(pnonce), plaintext.as_bytes())
            .unwrap();

        let out = mgr
            .unwrap_and_decrypt_place(
                c1,
                hex::encode(&wrapped),
                hex::encode(wnonce),
                hex::encode(&ct),
                hex::encode(pnonce),
            )
            .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn place_envelope_v2_does_not_decrypt_as_location() {
        // Domain separation, end-to-end: a v2 place envelope fed to the LOCATION
        // v2 reader MUST fail. The wrap AAD is shared (msg_key_wrap_aad_v2), so the
        // place key unwraps — but the payload was sealed under place_aad_v2(), so
        // neither location_aad_v2() nor the v1 empty-AAD fallback opens it. Fails
        // closed (Err), never surfaces the blob as a location.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let env = mgr
            .envelope_encrypt_place("{\"lat\":1.0}".to_string(), vec![c1.clone()])
            .unwrap();
        let wrap = &env.key_wraps[0];
        let as_location = mgr.unwrap_and_decrypt_location_v2(
            c1,
            wrap.wrapped_key.clone(),
            wrap.wrapped_key_nonce.clone(),
            env.ciphertext.clone(),
            env.ciphertext_nonce.clone(),
        );
        assert!(as_location.is_err(), "a place blob must not open as a location");
    }

    // ── Location sender-binding (AAD v3) ─────────────────────────────────────

    #[test]
    fn location_aad_v3_is_deterministic_and_sender_scoped() {
        // Deterministic, and distinct per sender pseudonym — the whole point:
        // a relabel to a different pseudonym yields a different AAD, so the tag
        // fails on read.
        assert_eq!(location_aad_v3("user-a"), location_aad_v3("user-a"));
        assert_ne!(location_aad_v3("user-a"), location_aad_v3("user-b"));
        // v3 must never collide with the domain-only v2 or a wrap AAD.
        assert_ne!(location_aad_v3("").to_vec(), location_aad_v2().to_vec());
        assert_ne!(location_aad_v3("x").to_vec(), msg_key_wrap_aad_v2("x").to_vec());
    }

    #[test]
    fn location_aad_v3_cross_language_vector() {
        // LOCKED byte-parity vector — the web JS locationAadV3(pseudonym) and the
        // iOS/Android clients MUST produce this exact hex for USER pseudonym
        // "testpseudo123", or a bound v3 location won't cross-decrypt and
        // relabel-detection desyncs across platforms. The framing is identical
        // regardless of what the pseudonym string means (it is just
        // hash(domain, pseudonym)); this publishes the vector for the fixed input.
        //   AAD = aad_v2_context("pingolin.aad.v3.location", "testpseudo123", 0, "", "")
        //       = LP("testpseudo123") || u32_le(0) || LP("") || LP(""), keyed_hash
        //         under derive_key("pingolin.aad.v2.context", "pingolin.aad.v3.location").
        let vector = hex::encode(location_aad_v3("testpseudo123"));
        println!("LOCKED location_aad_v3(\"testpseudo123\") = {vector}");
        assert_eq!(
            vector,
            "712a74a6dd5e773df27e1408c00190b8ea0e7fd4dbe4b61dbce768ff856c631e"
        );
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn location_bound_round_trips_and_blocks_relabel() {
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let loc = test_location();
        let sender = "user-pseudo-A".to_string();

        let ct = mgr
            .encrypt_location_bound(c1.clone(), loc.clone(), sender.clone())
            .unwrap();

        // Correct claimed pseudonym → v3 tag verifies → sender_verified = true.
        let ok = mgr
            .decrypt_location_bound(c1.clone(), ct.clone(), sender.clone())
            .unwrap();
        assert!(ok.sender_verified);
        assert_eq!(ok.location.latitude, loc.latitude);
        assert_eq!(ok.location.longitude, loc.longitude);

        // Server relabel: same ciphertext presented under a DIFFERENT claimed
        // pseudonym. The v3 tag fails, and the unbound v2/v1 fallback ALSO fails
        // (the ciphertext was sealed with the v3 AAD), so decrypt MUST error —
        // it must NOT surface the plaintext as unverified: instead of
        // mislabeling A's location as B's, the reader gets nothing.
        // (NB: `sender_verified = false` on a wrong pseudonym applies to LEGACY
        // unbound ciphertext — see the next test — NOT to a v3-sealed one, where
        // the fallback can't read it → error.)
        let relabelled =
            mgr.decrypt_location_bound(c1.clone(), ct, "user-pseudo-B".to_string());
        assert!(relabelled.is_err(), "a relabelled v3 location must not decrypt");
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn location_bound_reads_legacy_v2_and_v1_as_unverified() {
        // Ciphertext written before sender-binding existed carries none: the v3 tag can't
        // match, so decrypt_location_bound falls back to the existing v2-then-v1
        // reader and returns sender_verified = false (authentic circle data,
        // server-asserted sender). Proven for BOTH a v2 "location"-field write
        // and a v1 empty-AAD write.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let loc = test_location();
        let loc_json = serde_json::to_string(&loc).unwrap();

        // Legacy v2: sealed with the bound circle-field "location" AAD.
        let v2_ct = mgr
            .encrypt_data_v2(c1.clone(), loc_json, "location".into())
            .unwrap();
        let v2_out = mgr
            .decrypt_location_bound(c1.clone(), v2_ct, "any-pseudonym".into())
            .unwrap();
        assert!(!v2_out.sender_verified);
        assert_eq!(v2_out.location.latitude, loc.latitude);

        // Legacy v1: empty-AAD write via encrypt_location.
        let v1_ct = mgr.encrypt_location(c1.clone(), loc.clone()).unwrap();
        let v1_out = mgr
            .decrypt_location_bound(c1, v1_ct, "any-pseudonym".into())
            .unwrap();
        assert!(!v1_out.sender_verified);
        assert_eq!(v1_out.location.longitude, loc.longitude);
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader (shows its hazard)
    fn location_bound_for_user_survives_circle_key_rotation() {
        // Cross-rotation: a v3 sender-bound row sealed under circle-key v1 must
        // still verify after the circle key rotates to v2. The sender pseudonym is
        // a function of the circle KEY, so the active-only reader (which derives it
        // from the ACTIVE v2 key) can no longer match the v1-sealed row; the
        // per-version reader re-derives under each held version and finds v1.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let user_id = "22222222-2222-2222-2222-222222222222".to_string();

        // v1 is active: derive the sender pseudonym under v1 and seal a bound row.
        insert_test_circle_key(&mgr, &c1, vec![7u8; 32]);
        let pseudo_v1 = mgr.derive_user_pseudonym(c1.clone(), user_id.clone()).unwrap();
        let loc = test_location();
        let ct = mgr
            .encrypt_location_bound(c1.clone(), loc.clone(), pseudo_v1.clone())
            .unwrap();

        // Rotate: v2 becomes active. The pseudonym derived under v2 differs from v1.
        rotate_test_circle_key(&mgr, &c1, 2, vec![8u8; 32]);
        let pseudo_v2 = mgr.derive_user_pseudonym(c1.clone(), user_id.clone()).unwrap();
        assert_ne!(pseudo_v1, pseudo_v2, "rotation must change the derived pseudonym");

        // Active-only path: the reader derives the pseudonym under the ACTIVE
        // (v2) key, which no longer matches the v1-sealed row. v3 fails under every
        // version (v2 key mismatch; v1 key matches but the AAD carries P_v2 ≠ P_v1)
        // and the unbound v2/v1 fallback can't read a v3-sealed payload ⇒ it MUST
        // NOT return sender_verified = true (here it errors — the relabel-drop
        // path). That is the hazard: a superseded-version row is silently dropped.
        let active_only = mgr.decrypt_location_bound(c1.clone(), ct.clone(), pseudo_v2);
        match active_only {
            Ok(b) => assert!(
                !b.sender_verified,
                "active-only reader must not verify a pre-rotation row"
            ),
            Err(_) => { /* dropped — also acceptable (no plaintext surfaced) */ }
        }

        // Per-version path: re-derives the pseudonym under each held version and
        // finds v1 ⇒ authentic sender attribution survives the rotation.
        let fixed = mgr
            .decrypt_location_bound_for_user(c1.clone(), ct, user_id)
            .unwrap();
        assert!(
            fixed.sender_verified,
            "per-version reader must verify the v1-sealed row after rotation"
        );
        assert_eq!(fixed.location.latitude, loc.latitude);
        assert_eq!(fixed.location.longitude, loc.longitude);
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn location_bound_session_key_round_trips() {
        // The genuine session-key path ("s:{uuid}"): create a session key, seal a
        // bound location under it, and verify the sender on read.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![9u8; 32]);
        mgr.create_session_key(c1.clone(), 3600).unwrap();
        let loc = test_location();
        let sender = "user-pseudo-S".to_string();

        let sealed = mgr
            .encrypt_location_with_session_key_bound(c1.clone(), loc.clone(), sender.clone())
            .unwrap();
        assert!(sealed.key_id.starts_with("s:"), "expected session key id, got {}", sealed.key_id);

        let ok = mgr
            .decrypt_location_with_session_key_bound(
                c1.clone(),
                sealed.encrypted.clone(),
                sealed.key_id.clone(),
                sender,
            )
            .unwrap();
        assert!(ok.sender_verified);
        assert_eq!(ok.location.latitude, loc.latitude);

        // Wrong claimed pseudonym → v3 fails, empty-AAD fallback fails → error.
        let relabelled = mgr.decrypt_location_with_session_key_bound(
            c1,
            sealed.encrypted,
            sealed.key_id,
            "user-pseudo-WRONG".into(),
        );
        assert!(relabelled.is_err(), "relabelled session location must not decrypt");
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn location_bound_session_key_circle_fallback_round_trips() {
        // No session key present → encrypt_location_with_session_key_bound falls
        // back to the circle key ("c:{version}"); the bound decrypt resolves that
        // version and still verifies the sender.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![3u8; 32]);
        let loc = test_location();
        let sender = "user-pseudo-C".to_string();

        let sealed = mgr
            .encrypt_location_with_session_key_bound(c1.clone(), loc.clone(), sender.clone())
            .unwrap();
        assert_eq!(sealed.key_id, "c:1", "expected circle-key fallback id");

        let ok = mgr
            .decrypt_location_with_session_key_bound(c1, sealed.encrypted, sealed.key_id, sender)
            .unwrap();
        assert!(ok.sender_verified);
        assert_eq!(ok.location.timestamp, loc.timestamp);
    }

    /// Send side on its own: whatever raised the active version (here the
    /// map is written directly, as a reload or a merge of the stored keys can do
    /// without passing through `store_circle_key`), a session key published under
    /// an older version is never used to send — it is dropped and the circle key
    /// takes over.
    #[test]
    fn stale_session_key_is_never_used_to_send() {
        let m = CryptoManager::new();
        m.generate_keypair();
        insert_test_circle_key(&m, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", vec![1u8; 32]);
        let circle = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string();
        let sk = m.create_session_key(circle.clone(), 3600).unwrap();
        assert_eq!(sk.key_version, 1);
        assert!(m.has_active_session_key(circle.clone()));
        assert!(m.encrypt_timestamp_with_session_key(circle.clone(), 1).unwrap().key_id.starts_with("s:"));

        rotate_test_circle_key(&m, &circle, 2, vec![2u8; 32]);
        assert!(!m.has_active_session_key(circle.clone()), "a v1 session key is not active under v2");
        let sent = m.encrypt_timestamp_with_session_key(circle.clone(), 2).unwrap();
        assert_eq!(sent.key_id, "c:2");
        assert!(m.sender_session_keys.read().unwrap().get(&CircleKey::of(&circle)).is_none(), "the stale key is dropped");
    }

    /// Test helper: hand `b` the session key `a` just published, exactly as the
    /// apps do — the server round-trips the BARE `session_key_id`, so that is
    /// what `import_peer_session_key` is given. Returns that bare id.
    fn share_session_key(a: &CryptoManager, b: &CryptoManager, circle_id: &str) -> String {
        let published = a.create_session_key(circle_id.to_string(), 3600).unwrap();
        b.import_peer_session_key(
            circle_id.to_string(),
            published.session_key_id.clone(),
            published.encrypted_session_key,
            published.key_nonce,
            published.key_version,
            published.expires_at,
        )
        .unwrap();
        published.session_key_id
    }

    #[test]
    fn peer_session_key_pre_check_accepts_both_id_forms() {
        // The cache is keyed by the server's BARE uuid, but rows carry the routing
        // form "s:{uuid}". A VERBATIM lookup in has_peer_session_key would answer
        // false for every id a row actually carries.
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let a = CryptoManager::new();
        let b = CryptoManager::new();
        insert_test_circle_key(&a, &c1, vec![7u8; 32]);
        insert_test_circle_key(&b, &c1, vec![7u8; 32]);

        let bare = share_session_key(&a, &b, &c1);
        assert!(!bare.starts_with("s:"), "server issues a bare uuid, got {bare}");

        assert!(
            b.has_peer_session_key(bare.clone()),
            "bare id must resolve — it is how the cache is keyed"
        );
        assert!(
            b.has_peer_session_key(format!("s:{bare}")),
            "prefixed id must resolve too — it is what a row's key_id carries"
        );

        // Still fails closed on an id we genuinely do not hold, in either form.
        let unknown = "22222222-2222-2222-2222-222222222222";
        assert!(!b.has_peer_session_key(unknown.to_string()));
        assert!(!b.has_peer_session_key(format!("s:{unknown}")));
    }

    #[test]
    fn peer_session_key_pre_check_agrees_with_the_decrypt_resolver() {
        // The pre-check and resolve_decryption_key read the same map; they must
        // never disagree, because track-ios GATES the decrypt on the pre-check.
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let a = CryptoManager::new();
        let b = CryptoManager::new();
        insert_test_circle_key(&a, &c1, vec![7u8; 32]);
        insert_test_circle_key(&b, &c1, vec![7u8; 32]);

        let bare = share_session_key(&a, &b, &c1);
        let row_key_id = format!("s:{bare}");

        // Held: pre-check says yes AND the resolver hands back the key.
        assert!(b.has_peer_session_key(row_key_id.clone()));
        let resolved = b.resolve_decryption_key(&c1, &row_key_id).unwrap();
        // Both id forms resolve to the identical key material.
        let resolved_bare = b
            .with_peer_session_key(&c1, &bare, |cached| cached.key.clone())
            .expect("bare id resolves");
        assert!(resolved.as_slice() == resolved_bare.as_slice(), "both id forms, one key");

        // Not held: pre-check says no AND the resolver errors. Same verdict.
        let missing = "s:22222222-2222-2222-2222-222222222222";
        assert!(!b.has_peer_session_key(missing.to_string()));
        assert!(matches!(
            b.resolve_decryption_key(&c1, missing),
            Err(MobileError::SessionKeyNotFound(_))
        ));
    }

    #[test]
    fn imported_peer_session_key_opens_the_row_its_pre_check_gates() {
        // End-to-end in the shape track-ios uses: A seals a bound location under
        // its session key, B imports that key under the bare id, then B gates the
        // decrypt on has_peer_session_key(row.key_id). If that gate answered
        // false, the else branch would win and the row would be dropped as "key
        // missing".
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        let user = "user-A".to_string();
        let a = CryptoManager::new();
        let b = CryptoManager::new();
        insert_test_circle_key(&a, &c1, vec![7u8; 32]);
        insert_test_circle_key(&b, &c1, vec![7u8; 32]);

        share_session_key(&a, &b, &c1);
        let loc = test_location();
        let pseudonym = a.derive_user_pseudonym(c1.clone(), user.clone()).unwrap();
        let sealed = a
            .encrypt_location_with_session_key_bound(c1.clone(), loc.clone(), pseudonym)
            .unwrap();
        assert!(sealed.key_id.starts_with("s:"), "expected a session row, got {}", sealed.key_id);

        assert!(
            b.has_peer_session_key(sealed.key_id.clone()),
            "the gate must pass for a row whose key we imported"
        );
        let bound = b
            .decrypt_location_with_session_key_bound_for_user(
                c1,
                sealed.encrypted,
                sealed.key_id,
                user,
            )
            .unwrap();
        assert!(bound.sender_verified);
        assert_eq!(bound.location.latitude, loc.latitude);
        assert_eq!(bound.location.longitude, loc.longitude);
    }

    /// Every row shape a device reads, sealed under the circle's key in use.
    struct RowsUnder {
        bound: EncryptedData,
        legacy: EncryptedData,
        envelope: EnvelopeEncryptedLocation,
        session: SessionEncryptedData,
        circle_keyed: SessionEncryptedData,
        field: EncryptedData,
        field_v1: EncryptedData,
        place_wrap: KeyWrap,
        place: EnvelopeEncryptedLocation,
    }

    fn rows_under(mgr: &CryptoManager, circle: &str, user: &str, place_key: &str) -> RowsUnder {
        let loc = test_location();
        let pseudonym = mgr.derive_user_pseudonym(circle.into(), user.into()).unwrap();
        // "c:N": before any session key exists, the circle key seals it.
        let circle_keyed = mgr.encrypt_location_with_session_key_bound(circle.into(), loc.clone(), pseudonym.clone()).unwrap();
        mgr.create_session_key(circle.into(), 3600).unwrap();
        let session = mgr.encrypt_location_with_session_key_bound(circle.into(), loc.clone(), pseudonym.clone()).unwrap();
        mgr.invalidate_session_keys_for_circle(circle.into());
        RowsUnder {
            bound: mgr.encrypt_location_bound(circle.into(), loc.clone(), pseudonym.clone()).unwrap(),
            legacy: mgr.encrypt_location(circle.into(), loc.clone()).unwrap(),
            envelope: mgr.envelope_encrypt_location_bound(loc.clone(), vec![circle.into()], pseudonym.clone()).unwrap(),
            session,
            circle_keyed,
            field: mgr.encrypt_data_v2(circle.into(), "1790300000000".into(), "timestamp".into()).unwrap(),
            field_v1: mgr.encrypt_data(circle.into(), "a rule".into()).unwrap(),
            place_wrap: mgr.wrap_place_key(circle.into(), place_key.into(), user.into(), "p1".into()).unwrap(),
            place: mgr.envelope_encrypt_place("a place".into(), vec![circle.into()]).unwrap(),
        }
    }

    /// The version each reader reports for `rows`, in one list.
    #[allow(deprecated)]
    fn versions_read(mgr: &CryptoManager, circle: &str, user: &str, rows: &RowsUnder, pseudonym_then: &str) -> Vec<(&'static str, i32)> {
        let c = || circle.to_string();
        let envelope = &rows.envelope.key_wraps[0];
        let place = &rows.place.key_wraps[0];
        let opened_field = mgr.decrypt_data_v2_opened(c(), rows.field.clone(), "timestamp".into()).unwrap();
        assert_eq!(opened_field.text, mgr.decrypt_data_v2(c(), rows.field.clone(), "timestamp".into()).unwrap(), "the same text as decrypt_data_v2");
        vec![
            ("circle v3", mgr.decrypt_location_bound_for_user(c(), rows.bound.clone(), user.into()).unwrap().key_version),
            ("circle v3, one pseudonym", mgr.decrypt_location_bound(c(), rows.bound.clone(), pseudonym_then.into()).unwrap().key_version),
            ("circle legacy", mgr.decrypt_location_bound_for_user(c(), rows.legacy.clone(), user.into()).unwrap().key_version),
            ("circle legacy, one pseudonym", mgr.decrypt_location_bound(c(), rows.legacy.clone(), pseudonym_then.into()).unwrap().key_version),
            (
                "envelope",
                mgr.unwrap_and_decrypt_location_bound_for_user(
                    c(), envelope.wrapped_key.clone(), envelope.wrapped_key_nonce.clone(), rows.envelope.ciphertext.clone(), rows.envelope.ciphertext_nonce.clone(), user.into(),
                )
                .unwrap()
                .key_version,
            ),
            (
                "envelope, one pseudonym",
                mgr.unwrap_and_decrypt_location_bound(
                    c(), envelope.wrapped_key.clone(), envelope.wrapped_key_nonce.clone(), rows.envelope.ciphertext.clone(), rows.envelope.ciphertext_nonce.clone(), pseudonym_then.into(),
                )
                .unwrap()
                .key_version,
            ),
            ("session", mgr.decrypt_location_with_session_key_bound_for_user(c(), rows.session.encrypted.clone(), rows.session.key_id.clone(), user.into()).unwrap().key_version),
            ("session, one pseudonym", mgr.decrypt_location_with_session_key_bound(c(), rows.session.encrypted.clone(), rows.session.key_id.clone(), pseudonym_then.into()).unwrap().key_version),
            ("c:N", mgr.decrypt_location_with_session_key_bound_for_user(c(), rows.circle_keyed.encrypted.clone(), rows.circle_keyed.key_id.clone(), user.into()).unwrap().key_version),
            ("location twin", mgr.decrypt_location_opened(c(), rows.legacy.clone()).unwrap().key_version),
            ("field twin", opened_field.key_version),
            ("v1 twin", mgr.decrypt_data_opened(c(), rows.field_v1.clone()).unwrap().key_version),
            ("place key twin", mgr.unwrap_place_key_opened(c(), rows.place_wrap.wrapped_key.clone(), rows.place_wrap.wrapped_key_nonce.clone()).unwrap().key_version),
            (
                "place twin",
                mgr.unwrap_and_decrypt_place_opened(c(), place.wrapped_key.clone(), place.wrapped_key_nonce.clone(), rows.place.ciphertext.clone(), rows.place.ciphertext_nonce.clone())
                    .unwrap()
                    .key_version,
            ),
        ]
    }

    #[test]
    fn the_opening_version_is_reported() {
        // A key a removed member still holds opens rows that look fresh. So
        // every reader reports the version that opened a row, and only the
        // version this device seals under is CURRENT.
        let mgr = CryptoManager::new();
        mgr.generate_keypair();
        let circle = "11111111-1111-4111-8111-111111111111";
        let user = "a1a1a1a1-0000-4000-8000-0000000000aa";
        let place_key = hex::encode([0x61u8; 32]);
        insert_test_circle_key(&mgr, circle, vec![1u8; 32]);
        let pseudonym_v1 = mgr.derive_user_pseudonym(circle.into(), user.into()).unwrap();
        let under_v1 = rows_under(&mgr, circle, user, &place_key);
        rotate_test_circle_key(&mgr, circle, 2, vec![2u8; 32]);
        let pseudonym_v2 = mgr.derive_user_pseudonym(circle.into(), user.into()).unwrap();
        let under_v2 = rows_under(&mgr, circle, user, &place_key);
        for (reader, version) in versions_read(&mgr, circle, user, &under_v1, &pseudonym_v1) {
            assert_eq!(version, 1, "{reader}: a v1 row reports v1");
        }
        for (reader, version) in versions_read(&mgr, circle, user, &under_v2, &pseudonym_v2) {
            assert_eq!(version, 2, "{reader}: a v2 row reports v2");
        }
        // Only the version this device seals under is current: not the retired
        // one, and not one above it.
        assert!(mgr.is_current_key_version(circle.into(), 2));
        assert!(!mgr.is_current_key_version(circle.into(), 1));
        assert!(!mgr.is_current_key_version(circle.into(), 3));

        // A retired personal key (kept below 1) opens its rows as history.
        let personal = CryptoManager::new();
        personal.generate_keypair();
        insert_test_circle_key(&personal, PERSONAL_KEY_ID, vec![0x40u8; 32]);
        let old_row = personal.encrypt_location(PERSONAL_KEY_ID.into(), test_location()).unwrap();
        {
            let mut keys = personal.circle_keys.write().unwrap();
            let slot = keys.get_mut(&CircleKey::of(PERSONAL_KEY_ID)).unwrap();
            let old = slot.remove(&1).unwrap();
            slot.insert(0, old);
            slot.insert(1, Zeroizing::new(vec![0x41u8; 32]));
        }
        let read = personal.decrypt_location_opened(PERSONAL_KEY_ID.into(), old_row).unwrap();
        assert_eq!(read.key_version, 0);
        assert!(!personal.is_current_key_version(PERSONAL_KEY_ID.into(), 0));
        assert!(personal.is_current_key_version(PERSONAL_KEY_ID.into(), 1));
    }

    #[test]
    fn a_session_key_opens_only_its_own_circle() {
        // A session key is kept under the circle that opened it. A row of
        // another circle, or a personal row, never opens with it; the same id in
        // two circles is two keys; one id's key is replaced only by one opened
        // under a higher version.
        // Ids with letters, so another spelling (upper case) is another string.
        let a = "a1a1a1a1-1111-4111-8111-1111111111aa";
        let b = "b2b2b2b2-2222-4222-8222-2222222222bb";
        let user = "a1a1a1a1-0000-4000-8000-0000000000aa";
        let writer = CryptoManager::new();
        let reader = CryptoManager::new();
        for mgr in [&writer, &reader] {
            insert_test_circle_key(mgr, a, vec![0xaa; 32]);
            insert_test_circle_key(mgr, b, vec![0xbb; 32]);
        }
        insert_test_circle_key(&reader, PERSONAL_KEY_ID, vec![0x40; 32]);
        let id = share_session_key(&writer, &reader, b);
        let pseudonym = writer.derive_user_pseudonym(b.into(), user.into()).unwrap();
        let row = writer.encrypt_location_with_session_key_bound(b.into(), test_location(), pseudonym).unwrap();
        assert_eq!(row.key_id, format!("s:{id}"));
        let open = |circle: &str| reader.decrypt_location_with_session_key_bound_for_user(circle.into(), row.encrypted.clone(), row.key_id.clone(), user.into());
        assert_eq!(open(b).unwrap().key_version, 1, "its own circle's row opens");
        assert!(b.to_uppercase() != b);
        assert!(reader.resolve_decryption_key(&b.to_uppercase(), &row.key_id).is_ok(), "its circle in another spelling");
        for elsewhere in [a, PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
            assert!(matches!(open(elsewhere), Err(MobileError::SessionKeyNotFound(_))), "{elsewhere}: never with another circle's session key");
        }
        assert!(matches!(
            reader.decrypt_data_by_key_id(a.into(), row.encrypted.clone(), row.key_id.clone()),
            Err(MobileError::SessionKeyNotFound(_))
        ));
        assert!(reader.has_peer_session_key_for(b.into(), row.key_id.clone()));
        assert!(reader.has_peer_session_key_for(b.to_uppercase(), id.clone()), "the circle compared in its one spelling");
        assert!(!reader.has_peer_session_key_for(a.into(), id.clone()));
        assert!(!reader.has_peer_session_key_for(PERSONAL_KEY_ID.into(), id.clone()));
        assert!(reader.has_peer_session_key(row.key_id.clone()), "the circle-less pre-check answers for any circle");

        // The same id in circle A, another key: its own entry; B's still opens.
        let key_a = [0x5au8; 32];
        let sealed = encrypt_raw_bytes(&[0xaa; 32], &key_a).unwrap();
        let expires = current_unix_secs() + 3600;
        reader.import_peer_session_key(a.into(), id.clone(), sealed.ciphertext, sealed.nonce, 1, expires).unwrap();
        assert!(open(b).is_ok(), "B's key is not evicted by A's");
        let resolved = reader.resolve_decryption_key(a, &row.key_id).unwrap();
        assert!(resolved.as_slice() == key_a.as_slice(), "A's row opens with A's key");

        // One id, one key per circle, upgraded only: B holds v1 and v2.
        rotate_test_circle_key(&reader, b, 2, vec![0xbc; 32]);
        let import_b = |key: [u8; 32], version: i32| {
            let circle_key = if version == 1 { [0xbb; 32] } else { [0xbc; 32] };
            let sealed = encrypt_raw_bytes(&circle_key, &key).unwrap();
            reader.import_peer_session_key(b.into(), id.clone(), sealed.ciphertext, sealed.nonce, version, expires)
        };
        let theirs = [0x66u8; 32];
        assert!(matches!(import_b(theirs, 1), Err(MobileError::InvalidInput(_))), "another key at the same version: refused");
        assert_eq!(open(b).unwrap().key_version, 1, "the held key still opens");
        assert!(import_b(theirs, 2).is_ok(), "a key opened under a higher version replaces it");
        assert!(open(b).is_err(), "the replaced key is gone");
        let held = reader.resolve_decryption_key_opened(b, &row.key_id).unwrap();
        assert!(held.0 == 2 && held.1.as_slice() == theirs.as_slice());
        assert!(import_b(theirs, 2).is_ok(), "the same key again: nothing changes");
        let kept = reader.with_peer_session_key(b, &id, |cached| cached.key.to_vec()).unwrap();
        assert!(kept == theirs.to_vec(), "the key held is the one it upgraded to");
        let back = import_b([0x11u8; 32], 1);
        assert!(matches!(back, Err(MobileError::InvalidInput(_))), "a lower version never replaces it");

        // The personal slots are one namespace, in every spelling, and
        // their session key never opens a circle's row.
        let personal_id = reader.create_session_key(PERSONAL_KEY_ID.into(), 3600).unwrap().session_key_id;
        let personal_row = reader
            .encrypt_location_with_session_key_bound(
                PERSONAL_KEY_ID.into(),
                test_location(),
                reader.derive_user_pseudonym(PERSONAL_KEY_ID.into(), user.into()).unwrap(),
            )
            .unwrap();
        assert_eq!(personal_row.key_id, format!("s:{personal_id}"));
        let nil = uuid::Uuid::nil();
        for spelled in [PERSONAL_KEY_ID.to_string(), nil.simple().to_string(), nil.braced().to_string(), ANDROID_PERSONAL_KEY_SLOT.to_string()] {
            assert!(reader.has_peer_session_key_for(spelled.clone(), personal_id.clone()), "{spelled}");
            assert!(reader.resolve_decryption_key(&spelled, &personal_row.key_id).is_ok(), "{spelled}");
        }
        for circle in [a, b] {
            assert!(!reader.has_peer_session_key_for(circle.into(), personal_id.clone()));
            assert!(matches!(reader.resolve_decryption_key(circle, &personal_row.key_id), Err(MobileError::SessionKeyNotFound(_))));
        }
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn envelope_location_bound_round_trips_and_blocks_relabel() {
        // Envelope path (wrapped-msg-key): write a v3 sender-bound envelope with
        // envelope_encrypt_location_bound, then read it back with
        // unwrap_and_decrypt_location_bound. Correct pseudonym ⇒ verified; wrong
        // pseudonym ⇒ ERROR (relabel dropped, no plaintext).
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![5u8; 32]);
        let loc = test_location();
        let sender = "user-pseudo-ENV".to_string();

        let env = mgr
            .envelope_encrypt_location_bound(loc.clone(), vec![c1.clone()], sender.clone())
            .unwrap();
        assert_eq!(env.key_wraps.len(), 1);
        let wrap = &env.key_wraps[0];

        // Correct claimed pseudonym ⇒ v3 payload tag verifies ⇒ verified = true.
        let ok = mgr
            .unwrap_and_decrypt_location_bound(
                c1.clone(),
                wrap.wrapped_key.clone(),
                wrap.wrapped_key_nonce.clone(),
                env.ciphertext.clone(),
                env.ciphertext_nonce.clone(),
                sender.clone(),
            )
            .unwrap();
        assert!(ok.sender_verified);
        assert_eq!(ok.location.latitude, loc.latitude);
        assert_eq!(ok.location.longitude, loc.longitude);

        // Server relabel: same envelope, DIFFERENT claimed pseudonym. Unwrap still
        // succeeds (the wrap is target-bound), but the v3 payload tag fails and the
        // v2/v1 fallback also fails (payload sealed under v3) ⇒ ERROR (drop).
        let relabelled = mgr.unwrap_and_decrypt_location_bound(
            c1.clone(),
            wrap.wrapped_key.clone(),
            wrap.wrapped_key_nonce.clone(),
            env.ciphertext.clone(),
            env.ciphertext_nonce.clone(),
            "user-pseudo-WRONG".to_string(),
        );
        assert!(relabelled.is_err(), "a relabelled v3 envelope must not decrypt");
    }

    #[test]
    #[allow(deprecated)] // deliberately exercises the deprecated active-only reader
    fn envelope_location_bound_reads_legacy_v2_and_v1_as_unverified() {
        // An envelope written before sender-binding existed carries none: the v3 payload tag
        // can't match, so unwrap_and_decrypt_location_bound falls back to the
        // v2-then-v1 payload reader and returns sender_verified = false. Proven for
        // both a v2 envelope and a v1 envelope.
        let mgr = CryptoManager::new();
        let c1 = "11111111-1111-1111-1111-111111111111".to_string();
        insert_test_circle_key(&mgr, &c1, vec![6u8; 32]);
        let loc = test_location();

        // Legacy v2 envelope.
        let env2 = mgr
            .envelope_encrypt_location_v2(loc.clone(), vec![c1.clone()])
            .unwrap();
        let wrap2 = &env2.key_wraps[0];
        let out2 = mgr
            .unwrap_and_decrypt_location_bound(
                c1.clone(),
                wrap2.wrapped_key.clone(),
                wrap2.wrapped_key_nonce.clone(),
                env2.ciphertext.clone(),
                env2.ciphertext_nonce.clone(),
                "any-pseudonym".to_string(),
            )
            .unwrap();
        assert!(!out2.sender_verified);
        assert_eq!(out2.location.latitude, loc.latitude);

        // Legacy v1 envelope (empty-AAD payload + empty-AAD wrap).
        let env1 = mgr
            .envelope_encrypt_location(loc.clone(), vec![c1.clone()])
            .unwrap();
        let wrap1 = &env1.key_wraps[0];
        let out1 = mgr
            .unwrap_and_decrypt_location_bound(
                c1,
                wrap1.wrapped_key.clone(),
                wrap1.wrapped_key_nonce.clone(),
                env1.ciphertext.clone(),
                env1.ciphertext_nonce.clone(),
                "any-pseudonym".to_string(),
            )
            .unwrap();
        assert!(!out1.sender_verified);
        assert_eq!(out1.location.longitude, loc.longitude);
    }

    #[test]
    fn derive_user_pseudonym_cross_language_vector() {
        // LOCK the exact Rust output of the sender/reader pseudonym derivation so
        // the web (TS) and Android (Kotlin) clients can mirror-assert it. A silent
        // divergence here would make EVERY v3 location row fail sender
        // verification.
        //
        // Construction (pingolin-crypto `privacy::derive_user_pseudonym`):
        //   key_material = circle_key.as_bytes() (32) || user_id UTF-8 bytes
        //   hash         = blake3::derive_key("pingolin.privacy.pseudonym.user.v2", key_material)
        //   pseudonym    = lowercase-hex(hash[..16])   → 32 hex chars
        // Mobile `CryptoManager::derive_user_pseudonym` resolves the circle key
        // from circle_id, then calls this exact primitive.
        let circle_key_bytes = [0x42u8; 32];
        let user_id = "test-user-1234";
        let key = pingolin_crypto::keys::SymmetricKey::try_from_slice(&circle_key_bytes)
            .expect("valid 32-byte key");
        let pseudonym = pingolin_crypto::privacy::derive_user_pseudonym(&key, user_id);

        println!(
            "LOCKED derive_user_pseudonym: circle_key=0x{} user_id={:?} => {}",
            hex::encode(circle_key_bytes),
            user_id,
            pseudonym
        );

        assert_eq!(pseudonym, "a002b1055a4553f81f7232e1202f0083");
    }

    // ========================================================================
    // Graduated fail-closed for circle-key wrap signatures (store_circle_key)
    //
    // These exercise a REAL wrap round-trip (wrap_circle_key_for_member_full →
    // store_circle_key) across two independent in-test CryptoManager instances,
    // A (signer) and B (recipient). No network. They lock in the four states of
    // the graduated posture:
    //   1. pinned signer + valid signature  -> accept
    //   2. pinned signer + STRIPPED signature -> reject
    //   3. legacy / unpinned first-use, no signature -> grace-accept
    //   4. any signer + present-but-INVALID signature -> reject
    // NOTE: store_circle_key does NOT auto-pin — the recipient pins the signer
    // explicitly via pin_member_keys, so tests do the same.
    // ========================================================================

    // Fixed valid UUIDs (compute_sig_input parses circle/user ids as UUIDs).
    const WRAP_A_UID: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const WRAP_B_UID: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const WRAP_CIRCLE: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

    /// Build signer "A": X25519 sharing keypair, an Ed25519 signing keypair
    /// (installed in memory so wraps are signed), and an active circle key at
    /// version 1. Returns (manager, sharing_pubkey_hex, signing_pubkey_hex) —
    /// both pubkeys hex-encoded as store_circle_key / pin_member_keys expect.
    fn make_signer_with_circle(
        circle_id: &str,
        circle_key: Vec<u8>,
    ) -> (Arc<CryptoManager>, String, String) {
        let a = CryptoManager::new();
        a.generate_keypair();
        let signing = a.generate_signing_keypair();
        insert_test_circle_key(&a, circle_id, circle_key);
        let sharing_pub_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(a.export_public_key().unwrap())
                .unwrap(),
        );
        let signing_pub_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(signing.verifying_key_b64)
                .unwrap(),
        );
        (a, sharing_pub_hex, signing_pub_hex)
    }

    /// Recipient "B": just an X25519 keypair (needed to ECDH-unwrap). Returns
    /// (manager, sharing_public_key_base64) for use as the wrap target.
    fn make_recipient() -> (Arc<CryptoManager>, String) {
        let b = CryptoManager::new();
        b.generate_keypair();
        let pub_b64 = b.export_public_key().unwrap();
        (b, pub_b64)
    }

    /// store_circle_key wants hex(nonce || ciphertext); the bundle carries each
    /// as its own hex string, and concatenating two hex strings equals hex of
    /// the concatenated bytes (hex is per-byte).
    fn wrap_encrypted_key_hex(bundle: &MemberKeyBundle) -> String {
        format!(
            "{}{}",
            bundle.encrypted_circle_key.nonce, bundle.encrypted_circle_key.ciphertext
        )
    }

    // 1. Pinned signer + valid signature -> ACCEPT (and the stored key is the
    //    real circle key, proven by a cross-instance encrypt/decrypt).
    #[test]
    fn store_circle_key_accepts_signed_wrap_from_pinned_signer() {
        let circle_key = vec![7u8; 32];
        let (a, a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, circle_key.clone());
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(), // recipient_signing_pubkey_hex: ignored by impl
            )
            .unwrap();
        assert!(!bundle.wrap_signature.is_empty(), "A must sign the wrap");

        // B pins A up front (real clients pin from the directory). This ARMS the
        // stripped-signature rejection that test 2 relies on.
        let pin = b
            .pin_member_keys(
                WRAP_CIRCLE.to_string(),
                WRAP_A_UID.to_string(),
                a_sharing_hex,
                a_signing_hex.clone(),
            )
            .unwrap();
        assert!(matches!(pin.state, PinState::NewPinning));

        // Valid signature from the pinned signer -> stored.
        b.store_circle_key(
            WRAP_CIRCLE.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key.clone(),
            1,
            WRAP_A_UID.to_string(),
            WRAP_B_UID.to_string(),
            Some(bundle.wrap_signature.clone()),
            Some(a_signing_hex),
        )
        .unwrap();
        assert!(b.has_circle_key(WRAP_CIRCLE.to_string()));

        // The stored key is genuinely the circle key: A encrypts, B decrypts.
        let ct = a
            .encrypt_data(WRAP_CIRCLE.to_string(), "hello".to_string())
            .unwrap();
        assert_eq!(
            b.decrypt_data(WRAP_CIRCLE.to_string(), ct).unwrap(),
            "hello"
        );
    }

    // 2. Pinned signer + STRIPPED signature -> REJECT. We hold A's pinned key,
    //    so a legit wrap from A carries a signature; a missing one is a relay
    //    that stripped it.
    #[test]
    fn store_circle_key_rejects_stripped_signature_from_pinned_signer() {
        let (a, a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![9u8; 32]);
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();

        // B has A pinned (e.g. from a prior signed version of this circle key).
        b.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_A_UID.to_string(),
            a_sharing_hex,
            a_signing_hex.clone(),
        )
        .unwrap();

        let ek = wrap_encrypted_key_hex(&bundle);

        // (a) relay strips BOTH the signature and the signer-key field -> reject.
        let err = b
            .store_circle_key(
                WRAP_CIRCLE.to_string(),
                ek.clone(),
                bundle.ephemeral_public_key.clone(),
                2, // a fresh version
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::SignatureInvalid),
            "both-stripped: expected SignatureInvalid, got {:?}",
            err
        );

        // (b) relay strips only the signature; signer-key field survives
        //     (has_signer=true, has_sig=false still lands in the else branch) -> reject.
        let err2 = b
            .store_circle_key(
                WRAP_CIRCLE.to_string(),
                ek,
                bundle.ephemeral_public_key.clone(),
                2,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                None,
                Some(a_signing_hex),
            )
            .unwrap_err();
        assert!(
            matches!(err2, MobileError::SignatureInvalid),
            "sig-only-stripped: expected SignatureInvalid, got {:?}",
            err2
        );

        // Nothing was stored on either rejected attempt.
        assert!(!b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3a. Legacy wrap: backend recorded no signer (sender_user_id empty) and no
    //     signature -> GRACE-accept (no pin can exist for "").
    #[test]
    fn store_circle_key_grace_accepts_legacy_empty_signer() {
        let (a, _a_sharing_hex, _a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![3u8; 32]);
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();

        b.store_circle_key(
            WRAP_CIRCLE.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key,
            1,
            String::new(), // no recorded signer -> legacy
            String::new(),
            None,
            None,
        )
        .unwrap();
        assert!(b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3b. First-use TOFU: A is a KNOWN signer (valid user id, signer key even
    //     present) but B has NOT pinned A yet -> GRACE-accept. This proves we do
    //     NOT over-reject on `has_signer && !has_sig` — the reject is gated on
    //     the actual PIN, not on the signer field being present.
    #[test]
    fn store_circle_key_grace_accepts_unpinned_first_use() {
        let (a, _a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![4u8; 32]);
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();

        // B has NOT pinned A. Signer key is present but signature omitted.
        b.store_circle_key(
            WRAP_CIRCLE.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key,
            1,
            WRAP_A_UID.to_string(),
            WRAP_B_UID.to_string(),
            None,
            Some(a_signing_hex),
        )
        .unwrap();
        assert!(b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3c. ESTABLISHED circle (B has pinned a member) + a wrap from an UNPINNED
    //     signer -> REJECT — whether the signer is absent, or named-but-unpinned,
    //     even with a self-consistent signature. Closes the residual where a relay
    //     dodges the pinned-signer bar for a circle we already know by naming or
    //     inventing a sender we've never pinned. Genuine new members recover by
    //     refreshing the roster (which pins them) then retrying.
    #[test]
    fn store_circle_key_rejects_unpinned_signer_for_established_circle() {
        let (a, a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![11u8; 32]);
        let (b, b_pub) = make_recipient();

        // B pins A -> the circle is ESTABLISHED for B.
        b.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_A_UID.to_string(),
            a_sharing_hex,
            a_signing_hex.clone(),
        )
        .unwrap();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();

        // (i) stripped signer + signature -> reject.
        assert!(matches!(
            b.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key.clone(),
                1,
                String::new(),
                WRAP_B_UID.to_string(),
                None,
                None,
            ),
            Err(MobileError::SignatureInvalid)
        ));

        // (ii) a signer we have NOT pinned, even carrying a signature + key ->
        //      reject (it must be pinned via the roster first). A sender that
        //      is no UUID is refused before any pin is read.
        assert!(matches!(
            b.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key.clone(),
                1,
                "e0000000-0000-4000-8000-0000000000ee".to_string(),
                WRAP_B_UID.to_string(),
                Some(bundle.wrap_signature.clone()),
                Some(a_signing_hex.clone()),
            ),
            Err(MobileError::SignatureInvalid)
        ));
        assert!(matches!(
            b.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key.clone(),
                1,
                "unpinned-user-id".to_string(),
                WRAP_B_UID.to_string(),
                Some(bundle.wrap_signature.clone()),
                Some(a_signing_hex),
            ),
            Err(MobileError::InvalidInput(_))
        ));

        assert!(!b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3b. A wrap WE authored, on an ESTABLISHED circle -> ACCEPT.
    //
    // The roster pin loop skips self (we never TOFU our own identity), so
    // `pinned_keys[circle:me]` is always absent, and without this case our own
    // rotation slot would fall into the unpinned-signer refusal above —
    // locking us out of a circle we ourselves re-keyed, with the device stuck
    // on an older key version.
    //
    // Both directions are covered below, because "accept our own wrap" is one
    // bad edit away from "accept anyone claiming to be us".
    #[test]
    fn store_circle_key_accepts_our_own_signed_wrap_on_established_circle() {
        let (me, _me_sharing_hex, _me_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![21u8; 32]);

        // Someone ELSE is pinned => the circle counts as established for us,
        // which is the precondition for the refusal this guards.
        me.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_B_UID.to_string(),
            "cc".repeat(32),
            "dd".repeat(32),
        )
        .unwrap();

        // Exactly what a rotation writes for the rotating member.
        let bundle = me
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                String::new(), // ignored for our own entry — wrapped to our trusted key
                WRAP_A_UID.to_string(),
                WRAP_A_UID.to_string(),
                String::new(),
            )
            .unwrap();
        assert!(!bundle.wrap_signature.is_empty(), "precondition: the wrap is signed");

        // Drop the local copy so the store must come from the wrap, as it would
        // on the next session.
        me.circle_keys.write().unwrap().remove(&CircleKey::of(WRAP_CIRCLE));
        assert!(!me.has_circle_key(WRAP_CIRCLE.to_string()));

        me.store_circle_key(
            WRAP_CIRCLE.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key.clone(),
            1,
            WRAP_A_UID.to_string(),
            WRAP_A_UID.to_string(),
            Some(bundle.wrap_signature.clone()),
            None,
        )
        .expect("a wrap we signed ourselves must be storable");
        assert!(me.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3c. A wrap that CLAIMS sender == recipient == us but carries someone
    //     else's signature -> REJECT. This is the attack the acceptance above
    //     must not open: substituting the sender id costs a blind relay nothing.
    #[test]
    fn store_circle_key_rejects_a_wrap_that_only_claims_to_be_ours() {
        let (me, me_sharing_hex, _me_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![22u8; 32]);
        me.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_B_UID.to_string(),
            "cc".repeat(32),
            "dd".repeat(32),
        )
        .unwrap();

        // An impostor wraps a key TO US and signs with its own key.
        let (impostor, _imp_sharing_hex, imp_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![99u8; 32]);
        let forged = impostor
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                me_sharing_hex,
                WRAP_B_UID.to_string(),
                WRAP_A_UID.to_string(),
                String::new(),
            )
            .unwrap();

        me.circle_keys.write().unwrap().remove(&CircleKey::of(WRAP_CIRCLE));

        // Relabelled as ours. Verification runs against OUR signing key and fails.
        assert!(matches!(
            me.store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&forged),
                forged.ephemeral_public_key.clone(),
                1,
                WRAP_A_UID.to_string(),
                WRAP_A_UID.to_string(),
                Some(forged.wrap_signature.clone()),
                Some(imp_signing_hex), // wire signer is ignored for self wraps
            ),
            Err(MobileError::SignatureInvalid)
        ));
        assert!(!me.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 3d. An UNSIGNED wrap of ours -> ACCEPT. That is every legacy wrap.
    //
    // The server serves the creation wrap with no `wrap_signature` at all.
    // Treating self as a resolvable signer and demanding a signature would
    // refuse every one of those and make every existing circle undecryptable
    // on the next load. Tightening unsigned wraps is a data-loss change.
    #[test]
    fn store_circle_key_accepts_our_own_unsigned_wrap() {
        let (me, _me_sharing_hex, _me_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![23u8; 32]);
        me.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_B_UID.to_string(),
            "cc".repeat(32),
            "dd".repeat(32),
        )
        .unwrap();

        let bundle = me
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                String::new(),
                WRAP_A_UID.to_string(),
                WRAP_A_UID.to_string(),
                String::new(),
            )
            .unwrap();

        me.circle_keys.write().unwrap().remove(&CircleKey::of(WRAP_CIRCLE));

        me.store_circle_key(
            WRAP_CIRCLE.to_string(),
            wrap_encrypted_key_hex(&bundle),
            bundle.ephemeral_public_key.clone(),
            1,
            WRAP_A_UID.to_string(),
            WRAP_A_UID.to_string(),
            None, // no signature — the shape the server actually serves
            None,
        )
        .expect("an unsigned wrap of ours is every legacy wrap; refusing it is data loss");
        assert!(me.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 4. Present-but-INVALID signature (signer key also present) -> REJECT.
    //    Locks in the fail-closed path; independent of pinning.
    #[test]
    fn store_circle_key_rejects_present_but_invalid_signature() {
        let (a, _a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![5u8; 32]);
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();
        assert!(!bundle.wrap_signature.is_empty());

        // Corrupt the still-well-formed (64-byte) signature so verification
        // fails but the length/hex checks pass -> SignatureInvalid, not a decode error.
        let mut sig = hex::decode(&bundle.wrap_signature).unwrap();
        sig[0] ^= 0x01; // flip a byte of R
        let bad_sig_hex = hex::encode(&sig);

        let err = b
            .store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key,
                1,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                Some(bad_sig_hex),
                Some(a_signing_hex),
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::SignatureInvalid),
            "expected SignatureInvalid, got {:?}",
            err
        );
        assert!(!b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 5. Pinned signer + a present-but-bogus signature + NO signer key on the
    //    wire — the cold-cache shape clients hit on startup (they forward the
    //    server's signature but pass a nil signer because their in-memory member
    //    cache isn't warm yet). A pin gate keyed on `!has_sig` would let a
    //    present-but-garbage signature slip past and grace-accept a forged wrap;
    //    a pinned signer must ALWAYS be verified under the pinned key -> REJECT.
    #[test]
    fn store_circle_key_rejects_bogus_sig_without_signer_from_pinned_signer() {
        let (a, a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![11u8; 32]);
        let (b, b_pub) = make_recipient();

        let bundle = a
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();

        // B has A pinned from a prior signed version.
        b.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_A_UID.to_string(),
            a_sharing_hex,
            a_signing_hex,
        )
        .unwrap();

        // A well-formed (64-byte) but meaningless signature, and NO signer key.
        let bogus_sig_hex = hex::encode([0u8; 64]);
        let err = b
            .store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&bundle),
                bundle.ephemeral_public_key,
                2,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                Some(bogus_sig_hex),
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::SignatureInvalid),
            "cold-cache bogus-sig from pinned signer: expected SignatureInvalid, got {:?}",
            err
        );
        assert!(!b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // 6. Pinned signer, forged wrap: a ROGUE signer wraps an attacker-known key
    //    to B (impersonating A's user id) and signs it under its OWN key, and the
    //    relay presents that rogue signer key on the wire. Verifying against the
    //    WIRE key would call that valid and accept an attacker-known circle key —
    //    a full E2EE break for the circle. Verification under the PINNED key
    //    fails the rogue signature -> REJECT.
    #[test]
    fn store_circle_key_rejects_wire_signer_substitution_from_pinned_signer() {
        // Real signer A that B has pinned (identity only needed via the pin).
        let (_a, a_sharing_hex, a_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![1u8; 32]);
        let (b, b_pub) = make_recipient();

        b.pin_member_keys(
            WRAP_CIRCLE.to_string(),
            WRAP_A_UID.to_string(),
            a_sharing_hex,
            a_signing_hex,
        )
        .unwrap();

        // Rogue attacker with a DISTINCT signing key forges a wrap of its own
        // (attacker-known) circle key to B, impersonating A, signed under the
        // rogue key. Its signature is valid — but only under the rogue key.
        let (rogue, _rogue_sharing_hex, rogue_signing_hex) =
            make_signer_with_circle(WRAP_CIRCLE, vec![0xAAu8; 32]);
        let forged = rogue
            .wrap_circle_key_for_member_full(
                WRAP_CIRCLE.to_string(),
                b_pub,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                String::new(),
            )
            .unwrap();
        assert!(!forged.wrap_signature.is_empty());

        let err = b
            .store_circle_key(
                WRAP_CIRCLE.to_string(),
                wrap_encrypted_key_hex(&forged),
                forged.ephemeral_public_key.clone(),
                1,
                WRAP_A_UID.to_string(),
                WRAP_B_UID.to_string(),
                Some(forged.wrap_signature.clone()),
                Some(rogue_signing_hex),
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::SignatureInvalid),
            "wire-signer substitution from pinned signer: expected SignatureInvalid, got {:?}",
            err
        );
        assert!(!b.has_circle_key(WRAP_CIRCLE.to_string()));
    }

    // prepare_key_rotation must wrap SELF's entry to our OWN public key and
    // IGNORE the server-supplied key for the self entry. A malicious server that
    // substitutes only self's key in the returned roster must NOT be able to learn
    // the new circle key. Proven by: the self-wrap unwraps with our own private key
    // (identity twin) but NOT with the substituted (attacker) private key.
    #[test]
    fn prepare_key_rotation_wraps_self_to_own_key_not_server_supplied() {
        let circle_id = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string();
        let self_uid = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee".to_string();

        // Self ("a"): keep its private key so we can build an identity twin below.
        let a = CryptoManager::new();
        let a_keys = a.generate_keypair();
        insert_test_circle_key(&a, &circle_id, vec![1u8; 32]); // current version 1

        // Attacker keypair — its public key is what the server substitutes for self.
        let attacker = CryptoManager::new();
        attacker.generate_keypair();
        let attacker_pub_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(attacker.export_public_key().unwrap())
                .unwrap(),
        );
        let self_pub_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(a.export_public_key().unwrap())
                .unwrap(),
        );
        assert_ne!(
            attacker_pub_hex, self_pub_hex,
            "attacker key must differ from self's real key"
        );

        // Rotate: the roster is JUST self, but the server substituted the attacker
        // key for self's public key.
        let bundle = a
            .prepare_key_rotation(
                circle_id.clone(),
                self_uid.clone(),
                vec![self_uid.clone()],
                vec![attacker_pub_hex.clone()], // <-- attacker-substituted self key
                vec![String::new()],            // signing pubkeys reserved / unused
                "My Circle".to_string(),
            )
            .unwrap();
        assert_eq!(bundle.member_keys.len(), 1);
        let self_entry = &bundle.member_keys[0];
        assert_eq!(self_entry.user_id, self_uid);
        let new_version = bundle.new_key_version; // 2
        let ek = wrap_encrypted_key_hex(&self_entry.bundle);

        // POSITIVE: an identity twin holding self's OWN private key unwraps the
        // self-wrap (first-contact TOFU, no pins) and recovers the REAL new circle
        // key — proven by a cross-instance encrypt (a) / decrypt (twin).
        let a_twin = CryptoManager::new();
        a_twin.import_private_key(a_keys.private_key.clone()).unwrap();
        a_twin
            .store_circle_key(
                circle_id.clone(),
                ek.clone(),
                self_entry.bundle.ephemeral_public_key.clone(),
                new_version,
                self_uid.clone(),
                self_uid.clone(),
                None,
                None,
            )
            .expect("twin holding self's own private key must unwrap the self-wrap");
        let ct = a
            .encrypt_data(circle_id.clone(), "rotated!".to_string())
            .unwrap();
        assert_eq!(
            a_twin.decrypt_data(circle_id.clone(), ct).unwrap(),
            "rotated!",
            "twin recovered the real new circle key from the self-wrap"
        );

        // NEGATIVE: the attacker (holding the substituted key's PRIVATE half) can
        // NOT unwrap the self-wrap — confirming self was wrapped to our OWN key,
        // not the attacker key the server supplied.
        let err = attacker
            .store_circle_key(
                circle_id.clone(),
                ek,
                self_entry.bundle.ephemeral_public_key.clone(),
                new_version,
                self_uid.clone(),
                self_uid.clone(),
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::DecryptionFailed),
            "attacker must NOT unwrap the self-wrap, got {:?}",
            err
        );
    }

    // A rotation bundle carries a chain link from the new key back to the
    // outgoing one, and the link opens that key.
    #[test]
    fn prepare_key_rotation_emits_a_chain_link_back_to_the_outgoing_key() {
        // Without a chain link, a circle taken to v3 by an eject-and-rotate leaves
        // a client that holds only the current key (the web) unable to decrypt
        // anything sealed under v2 or earlier: the circle NAME renders as the
        // "Circle" placeholder forever, while the phone that performed the eject
        // reads it fine from keys it still holds.
        // The bundle must carry the link, and the link must actually open the
        // outgoing key.
        let circle_id = "cccccccc-cccc-cccc-cccc-cccccccccccc".to_string();
        let uid = "dddddddd-dddd-dddd-dddd-dddddddddddd".to_string();

        let a = CryptoManager::new();
        a.generate_keypair();
        let outgoing = vec![7u8; 32];
        insert_test_circle_key(&a, &circle_id, outgoing.clone()); // v1
        let self_pub_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(a.export_public_key().unwrap())
                .unwrap(),
        );

        let bundle = a
            .prepare_key_rotation(
                circle_id.clone(),
                uid.clone(),
                vec![uid.clone()],
                vec![self_pub_hex],
                vec![String::new()],
                "My Circle".to_string(),
            )
            .unwrap();

        let link = bundle
            .key_chain_link
            .expect("rotation must emit a chain link, or older ciphertext is orphaned");
        // Direction matters: readers hold `from` and walk to `to`.
        assert_eq!(link.from_version, bundle.new_key_version);
        assert_eq!(link.to_version, bundle.new_key_version - 1);

        // The link must OPEN — a well-formed link that decrypts to the wrong
        // bytes would pass a shape-only assertion and still orphan the data.
        let new_key_bytes = {
            let keys = a.circle_keys.read().unwrap();
            keys.get(&CircleKey::of(&circle_id)).unwrap().get(&bundle.new_key_version).unwrap().to_vec()
        };
        // b holds ONLY the new key, AT its real version — exactly like a client
        // that joined after the rotation. Inserting it as v1 would make the
        // import fail for the wrong reason.
        let b = CryptoManager::new();
        rotate_test_circle_key(&b, &circle_id, bundle.new_key_version, new_key_bytes);
        b.import_key_chain_link(
            circle_id.clone(),
            link.from_version,
            link.to_version,
            link.encrypted_key.clone(),
            link.nonce.clone(),
        )
        .expect("a holder of the new key must be able to walk back");

        let recovered = {
            let keys = b.circle_keys.read().unwrap();
            keys.get(&CircleKey::of(&circle_id)).unwrap().get(&link.to_version).unwrap().to_vec()
        };
        assert_eq!(recovered, outgoing, "the chain link must reveal the OUTGOING key");
    }

    // Rotation ordering: a member wrap that fails mid-loop (here a small-order,
    // all-zero member key rejected by reject_small_order_public) must leave the
    // local key state unchanged: no orphaned new key version, and
    // active_key_version still at its pre-rotation value.
    #[test]
    fn prepare_key_rotation_leaves_key_state_unchanged_on_member_wrap_failure() {
        let circle_id = "dddddddd-dddd-dddd-dddd-dddddddddddd".to_string();
        let self_uid = "cccccccc-cccc-cccc-cccc-cccccccccccc".to_string();
        let bad_member_uid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string();

        let a = CryptoManager::new();
        a.generate_keypair();
        insert_test_circle_key(&a, &circle_id, vec![1u8; 32]); // current version 1 active

        // Sanity: exactly one version (1), active version 1, before rotation.
        assert_eq!(a.get_active_version(circle_id.clone()).unwrap(), 1);

        // An all-zero (small-order) member public key makes the per-member wrap loop
        // fail at reject_small_order_public. The member is NOT self, so the failure
        // is the plain wrap-loop error path.
        let bad_pub_hex = hex::encode([0u8; 32]);
        let err = a
            .prepare_key_rotation(
                circle_id.clone(),
                self_uid.clone(),
                vec![bad_member_uid.clone()],
                vec![bad_pub_hex],
                vec![String::new()], // signing pubkeys reserved / unused
                "My Circle".to_string(),
            )
            .unwrap_err();
        assert!(
            matches!(err, MobileError::InvalidKey),
            "expected the small-order member key to be rejected, got {:?}",
            err
        );

        // The failed rotation must NOT have mutated key state: active version still
        // 1, and NO orphaned version-2 key inserted.
        assert_eq!(
            a.get_active_version(circle_id.clone()).unwrap(),
            1,
            "active_key_version must be unchanged after a failed member wrap"
        );
        let keys = a.circle_keys.read().unwrap();
        let versions = keys.get(&CircleKey::of(&circle_id)).expect("circle must still hold its key");
        assert_eq!(
            versions.len(),
            1,
            "only the original version must remain after a failed rotation"
        );
        assert!(
            versions.contains_key(&1) && !versions.contains_key(&2),
            "no orphaned version-2 key must be inserted on a failed rotation"
        );
    }

    // pinned_sharing_key returns the stored sharing hex for a pinned member
    // (directly comparable to the server-supplied sharing hex) and None otherwise.
    #[test]
    fn pinned_sharing_key_returns_pinned_hex_and_none_when_absent() {
        let m = CryptoManager::new();
        let circle = WRAP_CIRCLE.to_string();
        let user = WRAP_A_UID.to_string();

        // No pin yet -> None.
        assert_eq!(m.pinned_sharing_key(circle.clone(), user.clone()), None);

        let sharing_hex = hex::encode([0x11u8; 32]); // already lowercase
        let signing_hex = hex::encode([0x22u8; 32]);
        let res = m
            .pin_member_keys(
                circle.clone(),
                user.clone(),
                sharing_hex.clone(),
                signing_hex,
            )
            .unwrap();
        assert!(matches!(res.state, PinState::NewPinning));

        // Getter returns exactly the pinned sharing hex.
        assert_eq!(
            m.pinned_sharing_key(circle.clone(), user.clone()),
            Some(sharing_hex)
        );

        // A different (unpinned) member in the same circle -> None.
        assert_eq!(m.pinned_sharing_key(circle, WRAP_B_UID.to_string()), None);
    }

    /// Seal `plaintext` into a circle-key wrap addressed to `recipient_pub_b64`,
    /// using ONLY the recipient's X25519 public key — exactly what a malicious
    /// relay can do. Returns (encrypted_key_hex, ephemeral_pubkey_hex) ready to
    /// hand to `store_circle_key`.
    ///
    /// This is the crux of the threat model: the ECDH wrap is NOT authentication.
    /// Anyone holding the victim's public key can mint an ephemeral keypair,
    /// derive the same wrapping key and seal a plaintext of ARBITRARY length.
    fn forge_wrap_for(recipient_pub_b64: &str, plaintext: &[u8]) -> (String, String) {
        let recipient_bytes = base64::engine::general_purpose::STANDARD
            .decode(recipient_pub_b64)
            .unwrap();
        let mut recipient_arr = [0u8; 32];
        recipient_arr.copy_from_slice(&recipient_bytes);
        let recipient_public = PublicKey::from(recipient_arr);

        let eph_secret = StaticSecret::random_from_rng(OsRng);
        let eph_public = PublicKey::from(&eph_secret);
        let shared = eph_secret.diffie_hellman(&recipient_public);
        let wrapping_key = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());

        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping_key).unwrap();
        let nonce: [u8; 24] = generate_secure_nonce();
        let ct = cipher
            .encrypt(&XNonce::from(nonce), plaintext)
            .unwrap();

        (
            format!("{}{}", hex::encode(nonce), hex::encode(&ct)),
            hex::encode(eph_public.as_bytes()),
        )
    }

    /// SECURITY GUARD: `store_circle_key` must reject an
    /// ECDH-decrypted plaintext that is not exactly 32 bytes.
    ///
    /// Reachability: the only authentication on a wrap is the Ed25519 signature,
    /// and the genuine-first-contact branch accepts an UNSIGNED wrap by design
    /// (TOFU), so a fresh login or a newly-joined circle (no pins yet) plus a
    /// malicious relay reaches this. Pinned signers and established circles fail
    /// closed earlier and are covered by the tests above.
    ///
    /// Without the ingest guard the malformed key enters the key map and then
    /// PANICS `create_key_chain_link` / `import_key_chain_link`
    /// (copy_from_slice into a [0u8; 32]) — a hard app crash across the UniFFI
    /// boundary, attacker-triggered remotely, per victim.
    #[test]
    fn store_circle_key_rejects_non_32_byte_plaintext_from_tofu_relay() {
        let (b, b_pub_b64) = make_recipient();

        // 16 bytes instead of 32.
        let (encrypted_key_hex, eph_pub_hex) = forge_wrap_for(&b_pub_b64, &[0x41u8; 16]);

        assert!(
            !b.has_circle_key(WRAP_CIRCLE.to_string()),
            "precondition: no keys/pins for this circle, so the TOFU branch applies"
        );

        let res = b.store_circle_key(
            WRAP_CIRCLE.to_string(),
            encrypted_key_hex,
            eph_pub_hex,
            1,
            WRAP_A_UID.to_string(),
            WRAP_B_UID.to_string(),
            None, // unsigned — accepted by the first-contact branch by design
            None,
        );

        // Precisely InvalidKey: had the forged wrap not decrypted at all we would
        // see DecryptionFailed instead, so this also proves we reached the gate.
        assert!(
            matches!(res, Err(MobileError::InvalidKey)),
            "a non-32-byte ECDH plaintext must be rejected at ingest, got {:?}",
            res
        );
        assert!(
            !b.has_circle_key(WRAP_CIRCLE.to_string()),
            "malformed key must never enter the key map"
        );

        // POSITIVE CONTROL: the identical attacker construction with a correctly
        // sized 32-byte plaintext IS accepted over TOFU. This proves the path is
        // genuinely reachable and that ONLY the length gate stopped the one above
        // — i.e. the guard is doing the work, not some unrelated earlier check.
        let other_circle = "dddddddd-dddd-dddd-dddd-dddddddddddd";
        let (ok_hex, ok_eph) = forge_wrap_for(&b_pub_b64, &[0x42u8; 32]);
        b.store_circle_key(
            other_circle.to_string(),
            ok_hex,
            ok_eph,
            1,
            WRAP_A_UID.to_string(),
            WRAP_B_UID.to_string(),
            None,
            None,
        )
        .expect("a well-formed 32-byte TOFU wrap must still be accepted");
        assert!(b.has_circle_key(other_circle.to_string()));
    }

    /// SECURITY GUARD: neither key-chain fn may PANIC on a malformed
    /// key. `store_circle_key` rejects one at ingest, so this puts one
    /// DIRECTLY in the map to prove the defence-in-depth guards hold even if a
    /// malformed key ever reaches it by another route. Both sites copy_from_slice
    /// into a [0u8; 32], which panics on any length mismatch.
    #[test]
    fn key_chain_fns_reject_malformed_key_without_panicking() {
        // Case A: the ACTIVE (v2 / "from") key is malformed.
        let circle = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
        let m = CryptoManager::new();
        insert_test_circle_key(&m, circle, vec![3u8; 32]); // v1 well-formed
        rotate_test_circle_key(&m, circle, 2, vec![3u8; 17]); // v2 MALFORMED, active

        match m.create_key_chain_link(circle.to_string()) {
            Err(MobileError::CryptoError(msg)) => {
                assert!(msg.contains("Invalid key length"), "got {}", msg)
            }
            other => panic!("expected CryptoError(Invalid key length), got {:?}", other),
        }

        match m.import_key_chain_link(
            circle.to_string(),
            2, // from the malformed v2
            1,
            hex::encode([0u8; 48]),
            hex::encode([0u8; 24]), // valid nonce length, so our guard is what fires
        ) {
            Err(MobileError::CryptoError(msg)) => {
                assert!(msg.contains("Invalid key length"), "got {}", msg)
            }
            other => panic!("expected CryptoError(Invalid key length), got {:?}", other),
        }

        // Case B: the OLD (v1) key is malformed — must not mint a chain link
        // carrying a corrupt key.
        let circle2 = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        let m2 = CryptoManager::new();
        insert_test_circle_key(&m2, circle2, vec![4u8; 9]); // v1 MALFORMED
        rotate_test_circle_key(&m2, circle2, 2, vec![5u8; 32]); // v2 well-formed, active

        match m2.create_key_chain_link(circle2.to_string()) {
            Err(MobileError::CryptoError(msg)) => {
                assert!(msg.contains("Invalid key length"), "got {}", msg)
            }
            other => panic!("expected CryptoError(Invalid key length), got {:?}", other),
        }
    }
}


/// Internals that are not part of the FFI surface.
impl CryptoManager {
    /// Try each recovered identity against a wrap the current key could not open.
    /// Returns the key and the X25519 public key of the identity that opened it,
    /// so a signature can be checked under THAT identity's key.
    ///
    /// Read path only: these keys never wrap anything, so no data is ever written
    /// back under an identity the user has already moved off.
    fn unwrap_with_previous_identity(
        &self,
        sender_public: &PublicKey,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Option<(Zeroizing<Vec<u8>>, [u8; 32])> {
        let guard = self
            .previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner());
        for previous in guard.iter() {
            let shared = previous.diffie_hellman(sender_public);
            let wrapping = Zeroizing::new(blake3::derive_key(
                "pingolin.circle_key_wrap",
                shared.as_bytes(),
            ));
            let cipher = XChaCha20Poly1305::new_from_slice(wrapping.as_slice()).ok()?;
            if let Ok(plain) = cipher.decrypt(&XNonce::from(*nonce), ciphertext) {
                return Some((Zeroizing::new(plain), PublicKey::from(previous).to_bytes()));
            }
        }
        None
    }

    /// `store_circle_key`'s body. `may_replace_personal` is true only for
    /// `adopt_personal_key`: nothing else may replace a held personal key with
    /// a different one, and a replaced one is retired, not lost.
    #[allow(clippy::too_many_arguments)]
    fn store_circle_key_inner(
        &self,
        circle_id: String,
        encrypted_key: String,
        sender_public_key: String,
        key_version: i32,
        sender_user_id: String,
        recipient_user_id: String,
        wrap_signature_hex: Option<String>,
        sender_signing_pubkey_hex: Option<String>,
        may_replace_personal: bool,
    ) -> Result<(), MobileError> {
        tracing::debug!("store_circle_key called for circle_id: {}, version: {}", circle_id, key_version);

        // Reject an implausible key_version at ingestion. A malicious server could
        // otherwise TOFU-seed e.g. i32::MAX, which later overflows rotation's `+1`
        // into a negative version and corrupts version ordering. Legitimate
        // versions are small monotonic counters.
        if !(1..=1_000_000).contains(&key_version) {
            return Err(MobileError::InvalidInput(format!(
                "implausible circle key version: {key_version}"
            )));
        }

        // A personal key comes only from this account's own wrap, under the
        // slot's own id, before anything is verified or opened. A wrap into it
        // from a circle path (another sender, or none) is a key someone else
        // chose, pinned sender or not: never the personal key, marked or
        // unmarked.
        if names_a_personal_slot(&circle_id) {
            if circle_id != PERSONAL_KEY_ID && circle_id != ANDROID_PERSONAL_KEY_SLOT {
                return Err(MobileError::InvalidInput("a personal key slot is named by its own id only".to_string()));
            }
            let own_label = !sender_user_id.is_empty()
                && canonical_id("", &sender_user_id).ok().map_or(false, |sender| canonical_id("", &recipient_user_id).ok() == Some(sender));
            if !own_label {
                tracing::warn!("store_circle_key: REFUSING a wrap into a personal key slot that is not this account's own");
                return Err(MobileError::SignatureInvalid);
            }
        }

        // Get our private key (borrow via RwLock guard to avoid cloning secret key material)
        let guard = self
            .private_key
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let private_key = guard.as_ref().ok_or_else(|| {
            tracing::error!("store_circle_key failed: no private key available");
            tracing::debug!("store_circle_key failed for circle_id: {}: no private key available", circle_id);
            MobileError::KeyNotFound("No private key available".to_string())
        })?;

        // Decode sender's public key (handles both hex and base64 for cross-platform compatibility)
        let sender_public_bytes = decode_flexible(&sender_public_key)?;
        if sender_public_bytes.len() != 32 {
            tracing::error!("store_circle_key failed: sender public key length invalid");
            tracing::debug!("store_circle_key failed for circle_id: {}: sender public key length {}", circle_id, sender_public_bytes.len());
            return Err(MobileError::InvalidKey);
        }
        // SECURITY: Do NOT log public keys - enables correlation attacks

        // Parse the (nonce || ciphertext) blob early — we need both for ECDH
        // decrypt AND for signature verification (sig_input binds them).
        let encrypted_bytes_for_sig = match hex::decode(&encrypted_key) {
            Ok(bytes) => bytes,
            Err(_) => Vec::new(), // fall through; the existing decode below will produce the correct error
        };
        let (sig_nonce, sig_ct): (&[u8], &[u8]) = if encrypted_bytes_for_sig.len() >= 24 {
            encrypted_bytes_for_sig.split_at(24)
        } else {
            (&[], &[])
        };

        // Verify the wrap signature BEFORE decrypting the wrapped key so a
        // relay that flips the wrap can't trick us into accepting its key version.
        //
        // KEY BINDING: when we have already TOFU-pinned this signer for this
        // circle, verify against the PINNED signing key — NEVER a signer key handed
        // to us on the wire next to the wrap. Verifying against the wire key admits
        // forgeries: a malicious relay simply signs its forged wrap with a matching
        // key it also supplies, and a cold client cache may pass no signer key at
        // all. A pinned signer MUST therefore
        // present a signature that verifies under the pinned key; a stripped,
        // wrong-key, or tampered signature fails closed. Only a signer we have
        // NEVER pinned falls back to the wire key, on the legacy grace path: first
        // contact is TOFU, and the caller pins on success, arming the pinned-key
        // bar for every subsequent version.
        let has_sig = wrap_signature_hex.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
        let has_signer = sender_signing_pubkey_hex.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
        let sig_hex = wrap_signature_hex.clone().unwrap_or_default();
        let eph_hex = hex::encode(&sender_public_bytes);
        let nonce_hex = hex::encode(sig_nonce);
        let ct_hex = hex::encode(sig_ct);

        // A wrap WE authored: sender == recipient == us. The roster pin loop
        // skips self on purpose (we never TOFU our own identity), so
        // `pinned_keys[circle:me]` is always absent, and without this check
        // every self-signed wrap would fall into the "unpinned signer for an
        // established circle" refusal below. The self slot is exactly what a
        // rotation produces for the member doing the rotating, so rotating a
        // circle would lock that member out of it on their next session, the
        // phone stuck on an older key version.
        //
        // What the label is WORTH is the whole question, because the label is
        // the server's: an ECDH wrap authenticates nothing (anyone holding our
        // public key can seal a key of their choosing to us), so a relay can
        // mint `sender == recipient == us` around any key it likes. Only
        // a signature that verifies under OUR OWN signing key proves a wrap is
        // ours. Everything else labelled "ours" — unsigned (every creation wrap
        // and personal self key), or signed while our signing key is not
        // loaded — is UNAUTHENTICATED, and the version rules after the unwrap
        // admit an unauthenticated wrap only on genuine first contact or as a
        // byte-identical re-import.
        // Ids are compared, and pins found, in their one spelling: another
        // spelling of a member's id is the same member.
        let same_id = |a: &str, b: &str| canonical_id("", a).ok().map_or(false, |a| canonical_id("", b).ok() == Some(a));
        let is_self_wrap = !sender_user_id.is_empty() && same_id(&sender_user_id, &recipient_user_id);

        // The durable CIRCLE pin for this (circle, sender), if any — cloned out
        // so the read guard is not held across verify_wrap. Identity pins are
        // never consulted here: a user retired from this circle by
        // `retain_member_pins` must not be able to sign keys for it. A sender
        // that is no UUID is refused.
        let pinned_signer_hex: Option<String> = if sender_user_id.is_empty() || is_self_wrap {
            None
        } else {
            let key = member_pin_key(&circle_id, &sender_user_id)?;
            let pins = self.pinned_keys.read().unwrap_or_else(|e| e.into_inner());
            pins.get(&key).map(|p| p.signing_pubkey_hex.clone())
        };

        // A signed own wrap that does not verify under our CURRENT signing key
        // is judged after the unwrap, by the identity that opens it. Made for
        // this identity: refused. Made for an identity from before a password
        // reset: it counts only under THAT identity's bound signing key. Made
        // for an identity this device does not hold: nothing is stored
        // (DecryptionFailed, the state before a restore).
        let mut own_signature_failed = false;

        // true = the wrap is proven to come from a signer we trust for this
        // circle: ourselves, or a member pinned in it.
        let authenticated: bool = if is_self_wrap {
            let own_signer = if has_sig { self.signing_public_key_hex().ok() } else { None };
            match own_signer {
                Some(own_hex) => {
                    if self.wrap_sig_verifies_either_domain(
                        &own_hex, &sig_hex, &sender_user_id, &recipient_user_id,
                        &circle_id, key_version as u32, &eph_hex, &nonce_hex, &ct_hex,
                    )? {
                        true
                    } else {
                        own_signature_failed = true;
                        false
                    }
                }
                None => {
                    tracing::debug!(
                        "store_circle_key: our own wrap for circle {} v{} is unauthenticated (has_sig={})",
                        circle_id, key_version, has_sig
                    );
                    false
                }
            }
        } else if let Some(pinned_hex) = pinned_signer_hex {
            // PINNED signer: strict bar. A legitimate wrap from them carries a
            // signature that verifies under the key we pinned; anything less
            // (stripped, wrong-key, or tampered) is a relay attack — reject. This
            // closes both the wire-signer-substitution and the
            // signature-present-but-no-signer (cold-cache) bypasses.
            let ok = has_sig
                && self.wrap_sig_verifies_either_domain(
                    &pinned_hex, &sig_hex, &sender_user_id, &recipient_user_id,
                    &circle_id, key_version as u32, &eph_hex, &nonce_hex, &ct_hex,
                )?;
            if !ok {
                tracing::warn!(
                    "store_circle_key: wrap not verifiable under PINNED signer for circle {} v{} (has_sig={}) — refusing to store",
                    circle_id, key_version, has_sig
                );
                return Err(MobileError::SignatureInvalid);
            }
            true
        } else {
            // UNPINNED (circle, sender_user_id). Whether we trust it turns on
            // whether this is an ESTABLISHED circle (we already hold pins for one
            // of its members) or GENUINE first contact.
            //
            // The server records the signer's user id on every active wrap, so the
            // only wraps that reach here without a pinned+verifiable signer are
            // either a brand-new circle (no pins yet) or a relay substituting a key
            // it knows (it cannot forge a real member's signature, so it strips the
            // signature, invents a signer, or names an unpinned member). We gate on
            // the pin set rather than grace-accepting everything unpinned.
            let circle_has_pin = {
                // Member pins are kept under the one spelling of their ids; a
                // slot that is no UUID (the personal key's) keeps its own.
                let circle = canonical_id("circle_id", &circle_id).unwrap_or_else(|_| circle_id.clone());
                let prefix = format!("{}:", circle);
                let pins = self.pinned_keys.read().unwrap_or_else(|e| e.into_inner());
                pins.keys().any(|k| k.starts_with(&prefix))
            };

            if circle_has_pin {
                // ESTABLISHED circle, but this wrap's signer is one we have NEVER
                // pinned (or is absent). Members are pinned from the directory
                // roster; a wrap from a signer outside that roster — signed or not
                // — is exactly what a blind relay's key substitution looks like.
                // Fail closed. The caller should refresh the member roster (which
                // pins any genuinely-new signer) and retry; the pinned bar above
                // then verifies a legitimate wrap, and a real key change surfaces
                // via the key-change alarm instead of being silently accepted.
                tracing::warn!(
                    "store_circle_key: REJECTING wrap from an unpinned signer for established circle {} v{} (has_sig={}, has_signer={}); refresh members and retry",
                    circle_id, key_version, has_sig, has_signer
                );
                return Err(MobileError::SignatureInvalid);
            }

            // No pins for this circle yet (fresh login or a just-joined circle).
            // Trust-on-first-use so the user isn't locked out of a brand-new
            // circle; the caller pins the roster on success and every SUBSEQUENT
            // version is held to the pinned bar above. Whatever passes here is
            // UNAUTHENTICATED (a wire signer proves nothing), so the version
            // rules below take it only if this circle holds no key yet.
            if has_sig && has_signer {
                // Both fields present: verify the wrap against the wire signer.
                // This does not prove identity (the relay supplied the key) but
                // rejects a self-inconsistent wrap.
                let signer_hex = sender_signing_pubkey_hex.clone().unwrap_or_default();
                if !self.wrap_sig_verifies_either_domain(
                    &signer_hex, &sig_hex, &sender_user_id, &recipient_user_id,
                    &circle_id, key_version as u32, &eph_hex, &nonce_hex, &ct_hex,
                )? {
                    tracing::warn!(
                        "store_circle_key: first-contact wrap signature INVALID for circle {} v{} — refusing to store",
                        circle_id, key_version
                    );
                    return Err(MobileError::SignatureInvalid);
                }
            } else {
                // No signature / no signer key on true first contact: a genuine
                // legacy wrap is indistinguishable from a stripped one here, and a
                // cold member cache passes no signer, so accept (TOFU) rather than
                // lock the user out of a brand-new circle.
                tracing::debug!(
                    "store_circle_key: unauthenticated wrap for circle {} v{} (no pins yet; has_sig={}, has_signer={})",
                    circle_id, key_version, has_sig, has_signer
                );
            }
            false
        };

        let mut sender_public_array = [0u8; 32];
        sender_public_array.copy_from_slice(&sender_public_bytes);
        let sender_public = PublicKey::from(sender_public_array);

        // SECURITY: Reject small-order points that would produce an all-zero shared secret
        reject_small_order_public(&sender_public)?;

        // Compute shared secret via ECDH
        // SECURITY: SharedSecret derives Zeroize(drop) via x25519-dalek's default "zeroize" feature,
        // so it is automatically zeroized when dropped at end of scope.
        let shared_secret = private_key.diffie_hellman(&sender_public);

        // Derive wrapping key from shared secret using BLAKE3.
        // SECURITY: Zeroizing wipes the wrapping key on EVERY exit path — including
        // the hex-decode and length-check error returns below — not just on success.
        let wrapping_key = Zeroizing::new(blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes()));

        // Decrypt the circle key
        let encrypted_bytes = match hex::decode(&encrypted_key) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("store_circle_key failed: hex decode error");
                tracing::debug!("store_circle_key hex decode failed for circle_id: {}: {}", circle_id, e);
                return Err(MobileError::CryptoError(format!("Hex decode failed: {}", e)));
            }
        };
        // SECURITY: Do NOT log ciphertext sizes - reveals encryption format

        // Expected format: [nonce (24 bytes) | ciphertext + tag]
        if encrypted_bytes.len() < 24 {
            tracing::error!("store_circle_key failed: encrypted data too short");
            tracing::debug!("store_circle_key failed for circle_id: {}: encrypted data too short ({} < 24)", circle_id, encrypted_bytes.len());
            return Err(MobileError::DecryptionFailed);
        }

        let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(nonce_bytes);

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        // The recovered identity that opened the wrap, if the current one could not.
        let mut opened_by_previous: Option<[u8; 32]> = None;
        // SECURITY: Zeroizing from the moment it exists, so a REJECTED (wrong-length)
        // plaintext is wiped on the error path below too, not just on the stored path.
        let decrypted = match cipher.decrypt(&XNonce::from(nonce), ciphertext) {
            Ok(plain) => Zeroizing::new(plain),
            Err(_) => {
                // Before giving up, try any identity the user has RECOVERED from
                // before a password reset.
                //
                // An email reset replaces the account keypair, so every wrap made
                // for the old public key stops opening and the circle goes silent
                // with all of its data intact. See `import_previous_identities`.
                //
                // CURRENT KEY FIRST, always: the loop only runs after the current
                // key has failed. Trying a recovered key first would keep a device
                // reading through a superseded identity after a legitimate
                // rotation — this same failure running backwards.
                match self.unwrap_with_previous_identity(&sender_public, &nonce, ciphertext) {
                    Some((plain, identity)) => {
                        tracing::info!(
                            "store_circle_key: circle {} opened with a recovered pre-reset identity",
                            circle_id
                        );
                        opened_by_previous = Some(identity);
                        plain
                    }
                    None if own_signature_failed => {
                        tracing::warn!(
                            "store_circle_key: our own wrap for circle {} v{} was made for an identity this device does not hold (sealed before a reset)",
                            circle_id, key_version
                        );
                        return Err(MobileError::DecryptionFailed);
                    }
                    None => {
                        tracing::warn!("store_circle_key decryption failed for circle_id: {} (stale key or membership revoked)", circle_id);
                        return Err(MobileError::DecryptionFailed);
                    }
                }
            }
        };

        // Our signature by a RESTORED identity (see `own_signature_failed`)
        // counts only when that same identity's sharing key opened the wrap.
        // Whoever holds an old signing seed must not be able to plant keys
        // for the current identity, or for another restored one.
        let authenticated_by_previous = if own_signature_failed {
            let bound = opened_by_previous.and_then(|identity| {
                self.previous_signing_keys
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&identity)
                    .copied()
            });
            let verified = match bound {
                Some(signing) => self.wrap_sig_verifies_either_domain(
                    &hex::encode(signing), &sig_hex, &sender_user_id, &recipient_user_id,
                    &circle_id, key_version as u32, &eph_hex, &nonce_hex, &ct_hex,
                )?,
                None => false,
            };
            if !verified {
                tracing::warn!(
                    "store_circle_key: wrap CLAIMS to be ours but verifies neither under our own signing key nor under \
                     that of the identity that opens it, for circle {} v{} — refusing to store",
                    circle_id, key_version
                );
                return Err(MobileError::SignatureInvalid);
            }
            true
        } else {
            false
        };

        // SECURITY: A circle key MUST be exactly 32 bytes (XChaCha20-Poly1305 key
        // size). Reject anything else HERE, at ingest, so a malformed key can never
        // enter the key map.
        //
        // The ECDH wrap is NOT authentication: anyone holding our X25519 public key
        // can mint an ephemeral keypair, derive the same wrapping key and seal a
        // plaintext of ARBITRARY length. Authentication is only the Ed25519 wrap
        // signature, and the genuine-first-contact branch above accepts an unsigned
        // wrap by design (TOFU), so on a fresh login or a newly-joined circle a
        // malicious relay could otherwise plant a wrong-length "key".
        //
        // Consequences of letting one through: create_key_chain_link /
        // import_key_chain_link copy_from_slice it into a [0u8; 32] and PANIC, and a
        // panic across the UniFFI boundary is a hard Android/iOS crash; and a
        // malformed key at the active version makes encrypt_data return InvalidKey,
        // silently stopping location upload for that circle.
        //
        // This is the same guard load_persisted_keys already applies to the very
        // same data coming off disk.
        if decrypted.len() != 32 {
            // SECURITY: Do NOT log key lengths - reveals key structure
            tracing::warn!(
                "store_circle_key: REJECTING wrong-length circle key for circle {} v{}",
                circle_id, key_version
            );
            return Err(MobileError::InvalidKey);
        }

        // The unwrap is done: release our private key's read guard before
        // anything below persists (persist_keys reads that lock again).
        drop(guard);

        // On a circle with refresh records, a copy of a version whose record
        // this device holds is taken only if its key verifies that record's
        // tag. A copy that does not is never used, to seal or to read; the app
        // asks for a fresh one.
        if self.copy_contradicts_record(&circle_id, key_version, &decrypted) {
            tracing::warn!(
                "store_circle_key: REFUSING a copy of circle {} v{}: its key does not verify the record's tag",
                circle_id, key_version
            );
            return Err(MobileError::SignatureInvalid);
        }
        // A version whose stored copy didn't read here (kept as stored): on
        // a circle with records, only a copy its record's tag vouches for; on
        // one without, none. And such a copy means the circle is no first
        // contact.
        if self.holds_unreadable_copy(&circle_id, key_version) && !self.copy_vouched_by_record(&circle_id, key_version, &decrypted) {
            tracing::warn!(
                "store_circle_key: REFUSING a copy of circle {} v{}: this device's own copy of that version didn't read, and no record vouches for this one",
                circle_id, key_version
            );
            return Err(MobileError::SignatureInvalid);
        }
        let holds_unreadable = self.unreadable_circle_keys.read().unwrap_or_else(|e| e.into_inner()).contains_key(&CircleKey::of(&circle_id));
        // No unauthenticated first contact while the store can't be read: a key
        // this device held may be in it.
        let first_contact_allowed = !self.store_unreadable();

        // VERSION RULES — the same for every branch above. A key this device
        // already holds is never replaced by a different one: a relabelled or
        // replayed wrap (a removed member's genuinely signed "rotation", an old
        // wrap relabelled as the current version) would otherwise swap the
        // ACTIVE key for one somebody outside the circle knows. And an
        // unauthenticated wrap adds nothing to a circle whose key we already
        // hold, whoever it claims to be from: it is taken only on genuine
        // first contact — no key of any version held — which is the inherent
        // TOFU residual. The three replacements that remain are all keys this
        // device can vouch for:
        //   - our own UNCONFIRMED rotation, by an authenticated wrap: we lost the
        //     rotation race (rotate-keys answered `already_rotated`) and the
        //     winner's key is the circle's;
        //   - a personal-key slot, by the key already held in the other slot
        //     (track-android's copySelfKeySlot realignment);
        //   - the personal key, by a wrap WE signed: nobody else ever holds a
        //     personal key, so any key we signed for it is ours.
        //
        // Decided and applied under ONE write lock, so two imports of the same
        // version cannot both pass the check. Lock order: circle_keys, then
        // unconfirmed_rotations.
        // What a personal key is called in the provenance record.
        let personal_fingerprint = is_personal_slot(&circle_id).then(|| personal_key_fingerprint(&decrypted));
        let decision = {
            let mut keys = self.circle_keys.write().unwrap_or_else(|e| e.into_inner());
            let decision = {
                let unconfirmed = self
                    .unconfirmed_rotations
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&CircleKey::of(&circle_id))
                    .copied();
                let alias_map = personal_key_alias(&circle_id).and_then(|alias| keys.get(&CircleKey::of(&alias)));
                let alias_holds_same = alias_map
                    .and_then(|m| m.get(&key_version))
                    .map_or(false, |held| ct_eq(held, &decrypted));
                let own_map = keys.get(&CircleKey::of(&circle_id));
                // Keys IN USE only: a retired personal key (version <= 0) is
                // history, and never stands in the way of the account's key.
                let in_use = |m: &HashMap<i32, Zeroizing<Vec<u8>>>| m.keys().any(|v| *v >= 1);
                let holds_any = own_map.map_or(false, |m| in_use(m)) || alias_map.map_or(false, |m| in_use(m)) || holds_unreadable;
                if is_personal_slot(&circle_id) && opened_by_previous.is_some() {
                    // A personal key that came ONLY through an identity from before a
                    // reset is history. Signed by that identity's bound key, or
                    // unsigned (a legacy copy, at first contact only), it comes in
                    // RETIRED: never in use, adopted or signed. New rows go under a
                    // key this device mints (`personal_copy_superseded_by_reset`).
                    let held_anywhere = own_map
                        .into_iter()
                        .chain(alias_map)
                        .flat_map(|m| m.values())
                        .any(|held| ct_eq(held, &decrypted));
                    if held_anywhere {
                        StoreDecision::AlreadyHeld
                    } else if authenticated || authenticated_by_previous || !holds_any {
                        StoreDecision::StoreRetired
                    } else {
                        StoreDecision::RefuseUnauthenticated
                    }
                } else if authenticated_by_previous {
                    // Signed by this account before a reset. Stored NEW only, never
                    // replacing a held key.
                    match own_map.and_then(|m| m.get(&key_version)) {
                        Some(held) if ct_eq(held, &decrypted) => StoreDecision::AlreadyHeld,
                        Some(_) => StoreDecision::RefuseConflict,
                        None => StoreDecision::StoreNew { first_contact: !holds_any },
                    }
                } else {
                match own_map.and_then(|m| m.get(&key_version)) {
                    Some(held) if ct_eq(held, &decrypted) => StoreDecision::AlreadyHeld,
                    Some(_) => {
                        if (authenticated && unconfirmed == Some(key_version))
                            || alias_holds_same
                            || (may_replace_personal && authenticated && is_self_wrap && circle_id == PERSONAL_KEY_ID)
                        {
                            StoreDecision::Replace
                        } else {
                            StoreDecision::RefuseConflict
                        }
                    }
                    None => {
                        // While a personal key is held, a DIFFERENT one (a new version,
                        // or into the empty slot beside it) comes in only through
                        // adoption, like a replacement does.
                        if is_personal_slot(&circle_id) && holds_any && !alias_holds_same && !may_replace_personal {
                            StoreDecision::RefuseConflict
                        } else if (!holds_any && first_contact_allowed) || authenticated || alias_holds_same {
                            StoreDecision::StoreNew { first_contact: !holds_any }
                        } else {
                            StoreDecision::RefuseUnauthenticated
                        }
                    }
                }
                }
            };
            if matches!(decision, StoreDecision::StoreRetired) {
                let version_map = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
                let retired_at = next_retired_version(version_map);
                version_map.insert(retired_at, decrypted);
            } else if matches!(decision, StoreDecision::StoreNew { .. } | StoreDecision::Replace) {
                // Cap retained versions per circle to bound memory; oldest dropped
                // (Zeroize-wiped). A personal key is never dropped: a replaced one
                // is RETIRED below version 1, because it is the only key for the
                // rows sealed under it.
                let version_map = keys.entry(CircleKey::of(&circle_id)).or_insert_with(HashMap::new);
                if matches!(decision, StoreDecision::Replace) && is_personal_slot(&circle_id) {
                    if let Some(previous) = version_map.remove(&key_version) {
                        let retired_at = next_retired_version(version_map);
                        version_map.insert(retired_at, previous);
                    }
                }
                insert_circle_version(&circle_id, version_map, key_version, decrypted);
            }
            decision
        };
        if matches!(decision, StoreDecision::StoreNew { .. } | StoreDecision::Replace) {
            self.drop_unreadable_copy(&circle_id, key_version);
        }

        // Provenance: a personal key taken at an UNAUTHENTICATED first contact
        // is marked "taken on trust" and never signed here; a copy signed by
        // THIS account that opens to it clears the mark.
        let provenance_changed = match &personal_fingerprint {
            Some(fingerprint) => {
                let mut provenance = self.personal_provenance.write().unwrap_or_else(|e| e.into_inner());
                match decision {
                    StoreDecision::StoreNew { first_contact: true } | StoreDecision::StoreRetired
                        if !authenticated && !authenticated_by_previous =>
                    {
                        provenance.taken_on_trust.insert(fingerprint.clone())
                    }
                    StoreDecision::AlreadyHeld
                    | StoreDecision::StoreNew { .. }
                    | StoreDecision::Replace
                    | StoreDecision::StoreRetired
                        if (authenticated && is_self_wrap) || authenticated_by_previous =>
                    {
                        provenance.taken_on_trust.remove(fingerprint)
                    }
                    _ => false,
                }
            }
            None => false,
        };

        // Circle provenance. A circle key taken at an UNAUTHENTICATED first
        // contact is marked "taken on trust" and never signed or delivered here;
        // only a copy signed by THIS account (its current key, or the bound key
        // of the restored identity that opened it) clears it. A key that opened
        // only with a restored identity is marked, whoever signed it: that old
        // identity knows it.
        let circle_provenance_changed = if is_personal_slot(&circle_id) {
            false
        } else {
            let mark = (CircleKey::of(&circle_id), key_version);
            let mut provenance = self.circle_provenance.write().unwrap_or_else(|e| e.into_inner());
            let mut changed = false;
            match decision {
                StoreDecision::StoreNew { first_contact: true } if !authenticated && !authenticated_by_previous => {
                    changed |= provenance.taken_on_trust.insert(mark.clone());
                }
                // Only THIS account's signature: its current key, or the bound key
                // of the restored identity that opened it. Never a member's: after
                // a first contact their pin comes from the server's member list,
                // so the same wrap re-imported under it proves nothing new.
                StoreDecision::AlreadyHeld | StoreDecision::StoreNew { .. }
                    if (authenticated && is_self_wrap) || authenticated_by_previous =>
                {
                    changed |= provenance.taken_on_trust.remove(&mark);
                }
                // The key held at that version is now a different, authenticated one.
                StoreDecision::Replace => {
                    changed |= provenance.taken_on_trust.remove(&mark);
                }
                _ => {}
            }
            if opened_by_previous.is_some()
                && matches!(decision, StoreDecision::AlreadyHeld | StoreDecision::StoreNew { .. } | StoreDecision::Replace)
            {
                changed |= provenance.via_previous_identity.insert(mark);
            }
            changed
        };
        let provenance_changed = provenance_changed || circle_provenance_changed;

        let replaced = match decision {
            StoreDecision::AlreadyHeld => {
                // A byte-identical re-import (every sync): nothing changes, so
                // nothing is written. If it is the rotation we minted, the
                // server has it — that version is ours for good now.
                let confirmed = {
                    let mut unconfirmed =
                        self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner());
                    if unconfirmed.get(&CircleKey::of(&circle_id)) == Some(&key_version) {
                        unconfirmed.remove(&CircleKey::of(&circle_id));
                        true
                    } else {
                        false
                    }
                };
                if confirmed {
                    tracing::info!("store_circle_key: our rotation of circle {} to v{} is confirmed", circle_id, key_version);
                }
                if confirmed || provenance_changed {
                    if let Err(e) = self.persist_keys() {
                        tracing::warn!("Failed to persist keys after confirming a rotation: {}", e);
                    }
                }
                return Ok(());
            }
            StoreDecision::RefuseConflict => {
                tracing::warn!(
                    "store_circle_key: REFUSING a wrap for circle {} v{} that carries a DIFFERENT key than the one held for that version, or a second personal key outside adoption (authenticated={}, self={})",
                    circle_id, key_version, authenticated, is_self_wrap
                );
                return Err(MobileError::SignatureInvalid);
            }
            StoreDecision::RefuseUnauthenticated => {
                tracing::warn!(
                    "store_circle_key: REFUSING an unauthenticated wrap for circle {} v{} — this device already holds a key for it (self={}, has_sig={}, has_signer={})",
                    circle_id, key_version, is_self_wrap, has_sig, has_signer
                );
                return Err(MobileError::SignatureInvalid);
            }
            StoreDecision::StoreNew { first_contact } => {
                if first_contact && !authenticated {
                    tracing::warn!(
                        "store_circle_key: accepting first-contact wrap for circle {} v{} (no key held yet — TOFU; self={}, has_sig={}, has_signer={})",
                        circle_id, key_version, is_self_wrap, has_sig, has_signer
                    );
                }
                false
            }
            StoreDecision::Replace => {
                tracing::warn!(
                    "store_circle_key: replacing the key held for circle {} v{} (our unconfirmed rotation, or a personal-key slot)",
                    circle_id, key_version
                );
                true
            }
            StoreDecision::StoreRetired => {
                tracing::info!(
                    "store_circle_key: keeping a personal key from before a reset retired (read-only; authenticated={})",
                    authenticated || authenticated_by_previous
                );
                false
            }
        };

        // SECURITY: Do NOT log key lengths - reveals key structure
        tracing::debug!("store_circle_key SUCCESS for circle_id: {}, version: {}", circle_id, key_version);

        // A replaced unconfirmed rotation is settled either way.
        {
            let mut unconfirmed = self.unconfirmed_rotations.write().unwrap_or_else(|e| e.into_inner());
            if unconfirmed.get(&CircleKey::of(&circle_id)) == Some(&key_version) {
                unconfirmed.remove(&CircleKey::of(&circle_id));
            }
        }

        // Update active version if this is the highest. A retired key is never
        // the one in use.
        let raised_active = !matches!(decision, StoreDecision::StoreRetired) && {
            let mut active = self.active_key_version.write().unwrap_or_else(|e| e.into_inner());
            let current = active.get(&CircleKey::of(&circle_id)).copied().unwrap_or(0);
            if key_version > current {
                active.insert(CircleKey::of(&circle_id), key_version);
                true
            } else {
                false
            }
        };

        // This device's session key was sealed under the previous active
        // key (or under the key just replaced). Keeping it would keep every
        // location sent under it readable to whoever holds that key — a member
        // this rotation removed. The next send falls back to the circle key and
        // the app mints a fresh session key.
        if raised_active || replaced {
            self.sender_session_keys
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&CircleKey::of(&circle_id));
        }

        // A version whose record this device already took as its reference,
        // waiting only for a verified copy of the key, is accepted now (the
        // copy verified the tag above).
        self.accept_reference_with_key(&circle_id, key_version);

        // Auto-persist if secure storage is registered
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after storing circle key: {}", e);
        }

        Ok(())
    }

    /// Sign a wrap context with our Ed25519 signing key, WITHOUT the personal
    /// key refusal: for the internal routes, which check what they sign.
    fn sign_wrap_unchecked(&self, params: SignWrapParams) -> Result<String, MobileError> {
        // Build the sig_input using the locked scheme.
        let sig_input = compute_sig_input(&params)?;

        // Sign with our Ed25519 key.
        let guard = self.signing_keypair.read().unwrap_or_else(|e| e.into_inner());
        let sk = guard.as_ref().ok_or_else(|| {
            MobileError::KeyNotFound("No signing keypair loaded".to_string())
        })?;
        let sig: Signature = sk.sign(sig_input.as_bytes().as_slice());
        Ok(hex::encode(sig.to_bytes()))
    }

    /// Wrap `key` to this device's own X25519 identity: (nonce, ciphertext,
    /// ephemeral public key), the shape `store_circle_key` opens.
    fn wrap_key_to_own_identity(&self, key: &[u8]) -> Result<([u8; 24], Vec<u8>, [u8; 32]), MobileError> {
        let own_public = self
            .public_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MobileError::KeyNotFound("No own public key available".to_string()))?;
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(&own_public);
        drop(ephemeral_secret);
        let wrapping_key = Zeroizing::new(blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes()));
        let nonce: [u8; 24] = generate_secure_nonce();
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), key)
            .map_err(|_| MobileError::EncryptionFailed)?;
        Ok((nonce, ciphertext, ephemeral_public.to_bytes()))
    }

    /// The personal key in use: the nil UUID's, else track-android's "self".
    fn personal_key_in_use(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.get_active_circle_key(PERSONAL_KEY_ID)
            .or_else(|_| self.get_active_circle_key(ANDROID_PERSONAL_KEY_SLOT))
            .ok()
    }

    /// Whether the circle key held at (`circle_id`, `key_version`) was taken on
    /// trust.
    fn circle_key_is_taken_on_trust(&self, circle_id: &str, key_version: i32) -> bool {
        let provenance = self.circle_provenance.read().unwrap_or_else(|e| e.into_inner());
        !provenance.taken_on_trust.is_empty()
            && provenance.taken_on_trust.contains(&(CircleKey::of(circle_id), key_version))
    }

    /// Whether `key` is a personal key this device took on trust.
    fn is_taken_on_trust(&self, key: &[u8]) -> bool {
        let provenance = self.personal_provenance.read().unwrap_or_else(|e| e.into_inner());
        !provenance.taken_on_trust.is_empty()
            && provenance.taken_on_trust.contains(&personal_key_fingerprint(key))
    }

    /// Open a circle-key wrap made for this device (the current identity, then,
    /// with `with_recovered`, any recovered one) WITHOUT storing it, for a check
    /// that must pass before the key is adopted. The same unwrap
    /// `store_circle_key` performs.
    fn open_circle_key_wrap(
        &self,
        sender_public_bytes: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        with_recovered: bool,
    ) -> Result<Zeroizing<Vec<u8>>, MobileError> {
        let sender: [u8; 32] = sender_public_bytes.try_into().map_err(|_| MobileError::InvalidKey)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| MobileError::DecryptionFailed)?;
        let sender_public = PublicKey::from(sender);
        reject_small_order_public(&sender_public)?;
        let guard = self.private_key.read().unwrap_or_else(|e| e.into_inner());
        let private_key = guard
            .as_ref()
            .ok_or_else(|| MobileError::KeyNotFound("No private key available".to_string()))?;
        let shared_secret = private_key.diffie_hellman(&sender_public);
        let wrapping_key = Zeroizing::new(blake3::derive_key("pingolin.circle_key_wrap", shared_secret.as_bytes()));
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_slice()).expect("32-byte key");
        let key = match cipher.decrypt(&XNonce::from(nonce), ciphertext) {
            Ok(plain) => Zeroizing::new(plain),
            Err(_) if with_recovered => self
                .unwrap_with_previous_identity(&sender_public, &nonce, ciphertext)
                .map(|(key, _)| key)
                .ok_or(MobileError::DecryptionFailed)?,
            Err(_) => return Err(MobileError::DecryptionFailed),
        };
        if key.len() != 32 {
            return Err(MobileError::InvalidKey);
        }
        Ok(key)
    }

    /// The adoption verdict for a server copy of the personal key (see
    /// `check_personal_key_adoption`). Stores nothing.
    fn personal_key_verdict(
        &self,
        user_id: &str,
        encrypted_key: &str,
        sender_public_key: &str,
        key_version: i32,
        wrap_signature_hex: &str,
        recorded_pseudonym: &str,
    ) -> PersonalKeyVerdict {
        use PersonalKeyVerdict as V;
        if user_id.is_empty() || !(1..=1_000_000).contains(&key_version) {
            return V::Malformed;
        }
        let Ok(sender_public_bytes) = decode_flexible(sender_public_key) else {
            return V::Malformed;
        };
        let Ok(encrypted_bytes) = hex::decode(encrypted_key) else {
            return V::Malformed;
        };
        if sender_public_bytes.len() != 32 || encrypted_bytes.len() < 24 {
            return V::Malformed;
        }
        let (nonce, ciphertext) = encrypted_bytes.split_at(24);
        let recorded = recorded_pseudonym.trim().to_ascii_lowercase();
        if recorded.is_empty() {
            return V::NothingRecorded;
        }

        // (a) Every copy held here, both personal slots: one in use (version
        // >= 1) that matches means nothing to adopt; a RETIRED one (< 1) that
        // matches means the record names a key this device gave up.
        let (in_use_matches, retired_matches) = {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            let mut found = (false, false);
            for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
                for (version, key) in keys.get(&CircleKey::of(&slot)).into_iter().flatten() {
                    if user_pseudonym_for_key(key, user_id).as_deref() == Some(recorded.as_str()) {
                        if *version >= 1 {
                            found.0 = true;
                        } else {
                            found.1 = true;
                        }
                    }
                }
            }
            found
        };
        if in_use_matches {
            return V::OwnCopyMatches;
        }
        if retired_matches {
            return V::RetiredKey;
        }

        // (c) Signed by THIS account, under the key this device holds.
        let Ok(own_signing_hex) = self.signing_public_key_hex() else {
            return V::NoSigningKey;
        };
        if wrap_signature_hex.is_empty() {
            tracing::warn!("personal key: the server's copy is unsigned; refused");
            return V::Unsigned;
        }
        let signed_by_us = self.wrap_sig_verifies_either_domain(
            &own_signing_hex,
            wrap_signature_hex,
            user_id,
            user_id,
            PERSONAL_KEY_ID,
            key_version as u32,
            &hex::encode(&sender_public_bytes),
            &hex::encode(nonce),
            &hex::encode(ciphertext),
        );
        if !matches!(signed_by_us, Ok(true)) {
            tracing::warn!("personal key: the server's copy is not signed by this account; refused");
            return V::SignatureInvalid;
        }

        let Ok(key) = self.open_circle_key_wrap(&sender_public_bytes, nonce, ciphertext, true) else {
            return V::CannotOpen;
        };
        // A key this device retired is never adopted again.
        let served_is_retired = {
            let keys = self.circle_keys.read().unwrap_or_else(|e| e.into_inner());
            [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT].iter().any(|slot| {
                keys.get(&CircleKey::of(slot)).map_or(false, |versions| {
                    versions.iter().any(|(version, held)| *version < 1 && ct_eq(held, &key))
                })
            })
        };
        if served_is_retired {
            return V::RetiredKey;
        }
        // (b) It is the key the account's history is recorded under.
        if user_pseudonym_for_key(&key, user_id).as_deref() != Some(recorded.as_str()) {
            return V::PseudonymMismatch;
        }
        // Adopting must make it the personal key in use.
        let newer_held = self
            .circle_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(PERSONAL_KEY_ID))
            .map_or(false, |versions| versions.keys().any(|v| *v > key_version));
        if newer_held {
            return V::NewerVersionHeld;
        }
        let last = self.personal_provenance.read().unwrap_or_else(|e| e.into_inner()).last_adoption;
        if last.map_or(false, |at| current_unix_secs().saturating_sub(at) < PERSONAL_ADOPTION_INTERVAL_SECS) {
            return V::TooSoon;
        }
        V::Adopt
    }
}

/// Reading data sealed to an identity from before a password reset.
///
/// An email reset replaces the account keypair, so every circle key — each
/// ECDH-wrapped to the OLD public key — stops opening, and a device holds a
/// valid session while unable to read anything it stored before. These cover the
/// fallback and the two ways it could itself go wrong: preferring a superseded
/// key over the current one, or surviving a logout.
#[cfg(test)]
mod previous_identity_tests {
    use super::*;
    use crate::types::StorageCallbackError;

    /// Seal a recovered key exactly as the account portal's `sealForApps` does:
    /// libsodium secretbox under keyed BLAKE2b of the CURRENT private key.
    fn seal_for_apps(recovered: &StaticSecret, current: &StaticSecret) -> SealedPreviousIdentity {
        use base64::Engine as _;
        use crypto_secretbox::aead::{Aead, KeyInit};
        let engine = base64::engine::general_purpose::STANDARD;
        let wrap = blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity");
        let cipher = XSalsa20Poly1305::new_from_slice(&wrap).unwrap();
        let nonce = [7u8; 24];
        let ciphertext = cipher
            .encrypt(SalsaNonce::from_slice(&nonce), recovered.to_bytes().as_ref())
            .unwrap();
        SealedPreviousIdentity {
            nonce: engine.encode(nonce),
            ciphertext: engine.encode(ciphertext),
        }
    }

    /// Wrap a circle key to a recipient's public key, as a peer would.
    fn wrap_circle_key(circle_key: &[u8; 32], recipient: &PublicKey) -> (String, String) {
        use chacha20poly1305::aead::Aead;
        let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let shared = ephemeral.diffie_hellman(recipient);
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap();
        let nonce = [3u8; 24];
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), circle_key.as_ref())
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        (
            hex::encode(blob),
            hex::encode(PublicKey::from(&ephemeral).as_bytes()),
        )
    }

    fn manager_with(current: &StaticSecret) -> Arc<CryptoManager> {
        let cm = CryptoManager::new();
        cm.import_private_key(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            current.to_bytes(),
        ))
        .expect("import current key");
        cm
    }

    // ------------------------------------------------------------------
    // This account's own signatures from before a reset
    // ------------------------------------------------------------------

    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const CIRCLE: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER_CIRCLE: &str = "33333333-3333-4333-8333-333333333333";
    const MEMBER: &str = "44444444-4444-4444-8444-444444444444";

    /// One account before and after an email reset.
    struct ResetAccount {
        old_sharing: StaticSecret,
        old_signing: SigningKey,
        new_sharing: StaticSecret,
        new_signing: SigningKey,
    }

    fn reset_account() -> ResetAccount {
        ResetAccount {
            old_sharing: StaticSecret::random_from_rng(rand::rngs::OsRng),
            old_signing: SigningKey::generate(&mut rand::rngs::OsRng),
            new_sharing: StaticSecret::random_from_rng(rand::rngs::OsRng),
            new_signing: SigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// A device of the account after the reset: its current identity only.
    fn device_after(a: &ResetAccount) -> Arc<CryptoManager> {
        let cm = manager_with(&a.new_sharing);
        cm.import_signing_private_key(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            a.new_signing.to_bytes(),
        ))
        .unwrap();
        cm
    }

    /// Seal `plain` as the portal seals for the apps, under `label`.
    fn seal_under(plain: &[u8], current: &StaticSecret, label: &[u8]) -> SealedPreviousIdentity {
        use base64::Engine as _;
        use crypto_secretbox::aead::{Aead, KeyInit};
        let engine = base64::engine::general_purpose::STANDARD;
        let wrap = blake2b_keyed_32(current.to_bytes().as_ref(), label);
        let cipher = XSalsa20Poly1305::new_from_slice(&wrap).unwrap();
        let nonce = [9u8; 24];
        let ciphertext = cipher.encrypt(SalsaNonce::from_slice(&nonce), plain).unwrap();
        SealedPreviousIdentity { nonce: engine.encode(nonce), ciphertext: engine.encode(ciphertext) }
    }

    /// The portal's v2 blob: the recovered private key ‖ that identity's signing public key.
    fn seal_v2(identity: &StaticSecret, signing: &[u8; 32], current: &StaticSecret) -> SealedPreviousIdentity {
        seal_under(&[identity.to_bytes().as_slice(), signing.as_slice()].concat(), current, b"pingolin.previous-identity")
    }

    /// Restore the account's old identity: v2 (with its signing key) or v1.
    fn restore(cm: &CryptoManager, a: &ResetAccount, with_signing_key: bool) {
        if with_signing_key {
            let v2 = seal_v2(&a.old_sharing, &a.old_signing.verifying_key().to_bytes(), &a.new_sharing);
            assert_eq!(cm.import_previous_identities_v2(vec![v2]).unwrap(), 1);
        } else {
            assert_eq!(cm.import_previous_identities(vec![seal_for_apps(&a.old_sharing, &a.new_sharing)]).unwrap(), 1);
        }
    }

    /// A wrap of `key` for (circle, version) labelled sender = recipient =
    /// `user`, encrypted to `to` and signed by `signer` (None: unsigned).
    fn labelled_wrap(
        user: &str,
        circle: &str,
        version: i32,
        key: &[u8; 32],
        to: &PublicKey,
        signer: Option<&SigningKey>,
    ) -> (String, String, Option<String>) {
        let (encrypted, eph) = wrap_circle_key(key, to);
        let signature = signer.map(|sk| {
            let bytes = hex::decode(&encrypted).unwrap();
            let input = compute_sig_input(&SignWrapParams {
                domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
                sender_user_id: user.to_string(),
                recipient_user_id: user.to_string(),
                circle_id: circle.to_string(),
                place_id: String::new(),
                key_version: version as u32,
                ephemeral_pubkey_hex: eph.clone(),
                wrap_nonce_hex: hex::encode(&bytes[..24]),
                wrap_ciphertext_hex: hex::encode(&bytes[24..]),
            })
            .unwrap();
            hex::encode(sk.sign(input.as_bytes()).to_bytes())
        });
        (encrypted, eph, signature)
    }

    fn store_own(cm: &CryptoManager, circle: &str, version: i32, wrap: &(String, String, Option<String>)) -> Result<(), MobileError> {
        cm.store_circle_key(
            circle.into(), wrap.0.clone(), wrap.1.clone(), version,
            USER.into(), USER.into(), wrap.2.clone(), None,
        )
    }

    fn held(cm: &CryptoManager, circle: &str, version: i32) -> Option<Vec<u8>> {
        cm.circle_keys.read().unwrap().get(&CircleKey::of(&circle)).and_then(|m| m.get(&version)).map(|k| k.to_vec())
    }

    /// An in-memory key store, for restarts.
    #[derive(Clone, Default)]
    struct MemStore(Arc<std::sync::Mutex<Option<StoredKeyData>>>);
    impl KeyStorageCallback for MemStore {
        fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = Some(data);
            Ok(())
        }
        fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn delete_keys(&self) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn restart(store: &MemStore) -> Arc<CryptoManager> {
        let cm = CryptoManager::new();
        cm.register_secure_storage(Box::new(store.clone()));
        assert!(cm.load_persisted_keys().unwrap());
        cm
    }

    /// A vector from the account portal: its libsodium code sealed this v2
    /// blob; it must open here.
    #[test]
    fn the_portals_v2_vector_opens() {
        let current = StaticSecret::from([0x11u8; 32]);
        assert_eq!(
            hex::encode(blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity")),
            "4f9c6b0ea02870768b8f0ae29e6063bd86edef1a9f1e016ad0bf35a57860b9d2"
        );
        let old_signing_pk = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce";
        assert_eq!(hex::encode(SigningKey::from_bytes(&[0x33u8; 32]).verifying_key().as_bytes()), old_signing_pk);
        let engine = base64::engine::general_purpose::STANDARD;
        let vector = SealedPreviousIdentity {
            nonce: base64::Engine::encode(&engine, [0x44u8; 24]),
            ciphertext: base64::Engine::encode(
                &engine,
                hex::decode(concat!(
                    "e8698f6c2a1bb42924deda3f1011af82221c52dd8ca6a0b4d03ba087808f05ae",
                    "d78e0698b44cff6f6a9ff5f21e8ec4a85e340cbc670f1480908e2e6f85092abe",
                    "bef535c4bd0e1dac803205c1bd6a65d7"
                ))
                .unwrap(),
            ),
        };
        let cm = manager_with(&current);
        assert_eq!(cm.import_previous_identities_v2(vec![vector]).unwrap(), 1);
        assert!(cm.holds_previous_identity(hex::encode(PublicKey::from(&StaticSecret::from([0x22u8; 32])).as_bytes())));
        assert_eq!(cm.previous_signing_public_keys(), vec![old_signing_pk.to_string()]);
    }

    /// The owner-only circle: its only copy is the owner's own wrap, signed
    /// before the reset. Before a restore: the reset state, nothing stored.
    /// With v1 (the private key alone): still refused. With v2: it opens.
    #[test]
    fn an_owner_only_circle_reopens_after_a_restore() {
        let a = reset_account();
        let key = [5u8; 32];
        let wrap = labelled_wrap(USER, CIRCLE, 1, &key, &PublicKey::from(&a.old_sharing), Some(&a.old_signing));
        let dev = device_after(&a);

        assert!(matches!(store_own(&dev, CIRCLE, 1, &wrap), Err(MobileError::DecryptionFailed)));
        assert!(!dev.has_circle_key(CIRCLE.into()));
        assert!(!dev.circle_key_taken_on_trust(CIRCLE.into(), 1));
        assert!(!dev.active_key_came_via_previous_identity(CIRCLE.into()));

        restore(&dev, &a, false);
        assert!(matches!(store_own(&dev, CIRCLE, 1, &wrap), Err(MobileError::SignatureInvalid)));
        assert!(!dev.has_circle_key(CIRCLE.into()));

        restore(&dev, &a, true);
        store_own(&dev, CIRCLE, 1, &wrap).unwrap();
        assert_eq!(held(&dev, CIRCLE, 1).as_deref(), Some(&key[..]));
        assert!(!dev.circle_key_taken_on_trust(CIRCLE.into(), 1), "authenticated, not taken on trust");
        assert!(dev.active_key_came_via_previous_identity(CIRCLE.into()), "rotate before sealing");
    }

    /// A restored identity's signature counts only when that same
    /// identity's key opens the wrap.
    #[test]
    fn a_restored_signature_counts_only_with_its_own_identity() {
        let a = reset_account();
        let q_sharing = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let q_signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let dev = device_after(&a);
        assert_eq!(
            dev.import_previous_identities_v2(vec![
                seal_v2(&a.old_sharing, &a.old_signing.verifying_key().to_bytes(), &a.new_sharing),
                seal_v2(&q_sharing, &q_signing.verifying_key().to_bytes(), &a.new_sharing),
            ])
            .unwrap(),
            2
        );
        let key = [6u8; 32];
        let to_current = labelled_wrap(USER, CIRCLE, 1, &key, &PublicKey::from(&a.new_sharing), Some(&a.old_signing));
        assert!(matches!(store_own(&dev, CIRCLE, 1, &to_current), Err(MobileError::SignatureInvalid)), "signed by P, for the current identity");
        let to_q = labelled_wrap(USER, CIRCLE, 1, &key, &PublicKey::from(&q_sharing), Some(&a.old_signing));
        assert!(matches!(store_own(&dev, CIRCLE, 1, &to_q), Err(MobileError::SignatureInvalid)), "signed by P, opening with Q");
        assert!(!dev.has_circle_key(CIRCLE.into()));
        let q_own = labelled_wrap(USER, CIRCLE, 1, &key, &PublicKey::from(&q_sharing), Some(&q_signing));
        store_own(&dev, CIRCLE, 1, &q_own).unwrap();
        assert_eq!(held(&dev, CIRCLE, 1).as_deref(), Some(&key[..]));

        // A restored identity R with NO signing key (v1): P's signature on a
        // wrap R opens counts for nothing, though P's signing key is held.
        let r_sharing = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let solo = device_after(&a);
        assert_eq!(
            solo.import_previous_identities_v2(vec![
                seal_v2(&a.old_sharing, &a.old_signing.verifying_key().to_bytes(), &a.new_sharing),
                seal_for_apps(&r_sharing, &a.new_sharing),
            ])
            .unwrap(),
            2
        );
        let to_r = labelled_wrap(USER, CIRCLE, 1, &key, &PublicKey::from(&r_sharing), Some(&a.old_signing));
        assert!(matches!(store_own(&solo, CIRCLE, 1, &to_r), Err(MobileError::SignatureInvalid)), "signed by P, opening with v1-only R");
        assert!(!solo.has_circle_key(CIRCLE.into()));
    }

    /// A restored identity's signature stores NEW only. Never over a held
    /// key, not even our own unconfirmed rotation, which our current
    /// signature may replace.
    #[test]
    fn a_restored_signature_stores_new_only() {
        let a = reset_account();
        let old_pk = PublicKey::from(&a.old_sharing);
        let new_pk = PublicKey::from(&a.new_sharing);
        let dev = device_after(&a);
        restore(&dev, &a, true);
        let (k1, k2, k3) = ([1u8; 32], [2u8; 32], [3u8; 32]);

        store_own(&dev, CIRCLE, 2, &labelled_wrap(USER, CIRCLE, 2, &k2, &new_pk, Some(&a.new_signing))).unwrap();
        store_own(&dev, CIRCLE, 1, &labelled_wrap(USER, CIRCLE, 1, &k1, &old_pk, Some(&a.old_signing))).unwrap();
        assert_eq!(held(&dev, CIRCLE, 1).as_deref(), Some(&k1[..]), "an older version, stored new");
        assert_eq!(dev.get_active_version(CIRCLE.into()).unwrap(), 2);

        let over = labelled_wrap(USER, CIRCLE, 2, &k3, &old_pk, Some(&a.old_signing));
        assert!(matches!(store_own(&dev, CIRCLE, 2, &over), Err(MobileError::SignatureInvalid)));
        assert_eq!(held(&dev, CIRCLE, 2).as_deref(), Some(&k2[..]));

        dev.unconfirmed_rotations.write().unwrap().insert(CircleKey::of(CIRCLE), 2);
        assert!(matches!(store_own(&dev, CIRCLE, 2, &over), Err(MobileError::SignatureInvalid)), "not our unconfirmed rotation");
        assert_eq!(held(&dev, CIRCLE, 2).as_deref(), Some(&k2[..]));
        // Control: our CURRENT signature may replace our own unconfirmed rotation.
        store_own(&dev, CIRCLE, 2, &labelled_wrap(USER, CIRCLE, 2, &k3, &new_pk, Some(&a.new_signing))).unwrap();
        assert_eq!(held(&dev, CIRCLE, 2).as_deref(), Some(&k3[..]));
    }

    /// The personal key signed before a reset comes in RETIRED only: never in
    /// use, never published, still retired after a restart, kept beside a new
    /// personal key, and never in the way of the account's new copy. The
    /// device learns it may mint a new one only once the old one is held.
    #[test]
    fn the_old_personal_key_comes_in_retired_only() {
        let a = reset_account();
        let old_pk = PublicKey::from(&a.old_sharing);
        let new_pk = PublicKey::from(&a.new_sharing);
        let store = MemStore::default();
        let dev = device_after(&a);
        dev.register_secure_storage(Box::new(store.clone()));
        let old_personal = [8u8; 32];
        let old_copy = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &old_personal, &old_pk, Some(&a.old_signing));
        let superseded = |cm: &CryptoManager| cm.personal_copy_superseded_by_reset(old_copy.0.clone(), old_copy.1.clone());
        assert!(!superseded(&dev), "nothing restored: this device can't tell");
        restore(&dev, &a, false);
        assert!(matches!(store_own(&dev, PERSONAL_KEY_ID, 1, &old_copy), Err(MobileError::SignatureInvalid)));
        assert!(!superseded(&dev), "v1 alone: the old key is not held here, so minting would lose it");

        restore(&dev, &a, true);
        store_own(&dev, PERSONAL_KEY_ID, 1, &old_copy).unwrap();
        assert!(dev.personal_key_in_use().is_none(), "retired, never in use");
        assert!(dev.get_active_version(PERSONAL_KEY_ID.into()).is_err(), "no version in use at all");
        assert_eq!(held(&dev, PERSONAL_KEY_ID, 0).as_deref(), Some(&old_personal[..]));
        assert!(dev.publishable_personal_key(PERSONAL_KEY_ID.into(), USER.into()).is_err());
        store_own(&dev, PERSONAL_KEY_ID, 1, &old_copy).unwrap();
        assert_eq!(dev.circle_keys.read().unwrap()[&CircleKey::of(PERSONAL_KEY_ID)].len(), 1, "a re-import is already held");
        assert!(superseded(&dev), "the old key is held retired and nothing is in use: mint");
        let unknown = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &[0x18u8; 32], &old_pk, Some(&a.old_signing));
        assert!(
            !dev.personal_copy_superseded_by_reset(unknown.0.clone(), unknown.1.clone()),
            "a key this device does not hold: minting would lose it"
        );

        let after_restart = restart(&store);
        assert!(after_restart.personal_key_in_use().is_none(), "a slot of retired keys has none in use after a restart");
        assert_eq!(held(&after_restart, PERSONAL_KEY_ID, 0).as_deref(), Some(&old_personal[..]));

        // A new personal key for new rows; the retired one stays beside it.
        let creation = after_restart.prepare_circle_creation().unwrap();
        after_restart.finalize_circle_creation(creation.temp_circle_id, PERSONAL_KEY_ID.into()).unwrap();
        let new_personal = after_restart.personal_key_in_use().unwrap();
        assert_ne!(new_personal.as_slice(), &old_personal[..]);
        assert_eq!(held(&after_restart, PERSONAL_KEY_ID, 0).as_deref(), Some(&old_personal[..]));
        after_restart.import_previous_identities_v2(vec![seal_v2(&a.old_sharing, &a.old_signing.verifying_key().to_bytes(), &a.new_sharing)]).unwrap();
        assert!(!superseded(&after_restart), "a key in use: nothing to mint");

        // Another device holding only the retired key takes the account's NEW copy.
        let other = device_after(&a);
        restore(&other, &a, true);
        store_own(&other, PERSONAL_KEY_ID, 1, &old_copy).unwrap();
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&new_personal);
        let new_copy = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &new_key, &new_pk, Some(&a.new_signing));
        assert!(!other.personal_copy_superseded_by_reset(new_copy.0.clone(), new_copy.1.clone()), "a copy for the current identity");
        store_own(&other, PERSONAL_KEY_ID, 1, &new_copy).unwrap();
        assert_eq!(other.personal_key_in_use().unwrap().as_slice(), &new_key[..]);
        assert_eq!(held(&other, PERSONAL_KEY_ID, 0).as_deref(), Some(&old_personal[..]));
    }

    /// `has_circle_key` is the READ gate, true for any key held, a retired
    /// personal key included; `has_circle_key_in_use` is the WRITE gate, true
    /// only for a key this device may seal under.
    #[test]
    fn has_circle_key_in_use_is_the_write_gate() {
        let a = reset_account();
        let old_pk = PublicKey::from(&a.old_sharing);
        let store = MemStore::default();
        let dev = device_after(&a);
        dev.register_secure_storage(Box::new(store.clone()));
        for slot in [PERSONAL_KEY_ID, CIRCLE] {
            assert!(!dev.has_circle_key(slot.into()), "{slot}: nothing held");
            assert!(!dev.has_circle_key_in_use(slot.into()), "{slot}: nothing held");
        }

        // A personal slot holding only the retired pre-reset key.
        restore(&dev, &a, true);
        let old_copy = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &[8u8; 32], &old_pk, Some(&a.old_signing));
        store_own(&dev, PERSONAL_KEY_ID, 1, &old_copy).unwrap();
        assert!(dev.has_circle_key(PERSONAL_KEY_ID.into()), "READ: the retired key still opens old rows");
        assert!(!dev.has_circle_key_in_use(PERSONAL_KEY_ID.into()), "WRITE: nothing to seal under");
        let after_restart = restart(&store);
        assert!(after_restart.has_circle_key(PERSONAL_KEY_ID.into()));
        assert!(!after_restart.has_circle_key_in_use(PERSONAL_KEY_ID.into()), "the same after a restart");

        // A new personal key beside it: both.
        let personal = after_restart.prepare_circle_creation().unwrap();
        after_restart.finalize_circle_creation(personal.temp_circle_id, PERSONAL_KEY_ID.into()).unwrap();
        assert!(after_restart.has_circle_key(PERSONAL_KEY_ID.into()));
        assert!(after_restart.has_circle_key_in_use(PERSONAL_KEY_ID.into()));

        // A real circle: the two agree.
        let circle = after_restart.prepare_circle_creation().unwrap();
        assert!(after_restart.has_circle_key(circle.temp_circle_id.clone()));
        assert!(after_restart.has_circle_key_in_use(circle.temp_circle_id.clone()));
        after_restart.finalize_circle_creation(circle.temp_circle_id, CIRCLE.into()).unwrap();
        assert!(after_restart.has_circle_key(CIRCLE.into()));
        assert!(after_restart.has_circle_key_in_use(CIRCLE.into()));
    }

    /// An UNSIGNED legacy personal copy that opens only through a restored
    /// identity is retired too, and the device mints its own new key. One that
    /// opens with the CURRENT identity keeps the first-contact rule.
    #[test]
    fn an_unsigned_pre_reset_personal_copy_is_retired_too() {
        let a = reset_account();
        let old_pk = PublicKey::from(&a.old_sharing);
        let dev = device_after(&a);
        restore(&dev, &a, false);
        let legacy = [0x5au8; 32];
        let unsigned_old = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &legacy, &old_pk, None);
        store_own(&dev, PERSONAL_KEY_ID, 1, &unsigned_old).unwrap();
        assert!(dev.personal_key_in_use().is_none(), "retired, never in use");
        assert_eq!(held(&dev, PERSONAL_KEY_ID, 0).as_deref(), Some(&legacy[..]));
        assert!(dev.is_taken_on_trust(&legacy), "unauthenticated: marked, as any first contact");
        assert!(dev.personal_copy_superseded_by_reset(unsigned_old.0.clone(), unsigned_old.1.clone()), "mint a new one");

        let creation = dev.prepare_circle_creation().unwrap();
        dev.finalize_circle_creation(creation.temp_circle_id, PERSONAL_KEY_ID.into()).unwrap();
        let minted = dev.personal_key_in_use().unwrap();
        assert_ne!(minted.as_slice(), &legacy[..]);
        assert!(dev.publishable_personal_key(PERSONAL_KEY_ID.into(), USER.into()).is_ok(), "the minted key publishes");
        assert_eq!(held(&dev, PERSONAL_KEY_ID, 0).as_deref(), Some(&legacy[..]), "the old one stays for history");
        assert!(!dev.personal_copy_superseded_by_reset(unsigned_old.0.clone(), unsigned_old.1.clone()));

        // With a key in use, an unsigned copy of ANOTHER old key is refused, as
        // any unauthenticated personal copy is after first contact.
        let another = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &[0x5bu8; 32], &old_pk, None);
        assert!(matches!(store_own(&dev, PERSONAL_KEY_ID, 1, &another), Err(MobileError::SignatureInvalid)));
        assert_eq!(dev.personal_key_in_use().unwrap().as_slice(), minted.as_slice());

        // An unsigned copy for the CURRENT identity: an ordinary first contact.
        let fresh = device_after(&a);
        let current_copy = labelled_wrap(USER, PERSONAL_KEY_ID, 1, &legacy, &PublicKey::from(&a.new_sharing), None);
        store_own(&fresh, PERSONAL_KEY_ID, 1, &current_copy).unwrap();
        assert_eq!(fresh.personal_key_in_use().unwrap().as_slice(), &legacy[..], "in use, as on any first contact");
        assert!(fresh.publishable_personal_key(PERSONAL_KEY_ID.into(), USER.into()).is_err(), "taken on trust, as on any first contact");
    }

    /// The taken-on-trust mark: a circle key taken on trust is never signed
    /// here, by the own-wrap signing route, until a copy this account signed
    /// opens to it.
    #[test]
    fn a_circle_key_taken_on_trust_is_never_signed() {
        let a = reset_account();
        let new_pk = PublicKey::from(&a.new_sharing);
        let store = MemStore::default();
        let dev = device_after(&a);
        dev.register_secure_storage(Box::new(store.clone()));
        let key = [4u8; 32];
        let unsigned = labelled_wrap(USER, CIRCLE, 1, &key, &new_pk, None);
        store_own(&dev, CIRCLE, 1, &unsigned).unwrap();
        assert!(dev.circle_key_taken_on_trust(CIRCLE.into(), 1));
        let sign = |cm: &CryptoManager| {
            cm.sign_own_circle_key_wrap(CIRCLE.into(), USER.into(), 1, unsigned.0.clone(), unsigned.1.clone())
        };
        assert!(matches!(sign(&dev), Err(MobileError::InvalidInput(_))));

        let after_restart = restart(&store);
        assert!(after_restart.circle_key_taken_on_trust(CIRCLE.into(), 1), "the mark is persisted");
        assert!(matches!(sign(&after_restart), Err(MobileError::InvalidInput(_))));

        let member_sharing = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let deliver = |cm: &CryptoManager| {
            cm.wrap_circle_key_for_member_full(
                CIRCLE.into(),
                hex::encode(PublicKey::from(&member_sharing).as_bytes()),
                USER.into(),
                MEMBER.into(),
                String::new(),
            )
        };
        assert!(after_restart.active_key_taken_on_trust(CIRCLE.into()));
        assert!(matches!(deliver(&after_restart), Err(MobileError::InvalidInput(_))), "never delivered under our signature");

        let ours = labelled_wrap(USER, CIRCLE, 1, &key, &new_pk, Some(&a.new_signing));
        store_own(&after_restart, CIRCLE, 1, &ours).unwrap();
        assert!(!after_restart.circle_key_taken_on_trust(CIRCLE.into(), 1), "a copy this account signed clears it");
        assert!(!after_restart.active_key_taken_on_trust(CIRCLE.into()));
        assert!(sign(&after_restart).is_ok());
        assert!(deliver(&after_restart).is_ok());

        // A first contact from an UNPINNED sender, then that sender pinned (as
        // the apps do from the member list, i.e. the server's word) and the SAME
        // signed wrap re-imported: still taken on trust, and nothing delivered.
        // Only this account's own signed copy clears it.
        let fresh = device_after(&a);
        let other_key = [0x2au8; 32];
        let member_signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let (encrypted, eph) = wrap_circle_key(&other_key, &new_pk);
        let bytes = hex::decode(&encrypted).unwrap();
        let input = compute_sig_input(&SignWrapParams {
            domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
            sender_user_id: MEMBER.to_string(),
            recipient_user_id: USER.to_string(),
            circle_id: OTHER_CIRCLE.to_string(),
            place_id: String::new(),
            key_version: 1,
            ephemeral_pubkey_hex: eph.clone(),
            wrap_nonce_hex: hex::encode(&bytes[..24]),
            wrap_ciphertext_hex: hex::encode(&bytes[24..]),
        })
        .unwrap();
        let member_signature = hex::encode(member_signing.sign(input.as_bytes()).to_bytes());
        let member_signing_hex = hex::encode(member_signing.verifying_key().as_bytes());
        let from_member = |cm: &CryptoManager| {
            cm.store_circle_key(
                OTHER_CIRCLE.into(), encrypted.clone(), eph.clone(), 1, MEMBER.into(), USER.into(),
                Some(member_signature.clone()), Some(member_signing_hex.clone()),
            )
        };
        from_member(&fresh).unwrap();
        assert!(fresh.circle_key_taken_on_trust(OTHER_CIRCLE.into(), 1), "a first contact");
        fresh
            .pin_member_keys(
                OTHER_CIRCLE.into(),
                MEMBER.into(),
                hex::encode(PublicKey::from(&member_sharing).as_bytes()),
                member_signing_hex.clone(),
            )
            .unwrap();
        from_member(&fresh).unwrap();
        assert!(fresh.circle_key_taken_on_trust(OTHER_CIRCLE.into(), 1), "re-imported under the server's pin: still marked");
        let deliver_other = |cm: &CryptoManager| {
            cm.wrap_circle_key_for_member_full(
                OTHER_CIRCLE.into(),
                hex::encode(PublicKey::from(&member_sharing).as_bytes()),
                USER.into(),
                MEMBER.into(),
                String::new(),
            )
        };
        assert!(matches!(deliver_other(&fresh), Err(MobileError::InvalidInput(_))), "nothing delivered");
        let own_copy = labelled_wrap(USER, OTHER_CIRCLE, 1, &other_key, &new_pk, Some(&a.new_signing));
        store_own(&fresh, OTHER_CIRCLE, 1, &own_copy).unwrap();
        assert!(!fresh.circle_key_taken_on_trust(OTHER_CIRCLE.into(), 1), "our own signed copy clears it");
        assert!(deliver_other(&fresh).is_ok());

        // So does our PRE-RESET signature, bound to the restored identity that
        // opens the copy.
        let restored = device_after(&a);
        restore(&restored, &a, true);
        let old_pk = PublicKey::from(&a.old_sharing);
        let pre_reset_key = [0x3cu8; 32];
        store_own(&restored, CIRCLE, 1, &labelled_wrap(USER, CIRCLE, 1, &pre_reset_key, &old_pk, None)).unwrap();
        assert!(restored.circle_key_taken_on_trust(CIRCLE.into(), 1), "an unsigned first contact");
        store_own(&restored, CIRCLE, 1, &labelled_wrap(USER, CIRCLE, 1, &pre_reset_key, &old_pk, Some(&a.old_signing)))
            .unwrap();
        assert!(!restored.circle_key_taken_on_trust(CIRCLE.into(), 1), "our pre-reset signature, bound to its identity");
    }

    /// A key that opened only through a previous identity is marked, own wraps
    /// and member wraps alike; the mark survives a restart and the flag ends
    /// with a newer version.
    #[test]
    fn a_key_known_to_the_old_identity_is_flagged_until_rotated() {
        let a = reset_account();
        let old_pk = PublicKey::from(&a.old_sharing);
        let new_pk = PublicKey::from(&a.new_sharing);
        let store = MemStore::default();
        let dev = device_after(&a);
        dev.register_secure_storage(Box::new(store.clone()));
        restore(&dev, &a, true);
        store_own(&dev, CIRCLE, 1, &labelled_wrap(USER, CIRCLE, 1, &[1u8; 32], &old_pk, Some(&a.old_signing))).unwrap();
        assert!(dev.active_key_came_via_previous_identity(CIRCLE.into()));

        // A pinned member's wrap to the old identity.
        let member_signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let member_sharing = StaticSecret::random_from_rng(rand::rngs::OsRng);
        dev.pin_member_keys(
            OTHER_CIRCLE.into(),
            MEMBER.into(),
            hex::encode(PublicKey::from(&member_sharing).as_bytes()),
            hex::encode(member_signing.verifying_key().as_bytes()),
        )
        .unwrap();
        let (encrypted, eph) = wrap_circle_key(&[7u8; 32], &old_pk);
        let bytes = hex::decode(&encrypted).unwrap();
        let input = compute_sig_input(&SignWrapParams {
            domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
            sender_user_id: MEMBER.to_string(),
            recipient_user_id: USER.to_string(),
            circle_id: OTHER_CIRCLE.to_string(),
            place_id: String::new(),
            key_version: 1,
            ephemeral_pubkey_hex: eph.clone(),
            wrap_nonce_hex: hex::encode(&bytes[..24]),
            wrap_ciphertext_hex: hex::encode(&bytes[24..]),
        })
        .unwrap();
        dev.store_circle_key(
            OTHER_CIRCLE.into(), encrypted, eph, 1, MEMBER.into(), USER.into(),
            Some(hex::encode(member_signing.sign(input.as_bytes()).to_bytes())), None,
        )
        .unwrap();
        assert!(dev.active_key_came_via_previous_identity(OTHER_CIRCLE.into()));

        let after_restart = restart(&store);
        assert!(after_restart.active_key_came_via_previous_identity(CIRCLE.into()));
        store_own(&after_restart, CIRCLE, 2, &labelled_wrap(USER, CIRCLE, 2, &[2u8; 32], &new_pk, Some(&a.new_signing)))
            .unwrap();
        assert!(!after_restart.active_key_came_via_previous_identity(CIRCLE.into()), "a newer version ends it");
    }

    /// v2 blobs: a signing key is trusted only for a restored identity, never
    /// the current one or the current signing key, never when it clashes, and
    /// a v2 blob wins over a v1 blob of the same identity.
    #[test]
    fn v2_blobs_are_checked_at_import() {
        let a = reset_account();
        let dev = device_after(&a);
        let old_signing_pub = a.old_signing.verifying_key().to_bytes();
        let current_signing_pub = a.new_signing.verifying_key().to_bytes();
        let not_a_point = (0u8..=255)
            .map(|b| [b; 32])
            .find(|k| VerifyingKey::from_bytes(k).is_err())
            .expect("a byte pattern that is not a point");
        let v1 = || seal_for_apps(&a.old_sharing, &a.new_sharing);
        let v2 = |signing: &[u8; 32]| seal_v2(&a.old_sharing, signing, &a.new_sharing);
        let import = |blobs: Vec<SealedPreviousIdentity>| {
            let count = dev.import_previous_identities_v2(blobs).unwrap();
            (count, dev.previous_signing_public_keys())
        };

        let wrong_length = seal_under(&[7u8; 48], &a.new_sharing, b"pingolin.previous-identity");
        assert_eq!(import(vec![wrong_length]), (0, vec![]), "48 bytes");
        assert_eq!(import(vec![seal_v2(&a.new_sharing, &old_signing_pub, &a.new_sharing)]), (0, vec![]), "the current identity");
        assert_eq!(import(vec![v2(&current_signing_pub)]), (1, vec![]), "the current signing key");
        assert_eq!(import(vec![v2(&not_a_point)]), (1, vec![]), "not a signing key");
        let other_label = seal_under(
            &[a.old_sharing.to_bytes().as_slice(), old_signing_pub.as_slice()].concat(),
            &a.new_sharing,
            b"pingolin.previous-identity.signing",
        );
        assert_eq!(import(vec![other_label]), (0, vec![]), "another label");

        let stranger = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let shared_key = seal_v2(&stranger, &old_signing_pub, &a.new_sharing);
        assert_eq!(import(vec![v2(&old_signing_pub), shared_key]), (2, vec![]), "one signing key, two identities");
        let other_signing = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key().to_bytes();
        assert_eq!(import(vec![v2(&old_signing_pub), v2(&other_signing)]), (1, vec![]), "two signing keys, one identity");

        let expected = vec![hex::encode(old_signing_pub)];
        assert_eq!(import(vec![v1(), v2(&old_signing_pub)]), (1, expected.clone()), "v2 wins over v1");
        assert_eq!(import(vec![v2(&old_signing_pub), v1()]), (1, expected.clone()), "in either order");
        assert_eq!(import(vec![v1()]), (1, vec![]), "v1 alone: no signing key");

        // A v1 answer after a v2 one: signing keys are listed only for the
        // identities held, and a re-imported identity keeps its signing key.
        assert_eq!(import(vec![v2(&old_signing_pub)]), (1, expected.clone()));
        assert_eq!(dev.import_previous_identities(vec![seal_for_apps(&stranger, &a.new_sharing)]).unwrap(), 1);
        assert!(dev.previous_signing_public_keys().is_empty(), "the old identity is no longer held");
        assert_eq!(dev.import_previous_identities(vec![v1()]).unwrap(), 1);
        assert_eq!(dev.previous_signing_public_keys(), expected, "held again: its v2 signing key still counts");
    }

    /// Own statements: which key verified, and our own pre-reset invitation
    /// renews only with the v2 key.
    #[test]
    fn own_statements_say_which_key_verified() {
        use crate::membership::{InvitationRenewalFacts, MembershipStatement, MembershipStatementKind, OwnStatementSigner, INVITATION_LIFETIME_SECS};
        let a = reset_account();
        let signer = |sharing: &StaticSecret, signing: &SigningKey| {
            let cm = manager_with(sharing);
            cm.import_signing_private_key(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing.to_bytes()))
                .unwrap();
            cm
        };
        let now = chrono::Utc::now().timestamp();
        let hexseq = |start: u8| -> String { (0..32u8).map(|i| format!("{:02x}", start.wrapping_add(i))).collect() };
        let statement = MembershipStatement {
            kind: MembershipStatementKind::InvitationToAccount,
            circle_id: CIRCLE.into(),
            statement_id: "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e".into(),
            signer_user_id: USER.into(),
            issued_at: now - 60,
            expires_at: now - 60 + INVITATION_LIFETIME_SECS,
            at_version: 1,
            subject_user_id: Some(MEMBER.into()),
            subject_sharing_public_key_hex: Some(hexseq(0x40)),
            subject_signing_public_key_hex: Some(hexseq(0x60)),
            subject_email: None,
        };
        let before = signer(&a.old_sharing, &a.old_signing).sign_membership_statement(statement.clone()).unwrap();
        let after = signer(&a.new_sharing, &a.new_signing).sign_membership_statement(statement.clone()).unwrap();
        let stranger = SigningKey::generate(&mut rand::rngs::OsRng);
        let theirs = signer(&StaticSecret::random_from_rng(rand::rngs::OsRng), &stranger).sign_membership_statement(statement).unwrap();

        let dev = device_after(&a);
        store_own(&dev, CIRCLE, 1, &labelled_wrap(USER, CIRCLE, 1, &[1u8; 32], &PublicKey::from(&a.new_sharing), Some(&a.new_signing)))
            .unwrap();
        let which = |s: &crate::membership::SignedMembershipStatement| {
            dev.verify_own_membership_statement(s.statement_hex.clone(), s.signature_hex.clone()).unwrap()
        };
        let facts = || InvitationRenewalFacts {
            original_signer_is_owner_or_admin_now: true,
            renewer_is_owner_or_admin: true,
            subject_departed_or_tombstoned: false,
            invitation_withdrawn_or_dead: false,
        };
        let renew = || {
            dev.renew_invitation(
                CIRCLE.into(), USER.into(), before.statement_hex.clone(), before.signature_hex.clone(),
                hexseq(0x41), hexseq(0x61), facts(),
            )
        };
        assert_eq!(which(&after), OwnStatementSigner::CurrentKey);
        assert_eq!(which(&before), OwnStatementSigner::NotOurs, "nothing restored");
        assert!(matches!(renew(), Err(MobileError::SignatureInvalid)));
        restore(&dev, &a, false);
        assert_eq!(which(&before), OwnStatementSigner::NotOurs, "v1: the private key alone");
        assert!(matches!(renew(), Err(MobileError::SignatureInvalid)));
        restore(&dev, &a, true);
        assert_eq!(which(&before), OwnStatementSigner::PreviousKey);
        assert_eq!(which(&after), OwnStatementSigner::CurrentKey);
        assert_eq!(which(&theirs), OwnStatementSigner::NotOurs);
        let renewed = renew().unwrap();
        assert_eq!(which(&renewed), OwnStatementSigner::CurrentKey, "a renewal is signed with the current key");
    }

    /// Only an identity this device holds the private key of counts;
    /// the current key, a stranger's key and malformed input do not.
    #[test]
    fn holds_previous_identity_names_only_identities_this_device_opened() {
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let older = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let stranger = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let hex_of = |k: &StaticSecret| hex::encode(PublicKey::from(k).as_bytes());
        let cm = manager_with(&new);
        assert!(!cm.holds_previous_identity(hex_of(&old)), "nothing recovered yet");

        // `older` was sealed under a key this device does not hold: not opened.
        let sealed_elsewhere = seal_for_apps(&older, &stranger);
        assert_eq!(cm.import_previous_identities(vec![seal_for_apps(&old, &new), sealed_elsewhere]).unwrap(), 1);
        assert!(cm.holds_previous_identity(hex_of(&old)));
        assert!(cm.holds_previous_identity(hex_of(&old).to_uppercase()));
        assert!(cm.holds_previous_identity(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            PublicKey::from(&old).as_bytes(),
        )));
        assert!(!cm.holds_previous_identity(hex_of(&older)), "a blob this device could not open");
        assert!(!cm.holds_previous_identity(hex_of(&new)), "the current identity is not a previous one");
        assert!(!cm.holds_previous_identity(hex_of(&stranger)));
        assert!(!cm.holds_previous_identity(String::new()));
        assert!(!cm.holds_previous_identity(hex_of(&old)[..62].to_string()));
        assert!(!cm.holds_previous_identity("zz".repeat(32)));
        assert!(!cm.holds_previous_identity("not a key!".into()), "neither hex nor base64");
    }

    /// The holder's published-copy check counts only this account's CURRENT
    /// keys. A copy only a recovered (pre-reset) identity opens is one the
    /// account's other devices cannot open: CannotOpen.
    #[test]
    fn a_copy_only_a_recovered_identity_opens_is_cannot_open_for_the_holder() {
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let cm = manager_with(&new);
        cm.generate_signing_keypair();
        assert_eq!(cm.import_previous_identities(vec![seal_for_apps(&old, &new)]).unwrap(), 1);
        let personal = [7u8; 32];
        let (to_new, eph_new) = wrap_circle_key(&personal, &PublicKey::from(&new));
        let uid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string();
        // Labelled as this account's own, as every app stores its copy: an
        // unlabelled wrap into the personal slot is refused.
        cm.store_circle_key(PERSONAL_KEY_ID.into(), to_new.clone(), eph_new.clone(), 1, uid.clone(), uid.clone(), None, None)
            .unwrap();
        let (to_old, eph_old) = wrap_circle_key(&personal, &PublicKey::from(&old));
        assert_eq!(
            cm.check_published_personal_copy(uid.clone(), to_old, eph_old, 1, None),
            PublishedCopyStatus::CannotOpen
        );
        // Positive control: the same key wrapped to the current identity opens.
        assert_eq!(cm.check_published_personal_copy(uid, to_new, eph_new, 1, None), PublishedCopyStatus::Unsigned);
    }

    #[test]
    fn opens_a_circle_key_wrapped_to_the_pre_reset_identity() {
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let circle_key = [42u8; 32];
        let (blob, ephemeral) = wrap_circle_key(&circle_key, &PublicKey::from(&old));

        let cm = manager_with(&new);

        // Without the recovered identity the circle is unreadable.
        assert!(cm
            .store_circle_key("c1".into(), blob.clone(), ephemeral.clone(), 1,
                              String::new(), String::new(), None, None)
            .is_err());

        let imported = cm
            .import_previous_identities(vec![seal_for_apps(&old, &new)])
            .expect("import");
        assert_eq!(imported, 1);

        cm.store_circle_key("c1".into(), blob, ephemeral, 1,
                            String::new(), String::new(), None, None)
            .expect("opens with the recovered identity");
        assert!(cm.has_circle_key("c1".into()));
    }

    #[test]
    fn a_blob_sealed_to_someone_else_is_skipped_not_fatal() {
        // After a SECOND reset the seal is under a key we no longer hold. It
        // opens nothing, so it must be skipped quietly rather than failing the
        // import and taking the readable identities down with it.
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let stranger = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);

        let cm = manager_with(&new);
        let imported = cm
            .import_previous_identities(vec![
                seal_for_apps(&old, &stranger), // unreadable
                seal_for_apps(&old, &new),      // readable
            ])
            .expect("import");
        assert_eq!(imported, 1);
    }

    #[test]
    fn the_wrap_is_label_bound() {
        // note derives its vault key with the SAME construction over the SAME
        // input. If a differently-labelled key opened this, one derived key
        // would stand in for another.
        let current = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recovered = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let sealed = seal_for_apps(&recovered, &current);

        let vault_labelled =
            blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin-note-vault");
        assert!(open_secretbox(&sealed.ciphertext, &sealed.nonce, &vault_labelled).is_err());

        let right = blake2b_keyed_32(current.to_bytes().as_ref(), b"pingolin.previous-identity");
        assert!(open_secretbox(&sealed.ciphertext, &sealed.nonce, &right).is_ok());
    }

    #[test]
    fn logging_out_drops_them() {
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let cm = manager_with(&new);
        cm.import_previous_identities(vec![seal_for_apps(&old, &new)]).unwrap();
        assert_eq!(cm.previous_identity_count(), 1);

        cm.clear_all_keys();
        // Account key material must not outlive the session on a shared device.
        assert_eq!(cm.previous_identity_count(), 0);
    }
}

#[cfg(test)]
mod previous_vault_key_tests {
    use super::*;

    /// The vault key of a recovered identity must match what that identity
    /// derived before the reset — note's whole library hangs off this one value.
    #[test]
    fn a_recovered_identity_yields_its_own_era_vault_key() {
        use base64::Engine as _;
        let old = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new = StaticSecret::random_from_rng(rand::rngs::OsRng);

        let cm = CryptoManager::new();
        cm.import_private_key(
            base64::engine::general_purpose::STANDARD.encode(new.to_bytes()),
        )
        .unwrap();

        // Seal as the account portal does.
        use crypto_secretbox::aead::{Aead, KeyInit};
        let wrap = blake2b_keyed_32(new.to_bytes().as_ref(), b"pingolin.previous-identity");
        let cipher = XSalsa20Poly1305::new_from_slice(&wrap).unwrap();
        let nonce = [9u8; 24];
        let sealed = SealedPreviousIdentity {
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            ciphertext: base64::engine::general_purpose::STANDARD.encode(
                cipher
                    .encrypt(SalsaNonce::from_slice(&nonce), old.to_bytes().as_ref())
                    .unwrap(),
            ),
        };
        assert_eq!(cm.import_previous_identities(vec![sealed]).unwrap(), 1);

        let expected = base64::engine::general_purpose::STANDARD
            .encode(blake2b_keyed_32(old.to_bytes().as_ref(), b"pingolin-note-vault"));
        assert_eq!(cm.previous_vault_keys(), vec![expected]);
    }

    #[test]
    fn no_recovered_identity_means_no_vault_keys() {
        let cm = CryptoManager::new();
        assert!(cm.previous_vault_keys().is_empty());
    }
}

/// A golden vector produced by the real account portal.
///
/// The portal seals a recovered identity with libsodium via TypeScript; this SDK
/// opens it with a different implementation entirely (the `blake2` and
/// `crypto_secretbox` crates). Both sides can pass their own tests while
/// disagreeing on the keyed-BLAKE2b parameter order or the secretbox variant,
/// and the first sign of that would be a phone that silently cannot read
/// anything from before a reset.
///
/// The vector is the portal's own output: its `sealForApps` sealed a fresh
/// previous key under a fresh current key, both generated for this test and
/// belonging to no account. Regenerate it the same way if the seal format
/// ever changes.
#[cfg(test)]
mod portal_interop_tests {
    use super::*;

    const CURRENT_PRIVATE_KEY: &str = "YNGBYEeC/yaxdyJPsMNfMKnr3Uu2oV62wpeuDTx6/os=";
    const SEALED_CIPHERTEXT: &str =
        "c4OZcEUXivve/ffG27h68llHJS9JfadWvRPa0kGYqnzJbBpNIysLAiwB+vFh3iBb";
    const SEALED_NONCE: &str = "Vq7lLhuIXVzDuJEphxvNdLFcbsVYwEDQ";
    /// The X25519 public key the account had BEFORE the reset.
    const EXPECTED_PRE_RESET_PUBLIC: &str = "DpCE/awoMBgEhR4kimf0J4NEGAWaTdPQE1xxrMBL2FM=";

    #[test]
    fn opens_what_the_real_portal_sealed() {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;

        let cm = CryptoManager::new();
        cm.import_private_key(CURRENT_PRIVATE_KEY.to_string())
            .expect("import the current key");

        let imported = cm
            .import_previous_identities(vec![SealedPreviousIdentity {
                nonce: SEALED_NONCE.to_string(),
                ciphertext: SEALED_CIPHERTEXT.to_string(),
            }])
            .expect("import");
        assert_eq!(imported, 1, "the SDK must open what the portal actually writes");

        // And it is the RIGHT key: derive its public half and compare with the
        // identity the account genuinely had before the reset. Opening something
        // is not enough — it has to be the key that decrypts the old data.
        let guard = cm
            .previous_private_keys
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let recovered_public = PublicKey::from(&guard[0]);
        assert_eq!(
            engine.encode(recovered_public.as_bytes()),
            EXPECTED_PRE_RESET_PUBLIC,
        );
    }

    #[test]
    fn the_note_vault_key_for_that_identity_is_derivable() {
        // note's whole library hangs off this one value, and it is derived from
        // the key recovered above — so if the interop above ever drifts, this
        // says plainly which app breaks.
        let cm = CryptoManager::new();
        cm.import_private_key(CURRENT_PRIVATE_KEY.to_string()).unwrap();
        cm.import_previous_identities(vec![SealedPreviousIdentity {
            nonce: SEALED_NONCE.to_string(),
            ciphertext: SEALED_CIPHERTEXT.to_string(),
        }])
        .unwrap();

        let keys = cm.previous_vault_keys();
        assert_eq!(keys.len(), 1);
        // 32 bytes, base64 — the shape note passes to encrypt_note/decrypt_note.
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&keys[0])
            .expect("base64");
        assert_eq!(decoded.len(), 32);
    }
}

#[cfg(test)]
mod canonical_ids {
    //! One spelling of an id in the pin API and the member wrap.

    use super::*;
    use crate::types::StorageCallbackError;
    use std::sync::Arc;

    /// A pin state's name (it has no equality).
    fn state(result: Result<PinResult, MobileError>) -> String {
        format!("{:?}", result.map(|r| r.state))
    }

    const CIRCLE: &str = "c1c1c1c1-0000-4000-8000-00000000000c";
    const OTHER_CIRCLE: &str = "c2c2c2c2-0000-4000-8000-00000000000c";
    const USER: &str = "a1a1a1a1-0000-4000-8000-0000000000aa";
    const SHARING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SIGNING: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    /// Every other spelling of `id` a UUID parser reads.
    fn spellings(id: &str) -> Vec<String> {
        let uuid = uuid::Uuid::parse_str(id).unwrap();
        vec![
            id.to_uppercase(),
            uuid.simple().to_string(),
            uuid.simple().to_string().to_uppercase(),
            uuid.braced().to_string(),
            uuid.urn().to_string(),
        ]
    }

    #[derive(Clone, Default)]
    struct MemStore(Arc<std::sync::Mutex<Option<StoredKeyData>>>);
    impl KeyStorageCallback for MemStore {
        fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = Some(data);
            Ok(())
        }
        fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn delete_keys(&self) -> Result<(), StorageCallbackError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    fn pins_of(cm: &CryptoManager) -> (Vec<String>, Vec<String>) {
        let mut pins: Vec<String> = cm.pinned_keys.read().unwrap().keys().cloned().collect();
        let mut identity: Vec<String> = cm.identity_pins.read().unwrap().keys().cloned().collect();
        pins.sort();
        identity.sort();
        (pins, identity)
    }

    #[test]
    fn a_known_account_is_found_under_any_spelling_and_pinned_under_one() {
        // Lookups and equalities read any spelling of an id; a pin is WRITTEN
        // only under the one spelling (lower-case, hyphenated): any other is
        // refused.
        let cm = CryptoManager::new();
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into())), "Ok(NewPinning)");
        let one_pin = (vec![format!("{CIRCLE}:{USER}")], vec![USER.to_string()]);
        for user in spellings(USER) {
            for circle in spellings(CIRCLE) {
                assert_eq!(cm.pinned_sharing_key(circle.clone(), user.clone()).as_deref(), Some(SHARING), "{circle} {user}");
                assert_eq!(cm.pinned_signing_key(circle.clone(), user.clone()).as_deref(), Some(SIGNING), "{circle} {user}");
                // Written under another spelling: refused, whatever the keys.
                for sharing in [SHARING, OTHER] {
                    assert!(matches!(cm.pin_member_keys(circle.clone(), user.clone(), sharing.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))), "{circle} {user}");
                    assert!(matches!(cm.approve_member_key_change(circle.clone(), user.clone(), sharing.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))), "{circle} {user}");
                }
                assert!(matches!(cm.pin_member_keys(CIRCLE.into(), user.clone(), OTHER.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))));
                assert!(matches!(cm.pin_member_keys(circle.clone(), USER.into(), OTHER.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))));
            }
            // A new circle: the member's identity pin, read under any spelling.
            assert_eq!(cm.pinned_signing_key(OTHER_CIRCLE.into(), user.clone()).as_deref(), Some(SIGNING));
            assert!(matches!(cm.retain_member_pins(CIRCLE.into(), vec![user.clone()]), Err(MobileError::InvalidInput(_))));
        }
        assert_eq!(pins_of(&cm), one_pin, "nothing pinned under another spelling");
        // Under the one spelling: matched, changed, and a new circle by the identity pin.
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into())), "Ok(Matched)");
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into())), "Ok(ChangedSharing)");
        assert_eq!(state(cm.pin_member_keys(OTHER_CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into())), "Ok(ChangedSharing)");
        cm.approve_member_key_change(CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into()).unwrap();
        assert_eq!(cm.pinned_sharing_key(CIRCLE.to_uppercase(), spellings(USER)[3].clone()).as_deref(), Some(OTHER));
        assert_eq!(pins_of(&cm), one_pin);
        assert_eq!(cm.retain_member_pins(CIRCLE.into(), vec![USER.into()]).unwrap(), 0);
        assert_eq!(cm.retain_member_pins(CIRCLE.into(), vec!["b1b1b1b1-0000-4000-8000-0000000000bb".into()]).unwrap(), 1);
    }

    #[test]
    fn a_non_uuid_is_refused_everywhere_and_nothing_is_written() {
        let cm = CryptoManager::new();
        for (circle, user) in [("not-a-circle", USER), (CIRCLE, "not-a-user"), (CIRCLE, ""), ("", USER)] {
            assert!(matches!(cm.pin_member_keys(circle.into(), user.into(), SHARING.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))), "{circle} {user}");
            assert!(matches!(cm.approve_member_key_change(circle.into(), user.into(), SHARING.into(), SIGNING.into()), Err(MobileError::InvalidInput(_))), "{circle} {user}");
            // A lookup has nothing under it, and every call that pins, approves
            // or wraps refuses the same id.
            assert_eq!((cm.pinned_sharing_key(circle.into(), user.into()), cm.pinned_signing_key(circle.into(), user.into())), (None, None));
        }
        assert_eq!(pins_of(&cm), (Vec::<String>::new(), Vec::<String>::new()));
        cm.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into()).unwrap();
        assert!(matches!(cm.retain_member_pins("not-a-circle".into(), vec![USER.into()]), Err(MobileError::InvalidInput(_))));
        assert!(matches!(cm.retain_member_pins(CIRCLE.into(), vec!["not-a-user".into()]), Err(MobileError::InvalidInput(_))));
        assert_eq!(pins_of(&cm), (vec![format!("{CIRCLE}:{USER}")], vec![USER.to_string()]), "nothing retired on a refused roster");
        assert!(matches!(cm.export_member_pins("not-a-user".into()), Err(MobileError::InvalidInput(_))));
        let blob = cm.export_member_pins(USER.to_uppercase()).unwrap();
        assert!(matches!(cm.import_member_pins("not-a-user".into(), blob.clone()), Err(MobileError::InvalidInput(_))));
        let fresh = CryptoManager::new();
        assert_eq!(fresh.import_member_pins(spellings(USER)[3].clone(), blob).unwrap(), 2, "the same account in another spelling");
        assert_eq!(pins_of(&fresh), (vec![format!("{CIRCLE}:{USER}")], vec![USER.to_string()]));
    }

    #[test]
    fn two_spellings_of_one_member_read_at_load_as_one_pin() {
        // Stored by an older SDK: the same member under two spellings.
        let pin = |sharing: &str, first: i64| PinRecord {
            sharing_pubkey_hex: sharing.into(),
            signing_pubkey_hex: SIGNING.into(),
            first_pinned_at: first,
            last_verified_at: first,
            user_approved_change_at: None,
        };
        let stored = |second_sharing: &str| {
            let mut pins: HashMap<String, PinRecord> = HashMap::new();
            pins.insert(format!("{CIRCLE}:{USER}"), pin(SHARING, 200));
            pins.insert(format!("{}:{}", CIRCLE.to_uppercase(), USER.to_uppercase()), pin(second_sharing, 100));
            pins.insert(format!("{IDENTITY_PIN_PREFIX}{}", spellings(USER)[3]), pin(second_sharing, 100));
            pins.insert(format!("{IDENTITY_PIN_PREFIX}{USER}"), pin(SHARING, 200));
            let store = MemStore::default();
            *store.0.lock().unwrap() = Some(StoredKeyData {
                private_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]),
                circle_keys_json: "{}".into(),
                pinned_keys_json: Some(serde_json::to_string(&pins).unwrap()),
                signing_private_key_b64: None,
            });
            let cm = CryptoManager::new();
            cm.register_secure_storage(Box::new(store));
            assert!(cm.load_persisted_keys().unwrap());
            cm
        };
        // The same keys: one pin, from the earlier first contact.
        let cm = stored(SHARING);
        assert_eq!(pins_of(&cm), (vec![format!("{CIRCLE}:{USER}")], vec![USER.to_string()]));
        assert_eq!(cm.pinned_keys.read().unwrap()[&format!("{CIRCLE}:{USER}")].first_pinned_at, 100);
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into())), "Ok(Matched)");
        // Different keys: neither is matched, nor new, until the person approves one.
        let cm = stored(OTHER);
        assert_eq!(pins_of(&cm), (vec![format!("{CIRCLE}:{USER}")], vec![USER.to_string()]));
        for sharing in [SHARING, OTHER] {
            assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), sharing.into(), SIGNING.into())), "Ok(ChangedBoth)");
            assert_eq!(state(cm.pin_member_keys(OTHER_CIRCLE.into(), USER.into(), sharing.into(), SIGNING.into())), "Ok(ChangedBoth)");
            assert_ne!(cm.pinned_sharing_key(CIRCLE.into(), USER.into()).as_deref(), Some(sharing));
        }
        assert_eq!(cm.pinned_keys.read().unwrap()[&format!("{CIRCLE}:{USER}")].first_pinned_at, 100, "the earlier first contact");
        cm.approve_member_key_change(CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into()).unwrap();
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into())), "Ok(Matched)");
    }

    /// A device of the account `user`, its sharing secret `sharing` and
    /// signing seed `signing`, holding key `circle_key` for CIRCLE at v1.
    fn device_of(sharing: u8, signing: u8, circle_key: [u8; 32]) -> Arc<CryptoManager> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let cm = CryptoManager::new();
        cm.import_private_key(b64.encode([sharing; 32])).unwrap();
        cm.import_signing_private_key(b64.encode([signing; 32])).unwrap();
        assert!(cm.add_verified_key(CIRCLE, 1, &circle_key));
        cm
    }

    /// Open `bundle` with the sharing secret `sharing`: the key it carries.
    fn open(bundle: &MemberKeyBundle, sharing: u8) -> Option<Vec<u8>> {
        let eph: [u8; 32] = hex::decode(&bundle.ephemeral_public_key).ok()?.try_into().ok()?;
        let shared = StaticSecret::from([sharing; 32]).diffie_hellman(&PublicKey::from(eph));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce: [u8; 24] = hex::decode(&bundle.encrypted_circle_key.nonce).ok()?.try_into().ok()?;
        XChaCha20Poly1305::new_from_slice(&wrapping).ok()?.decrypt(&XNonce::from(nonce), hex::decode(&bundle.encrypted_circle_key.ciphertext).ok()?.as_ref()).ok()
    }

    #[test]
    fn our_own_id_in_another_spelling_is_still_us_where_the_server_names_it() {
        // The self-substitution guards compare canonical ids. A roster listing
        // this account in another spelling, with an attacker's key, still gets
        // the new key wrapped to OUR key.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let attacker = hex::encode(PublicKey::from(&StaticSecret::from([0x66u8; 32])).as_bytes());
        for spelled in spellings(me) {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            let bundle = cm
                .prepare_key_rotation(CIRCLE.into(), me.into(), vec![spelled.clone()], vec![attacker.clone()], vec![String::new()], "Family".into())
                .unwrap();
            let entry = &bundle.member_keys[0];
            assert!(open(&entry.bundle, 0x21).is_some() && open(&entry.bundle, 0x66).is_none(), "{spelled}: wrapped to our own key");
            let wrapped = cm.wrap_circle_key_for_member_full(CIRCLE.into(), attacker.clone(), me.into(), spelled.clone(), String::new()).unwrap();
            assert!(open(&wrapped, 0x21).is_some() && open(&wrapped, 0x66).is_none(), "{spelled}: the member wrap too");
        }
        // A non-UUID there is refused, never "not us".
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        assert!(cm.prepare_key_rotation(CIRCLE.into(), me.into(), vec!["not-me".into()], vec![attacker.clone()], vec![String::new()], "Family".into()).is_err());
        assert!(cm.prepare_key_rotation(CIRCLE.into(), "not-me".into(), vec![me.into()], vec![attacker], vec![String::new()], "Family".into()).is_err());
    }

    #[test]
    fn a_self_wrap_whose_ids_differ_only_in_spelling_is_judged_as_ours() {
        // Another device of the same account, in an established circle (a
        // member pinned): our own wrap, its sender spelled differently from its
        // recipient, is ours, verified under our own key; another key's
        // signature on it is refused, and a non-UUID sender too.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let phone = device_of(0x21, 0x22, [9u8; 32]);
        let own_pk = hex::encode(PublicKey::from(&StaticSecret::from([0x21u8; 32])).as_bytes());
        let bundle = phone.wrap_circle_key_for_member_full(CIRCLE.into(), own_pk, me.into(), me.into(), String::new()).unwrap();
        let tablet = || {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD;
            let cm = CryptoManager::new();
            cm.import_private_key(b64.encode([0x21u8; 32])).unwrap();
            cm.import_signing_private_key(b64.encode([0x22u8; 32])).unwrap();
            cm.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into()).unwrap();
            cm
        };
        let store = |cm: &CryptoManager, sender: &str, recipient: &str, signature: &str| {
            cm.store_circle_key(
                CIRCLE.into(),
                format!("{}{}", bundle.encrypted_circle_key.nonce, bundle.encrypted_circle_key.ciphertext),
                bundle.ephemeral_public_key.clone(),
                1,
                sender.into(),
                recipient.into(),
                Some(signature.into()),
                None,
            )
        };
        for spelled in spellings(me) {
            let cm = tablet();
            store(&cm, &spelled, me, &bundle.wrap_signature).unwrap_or_else(|e| panic!("{spelled}: {e:?}"));
            assert!(cm.has_circle_key(CIRCLE.into()), "{spelled}");
        }
        let forged = hex::encode(SigningKey::from_bytes(&[0x44u8; 32]).sign(b"not ours").to_bytes());
        assert!(store(&tablet(), &me.to_uppercase(), me, &forged).is_err());
        assert!(matches!(store(&tablet(), "not-me", me, &bundle.wrap_signature), Err(MobileError::InvalidInput(_))));
    }

    #[test]
    fn the_all_zero_pin_matches_nothing_and_opens_nothing() {
        // A conflict's zeros can't be used: no wrap to a zero key, no signature
        // verifies under a zero key.
        let zeros = "0".repeat(64);
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        assert!(cm.wrap_circle_key_for_member_full(CIRCLE.into(), zeros.clone(), me.into(), USER.into(), String::new()).is_err());
        let params = SignWrapParams {
            domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
            sender_user_id: me.into(),
            recipient_user_id: USER.into(),
            circle_id: CIRCLE.into(),
            place_id: String::new(),
            key_version: 1,
            ephemeral_pubkey_hex: hex::encode([3u8; 32]),
            wrap_nonce_hex: hex::encode([4u8; 24]),
            wrap_ciphertext_hex: hex::encode([5u8; 48]),
        };
        let signature = cm.sign_wrap_unchecked(params.clone()).unwrap();
        assert!(!matches!(cm.verify_wrap(zeros.clone(), signature.clone(), params), Ok(true)));
        let statement = cm
            .sign_invitation_to_account(CIRCLE.into(), me.into(), USER.into(), SHARING.into(), SIGNING.into())
            .unwrap();
        assert!(!matches!(cm.verify_membership_statement(statement.statement_hex, statement.signature_hex, zeros), Ok(true)));
    }

    /// Every spelling of a personal key slot: the nil UUID in each form the
    /// parser reads, and track-android's "self".
    fn personal_slot_spellings() -> Vec<String> {
        let nil = uuid::Uuid::nil();
        vec![
            PERSONAL_KEY_ID.to_string(),
            nil.simple().to_string(),
            nil.braced().to_string(),
            nil.urn().to_string(),
            ANDROID_PERSONAL_KEY_SLOT.to_string(),
        ]
    }

    /// Hold `key` for `slot` at `version`, the newest, under that very spelling.
    fn hold(cm: &CryptoManager, slot: &str, version: i32, key: [u8; 32]) {
        cm.circle_keys.write().unwrap().entry(CircleKey::of(&slot)).or_default().insert(version, Zeroizing::new(key.to_vec()));
        cm.active_key_version.write().unwrap().insert(CircleKey::of(&slot), version);
    }

    #[test]
    fn a_personal_slot_is_wrapped_for_this_account_only() {
        // A server listing the nil id as a circle, a puppet on its roster, never
        // gets the personal key wrapped to the puppet: not in any spelling of the
        // nil id, nor under "self". Each spelling holds a key under that very
        // spelling, so nothing but the rule stands in the way.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let puppet = hex::encode(PublicKey::from(&StaticSecret::from([0x66u8; 32])).as_bytes());
        for slot in personal_slot_spellings() {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            hold(&cm, &slot, 1, [0x5a; 32]);
            let refused = cm.wrap_circle_key_for_member_full(slot.clone(), puppet.clone(), me.into(), USER.into(), String::new());
            assert!(
                matches!(&refused, Err(MobileError::InvalidInput(why)) if why == "a personal key is wrapped for this account only"),
                "{slot}: {:?}",
                refused.as_ref().err()
            );
        }
        // The same wrap of a circle's key goes out: the refusal is the slot's.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        let wrapped = cm.wrap_circle_key_for_member_full(CIRCLE.into(), puppet, me.into(), USER.into(), String::new()).unwrap();
        assert!(open(&wrapped, 0x66).is_some());
    }

    #[test]
    fn the_personal_key_still_goes_to_this_account() {
        // Its own copy is still made: the nil id's signed and wrapped to this
        // device's own key, whatever key the server named, our id in another
        // spelling included; "self"'s the unsigned copy.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let puppet = hex::encode(PublicKey::from(&StaticSecret::from([0x66u8; 32])).as_bytes());
        for recipient in [me.to_string(), me.to_uppercase()] {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            hold(&cm, PERSONAL_KEY_ID, 1, [0x5a; 32]);
            let own = cm
                .wrap_circle_key_for_member_full(PERSONAL_KEY_ID.into(), puppet.clone(), me.into(), recipient.clone(), String::new())
                .unwrap();
            assert!(!own.wrap_signature.is_empty(), "{recipient}: signed");
            assert!(open(&own, 0x21).map_or(false, |key| key == [0x5a; 32]), "{recipient}: to our own key");
            assert!(open(&own, 0x66).is_none(), "{recipient}: never to the key the server named");
        }
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        hold(&cm, ANDROID_PERSONAL_KEY_SLOT, 1, [0x5b; 32]);
        let copy = cm.wrap_circle_key_for_member_full(ANDROID_PERSONAL_KEY_SLOT.into(), puppet, me.into(), me.into(), String::new()).unwrap();
        assert!(copy.wrap_signature.is_empty(), "the \"self\" copy is unsigned");
        assert!(open(&copy, 0x21).map_or(false, |key| key == [0x5b; 32]));
    }

    #[test]
    fn a_personal_slot_is_never_rotated_or_linked() {
        // Rotated as a circle, a personal slot would give its members a new
        // personal key and a link down to the old one. Nothing is rotated or
        // linked there, and the key store stays as it was.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let member = hex::encode(PublicKey::from(&StaticSecret::from([0x66u8; 32])).as_bytes());
        let held = |cm: &CryptoManager, slot: &str| {
            let mut held: Vec<(i32, Vec<u8>)> =
                cm.circle_keys.read().unwrap().get(&CircleKey::of(&slot)).map(|m| m.iter().map(|(v, k)| (*v, k.to_vec())).collect()).unwrap_or_default();
            held.sort();
            held
        };
        let rotate = |cm: &CryptoManager, slot: &str| {
            cm.prepare_key_rotation(
                slot.into(),
                me.into(),
                vec![me.into(), USER.into()],
                vec![String::new(), member.clone()],
                vec![String::new(), String::new()],
                "Family".into(),
            )
        };
        for slot in personal_slot_spellings() {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            hold(&cm, &slot, 1, [0x51; 32]);
            hold(&cm, &slot, 2, [0x52; 32]);
            let before = held(&cm, &slot);
            let rotated = rotate(&cm, &slot);
            assert!(
                matches!(&rotated, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is no circle: it is never rotated as one"),
                "{slot}: {:?}",
                rotated.as_ref().err()
            );
            let linked = cm.create_key_chain_link(slot.clone());
            assert!(
                matches!(&linked, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is no circle: no key chain link is made for it"),
                "{slot}: {:?}",
                linked.as_ref().err()
            );
            assert!(held(&cm, &slot) == before, "{slot}: the keys held are as they were");
            assert_eq!(cm.active_key_version.read().unwrap().get(&CircleKey::of(&slot)).copied(), Some(2), "{slot}");
            assert!(!cm.unconfirmed_rotations.read().unwrap().contains_key(&CircleKey::of(&slot)), "{slot}");
        }
        // A circle rotates, with its link, and links: the refusals are the slot's.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        assert!(rotate(&cm, CIRCLE).unwrap().key_chain_link.is_some());
        assert!(cm.create_key_chain_link(CIRCLE.into()).is_ok());
    }

    #[test]
    fn no_statement_names_a_personal_slot() {
        // This account never signs anyone into a personal key slot, which
        // would confirm them for every member: no invitation, admission or
        // renewal, whichever signer the app calls.
        use crate::membership::{
            encode_statement, statement_digest, InvitationRenewalFacts, MembershipStatement, MembershipStatementKind, INVITATION_LIFETIME_SECS,
        };
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let refused = |result: Result<crate::membership::SignedMembershipStatement, MobileError>, what: &str| {
            assert!(
                matches!(&result, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is no circle: no statement names it"),
                "{what}: {:?}",
                result.as_ref().err()
            );
        };
        let now = chrono::Utc::now().timestamp();
        let invitation = |circle: &str| MembershipStatement {
            kind: MembershipStatementKind::InvitationToAccount,
            circle_id: circle.into(),
            statement_id: "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e".into(),
            signer_user_id: me.into(),
            issued_at: now - 60,
            expires_at: now - 60 + INVITATION_LIFETIME_SECS,
            at_version: 1,
            subject_user_id: Some(USER.into()),
            subject_sharing_public_key_hex: Some(SHARING.into()),
            subject_signing_public_key_hex: Some(SIGNING.into()),
            subject_email: None,
        };
        let facts = || InvitationRenewalFacts {
            original_signer_is_owner_or_admin_now: true,
            renewer_is_owner_or_admin: true,
            subject_departed_or_tombstoned: false,
            invitation_withdrawn_or_dead: false,
        };
        // Our own invitation into `circle`, signed as an older SDK would have.
        let renew = |cm: &CryptoManager, circle: &str| {
            let (bytes, _) = encode_statement(&invitation(circle)).unwrap();
            let signature = cm.sign_with_identity_key(&statement_digest(&bytes)).unwrap();
            cm.renew_invitation(circle.into(), me.into(), hex::encode(&bytes), hex::encode(signature), OTHER.into(), OTHER.into(), facts())
        };
        for slot in personal_slot_spellings() {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            hold(&cm, &slot, 1, [0x5a; 32]);
            refused(cm.sign_invitation_to_account(slot.clone(), me.into(), USER.into(), SHARING.into(), SIGNING.into()), &slot);
            refused(cm.sign_invitation_to_email(slot.clone(), me.into(), "someone@example.com".into()), &slot);
            refused(cm.sign_membership_admission(slot.clone(), me.into(), USER.into(), SHARING.into(), SIGNING.into()), &slot);
            refused(cm.sign_membership_statement(invitation(&slot)), &slot);
            if slot != ANDROID_PERSONAL_KEY_SLOT {
                refused(renew(&cm, &slot), &slot);
            }
        }
        // A circle's go out: the refusals are the slot's.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        assert!(cm.sign_invitation_to_account(CIRCLE.into(), me.into(), USER.into(), SHARING.into(), SIGNING.into()).is_ok());
        assert!(cm.sign_invitation_to_email(CIRCLE.into(), me.into(), "someone@example.com".into()).is_ok());
        assert!(cm.sign_membership_admission(CIRCLE.into(), me.into(), USER.into(), SHARING.into(), SIGNING.into()).is_ok());
        assert!(cm.sign_membership_statement(invitation(CIRCLE)).is_ok());
        assert!(renew(&cm, CIRCLE).is_ok());
    }

    #[test]
    fn a_latch_kept_under_a_personal_slot_is_dropped_at_load_and_its_keys_stay() {
        // An older SDK could latch the nil id on a head "seen" for it, which
        // stops personal rows sealing for good. At load that state is dropped;
        // the personal keys, a retired one included, stay exactly as they
        // were. A circle's latch is kept.
        let store = MemStore::default();
        let device = device_of(0x21, 0x22, [9u8; 32]);
        device.register_secure_storage(Box::new(store.clone()));
        let pin = || PinRecord { sharing_pubkey_hex: SHARING.into(), signing_pubkey_hex: SIGNING.into(), first_pinned_at: 1, last_verified_at: 1, user_approved_change_at: None };
        let urn = uuid::Uuid::nil().urn().to_string();
        for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
            hold(&device, slot, 0, [0x50; 32]);
            hold(&device, slot, 1, [0x51; 32]);
            device.refresh.write().unwrap().entry(CircleKey::of(&slot)).or_default().latched = true;
        }
        // Pins an older SDK kept for "members" of a personal slot (new ones are
        // refused), in the one spelling, a urn spelling and "self"; and a circle's.
        for slot in [PERSONAL_KEY_ID, urn.as_str(), ANDROID_PERSONAL_KEY_SLOT] {
            device.pinned_keys.write().unwrap().insert(format!("{slot}:{USER}"), pin());
        }
        let user_urn = uuid::Uuid::parse_str(USER).unwrap().urn().to_string();
        device.pinned_keys.write().unwrap().insert(format!("{PERSONAL_KEY_ID}:{user_urn}"), pin());
        device.pin_member_keys(CIRCLE.into(), USER.into(), SHARING.into(), SIGNING.into()).unwrap();
        device.note_circle_has_records(CIRCLE.into());
        device.persist_keys().unwrap();
        let personal_keys = |cm: &CryptoManager| {
            let keys = cm.circle_keys.read().unwrap();
            let mut held: Vec<(String, i32, Vec<u8>)> = Vec::new();
            for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
                for (version, key) in keys.get(&CircleKey::of(&slot)).into_iter().flatten() {
                    held.push((slot.to_string(), *version, key.to_vec()));
                }
            }
            held.sort();
            held
        };
        let before = personal_keys(&device);
        assert_eq!(before.len(), 4);
        let restarted = CryptoManager::new();
        restarted.register_secure_storage(Box::new(store.clone()));
        assert!(restarted.load_persisted_keys().unwrap());
        for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
            assert!(restarted.refresh.read().unwrap().get(&CircleKey::of(&slot)).is_none(), "{slot}: no latch");
            assert!(!restarted.circle_has_refresh_records(slot.into()) && !restarted.is_behind(slot.into()), "{slot}");
            assert_eq!(restarted.get_active_version(slot.into()).unwrap(), 1, "{slot}");
            assert!(restarted.encrypt_data(slot.into(), "a personal row".into()).is_ok(), "{slot}: its rows seal again");
        }
        assert!(personal_keys(&restarted) == before, "the personal keys, the retired one included, are as they were");
        assert!(restarted.circle_has_refresh_records(CIRCLE.into()), "a circle's latch is kept");
        // The pins under a personal slot are gone; the circle's is kept.
        let pins = |cm: &CryptoManager| {
            let mut pins: Vec<String> = cm.pinned_keys.read().unwrap().keys().cloned().collect();
            pins.sort();
            pins
        };
        assert_eq!(pins(&restarted), vec![format!("{CIRCLE}:{USER}")]);
        // An export taken before (it still names them) brings them back nowhere.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let exported = device.export_member_pins(me.into()).unwrap();
        assert_eq!(restarted.import_member_pins(me.into(), exported).unwrap(), 2, "the circle's pin and the identity pin");
        assert_eq!(pins(&restarted), vec![format!("{CIRCLE}:{USER}")]);
    }

    /// `key` sealed to the sharing secret `to`, as any wrap is: (hex of nonce
    /// then ciphertext, hex of the ephemeral public key).
    fn sealed_to(key: [u8; 32], to: u8) -> (String, String) {
        let ephemeral = StaticSecret::from([0x77u8; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(&StaticSecret::from([to; 32])));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = [3u8; 24];
        let ciphertext = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap().encrypt(&XNonce::from(nonce), key.as_ref()).unwrap();
        (format!("{}{}", hex::encode(nonce), hex::encode(ciphertext)), hex::encode(PublicKey::from(&ephemeral).as_bytes()))
    }

    #[test]
    fn a_personal_slot_takes_only_this_accounts_own_wrap() {
        // On a device with no personal key in use, a circle path's wrap into a
        // personal slot (a member's, a pinned member's signed one, an export's
        // unlabelled one) must not be taken as the personal key at first
        // contact. Only a wrap labelled as this account's own goes there, only
        // under the slot's own id; no first key, link or pin either.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let puppet = "b3b3b3b3-0000-4000-8000-0000000000bb";
        let puppet_device = device_of(0x66, 0x67, [1u8; 32]);
        let (encrypted, ephemeral) = sealed_to([0x5a; 32], 0x21);
        let store = |cm: &CryptoManager, slot: &str, sender: &str, recipient: &str, signature: Option<String>| {
            cm.store_circle_key(slot.into(), encrypted.clone(), ephemeral.clone(), 1, sender.into(), recipient.into(), signature, None)
        };
        // The puppet pinned as a member of `circle` (a pin an older SDK kept, for
        // a personal slot), and its signature on this wrap as a member's there.
        let pin_puppet = |cm: &CryptoManager, circle: &str| {
            let signing = puppet_device.signing_public_key_hex().unwrap();
            let pin = PinRecord { sharing_pubkey_hex: SHARING.into(), signing_pubkey_hex: signing, first_pinned_at: 1, last_verified_at: 1, user_approved_change_at: None };
            cm.pinned_keys.write().unwrap().insert(format!("{circle}:{puppet}"), pin);
        };
        let signed_for = |circle: &str| {
            let (nonce, ciphertext) = encrypted.split_at(48);
            puppet_device
                .sign_wrap_unchecked(SignWrapParams {
                    domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
                    sender_user_id: puppet.into(),
                    recipient_user_id: me.into(),
                    circle_id: circle.into(),
                    place_id: String::new(),
                    key_version: 1,
                    ephemeral_pubkey_hex: ephemeral.clone(),
                    wrap_nonce_hex: nonce.into(),
                    wrap_ciphertext_hex: ciphertext.into(),
                })
                .unwrap()
        };
        for slot in [PERSONAL_KEY_ID, ANDROID_PERSONAL_KEY_SLOT] {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            assert!(matches!(store(&cm, slot, puppet, me, None), Err(MobileError::SignatureInvalid)), "{slot}: a member's");
            assert!(matches!(store(&cm, slot, "", "", None), Err(MobileError::SignatureInvalid)), "{slot}: an export's, unlabelled");
            if slot == PERSONAL_KEY_ID {
                pin_puppet(&cm, slot);
                assert!(matches!(store(&cm, slot, puppet, me, Some(signed_for(slot))), Err(MobileError::SignatureInvalid)), "{slot}: a pinned member's, signed");
            }
            assert!(!cm.has_circle_key(slot.into()), "{slot}: nothing stored");
            // This account's own, unsigned, our id in another spelling: taken on
            // trust at first contact.
            store(&cm, slot, me, &me.to_uppercase(), None).unwrap();
            assert!(cm.has_circle_key_in_use(slot.into()), "{slot}: our own is taken");
        }
        // On a circle, a member's first copy is taken, on trust; a pinned
        // member's signed one is taken UNMARKED. The refusals above are the
        // slot's, and the signature is good.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        store(&cm, OTHER_CIRCLE, puppet, me, None).unwrap();
        assert!(cm.has_circle_key(OTHER_CIRCLE.into()) && cm.circle_key_is_taken_on_trust(OTHER_CIRCLE, 1));
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        pin_puppet(&cm, OTHER_CIRCLE);
        store(&cm, OTHER_CIRCLE, puppet, me, Some(signed_for(OTHER_CIRCLE))).unwrap();
        assert!(cm.has_circle_key(OTHER_CIRCLE.into()) && !cm.circle_key_is_taken_on_trust(OTHER_CIRCLE, 1));

        // The nil id in another spelling holds nothing, our own wrap included.
        let nil = uuid::Uuid::nil();
        for spelled in [nil.simple().to_string(), nil.braced().to_string(), nil.urn().to_string()] {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            let refused = store(&cm, &spelled, me, me, None);
            assert!(
                matches!(&refused, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is named by its own id only"),
                "{spelled}: {:?}",
                refused.as_ref().err()
            );
            assert!(!cm.has_circle_key(spelled.clone()), "{spelled}");
        }

        // No first key, no link and no member for any spelling.
        let v1 = [0x51u8; 32];
        let v2 = [0x52u8; 32];
        let link_nonce = [4u8; 24];
        let link = hex::encode(XChaCha20Poly1305::new_from_slice(&v2).unwrap().encrypt(&XNonce::from(link_nonce), v1.as_ref()).unwrap());
        let is_text = |result: Result<(), MobileError>, text: &str, what: &str| {
            assert!(matches!(&result, Err(MobileError::InvalidInput(why)) if why == text), "{what}: {:?}", result.as_ref().err());
        };
        for slot in personal_slot_spellings() {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            is_text(
                cm.store_first_circle_key(slot.clone(), encrypted.clone(), ephemeral.clone(), 1, puppet.into(), me.into(), "00".repeat(64), SIGNING.into(), None),
                "the personal key has no first key to take",
                &slot,
            );
            hold(&cm, &slot, 2, v2);
            is_text(
                cm.import_key_chain_link(slot.clone(), 2, 1, link.clone(), hex::encode(link_nonce)),
                "a personal key slot is no circle: it takes no key chain link",
                &slot,
            );
            assert!(cm.circle_keys.read().unwrap()[&CircleKey::of(&slot)].get(&1).is_none(), "{slot}: no v1 through a link");
            let pinned = cm.pin_member_keys(slot.clone(), USER.into(), SHARING.into(), SIGNING.into()).map(|_| ());
            is_text(pinned, "a personal key slot is no circle: it has no members", &slot);
            is_text(
                cm.approve_member_key_change(slot.clone(), USER.into(), SHARING.into(), SIGNING.into()),
                "a personal key slot is no circle: it has no members",
                &slot,
            );
        }
        // On a circle the link goes in: the refusal is the slot's.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        hold(&cm, OTHER_CIRCLE, 2, v2);
        cm.import_key_chain_link(OTHER_CIRCLE.into(), 2, 1, link, hex::encode(link_nonce)).unwrap();
        assert!(cm.circle_keys.read().unwrap()[&CircleKey::of(OTHER_CIRCLE)].get(&1).map_or(false, |key| key.as_slice() == v1));
    }

    #[test]
    fn a_member_pin_kept_as_stored_still_vouches_under_the_members_one_spelling() {
        // An install that predates identity pins, with a pin kept as stored (its
        // slot is no UUID, so its key isn't re-keyed): the member is found in it
        // by the one spelling of their id, however it was stored.
        let mut stored: HashMap<String, PinRecord> = HashMap::new();
        stored.insert(
            format!("legacy-slot:{}", uuid::Uuid::parse_str(USER).unwrap().braced()),
            PinRecord { sharing_pubkey_hex: SHARING.into(), signing_pubkey_hex: SIGNING.into(), first_pinned_at: 5, last_verified_at: 5, user_approved_change_at: None },
        );
        let store = MemStore::default();
        *store.0.lock().unwrap() = Some(StoredKeyData {
            private_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]),
            circle_keys_json: "{}".into(),
            pinned_keys_json: Some(serde_json::to_string(&stored).unwrap()),
            signing_private_key_b64: None,
        });
        let cm = CryptoManager::new();
        cm.register_secure_storage(Box::new(store));
        assert!(cm.load_persisted_keys().unwrap());
        assert_eq!(state(cm.pin_member_keys(CIRCLE.into(), USER.into(), OTHER.into(), SIGNING.into())), "Ok(ChangedSharing)");
        assert_eq!(cm.pinned_sharing_key(CIRCLE.into(), USER.to_uppercase()).as_deref(), Some(SHARING));
    }

    #[test]
    fn a_conflict_at_load_leaves_the_sdks_own_entries_as_they_were() {
        // Reserved entries (`~…`, `*:` is an identity pin) are not member pins.
        // A per-circle marker is kept under its circle's key: two spellings
        // holding the SAME unconfirmed rotation are one marker.
        let pin = |sharing: &str| PinRecord {
            sharing_pubkey_hex: sharing.into(),
            signing_pubkey_hex: SIGNING.into(),
            first_pinned_at: 5,
            last_verified_at: 5,
            user_approved_change_at: None,
        };
        let mut stored: HashMap<String, PinRecord> = HashMap::new();
        stored.insert(format!("{CIRCLE}:{USER}"), pin(SHARING));
        stored.insert(format!("{}:{}", CIRCLE, USER.to_uppercase()), pin(OTHER));
        let marker = PinRecord { sharing_pubkey_hex: String::new(), signing_pubkey_hex: String::new(), first_pinned_at: 3, last_verified_at: 0, user_approved_change_at: None };
        stored.insert(format!("{UNCONFIRMED_ROTATION_PREFIX}{CIRCLE}"), marker.clone());
        stored.insert(format!("{UNCONFIRMED_ROTATION_PREFIX}{}", CIRCLE.to_uppercase()), marker);
        let store = MemStore::default();
        *store.0.lock().unwrap() = Some(StoredKeyData {
            private_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]),
            circle_keys_json: "{}".into(),
            pinned_keys_json: Some(serde_json::to_string(&stored).unwrap()),
            signing_private_key_b64: None,
        });
        let cm = CryptoManager::new();
        cm.register_secure_storage(Box::new(store.clone()));
        assert!(cm.load_persisted_keys().unwrap());
        let rotations = cm.unconfirmed_rotations.read().unwrap().clone();
        assert_eq!(rotations, HashMap::from([(CircleKey::of(CIRCLE), 3)]), "one marker, under the circle's key");
        assert_eq!(pins_of(&cm).0, vec![format!("{CIRCLE}:{USER}")]);
    }

    #[test]
    fn a_non_uuid_in_the_invite_order_writes_no_pin_wraps_nothing_and_signs_nothing() {
        // The invite's order with a non-UUID: the lookup finds nothing, and
        // every step after it refuses.
        let cm = device_of(0x21, 0x22, [9u8; 32]);
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let member = hex::encode(PublicKey::from(&StaticSecret::from([0x55u8; 32])).as_bytes());
        for invitee in ["not-a-user", "", "a2a2a2a2-0000-4000-8000-0000000000a"] {
            assert_eq!(cm.pinned_sharing_key(CIRCLE.into(), invitee.into()), None);
            assert!(cm.pin_member_keys(CIRCLE.into(), invitee.into(), member.clone(), SIGNING.into()).is_err());
            assert!(cm.wrap_circle_key_for_member_full(CIRCLE.into(), member.clone(), me.into(), invitee.into(), String::new()).is_err());
            assert!(cm.sign_invitation_to_account(CIRCLE.into(), me.into(), invitee.into(), member.clone(), SIGNING.into()).is_err());
        }
        assert_eq!(pins_of(&cm), (Vec::<String>::new(), Vec::<String>::new()));
    }

    #[test]
    fn the_member_wrap_reads_its_ids_first_and_never_goes_unsigned_but_with_no_key() {
        let cm = CryptoManager::new();
        cm.generate_keypair();
        cm.generate_signing_keypair();
        assert!(cm.add_verified_key(CIRCLE, 1, &[9u8; 32]));
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let member = x25519_dalek::PublicKey::from(&StaticSecret::from([5u8; 32]));
        let wrap = |circle: &str, sender: &str, recipient: &str, member_pk: &str| {
            cm.wrap_circle_key_for_member_full(circle.into(), member_pk.into(), sender.into(), recipient.into(), String::new())
        };
        // A non-UUID recipient, sender or circle: nothing is wrapped.
        for (circle, sender, recipient) in [(CIRCLE, me, "not-a-user"), (CIRCLE, "not-me", USER), ("not-a-circle", me, USER)] {
            assert!(matches!(wrap(circle, sender, recipient, &hex::encode(member.as_bytes())), Err(MobileError::InvalidInput(_))), "{circle} {sender} {recipient}");
        }
        // Signed, under any spelling of the member's id.
        let bundle = wrap(CIRCLE, &me.to_uppercase(), &spellings(USER)[4], &hex::encode(member.as_bytes())).unwrap();
        assert_eq!(bundle.wrap_signature.len(), 128);
        // Our own id in another spelling is us: our own key, whatever the
        // server says it is.
        assert!(wrap(CIRCLE, me, &me.to_uppercase(), "zz").unwrap().wrap_signature.len() == 128);
        // The Android personal key's slot: only to this account, unsigned.
        cm.add_verified_key(ANDROID_PERSONAL_KEY_SLOT, 1, &[8u8; 32]);
        assert_eq!(wrap(ANDROID_PERSONAL_KEY_SLOT, me, me, "").unwrap().wrap_signature, "");
        assert!(matches!(wrap(ANDROID_PERSONAL_KEY_SLOT, me, USER, &hex::encode(member.as_bytes())), Err(MobileError::InvalidInput(_))));
        // With no signing key installed (a legacy install): unsigned, as documented.
        let legacy = CryptoManager::new();
        legacy.generate_keypair();
        assert!(legacy.add_verified_key(CIRCLE, 1, &[9u8; 32]));
        let unsigned = legacy.wrap_circle_key_for_member_full(CIRCLE.into(), hex::encode(member.as_bytes()), me.into(), USER.into(), String::new()).unwrap();
        assert_eq!(unsigned.wrap_signature, "");
    }

    #[test]
    fn a_circle_is_one_store_in_every_spelling() {
        // Every per-circle store is kept under the circle's one spelling, so no
        // spelling opens a second namespace for it: its keys, marks, rotation,
        // session key and records are one.
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        for spelled in spellings(CIRCLE) {
            assert!(spelled != CIRCLE);
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            // The key held under the one spelling is the key under any other.
            assert!(cm.has_circle_key(spelled.clone()) && cm.has_circle_key_in_use(spelled.clone()), "{spelled}");
            assert_eq!(cm.get_active_version(spelled.clone()).unwrap(), cm.get_active_version(CIRCLE.into()).unwrap(), "{spelled}");
            let sealed = cm.encrypt_data(spelled.clone(), "one circle".into()).unwrap();
            assert_eq!(cm.decrypt_data(CIRCLE.into(), sealed).unwrap(), "one circle", "{spelled}");
            // The AADs keep the caller's string: another spelling opens
            // nothing sealed id-bound under the one spelling, and fails closed.
            let bound = cm.encrypt_data_v2(CIRCLE.into(), "bound".into(), "user_id".into()).unwrap();
            assert!(cm.decrypt_data_v2(spelled.clone(), bound.clone(), "user_id".into()).is_err(), "{spelled}");
            assert_eq!(cm.decrypt_data_v2(CIRCLE.into(), bound, "user_id".into()).unwrap(), "bound");
            // A rotation, a session key and a latch under another spelling are the circle's.
            cm.prepare_key_rotation(spelled.clone(), me.into(), vec![me.into()], vec![String::new()], vec![String::new()], "n".into()).unwrap();
            assert_eq!(cm.get_active_version(CIRCLE.into()).unwrap(), 2, "{spelled}");
            assert!(cm.discard_unconfirmed_rotation(CIRCLE.into()), "{spelled}: the rotation is the circle's");
            assert_eq!(cm.get_active_version(CIRCLE.into()).unwrap(), 1);
            cm.create_session_key(spelled.clone(), 3600).unwrap();
            assert!(cm.has_active_session_key(CIRCLE.into()), "{spelled}");
            cm.note_circle_has_records(spelled.clone());
            assert!(cm.circle_has_refresh_records(CIRCLE.into()) && cm.is_behind(CIRCLE.into()), "{spelled}");
            // Forgotten under another spelling, it is gone under every one.
            assert!(cm.forget_circle(spelled.clone()));
            assert!(!cm.has_circle_key(CIRCLE.into()), "{spelled}");
            // A first contact under another spelling is the circle's, and its mark too.
            let fresh = device_of(0x21, 0x22, [9u8; 32]);
            let (encrypted, ephemeral) = sealed_to([0x5a; 32], 0x21);
            let other = OTHER_CIRCLE.to_uppercase();
            fresh.store_circle_key(other.clone(), encrypted, ephemeral, 1, USER.into(), me.into(), None, None).unwrap();
            assert!(fresh.has_circle_key(OTHER_CIRCLE.into()) && fresh.circle_key_taken_on_trust(OTHER_CIRCLE.into(), 1));
            assert!(fresh.circle_key_taken_on_trust(other, 1));
        }
    }

    /// A device that loads `circle_keys` (circle id -> version -> key) and
    /// `pins` (the pins blob's entries) from its store: this account's identity.
    fn loaded_from(circle_keys: serde_json::Value, pins: serde_json::Value) -> (Arc<CryptoManager>, MemStore) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let store = MemStore::default();
        *store.0.lock().unwrap() = Some(StoredKeyData {
            private_key: b64.encode([0x21u8; 32]),
            circle_keys_json: circle_keys.to_string(),
            pinned_keys_json: Some(pins.to_string()),
            signing_private_key_b64: Some(b64.encode([0x22u8; 32])),
        });
        let cm = CryptoManager::new();
        cm.register_secure_storage(Box::new(store.clone()));
        assert!(cm.load_persisted_keys().unwrap());
        (cm, store)
    }

    fn b64_key(byte: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn held_key(cm: &CryptoManager, circle: &str, version: i32) -> Option<Vec<u8>> {
        cm.circle_keys.read().unwrap().get(&CircleKey::of(circle)).and_then(|versions| versions.get(&version)).map(|key| key.to_vec())
    }

    #[test]
    fn the_load_folds_a_circles_spellings_strictly() {
        // An older build may have kept one circle under two spellings. At load
        // only what they agree on is filed; every copy they don't agree on is
        // kept as stored, and that version "didn't read here": no first contact
        // takes it, and nothing is sealed below it.
        let upper = CIRCLE.to_uppercase();
        let marker = |at: i64| serde_json::json!({"sharing_pubkey_hex": "", "signing_pubkey_hex": "", "first_pinned_at": at, "last_verified_at": 0, "user_approved_change_at": null});
        // (a) Only another spelling: moved to the one spelling.
        let (cm, _) = loaded_from(serde_json::json!({ upper.clone(): {"1": b64_key(0x51)} }), serde_json::json!({}));
        assert!(held_key(&cm, CIRCLE, 1).map_or(false, |key| key == [0x51; 32]));
        assert_eq!(cm.get_active_version(CIRCLE.into()).unwrap(), 1);
        // (b) The same copy under both: one.
        let (cm, _) = loaded_from(serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x51)} }), serde_json::json!({}));
        assert!(held_key(&cm, CIRCLE, 1).map_or(false, |key| key == [0x51; 32]) && !cm.holds_unreadable_copy(CIRCLE, 1));
        // (c) Different copies of one version: neither is filed, both are kept.
        let (cm, _) = loaded_from(serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x52)} }), serde_json::json!({}));
        assert!(held_key(&cm, CIRCLE, 1).is_none() && cm.holds_unreadable_copy(CIRCLE, 1));
        assert!(cm.get_active_version(CIRCLE.into()).is_err(), "nothing to seal under");
        let (encrypted, ephemeral) = sealed_to([0x51; 32], 0x21);
        assert!(
            cm.store_circle_key(CIRCLE.into(), encrypted, ephemeral, 1, USER.into(), "a2a2a2a2-0000-4000-8000-0000000000aa".into(), None, None).is_err(),
            "no first contact at a version that didn't read"
        );
        // (d) A version only the other spelling holds (a second namespace): not filed.
        let (cm, store) = loaded_from(
            serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x51), "2": b64_key(0x53)} }),
            serde_json::json!({}),
        );
        assert!(held_key(&cm, CIRCLE, 1).is_some() && held_key(&cm, CIRCLE, 2).is_none() && cm.holds_unreadable_copy(CIRCLE, 2));
        assert!(cm.get_active_version(CIRCLE.into()).is_err(), "the circle waits: nothing is sealed below v2");
        // (i) Idempotent: what it writes back loads the same, and writes the same.
        cm.persist_keys().unwrap();
        let first = store.0.lock().unwrap().clone().unwrap();
        let again = CryptoManager::new();
        again.register_secure_storage(Box::new(store.clone()));
        assert!(again.load_persisted_keys().unwrap());
        assert!(held_key(&again, CIRCLE, 1).is_some() && held_key(&again, CIRCLE, 2).is_none() && again.holds_unreadable_copy(CIRCLE, 2));
        again.persist_keys().unwrap();
        let second = store.0.lock().unwrap().clone().unwrap();
        let parsed = |json: &str| serde_json::from_str::<serde_json::Value>(json).unwrap();
        assert!(parsed(&first.circle_keys_json) == parsed(&second.circle_keys_json), "the circle keys written back are the same");
        assert!(parsed(&first.circle_keys_json).get(&upper).is_none(), "under the one spelling only");
        // (c) again, after a write: both copies still apart, nothing filed.
        let (cm, store) = loaded_from(serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x52)} }), serde_json::json!({}));
        cm.persist_keys().unwrap();
        let again = CryptoManager::new();
        again.register_secure_storage(Box::new(store.clone()));
        assert!(again.load_persisted_keys().unwrap());
        assert!(held_key(&again, CIRCLE, 1).is_none() && again.holds_unreadable_copy(CIRCLE, 1), "a write never files either copy");
        // (g) Marks under either spelling are the circle's.
        let (cm, _) = loaded_from(
            serde_json::json!({ CIRCLE: {"1": b64_key(0x51)} }),
            serde_json::json!({ format!("{CIRCLE_TRUST_MARK_PREFIX}{upper}:1"): marker(0), format!("{VIA_PREVIOUS_MARK_PREFIX}{CIRCLE}:1"): marker(0) }),
        );
        assert!(cm.circle_key_taken_on_trust(CIRCLE.into(), 1) && cm.active_key_came_via_previous_identity(CIRCLE.into()));
        // (h) Different unconfirmed rotations: neither stands.
        let (cm, _) = loaded_from(
            serde_json::json!({ CIRCLE: {"1": b64_key(0x51)} }),
            serde_json::json!({ format!("{UNCONFIRMED_ROTATION_PREFIX}{CIRCLE}"): marker(2), format!("{UNCONFIRMED_ROTATION_PREFIX}{upper}"): marker(3) }),
        );
        assert!(cm.unconfirmed_rotations.read().unwrap().is_empty());
        // (j) The nil id in another spelling is the personal slot; "self" is its own.
        let braced = uuid::Uuid::nil().braced().to_string();
        let (cm, _) = loaded_from(serde_json::json!({ braced: {"1": b64_key(0x40)}, ANDROID_PERSONAL_KEY_SLOT: {"1": b64_key(0x41)} }), serde_json::json!({}));
        assert!(held_key(&cm, PERSONAL_KEY_ID, 1).map_or(false, |key| key == [0x40; 32]));
        assert!(held_key(&cm, ANDROID_PERSONAL_KEY_SLOT, 1).map_or(false, |key| key == [0x41; 32]));
        // (k) A copy kept apart never replaces another: one kept before, and
        // two that don't agree now, are three; the same copy twice is one.
        let kept_copies = |cm: &CryptoManager| -> HashSet<String> {
            cm.unreadable_circle_keys.read().unwrap().get(&CircleKey::of(CIRCLE)).map_or_else(HashSet::new, |kept| kept.values().map(|copy| copy.as_str().to_owned()).collect())
        };
        let kept_count = |cm: &CryptoManager| cm.unreadable_circle_keys.read().unwrap().get(&CircleKey::of(CIRCLE)).map_or(0, |kept| kept.len());
        let (cm, _) = loaded_from(
            serde_json::json!({ CIRCLE: {"1": b64_key(0x51), "1~0": b64_key(0x61)}, upper.clone(): {"1": b64_key(0x52)} }),
            serde_json::json!({}),
        );
        assert!(kept_copies(&cm) == HashSet::from([b64_key(0x51), b64_key(0x52), b64_key(0x61)]) && kept_count(&cm) == 3, "every copy kept");
        let braced_circle = uuid::Uuid::parse_str(CIRCLE).unwrap().braced().to_string();
        let (cm, _) = loaded_from(
            serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x52)}, braced_circle.clone(): {"1": b64_key(0x52)} }),
            serde_json::json!({}),
        );
        assert!(kept_copies(&cm) == HashSet::from([b64_key(0x51), b64_key(0x52)]) && kept_count(&cm) == 2, "the same copy once");
        // (l) A reload keeps every copy held before, whatever another writer
        // kept under the same name.
        let (cm, store) = loaded_from(serde_json::json!({ CIRCLE: {"1": b64_key(0x51)}, upper.clone(): {"1": b64_key(0x52)} }), serde_json::json!({}));
        store.0.lock().unwrap().as_mut().unwrap().circle_keys_json = serde_json::json!({ CIRCLE: {"1~0": b64_key(0x63)} }).to_string();
        assert!(cm.load_persisted_keys().unwrap());
        assert!(kept_copies(&cm) == HashSet::from([b64_key(0x51), b64_key(0x52), b64_key(0x63)]), "a reload replaces no copy");
        // (n) With the one spelling not stored, a version is filed only if every
        // spelling holds the same copy of it.
        let (cm, _) = loaded_from(
            serde_json::json!({ upper.clone(): {"1": b64_key(0x51)}, braced_circle.clone(): {"1": b64_key(0x51), "2": b64_key(0x53)} }),
            serde_json::json!({}),
        );
        assert!(held_key(&cm, CIRCLE, 1).is_some() && held_key(&cm, CIRCLE, 2).is_none() && cm.holds_unreadable_copy(CIRCLE, 2));
        // (o) The one spelling stored with no keys is no reference.
        let (cm, _) = loaded_from(serde_json::json!({ CIRCLE: {}, upper.clone(): {"1": b64_key(0x51)} }), serde_json::json!({}));
        assert!(held_key(&cm, CIRCLE, 1).map_or(false, |key| key == [0x51; 32]) && kept_count(&cm) == 0);
        // (m) A copy kept apart of a version held here since is not written back.
        let (cm, store) = loaded_from(serde_json::json!({ CIRCLE: {"1": b64_key(0x51), "2": b64_key(0x53), "2~0": b64_key(0x62)} }), serde_json::json!({}));
        assert!(held_key(&cm, CIRCLE, 2).is_some() && kept_count(&cm) == 1);
        cm.persist_keys().unwrap();
        let written = parsed(&store.0.lock().unwrap().as_ref().unwrap().circle_keys_json);
        assert!(written[CIRCLE].get("2").is_some() && written[CIRCLE].get("2~0").is_none(), "held since: not written back");
    }

    /// The exported CryptoManager methods, by name, from the source itself.
    fn exported_methods() -> Vec<String> {
        let mut names = Vec::new();
        for source in [include_str!("crypto.rs"), include_str!("refresh.rs"), include_str!("membership.rs")] {
            let mut rest = source;
            while let Some(at) = rest.find("#[uniffi::export]\nimpl CryptoManager {\n") {
                let block = &rest[at..];
                let end = block.find("\n}\n").expect("the block ends");
                for line in block[..end].lines() {
                    if let Some(name) = line.strip_prefix("    pub fn ") {
                        names.push(name.split(|c: char| c == '(' || c == '<').next().unwrap().to_string());
                    }
                }
                rest = &block[end..];
            }
        }
        names
    }

    #[test]
    fn every_key_path_refuses_a_personal_slot_or_is_allowlisted() {
        // With every spelling of the nil id the personal slot, a circle path
        // handed one of them REACHES the personal key. So every exported method
        // is classed: it refuses a personal slot, or it is on the personal-key
        // allowlist (with why), or it hands out and seals under no circle's key.
        // A new method fails here until it is classed; each refusal is driven
        // with 4 spellings.
        const REFUSES: &[&str] = &[
            "wrap_circle_key_for_member_full", "prepare_key_rotation", "prepare_recorded_rotation", "create_key_chain_link",
            "import_key_chain_link", "import_refresh_records", "note_circle_has_records", "sign_circle_head", "sign_wrap",
            "sign_membership_statement", "sign_invitation_to_account", "sign_invitation_to_email", "sign_membership_admission",
            "renew_invitation", "store_first_circle_key", "pin_member_keys", "approve_member_key_change", "forget_circle",
            "discard_unconfirmed_rotation", "prepare_recorded_circle_creation", "discard_circle_creation",
            "finalize_circle_creation",
        ];
        const PERSONAL_ALLOWLIST: &[(&str, &str)] = &[
            ("store_circle_key", "into a personal slot only this account's own wrap, under the slot's own id"),
            ("check_personal_key_adoption", "this account's own copy"),
            ("adopt_personal_key", "this account's own signed copy"),
            ("copy_personal_key", "between this device's two personal slots"),
            ("publishable_personal_key", "wrapped to this account's own key"),
            ("check_published_personal_copy", "reads this account's own copy"),
            ("personal_key_taken_on_trust", "a fact about this device's own key"),
            ("personal_copy_superseded_by_reset", "reads this account's own copy"),
            ("sign_own_circle_key_wrap", "signs only a wrap to this device that opens to the key held"),
            ("sign_circle_creation_wrap", "signs only this device's own creation wrap"),
            ("finalize_circle_creation", "how the personal key is made: into a slot by its own id only, never from one (in REFUSES)"),
            ("wrap_circle_key_for_member_full", "to this account only: refused for anyone else (in REFUSES)"),
            ("encrypt_location", "seals a personal row, which only this account opens"),
            ("encrypt_location_bound", "seals a personal row"),
            ("encrypt_data", "seals a personal field"),
            ("encrypt_data_v2", "seals a personal field"),
            ("encrypt_timestamp", "seals a personal field"),
            ("encrypt_alert_conditions", "seals a personal field"),
            ("encrypt_location_with_session_key", "seals a personal row"),
            ("encrypt_location_with_session_key_bound", "seals a personal row"),
            ("encrypt_timestamp_with_session_key", "seals a personal field"),
            ("envelope_encrypt_location", "a personal target: sealed for this account"),
            ("envelope_encrypt_location_v2", "a personal target"),
            ("envelope_encrypt_location_bound", "a personal target"),
            ("envelope_encrypt_place", "a personal target"),
            ("wrap_place_key", "a personal place's key, under this account's key"),
            ("wrap_place_key_for_circle", "a personal place's key"),
            ("create_session_key", "a personal session key, sealed for this account"),
            ("derive_user_pseudonym", "one-way: the personal rows carry it"),
            ("derive_device_pseudonym", "one-way"),
            ("derive_pseudonyms", "one-way"),
            ("derive_user_pseudonyms_all_versions", "one-way; the erasure list carries them"),
            ("collect_deletion_pseudonyms", "one-way; for this account's erasure"),
            ("compute_event_type_hash", "one-way"),
        ];
        const NOT_A_KEY_PATH: &[&str] = &[
            "new", "register_secure_storage", "load_persisted_keys", "key_store_status", "drop_unreadable_entries", "persist_keys",
            "begin_bulk_key_import", "end_bulk_key_import", "generate_keypair", "import_private_key", "export_public_key",
            "import_previous_identities", "previous_vault_keys", "import_previous_identities_v2", "previous_signing_public_keys",
            "circle_key_taken_on_trust", "active_key_taken_on_trust", "active_key_came_via_previous_identity", "previous_identity_count",
            "holds_previous_identity", "decrypt_location", "decrypt_location_opened", "decrypt_location_bound",
            "decrypt_location_bound_for_user", "decrypt_data_v2", "decrypt_data_v2_opened", "decrypt_data", "decrypt_data_opened",
            "decrypt_data_with_version", "generate_place_key", "unwrap_place_key", "unwrap_place_key_opened", "encrypt_with_place_key",
            "decrypt_with_place_key", "encrypt_with_place_key_v2", "decrypt_with_place_key_v2", "decrypt_data_by_key_id",
            "unwrap_and_decrypt_location", "unwrap_and_decrypt_location_v2", "unwrap_and_decrypt_location_bound",
            "unwrap_and_decrypt_location_bound_for_user", "unwrap_and_decrypt_place", "unwrap_and_decrypt_place_opened",
            "clear_all_keys", "clear_password_key_cache", "has_circle_key", "has_circle_key_in_use", "get_active_version",
            "import_peer_session_key", "has_active_session_key", "get_sender_session_key_id", "has_peer_session_key",
            "has_peer_session_key_for", "is_current_key_version", "decrypt_location_with_session_key_bound",
            "decrypt_location_with_session_key_bound_for_user", "invalidate_session_keys_for_circle", "prepare_circle_creation",
            "decrypt_timestamp", "encrypt_with_password", "encrypt_with_key", "generate_master_key", "decrypt_with_key",
            "encrypt_note", "decrypt_note", "decrypt_with_password", "decrypt_alert_conditions", "evaluate_place_alert",
            "evaluate_inactivity_alert", "generate_signing_keypair", "import_signing_private_key", "signing_public_key_hex",
            "verify_wrap", "pinned_sharing_key", "pinned_signing_key", "compute_safety_number", "retain_member_pins",
            "export_member_pins", "import_member_pins", "generate_signing_keypair_detached", "refresh_eligibility", "chain_role",
            "refresh_head_versions", "circle_has_refresh_records", "is_behind", "newest_held_version",
            "verify_circle_head", "verify_own_membership_statement", "verify_membership_statement", "parse_membership_statement",
        ];
        let exported = exported_methods();
        assert!(exported.len() > 100, "the sweep reads the exported blocks");
        for name in &exported {
            let classes = [REFUSES.contains(&name.as_str()), NOT_A_KEY_PATH.contains(&name.as_str()), PERSONAL_ALLOWLIST.iter().any(|(n, _)| n == name)];
            let count = classes.iter().filter(|c| **c).count();
            // The member wrap is in both REFUSES (anyone else) and the allowlist
            // (this account); so is the creation's finalize (from a slot, or
            // into one by another spelling; into one by its own id).
            let expected = if name == "wrap_circle_key_for_member_full" || name == "finalize_circle_creation" { 2 } else { 1 };
            assert_eq!(count, expected, "{name}: classed {count} times; every exported method is classed once");
        }
        for name in REFUSES.iter().copied().chain(NOT_A_KEY_PATH.iter().copied()).chain(PERSONAL_ALLOWLIST.iter().map(|(n, _)| *n)) {
            assert!(exported.iter().any(|e| e == name), "{name} is listed but not exported");
        }

        use crate::membership::{encode_statement, statement_digest, InvitationRenewalFacts, MembershipStatement, MembershipStatementKind, INVITATION_LIFETIME_SECS};
        let me = "a2a2a2a2-0000-4000-8000-0000000000aa";
        let member = hex::encode(PublicKey::from(&StaticSecret::from([0x66u8; 32])).as_bytes());
        let personal = |why: &str| why.contains("personal");
        let refused = |result: Result<(), MobileError>, what: &str, spelled: &str| match result {
            Err(MobileError::InvalidInput(why)) if personal(&why) => {}
            other => panic!("{what} with {spelled}: {:?}", other.err()),
        };
        let nil = uuid::Uuid::nil();
        for spelled in [PERSONAL_KEY_ID.to_string(), nil.simple().to_string(), nil.braced().to_string(), nil.urn().to_string()] {
            let cm = device_of(0x21, 0x22, [9u8; 32]);
            hold(&cm, PERSONAL_KEY_ID, 1, [0x40; 32]);
            let s = || spelled.clone();
            refused(cm.wrap_circle_key_for_member_full(s(), member.clone(), me.into(), USER.into(), String::new()).map(|_| ()), "wrap", &spelled);
            refused(cm.prepare_key_rotation(s(), me.into(), vec![me.into(), USER.into()], vec![String::new(), member.clone()], vec![String::new(), String::new()], "n".into()).map(|_| ()), "rotation", &spelled);
            refused(cm.prepare_recorded_rotation(s(), me.into(), crate::refresh::RefreshRecordKind::Transition, vec![], vec![], true, "n".into()).map(|_| ()), "recorded rotation", &spelled);
            refused(cm.create_key_chain_link(s()).map(|_| ()), "link", &spelled);
            refused(cm.import_key_chain_link(s(), 2, 1, "00".repeat(48), "00".repeat(24)), "link import", &spelled);
            refused(cm.import_refresh_records(s(), vec![], vec![], vec![], true, None, vec![]).map(|_| ()), "import", &spelled);
            cm.note_circle_has_records(s());
            assert!(!cm.circle_has_refresh_records(PERSONAL_KEY_ID.into()), "latch with {spelled}");
            refused(cm.sign_circle_head(s(), me.into()).map(|_| ()), "head", &spelled);
            let params = SignWrapParams {
                domain: DOMAIN_CIRCLE_MEMBER_WRAP.to_string(),
                sender_user_id: me.into(),
                recipient_user_id: USER.into(),
                circle_id: s(),
                place_id: String::new(),
                key_version: 1,
                ephemeral_pubkey_hex: hex::encode([3u8; 32]),
                wrap_nonce_hex: hex::encode([4u8; 24]),
                wrap_ciphertext_hex: hex::encode([5u8; 48]),
            };
            refused(cm.sign_wrap(params).map(|_| ()), "sign_wrap", &spelled);
            let now = chrono::Utc::now().timestamp();
            let invitation = MembershipStatement {
                kind: MembershipStatementKind::InvitationToAccount,
                circle_id: s(),
                statement_id: "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e".into(),
                signer_user_id: me.into(),
                issued_at: now - 60,
                expires_at: now - 60 + INVITATION_LIFETIME_SECS,
                at_version: 1,
                subject_user_id: Some(USER.into()),
                subject_sharing_public_key_hex: Some(SHARING.into()),
                subject_signing_public_key_hex: Some(SIGNING.into()),
                subject_email: None,
            };
            refused(cm.sign_membership_statement(invitation.clone()).map(|_| ()), "statement", &spelled);
            refused(cm.sign_invitation_to_account(s(), me.into(), USER.into(), SHARING.into(), SIGNING.into()).map(|_| ()), "invitation", &spelled);
            refused(cm.sign_invitation_to_email(s(), me.into(), "someone@example.com".into()).map(|_| ()), "email invitation", &spelled);
            refused(cm.sign_membership_admission(s(), me.into(), USER.into(), SHARING.into(), SIGNING.into()).map(|_| ()), "admission", &spelled);
            let (bytes, _) = encode_statement(&invitation).unwrap();
            let signature = cm.sign_with_identity_key(&statement_digest(&bytes)).unwrap();
            let facts = InvitationRenewalFacts {
                original_signer_is_owner_or_admin_now: true,
                renewer_is_owner_or_admin: true,
                subject_departed_or_tombstoned: false,
                invitation_withdrawn_or_dead: false,
            };
            refused(cm.renew_invitation(s(), me.into(), hex::encode(&bytes), hex::encode(signature), OTHER.into(), OTHER.into(), facts).map(|_| ()), "renewal", &spelled);
            refused(cm.store_first_circle_key(s(), "00".repeat(48), member.clone(), 1, USER.into(), me.into(), "00".repeat(64), SIGNING.into(), None), "first key", &spelled);
            refused(cm.pin_member_keys(s(), USER.into(), SHARING.into(), SIGNING.into()).map(|_| ()), "pin", &spelled);
            refused(cm.approve_member_key_change(s(), USER.into(), SHARING.into(), SIGNING.into()), "approval", &spelled);
            assert!(!cm.forget_circle(s()), "forget with {spelled}");
            // An unconfirmed rotation an older SDK kept for the slot: never discarded.
            cm.unconfirmed_rotations.write().unwrap().insert(CircleKey::of(PERSONAL_KEY_ID), 1);
            assert!(!cm.discard_unconfirmed_rotation(s()), "discard with {spelled}");
            assert!(held_key(&cm, PERSONAL_KEY_ID, 1).map_or(false, |key| key == [0x40; 32]), "{spelled}: the personal key stays");
            assert!(matches!(cm.prepare_recorded_circle_creation(me.into(), s()), Err(MobileError::InvalidInput(_))), "creation with {spelled}");
            // A creation this device made, were it ever filed under the slot: never discarded.
            let made = "0b0b0b0b-1c1c-4d2d-8e3e-4f4f4f4f4f4f";
            cm.prepare_recorded_circle_creation(me.into(), made.into()).unwrap();
            let chain = cm.refresh.write().unwrap().remove(&CircleKey::of(made)).unwrap();
            cm.refresh.write().unwrap().insert(CircleKey::of(PERSONAL_KEY_ID), chain);
            assert!(!cm.discard_circle_creation(s()), "discard of a creation with {spelled}");
            assert!(held_key(&cm, PERSONAL_KEY_ID, 1).map_or(false, |key| key == [0x40; 32]), "{spelled}: the personal key stays");
            // One slot in two spellings is one slot: no copy onto itself.
            refused(cm.copy_personal_key(PERSONAL_KEY_ID.into(), s()), "copy", &spelled);
            // Never finalized FROM a slot, in any spelling; into one only by
            // its own id.
            refused(cm.finalize_circle_creation(s(), OTHER_CIRCLE.into()), "finalize from", &spelled);
            assert!(held_key(&cm, OTHER_CIRCLE, 1).is_none(), "{spelled}: the personal key went nowhere");
            let creation = cm.prepare_circle_creation().unwrap();
            if spelled != PERSONAL_KEY_ID {
                refused(cm.finalize_circle_creation(creation.temp_circle_id.clone(), s()), "finalize into", &spelled);
            }
            assert!(held_key(&cm, PERSONAL_KEY_ID, 1).map_or(false, |key| key == [0x40; 32]), "{spelled}: the personal key stays");
        }
    }
}
