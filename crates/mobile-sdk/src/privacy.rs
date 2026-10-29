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

//! Privacy-enhancing features for the mobile SDK
//!
//! This module provides configurable privacy protections:
//! - Timestamp bucketing to reduce timing precision
//! - Batch uploads with dummy padding to obscure activity patterns
//! - Per-circle pseudonyms (via crypto manager integration)
//! - Bubble mode (approximate location) for reduced precision sharing

use crate::types::{EncryptedData, MobileError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Privacy configuration for the SDK
///
/// All privacy features are optional and configurable; see `maximum_privacy`,
/// `realtime` and `none` for ready-made presets.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct PrivacyConfig {
    /// Enable timestamp bucketing (default: true)
    pub enable_timestamp_bucketing: bool,

    /// Timestamp bucket size in seconds (default: 300 = 5 minutes)
    /// Valid range: 60-3600 (1 minute to 1 hour)
    pub timestamp_bucket_seconds: i64,

    /// Add random jitter within timestamp bucket (default: true)
    pub add_timestamp_jitter: bool,

    /// Enable batch uploads (default: false - opt-in feature)
    pub enable_batch_uploads: bool,

    /// Batch size for uploads (default: 10)
    /// Locations are accumulated until batch_size is reached or max_batch_delay passes
    pub batch_size: u32,

    /// Maximum delay before flushing a partial batch in seconds (default: 60)
    pub max_batch_delay_seconds: u64,

    /// Enable dummy location padding in batches (default: true when batching enabled)
    /// Pads batches to fixed size with encrypted garbage
    pub enable_batch_padding: bool,

    /// Padded batch size (default: 10)
    /// Batches will be padded to this size with dummy entries
    pub padded_batch_size: u32,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enable_timestamp_bucketing: true,
            timestamp_bucket_seconds: 300, // 5 minutes
            add_timestamp_jitter: true,
            enable_batch_uploads: false, // Opt-in
            batch_size: 10,
            max_batch_delay_seconds: 60,
            enable_batch_padding: true,
            padded_batch_size: 10,
        }
    }
}

impl PrivacyConfig {
    /// Create a privacy config with all protections enabled
    pub fn maximum_privacy() -> Self {
        Self {
            enable_timestamp_bucketing: true,
            timestamp_bucket_seconds: 900, // 15 minutes
            add_timestamp_jitter: true,
            enable_batch_uploads: true,
            batch_size: 10,
            max_batch_delay_seconds: 120,
            enable_batch_padding: true,
            padded_batch_size: 10,
        }
    }

    /// Create a privacy config optimized for real-time tracking
    /// (less privacy but lower latency)
    pub fn realtime() -> Self {
        Self {
            enable_timestamp_bucketing: true,
            timestamp_bucket_seconds: 60, // 1 minute
            add_timestamp_jitter: true,
            enable_batch_uploads: false,
            batch_size: 1,
            max_batch_delay_seconds: 10,
            enable_batch_padding: false,
            padded_batch_size: 1,
        }
    }

    /// Disable all privacy features (not recommended)
    pub fn none() -> Self {
        Self {
            enable_timestamp_bucketing: false,
            timestamp_bucket_seconds: 1,
            add_timestamp_jitter: false,
            enable_batch_uploads: false,
            batch_size: 1,
            max_batch_delay_seconds: 0,
            enable_batch_padding: false,
            padded_batch_size: 1,
        }
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), MobileError> {
        if self.timestamp_bucket_seconds < 60 || self.timestamp_bucket_seconds > 3600 {
            return Err(MobileError::InvalidInput(
                "timestamp_bucket_seconds must be between 60 and 3600".into(),
            ));
        }
        if self.batch_size == 0 || self.batch_size > 100 {
            return Err(MobileError::InvalidInput(
                "batch_size must be between 1 and 100".into(),
            ));
        }
        if self.padded_batch_size < self.batch_size {
            return Err(MobileError::InvalidInput(
                "padded_batch_size must be >= batch_size".into(),
            ));
        }
        Ok(())
    }
}

/// Bucket a timestamp according to privacy config.
///
/// Delegates to `pingolin_crypto::privacy::bucket_timestamp` so every platform
/// buckets identically.
pub fn bucket_timestamp(timestamp_ms: i64, config: &PrivacyConfig) -> i64 {
    if !config.enable_timestamp_bucketing {
        return timestamp_ms;
    }

    let shared_config = pingolin_crypto::privacy::TimestampBucketConfig {
        bucket_ms: config.timestamp_bucket_seconds * 1000,
        add_jitter: config.add_timestamp_jitter,
    };
    pingolin_crypto::privacy::bucket_timestamp(timestamp_ms, &shared_config)
}

/// A batch of encrypted locations ready for upload
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct LocationBatch {
    /// The encrypted locations in this batch
    pub locations: Vec<BatchedLocation>,
    /// Batch creation time, Unix epoch milliseconds.
    pub created_at: i64,
    /// Number of real (non-dummy) locations. Creator-only, like `is_dummy`:
    /// `#[serde(skip)]` so serializing a padded batch never reveals how many
    /// entries are dummies (that would defeat the padding). It still crosses
    /// the UniFFI boundary, so the client itself can tell real from padding.
    #[serde(skip)]
    pub real_count: u32,
}

/// A single location in a batch (may be real or dummy)
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BatchedLocation {
    /// User pseudonym (derived from circle key)
    pub user_pseudonym: String,
    /// Device pseudonym (derived from circle key)
    pub device_pseudonym: String,
    /// Circle ID — plaintext on the wire. The server learns which circle a row
    /// belongs to; the pseudonyms and payload hide who and where.
    pub circle_id: String,
    /// Bucketed timestamp, Unix epoch milliseconds (see `bucket_timestamp`).
    pub timestamp: i64,
    /// Encrypted location payload
    pub encrypted_payload: EncryptedData,
    /// Whether this is a dummy entry (only known to creator)
    /// This is encrypted inside the payload, server cannot distinguish
    #[serde(skip)]
    pub is_dummy: bool,
}

/// Location batcher for accumulating and padding location uploads
#[derive(uniffi::Object)]
pub struct LocationBatcher {
    config: PrivacyConfig,
    pending: Arc<Mutex<VecDeque<BatchedLocation>>>,
    last_flush: Arc<Mutex<Instant>>,
}

#[uniffi::export]
impl LocationBatcher {
    /// Create a new location batcher with the given privacy config
    #[uniffi::constructor]
    pub fn new(config: PrivacyConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            last_flush: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Create a batcher with default privacy config
    #[uniffi::constructor]
    pub fn with_defaults() -> Arc<Self> {
        Self::new(PrivacyConfig::default())
    }

    /// Create a batcher configured for maximum privacy
    #[uniffi::constructor]
    pub fn maximum_privacy() -> Arc<Self> {
        Self::new(PrivacyConfig::maximum_privacy())
    }

    /// Add a location to the batch
    ///
    /// Returns Some(batch) if the batch is ready to send, None otherwise.
    /// The batch should be sent immediately when returned.
    pub fn add_location(&self, location: BatchedLocation) -> Option<LocationBatch> {
        if !self.config.enable_batch_uploads {
            return Some(LocationBatch {
                locations: vec![location],
                created_at: chrono::Utc::now().timestamp_millis(),
                real_count: 1,
            });
        }

        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.push_back(location);

        let should_flush = pending.len() >= self.config.batch_size as usize
            || self.last_flush.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
                > Duration::from_secs(self.config.max_batch_delay_seconds);

        if should_flush {
            drop(pending);
            self.flush()
        } else {
            None
        }
    }

    /// Force flush the current batch regardless of size
    ///
    /// Returns Some(batch) if there are pending locations, None if empty.
    pub fn flush(&self) -> Option<LocationBatch> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());

        if pending.is_empty() {
            return None;
        }

        let mut locations: Vec<BatchedLocation> = pending.drain(..).collect();
        let real_count = locations.len() as u32;

        if self.config.enable_batch_padding {
            while locations.len() < self.config.padded_batch_size as usize {
                locations.push(self.generate_dummy_location(&locations[0]));
            }
        }

        // Shuffle to prevent position-based analysis
        use rand::seq::SliceRandom;
        locations.shuffle(&mut rand::thread_rng());

        *self.last_flush.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();

        Some(LocationBatch {
            locations,
            created_at: chrono::Utc::now().timestamp_millis(),
            real_count,
        })
    }

    /// Check how many locations are pending
    pub fn pending_count(&self) -> u32 {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len() as u32
    }

    /// Check if a flush is due based on time
    pub fn should_flush(&self) -> bool {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_empty() {
            return false;
        }

        self.last_flush.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
            > Duration::from_secs(self.config.max_batch_delay_seconds)
    }

    /// Clear all pending locations (e.g., on logout)
    pub fn clear(&self) {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Get the current privacy configuration
    pub fn get_config(&self) -> PrivacyConfig {
        self.config.clone()
    }
}

impl LocationBatcher {
    /// Generate a dummy location entry that is indistinguishable from real ones
    ///
    /// The dummy data is encrypted garbage that the server will store but
    /// clients will recognize and ignore during decryption.
    fn generate_dummy_location(&self, template: &BatchedLocation) -> BatchedLocation {
        let mut rng = rand::thread_rng();

        // Random bytes shaped like a real payload — matching the size is what
        // makes a dummy indistinguishable from a real entry on the wire.
        let dummy_nonce: [u8; 24] = rng.gen();
        // Typical encrypted location is ~100-200 bytes
        let dummy_ciphertext: Vec<u8> = (0..150).map(|_| rng.gen()).collect();

        // Real pseudonyms are 16 hash bytes hex-encoded (32 chars); dummies use
        // the same shape so length reveals nothing.
        let dummy_user_pseudo: [u8; 16] = rng.gen();
        let dummy_device_pseudo: [u8; 16] = rng.gen();

        BatchedLocation {
            user_pseudonym: hex::encode(dummy_user_pseudo),
            device_pseudonym: hex::encode(dummy_device_pseudo),
            circle_id: template.circle_id.clone(), // Same circle
            timestamp: bucket_timestamp(
                chrono::Utc::now().timestamp_millis(),
                &self.config,
            ),
            encrypted_payload: EncryptedData {
                nonce: hex::encode(dummy_nonce),
                ciphertext: hex::encode(dummy_ciphertext),
            },
            is_dummy: true,
        }
    }
}

/// Marker that can be included in encrypted payload to identify dummy entries
/// This is encrypted so the server cannot see it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationPayload {
    /// Actual location data (null for dummy entries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<LocationData>,
    /// Marker for dummy entries (encrypted, server can't see)
    #[serde(default)]
    pub is_dummy: bool,
    /// Payload version for forward compatibility
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationData {
    pub latitude: f64,
    pub longitude: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub altitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heading: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accuracy: Option<f64>,
}

impl LocationPayload {
    /// Create a real location payload
    pub fn real(location: LocationData) -> Self {
        Self {
            location: Some(location),
            is_dummy: false,
            version: 1,
        }
    }

    /// Create a dummy location payload
    pub fn dummy() -> Self {
        Self {
            location: None,
            is_dummy: true,
            version: 1,
        }
    }

    /// True for an explicit dummy marker OR a payload carrying no location —
    /// either way the receiver must discard it rather than render it.
    pub fn is_dummy(&self) -> bool {
        self.is_dummy || self.location.is_none()
    }
}

// ============================================================================
// BUBBLE MODE (Approximate Location)
// ============================================================================

/// Sharing mode for a circle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum SharingMode {
    /// Share exact location
    Exact,
    /// Share approximate location within a radius (bubble mode)
    Approximate,
    /// Location sharing is paused
    Paused,
}

impl Default for SharingMode {
    /// SECURITY: the default is the MOST private mode, not the least.
    ///
    /// This default is what a MISS resolves to (see `SharingManager::get_circle_settings`),
    /// and a miss means "this circle's settings have not been loaded yet" — never
    /// "the user chose to share exactly". A default of `Exact` would make an
    /// unhydrated circle publish precise coordinates, which is the wrong
    /// fail-safe direction for a location-privacy product: an over-restrictive
    /// default is visible to the user and self-corrects on hydration, whereas an
    /// over-permissive one leaks silently. Callers wanting exact sharing must say
    /// so explicitly via `CircleSharingSettings::exact()` / `resume_exact`.
    fn default() -> Self {
        SharingMode::Paused
    }
}

/// Per-circle sharing settings
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct CircleSharingSettings {
    /// The sharing mode
    pub mode: SharingMode,
    /// Radius in miles for approximate mode (1-25)
    pub approximate_radius_miles: Option<u32>,
    /// When bubble mode expires (Unix timestamp in milliseconds, None = indefinite)
    pub approximate_until: Option<i64>,
    /// When pause expires (Unix timestamp in milliseconds, None = indefinite)
    pub paused_until: Option<i64>,
}

impl Default for CircleSharingSettings {
    /// SECURITY: defaults to PAUSED — see `impl Default for SharingMode`. This is
    /// the value an unhydrated circle resolves to, so it must be the most private
    /// mode, not the least.
    fn default() -> Self {
        Self {
            mode: SharingMode::Paused,
            approximate_radius_miles: None,
            approximate_until: None,
            paused_until: None,
        }
    }
}

impl CircleSharingSettings {
    /// Create settings for exact sharing
    pub fn exact() -> Self {
        // Constructed explicitly, NOT via Self::default(): the default is
        // deliberately Paused (most private), so delegating here would make
        // `exact()` — and `resume_exact()`, which calls it — silently return
        // paused settings.
        Self {
            mode: SharingMode::Exact,
            approximate_radius_miles: None,
            approximate_until: None,
            paused_until: None,
        }
    }

    /// Create settings for bubble mode
    pub fn bubble(radius_miles: u32, until: Option<i64>) -> Self {
        Self {
            mode: SharingMode::Approximate,
            approximate_radius_miles: Some(radius_miles.clamp(1, 25)),
            approximate_until: until,
            paused_until: None,
        }
    }

    /// Create settings for paused sharing
    pub fn paused(until: Option<i64>) -> Self {
        Self {
            mode: SharingMode::Paused,
            approximate_radius_miles: None,
            approximate_until: None,
            paused_until: until,
        }
    }

    /// Check if settings have expired and should revert to exact mode
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        match self.mode {
            SharingMode::Approximate => {
                self.approximate_until.map(|t| now > t).unwrap_or(false)
            }
            SharingMode::Paused => {
                self.paused_until.map(|t| now > t).unwrap_or(false)
            }
            SharingMode::Exact => false,
        }
    }

    /// Get effective mode (checking expiration)
    pub fn effective_mode(&self) -> SharingMode {
        if self.is_expired() {
            SharingMode::Exact
        } else {
            self.mode
        }
    }
}

/// Manages per-circle sharing settings for bubble mode and pause
#[derive(uniffi::Object)]
pub struct SharingManager {
    settings: Arc<RwLock<HashMap<String, CircleSharingSettings>>>,
}

#[uniffi::export]
impl SharingManager {
    /// Create a new sharing manager
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            settings: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Set sharing settings for a circle
    pub fn set_circle_settings(&self, circle_id: String, settings: CircleSharingSettings) {
        self.settings.write().unwrap_or_else(|e| e.into_inner()).insert(circle_id, settings);
    }

    /// Get sharing settings for a circle.
    ///
    /// SECURITY: an unknown circle resolves to the DEFAULT, which is `Paused`
    /// (the most private mode) — not exact. This map has no persistence, so it is
    /// empty on every cold start; a caller that has not hydrated it yet must not
    /// be told the user opted into precise sharing. Use `has_circle_settings` to
    /// distinguish "not loaded yet" from "the user really did pause".
    pub fn get_circle_settings(&self, circle_id: String) -> CircleSharingSettings {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&circle_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether this circle's settings have actually been loaded.
    ///
    /// `get_circle_settings` deliberately cannot distinguish an unhydrated circle
    /// from a genuinely paused one (both report `Paused`, the safe default), so
    /// callers that need to tell them apart — e.g. to decide whether to fetch
    /// settings before uploading — ask here first.
    pub fn has_circle_settings(&self, circle_id: String) -> bool {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&circle_id)
    }

    /// Enable bubble mode for a circle
    pub fn enable_bubble(&self, circle_id: String, radius_miles: u32, duration_hours: Option<u32>) {
        let until = duration_hours.map(|h| {
            chrono::Utc::now().timestamp_millis() + (h as i64 * 3600 * 1000)
        });
        self.set_circle_settings(circle_id, CircleSharingSettings::bubble(radius_miles, until));
    }

    /// Pause sharing for a circle
    pub fn pause_sharing(&self, circle_id: String, duration_hours: Option<u32>) {
        let until = duration_hours.map(|h| {
            chrono::Utc::now().timestamp_millis() + (h as i64 * 3600 * 1000)
        });
        self.set_circle_settings(circle_id, CircleSharingSettings::paused(until));
    }

    /// Resume exact sharing for a circle
    pub fn resume_exact(&self, circle_id: String) {
        self.set_circle_settings(circle_id, CircleSharingSettings::exact());
    }

    /// Check if sharing is paused for a circle
    pub fn is_paused(&self, circle_id: String) -> bool {
        self.get_circle_settings(circle_id).effective_mode() == SharingMode::Paused
    }

    /// Check if bubble mode is active for a circle
    pub fn is_bubble_active(&self, circle_id: String) -> bool {
        self.get_circle_settings(circle_id).effective_mode() == SharingMode::Approximate
    }

    /// Apply privacy settings to a location before encryption
    ///
    /// This MUST be called before encrypting location data to ensure bubble mode
    /// privacy is applied client-side. If sharing is paused, returns None.
    ///
    /// For bubble mode, the location is snapped to a deterministic grid cell of
    /// the configured radius (see `approximate_location`) so repeated samples of a
    /// stationary user can't be averaged back to the exact coordinates.
    pub fn apply_to_location(
        &self,
        circle_id: String,
        latitude: f64,
        longitude: f64,
    ) -> Option<ApproximatedLocation> {
        let settings = self.get_circle_settings(circle_id);

        match settings.effective_mode() {
            SharingMode::Paused => None,
            SharingMode::Exact => Some(ApproximatedLocation {
                latitude,
                longitude,
                is_approximate: false,
                approximate_radius_miles: None,
            }),
            SharingMode::Approximate => {
                let radius_miles = settings.approximate_radius_miles.unwrap_or(5);
                let (approx_lat, approx_lng) = approximate_location(latitude, longitude, radius_miles);
                Some(ApproximatedLocation {
                    latitude: approx_lat,
                    longitude: approx_lng,
                    is_approximate: true,
                    approximate_radius_miles: Some(radius_miles),
                })
            }
        }
    }

    /// Clear all settings (e.g., on logout)
    pub fn clear(&self) {
        self.settings.write().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Get the circle IDs that have stored settings (i.e. those for which
    /// `has_circle_settings` is true), in unspecified order.
    pub fn get_configured_circles(&self) -> Vec<String> {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect()
    }
}

impl Default for SharingManager {
    fn default() -> Self {
        Self {
            settings: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Result of applying privacy settings to a location
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ApproximatedLocation {
    /// The (potentially approximated) latitude
    pub latitude: f64,
    /// The (potentially approximated) longitude
    pub longitude: f64,
    /// Whether this location was approximated (bubble mode)
    pub is_approximate: bool,
    /// The radius used for approximation (if applicable)
    pub approximate_radius_miles: Option<u32>,
}

/// Coarsen a location to a deterministic grid cell of the given radius.
///
/// DETERMINISTIC snap-to-grid: quantize the true coordinate to a fixed grid
/// whose cell size is the approximation radius and return the cell CENTRE.
/// Repeated calls at the same true location return the SAME point, so a
/// receiver collecting many samples of a stationary user cannot average them
/// down to the true position — the averaging attack that a fresh per-call
/// random offset is vulnerable to. The Android client coarsens with the same
/// snap-to-grid, so both produce the same cell for the same input.
fn approximate_location(lat: f64, lng: f64, radius_miles: u32) -> (f64, f64) {
    // Convert miles to degrees (approximate). At the equator 1 degree ≈ 69.172
    // miles; longitude degrees shrink by cos(lat), floored at 0.1 so the cell
    // stays finite near the poles.
    let cell_lat = (radius_miles as f64 / 69.172).max(f64::MIN_POSITIVE);
    let cell_lng =
        (radius_miles as f64 / (69.172 * lat.to_radians().cos().abs().max(0.1))).max(f64::MIN_POSITIVE);

    // Snap to the centre of the containing grid cell. Max displacement is half a
    // cell per axis, so the coarsened point stays within the radius.
    let snapped_lat = ((lat / cell_lat).floor() + 0.5) * cell_lat;
    let snapped_lng = ((lng / cell_lng).floor() + 0.5) * cell_lng;

    (snapped_lat, snapped_lng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_config_validation() {
        let mut config = PrivacyConfig::default();
        assert!(config.validate().is_ok());

        config.timestamp_bucket_seconds = 30;
        assert!(config.validate().is_err());

        config.timestamp_bucket_seconds = 300;
        config.batch_size = 0;
        assert!(config.validate().is_err());

        config.batch_size = 10;
        config.padded_batch_size = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_timestamp_bucketing() {
        let config = PrivacyConfig {
            enable_timestamp_bucketing: true,
            timestamp_bucket_seconds: 300,
            add_timestamp_jitter: false,
            ..Default::default()
        };

        let ts = 1704067200000_i64; // 2024-01-01 00:00:00 UTC
        let bucketed = bucket_timestamp(ts + 60_000, &config);
        assert_eq!(bucketed, ts);
    }

    #[test]
    fn test_batch_padding() {
        let config = PrivacyConfig {
            enable_batch_uploads: true,
            batch_size: 3,
            padded_batch_size: 5,
            enable_batch_padding: true,
            max_batch_delay_seconds: 1000,
            ..Default::default()
        };

        let batcher = LocationBatcher::new(config);

        for i in 0..3 {
            let loc = BatchedLocation {
                user_pseudonym: format!("user_{}", i),
                device_pseudonym: format!("device_{}", i),
                circle_id: "circle_123".to_string(),
                timestamp: 1704067200000 + i as i64 * 1000,
                encrypted_payload: EncryptedData {
                    nonce: "abc".to_string(),
                    ciphertext: "xyz".to_string(),
                },
                is_dummy: false,
            };

            if i < 2 {
                assert!(batcher.add_location(loc).is_none());
            } else {
                let batch = batcher.add_location(loc);
                assert!(batch.is_some());
                let batch = batch.unwrap();
                assert_eq!(batch.locations.len(), 5); // Padded to 5
                assert_eq!(batch.real_count, 3);
            }
        }
    }

    #[test]
    fn test_sharing_mode_exact() {
        let manager = SharingManager::new();
        let circle_id = "circle_123".to_string();

        // Exact sharing must be chosen EXPLICITLY — it is never the miss-default.
        manager.resume_exact(circle_id.clone());

        let settings = manager.get_circle_settings(circle_id.clone());
        assert_eq!(settings.effective_mode(), SharingMode::Exact);

        let result = manager.apply_to_location(circle_id, 51.5074, -0.1278);
        assert!(result.is_some());
        let loc = result.unwrap();
        assert_eq!(loc.latitude, 51.5074);
        assert_eq!(loc.longitude, -0.1278);
        assert!(!loc.is_approximate);
    }

    /// SECURITY: an UNKNOWN circle must resolve to the most private mode, never
    /// to exact coordinates. The settings map has no persistence, so it is empty
    /// on every cold start; an `Exact` default would mean any circle whose
    /// settings hadn't been loaded yet publishes precise location.
    #[test]
    fn test_unhydrated_circle_defaults_to_most_private() {
        let manager = SharingManager::new();
        let circle_id = "never_configured".to_string();

        // Nothing was ever stored for this circle.
        assert!(!manager.has_circle_settings(circle_id.clone()));

        let settings = manager.get_circle_settings(circle_id.clone());
        assert_eq!(settings.effective_mode(), SharingMode::Paused);
        assert!(manager.is_paused(circle_id.clone()));

        // The load-bearing assertion: no coordinates leave the device.
        assert!(
            manager.apply_to_location(circle_id, 51.5074, -0.1278).is_none(),
            "an unhydrated circle must not publish coordinates"
        );
    }

    /// `exact()` must NOT delegate to `default()` — the default is deliberately
    /// Paused, so delegating would make resume_exact() silently pause sharing.
    #[test]
    fn test_exact_constructor_is_not_the_default() {
        assert_eq!(CircleSharingSettings::exact().mode, SharingMode::Exact);
        assert_eq!(CircleSharingSettings::default().mode, SharingMode::Paused);
        assert_eq!(SharingMode::default(), SharingMode::Paused);

        // resume_exact() really does restore exact sharing.
        let manager = SharingManager::new();
        let circle_id = "circle_resume".to_string();
        manager.pause_sharing(circle_id.clone(), None);
        assert!(manager.is_paused(circle_id.clone()));
        manager.resume_exact(circle_id.clone());
        assert_eq!(
            manager.get_circle_settings(circle_id).effective_mode(),
            SharingMode::Exact
        );
    }

    /// has_circle_settings distinguishes "not loaded yet" from "user chose paused"
    /// — get_circle_settings reports Paused for both.
    #[test]
    fn test_has_circle_settings_distinguishes_hydration() {
        let manager = SharingManager::new();
        let circle_id = "circle_hydrate".to_string();

        assert!(!manager.has_circle_settings(circle_id.clone()));
        manager.pause_sharing(circle_id.clone(), None);
        assert!(manager.has_circle_settings(circle_id.clone()));

        // Both report Paused, but hydration state now tells them apart.
        assert_eq!(
            manager.get_circle_settings(circle_id).effective_mode(),
            SharingMode::Paused
        );
    }

    #[test]
    fn test_sharing_mode_bubble() {
        let manager = SharingManager::new();
        let circle_id = "circle_123".to_string();

        manager.enable_bubble(circle_id.clone(), 5, None);

        assert!(manager.is_bubble_active(circle_id.clone()));
        assert!(!manager.is_paused(circle_id.clone()));

        let result = manager.apply_to_location(circle_id, 51.5074, -0.1278);
        assert!(result.is_some());
        let loc = result.unwrap();
        assert!(loc.is_approximate);
        assert_eq!(loc.approximate_radius_miles, Some(5));
        // Snapped to a grid-cell centre, so displacement stays inside the radius.
        let distance_lat = (loc.latitude - 51.5074).abs();
        let distance_lng = (loc.longitude - (-0.1278)).abs();
        // 5 miles ≈ 0.072 degrees latitude
        assert!(distance_lat < 0.1);
        assert!(distance_lng < 0.2);
    }

    #[test]
    fn test_sharing_mode_paused() {
        let manager = SharingManager::new();
        let circle_id = "circle_123".to_string();

        manager.pause_sharing(circle_id.clone(), None);

        assert!(manager.is_paused(circle_id.clone()));
        assert!(!manager.is_bubble_active(circle_id.clone()));

        // The load-bearing assertion: a paused circle publishes nothing.
        let result = manager.apply_to_location(circle_id, 51.5074, -0.1278);
        assert!(result.is_none());
    }

    #[test]
    fn test_bubble_mode_expiration() {
        let circle_id = "circle_123".to_string();

        // Create settings that expired in the past
        let expired_settings = CircleSharingSettings {
            mode: SharingMode::Approximate,
            approximate_radius_miles: Some(5),
            approximate_until: Some(chrono::Utc::now().timestamp_millis() - 1000),
            paused_until: None,
        };

        assert!(expired_settings.is_expired());
        assert_eq!(expired_settings.effective_mode(), SharingMode::Exact);

        // Create settings that haven't expired
        let active_settings = CircleSharingSettings {
            mode: SharingMode::Approximate,
            approximate_radius_miles: Some(5),
            approximate_until: Some(chrono::Utc::now().timestamp_millis() + 3600000),
            paused_until: None,
        };

        assert!(!active_settings.is_expired());
        assert_eq!(active_settings.effective_mode(), SharingMode::Approximate);
    }

    #[test]
    fn test_approximate_location_within_radius() {
        // Coarsening is deterministic, so every iteration must return the same
        // cell centre, and that centre must lie within the radius.
        let original_lat = 40.7128;
        let original_lng = -74.0060;
        let radius_miles = 10;

        for _ in 0..100 {
            let (approx_lat, approx_lng) = approximate_location(original_lat, original_lng, radius_miles);

            // Per-axis degree offset; Euclidean is close enough at this scale.
            let lat_diff = (approx_lat - original_lat).abs();
            let lng_diff = (approx_lng - original_lng).abs();

            // 10 miles ≈ 0.145 degrees latitude
            // Allow some margin for the longitude calculation
            assert!(lat_diff < 0.2, "Latitude offset too large: {}", lat_diff);
            assert!(lng_diff < 0.3, "Longitude offset too large: {}", lng_diff);
        }
    }
}
