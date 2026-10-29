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

//! E2EE Boundary Monitoring Service
//!
//! This module provides client-side boundary monitoring that maintains end-to-end encryption.
//! The server never sees boundary coordinates or user locations - all checking happens locally.
//!
//! ## How it works
//!
//! 1. Client fetches encrypted places from the server
//! 2. Client decrypts place coordinates using circle keys
//! 3. Client subscribes to location updates from circle members
//! 4. Client decrypts incoming locations and checks against boundaries
//! 5. When crossings are detected, client shows notifications and reports to server
//!
//! ## Background Monitoring
//!
//! For iOS and Android, background monitoring is achieved through:
//!
//! ### iOS
//! - Silent Push Notifications (APNs) wake the app periodically
//! - Background App Refresh provides additional wake opportunities
//! - App processes queued location updates on wake
//!
//! ### Android
//! - Foreground Service with notification keeps app alive
//! - Firebase Cloud Messaging (FCM) for data messages
//! - WorkManager for periodic sync when FCM unavailable

use crate::boundary::{Boundary, BoundaryChecker, BoundaryCrossing, BoundaryCrossingType};
use crate::crypto::CryptoManager;
use crate::types::{EncryptedData, Location, MobileError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Encrypted place data from the server
#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedPlace {
    pub id: String,
    pub circle_id: Option<String>,
    pub encrypted_name: EncryptedData,
    pub encrypted_location: EncryptedData,
    pub radius_meters: u32,
}

/// Decrypted place with coordinates
#[derive(Debug, Clone)]
pub struct DecryptedPlace {
    // id / circle_id complete the place record but aren't read by the geofence
    // math here (name + coordinates + radius are).
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub circle_id: String,
    pub name: String,
    pub latitude: f64,
    pub longitude: f64,
    pub radius_meters: u32,
}

/// Location update from another user (encrypted from server)
#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedMemberLocation {
    pub user_id: String,
    pub device_id: String,
    pub circle_id: String,
    pub encrypted_location: EncryptedData,
    pub timestamp: i64,
}

/// Callback interface for boundary monitoring events
#[uniffi::export(callback_interface)]
pub trait BoundaryMonitorCallback: Send + Sync {
    /// Called when a boundary crossing is detected for any monitored user
    fn on_crossing_detected(
        &self,
        user_id: String,
        boundary_name: String,
        crossing_type: BoundaryCrossingType,
        distance_meters: f64,
    );

    /// Called when places are loaded/updated
    fn on_places_loaded(&self, count: u32);

    /// Called when an error occurs
    fn on_error(&self, error: String);

    /// Called to request that a crossing be reported to the server. The SDK has
    /// no reporting entry point of its own — the platform owns that HTTP call,
    /// so a platform that ignores this callback silently reports nothing.
    fn on_request_report_crossing(
        &self,
        place_id: String,
        user_id: String,
        device_id: String,
        crossing_type: String,
    );
}

/// E2EE Boundary Monitor
///
/// Monitors circle members' locations for boundary crossings while maintaining
/// end-to-end encryption. All decryption and checking happens on-device.
#[derive(uniffi::Object)]
pub struct BoundaryMonitor {
    crypto: Arc<CryptoManager>,
    checker: BoundaryChecker,

    /// Decrypted places indexed by circle_id -> place_id -> DecryptedPlace
    places: Arc<RwLock<HashMap<String, HashMap<String, DecryptedPlace>>>>,

    /// Track last known position per user for crossing detection
    user_states: Arc<RwLock<HashMap<String, UserBoundaryState>>>,

    callback: Arc<RwLock<Option<Box<dyn BoundaryMonitorCallback>>>>,

    /// Which users to monitor (user_id -> set of circle_ids)
    monitored_users: Arc<RwLock<HashMap<String, Vec<String>>>>,

    /// user_id -> display name, so notifications say a name instead of a UUID
    display_names: Arc<RwLock<HashMap<String, String>>>,
}

/// Track boundary state for a monitored user
#[derive(Debug, Clone, Default)]
struct UserBoundaryState {
    /// place_id -> is_inside
    inside_boundaries: HashMap<String, bool>,
    /// Last known (latitude, longitude)
    last_location: Option<(f64, f64)>,
}

#[uniffi::export]
impl BoundaryMonitor {
    #[uniffi::constructor]
    pub fn new(crypto: Arc<CryptoManager>) -> Arc<Self> {
        Arc::new(Self {
            crypto,
            checker: BoundaryChecker::new(),
            places: Arc::new(RwLock::new(HashMap::new())),
            user_states: Arc::new(RwLock::new(HashMap::new())),
            callback: Arc::new(RwLock::new(None)),
            monitored_users: Arc::new(RwLock::new(HashMap::new())),
            display_names: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Set the callback for boundary events
    pub async fn set_callback(&self, callback: Box<dyn BoundaryMonitorCallback>) {
        *self.callback.write().await = Some(callback);
    }

    pub async fn clear_callback(&self) {
        *self.callback.write().await = None;
    }

    /// Add a user to monitor for boundary crossings
    ///
    /// The user must be in a shared circle so their location can be decrypted.
    pub async fn monitor_user(&self, user_id: String, circle_id: String) {
        let mut monitored = self.monitored_users.write().await;
        monitored
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(circle_id);
    }

    /// Stop monitoring a user and forget their inside/outside state, so a later
    /// re-monitor starts from a clean slate rather than a stale one.
    pub async fn unmonitor_user(&self, user_id: String) {
        let mut monitored = self.monitored_users.write().await;
        monitored.remove(&user_id);

        let mut states = self.user_states.write().await;
        states.remove(&user_id);
    }

    /// Load encrypted places and decrypt them using circle keys
    ///
    /// Call this when places are fetched from the server.
    pub async fn load_encrypted_places(&self, places: Vec<EncryptedPlace>) -> Result<u32, MobileError> {
        let mut decrypted_places = self.places.write().await;
        decrypted_places.clear();

        let mut count = 0;

        for place in places {
            let circle_id = match &place.circle_id {
                Some(id) => id.clone(),
                None => continue, // Personal places without circle_id can't be used for monitoring others
            };

            if !self.crypto.has_circle_key(circle_id.clone()) {
                tracing::warn!("Missing circle key for place {}, skipping", place.id);
                continue;
            }

            // Clients write place fields with the bound circle-field AAD (tag
            // "name"), so they must be read back through decrypt_data_v2: it
            // tries the v2 AAD and falls back to the v1 empty-AAD ciphertext.
            // A v1-only decrypt silently fails on a v2 field → the place is
            // skipped → geofence alerts stop firing.
            let name = match self.crypto.decrypt_data_v2(circle_id.clone(), place.encrypted_name.clone(), "name".to_string()) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("Failed to decrypt place name for {}: {:?}", place.id, e);
                    continue;
                }
            };

            // Decrypt the location (bound circle-field AAD tag "location", with
            // v1 empty-AAD fallback — see the name comment above).
            let location_json = match self.crypto.decrypt_data_v2(circle_id.clone(), place.encrypted_location.clone(), "location".to_string()) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("Failed to decrypt place location for {}: {:?}", place.id, e);
                    continue;
                }
            };

            let location: Location = match serde_json::from_str(&location_json) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("Failed to parse place location for {}: {}", place.id, e);
                    continue;
                }
            };

            let decrypted = DecryptedPlace {
                id: place.id.clone(),
                circle_id: circle_id.clone(),
                name: name.clone(),
                latitude: location.latitude,
                longitude: location.longitude,
                radius_meters: place.radius_meters,
            };

            decrypted_places
                .entry(circle_id.clone())
                .or_insert_with(HashMap::new)
                .insert(place.id.clone(), decrypted.clone());

            // Also add to the underlying boundary checker for self-monitoring
            let boundary = Boundary {
                id: place.id,
                circle_id,
                center_lat: location.latitude,
                center_lng: location.longitude,
                radius_meters: place.radius_meters,
                name,
            };
            self.checker.add_boundary(boundary).await;

            count += 1;
        }

        if let Some(cb) = &*self.callback.read().await {
            cb.on_places_loaded(count);
        }

        Ok(count)
    }

    /// Process an encrypted location update from a circle member
    ///
    /// This decrypts the location, checks against all boundaries for that circle,
    /// and triggers callbacks for any crossings detected.
    pub async fn process_member_location(
        &self,
        member_location: EncryptedMemberLocation,
    ) -> Result<Vec<BoundaryCrossing>, MobileError> {
        let user_id = &member_location.user_id;
        let circle_id = &member_location.circle_id;

        let monitored = self.monitored_users.read().await;
        let is_monitored = monitored
            .get(user_id)
            .map(|circles| circles.contains(circle_id))
            .unwrap_or(false);

        if !is_monitored {
            return Ok(vec![]);
        }

        // Streaming member locations are written v1 (encrypt_location / session
        // key), but are read through the same v2-then-v1 AAD ladder (tag
        // "location") so this stays correct if a sender ever flips the location
        // field to the bound v2 AAD; the v1 empty-AAD fallback keeps current
        // ciphertext decodable.
        //
        // Goes through the TYPED `decrypt_location` rather than
        // `decrypt_data_v2` + `serde_json::from_str`: the plaintext is a PACKED
        // binary document (see location_codec), not text, so decoding it as
        // a UTF-8 string would fail. `decrypt_location` runs the identical key
        // and AAD ladder and accepts both the packed and the legacy JSON form.
        let location: Location = self.crypto.decrypt_location(
            circle_id.clone(),
            member_location.encrypted_location,
        )?;

        let places = self.places.read().await;
        let circle_places = match places.get(circle_id) {
            Some(p) => p,
            None => return Ok(vec![]), // No places to check
        };

        let mut states = self.user_states.write().await;
        let user_state = states.entry(user_id.clone()).or_insert_with(UserBoundaryState::default);

        let mut crossings = Vec::new();

        for (place_id, place) in circle_places.iter() {
            let distance = haversine_distance(
                location.latitude,
                location.longitude,
                place.latitude,
                place.longitude,
            );
            // A plain radius test: unlike `BoundaryChecker::check_location` this
            // path has no exit margin and no first-observation priming, so it can
            // flip on a single fix and treats a place it has never seen the user
            // at as "outside".
            let is_inside = distance <= place.radius_meters as f64;

            let was_inside = *user_state.inside_boundaries.get(place_id).unwrap_or(&false);

            if is_inside != was_inside {
                let crossing_type = if is_inside {
                    BoundaryCrossingType::Enter
                } else {
                    BoundaryCrossingType::Exit
                };

                let crossing = BoundaryCrossing {
                    boundary_id: place_id.clone(),
                    crossing_type: crossing_type.clone(),
                    distance_meters: distance,
                    boundary_name: place.name.clone(),
                };

                crossings.push(crossing);

                if let Some(cb) = &*self.callback.read().await {
                    cb.on_crossing_detected(
                        user_id.clone(),
                        place.name.clone(),
                        crossing_type.clone(),
                        distance,
                    );

                    cb.on_request_report_crossing(
                        place_id.clone(),
                        user_id.clone(),
                        member_location.device_id.clone(),
                        match crossing_type {
                            BoundaryCrossingType::Enter => "enter".to_string(),
                            BoundaryCrossingType::Exit => "exit".to_string(),
                        },
                    );
                }
            }

            user_state.inside_boundaries.insert(place_id.clone(), is_inside);
        }

        user_state.last_location = Some((location.latitude, location.longitude));

        Ok(crossings)
    }

    /// Check this device's own location against every loaded place.
    ///
    /// Delegates to the underlying `BoundaryChecker`, so the exit margin, the
    /// accuracy gate and first-observation priming described there apply here —
    /// but not to `process_member_location`, which has its own simpler detector.
    ///
    /// `accuracy_meters` is optional and defaults to `None` (unknown, and so
    /// evaluated); see `BoundaryChecker::check_location`.
    #[uniffi::method(default(accuracy_meters = None))]
    pub async fn check_own_location(
        &self,
        lat: f64,
        lng: f64,
        accuracy_meters: Option<f64>,
    ) -> Vec<BoundaryCrossing> {
        self.checker.check_location(lat, lng, accuracy_meters).await
    }

    /// Total places loaded across all circles
    pub async fn place_count(&self) -> u32 {
        let places = self.places.read().await;
        places.values().map(|p| p.len() as u32).sum()
    }

    pub async fn get_monitored_users(&self) -> Vec<String> {
        self.monitored_users.read().await.keys().cloned().collect()
    }

    /// user_id -> the circle_ids that user is monitored through
    pub async fn get_monitored_users_with_circles(&self) -> HashMap<String, Vec<String>> {
        self.monitored_users.read().await.clone()
    }

    /// Name a user for notification text; call when circle members are loaded,
    /// otherwise notifications fall back to the raw user_id.
    pub async fn set_display_name(&self, user_id: String, display_name: String) {
        self.display_names.write().await.insert(user_id, display_name);
    }

    /// Merge in several display names at once (existing entries are overwritten)
    pub async fn set_display_names(&self, names: HashMap<String, String>) {
        let mut display_names = self.display_names.write().await;
        for (user_id, name) in names {
            display_names.insert(user_id, name);
        }
    }

    /// Get the display name for a user, falling back to user_id if not set
    pub async fn get_display_name(&self, user_id: &str) -> String {
        self.display_names
            .read()
            .await
            .get(user_id)
            .cloned()
            .unwrap_or_else(|| user_id.to_string())
    }

    /// Clear all display names (call on logout)
    pub async fn clear_display_names(&self) {
        self.display_names.write().await.clear();
    }
}

/// Great-circle distance in metres between two points (Haversine)
fn haversine_distance(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    const EARTH_RADIUS_METERS: f64 = 6_371_000.0;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lng = (lng2 - lng1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();

    EARTH_RADIUS_METERS * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_short_distance() {
        // Two points ~100m apart
        let lat1 = 51.5074;
        let lng1 = -0.1278;
        let lat2 = 51.5083;
        let lng2 = -0.1278;

        let distance = haversine_distance(lat1, lng1, lat2, lng2);
        assert!((distance - 100.0).abs() < 10.0);
    }
}
