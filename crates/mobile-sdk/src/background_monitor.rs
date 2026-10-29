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

//! Background Monitoring Service
//!
//! This module provides the infrastructure for monitoring circle members' locations
//! in the background, even when the app is not in the foreground.
//!
//! ## Platform Integration
//!
//! The actual background execution is platform-specific. This module provides:
//! 1. A queue for processing location updates
//! 2. Persistence for monitoring state across app restarts
//! 3. Callbacks for platform code to implement push notifications
//!
//! ### iOS Implementation Guide
//!
//! ```swift
//! // 1. Enable Background Modes in Xcode:
//! //    - Background fetch
//! //    - Remote notifications
//! //
//! // 2. Register for silent push notifications:
//! application.registerForRemoteNotifications()
//!
//! // 3. Handle background fetch:
//! func application(_ application: UIApplication,
//!                  performFetchWithCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
//!     // Fetch latest locations from server
//!     // Pass to BackgroundMonitorService.processQueuedLocations()
//!     // Show local notification if crossing detected
//!     completionHandler(.newData)
//! }
//!
//! // 4. Handle silent push:
//! func application(_ application: UIApplication,
//!                  didReceiveRemoteNotification userInfo: [AnyHashable: Any],
//!                  fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
//!     // Process location update from push payload
//!     // Check boundaries via BackgroundMonitorService
//!     completionHandler(.newData)
//! }
//! ```
//!
//! ### Android Implementation Guide
//!
//! ```kotlin
//! // 1. Add foreground service permission:
//! // <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
//!
//! // 2. Create a ForegroundService:
//! class LocationMonitorService : Service() {
//!     override fun onCreate() {
//!         val notification = createNotification()
//!         startForeground(NOTIFICATION_ID, notification)
//!         // Initialize BackgroundMonitorService
//!     }
//!
//!     // Poll for location updates or listen to FCM
//! }
//!
//! // 3. Or use WorkManager for periodic checks:
//! class LocationCheckWorker(context: Context, params: WorkerParameters)
//!     : CoroutineWorker(context, params) {
//!     override suspend fun doWork(): Result {
//!         // Fetch and process locations
//!         return Result.success()
//!     }
//! }
//!
//! // Schedule periodic work:
//! val request = PeriodicWorkRequestBuilder<LocationCheckWorker>(15, TimeUnit.MINUTES)
//!     .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
//!     .build()
//! WorkManager.getInstance(context).enqueueUniquePeriodicWork(
//!     "location_monitor", ExistingPeriodicWorkPolicy.KEEP, request)
//! ```

use crate::boundary_monitor::{BoundaryMonitor, EncryptedMemberLocation};
use crate::types::MobileError;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum number of locations to queue before dropping oldest
const MAX_QUEUE_SIZE: usize = 1000;

/// Callback for platform-specific background operations
#[uniffi::export(callback_interface)]
pub trait BackgroundMonitorPlatform: Send + Sync {
    /// Show a local notification for a boundary crossing
    fn show_local_notification(
        &self,
        title: String,
        body: String,
        data: String, // JSON payload
    );

    /// Request the server to send a push notification to the subscriber
    /// This is used when the monitoring client detects a crossing
    fn request_server_notification(
        &self,
        place_id: String,
        crossing_user_id: String,
        event_type: String, // "enter" or "exit"
    );

    /// Called when the monitor needs to fetch latest locations from server
    fn fetch_latest_locations(&self, circle_ids: Vec<String>);

    /// Persist monitoring state to storage (for app restart recovery)
    fn persist_state(&self, state_json: String);

    /// Load the JSON last handed to `persist_state`, or `None` on a first run
    fn load_persisted_state(&self) -> Option<String>;
}

/// Queued location update awaiting processing
#[derive(Debug, Clone, uniffi::Record)]
pub struct QueuedLocation {
    pub user_id: String,
    pub device_id: String,
    pub circle_id: String,
    pub encrypted_nonce: String,
    pub encrypted_ciphertext: String,
    pub timestamp: i64,
    pub received_at: i64,
}

/// State that can be persisted across app restarts
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    /// Users being monitored (user_id -> circle_ids)
    pub monitored_users: std::collections::HashMap<String, Vec<String>>,
    /// Last processed timestamp per user
    pub last_processed: std::collections::HashMap<String, i64>,
    /// Queued locations not yet processed
    pub queued_locations: Vec<QueuedLocationSerde>,
}

/// Serialisation mirror of `QueuedLocation` used inside `PersistedState`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueuedLocationSerde {
    pub user_id: String,
    pub device_id: String,
    pub circle_id: String,
    pub encrypted_nonce: String,
    pub encrypted_ciphertext: String,
    pub timestamp: i64,
    pub received_at: i64,
}

/// Background monitoring service
///
/// This service manages a queue of location updates and processes them
/// to detect boundary crossings. It's designed to work with platform-specific
/// background execution mechanisms.
#[derive(uniffi::Object)]
pub struct BackgroundMonitorService {
    monitor: Arc<BoundaryMonitor>,
    queue: Arc<RwLock<VecDeque<QueuedLocation>>>,
    platform: Arc<RwLock<Option<Box<dyn BackgroundMonitorPlatform>>>>,
    last_processed: Arc<RwLock<std::collections::HashMap<String, i64>>>,
}

#[uniffi::export]
impl BackgroundMonitorService {
    #[uniffi::constructor]
    pub fn new(monitor: Arc<BoundaryMonitor>) -> Arc<Self> {
        Arc::new(Self {
            monitor,
            queue: Arc::new(RwLock::new(VecDeque::new())),
            platform: Arc::new(RwLock::new(None)),
            last_processed: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    pub async fn set_platform(&self, platform: Box<dyn BackgroundMonitorPlatform>) {
        *self.platform.write().await = Some(platform);
    }

    /// Queue a location update for processing
    ///
    /// Call this when a location update is received (via push, polling, etc.)
    pub async fn queue_location(&self, location: QueuedLocation) {
        let mut queue = self.queue.write().await;

        while queue.len() >= MAX_QUEUE_SIZE {
            queue.pop_front();
        }

        queue.push_back(location);
    }

    /// Process all queued locations
    ///
    /// Returns the number of crossings detected
    pub async fn process_queue(&self) -> Result<u32, MobileError> {
        // Take the whole queue under a short write lock and release it before
        // processing anything. `persist_state` at the end re-acquires this
        // same lock for reading, and tokio's RwLock is not reentrant — holding
        // the write guard across that call deadlocks the task outright, and
        // holding it across the processing loop would block `queue_location`
        // for the entire run.
        let pending: VecDeque<QueuedLocation> = {
            let mut queue = self.queue.write().await;
            std::mem::take(&mut *queue)
        };
        let mut crossings = 0;

        for loc in pending {
            // Skip if we've already processed a newer location for this user
            let last = self.last_processed.read().await;
            if let Some(&last_ts) = last.get(&loc.user_id) {
                if loc.timestamp <= last_ts {
                    continue;
                }
            }
            drop(last);

            let member_loc = EncryptedMemberLocation {
                user_id: loc.user_id.clone(),
                device_id: loc.device_id.clone(),
                circle_id: loc.circle_id.clone(),
                encrypted_location: crate::types::EncryptedData {
                    nonce: loc.encrypted_nonce,
                    ciphertext: loc.encrypted_ciphertext,
                },
                timestamp: loc.timestamp,
            };

            match self.monitor.process_member_location(member_loc).await {
                Ok(detected) => {
                    crossings += detected.len() as u32;

                    if let Some(platform) = &*self.platform.read().await {
                        for crossing in detected {
                            let title = match crossing.crossing_type {
                                crate::boundary::BoundaryCrossingType::Enter => {
                                    format!("Arrived at {}", crossing.boundary_name)
                                }
                                crate::boundary::BoundaryCrossingType::Exit => {
                                    format!("Left {}", crossing.boundary_name)
                                }
                            };

                            let display_name = self.monitor.get_display_name(&loc.user_id).await;

                            let body = format!(
                                "{} has {} {}",
                                display_name,
                                match crossing.crossing_type {
                                    crate::boundary::BoundaryCrossingType::Enter => "arrived at",
                                    crate::boundary::BoundaryCrossingType::Exit => "left",
                                },
                                crossing.boundary_name
                            );

                            let data = serde_json::json!({
                                "type": "boundary_crossing",
                                "user_id": loc.user_id,
                                "place_id": crossing.boundary_id,
                                "event_type": match crossing.crossing_type {
                                    crate::boundary::BoundaryCrossingType::Enter => "enter",
                                    crate::boundary::BoundaryCrossingType::Exit => "exit",
                                },
                            });

                            platform.show_local_notification(title, body, data.to_string());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to process location for {}: {:?}", loc.user_id, e);
                }
            }

            self.last_processed.write().await.insert(loc.user_id, loc.timestamp);
        }

        self.persist_state().await;

        Ok(crossings)
    }

    /// Get the current queue size
    pub async fn queue_size(&self) -> u32 {
        self.queue.read().await.len() as u32
    }

    /// Persist current state for recovery after app restart
    async fn persist_state(&self) {
        if let Some(platform) = &*self.platform.read().await {
            // The circle_ids have to round-trip: restore_state re-registers every
            // (user, circle) pair, and a user with no circle is never matched.
            let monitored_users = self.monitor.get_monitored_users_with_circles().await;
            let last_processed = self.last_processed.read().await.clone();

            let queue = self.queue.read().await;
            let queued: Vec<QueuedLocationSerde> = queue
                .iter()
                .map(|l| QueuedLocationSerde {
                    user_id: l.user_id.clone(),
                    device_id: l.device_id.clone(),
                    circle_id: l.circle_id.clone(),
                    encrypted_nonce: l.encrypted_nonce.clone(),
                    encrypted_ciphertext: l.encrypted_ciphertext.clone(),
                    timestamp: l.timestamp,
                    received_at: l.received_at,
                })
                .collect();

            let state = PersistedState {
                monitored_users,
                last_processed,
                queued_locations: queued,
            };

            if let Ok(json) = serde_json::to_string(&state) {
                platform.persist_state(json);
            }
        }
    }

    /// Restore state from persistence
    ///
    /// Call this on app startup to restore monitoring state
    pub async fn restore_state(&self) -> Result<(), MobileError> {
        let platform = self.platform.read().await;
        let Some(platform) = &*platform else {
            return Ok(());
        };

        let Some(json) = platform.load_persisted_state() else {
            return Ok(());
        };

        let state: PersistedState = serde_json::from_str(&json)
            .map_err(|e| MobileError::InvalidInput(format!("Invalid persisted state: {}", e)))?;

        for (user_id, circle_ids) in state.monitored_users {
            for circle_id in circle_ids {
                self.monitor.monitor_user(user_id.clone(), circle_id).await;
            }
        }

        *self.last_processed.write().await = state.last_processed;

        let mut queue = self.queue.write().await;
        for loc in state.queued_locations {
            queue.push_back(QueuedLocation {
                user_id: loc.user_id,
                device_id: loc.device_id,
                circle_id: loc.circle_id,
                encrypted_nonce: loc.encrypted_nonce,
                encrypted_ciphertext: loc.encrypted_ciphertext,
                timestamp: loc.timestamp,
                received_at: loc.received_at,
            });
        }

        Ok(())
    }

    /// Clear all state (for logout)
    pub async fn clear_state(&self) {
        self.queue.write().await.clear();
        self.last_processed.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoManager;

    /// A platform that does nothing but exist. `persist_state` short-circuits
    /// when no platform is registered, so without one the deadlock below never
    /// even gets a chance to happen.
    struct NoopPlatform;

    impl BackgroundMonitorPlatform for NoopPlatform {
        fn show_local_notification(&self, _title: String, _body: String, _data: String) {}
        fn request_server_notification(
            &self,
            _place_id: String,
            _crossing_user_id: String,
            _event_type: String,
        ) {
        }
        fn fetch_latest_locations(&self, _circle_ids: Vec<String>) {}
        fn persist_state(&self, _state_json: String) {}
        fn load_persisted_state(&self) -> Option<String> {
            None
        }
    }

    fn service() -> Arc<BackgroundMonitorService> {
        BackgroundMonitorService::new(BoundaryMonitor::new(CryptoManager::new()))
    }

    fn queued(user_id: &str, timestamp: i64) -> QueuedLocation {
        QueuedLocation {
            user_id: user_id.to_string(),
            device_id: "device-1".to_string(),
            circle_id: "circle-1".to_string(),
            encrypted_nonce: "00".to_string(),
            encrypted_ciphertext: "00".to_string(),
            timestamp,
            received_at: timestamp,
        }
    }

    /// `process_queue` must not hold `queue.write()` across `persist_state()`,
    /// which takes `queue.read()`: tokio's RwLock is not reentrant, so the task
    /// would deadlock on itself and never return — background boundary
    /// monitoring would simply stop, with no error anywhere. The timeout turns
    /// such a deadlock into a failure instead of a hung test run.
    #[tokio::test]
    async fn process_queue_does_not_deadlock_against_its_own_persist_state() {
        let service = service();
        service.set_platform(Box::new(NoopPlatform)).await;
        service.queue_location(queued("user-1", 1_000)).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.process_queue(),
        )
        .await;

        assert!(
            result.is_ok(),
            "process_queue deadlocked taking queue.read() while holding queue.write()"
        );
        assert_eq!(
            service.queue_size().await,
            0,
            "the queue must be drained even though decryption fails"
        );
    }

    /// Draining under a short lock must not drop anything: every queued item
    /// still gets processed exactly once, and none are left behind.
    #[tokio::test]
    async fn process_queue_drains_every_queued_location() {
        let service = service();
        service.set_platform(Box::new(NoopPlatform)).await;
        for i in 0..5 {
            service.queue_location(queued(&format!("user-{}", i), 1_000 + i)).await;
        }
        assert_eq!(service.queue_size().await, 5);

        tokio::time::timeout(std::time::Duration::from_secs(5), service.process_queue())
            .await
            .expect("process_queue must return")
            .expect("process_queue must not error");

        assert_eq!(service.queue_size().await, 0, "nothing may be left queued");
    }

    /// The lock must be released before processing, not just before persisting:
    /// a producer has to be able to enqueue while a drain is running.
    #[tokio::test]
    async fn queue_location_is_not_blocked_while_process_queue_runs() {
        let service = service();
        service.set_platform(Box::new(NoopPlatform)).await;
        service.queue_location(queued("user-1", 1_000)).await;

        let producer = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.queue_location(queued("user-2", 2_000)).await })
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), service.process_queue())
            .await
            .expect("process_queue must return")
            .expect("process_queue must not error");
        tokio::time::timeout(std::time::Duration::from_secs(5), producer)
            .await
            .expect("queue_location must not be blocked out by process_queue")
            .expect("producer task must not panic");
    }
}
