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

//! Inactivity Monitoring for Offline Detection
//!
//! This module provides client-side monitoring to detect when circle members
//! go "offline" (stop sending location updates). This is implemented client-side
//! to maintain E2EE - the server never knows activity patterns.
//!
//! ## How It Works
//!
//! 1. Client receives location updates from circle members via subscription
//! 2. Client tracks "last seen" timestamp for each monitored user
//! 3. When no update is received within the configured timeout, triggers alert
//! 4. Alert shown locally (no server notification to preserve privacy)
//!
//! ## Privacy Considerations
//!
//! - All monitoring happens on the observing client
//! - Server doesn't know who is being monitored or their activity patterns
//! - Alerts are local notifications only
//!
//! ## Platform Integration
//!
//! ### Android
//! ```kotlin
//! // Every field is required — a uniffi record has no default arguments.
//! val inactivityMonitor = InactivityMonitor.withConfig(
//!     InactivityMonitorConfig(
//!         defaultTimeoutSeconds = 3600uL, // 1 hour
//!         alertCooldownSeconds = 3600uL,
//!         startupGraceSeconds = 300uL,    // 5 minutes
//!     )
//! )
//!
//! inactivityMonitor.startMonitoring("user_id", "circle_id", "John")
//!
//! // Feed it every location update you receive for that user
//! inactivityMonitor.recordActivity("user_id", System.currentTimeMillis())
//!
//! // Poll on a timer (e.g. WorkManager) — nothing fires on its own
//! val inactive = inactivityMonitor.checkInactiveUsers()
//! for (alert in inactive) {
//!     showNotification("${alert.displayName} appears to be offline")
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for inactivity monitoring
#[derive(Debug, Clone, uniffi::Record)]
pub struct InactivityMonitorConfig {
    /// Default timeout in seconds before a user is considered inactive (default: 1 hour)
    pub default_timeout_seconds: u64,
    /// Minimum time between alerts for the same user in seconds (default: 1 hour)
    pub alert_cooldown_seconds: u64,
    /// Grace period after app start before triggering alerts (default: 5 minutes)
    /// This prevents false alerts when the app is just starting up
    pub startup_grace_seconds: u64,
}

impl Default for InactivityMonitorConfig {
    fn default() -> Self {
        Self {
            default_timeout_seconds: 60 * 60,      // 1 hour
            alert_cooldown_seconds: 60 * 60,       // 1 hour
            startup_grace_seconds: 5 * 60,         // 5 minutes
        }
    }
}

/// Presets. Rust-side only: `InactivityMonitorConfig` crosses the FFI as a
/// plain record, so Kotlin/Swift build it field by field.
impl InactivityMonitorConfig {
    /// Custom timeout, with the cooldown and grace period left at their defaults
    pub fn with_timeout(timeout_seconds: u64) -> Self {
        Self {
            default_timeout_seconds: timeout_seconds,
            ..Default::default()
        }
    }

    /// Notices sooner and repeats sooner — more alerts, more false ones
    pub fn sensitive() -> Self {
        Self {
            default_timeout_seconds: 30 * 60,      // 30 minutes
            alert_cooldown_seconds: 30 * 60,       // 30 minutes
            startup_grace_seconds: 2 * 60,         // 2 minutes
        }
    }

    /// Tolerates a device that only reports every few hours
    pub fn relaxed() -> Self {
        Self {
            default_timeout_seconds: 4 * 60 * 60,  // 4 hours
            alert_cooldown_seconds: 4 * 60 * 60,   // 4 hours
            startup_grace_seconds: 10 * 60,        // 10 minutes
        }
    }
}

/// A user being monitored for inactivity
#[derive(Debug, Clone)]
struct MonitoredUser {
    user_id: String,
    /// Circle ID this user is monitored through
    circle_id: String,
    /// Display name for notifications
    display_name: String,
    /// Per-user override of the config's default timeout
    timeout_seconds: Option<u64>,
    /// Last activity timestamp (Unix ms)
    last_activity: Option<i64>,
    /// When monitoring started (Unix ms). Recorded but not read: the inactivity
    /// check works off last_activity and last_alert_time only.
    #[allow(dead_code)]
    monitoring_started: i64,
    /// Last alert timestamp (Unix ms)
    last_alert_time: Option<i64>,
    is_inactive: bool,
}

/// Information about a detected inactivity
#[derive(Debug, Clone, uniffi::Record)]
pub struct InactivityAlert {
    /// The user who went quiet
    pub user_id: String,
    pub circle_id: String,
    /// Display name for notifications
    pub display_name: String,
    /// How long the user has been inactive (seconds)
    pub inactive_duration_seconds: u64,
    /// When the alert was triggered (Unix ms)
    pub triggered_at: i64,
    /// Last known activity timestamp (Unix ms)
    pub last_activity: Option<i64>,
}

/// User activity status
#[derive(Debug, Clone, uniffi::Record)]
pub struct UserActivityStatus {
    pub user_id: String,
    pub display_name: String,
    pub circle_id: String,
    pub is_active: bool,
    /// Last activity timestamp (Unix ms); `None` until the first update arrives
    pub last_activity: Option<i64>,
    /// Seconds since last activity; `None` until the first update arrives
    pub seconds_since_activity: Option<u64>,
}

/// Callback interface for inactivity alerts
#[uniffi::export(callback_interface)]
pub trait InactivityAlertCallback: Send + Sync {
    /// Called when a user becomes inactive
    fn on_user_inactive(&self, alert: InactivityAlert);

    /// Called when a previously inactive user becomes active again
    fn on_user_active(&self, user_id: String, display_name: String);
}

/// Client-side inactivity monitor
///
/// Monitors circle members for inactivity and triggers local alerts.
/// All monitoring is done client-side to maintain E2EE privacy.
#[derive(uniffi::Object)]
pub struct InactivityMonitor {
    config: InactivityMonitorConfig,
    /// Users being monitored: user_id -> MonitoredUser
    monitored_users: Arc<RwLock<HashMap<String, MonitoredUser>>>,
    /// Monitor start time (Unix ms), which the startup grace period runs from
    started_at: i64,
    callback: Arc<RwLock<Option<Box<dyn InactivityAlertCallback>>>>,
}

#[uniffi::export]
impl InactivityMonitor {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Self::with_config(InactivityMonitorConfig::default())
    }

    #[uniffi::constructor]
    pub fn with_config(config: InactivityMonitorConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            monitored_users: Arc::new(RwLock::new(HashMap::new())),
            started_at: chrono::Utc::now().timestamp_millis(),
            callback: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn set_callback(&self, callback: Box<dyn InactivityAlertCallback>) {
        *self.callback.write().await = Some(callback);
    }

    /// Start monitoring a user, using the config's default timeout.
    ///
    /// `circle_id` is the circle this user is watched through; `display_name` is
    /// what an alert will call them.
    pub async fn start_monitoring(
        &self,
        user_id: String,
        circle_id: String,
        display_name: String,
    ) {
        self.start_monitoring_with_timeout(user_id, circle_id, display_name, None).await
    }

    /// Start monitoring a user. A `timeout_seconds` of `None` means "use the
    /// config default"; monitoring the same user again replaces the entry and
    /// discards their recorded activity.
    pub async fn start_monitoring_with_timeout(
        &self,
        user_id: String,
        circle_id: String,
        display_name: String,
        timeout_seconds: Option<u64>,
    ) {
        let now = chrono::Utc::now().timestamp_millis();

        let user = MonitoredUser {
            user_id: user_id.clone(),
            circle_id,
            display_name,
            timeout_seconds,
            last_activity: None, // Will be set on first location update
            monitoring_started: now,
            last_alert_time: None,
            is_inactive: false,
        };

        tracing::info!("Starting inactivity monitoring for user {}", user_id);
        self.monitored_users.write().await.insert(user_id, user);
    }

    pub async fn stop_monitoring(&self, user_id: &str) {
        tracing::info!("Stopping inactivity monitoring for user {}", user_id);
        self.monitored_users.write().await.remove(user_id);
    }

    /// Reset a user's inactivity timer; call on every location update received
    /// for them.
    ///
    /// `timestamp` is Unix ms and is stored verbatim, then compared against the
    /// local clock — a skewed or already-stale timestamp ages the user by that
    /// much. A user who isn't being monitored is silently ignored.
    pub async fn record_activity(&self, user_id: &str, timestamp: i64) {
        let mut users = self.monitored_users.write().await;

        if let Some(user) = users.get_mut(user_id) {
            let was_inactive = user.is_inactive;
            user.last_activity = Some(timestamp);
            user.is_inactive = false;

            if was_inactive {
                tracing::info!("User {} is now active again", user_id);
                if let Some(callback) = &*self.callback.read().await {
                    callback.on_user_active(user_id.to_string(), user.display_name.clone());
                }
            }
        }
    }

    /// Evaluate every monitored user and return those that just went inactive.
    ///
    /// Nothing here is timer-driven: the platform must call this periodically
    /// (roughly every minute) or no alert is ever produced. Alerts already
    /// emitted within the cooldown are not repeated.
    pub async fn check_inactive_users(&self) -> Vec<InactivityAlert> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut alerts = Vec::new();

        // The grace period runs from monitor construction, not from app launch:
        // a monitor built late still gets its full quiet window.
        let grace_ms = self.config.startup_grace_seconds as i64 * 1000;
        if now - self.started_at < grace_ms {
            tracing::debug!("Still in startup grace period, skipping inactivity check");
            return alerts;
        }

        let mut users = self.monitored_users.write().await;

        for user in users.values_mut() {
            // No update has arrived since monitoring started (first sync, or a
            // member who has never reported). There is nothing to time out from,
            // so stay quiet rather than alert on a user we have never seen.
            let Some(last_activity) = user.last_activity else {
                continue;
            };

            let timeout_ms = user.timeout_seconds
                .unwrap_or(self.config.default_timeout_seconds) as i64 * 1000;

            let inactive_duration_ms = now - last_activity;

            if inactive_duration_ms > timeout_ms {
                let cooldown_ms = self.config.alert_cooldown_seconds as i64 * 1000;
                let in_cooldown = user.last_alert_time
                    .map(|t| now - t < cooldown_ms)
                    .unwrap_or(false);

                if !in_cooldown {
                    user.is_inactive = true;
                    user.last_alert_time = Some(now);

                    let alert = InactivityAlert {
                        user_id: user.user_id.clone(),
                        circle_id: user.circle_id.clone(),
                        display_name: user.display_name.clone(),
                        inactive_duration_seconds: (inactive_duration_ms / 1000) as u64,
                        triggered_at: now,
                        last_activity: Some(last_activity),
                    };

                    tracing::info!(
                        "User {} has been inactive for {} seconds",
                        user.user_id,
                        alert.inactive_duration_seconds
                    );

                    if let Some(callback) = &*self.callback.read().await {
                        callback.on_user_inactive(alert.clone());
                    }

                    alerts.push(alert);
                }
            }
        }

        alerts
    }

    /// Get current activity status for all monitored users
    pub async fn get_all_status(&self) -> Vec<UserActivityStatus> {
        let now = chrono::Utc::now().timestamp_millis();
        let users = self.monitored_users.read().await;

        users.values().map(|user| {
            let seconds_since = user.last_activity
                .map(|t| ((now - t) / 1000) as u64);

            UserActivityStatus {
                user_id: user.user_id.clone(),
                display_name: user.display_name.clone(),
                circle_id: user.circle_id.clone(),
                is_active: !user.is_inactive,
                last_activity: user.last_activity,
                seconds_since_activity: seconds_since,
            }
        }).collect()
    }

    /// Activity status for one user, or `None` if they aren't being monitored
    pub async fn get_user_status(&self, user_id: &str) -> Option<UserActivityStatus> {
        let now = chrono::Utc::now().timestamp_millis();
        let users = self.monitored_users.read().await;

        users.get(user_id).map(|user| {
            let seconds_since = user.last_activity
                .map(|t| ((now - t) / 1000) as u64);

            UserActivityStatus {
                user_id: user.user_id.clone(),
                display_name: user.display_name.clone(),
                circle_id: user.circle_id.clone(),
                is_active: !user.is_inactive,
                last_activity: user.last_activity,
                seconds_since_activity: seconds_since,
            }
        })
    }

    /// Whether the last `check_inactive_users` marked this user inactive. The
    /// flag flips only when an alert actually fires, so a user suppressed by the
    /// cooldown can still read as active; an unmonitored user reads as active
    /// too, since there is no "unknown" to return.
    pub async fn is_user_inactive(&self, user_id: &str) -> bool {
        self.monitored_users.read().await
            .get(user_id)
            .map(|u| u.is_inactive)
            .unwrap_or(false)
    }

    pub async fn monitored_user_count(&self) -> u32 {
        self.monitored_users.read().await.len() as u32
    }

    pub async fn get_monitored_user_ids(&self) -> Vec<String> {
        self.monitored_users.read().await.keys().cloned().collect()
    }

    /// Update the display name for a monitored user
    pub async fn update_display_name(&self, user_id: &str, display_name: String) {
        if let Some(user) = self.monitored_users.write().await.get_mut(user_id) {
            user.display_name = display_name;
        }
    }

    /// Clear all monitoring state (e.g., on logout)
    pub async fn clear(&self) {
        self.monitored_users.write().await.clear();
    }

    /// Get the default timeout in seconds
    pub fn get_default_timeout(&self) -> u64 {
        self.config.default_timeout_seconds
    }
}

impl Default for InactivityMonitor {
    fn default() -> Self {
        Self {
            config: InactivityMonitorConfig::default(),
            monitored_users: Arc::new(RwLock::new(HashMap::new())),
            started_at: chrono::Utc::now().timestamp_millis(),
            callback: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestCallback {
        inactive_count: AtomicU32,
        active_count: AtomicU32,
    }

    impl TestCallback {
        fn new() -> Self {
            Self {
                inactive_count: AtomicU32::new(0),
                active_count: AtomicU32::new(0),
            }
        }
    }

    impl InactivityAlertCallback for TestCallback {
        fn on_user_inactive(&self, _alert: InactivityAlert) {
            self.inactive_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_user_active(&self, _user_id: String, _display_name: String) {
            self.active_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn create_monitor_past_grace_period() -> InactivityMonitor {
        let config = InactivityMonitorConfig {
            default_timeout_seconds: 60,       // 1 minute
            alert_cooldown_seconds: 60,        // 1 minute
            startup_grace_seconds: 0,          // No grace period for tests
        };
        InactivityMonitor {
            config,
            monitored_users: Arc::new(RwLock::new(HashMap::new())),
            started_at: chrono::Utc::now().timestamp_millis() - 1000, // Started 1 second ago
            callback: Arc::new(RwLock::new(None)),
        }
    }

    #[tokio::test]
    async fn test_start_stop_monitoring() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John Doe".to_string(),
        ).await;

        assert_eq!(monitor.monitored_user_count().await, 1);
        assert!(monitor.get_monitored_user_ids().await.contains(&"user1".to_string()));

        monitor.stop_monitoring("user1").await;
        assert_eq!(monitor.monitored_user_count().await, 0);
    }

    #[tokio::test]
    async fn test_record_activity() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        let now = chrono::Utc::now().timestamp_millis();
        monitor.record_activity("user1", now).await;

        let status = monitor.get_user_status("user1").await.unwrap();
        assert_eq!(status.last_activity, Some(now));
        assert!(status.is_active);
    }

    #[tokio::test]
    async fn test_no_alert_when_active() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Record recent activity
        let now = chrono::Utc::now().timestamp_millis();
        monitor.record_activity("user1", now).await;

        let alerts = monitor.check_inactive_users().await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn test_alert_when_inactive() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Record old activity (2 minutes ago, timeout is 1 minute)
        let old_time = chrono::Utc::now().timestamp_millis() - 120_000;
        monitor.record_activity("user1", old_time).await;

        let alerts = monitor.check_inactive_users().await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].user_id, "user1");
        assert_eq!(alerts[0].display_name, "John");
        assert!(alerts[0].inactive_duration_seconds >= 120);
    }

    #[tokio::test]
    async fn test_alert_cooldown() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Record old activity
        let old_time = chrono::Utc::now().timestamp_millis() - 120_000;
        monitor.record_activity("user1", old_time).await;

        // First check triggers alert
        let alerts = monitor.check_inactive_users().await;
        assert_eq!(alerts.len(), 1);

        // Second check should be in cooldown
        let alerts = monitor.check_inactive_users().await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn test_user_becomes_active_again() {
        let monitor = Arc::new(create_monitor_past_grace_period());
        let callback = Arc::new(TestCallback::new());
        let callback_clone = callback.clone();
        monitor.set_callback(Box::new(TestCallbackWrapper(callback_clone))).await;

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Record old activity and trigger inactive alert
        let old_time = chrono::Utc::now().timestamp_millis() - 120_000;
        monitor.record_activity("user1", old_time).await;
        let _ = monitor.check_inactive_users().await;

        assert_eq!(callback.inactive_count.load(Ordering::SeqCst), 1);
        assert!(monitor.is_user_inactive("user1").await);

        // User becomes active again
        let now = chrono::Utc::now().timestamp_millis();
        monitor.record_activity("user1", now).await;

        assert!(!monitor.is_user_inactive("user1").await);
        assert_eq!(callback.active_count.load(Ordering::SeqCst), 1);
    }

    /// Wrapper to make Arc<TestCallback> implement InactivityAlertCallback
    struct TestCallbackWrapper(Arc<TestCallback>);

    impl InactivityAlertCallback for TestCallbackWrapper {
        fn on_user_inactive(&self, alert: InactivityAlert) {
            self.0.on_user_inactive(alert);
        }

        fn on_user_active(&self, user_id: String, display_name: String) {
            self.0.on_user_active(user_id, display_name);
        }
    }

    #[tokio::test]
    async fn test_custom_timeout() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        // User with 30-second timeout
        monitor.start_monitoring_with_timeout(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
            Some(30),
        ).await;

        // Record activity 45 seconds ago (past custom timeout)
        let old_time = chrono::Utc::now().timestamp_millis() - 45_000;
        monitor.record_activity("user1", old_time).await;

        let alerts = monitor.check_inactive_users().await;
        assert_eq!(alerts.len(), 1);
    }

    #[tokio::test]
    async fn test_no_alert_without_initial_activity() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        // Start monitoring but never record any activity
        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Should not alert because we haven't seen any activity yet
        // (user might just be syncing)
        let alerts = monitor.check_inactive_users().await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn test_startup_grace_period() {
        let config = InactivityMonitorConfig {
            default_timeout_seconds: 60,
            alert_cooldown_seconds: 60,
            startup_grace_seconds: 300, // 5 minute grace period
        };
        let monitor = InactivityMonitor::with_config(config);

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        // Record old activity
        let old_time = chrono::Utc::now().timestamp_millis() - 120_000;
        monitor.record_activity("user1", old_time).await;

        // Should not alert due to grace period
        let alerts = monitor.check_inactive_users().await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring("user1".to_string(), "circle1".to_string(), "John".to_string()).await;
        monitor.start_monitoring("user2".to_string(), "circle1".to_string(), "Jane".to_string()).await;
        monitor.start_monitoring("user3".to_string(), "circle1".to_string(), "Bob".to_string()).await;

        let now = chrono::Utc::now().timestamp_millis();
        let old = now - 120_000;

        // user1 is active, user2 and user3 are inactive
        monitor.record_activity("user1", now).await;
        monitor.record_activity("user2", old).await;
        monitor.record_activity("user3", old).await;

        let alerts = monitor.check_inactive_users().await;
        assert_eq!(alerts.len(), 2);

        let alert_user_ids: Vec<_> = alerts.iter().map(|a| a.user_id.as_str()).collect();
        assert!(alert_user_ids.contains(&"user2"));
        assert!(alert_user_ids.contains(&"user3"));
        assert!(!alert_user_ids.contains(&"user1"));
    }

    #[tokio::test]
    async fn test_get_all_status() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring("user1".to_string(), "circle1".to_string(), "John".to_string()).await;
        monitor.start_monitoring("user2".to_string(), "circle1".to_string(), "Jane".to_string()).await;

        let now = chrono::Utc::now().timestamp_millis();
        monitor.record_activity("user1", now).await;

        let statuses = monitor.get_all_status().await;
        assert_eq!(statuses.len(), 2);
    }

    #[tokio::test]
    async fn test_update_display_name() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring(
            "user1".to_string(),
            "circle1".to_string(),
            "John".to_string(),
        ).await;

        monitor.update_display_name("user1", "John Doe".to_string()).await;

        let status = monitor.get_user_status("user1").await.unwrap();
        assert_eq!(status.display_name, "John Doe");
    }

    #[tokio::test]
    async fn test_clear() {
        let monitor = Arc::new(create_monitor_past_grace_period());

        monitor.start_monitoring("user1".to_string(), "circle1".to_string(), "John".to_string()).await;
        monitor.start_monitoring("user2".to_string(), "circle1".to_string(), "Jane".to_string()).await;

        assert_eq!(monitor.monitored_user_count().await, 2);

        monitor.clear().await;

        assert_eq!(monitor.monitored_user_count().await, 0);
    }

    #[tokio::test]
    async fn test_config_presets() {
        let sensitive = InactivityMonitorConfig::sensitive();
        assert_eq!(sensitive.default_timeout_seconds, 30 * 60);

        let relaxed = InactivityMonitorConfig::relaxed();
        assert_eq!(relaxed.default_timeout_seconds, 4 * 60 * 60);

        let custom = InactivityMonitorConfig::with_timeout(45 * 60);
        assert_eq!(custom.default_timeout_seconds, 45 * 60);
    }
}
