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

//! Battery Monitoring for Low Battery Alerts
//!
//! This module provides client-side battery monitoring to detect low battery
//! conditions and notify circle members. This is implemented client-side to
//! maintain E2EE - battery levels stay on the device until an alert is due.
//!
//! ## How It Works
//!
//! 1. Platform code provides battery level updates via `update_battery_level()`
//! 2. Reaching the threshold triggers an alert — the test is `<=`, so the
//!    default 10% fires AT 10%, not below it
//! 3. Alert is sent to server which notifies circle members
//! 4. Cooldown prevents repeated alerts (default 6 hours), except for a
//!    Low -> Critical escalation
//!
//! ## Platform Integration
//!
//! ### Android
//! ```kotlin
//! // Register battery receiver
//! val batteryReceiver = object : BroadcastReceiver() {
//!     override fun onReceive(context: Context, intent: Intent) {
//!         val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
//!         val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
//!         val percent = (level * 100 / scale.toFloat()).toInt().toUByte()
//!         val isCharging = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ==
//!             BatteryManager.BATTERY_STATUS_CHARGING
//!         batteryMonitor.updateBatteryLevel(percent, isCharging)
//!     }
//! }
//! context.registerReceiver(batteryReceiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
//! ```

use crate::types::MobileError;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for battery monitoring
#[derive(Debug, Clone, uniffi::Record)]
pub struct BatteryMonitorConfig {
    /// Battery percentage threshold for low battery alert (default: 10)
    pub low_battery_threshold: u8,
    /// Critical battery percentage threshold (default: 5)
    pub critical_battery_threshold: u8,
    /// Cooldown between alerts in seconds (default: 6 hours = 21600)
    pub alert_cooldown_seconds: u64,
    /// Whether to skip alerts when charging (default: true)
    pub skip_when_charging: bool,
}

impl Default for BatteryMonitorConfig {
    fn default() -> Self {
        Self {
            low_battery_threshold: 10,
            critical_battery_threshold: 5,
            alert_cooldown_seconds: 6 * 60 * 60, // 6 hours
            skip_when_charging: true,
        }
    }
}

impl BatteryMonitorConfig {
    /// Change only the low-battery threshold; the critical threshold, cooldown
    /// and charging behaviour keep their defaults.
    pub fn with_threshold(threshold: u8) -> Self {
        Self {
            low_battery_threshold: threshold,
            ..Default::default()
        }
    }

    /// Alerts earlier (15%) and repeats sooner (2-hour cooldown)
    pub fn aggressive() -> Self {
        Self {
            low_battery_threshold: 15,
            critical_battery_threshold: 5,
            alert_cooldown_seconds: 2 * 60 * 60, // 2 hours
            skip_when_charging: true,
        }
    }
}

/// Battery alert severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BatteryAlertLevel {
    /// At or below low_battery_threshold, but above the critical one
    Low,
    /// At or below critical_battery_threshold
    Critical,
}

/// Information about a triggered battery alert
#[derive(Debug, Clone, uniffi::Record)]
pub struct BatteryAlert {
    /// Battery percentage when the alert fired
    pub battery_level: u8,
    /// Alert severity
    pub level: BatteryAlertLevel,
    /// Timestamp when alert was triggered (Unix ms)
    pub triggered_at: i64,
    /// Circle IDs to notify
    pub circle_ids: Vec<String>,
}

/// Callback interface for platform-specific battery alert handling
#[uniffi::export(callback_interface)]
pub trait BatteryAlertCallback: Send + Sync {
    /// Called when a low battery alert should be sent to the server
    ///
    /// Platform should make HTTP request to notify circle members:
    /// POST /api/v1/internal/notify
    /// {
    ///   "notification_type": "low_battery",
    ///   "circle_ids": [...],
    ///   "data": { "battery_level": N, "user_id": "..." }
    /// }
    fn send_low_battery_alert(&self, alert: BatteryAlert);

    /// Called when battery level changes (for UI updates)
    fn on_battery_level_changed(&self, level: u8, is_charging: bool);
}

/// Client-side battery monitor
///
/// Tracks battery level and triggers alerts when below threshold.
/// Maintains E2EE by keeping battery data client-side until alert is needed.
#[derive(uniffi::Object)]
pub struct BatteryMonitor {
    config: BatteryMonitorConfig,
    /// Current battery percentage, `None` until the platform reports one
    current_level: Arc<RwLock<Option<u8>>>,
    is_charging: Arc<RwLock<bool>>,
    /// Last alert timestamp (Unix ms)
    last_alert_time: Arc<RwLock<Option<i64>>>,
    /// Severity of the last alert, so a Low -> Critical escalation can be told
    /// apart from a repeat and allowed through the cooldown
    last_alert_level: Arc<RwLock<Option<BatteryAlertLevel>>>,
    /// Circle IDs to notify on low battery
    circle_ids: Arc<RwLock<HashSet<String>>>,
    callback: Arc<RwLock<Option<Box<dyn BatteryAlertCallback>>>>,
}

#[uniffi::export]
impl BatteryMonitor {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Self::with_config(BatteryMonitorConfig::default())
    }

    #[uniffi::constructor]
    pub fn with_config(config: BatteryMonitorConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            current_level: Arc::new(RwLock::new(None)),
            is_charging: Arc::new(RwLock::new(false)),
            last_alert_time: Arc::new(RwLock::new(None)),
            last_alert_level: Arc::new(RwLock::new(None)),
            circle_ids: Arc::new(RwLock::new(HashSet::new())),
            callback: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn set_callback(&self, callback: Box<dyn BatteryAlertCallback>) {
        *self.callback.write().await = Some(callback);
    }

    /// Add a circle to notify on low battery
    pub async fn add_circle(&self, circle_id: String) {
        self.circle_ids.write().await.insert(circle_id);
    }

    /// Remove a circle from notifications
    pub async fn remove_circle(&self, circle_id: String) {
        self.circle_ids.write().await.remove(&circle_id);
    }

    /// Replace the whole notify set. With no circles set, alerts are computed
    /// and then dropped — see `check_and_trigger_alert`.
    pub async fn set_circles(&self, circle_ids: Vec<String>) {
        let mut circles = self.circle_ids.write().await;
        circles.clear();
        circles.extend(circle_ids);
    }

    /// Current battery percentage, or `None` if the platform has not reported
    /// a level yet
    pub async fn get_battery_level(&self) -> Option<u8> {
        *self.current_level.read().await
    }

    pub async fn is_charging(&self) -> bool {
        *self.is_charging.read().await
    }

    /// Feed in a battery reading from the platform, as a percentage (anything
    /// over 100 is clamped). Returns the alert this reading triggered, if any.
    pub async fn update_battery_level(
        &self,
        level: u8,
        is_charging: bool,
    ) -> Result<Option<BatteryAlert>, MobileError> {
        let level = level.min(100);

        *self.current_level.write().await = Some(level);
        *self.is_charging.write().await = is_charging;

        if let Some(callback) = &*self.callback.read().await {
            callback.on_battery_level_changed(level, is_charging);
        }

        let alert = self.check_and_trigger_alert(level, is_charging).await?;

        Ok(alert)
    }

    /// Re-run the alert check against the last reported level. Errors if the
    /// platform has never reported one.
    pub async fn check_now(&self) -> Result<Option<BatteryAlert>, MobileError> {
        let level = self.current_level.read().await
            .ok_or_else(|| MobileError::InvalidInput("No battery level set".into()))?;
        let is_charging = *self.is_charging.read().await;

        self.check_and_trigger_alert(level, is_charging).await
    }

    /// Reset alert state (e.g., after user acknowledges or charges phone)
    pub async fn reset_alert_state(&self) {
        *self.last_alert_time.write().await = None;
        *self.last_alert_level.write().await = None;
    }

    /// Configured low-battery threshold, as a percentage
    pub fn get_threshold(&self) -> u8 {
        self.config.low_battery_threshold
    }

    /// Check if an alert is currently in cooldown
    pub async fn is_in_cooldown(&self) -> bool {
        if let Some(last_time) = *self.last_alert_time.read().await {
            let now = chrono::Utc::now().timestamp_millis();
            let cooldown_ms = self.config.alert_cooldown_seconds as i64 * 1000;
            now - last_time < cooldown_ms
        } else {
            false
        }
    }
}

impl BatteryMonitor {
    /// Decide whether a reading warrants an alert and fire it. Charging, the
    /// cooldown, and an empty circle set each suppress it independently.
    async fn check_and_trigger_alert(
        &self,
        level: u8,
        is_charging: bool,
    ) -> Result<Option<BatteryAlert>, MobileError> {
        if is_charging && self.config.skip_when_charging {
            tracing::debug!("Skipping battery alert check - device is charging");
            return Ok(None);
        }

        // Thresholds are inclusive: a level exactly AT the threshold alerts.
        let alert_level = if level <= self.config.critical_battery_threshold {
            Some(BatteryAlertLevel::Critical)
        } else if level <= self.config.low_battery_threshold {
            Some(BatteryAlertLevel::Low)
        } else {
            None
        };

        let Some(alert_level) = alert_level else {
            // Recovering above the threshold clears the cooldown, so a second
            // discharge alerts again instead of being swallowed as a repeat.
            if self.last_alert_level.read().await.is_some() {
                tracing::debug!("Battery recovered above threshold, resetting alert state");
                self.reset_alert_state().await;
            }
            return Ok(None);
        };

        let now = chrono::Utc::now().timestamp_millis();
        if let Some(last_time) = *self.last_alert_time.read().await {
            let cooldown_ms = self.config.alert_cooldown_seconds as i64 * 1000;
            if now - last_time < cooldown_ms {
                // The cooldown holds, with one exception: a Low -> Critical
                // escalation goes out immediately. Having told the circle about
                // 10% is no reason to stay quiet about 5%.
                let last_level = *self.last_alert_level.read().await;
                if !(last_level == Some(BatteryAlertLevel::Low)
                    && alert_level == BatteryAlertLevel::Critical) {
                    tracing::debug!(
                        "Battery alert in cooldown ({} seconds remaining)",
                        (cooldown_ms - (now - last_time)) / 1000
                    );
                    return Ok(None);
                }
                tracing::info!("Escalating from Low to Critical battery alert");
            }
        }

        let circle_ids: Vec<String> = self.circle_ids.read().await.iter().cloned().collect();
        if circle_ids.is_empty() {
            tracing::warn!("No circles configured for battery alerts");
            return Ok(None);
        }

        let alert = BatteryAlert {
            battery_level: level,
            level: alert_level,
            triggered_at: now,
            circle_ids,
        };

        *self.last_alert_time.write().await = Some(now);
        *self.last_alert_level.write().await = Some(alert_level);

        tracing::info!(
            "Triggering {:?} battery alert at {}%",
            alert_level,
            level
        );

        if let Some(callback) = &*self.callback.read().await {
            callback.send_low_battery_alert(alert.clone());
        }

        Ok(Some(alert))
    }
}

impl Default for BatteryMonitor {
    fn default() -> Self {
        Self {
            config: BatteryMonitorConfig::default(),
            current_level: Arc::new(RwLock::new(None)),
            is_charging: Arc::new(RwLock::new(false)),
            last_alert_time: Arc::new(RwLock::new(None)),
            last_alert_level: Arc::new(RwLock::new(None)),
            circle_ids: Arc::new(RwLock::new(HashSet::new())),
            callback: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestCallback {
        alert_count: AtomicU32,
        last_level: std::sync::RwLock<Option<u8>>,
    }

    impl TestCallback {
        fn new() -> Self {
            Self {
                alert_count: AtomicU32::new(0),
                last_level: std::sync::RwLock::new(None),
            }
        }

        fn get_alert_count(&self) -> u32 {
            self.alert_count.load(Ordering::SeqCst)
        }
    }

    impl BatteryAlertCallback for TestCallback {
        fn send_low_battery_alert(&self, alert: BatteryAlert) {
            self.alert_count.fetch_add(1, Ordering::SeqCst);
            *self.last_level.write().unwrap() = Some(alert.battery_level);
        }

        fn on_battery_level_changed(&self, level: u8, _is_charging: bool) {
            *self.last_level.write().unwrap() = Some(level);
        }
    }

    #[tokio::test]
    async fn test_battery_monitor_no_alert_above_threshold() {
        let monitor = BatteryMonitor::new();
        monitor.add_circle("circle1".to_string()).await;

        // 50% battery should not trigger alert
        let result = monitor.update_battery_level(50, false).await.unwrap();
        assert!(result.is_none());

        // 15% battery should not trigger alert (threshold is 10)
        let result = monitor.update_battery_level(15, false).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_battery_monitor_triggers_low_alert() {
        let monitor = BatteryMonitor::new();
        monitor.add_circle("circle1".to_string()).await;

        // 10% battery should trigger low alert
        let result = monitor.update_battery_level(10, false).await.unwrap();
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.battery_level, 10);
        assert_eq!(alert.level, BatteryAlertLevel::Low);
        assert_eq!(alert.circle_ids, vec!["circle1".to_string()]);
    }

    #[tokio::test]
    async fn test_battery_monitor_triggers_critical_alert() {
        let monitor = BatteryMonitor::new();
        monitor.add_circle("circle1".to_string()).await;

        // 5% battery should trigger critical alert
        let result = monitor.update_battery_level(5, false).await.unwrap();
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.battery_level, 5);
        assert_eq!(alert.level, BatteryAlertLevel::Critical);
    }

    #[tokio::test]
    async fn test_battery_monitor_skips_when_charging() {
        let config = BatteryMonitorConfig {
            skip_when_charging: true,
            ..Default::default()
        };
        let monitor = BatteryMonitor::with_config(config);
        monitor.add_circle("circle1".to_string()).await;

        // Low battery while charging should NOT trigger alert
        let result = monitor.update_battery_level(5, true).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_battery_monitor_respects_cooldown() {
        let config = BatteryMonitorConfig {
            alert_cooldown_seconds: 3600, // 1 hour
            ..Default::default()
        };
        let monitor = BatteryMonitor::with_config(config);
        monitor.add_circle("circle1".to_string()).await;

        // First alert should trigger
        let result = monitor.update_battery_level(8, false).await.unwrap();
        assert!(result.is_some());

        // Second alert should be blocked by cooldown
        let result = monitor.update_battery_level(7, false).await.unwrap();
        assert!(result.is_none());

        // Should be in cooldown
        assert!(monitor.is_in_cooldown().await);
    }

    #[tokio::test]
    async fn test_battery_monitor_escalates_to_critical() {
        let config = BatteryMonitorConfig {
            alert_cooldown_seconds: 3600,
            low_battery_threshold: 10,
            critical_battery_threshold: 5,
            ..Default::default()
        };
        let monitor = BatteryMonitor::with_config(config);
        monitor.add_circle("circle1".to_string()).await;

        // First alert at 10% (Low)
        let result = monitor.update_battery_level(10, false).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().level, BatteryAlertLevel::Low);

        // Escalation to Critical should bypass cooldown
        let result = monitor.update_battery_level(5, false).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().level, BatteryAlertLevel::Critical);
    }

    #[tokio::test]
    async fn test_battery_monitor_no_circles_no_alert() {
        let monitor = BatteryMonitor::new();
        // No circles added

        // Low battery but no circles to notify
        let result = monitor.update_battery_level(5, false).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_battery_monitor_reset_after_recovery() {
        let config = BatteryMonitorConfig {
            alert_cooldown_seconds: 3600,
            ..Default::default()
        };
        let monitor = BatteryMonitor::with_config(config);
        monitor.add_circle("circle1".to_string()).await;

        // Trigger alert
        let result = monitor.update_battery_level(8, false).await.unwrap();
        assert!(result.is_some());
        assert!(monitor.is_in_cooldown().await);

        // Recover above threshold
        let result = monitor.update_battery_level(50, false).await.unwrap();
        assert!(result.is_none());

        // Cooldown should be reset
        assert!(!monitor.is_in_cooldown().await);

        // New alert should trigger
        let result = monitor.update_battery_level(8, false).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_battery_monitor_callback() {
        let monitor = BatteryMonitor::new();
        let callback = Arc::new(TestCallback::new());
        let callback_clone = callback.clone();
        monitor.set_callback(Box::new(TestCallbackWrapper(callback_clone))).await;
        monitor.add_circle("circle1".to_string()).await;

        // Trigger alert
        let _ = monitor.update_battery_level(5, false).await.unwrap();

        assert_eq!(callback.get_alert_count(), 1);
    }

    /// Wrapper to make Arc<TestCallback> implement BatteryAlertCallback
    struct TestCallbackWrapper(Arc<TestCallback>);

    impl BatteryAlertCallback for TestCallbackWrapper {
        fn send_low_battery_alert(&self, alert: BatteryAlert) {
            self.0.send_low_battery_alert(alert);
        }

        fn on_battery_level_changed(&self, level: u8, is_charging: bool) {
            self.0.on_battery_level_changed(level, is_charging);
        }
    }

    #[tokio::test]
    async fn test_battery_level_clamped() {
        let monitor = BatteryMonitor::new();

        // Values over 100 should be clamped
        let _ = monitor.update_battery_level(150, false).await.unwrap();
        assert_eq!(monitor.get_battery_level().await, Some(100));
    }

    #[tokio::test]
    async fn test_custom_threshold() {
        let config = BatteryMonitorConfig::with_threshold(20);
        let monitor = BatteryMonitor::with_config(config);
        monitor.add_circle("circle1".to_string()).await;

        // 15% should trigger with 20% threshold
        let result = monitor.update_battery_level(15, false).await.unwrap();
        assert!(result.is_some());

        assert_eq!(monitor.get_threshold(), 20);
    }
}
