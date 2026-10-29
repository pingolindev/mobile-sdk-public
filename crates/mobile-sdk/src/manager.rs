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

use crate::types::{Circle, MobileError};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory cache of circle metadata for the life of the process. Nothing
/// here is persisted or sent anywhere; it exists so platform code can hold
/// decrypted circle names without re-decrypting on every screen.
#[derive(uniffi::Object)]
pub struct CircleManager {
    circles: Arc<RwLock<HashMap<String, Circle>>>,
}

#[uniffi::export]
impl CircleManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            circles: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Inserts by `circle.id`, replacing any existing entry.
    pub fn add_circle(&self, circle: Circle) {
        tracing::debug!("Adding circle: {}", circle.id);
        self.circles
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(circle.id.clone(), circle);
    }

    pub fn remove_circle(&self, circle_id: String) {
        tracing::info!("Removing circle: {}", circle_id);
        self.circles
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&circle_id);
    }

    /// Unordered — `HashMap` iteration order, not insertion order.
    pub fn get_all_circles(&self) -> Vec<Circle> {
        self.circles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn get_circle(&self, circle_id: String) -> Result<Circle, MobileError> {
        self.circles
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&circle_id)
            .cloned()
            .ok_or_else(|| MobileError::KeyNotFound(format!("Circle not found: {}", circle_id)))
    }
}

impl Default for CircleManager {
    fn default() -> Self {
        Self {
            circles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Holds the JWT and user id in memory for the life of the process. Callers
/// are responsible for persisting the token themselves (platform secure
/// storage) — nothing here survives a restart.
#[derive(uniffi::Object)]
pub struct SessionManager {
    token: Arc<RwLock<Option<String>>>,
    user_id: Arc<RwLock<Option<String>>>,
}

#[uniffi::export]
impl SessionManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token: Arc::new(RwLock::new(None)),
            user_id: Arc::new(RwLock::new(None)),
        })
    }

    pub fn store_token(&self, token: String) {
        tracing::debug!("Storing JWT token");
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = Some(token);
    }

    pub fn get_token(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Logout. Leaves `user_id` in place — clear it separately if needed.
    pub fn clear_token(&self) {
        tracing::info!("Clearing JWT token (logout)");
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// True only for a stored, non-empty token. This is a local presence
    /// check: it says nothing about whether the token is still valid or
    /// unexpired server-side.
    pub fn is_authenticated(&self) -> bool {
        self.token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    }

    pub fn store_user_id(&self, user_id: String) {
        tracing::debug!("Storing user ID: {}", user_id);
        *self.user_id.write().unwrap_or_else(|e| e.into_inner()) = Some(user_id);
    }

    pub fn get_user_id(&self) -> Option<String> {
        self.user_id.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            token: Arc::new(RwLock::new(None)),
            user_id: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_circle(id: &str, name: &str) -> Circle {
        Circle {
            id: id.to_string(),
            name: name.to_string(),
            created_at: 1704067200000, // 2024-01-01 00:00:00 UTC
        }
    }

    // ========================================
    // CircleManager tests
    // ========================================

    #[test]
    fn test_circle_manager_new_is_empty() {
        let manager = CircleManager::new();
        assert!(manager.get_all_circles().is_empty());
    }

    #[test]
    fn test_circle_manager_add_circle() {
        let manager = CircleManager::new();
        let circle = make_test_circle("circle-1", "Family");

        manager.add_circle(circle);

        let circles = manager.get_all_circles();
        assert_eq!(circles.len(), 1);
        assert_eq!(circles[0].name, "Family");
    }

    #[test]
    fn test_circle_manager_add_multiple_circles() {
        let manager = CircleManager::new();
        manager.add_circle(make_test_circle("circle-1", "Family"));
        manager.add_circle(make_test_circle("circle-2", "Friends"));
        manager.add_circle(make_test_circle("circle-3", "Work"));

        let circles = manager.get_all_circles();
        assert_eq!(circles.len(), 3);
    }

    #[test]
    fn test_circle_manager_get_circle_success() {
        let manager = CircleManager::new();
        manager.add_circle(make_test_circle("circle-1", "Family"));

        let result = manager.get_circle("circle-1".to_string());
        assert!(result.is_ok());
        let circle = result.unwrap();
        assert_eq!(circle.id, "circle-1");
        assert_eq!(circle.name, "Family");
    }

    #[test]
    fn test_circle_manager_get_circle_not_found() {
        let manager = CircleManager::new();

        let result = manager.get_circle("nonexistent".to_string());
        assert!(matches!(result, Err(MobileError::KeyNotFound(_))));
    }

    #[test]
    fn test_circle_manager_remove_circle() {
        let manager = CircleManager::new();
        manager.add_circle(make_test_circle("circle-1", "Family"));
        manager.add_circle(make_test_circle("circle-2", "Friends"));

        manager.remove_circle("circle-1".to_string());

        assert_eq!(manager.get_all_circles().len(), 1);
        assert!(manager.get_circle("circle-1".to_string()).is_err());
        assert!(manager.get_circle("circle-2".to_string()).is_ok());
    }

    #[test]
    fn test_circle_manager_remove_nonexistent_circle() {
        let manager = CircleManager::new();
        manager.add_circle(make_test_circle("circle-1", "Family"));

        // Should not panic when removing nonexistent circle
        manager.remove_circle("nonexistent".to_string());

        assert_eq!(manager.get_all_circles().len(), 1);
    }

    #[test]
    fn test_circle_manager_overwrite_circle() {
        let manager = CircleManager::new();
        manager.add_circle(make_test_circle("circle-1", "Family"));
        manager.add_circle(make_test_circle("circle-1", "Updated Family"));

        let circles = manager.get_all_circles();
        assert_eq!(circles.len(), 1);
        assert_eq!(circles[0].name, "Updated Family");
    }

    #[test]
    fn test_circle_manager_default() {
        let manager = CircleManager::default();
        assert!(manager.get_all_circles().is_empty());
    }

    // ========================================
    // SessionManager tests
    // ========================================

    #[test]
    fn test_session_manager_new_no_token() {
        let manager = SessionManager::new();
        assert!(manager.get_token().is_none());
        assert!(!manager.is_authenticated());
    }

    #[test]
    fn test_session_manager_store_and_get_token() {
        let manager = SessionManager::new();
        manager.store_token("jwt_token_123".to_string());

        assert_eq!(manager.get_token(), Some("jwt_token_123".to_string()));
        assert!(manager.is_authenticated());
    }

    #[test]
    fn test_session_manager_clear_token() {
        let manager = SessionManager::new();
        manager.store_token("jwt_token_123".to_string());
        assert!(manager.is_authenticated());

        manager.clear_token();

        assert!(manager.get_token().is_none());
        assert!(!manager.is_authenticated());
    }

    #[test]
    fn test_session_manager_overwrite_token() {
        let manager = SessionManager::new();
        manager.store_token("first_token".to_string());
        manager.store_token("second_token".to_string());

        assert_eq!(manager.get_token(), Some("second_token".to_string()));
    }

    #[test]
    fn test_session_manager_store_and_get_user_id() {
        let manager = SessionManager::new();
        assert!(manager.get_user_id().is_none());

        manager.store_user_id("user_12345".to_string());

        assert_eq!(manager.get_user_id(), Some("user_12345".to_string()));
    }

    #[test]
    fn test_session_manager_user_id_independent_of_token() {
        let manager = SessionManager::new();
        manager.store_token("jwt_token".to_string());
        manager.store_user_id("user_123".to_string());

        // Clearing token should not affect user_id
        manager.clear_token();

        assert!(manager.get_token().is_none());
        assert_eq!(manager.get_user_id(), Some("user_123".to_string()));
    }

    #[test]
    fn test_session_manager_default() {
        let manager = SessionManager::default();
        assert!(manager.get_token().is_none());
        assert!(manager.get_user_id().is_none());
        assert!(!manager.is_authenticated());
    }

    #[test]
    fn test_session_manager_empty_token() {
        let manager = SessionManager::new();
        manager.store_token("".to_string());

        // Empty string is stored but is_authenticated should return false
        assert_eq!(manager.get_token(), Some("".to_string()));
        assert!(!manager.is_authenticated());
    }

    // ========================================
    // Thread safety tests
    // ========================================

    #[test]
    fn test_circle_manager_thread_safety() {
        use std::thread;

        let manager = CircleManager::new();
        let manager_clone = Arc::clone(&manager);

        let handle = thread::spawn(move || {
            manager_clone.add_circle(make_test_circle("thread-circle", "Thread Circle"));
        });

        handle.join().unwrap();

        let circles = manager.get_all_circles();
        assert_eq!(circles.len(), 1);
        assert_eq!(circles[0].id, "thread-circle");
    }

    #[test]
    fn test_session_manager_thread_safety() {
        use std::thread;

        let manager = SessionManager::new();
        let manager_clone = Arc::clone(&manager);

        let handle = thread::spawn(move || {
            manager_clone.store_token("thread_token".to_string());
        });

        handle.join().unwrap();

        assert_eq!(manager.get_token(), Some("thread_token".to_string()));
    }
}
