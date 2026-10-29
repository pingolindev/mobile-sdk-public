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

//! Secure Storage Abstraction
//!
//! Provides a platform-agnostic interface for secure credential storage.
//! Platform-specific implementations (Android KeyStore, iOS Keychain) are
//! provided via FFI callbacks.

use crate::types::{MobileError, StorageCallbackError};
use std::sync::{Arc, RwLock};

/// Key names this SDK uses in platform secure storage.
pub mod keys {
    pub const JWT_TOKEN: &str = "pingolin_jwt_token";
    pub const REFRESH_TOKEN: &str = "pingolin_refresh_token";
    pub const USER_ID: &str = "pingolin_user_id";
    pub const DEVICE_ID: &str = "pingolin_device_id";
    pub const PRIVATE_KEY: &str = "pingolin_private_key";
}

/// Platform-provided secure storage callback
///
/// Platform code (Android/iOS) must implement this interface to provide
/// secure storage backed by KeyStore/Keychain.
///
/// A failure THROWS, whatever the error (`StorageCallbackError.Failed` is the
/// declared one; any other arrives as it, never as a panic).
#[uniffi::export(callback_interface)]
pub trait SecureStorageCallback: Send + Sync {
    /// Store a value securely
    fn store(&self, key: String, value: String) -> Result<(), StorageCallbackError>;

    /// Retrieve a value; `Ok(None)` means the key is absent (not an error).
    fn retrieve(&self, key: String) -> Result<Option<String>, StorageCallbackError>;

    /// Delete a value from secure storage
    fn delete(&self, key: String) -> Result<(), StorageCallbackError>;

    /// Check if a key exists
    fn contains(&self, key: String) -> Result<bool, StorageCallbackError>;

    /// Clear all SDK-related data from secure storage
    fn clear_all(&self) -> Result<(), StorageCallbackError>;
}

/// Secure storage manager that delegates to platform-specific implementations.
///
/// SECURITY: No fallback storage is provided — every operation fails with
/// `StorageError` until platform code registers a `SecureStorageCallback`. That
/// is deliberate: credentials only ever live in the platform's protected store
/// (Android KeyStore-backed storage, iOS Keychain), never in an in-memory or
/// on-disk Rust-side substitute that would silently be less protected.
#[derive(uniffi::Object)]
pub struct SecureStorage {
    callback: Arc<RwLock<Option<Box<dyn SecureStorageCallback>>>>,
}

#[uniffi::export]
impl SecureStorage {
    /// Create a new secure storage manager.
    ///
    /// IMPORTANT: You must call `register_callback()` with a platform-specific
    /// implementation before using any storage operations.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            callback: Arc::new(RwLock::new(None)),
        })
    }

    /// Register the platform-specific secure storage implementation
    ///
    /// This should be called during app initialization with a platform-specific
    /// implementation (Android KeyStore wrapper or iOS Keychain wrapper).
    pub fn register_callback(&self, callback: Box<dyn SecureStorageCallback>) {
        tracing::info!("Registering secure storage callback");
        // SECURITY: tolerate a poisoned lock (recover the guard) rather than
        // panicking. A poisoned RwLock here would make EVERY storage op panic —
        // including logout() and clear_all_data(), the credential wipes — which
        // is the wrong failure direction for a security module. Matches the
        // pattern used across crypto/geocoding/location/privacy.
        *self.callback.write().unwrap_or_else(|e| e.into_inner()) = Some(callback);
    }

    /// Store JWT token securely
    pub fn store_token(&self, token: String) -> Result<(), MobileError> {
        self.store(keys::JWT_TOKEN.to_string(), token)
    }

    /// Retrieve JWT token
    pub fn get_token(&self) -> Result<Option<String>, MobileError> {
        self.retrieve(keys::JWT_TOKEN.to_string())
    }

    /// Store refresh token securely
    pub fn store_refresh_token(&self, token: String) -> Result<(), MobileError> {
        self.store(keys::REFRESH_TOKEN.to_string(), token)
    }

    /// Retrieve refresh token
    pub fn get_refresh_token(&self) -> Result<Option<String>, MobileError> {
        self.retrieve(keys::REFRESH_TOKEN.to_string())
    }

    /// Store user ID
    pub fn store_user_id(&self, user_id: String) -> Result<(), MobileError> {
        self.store(keys::USER_ID.to_string(), user_id)
    }

    /// Retrieve user ID
    pub fn get_user_id(&self) -> Result<Option<String>, MobileError> {
        self.retrieve(keys::USER_ID.to_string())
    }

    /// Store device ID
    pub fn store_device_id(&self, device_id: String) -> Result<(), MobileError> {
        self.store(keys::DEVICE_ID.to_string(), device_id)
    }

    /// Retrieve device ID
    pub fn get_device_id(&self) -> Result<Option<String>, MobileError> {
        self.retrieve(keys::DEVICE_ID.to_string())
    }

    /// Store private key securely
    pub fn store_private_key(&self, key: String) -> Result<(), MobileError> {
        self.store(keys::PRIVATE_KEY.to_string(), key)
    }

    /// Retrieve private key
    pub fn get_private_key(&self) -> Result<Option<String>, MobileError> {
        self.retrieve(keys::PRIVATE_KEY.to_string())
    }

    /// Whether a JWT is present in secure storage. It is NOT parsed or checked
    /// for expiry, and a storage error reads as "not authenticated" — treat this
    /// as a UI hint, never as an authorization decision.
    pub fn is_authenticated(&self) -> bool {
        self.get_token().ok().flatten().is_some()
    }

    /// Logout: deletes the JWT and refresh token only. The user ID, device ID
    /// and stored private key survive — use `clear_all_data` for a full wipe.
    ///
    /// Both deletes are ALWAYS attempted, and the first error is reported only
    /// after that. Short-circuiting on the JWT delete would leave the refresh
    /// token on the device after a "successful-looking" logout — a live
    /// credential that still mints new access tokens.
    pub fn logout(&self) -> Result<(), MobileError> {
        let jwt_result = self.delete(keys::JWT_TOKEN.to_string());
        let refresh_result = self.delete(keys::REFRESH_TOKEN.to_string());
        jwt_result?;
        refresh_result?;
        Ok(())
    }

    /// Full wipe of the SDK's data in the platform store, including the stored
    /// private key — a much stronger reset than `logout`.
    pub fn clear_all_data(&self) -> Result<(), MobileError> {
        let callback = self.callback.read().unwrap_or_else(|e| e.into_inner());
        let callback = callback.as_ref().ok_or_else(|| {
            MobileError::StorageError("Secure storage callback not registered. Call register_callback() first.".into())
        })?;
        Ok(callback.clear_all()?)
    }

    // Internal storage methods - all require callback to be registered
    fn store(&self, key: String, value: String) -> Result<(), MobileError> {
        let callback = self.callback.read().unwrap_or_else(|e| e.into_inner());
        let callback = callback.as_ref().ok_or_else(|| {
            MobileError::StorageError("Secure storage callback not registered. Call register_callback() first.".into())
        })?;
        Ok(callback.store(key, value)?)
    }

    fn retrieve(&self, key: String) -> Result<Option<String>, MobileError> {
        let callback = self.callback.read().unwrap_or_else(|e| e.into_inner());
        let callback = callback.as_ref().ok_or_else(|| {
            MobileError::StorageError("Secure storage callback not registered. Call register_callback() first.".into())
        })?;
        Ok(callback.retrieve(key)?)
    }

    fn delete(&self, key: String) -> Result<(), MobileError> {
        let callback = self.callback.read().unwrap_or_else(|e| e.into_inner());
        let callback = callback.as_ref().ok_or_else(|| {
            MobileError::StorageError("Secure storage callback not registered. Call register_callback() first.".into())
        })?;
        Ok(callback.delete(key)?)
    }
}

impl Default for SecureStorage {
    fn default() -> Self {
        Self {
            callback: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock implementation of SecureStorageCallback for testing
    struct MockStorage {
        data: Mutex<HashMap<String, String>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecureStorageCallback for MockStorage {
        fn store(&self, key: String, value: String) -> Result<(), StorageCallbackError> {
            self.data.lock().unwrap().insert(key, value);
            Ok(())
        }

        fn retrieve(&self, key: String) -> Result<Option<String>, StorageCallbackError> {
            Ok(self.data.lock().unwrap().get(&key).cloned())
        }

        fn delete(&self, key: String) -> Result<(), StorageCallbackError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }

        fn contains(&self, key: String) -> Result<bool, StorageCallbackError> {
            Ok(self.data.lock().unwrap().contains_key(&key))
        }

        fn clear_all(&self) -> Result<(), StorageCallbackError> {
            self.data.lock().unwrap().clear();
            Ok(())
        }
    }

    /// Records every delete and fails the one named by `fail_on`, so a test can
    /// prove which deletes were actually ATTEMPTED rather than only which
    /// succeeded.
    struct DeleteRecorder {
        attempted: Arc<Mutex<Vec<String>>>,
        fail_on: String,
    }

    impl SecureStorageCallback for DeleteRecorder {
        fn store(&self, _key: String, _value: String) -> Result<(), StorageCallbackError> {
            Ok(())
        }

        fn retrieve(&self, _key: String) -> Result<Option<String>, StorageCallbackError> {
            Ok(None)
        }

        fn delete(&self, key: String) -> Result<(), StorageCallbackError> {
            self.attempted.lock().unwrap().push(key.clone());
            if key == self.fail_on {
                return Err(StorageCallbackError::Failed);
            }
            Ok(())
        }

        fn contains(&self, _key: String) -> Result<bool, StorageCallbackError> {
            Ok(false)
        }

        fn clear_all(&self) -> Result<(), StorageCallbackError> {
            Ok(())
        }
    }

    /// A platform store that fails every call: each operation reports a
    /// storage error, and the check that returns a bare bool says "not
    /// authenticated". Nothing panics.
    #[test]
    fn a_failing_platform_store_is_a_storage_error_on_every_call() {
        struct Failing;
        impl SecureStorageCallback for Failing {
            fn store(&self, _: String, _: String) -> Result<(), StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
            fn retrieve(&self, _: String) -> Result<Option<String>, StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
            fn delete(&self, _: String) -> Result<(), StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
            fn contains(&self, _: String) -> Result<bool, StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
            fn clear_all(&self) -> Result<(), StorageCallbackError> {
                Err(StorageCallbackError::Failed)
            }
        }
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(Failing));
        let storage_error = |r: Result<(), MobileError>| matches!(r, Err(MobileError::StorageError(_)));
        assert!(storage_error(storage.store_token("t".into())));
        assert!(matches!(storage.get_token(), Err(MobileError::StorageError(_))));
        assert!(storage_error(storage.logout()));
        assert!(storage_error(storage.clear_all_data()));
        assert!(!storage.is_authenticated());
    }

    /// If `logout` used `?` on the JWT delete, a keystore hiccup on the first
    /// key would return early and leave the REFRESH token on the device — a
    /// live credential that still mints new access tokens, behind a logout the
    /// user believes happened. Both deletes must be attempted regardless.
    #[test]
    fn logout_still_deletes_the_refresh_token_when_the_jwt_delete_fails() {
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(DeleteRecorder {
            attempted: Arc::clone(&attempted),
            fail_on: keys::JWT_TOKEN.to_string(),
        }));

        let result = storage.logout();

        assert!(result.is_err(), "the failed delete must still be reported");
        let attempted = attempted.lock().unwrap();
        assert!(
            attempted.iter().any(|k| k == keys::REFRESH_TOKEN),
            "refresh token delete was skipped: attempted {:?}",
            attempted
        );
    }

    /// The mirror case: a failure on the SECOND delete must not be swallowed
    /// just because the first one succeeded.
    #[test]
    fn logout_reports_a_failure_on_the_refresh_token_delete() {
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(DeleteRecorder {
            attempted: Arc::clone(&attempted),
            fail_on: keys::REFRESH_TOKEN.to_string(),
        }));

        assert!(storage.logout().is_err(), "a failed refresh delete must surface");
        assert_eq!(attempted.lock().unwrap().len(), 2, "both deletes must be attempted");
    }

    #[test]
    fn test_storage_requires_callback() {
        let storage = SecureStorage::new();

        // Should fail without callback registered
        let result = storage.store_token("test".to_string());
        assert!(matches!(result, Err(MobileError::StorageError(_))));
    }

    #[test]
    fn test_store_and_retrieve_token() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_token("my_jwt_token".to_string()).unwrap();

        let token = storage.get_token().unwrap();
        assert_eq!(token, Some("my_jwt_token".to_string()));
    }

    #[test]
    fn test_store_and_retrieve_refresh_token() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_refresh_token("my_refresh_token".to_string()).unwrap();

        let token = storage.get_refresh_token().unwrap();
        assert_eq!(token, Some("my_refresh_token".to_string()));
    }

    #[test]
    fn test_store_and_retrieve_user_id() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_user_id("user_123".to_string()).unwrap();

        let user_id = storage.get_user_id().unwrap();
        assert_eq!(user_id, Some("user_123".to_string()));
    }

    #[test]
    fn test_store_and_retrieve_device_id() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_device_id("device_456".to_string()).unwrap();

        let device_id = storage.get_device_id().unwrap();
        assert_eq!(device_id, Some("device_456".to_string()));
    }

    #[test]
    fn test_store_and_retrieve_private_key() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_private_key("secret_key".to_string()).unwrap();

        let key = storage.get_private_key().unwrap();
        assert_eq!(key, Some("secret_key".to_string()));
    }

    #[test]
    fn test_is_authenticated() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        assert!(!storage.is_authenticated());

        storage.store_token("token".to_string()).unwrap();
        assert!(storage.is_authenticated());
    }

    #[test]
    fn test_logout() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_token("jwt".to_string()).unwrap();
        storage.store_refresh_token("refresh".to_string()).unwrap();

        assert!(storage.is_authenticated());

        storage.logout().unwrap();

        assert!(!storage.is_authenticated());
        assert!(storage.get_token().unwrap().is_none());
        assert!(storage.get_refresh_token().unwrap().is_none());
    }

    #[test]
    fn test_clear_all_data() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_token("jwt".to_string()).unwrap();
        storage.store_user_id("user".to_string()).unwrap();
        storage.store_device_id("device".to_string()).unwrap();

        storage.clear_all_data().unwrap();

        assert!(storage.get_token().unwrap().is_none());
        assert!(storage.get_user_id().unwrap().is_none());
        assert!(storage.get_device_id().unwrap().is_none());
    }

    #[test]
    fn test_retrieve_nonexistent_key() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        let result = storage.get_token().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_overwrite_value() {
        let storage = SecureStorage::new();
        storage.register_callback(Box::new(MockStorage::new()));

        storage.store_token("first_token".to_string()).unwrap();
        storage.store_token("second_token".to_string()).unwrap();

        let token = storage.get_token().unwrap();
        assert_eq!(token, Some("second_token".to_string()));
    }

    #[test]
    fn test_storage_keys() {
        assert_eq!(keys::JWT_TOKEN, "pingolin_jwt_token");
        assert_eq!(keys::REFRESH_TOKEN, "pingolin_refresh_token");
        assert_eq!(keys::USER_ID, "pingolin_user_id");
        assert_eq!(keys::DEVICE_ID, "pingolin_device_id");
        assert_eq!(keys::PRIVATE_KEY, "pingolin_private_key");
    }
}
