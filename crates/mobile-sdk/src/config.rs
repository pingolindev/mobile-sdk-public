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

//! SDK Configuration
//!
//! Provides environment-aware configuration for connecting to Pingolin services.

/// Default endpoints for different environments
pub mod defaults {
    pub mod prod {
        pub const AUTH_ENDPOINT: &str = "https://api-auth.pingolin.com";
        pub const INGEST_ENDPOINT: &str = "https://ingest-track.pingolin.com";
        pub const API_ENDPOINT: &str = "https://api-track.pingolin.com";
    }

    pub mod dev {
        pub const AUTH_ENDPOINT: &str = "https://auth.pingolindev.com";
        pub const INGEST_ENDPOINT: &str = "https://ingest-track.pingolindev.com";
        pub const API_ENDPOINT: &str = "https://api-track.pingolindev.com";
    }

    /// Loopback endpoints for a locally running stack.
    pub mod local {
        pub const AUTH_ENDPOINT: &str = "http://localhost:8081";
        pub const INGEST_ENDPOINT: &str = "http://localhost:50051";
        pub const API_ENDPOINT: &str = "http://localhost:8080";
    }
}

/// Environment selection for SDK configuration
#[derive(Debug, Clone, Copy, Default, uniffi::Enum)]
pub enum Environment {
    #[default]
    Production,
    Development,
    Local,
    /// Endpoints supplied by the caller via `SdkConfig::custom()`.
    Custom,
}

/// SDK Configuration for connecting to Pingolin services
#[derive(Debug, Clone, uniffi::Record)]
pub struct SdkConfig {
    /// Authentication service endpoint.
    pub auth_endpoint: String,
    /// Location ingest endpoint. gRPC, not REST — see `LocationManager`.
    pub ingest_endpoint: String,
    /// REST endpoint for everything that is not location ingest.
    pub api_endpoint: String,
    pub environment: Environment,
}

impl SdkConfig {
    pub fn production() -> Self {
        Self {
            auth_endpoint: defaults::prod::AUTH_ENDPOINT.to_string(),
            ingest_endpoint: defaults::prod::INGEST_ENDPOINT.to_string(),
            api_endpoint: defaults::prod::API_ENDPOINT.to_string(),
            environment: Environment::Production,
        }
    }

    pub fn development() -> Self {
        Self {
            auth_endpoint: defaults::dev::AUTH_ENDPOINT.to_string(),
            ingest_endpoint: defaults::dev::INGEST_ENDPOINT.to_string(),
            api_endpoint: defaults::dev::API_ENDPOINT.to_string(),
            environment: Environment::Development,
        }
    }

    pub fn local() -> Self {
        Self {
            auth_endpoint: defaults::local::AUTH_ENDPOINT.to_string(),
            ingest_endpoint: defaults::local::INGEST_ENDPOINT.to_string(),
            api_endpoint: defaults::local::API_ENDPOINT.to_string(),
            environment: Environment::Local,
        }
    }

    pub fn custom(auth_endpoint: String, ingest_endpoint: String, api_endpoint: String) -> Self {
        Self {
            auth_endpoint,
            ingest_endpoint,
            api_endpoint,
            environment: Environment::Custom,
        }
    }
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config() {
        let config = SdkConfig::production();

        assert_eq!(config.auth_endpoint, "https://api-auth.pingolin.com");
        assert_eq!(config.ingest_endpoint, "https://ingest-track.pingolin.com");
        assert_eq!(config.api_endpoint, "https://api-track.pingolin.com");
        assert!(matches!(config.environment, Environment::Production));
    }

    #[test]
    fn test_development_config() {
        let config = SdkConfig::development();

        assert_eq!(config.auth_endpoint, "https://auth.pingolindev.com");
        assert_eq!(config.ingest_endpoint, "https://ingest-track.pingolindev.com");
        assert_eq!(config.api_endpoint, "https://api-track.pingolindev.com");
        assert!(matches!(config.environment, Environment::Development));
    }

    #[test]
    fn test_local_config() {
        let config = SdkConfig::local();

        assert_eq!(config.auth_endpoint, "http://localhost:8081");
        assert_eq!(config.ingest_endpoint, "http://localhost:50051");
        assert_eq!(config.api_endpoint, "http://localhost:8080");
        assert!(matches!(config.environment, Environment::Local));
    }

    #[test]
    fn test_custom_config() {
        let config = SdkConfig::custom(
            "https://custom-auth.example.com".to_string(),
            "https://custom-ingest.example.com".to_string(),
            "https://custom-api.example.com".to_string(),
        );

        assert_eq!(config.auth_endpoint, "https://custom-auth.example.com");
        assert_eq!(config.ingest_endpoint, "https://custom-ingest.example.com");
        assert_eq!(config.api_endpoint, "https://custom-api.example.com");
        assert!(matches!(config.environment, Environment::Custom));
    }

    #[test]
    fn test_default_is_production() {
        let default_config = SdkConfig::default();
        let prod_config = SdkConfig::production();

        assert_eq!(default_config.auth_endpoint, prod_config.auth_endpoint);
        assert_eq!(default_config.ingest_endpoint, prod_config.ingest_endpoint);
        assert_eq!(default_config.api_endpoint, prod_config.api_endpoint);
    }

    #[test]
    fn test_environment_default_is_production() {
        let env = Environment::default();
        assert!(matches!(env, Environment::Production));
    }

    #[test]
    fn test_config_clone() {
        let config = SdkConfig::production();
        let cloned = config.clone();

        assert_eq!(config.auth_endpoint, cloned.auth_endpoint);
        assert_eq!(config.ingest_endpoint, cloned.ingest_endpoint);
        assert_eq!(config.api_endpoint, cloned.api_endpoint);
    }

    #[test]
    fn test_all_prod_endpoints_use_https() {
        let config = SdkConfig::production();

        assert!(config.auth_endpoint.starts_with("https://"));
        assert!(config.ingest_endpoint.starts_with("https://"));
        assert!(config.api_endpoint.starts_with("https://"));
    }

    #[test]
    fn test_local_endpoints_use_http() {
        let config = SdkConfig::local();

        assert!(config.auth_endpoint.starts_with("http://localhost"));
        assert!(config.ingest_endpoint.starts_with("http://localhost"));
        assert!(config.api_endpoint.starts_with("http://localhost"));
    }
}
