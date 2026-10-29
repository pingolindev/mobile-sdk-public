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

mod backup_container;
mod background_monitor;
mod battery_monitor;
mod boundary;
mod boundary_monitor;
mod config;
mod crypto;
mod geocode_tokens;
mod geocoding;
mod import_providers;
mod inactivity_monitor;
mod location;
mod location_codec;
mod location_retry;
mod manager;
mod membership;
mod privacy;
mod refresh;
mod refresh_record;
mod srp;
mod storage;
mod types;

pub use background_monitor::{BackgroundMonitorPlatform, BackgroundMonitorService, QueuedLocation};
pub use battery_monitor::{
    BatteryAlert, BatteryAlertCallback, BatteryAlertLevel, BatteryMonitor, BatteryMonitorConfig,
};
pub use boundary::{Boundary, BoundaryCallback, BoundaryChecker, BoundaryCrossing, BoundaryCrossingType};
pub use boundary_monitor::{BoundaryMonitor, BoundaryMonitorCallback, EncryptedMemberLocation, EncryptedPlace};
pub use config::{Environment, SdkConfig};
pub use crypto::{CryptoManager, SealedPreviousIdentity};
pub use geocode_tokens::{
    geocode_blind_tokens, geocode_finalize_tokens, GeocodeBlindResult, GeocodeToken,
};
pub use geocoding::{GeocodingDownloader, GeocodingResult};
pub use import_providers::{
    provider_specs, AuthMethod, CredentialField, ImportSection, OAuthConfig, ProviderSpec,
};
pub use inactivity_monitor::{
    InactivityAlert, InactivityAlertCallback, InactivityMonitor, InactivityMonitorConfig,
    UserActivityStatus,
};
pub use location::{BackgroundLocationService, LocationCallback, LocationManager, StreamErrorCallback};
pub use manager::{CircleManager, SessionManager};
pub use membership::{
    MembershipStatement, MembershipStatementKind, InvitationRenewalFacts, OwnStatementSigner, SignedMembershipStatement,
    INVITATION_LIFETIME_SECS, MEMBERSHIP_STATEMENT_DOMAIN,
};
pub use refresh::{
    CircleHead, CircleRole, EligibilityBasis, EligibilityPurpose, HeldStatement, MemberEligibility, MemberHead,
    PlannedEntry, RecordMember, RecordMemberState, RecordProblem, RecordVersionState, RecordVersionStatus,
    RecordedCircleCreation, RecordedRotationBundle, RefreshRecordKind, RefreshRecordsReport, SignedCircleHead,
    SignedRefreshRecord,
};
pub use privacy::{
    LocationBatch, LocationBatcher, BatchedLocation, LocationPayload, LocationData,
    PrivacyConfig, bucket_timestamp,
};
pub use srp::{
    srp_compute_login_proof, srp_generate_registration, srp_verify_server_proof, SrpLoginProof, SrpProofEncoding,
    SrpRegistrationData,
};
pub use storage::{SecureStorage, SecureStorageCallback};
pub use types::*;

// Bindings are generated from the proc macros above, not from a UDL file.
uniffi::setup_scaffolding!();

/// Call once at startup. A second call is a no-op: the global subscriber can
/// only be set once, and the failure is logged rather than propagated.
#[uniffi::export]
pub fn init_logging(level: LogLevel) {
    let log_level = match level {
        LogLevel::Trace => tracing::Level::TRACE,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Error => tracing::Level::ERROR,
    };

    // Android: forward tracing events to logcat.
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::layer::SubscriberExt;

        match tracing_android::layer("PingolinSDK") {
            Ok(android_layer) => {
                let subscriber = tracing_subscriber::registry()
                    .with(android_layer)
                    .with(tracing_subscriber::filter::LevelFilter::from_level(log_level));

                match tracing::subscriber::set_global_default(subscriber) {
                    Ok(()) => {
                        // Confirm via android_logger: the tracing layer may not
                        // be delivering to logcat yet at this point.
                        #[cfg(target_os = "android")]
                        android_logger::init_once(
                            android_logger::Config::default()
                                .with_max_level(log::LevelFilter::Debug)
                                .with_tag("PingolinSDK")
                        );
                        log::info!("PingolinSDK logging initialized at {:?} level", log_level);
                    }
                    Err(e) => {
                        // A subscriber is already installed; stderr is all we have.
                        eprintln!("PingolinSDK: Failed to set tracing subscriber: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("PingolinSDK: Failed to create Android tracing layer: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        match tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(false)
            .try_init()
        {
            Ok(()) => {
                tracing::info!("PingolinSDK logging initialized at {:?} level", log_level);
            }
            Err(e) => {
                eprintln!("PingolinSDK: Failed to init tracing: {}", e);
            }
        }
    }
}

/// The crate version, baked in at compile time.
#[uniffi::export]
pub fn get_sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Always the production configuration, whatever the build flavor. Callers
/// that need another environment must construct `SdkConfig` themselves.
#[uniffi::export]
pub fn get_default_config() -> SdkConfig {
    SdkConfig::production()
}
