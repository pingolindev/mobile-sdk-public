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

use crate::config::SdkConfig;
use crate::crypto::CryptoManager;
use crate::location_retry::{
    action_for_ack, retry_wakeup, Abandoned, AckAction, DropReason, RetryItem, RetryQueue,
    TransportBackoff, MAX_RETRY_ATTEMPTS,
};
use crate::privacy::PrivacyConfig;
use crate::types::{EncryptedData, EncryptedLocation, Location, MobileError, PseudonymPair};
use std::error::Error;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc;
use track_proto::track::{
    location_ingest_client::LocationIngestClient,
    EncryptedBlob, LocationUpdate,
};

/// Global shared Tokio runtime for all async operations.
/// This prevents creating a new runtime per stream/request which would exhaust OS threads.
static SHARED_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Default capacity for the per-stream location update channel when the
/// caller does not pass one explicitly. 64 absorbs short bursts (a few seconds
/// of high-frequency GPS) while keeping memory bounded.
const DEFAULT_LOCATION_QUEUE_CAPACITY: usize = 64;

/// Worker threads for the shared runtime: two, whatever the device.
///
/// It drives ONE upload task — every circle's location goes out as a unary
/// RPC over a single gRPC channel — plus the geocoder's HTTP connections.
/// Nothing on it is CPU-bound, and each extra worker is one more thread parked
/// on a phone for the life of the process. Two, not one, so a slow geocoding
/// download can never stall the upload task behind it.
const SHARED_RUNTIME_WORKERS: usize = 2;

/// The one runtime the SDK runs async work on: the upload loop and every
/// geocoding download. Sharing it is what lets the geocoder's HTTP client
/// keep its connection pool between calls — a pooled connection belongs to
/// the runtime that opened it.
pub(crate) fn get_shared_runtime() -> &'static tokio::runtime::Runtime {
    SHARED_RUNTIME.get_or_init(|| {
        let workers = SHARED_RUNTIME_WORKERS;
        tracing::debug!("Initializing shared SDK runtime with {} worker threads", workers);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .thread_name("track-sdk-worker")
            .build()
            .expect("Failed to create shared Tokio runtime")
    })
}

/// How often the shutdown wait re-checks whether the runtime has drained.
/// Clamped to the remaining time so the poll never overshoots the deadline.
const SHUTDOWN_POLL_INTERVAL_MS: u64 = 10;

/// Block until the runtime behind `handle` has no spawned tasks left, or until
/// `timeout` elapses. `true` means it actually drained.
///
/// Split out of `shutdown_location_runtime` so the wait is testable: the shared
/// runtime is a process-global `OnceLock` that a test can neither replace nor
/// tear down.
///
/// MUST be called from a thread with no runtime context — `Handle::block_on`
/// panics inside one.
fn wait_for_runtime_drain(
    handle: &tokio::runtime::Handle,
    timeout: std::time::Duration,
) -> bool {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + timeout;
    let metrics_handle = handle.clone();
    handle.block_on(async move {
        loop {
            // `block_on`'s own future is not a spawned task and so is not
            // counted here: zero really does mean every upload task has exited.
            if metrics_handle.metrics().num_alive_tasks() == 0 {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::time::sleep(
                (deadline - now).min(Duration::from_millis(SHUTDOWN_POLL_INTERVAL_MS)),
            )
            .await;
        }
    })
}

/// Shut the shared Tokio runtime down gracefully, waiting up to `timeout_ms`
/// for pending async work (location uploads, gRPC calls) to drain. Call this
/// when the application is terminating.
///
/// Returns `true` when the drain finished; `false` means the wait was cut
/// short and some operations may have been cancelled mid-flight. A `false`
/// here typically means `stop_streaming` was never called, so the upload task
/// is still parked on its channel and will never exit on its own.
#[uniffi::export]
pub fn shutdown_location_runtime(timeout_ms: u64) -> bool {
    use std::time::Duration;

    if let Some(rt) = SHARED_RUNTIME.get() {
        tracing::info!("Shutting down location SDK runtime (timeout: {}ms)", timeout_ms);

        let start = std::time::Instant::now();

        // A `static` runtime can't be consumed, so `Runtime::shutdown_timeout`
        // (which takes `self` by value) is unavailable. Instead a scratch
        // thread — one with no runtime context, as `block_on` requires — polls
        // the alive-task count until the work finishes or the deadline passes.
        let handle = rt.handle().clone();
        let drained = std::thread::spawn(move || {
            wait_for_runtime_drain(&handle, Duration::from_millis(timeout_ms))
        }).join().unwrap_or(false);

        let elapsed = start.elapsed();
        tracing::info!(
            "Location SDK runtime shutdown finished in {:?} (drained: {})",
            elapsed,
            drained
        );

        drained
    } else {
        // Runtime was never created, nothing to shutdown
        true
    }
}

const MS_PER_DAY: i64 = 86_400_000;

/// Days since the Unix epoch.
fn timestamp_to_day_bucket(timestamp_ms: i64) -> i32 {
    (timestamp_ms / MS_PER_DAY) as i32
}

/// Manages location upload to the ingest service over gRPC.
#[derive(uniffi::Object)]
pub struct LocationManager {
    config: SdkConfig,
    /// Shared with the running upload task, which re-reads it before every
    /// RPC — that is what lets `update_token` apply to a live stream.
    jwt_token: Arc<Mutex<String>>,
    user_id: String,
    is_streaming: Arc<Mutex<bool>>,
    // `None` until `start_streaming` opens the upload task's channel.
    tx: Arc<Mutex<Option<mpsc::Sender<LocationUpdateMessage>>>>,
    // Derives per-circle pseudonyms and seals the precise timestamp.
    crypto_manager: Option<Arc<CryptoManager>>,
    // Privacy config for timestamp bucketing. Retained on the manager; timestamp
    // bucketing currently happens in the crypto layer, so it isn't read here.
    #[allow(dead_code)]
    privacy_config: PrivacyConfig,
    // Callback for stream errors (e.g., device rejected by server)
    error_callback: Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>>,
    // Buffered capacity for the per-stream location update channel.
    // Configurable so callers with bursty location feeds (e.g. high-frequency
    // GPS, multi-device tracking) can avoid back-pressuring the producer.
    queue_capacity: usize,
}

/// Internal message for location updates (with privacy-preserving fields)
///
/// `run_streaming_loop` keeps one of these alive across its own RPC — that is
/// what makes a transient rejection retryable, since the bytes the server
/// refused are still in hand. `build_update` therefore takes it by REFERENCE;
/// moving it into the proto would lose the bytes a retry needs.
struct LocationUpdateMessage {
    device_id: String,  // Real device ID for server-side ownership validation
    circle_id: String,
    encrypted_location: EncryptedLocation,
    /// Which key sealed `encrypted_location` — the value the reader needs to
    /// route decryption. `CryptoManager::encrypt_location_with_session_key*`
    /// already returns it in wire format ("s:{uuid}" for a session key,
    /// "c:{version}" for the circle-key fallback); this carries it to the proto
    /// unchanged. `None` means "no key id" — envelope sends, which the reader
    /// routes on `wrapped_msg_key` instead — and goes out as an empty string.
    location_key_id: Option<String>,
    // Privacy-preserving pseudonyms (derived from circle key)
    user_pseudonym: Option<String>,
    device_pseudonym: Option<String>,
    // Day bucket for server-side range queries (days since Unix epoch)
    // Server uses this for efficient filtering; precise time is encrypted
    day_bucket: i32,
    // Encrypted precise timestamp - only circle members can decrypt
    encrypted_timestamp: Option<EncryptedData>,
    // Envelope encryption: wrapped msg_key for this target
    wrapped_msg_key: Option<Vec<u8>>,
    wrapped_msg_key_nonce: Option<Vec<u8>>,
    /// True when this update is a LIVENESS REFRESH: the device took a fix, has
    /// not moved far enough to be worth a history row, and is checking in so
    /// the product knows the phone is alive. The server keeps it as the latest
    /// location only, never in history. Set by `send_liveness_refresh` /
    /// `send_envelope_liveness_refresh`; false for every ordinary send.
    ///
    /// It changes nothing else about the message: same ciphertext, same
    /// encrypted timestamp, same pseudonyms, same day bucket, same retry
    /// treatment. A liveness refusal is retryable exactly like a location's.
    liveness_only: bool,
    /// True when this is a late HISTORY point: taken while the device could
    /// not open the circle, sent once it can. The server stores it in
    /// `locations` only (no latest location, no fan-out, no alerts). Set by
    /// `send_history_location` / `send_envelope_history_location`; never
    /// together with `liveness_only`. The retry queue keeps it up to 48 h and
    /// never counts it as superseded (location_retry.rs).
    history_only: bool,
}

impl RetryItem for LocationUpdateMessage {
    /// The emitter this update competes to be the latest location OF. Keyed on
    /// the pair rather than the device alone because the same fix is sent once
    /// per circle, and one circle's acceptance says nothing about another's.
    fn emitter(&self) -> (&str, &str) {
        (&self.circle_id, &self.device_id)
    }

    /// The fix's own wall-clock time, not the time of the send attempt. That
    /// distinction is the whole staleness rule: what matters is how old the
    /// POSITION is when it finally lands.
    fn fix_timestamp_ms(&self) -> i64 {
        self.encrypted_location.timestamp
    }

    fn history_only(&self) -> bool {
        self.history_only
    }
}

#[uniffi::export]
impl LocationManager {
    /// The `CryptoManager` is mandatory, not optional: without it there is no
    /// pseudonym derivation and no encrypted timestamp, so plaintext user and
    /// device ids would reach the server.
    ///
    /// Uses the default queue capacity (64); call `new_with_capacity` to
    /// override for bursty workloads.
    #[uniffi::constructor]
    pub fn new(
        config: SdkConfig,
        jwt_token: String,
        user_id: String,
        crypto_manager: Arc<CryptoManager>,
        privacy_config: PrivacyConfig,
    ) -> Arc<Self> {
        Self::new_with_capacity(
            config,
            jwt_token,
            user_id,
            crypto_manager,
            privacy_config,
            DEFAULT_LOCATION_QUEUE_CAPACITY as u32,
        )
    }

    /// `queue_capacity` is clamped to a minimum of 1 to keep the bounded
    /// channel valid; values >= 64 are recommended for bursty location feeds.
    #[uniffi::constructor]
    pub fn new_with_capacity(
        config: SdkConfig,
        jwt_token: String,
        user_id: String,
        crypto_manager: Arc<CryptoManager>,
        privacy_config: PrivacyConfig,
        queue_capacity: u32,
    ) -> Arc<Self> {
        tracing::info!(
            "Creating LocationManager with privacy support for {} environment",
            match config.environment {
                crate::config::Environment::Production => "production",
                crate::config::Environment::Development => "development",
                crate::config::Environment::Local => "local",
                crate::config::Environment::Custom => "custom",
            }
        );
        tracing::debug!("Privacy: timestamp_bucketing={}, bucket_size={}s",
            privacy_config.enable_timestamp_bucketing,
            privacy_config.timestamp_bucket_seconds
        );

        let queue_capacity = (queue_capacity as usize).max(1);
        Arc::new(Self {
            config,
            jwt_token: Arc::new(Mutex::new(jwt_token)),
            user_id,
            is_streaming: Arc::new(Mutex::new(false)),
            tx: Arc::new(Mutex::new(None)),
            crypto_manager: Some(crypto_manager),
            privacy_config,
            error_callback: Arc::new(Mutex::new(None)),
            queue_capacity,
        })
    }

    #[uniffi::constructor]
    pub fn production(
        jwt_token: String,
        user_id: String,
        crypto_manager: Arc<CryptoManager>,
        privacy_config: PrivacyConfig,
    ) -> Arc<Self> {
        Self::new(SdkConfig::production(), jwt_token, user_id, crypto_manager, privacy_config)
    }

    /// Swap in a refreshed JWT. The upload task re-reads the token before
    /// every RPC, so this takes effect on the NEXT queued location — no
    /// `stop_streaming` + `start_streaming` cycle is needed. Uploads already
    /// in flight keep the token they were issued with.
    pub fn update_token(&self, jwt_token: String) {
        *self.jwt_token.lock().unwrap_or_else(|e| e.into_inner()) = jwt_token;
        tracing::debug!("JWT token updated");
    }

    /// Open the gRPC channel and start the background task that drains queued
    /// updates. `send_location` only works once this has been called: each
    /// queued update goes out as its own unary RPC over the shared HTTP/2
    /// connection and is acked individually (see `run_streaming_loop`).
    pub fn start_streaming(&self, device_id: String) -> Result<(), MobileError> {
        let is_streaming = self.is_streaming.lock().unwrap_or_else(|e| e.into_inner());
        if *is_streaming {
            tracing::warn!("Already streaming, ignoring start request");
            return Ok(());
        }
        drop(is_streaming);

        tracing::info!(
            "Starting location streaming for device {} to {}",
            device_id,
            self.config.ingest_endpoint
        );

        let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(self.queue_capacity);

        *self.tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);

        *self.is_streaming.lock().unwrap_or_else(|e| e.into_inner()) = true;

        let endpoint = self.config.ingest_endpoint.clone();
        let token = Arc::clone(&self.jwt_token);
        let is_streaming = Arc::clone(&self.is_streaming);
        let error_callback = Arc::clone(&self.error_callback);

        // UniFFI calls arrive from Kotlin/Swift threads with no Tokio runtime
        // attached, so the async work has to be handed to one we own.
        let rt = get_shared_runtime();
        rt.spawn(async move {
            match run_streaming_loop(&endpoint, &token, &device_id, rx, error_callback).await {
                Ok(()) => {
                    tracing::info!("Streaming loop completed normally");
                }
                Err(e) => {
                    tracing::error!("Streaming loop error: {}", e);
                }
            }

            *is_streaming.lock().unwrap_or_else(|e| e.into_inner()) = false;
        });

        Ok(())
    }

    pub fn stop_streaming(&self) {
        tracing::info!("Stopping location streaming");

        // Dropping the sender closes the channel; that is what makes the
        // upload task fall out of its recv loop and exit.
        *self.tx.lock().unwrap_or_else(|e| e.into_inner()) = None;

        *self.is_streaming.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }

    /// Queue one location update for upload. Requires an active stream —
    /// there is no non-streaming path, so this errors if `start_streaming`
    /// has not been called.
    ///
    /// Before queueing it: derives the per-circle pseudonyms that stand in for
    /// user_id/device_id, and encrypts the precise timestamp so the server
    /// sees only `day_bucket` (coarse enough to hide the time of day, precise
    /// enough for server-side range queries).
    ///
    /// `location_key_id` MUST be the `key_id` returned alongside the ciphertext
    /// by whichever `CryptoManager::encrypt_location*` call produced
    /// `encrypted_location` — pass `SessionEncryptedData.key_id` verbatim, or
    /// `None` when the payload was sealed with a plain circle-key encrypt that
    /// returns no id.
    ///
    /// It is a REQUIRED parameter, deliberately, rather than something the SDK
    /// infers: only the caller knows which key it actually used. Asking
    /// `get_sender_session_key_id()` here would mislabel a payload whenever the
    /// caller had fallen back to a circle-key encrypt, which is worse than no
    /// id at all — the reader would route to session decryption and fail.
    ///
    /// Dropping this value makes session-key-encrypted locations permanently
    /// unreadable — the ciphertext ships fine while the id that selects its
    /// key never leaves the device. See `payload_blob`.
    pub fn send_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        location_key_id: Option<String>,
    ) -> Result<(), MobileError> {
        self.queue_location(device_id, circle_id, encrypted_location, location_key_id, false, false)
    }

    /// Queue a LIVENESS REFRESH: identical to `send_location` in every respect
    /// except that the server keeps it as the latest location only, never in the
    /// location history.
    ///
    /// Send this when the device took a fix at its normal cadence and found it
    /// has NOT moved far enough for the position to be worth keeping. The fix
    /// still travels — fully encrypted, with a fresh encrypted timestamp and
    /// today's day bucket — because "this phone is alive and could have sent a
    /// position" is exactly what the green dot and the inactivity alerts mean.
    /// A phone that stops calling either of these at all is inactive; a live
    /// phone that is simply not moving is not.
    ///
    /// The arguments are `send_location`'s, unchanged, so a caller switches
    /// between the two on its moved/not-moved decision alone. Every server-side
    /// check and side effect is the same, so a refusal is classified and retried
    /// the same way.
    ///
    /// Requires an active stream, like `send_location`.
    pub fn send_liveness_refresh(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        location_key_id: Option<String>,
    ) -> Result<(), MobileError> {
        self.queue_location(device_id, circle_id, encrypted_location, location_key_id, true, false)
    }

    /// Queue a late HISTORY point: identical to `send_location` except that the
    /// server stores it in the history table only: no latest location, no live
    /// fan-out, no alerts. For the points a device kept while it could not open
    /// a circle ("Waiting to sync"), sent once it holds the circle's current
    /// key. The server takes them up to 48 h after the fix; a transient
    /// refusal is retried for as long, and a newer live fix never replaces one.
    ///
    /// Encrypt each point with the key the device holds NOW, as for any send;
    /// the fix keeps its own timestamp. Requires an active stream.
    pub fn send_history_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        location_key_id: Option<String>,
    ) -> Result<(), MobileError> {
        self.queue_location(device_id, circle_id, encrypted_location, location_key_id, false, true)
    }

    /// Queue one target's share of an envelope-encrypted location: the same
    /// `encrypted_location` ciphertext goes to every target, accompanied by
    /// the msg_key wrapped (hex-encoded) for this target alone. Pass the nil
    /// UUID as `circle_id` for self-tracking. `device_id` is the real id, not
    /// a pseudonym — the server validates device ownership against it.
    pub fn send_envelope_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        wrapped_msg_key_hex: String,
        wrapped_msg_key_nonce_hex: String,
    ) -> Result<(), MobileError> {
        self.queue_envelope_location(
            device_id, circle_id, encrypted_location,
            wrapped_msg_key_hex, wrapped_msg_key_nonce_hex, false, false,
        )
    }

    /// The envelope form of `send_liveness_refresh`: same arguments as
    /// `send_envelope_location`, and the same "stored in `latest_locations`
    /// only" semantics.
    ///
    /// This exists because BOTH shipping apps take the envelope path for their
    /// real sends — track-android's `LocationHeartbeatWorker` calls
    /// `sendEnvelopeLocation`, and so does iOS's `SDKLocationStreamer` — so a
    /// liveness refresh that only existed on the plain path could not actually
    /// be sent by either of them. One call per target, exactly as with an
    /// ordinary envelope send.
    pub fn send_envelope_liveness_refresh(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        wrapped_msg_key_hex: String,
        wrapped_msg_key_nonce_hex: String,
    ) -> Result<(), MobileError> {
        self.queue_envelope_location(
            device_id, circle_id, encrypted_location,
            wrapped_msg_key_hex, wrapped_msg_key_nonce_hex, true, false,
        )
    }

    /// The envelope form of `send_history_location` (both apps send through
    /// the envelope path): same arguments as `send_envelope_location`, stored
    /// in history only.
    pub fn send_envelope_history_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        wrapped_msg_key_hex: String,
        wrapped_msg_key_nonce_hex: String,
    ) -> Result<(), MobileError> {
        self.queue_envelope_location(
            device_id, circle_id, encrypted_location,
            wrapped_msg_key_hex, wrapped_msg_key_nonce_hex, false, true,
        )
    }


    /// Derive the per-circle pseudonyms for this update (BLAKE3 keyed hash of
    /// circle_key + user/device ID). Deterministic, but never cached: they are
    /// derived from the key in use for every update.
    fn get_or_derive_pseudonyms(
        &self,
        crypto: &CryptoManager,
        circle_id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<PseudonymPair, MobileError> {
        // Derived fresh on every update, never cached. The key a pseudonym comes
        // from changes (a rotation, or a personal key adopted at the same
        // version), and a cached pseudonym would tag every later row with the old
        // key's, which for the personal key the server would then record as the
        // account's. So derive from the key in use for every update: two keyed
        // hashes.
        crypto.derive_pseudonyms(circle_id.to_string(), user_id.to_string(), device_id.to_string())
            .map_err(|e| {
                MobileError::CryptoError(format!(
                    "Failed to derive pseudonyms for circle {}: {}. Ensure circle key is stored.",
                    circle_id, e
                ))
            })
    }

    pub fn is_streaming(&self) -> bool {
        *self.is_streaming.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get_ingest_endpoint(&self) -> String {
        self.config.ingest_endpoint.clone()
    }

    /// The callback fires when the server rejects a location update (e.g. the
    /// device is not owned by this user) or the gRPC call fails fatally.
    /// Platform code implements `StreamErrorCallback` to react — typically by
    /// re-registering the device.
    pub fn set_error_callback(&self, callback: Box<dyn StreamErrorCallback>) {
        tracing::info!("Registering stream error callback");
        *self.error_callback.lock().unwrap_or_else(|e| e.into_inner()) = Some(callback);
    }

    pub fn clear_error_callback(&self) {
        tracing::debug!("Clearing stream error callback");
        *self.error_callback.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The shared send bodies. Deliberately OUTSIDE the `#[uniffi::export]`
/// block: uniffi exports every method of an exported impl, private ones
/// included, and these two are internal plumbing, not API the apps should see
/// (they would arrive on the phones as `queueLocation` / `queueEnvelopeLocation`
/// with a raw boolean, next to the four named entry points that exist to make
/// the choice readable).
impl LocationManager {
    /// The body the plain sends share. `liveness_only` and `history_only` are
    /// the ONLY differences between them: same encryption, same pseudonyms,
    /// same queueing, same errors. Kept as one function so a change to the
    /// send path cannot apply to one send and silently skip another.
    fn queue_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        location_key_id: Option<String>,
        liveness_only: bool,
        history_only: bool,
    ) -> Result<(), MobileError> {
        let timestamp_ms = encrypted_location.timestamp;

        let day_bucket = timestamp_to_day_bucket(timestamp_ms);

        tracing::debug!(
            "Queueing {} for circle {} at timestamp {} (day_bucket: {})",
            update_label(liveness_only, history_only),
            circle_id,
            timestamp_ms,
            day_bucket
        );

        let crypto = self.crypto_manager.as_ref().expect("CryptoManager is always set");

        let pseudonyms = self.get_or_derive_pseudonyms(crypto, &circle_id, &self.user_id.clone(), &device_id)?;
        let user_pseudonym = Some(pseudonyms.user_pseudonym);
        let device_pseudonym = Some(pseudonyms.device_pseudonym);
        tracing::debug!("Derived pseudonyms for privacy-preserving storage");

        let encrypted_timestamp = Some(crypto.encrypt_timestamp(circle_id.clone(), timestamp_ms)
            .map_err(|e| {
                MobileError::CryptoError(format!(
                    "Failed to encrypt timestamp for circle {}: {}. Ensure circle key is stored.",
                    circle_id, e
                ))
            })?);
        tracing::debug!("Encrypted timestamp for E2EE metadata privacy");

        if let Some(tx) = self.tx.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let msg = LocationUpdateMessage {
                device_id,
                circle_id,
                encrypted_location,
                location_key_id,
                user_pseudonym,
                device_pseudonym,
                day_bucket,
                encrypted_timestamp,
                wrapped_msg_key: None,
                wrapped_msg_key_nonce: None,
                liveness_only,
                history_only,
            };

            tx.try_send(msg).map_err(|e| {
                MobileError::NetworkError(format!("Failed to queue location: {}", e))
            })?;

            return Ok(());
        }

        // No active stream, and there is no HTTP fallback to take: the server
        // ingests locations over gRPC only. Callers must call
        // `start_streaming` first, so surface a clear error rather than
        // silently dropping the location.
        let _ = (user_pseudonym, device_pseudonym, day_bucket, encrypted_timestamp, device_id, location_key_id);
        Err(MobileError::NetworkError(
            "Location stream not started — call start_streaming(device_id) before send_location".to_string()
        ))
    }

    /// Shared body of the two envelope sends — see `queue_location` for why
    /// they are one function.
    fn queue_envelope_location(
        &self,
        device_id: String,
        circle_id: String,
        encrypted_location: EncryptedLocation,
        wrapped_msg_key_hex: String,
        wrapped_msg_key_nonce_hex: String,
        liveness_only: bool,
        history_only: bool,
    ) -> Result<(), MobileError> {
        let timestamp_ms = encrypted_location.timestamp;
        let day_bucket = timestamp_to_day_bucket(timestamp_ms);

        tracing::debug!(
            "Queueing envelope {} for circle {} at timestamp {} (day_bucket: {})",
            update_label(liveness_only, history_only),
            circle_id, timestamp_ms, day_bucket
        );

        let crypto = self.crypto_manager.as_ref().expect("CryptoManager is always set");

        let pseudonyms = self.get_or_derive_pseudonyms(crypto, &circle_id, &self.user_id.clone(), &device_id)?;
        let user_pseudonym = Some(pseudonyms.user_pseudonym);
        let device_pseudonym = Some(pseudonyms.device_pseudonym);

        let encrypted_timestamp = Some(crypto.encrypt_timestamp(circle_id.clone(), timestamp_ms)
            .map_err(|e| {
                MobileError::CryptoError(format!(
                    "Failed to encrypt timestamp for circle {}: {}. Ensure circle key is stored.",
                    circle_id, e
                ))
            })?);

        // The wrap crosses the FFI boundary as hex; the proto wants bytes.
        let wrapped_msg_key = Some(hex::decode(&wrapped_msg_key_hex)
            .map_err(|_| MobileError::CryptoError("Invalid wrapped_msg_key hex".to_string()))?);
        let wrapped_msg_key_nonce = Some(hex::decode(&wrapped_msg_key_nonce_hex)
            .map_err(|_| MobileError::CryptoError("Invalid wrapped_msg_key_nonce hex".to_string()))?);

        if let Some(tx) = self.tx.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let msg = LocationUpdateMessage {
                device_id,
                circle_id,
                encrypted_location,
                // Envelope sends carry no key id on purpose: the Android and
                // iOS readers route this shape on `wrapped_msg_key` being
                // present, not on key_id. The msg_key is per-message and
                // unwrapped from the circle key, so there is no key to name.
                location_key_id: None,
                user_pseudonym,
                device_pseudonym,
                day_bucket,
                encrypted_timestamp,
                wrapped_msg_key,
                wrapped_msg_key_nonce,
                liveness_only,
                history_only,
            };

            tx.try_send(msg).map_err(|e| {
                MobileError::NetworkError(format!("Failed to queue envelope location: {}", e))
            })?;

            return Ok(());
        }

        // gRPC-only, same as `send_location`: no stream, no send.
        Err(MobileError::NetworkError(
            "Location stream not started — call start_streaming(device_id) before send_envelope_location".to_string()
        ))
    }
}

/// What a queued update is, for the debug log.
fn update_label(liveness_only: bool, history_only: bool) -> &'static str {
    match (liveness_only, history_only) {
        (true, _) => "liveness refresh",
        (false, true) => "history point",
        (false, false) => "location update",
    }
}

/// Build the wire blob for the location payload.
///
/// Split out of `run_streaming_loop` purely so the key_id mapping is testable.
/// The failure it guards against is a one-line change no compiler check
/// catches, whose only symptom is locations nobody can decrypt — noticed, if
/// ever, long after the rows are written.
///
/// `key_id` is NOT ours to invent: it names the key that actually sealed this
/// ciphertext, and is what the reader branches on ("s:{uuid}" => session key,
/// anything else => circle key). Hardcoding it (to `String::new()`, say)
/// discards the id for every session-encrypted location — the row is stored
/// intact and no receiver can ever select its key again. Empty is correct
/// only for circle-key and envelope sends, which name no key.
fn payload_blob(location: &EncryptedData, location_key_id: Option<String>) -> EncryptedBlob {
    EncryptedBlob {
        nonce: hex::decode(&location.nonce).unwrap_or_default(),
        ciphertext: hex::decode(&location.ciphertext).unwrap_or_default(),
        key_id: location_key_id.unwrap_or_default(),
    }
}

/// Idle HTTP/2 keepalive for the ingest channel, in seconds.
///
/// The phone's HTTP/2 peer is Cloudflare's edge, not the ingest service
/// itself (the ingest hosts are proxied). The edge closes an IDLE connection
/// with a GOAWAY at about 400 s and never sends PINGs of its own, while one
/// client PING every 330 s holds a connection open across consecutive gaps.
/// So 330 s keeps the connection warm for the next send while costing at
/// most one radio wake per 5.5 idle minutes — against ten per 5 minutes at a
/// 30 s keepalive, on a still phone whose sends are 300 s apart and would
/// otherwise not need to wake the radio in between at all.
const INGEST_KEEPALIVE_INTERVAL_SECS: u64 = 330;

/// Build the ingest channel. `connect_lazy`, deliberately: nothing is dialled
/// until the first RPC, and a failed dial comes back as THAT RPC's
/// `Unavailable` — which the upload loop treats like any other transport
/// failure — instead of an error out of `connect()`, which would end the
/// upload task before it had sent anything, with no callback at all. tonic's
/// `Reconnect` stores a lazy channel's dial error and hands it to the next
/// call rather than failing the channel, so the next RPC dials again.
fn build_ingest_channel(endpoint: &str) -> Result<tonic::transport::Channel, MobileError> {
    use std::time::Duration;
    use tonic::transport::{Channel, ClientTlsConfig};

    let mut channel_builder = Channel::from_shared(endpoint.to_string())
        .map_err(|e| MobileError::NetworkError(format!("Invalid endpoint: {}", e)))?;

    if endpoint.starts_with("https://") {
        tracing::info!("Configuring TLS with webpki root certificates (Mozilla CA bundle)");
        let tls_config = ClientTlsConfig::new().with_webpki_roots();
        channel_builder = channel_builder
            .tls_config(tls_config)
            .map_err(|e| MobileError::NetworkError(format!("TLS config failed: {}", e)))?;
    }

    Ok(channel_builder
        .http2_keep_alive_interval(Duration::from_secs(INGEST_KEEPALIVE_INTERVAL_SECS))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true)
        // No `http2_adaptive_window`: its BDP probe sends a PING after
        // received DATA, which for 360-byte location acks measures nothing and
        // is one more frame on the radio per send.
        .connect_timeout(Duration::from_secs(30))
        // Per-RPC deadline. Keepalive above is the primary liveness guard, but a
        // wedged/half-open socket that the HTTP/2 PING doesn't trip can otherwise
        // leave `client.send_location().await` (below) hanging indefinitely. While
        // it hangs the task never exits, `is_streaming` stays true, the caller's
        // try_send keeps "succeeding", and the client-side staleness watchdog is
        // fooled into thinking sends are landing — the device goes silently dark.
        // A 30s ceiling turns that hang into a `Cancelled` status, which the loop
        // treats as a transport failure: the fix is held and the send retried.
        .timeout(Duration::from_secs(30))
        .connect_lazy())
}

/// How the upload loop treats a FAILED RPC — a gRPC status, as opposed to an
/// ack carrying `success: false`, which `location_retry::action_for_ack` owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcFailure {
    /// No verdict on the update itself: the connection could not be made or
    /// dropped mid-call, the call timed out, a proxy answered 502/503/504/429
    /// or truncated the stream, the ingest was overloaded or its rate limiter
    /// was unavailable. The same bytes can succeed later, and tonic re-dials on
    /// the next call, so the fix is held and the upload task carries on.
    Transport,
    /// A decision that re-sending cannot change: an expired or missing token
    /// (`Unauthenticated`), a forbidden request, a route that does not exist.
    /// The app has to act — refresh the token, re-register — so the loop
    /// reports it through `on_stream_error` and ends.
    Settled,
}

fn classify_rpc_failure(code: tonic::Code) -> RpcFailure {
    use tonic::Code;
    match code {
        Code::Unavailable
        | Code::Unknown
        | Code::Cancelled
        | Code::DeadlineExceeded
        | Code::Aborted
        | Code::Internal
        | Code::ResourceExhausted
        // A failed call carrying `Ok` is a malformed status, not a verdict.
        | Code::Ok => RpcFailure::Transport,
        // Unauthenticated, PermissionDenied, InvalidArgument, NotFound,
        // FailedPrecondition, Unimplemented, OutOfRange, AlreadyExists,
        // DataLoss — and any code a future tonic adds, which should not be
        // retried until someone has decided it is transient.
        _ => RpcFailure::Settled,
    }
}

/// Tell the app the upload stream is over, then account for every fix it was
/// still holding — the one in flight, the retry queue, and anything still
/// buffered in the channel — so none of them is dropped without a callback.
///
/// The order matters: `on_stream_error` first, so the app's recovery (token
/// refresh, re-registration, reconnect) starts before a burst of per-fix
/// reports arrives. Closing the channel makes the app's further `try_send`s
/// fail instead of queueing into a receiver that is about to disappear.
fn end_stream(
    error_callback: &Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>>,
    error: &str,
    in_flight: Option<LocationUpdateMessage>,
    retry_queue: &mut RetryQueue<LocationUpdateMessage>,
    rx: &mut mpsc::Receiver<LocationUpdateMessage>,
) {
    if let Some(cb) = error_callback.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        cb.on_stream_error(error.to_string());
    }

    rx.close();
    let mut stranded: Vec<Abandoned<LocationUpdateMessage>> = Vec::new();
    if let Some(msg) = in_flight {
        stranded.push(Abandoned {
            item: msg,
            reason: DropReason::StreamEnded,
            last_error: error.to_string(),
        });
    }
    stranded.extend(retry_queue.drain_all());
    while let Ok(msg) = rx.try_recv() {
        stranded.push(Abandoned {
            item: msg,
            reason: DropReason::StreamEnded,
            last_error: error.to_string(),
        });
    }
    if !stranded.is_empty() {
        tracing::warn!(
            "{} location(s) abandoned: the upload stream ended ({})",
            stranded.len(),
            error
        );
    }
    for abandoned in stranded {
        report_abandoned(error_callback, abandoned);
    }
}

/// Log a failed RPC with its full cause chain — for a failed dial the useful
/// part (DNS, refused, TLS) is several sources down.
fn log_status_chain(status: &tonic::Status) {
    let mut current: &dyn Error = status;
    let mut depth = 0;
    while let Some(source) = current.source() {
        depth += 1;
        tracing::debug!("  Caused by ({}): {:?}", depth, source);
        current = source;
    }
}

/// Internal loop that sends location updates as individual unary gRPC calls.
/// Each location update gets its own request/response cycle, which is
/// compatible with Cloudflare proxy (no streaming required).
/// The HTTP/2 connection is reused across calls for efficiency.
///
/// The task lives until `stop_streaming` closes the channel or an RPC fails
/// with a SETTLED status (see [`RpcFailure`]); every exit other than the
/// channel closing reports `on_stream_error` first. A TRANSPORT failure does
/// not end it: the fix is held and every send waits behind
/// [`TransportBackoff`] until one probe gets through.
async fn run_streaming_loop(
    endpoint: &str,
    token: &Arc<Mutex<String>>,
    _device_id: &str,
    mut rx: mpsc::Receiver<LocationUpdateMessage>,
    error_callback: Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>>,
) -> Result<(), MobileError> {
    use tonic::Request;

    tracing::info!("Opening gRPC channel to {} (connects on first send)", endpoint);

    // Fixes waiting for another attempt: ones the server refused for reasons
    // that had nothing to do with them, and ones held while the connection was
    // down. See `location_retry` for the classification, the bounds, and — the
    // part worth reading before changing any of this — why a fix has a shelf
    // life.
    let mut retry_queue: RetryQueue<LocationUpdateMessage> = RetryQueue::new();
    let mut transport = TransportBackoff::new();

    let channel = match build_ingest_channel(endpoint) {
        Ok(channel) => channel,
        Err(e) => {
            // Nothing can ever be sent on this stream. Say so, rather than
            // letting the task vanish while the app keeps queueing into it.
            let error = format!("Upload channel could not be set up: {}", e);
            tracing::error!("{}", error);
            end_stream(&error_callback, &error, None, &mut retry_queue, &mut rx);
            return Err(e);
        }
    };
    let mut client = LocationIngestClient::new(channel);

    loop {
        // Reap fixes that can no longer usefully be sent, so one that goes
        // stale (or gets superseded) while waiting is reported promptly rather
        // than at whatever moment its backoff happens to expire. Guarded
        // because the queue is empty on the overwhelmingly common path.
        if !retry_queue.is_empty() {
            // Wall clock for the shelf-life rules — they are compared against
            // the fix's own timestamp. The backoff uses a monotonic `Instant`
            // instead, so a clock step cannot strand a queued fix.
            let now_ms = chrono::Utc::now().timestamp_millis();
            for abandoned in retry_queue.purge(now_ms) {
                report_abandoned(&error_callback, abandoned);
            }
        }

        let (msg, attempts_so_far) = tokio::select! {
            // Not `biased`: a device that produces fixes faster than they are
            // sent would starve the retry arm forever under a fixed priority.
            incoming = rx.recv() => match incoming {
                Some(msg) => {
                    // While the connection is failing, a new fix waits behind
                    // the gate with everything else instead of dialling out on
                    // its own: on a phone every attempt is a radio wake, and a
                    // tunnel would otherwise cost one per fix.
                    if transport.is_blocked(std::time::Instant::now()) {
                        let outcome = retry_queue.hold_for_connection(
                            msg,
                            0,
                            transport.last_error(),
                            std::time::Instant::now(),
                            chrono::Utc::now().timestamp_millis(),
                            false,
                        );
                        for abandoned in outcome.abandoned {
                            report_abandoned(&error_callback, abandoned);
                        }
                        continue;
                    }
                    (msg, 0u32)
                }
                None => break,
            },
            // Held fixes wake the loop no earlier than the connection gate
            // opens; with nothing queued this never fires.
            _ = sleep_until_opt(retry_wakeup(retry_queue.next_due(), transport.blocked_until())) => {
                match retry_queue.take_due(std::time::Instant::now()) {
                    Some(due) => due,
                    // Woken by a deadline whose entry the purge above removed,
                    // or held back by the re-send spacing. Re-evaluate.
                    None => continue,
                }
            }
        };

        // Read the token per RPC rather than once at connect time: the stream
        // outlives the JWT, and `update_token` refreshes it in place. A value
        // captured here at connect would keep presenting the expired token
        // until something tore the stream down and rebuilt it.
        let auth_header = {
            let token = token.lock().unwrap_or_else(|e| e.into_inner());
            format!("Bearer {}", *token)
        };
        let auth_value: tonic::metadata::MetadataValue<_> = match auth_header.parse() {
            Ok(value) => value,
            Err(_) => {
                // No RPC can succeed with this token. Worded as an
                // Unauthenticated error because that is the recovery it needs
                // — both apps refresh the token on that word.
                let error = "gRPC error: Unauthenticated - the stored token is not a valid header value"
                    .to_string();
                end_stream(&error_callback, &error, Some(msg), &mut retry_queue, &mut rx);
                return Err(MobileError::InvalidInput("Invalid token format".to_string()));
            }
        };

        tracing::debug!(
            "Sending location update: device={}, circle={}, day_bucket={}, attempt={}",
            msg.device_id,
            msg.circle_id,
            msg.day_bucket,
            attempts_so_far + 1
        );

        // Built from a BORROW. The message has to survive its own RPC: a
        // rejection is only retryable if the bytes that were rejected are
        // still in hand.
        let mut request = Request::new(build_update(&msg));
        request.metadata_mut().insert("authorization", auth_value);

        match client.send_location(request).await {
            Ok(response) => {
                // Any answer — accepted or refused — proves the connection.
                transport.record_success();
                let ack = response.into_inner();
                match action_for_ack(ack.success, &ack.error) {
                    AckAction::Accepted => {
                        tracing::debug!("Location accepted: device={}", ack.device_id);
                        // Records this emitter's high-water mark, which is what
                        // lets an older queued fix be abandoned instead of
                        // landing late and walking the peer's marker backwards.
                        retry_queue.note_accepted(&msg);
                    }
                    AckAction::Retry { server_retry_after } => {
                        let attempts = attempts_so_far + 1;
                        let outcome = retry_queue.requeue(
                            msg,
                            attempts,
                            server_retry_after,
                            &ack.error,
                            std::time::Instant::now(),
                            chrono::Utc::now().timestamp_millis(),
                        );
                        if let Some(delay) = outcome.queued {
                            tracing::info!(
                                "Location refused transiently (attempt {}/{}), re-sending in {:?} ({} waiting): {}",
                                attempts,
                                MAX_RETRY_ATTEMPTS,
                                delay,
                                retry_queue.len(),
                                ack.error
                            );
                        }
                        // Whatever the requeue gave up on: this fix if it was
                        // past saving, plus anything evicted to make room. Each
                        // one logs its own reason.
                        for abandoned in outcome.abandoned {
                            report_abandoned(&error_callback, abandoned);
                        }
                    }
                    AckAction::Drop => {
                        // A settled refusal. Reported immediately and exactly
                        // once, which is the behaviour both apps' device
                        // re-registration path already depends on.
                        tracing::warn!(
                            "Location rejected: device={}, error={}",
                            ack.device_id,
                            ack.error
                        );
                        if let Some(cb) =
                            error_callback.lock().unwrap_or_else(|e| e.into_inner()).as_ref()
                        {
                            cb.on_location_rejected(ack.device_id, ack.error);
                        }
                    }
                }
            }
            Err(status) => match classify_rpc_failure(status.code()) {
                RpcFailure::Transport => {
                    let error = format!("{:?}: {}", status.code(), status.message());
                    let now = std::time::Instant::now();
                    let hold = transport.record_failure(now, &error);
                    // Back to the FRONT: it was taken before anything that
                    // queued behind the gate, and the backlog has to drain in
                    // the order the fixes were taken.
                    let outcome = retry_queue.hold_for_connection(
                        msg,
                        attempts_so_far + 1,
                        &error,
                        now,
                        chrono::Utc::now().timestamp_millis(),
                        true,
                    );
                    tracing::warn!(
                        "Upload RPC failed ({}); holding sends for {:?}, fix {} ({} waiting)",
                        error,
                        hold,
                        if outcome.queued.is_some() { "held" } else { "given up" },
                        retry_queue.len()
                    );
                    log_status_chain(&status);
                    for abandoned in outcome.abandoned {
                        report_abandoned(&error_callback, abandoned);
                    }
                }
                RpcFailure::Settled => {
                    // The format both apps match on ("Unauthenticated",
                    // "Invalid or expired token") — keep it.
                    let error = format!("gRPC error: {:?} - {}", status.code(), status.message());
                    tracing::error!("gRPC SendLocation refused: {}", error);
                    end_stream(&error_callback, &error, Some(msg), &mut retry_queue, &mut rx);
                    return Err(MobileError::NetworkError(format!("gRPC call failed: {}", status)));
                }
            },
        }
    }

    let stranded = retry_queue.drain_all();
    if !stranded.is_empty() {
        tracing::warn!(
            "{} queued location(s) abandoned: streaming stopped before they could be re-sent",
            stranded.len()
        );
        for abandoned in stranded {
            report_abandoned(&error_callback, abandoned);
        }
    }

    tracing::info!("Location send loop ended (channel closed)");
    Ok(())
}

/// Wait until `deadline`, or forever when there is nothing to wait for.
///
/// The `None` arm has to be a future that never completes rather than one that
/// completes immediately: an immediate one would turn `select!` into a spin
/// loop whenever the retry queue is empty, which is nearly always.
async fn sleep_until_opt(deadline: Option<std::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Tell the app about a location that will never be stored, and say why.
///
/// `on_location_rejected` fires once per fix, at the moment the fix is
/// given up on — not once per refusal. A transient refusal that is about to be
/// re-sent is not a rejection the app can act on, and reporting each attempt
/// would turn one lost fix into a burst of identical callbacks.
fn report_abandoned(
    error_callback: &Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>>,
    abandoned: Abandoned<LocationUpdateMessage>,
) {
    tracing::warn!(
        "Location dropped ({}): device={}, circle={}, last server error: {}",
        abandoned.reason.as_str(),
        abandoned.item.device_id,
        abandoned.item.circle_id,
        abandoned.last_error
    );
    if let Some(cb) = error_callback.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        cb.on_location_rejected(
            abandoned.item.device_id.clone(),
            format!("{} ({})", abandoned.last_error, abandoned.reason.as_str()),
        );
    }
}

/// Build the wire message from a queued update, WITHOUT consuming it.
///
/// Split out for the same reason as `payload_blob`: it is a field-by-field
/// mapping no compiler check protects, whose only symptom when wrong is rows
/// nobody can read. Taking `&msg` is load-bearing too — the retry queue needs
/// the message back after the RPC that rejected it.
fn build_update(msg: &LocationUpdateMessage) -> LocationUpdate {
    // The timestamp is sealed by `send_location`/`send_envelope_location`
    // themselves via `crypto.encrypt_timestamp(circle_id, ..)`, which always
    // uses the CIRCLE key — never a session key. So it genuinely has no id
    // to name, and the reader decrypts it by trying held circle-key
    // versions. Empty here is correct, not a dropped value.
    let encrypted_timestamp = msg.encrypted_timestamp.as_ref().map(|enc| EncryptedBlob {
        nonce: hex::decode(&enc.nonce).unwrap_or_default(),
        ciphertext: hex::decode(&enc.ciphertext).unwrap_or_default(),
        key_id: String::new(),
    });

    let encrypted_payload = payload_blob(
        &msg.encrypted_location.location,
        msg.location_key_id.clone(),
    );

    // timestamp_ms is a deprecated proto field the server ignores; we still
    // must set it in the generated struct literal, so allow the deprecation.
    #[allow(deprecated)]
    LocationUpdate {
        device_id: msg.device_id.clone(),
        circle_id: msg.circle_id.clone(),
        timestamp_ms: 0, // DEPRECATED: Server ignores this
        encrypted_payload: Some(encrypted_payload),
        latitude: None,
        longitude: None,
        encrypted_timestamp,
        user_pseudonym: msg.user_pseudonym.clone(),
        device_pseudonym: msg.device_pseudonym.clone(),
        day_bucket: Some(msg.day_bucket),
        wrapped_msg_key: msg.wrapped_msg_key.clone(),
        wrapped_msg_key_nonce: msg.wrapped_msg_key_nonce.clone(),
        // Drop this and every liveness refresh becomes a history row — the
        // exact cost the flag exists to avoid, and invisible from the client:
        // the send still succeeds and the map still updates.
        liveness_only: msg.liveness_only,
        // Drop this and every late history point becomes a live report: the
        // server's freshness check refuses it, or it moves a marker backwards.
        history_only: msg.history_only,
    }
}

/// Platform-agnostic front for native background tracking: it holds the
/// tracking flag and routes fixes, while the actual work is delegated through
/// `LocationCallback`.
#[derive(uniffi::Object)]
pub struct BackgroundLocationService {
    is_tracking: Arc<Mutex<bool>>,
    callback: Arc<Mutex<Option<Box<dyn LocationCallback>>>>,
}

/// Callback interface implemented by the platform (Android LocationManager,
/// iOS CoreLocation) and invoked by `BackgroundLocationService`.
#[uniffi::export(callback_interface)]
pub trait LocationCallback: Send + Sync {
    fn on_location_received(&self, location: Location);

    fn on_permission_changed(&self, granted: bool);

    fn on_error(&self, error: String);
}

/// Callback interface for gRPC upload errors, implemented by platform code so
/// the app can react to server-side rejections.
#[uniffi::export(callback_interface)]
pub trait StreamErrorCallback: Send + Sync {
    /// One location will never be stored, and the SDK has stopped trying.
    ///
    /// This fires once per lost fix, at the point the SDK gives up — NOT once
    /// per refusal. Rejections the server can recover from (rate limiting,
    /// storage backpressure, the server's ordering check failing closed while
    /// its store is briefly unavailable) are re-sent inside the SDK and never
    /// reach here unless the retry budget or the fix's shelf life runs out
    /// first; see `location_retry`. What does reach here immediately is a
    /// settled refusal: "Device not found or not owned by user" (the device
    /// needs re-registration), "Not a member of this circle" (the user was
    /// removed), "Session revoked" (the app needs a new login).
    ///
    /// `error` is the server's own message. When the SDK gave up on a fix it
    /// had been retrying, the reason it gave up is appended in parentheses.
    fn on_location_rejected(&self, device_id: String, error: String);

    fn on_stream_error(&self, error: String);
}

#[uniffi::export]
impl BackgroundLocationService {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            is_tracking: Arc::new(Mutex::new(false)),
            callback: Arc::new(Mutex::new(None)),
        })
    }

    /// Required before `start_tracking`, which errors without it.
    pub fn register_callback(&self, callback: Box<dyn LocationCallback>) {
        tracing::info!("Registering location callback");
        *self.callback.lock().unwrap_or_else(|e| e.into_inner()) = Some(callback);
    }

    /// Always returns `false` ("not yet granted"). The SDK cannot drive the
    /// permission UI, so the platform layer owns the request — Android asks
    /// for ACCESS_FINE_LOCATION plus ACCESS_BACKGROUND_LOCATION, iOS for
    /// kCLAuthorizationStatusAuthorizedAlways — and reports the outcome
    /// through `LocationCallback::on_permission_changed`.
    pub fn request_permissions(&self) -> Result<bool, MobileError> {
        tracing::info!("Requesting location permissions");

        Ok(false) // Permissions need to be requested
    }

    /// Always returns `false`: the SDK has no way to query platform permission
    /// state, and denying is the safe default. Platform code must run its own
    /// check instead of trusting this.
    pub fn has_permissions(&self) -> bool {
        tracing::debug!("Checking location permissions");
        false
    }

    /// Flags the service as tracking; the platform layer starts the native
    /// updates — a foreground service with a notification on Android,
    /// significant-change or continuous updates on iOS — and feeds them back
    /// through `on_location_update`.
    pub fn start_tracking(&self, interval_seconds: i32) -> Result<(), MobileError> {
        if self.callback.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
            return Err(MobileError::InvalidInput(
                "Location callback not registered. Call register_callback first.".to_string(),
            ));
        }

        tracing::info!(
            "Starting background location tracking with {} second interval",
            interval_seconds
        );

        *self.is_tracking.lock().unwrap_or_else(|e| e.into_inner()) = true;

        Ok(())
    }

    pub fn stop_tracking(&self) {
        tracing::info!("Stopping background location tracking");
        *self.is_tracking.lock().unwrap_or_else(|e| e.into_inner()) = false;
    }

    pub fn is_tracking(&self) -> bool {
        *self.is_tracking.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Entry point for platform code to hand a fresh fix to the SDK. It is
    /// only forwarded to the registered `LocationCallback` — encryption and
    /// upload happen in `LocationManager`, driven by whoever owns that
    /// callback, not here.
    pub fn on_location_update(&self, location: Location) {
        tracing::debug!(
            "Received location update: lat={}, lng={}, timestamp={}",
            location.latitude,
            location.longitude,
            location.timestamp
        );

        if let Some(callback) = self.callback.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            callback.on_location_received(location);
        }
    }
}

impl Default for BackgroundLocationService {
    fn default() -> Self {
        Self {
            is_tracking: Arc::new(Mutex::new(false)),
            callback: Arc::new(Mutex::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(nonce_hex: &str, ct_hex: &str) -> EncryptedData {
        EncryptedData { nonce: nonce_hex.to_string(), ciphertext: ct_hex.to_string() }
    }

    /// A session-key id supplied by the caller must reach the wire VERBATIM.
    /// `CryptoManager` already returns it in wire format, so any transformation
    /// here is wrong — the reader matches on the exact "s:" prefix.
    #[test]
    fn session_key_id_reaches_the_wire_unchanged() {
        let key_id = "s:3f2504e0-4f89-11d3-9a0c-0305e82c3301";
        let blob = payload_blob(&enc("00ff", "abcd"), Some(key_id.to_string()));
        assert_eq!(blob.key_id, key_id, "session key_id must survive verbatim");
    }

    /// The circle-key fallback id ("c:{version}") must survive too. It does not
    /// take the reader's session branch, but it still names the key version.
    #[test]
    fn circle_key_fallback_id_reaches_the_wire_unchanged() {
        let blob = payload_blob(&enc("00ff", "abcd"), Some("c:7".to_string()));
        assert_eq!(blob.key_id, "c:7");
    }

    /// No id => empty string. Envelope sends rely on this: the reader routes
    /// them on `wrapped_msg_key`, and a non-empty key_id would send them down
    /// the wrong branch.
    #[test]
    fn absent_key_id_is_an_empty_string() {
        let blob = payload_blob(&enc("00ff", "abcd"), None);
        assert!(blob.key_id.is_empty(), "absent id must not invent a value");
    }

    /// Guards the pairing, not just the id: a key_id that survives while the
    /// ciphertext it names is mangled would be worse than useless.
    #[test]
    fn hex_fields_decode_alongside_the_key_id() {
        let blob = payload_blob(&enc("00ff", "abcd"), Some("s:x".to_string()));
        assert_eq!(blob.nonce, vec![0x00, 0xff]);
        assert_eq!(blob.ciphertext, vec![0xab, 0xcd]);
        assert_eq!(blob.key_id, "s:x");
    }

    /// `update_token` must replace the token the upload task reads, or a
    /// refreshed JWT never reaches the upload task: every later RPC keeps
    /// presenting the expired token and the server keeps rejecting it. Reading
    /// the field back is the whole point — it is the value `run_streaming_loop`
    /// sends.
    #[test]
    fn update_token_replaces_the_token_the_upload_task_reads() {
        let manager = LocationManager::new(
            SdkConfig::development(),
            "stale.jwt".to_string(),
            "user-1".to_string(),
            CryptoManager::new(),
            PrivacyConfig::default(),
        );

        manager.update_token("fresh.jwt".to_string());

        assert_eq!(
            *manager.jwt_token.lock().unwrap(),
            "fresh.jwt",
            "the refreshed token must land where the upload task reads it"
        );
    }

    fn queued(circle: &str, device: &str, ts: i64) -> LocationUpdateMessage {
        LocationUpdateMessage {
            device_id: device.to_string(),
            circle_id: circle.to_string(),
            encrypted_location: EncryptedLocation {
                location: enc("00ff", "abcd"),
                timestamp: ts,
                user_id: "u1".to_string(),
                device_id: device.to_string(),
            },
            location_key_id: Some("s:key".to_string()),
            user_pseudonym: Some("up".to_string()),
            device_pseudonym: Some("dp".to_string()),
            day_bucket: timestamp_to_day_bucket(ts),
            encrypted_timestamp: Some(enc("1122", "3344")),
            wrapped_msg_key: Some(vec![1, 2, 3]),
            wrapped_msg_key_nonce: Some(vec![4, 5, 6]),
            liveness_only: false,
            history_only: false,
        }
    }

    /// `build_update` has to take the message by REFERENCE. If it consumed
    /// one, a rejected update could not be re-sent — the bytes the server
    /// refused would be gone — and the retry queue would silently become a
    /// no-op. Building twice from one message is the cheapest way to hold that
    /// property to the compiler.
    #[test]
    fn build_update_leaves_the_message_available_to_retry() {
        let msg = queued("circle-1", "device-1", 1_755_000_000_000);

        let first = build_update(&msg);
        let second = build_update(&msg);

        assert_eq!(first, second, "the same message must produce the same wire update");
        assert_eq!(msg.circle_id, "circle-1", "the message must survive the send");
    }

    /// Field-by-field, because nothing in the type system pairs these up and
    /// the only symptom of a mis-mapping is rows nobody can read.
    #[test]
    fn build_update_carries_every_field_to_the_wire() {
        let ts = 1_755_000_000_000i64;
        let update = build_update(&queued("circle-1", "device-1", ts));

        assert_eq!(update.device_id, "device-1");
        assert_eq!(update.circle_id, "circle-1");
        assert_eq!(update.day_bucket, Some(timestamp_to_day_bucket(ts)));
        assert_eq!(update.user_pseudonym.as_deref(), Some("up"));
        assert_eq!(update.device_pseudonym.as_deref(), Some("dp"));
        assert_eq!(update.wrapped_msg_key, Some(vec![1, 2, 3]));
        assert_eq!(update.wrapped_msg_key_nonce, Some(vec![4, 5, 6]));

        let payload = update.encrypted_payload.expect("payload");
        assert_eq!(payload.key_id, "s:key", "the key that sealed it must be named");
        assert_eq!(payload.ciphertext, vec![0xab, 0xcd]);

        let enc_ts = update.encrypted_timestamp.expect("encrypted timestamp");
        assert_eq!(enc_ts.nonce, vec![0x11, 0x22]);
        assert_eq!(enc_ts.ciphertext, vec![0x33, 0x44]);
        assert!(
            enc_ts.key_id.is_empty(),
            "the sealed timestamp names no key — it is always circle-key sealed"
        );

        // SECURITY (blindness): the deprecated plaintext coordinate fields must
        // stay empty. The server's ingest rejects any update that carries them.
        assert!(update.latitude.is_none() && update.longitude.is_none());

        // An ordinary send is a history row: the flag must be OFF unless a
        // caller asked for a liveness refresh.
        assert!(!update.liveness_only, "an ordinary send must still write history");
    }

    /// The liveness flag is the whole feature and nothing in the type system
    /// carries it — `build_update` is a hand-written field-by-field mapping, and
    /// dropping this one line would silently turn every refresh back into a
    /// history row while the client kept working perfectly.
    #[test]
    fn build_update_carries_the_liveness_flag() {
        let mut msg = queued("circle-1", "device-1", 1_755_000_000_000);
        msg.liveness_only = true;

        let update = build_update(&msg);

        assert!(update.liveness_only, "the refresh must be marked on the wire");
        // Everything else is IDENTICAL to a history send: a liveness row is a
        // full row, because latest_locations is a ReplacingMergeTree and a
        // partial one would win the dedup and blank the position.
        let history = build_update(&queued("circle-1", "device-1", 1_755_000_000_000));
        assert_eq!(update.encrypted_payload, history.encrypted_payload);
        assert_eq!(update.encrypted_timestamp, history.encrypted_timestamp);
        assert_eq!(update.day_bucket, history.day_bucket);
        assert_eq!(update.user_pseudonym, history.user_pseudonym);
        assert_eq!(update.device_pseudonym, history.device_pseudonym);
        assert_eq!(update.wrapped_msg_key, history.wrapped_msg_key);
        assert_eq!(update.wrapped_msg_key_nonce, history.wrapped_msg_key_nonce);
    }

    /// The two exported entry points differ ONLY in the flag. Checked through
    /// the shared bodies rather than the `#[uniffi::export]` wrappers, which
    /// need a live stream; the wrappers are one-line delegations to these.
    #[test]
    fn only_the_liveness_entry_points_set_the_flag() {
        for (liveness_only, expected) in [(false, false), (true, true)] {
            let msg = LocationUpdateMessage { liveness_only, ..queued("c", "d", 1_755_000_000_000) };
            assert_eq!(build_update(&msg).liveness_only, expected);
        }
    }

    /// `history_only` rides a hand-written field-by-field mapping too: dropping
    /// it turns every late point into a live report, which the server refuses
    /// as stale or lets move a marker backwards.
    #[test]
    fn build_update_carries_the_history_flag() {
        let msg = LocationUpdateMessage { history_only: true, ..queued("circle-1", "device-1", 1_755_000_000_000) };
        let update = build_update(&msg);
        assert!(update.history_only, "the late point must be marked on the wire");
        assert!(!update.liveness_only);
        // Everything else is the ordinary send's.
        let ordinary = build_update(&queued("circle-1", "device-1", 1_755_000_000_000));
        assert!(!ordinary.history_only, "an ordinary send is live");
        assert_eq!(LocationUpdate { history_only: false, ..update }, ordinary);
    }

    /// Field 14 on the wire, absent (so `false`) on every other send: what an
    /// old server skips and a new one reads.
    #[test]
    fn the_history_flag_is_field_14_and_defaults_to_false() {
        use prost::Message;
        let history = build_update(&LocationUpdateMessage { history_only: true, ..queued("c", "d", 1_755_000_000_000) });
        let bytes = history.encode_to_vec();
        assert!(bytes.windows(2).any(|w| w == [14 << 3, 1]), "field 14, varint true");
        assert!(LocationUpdate::decode(bytes.as_slice()).unwrap().history_only, "round-trips");

        let ordinary = build_update(&queued("c", "d", 1_755_000_000_000)).encode_to_vec();
        assert!(!ordinary.windows(2).any(|w| w == [14 << 3, 1]), "an ordinary send omits it");
        assert!(!LocationUpdate::decode(ordinary.as_slice()).unwrap().history_only, "an old client's bytes read as false");
    }

    /// Through the EXPORTED entry points, with the upload channel in hand: each
    /// sets exactly its own flag, and only the two history sends set history.
    #[test]
    fn each_send_entry_point_sets_exactly_its_own_flag() {
        let crypto = CryptoManager::new();
        crypto.generate_keypair();
        let created = crypto.prepare_circle_creation().unwrap();
        let circle = "11111111-2222-4333-8444-555555555555";
        crypto.finalize_circle_creation(created.temp_circle_id, circle.to_string()).unwrap();
        let manager = LocationManager::new(
            SdkConfig::development(),
            "jwt".to_string(),
            "user-1".to_string(),
            crypto,
            PrivacyConfig::default(),
        );
        let (tx, mut rx) = mpsc::channel::<LocationUpdateMessage>(8);
        *manager.tx.lock().unwrap() = Some(tx);
        let fix = |ts: i64| EncryptedLocation {
            location: enc("00ff", "abcd"),
            timestamp: ts,
            user_id: "user-1".to_string(),
            device_id: "device-1".to_string(),
        };
        let (d, c) = ("device-1".to_string(), circle.to_string());
        let ts = 1_755_000_000_000i64;
        manager.send_location(d.clone(), c.clone(), fix(ts), None).unwrap();
        manager.send_liveness_refresh(d.clone(), c.clone(), fix(ts), None).unwrap();
        manager.send_history_location(d.clone(), c.clone(), fix(ts), None).unwrap();
        manager.send_envelope_location(d.clone(), c.clone(), fix(ts), "0102".into(), "0304".into()).unwrap();
        manager.send_envelope_liveness_refresh(d.clone(), c.clone(), fix(ts), "0102".into(), "0304".into()).unwrap();
        manager.send_envelope_history_location(d.clone(), c.clone(), fix(ts), "0102".into(), "0304".into()).unwrap();

        let mut flags = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            let update = build_update(&msg);
            assert_eq!((update.liveness_only, update.history_only), (msg.liveness_only, msg.history_only));
            flags.push((msg.liveness_only, msg.history_only, msg.wrapped_msg_key.is_some()));
        }
        assert_eq!(
            flags,
            vec![
                (false, false, false),
                (true, false, false),
                (false, true, false),
                (false, false, true),
                (true, false, true),
                (false, true, true),
            ]
        );
    }

    /// After the personal key in use changes (an adopted copy), the NEXT
    /// update carries the new key's pseudonym. A cached pseudonym would tag
    /// new rows with the old key's, and the server records whatever a
    /// personal row carries as the account's.
    #[test]
    fn a_changed_key_changes_the_pseudonym_on_the_next_send() {
        use crate::types::PersonalKeyVerdict;
        const PERSONAL: &str = "00000000-0000-0000-0000-000000000000";
        const UID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        // Two devices of one account, each holding a personal key of its own.
        let good = CryptoManager::new();
        let kp = good.generate_keypair();
        let sk = good.generate_signing_keypair();
        let created = good.prepare_circle_creation().unwrap();
        good.finalize_circle_creation(created.temp_circle_id, PERSONAL.to_string()).unwrap();
        let phone = CryptoManager::new();
        phone.import_private_key(kp.private_key.clone()).unwrap();
        phone.import_signing_private_key(sk.secret_seed_b64.clone()).unwrap();
        let created = phone.prepare_circle_creation().unwrap();
        phone.finalize_circle_creation(created.temp_circle_id, PERSONAL.to_string()).unwrap();

        let manager = LocationManager::new(
            SdkConfig::development(),
            "jwt".to_string(),
            UID.to_string(),
            Arc::clone(&phone),
            PrivacyConfig::default(),
        );
        let (tx, mut rx) = mpsc::channel::<LocationUpdateMessage>(4);
        *manager.tx.lock().unwrap() = Some(tx);
        let fix = EncryptedLocation {
            location: enc("00ff", "abcd"),
            timestamp: 1_755_000_000_000,
            user_id: UID.to_string(),
            device_id: "device-1".to_string(),
        };
        manager.send_location("device-1".into(), PERSONAL.into(), fix.clone(), None).unwrap();
        let first = rx.try_recv().unwrap().user_pseudonym.unwrap();

        // The phone adopts the account's copy: the other device's key.
        let bundle = good
            .wrap_circle_key_for_member_full(PERSONAL.into(), String::new(), UID.into(), UID.into(), String::new())
            .unwrap();
        let recorded = good.derive_user_pseudonym(PERSONAL.into(), UID.into()).unwrap();
        let verdict = phone
            .adopt_personal_key(
                UID.into(),
                format!("{}{}", bundle.encrypted_circle_key.nonce, bundle.encrypted_circle_key.ciphertext),
                bundle.ephemeral_public_key.clone(),
                1,
                Some(bundle.wrap_signature.clone()),
                recorded.clone(),
            )
            .unwrap();
        assert_eq!(verdict, PersonalKeyVerdict::Adopt);

        manager.send_location("device-1".into(), PERSONAL.into(), fix, None).unwrap();
        let second = rx.try_recv().unwrap().user_pseudonym.unwrap();
        assert_ne!(first, second);
        assert_eq!(second, recorded, "the next row carries the adopted key's pseudonym");
    }

    /// The retry queue abandons a queued fix once a NEWER one from the same
    /// emitter lands, and keys that on (circle, device) — so this mapping is
    /// what stops one circle's acceptance discarding another circle's fix.
    #[test]
    fn a_queued_update_identifies_its_emitter_and_its_own_age() {
        let msg = queued("circle-1", "device-1", 1_755_000_000_000);
        assert_eq!(msg.emitter(), ("circle-1", "device-1"));
        assert_eq!(
            msg.fix_timestamp_ms(),
            1_755_000_000_000,
            "staleness is measured on the FIX, not on the send attempt"
        );
    }

    // ===================================================================
    // End-to-end over a real gRPC server.
    //
    // Everything above tests the pieces. These drive the actual upload loop
    // against a real `LocationIngest` server, because what matters is the
    // loop: one that looks at a `success: false` ack and moves on passes every
    // piece's test. Only a test that watches the wire can tell a re-send from
    // a well-tested intention to re-send.
    // ===================================================================

    use std::collections::VecDeque;
    use tonic::Request;
    use track_proto::track::{
        location_ingest_server::{LocationIngest, LocationIngestServer},
        LocationAck,
    };

    /// One scripted answer from the test server.
    enum Reply {
        /// A healthy ack.
        Accept,
        /// An ack with `success: false` and this error: an application-level
        /// refusal, which `location_retry` classifies.
        Refuse(String),
        /// No ack at all: the RPC fails with this gRPC status, which is what a
        /// dropped connection, a timeout or an expired token looks like.
        Fail(tonic::Code, &'static str),
    }

    /// A server that answers from a script, one entry per call.
    struct ScriptedIngest {
        received: Arc<Mutex<Vec<LocationUpdate>>>,
        script: Arc<Mutex<VecDeque<Reply>>>,
    }

    #[tonic::async_trait]
    #[allow(deprecated)] // LocationAck::timestamp_ms
    impl LocationIngest for ScriptedIngest {
        async fn send_location(
            &self,
            request: Request<LocationUpdate>,
        ) -> Result<tonic::Response<LocationAck>, tonic::Status> {
            let update = request.into_inner();
            // Past the end of the script means "accept": a test that expects
            // two calls and gets five should fail on the count, not by
            // panicking inside the server.
            let reply = self.script.lock().unwrap().pop_front().unwrap_or(Reply::Accept);
            let device_id = update.device_id.clone();
            // Every call is recorded, failed ones included: the tests count
            // ATTEMPTS on the wire.
            self.received.lock().unwrap().push(update);
            let refusal = match reply {
                Reply::Accept => None,
                Reply::Refuse(error) => Some(error),
                Reply::Fail(code, message) => return Err(tonic::Status::new(code, message)),
            };
            Ok(tonic::Response::new(LocationAck {
                device_id,
                timestamp_ms: 0,
                success: refusal.is_none(),
                error: refusal.unwrap_or_default(),
                queue_depth_percent: 0,
            }))
        }
    }

    /// Records what the SDK told the platform layer.
    struct RecordingCallback {
        rejections: Arc<Mutex<Vec<(String, String)>>>,
        stream_errors: Arc<Mutex<Vec<String>>>,
    }

    impl StreamErrorCallback for RecordingCallback {
        fn on_location_rejected(&self, device_id: String, error: String) {
            self.rejections.lock().unwrap().push((device_id, error));
        }
        fn on_stream_error(&self, error: String) {
            self.stream_errors.lock().unwrap().push(error);
        }
    }

    struct Harness {
        endpoint: String,
        received: Arc<Mutex<Vec<LocationUpdate>>>,
        rejections: Arc<Mutex<Vec<(String, String)>>>,
        stream_errors: Arc<Mutex<Vec<String>>>,
        error_callback: Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>>,
    }

    /// Bind a scripted server to an ephemeral port on loopback. `Some(error)`
    /// refuses with that ack error, `None` accepts.
    async fn start_scripted_server(script: Vec<Option<String>>) -> Harness {
        start_server_with_replies(
            script
                .into_iter()
                .map(|r| match r {
                    Some(error) => Reply::Refuse(error),
                    None => Reply::Accept,
                })
                .collect(),
        )
        .await
    }

    async fn start_server_with_replies(script: Vec<Reply>) -> Harness {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let harness = harness_for(&listener);
        serve_on(listener, script, Arc::clone(&harness.received));
        harness
    }

    /// The callback side of a harness, pointed at whatever listens on the
    /// listener's address — possibly nothing yet.
    fn harness_for(listener: &tokio::net::TcpListener) -> Harness {
        let addr = listener.local_addr().expect("local addr");
        let rejections = Arc::new(Mutex::new(Vec::new()));
        let stream_errors = Arc::new(Mutex::new(Vec::new()));
        let error_callback: Arc<Mutex<Option<Box<dyn StreamErrorCallback>>>> =
            Arc::new(Mutex::new(Some(Box::new(RecordingCallback {
                rejections: Arc::clone(&rejections),
                stream_errors: Arc::clone(&stream_errors),
            }))));
        Harness {
            endpoint: format!("http://{}", addr),
            received: Arc::new(Mutex::new(Vec::new())),
            rejections,
            stream_errors,
            error_callback,
        }
    }

    fn serve_on(
        listener: tokio::net::TcpListener,
        script: Vec<Reply>,
        received: Arc<Mutex<Vec<LocationUpdate>>>,
    ) {
        let service = ScriptedIngest {
            received,
            script: Arc::new(Mutex::new(script.into_iter().collect())),
        };
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(LocationIngestServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await;
        });
    }

    /// A queued update whose ciphertext names it, so a test can read the ORDER
    /// fixes reached the wire in.
    fn queued_tagged(circle: &str, ts: i64, tag: u8) -> LocationUpdateMessage {
        let mut msg = queued(circle, "device-1", ts);
        msg.encrypted_location.location = enc("00ff", &format!("{:02x}", tag));
        msg
    }

    fn wire_tag(update: &LocationUpdate) -> u8 {
        update.encrypted_payload.as_ref().expect("payload").ciphertext[0]
    }

    async fn wait_for(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for: {}", what);
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// A timestamp that is both fresh (inside the shelf life) and jitter-free,
    /// so the backoff a test waits on is exactly the base step. The jitter is
    /// `timestamp % (step / 2 + 1)`, hence the round-trip through 1001.
    fn jitter_free_now_ms() -> i64 {
        (chrono::Utc::now().timestamp_millis() / 1001) * 1001
    }

    /// A rate-limited location must not be logged and dropped: nothing would
    /// backfill the row. It must reach the server a second time and be
    /// stored.
    #[test]
    fn a_transiently_refused_location_is_re_sent_until_it_lands() {
        let rt = test_runtime();
        rt.block_on(async {
            let harness = start_scripted_server(vec![
                Some("Rate limited: Too fast. Retry in 1s".to_string()),
                None,
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            tx.send(queued("circle-1", "device-1", jitter_free_now_ms()))
                .await
                .expect("queue the location");

            // The first backoff step is 2s; give it room without making the
            // test wait on the timeout when it works.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while harness.received.lock().unwrap().len() < 2 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the refused location was never re-sent: it would be lost"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            let received = harness.received.lock().unwrap().clone();
            assert_eq!(received.len(), 2, "sent once, then re-sent once");
            assert_eq!(
                received[0].encrypted_payload, received[1].encrypted_payload,
                "the re-send must carry the SAME sealed location, not a re-encryption"
            );
            assert_eq!(received[1].day_bucket, received[0].day_bucket);

            assert!(
                harness.rejections.lock().unwrap().is_empty(),
                "a rejection the SDK recovered from must not be reported as a lost fix"
            );

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }

    /// The negative control on the same path: a settled refusal must be sent
    /// EXACTLY once and handed straight to the platform layer, whose device
    /// re-registration depends on seeing that string.
    #[test]
    fn a_settled_refusal_is_reported_at_once_and_never_re_sent() {
        let rt = test_runtime();
        rt.block_on(async {
            let harness = start_scripted_server(vec![
                Some("Device not found or not owned by user".to_string()),
                // Any further call would be a retry, and would be recorded.
                Some("Device not found or not owned by user".to_string()),
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            tx.send(queued("circle-1", "device-1", jitter_free_now_ms()))
                .await
                .expect("queue the location");

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while harness.rejections.lock().unwrap().is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "a settled refusal was never reported to the platform layer"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            let rejections = harness.rejections.lock().unwrap().clone();
            assert_eq!(rejections.len(), 1);
            assert_eq!(rejections[0].0, "device-1");
            assert_eq!(
                rejections[0].1, "Device not found or not owned by user",
                "the string both apps match on must arrive verbatim, not decorated"
            );

            // Well past the first backoff step: nothing should have been resent.
            tokio::time::sleep(std::time::Duration::from_millis(3_000)).await;
            assert_eq!(
                harness.received.lock().unwrap().len(),
                1,
                "a settled refusal must not be retried — that is a busy-loop on a battery"
            );

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }

    /// Every tonic code lands in exactly one class, and the two that matter
    /// most land where the apps' recovery expects them: an expired token must
    /// reach `on_stream_error` (the apps refresh on it), and a dropped
    /// connection must NOT (it is the SDK's to retry, cheaply).
    #[test]
    fn rpc_failures_split_into_transport_and_settled() {
        use tonic::Code;
        for code in [
            Code::Unavailable,
            Code::Unknown,
            Code::Cancelled,
            Code::DeadlineExceeded,
            Code::Aborted,
            Code::Internal,
            Code::ResourceExhausted,
            Code::Ok,
        ] {
            assert_eq!(classify_rpc_failure(code), RpcFailure::Transport, "{:?}", code);
        }
        for code in [
            Code::Unauthenticated,
            Code::PermissionDenied,
            Code::InvalidArgument,
            Code::NotFound,
            Code::FailedPrecondition,
            Code::Unimplemented,
            Code::OutOfRange,
            Code::AlreadyExists,
            Code::DataLoss,
        ] {
            assert_eq!(classify_rpc_failure(code), RpcFailure::Settled, "{:?}", code);
        }
    }

    /// A dropped connection must not end the upload task: the fix in flight
    /// would be lost, and nothing would restart the stream. The fix is held
    /// and re-sent once the connection is back, and the app never hears about
    /// it.
    #[test]
    fn a_transport_failure_is_retried_and_never_ends_the_stream() {
        let rt = test_runtime();
        rt.block_on(async {
            let harness = start_server_with_replies(vec![
                Reply::Fail(tonic::Code::Unavailable, "ingest restarting"),
                Reply::Accept,
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            tx.send(queued_tagged("circle-1", jitter_free_now_ms(), 1))
                .await
                .expect("queue the location");

            let received = Arc::clone(&harness.received);
            wait_for("the held fix to be re-sent", 20, || received.lock().unwrap().len() >= 2).await;

            let received = harness.received.lock().unwrap().clone();
            assert_eq!(received.len(), 2, "failed once, re-sent once");
            assert_eq!(wire_tag(&received[1]), 1, "the same fix, not a new one");
            assert!(
                harness.stream_errors.lock().unwrap().is_empty(),
                "a transport failure is the SDK's to retry; the app must not be told to rebuild"
            );
            assert!(
                harness.rejections.lock().unwrap().is_empty(),
                "a fix that landed is not a lost fix"
            );
            assert!(!loop_task.is_finished(), "the upload task must survive a dropped connection");

            // And it still carries new fixes afterwards.
            tx.send(queued_tagged("circle-1", jitter_free_now_ms() + 1, 2))
                .await
                .expect("queue another");
            let received = Arc::clone(&harness.received);
            wait_for("the next fix", 10, || received.lock().unwrap().len() >= 3).await;

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }

    /// No hot loop while the connection is down: fixes that arrive behind a
    /// failure wait at the gate instead of each dialling out, and when one
    /// probe gets through the backlog drains in the order the fixes were taken.
    #[test]
    fn fixes_queue_behind_one_probe_and_drain_in_order() {
        let rt = test_runtime();
        rt.block_on(async {
            // Two failures: the first strands fix 0 at the gate, and the
            // second fails the PROBE after fixes 1-3 have queued behind it —
            // which is the moment a held fix could lose its place in line.
            let harness = start_server_with_replies(vec![
                Reply::Fail(tonic::Code::Unavailable, "no route to host"),
                Reply::Fail(tonic::Code::Unavailable, "no route to host"),
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            let t0 = jitter_free_now_ms();
            tx.send(queued_tagged("circle-1", t0, 0)).await.expect("queue");
            let received = Arc::clone(&harness.received);
            wait_for("the first attempt", 10, || received.lock().unwrap().len() >= 1).await;

            // Three more fixes arrive while the connection is known to be down.
            for i in 1..=3u8 {
                tx.send(queued_tagged("circle-1", t0 + i as i64 * 10, i)).await.expect("queue");
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            assert_eq!(
                harness.received.lock().unwrap().len(),
                1,
                "fixes arriving behind a failed connection must wait at the gate, not dial out"
            );

            let received = Arc::clone(&harness.received);
            wait_for("the backlog to drain", 30, || received.lock().unwrap().len() >= 6).await;
            let wire: Vec<u8> = harness.received.lock().unwrap().iter().map(wire_tag).collect();
            assert_eq!(wire[1], 0, "the one probe when the gate opened was the oldest fix");
            assert_eq!(&wire[2..], &[0, 1, 2, 3], "oldest first, the twice-failed probe included");
            assert!(harness.stream_errors.lock().unwrap().is_empty());
            assert!(harness.rejections.lock().unwrap().is_empty(), "nothing was lost");

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }

    /// A settled failure ends the stream and tells the app — and accounts for
    /// EVERY fix it held: the one in flight, and the ones still buffered in
    /// the channel, which would otherwise be dropped with the receiver and
    /// never reported.
    #[test]
    fn an_expired_token_ends_the_stream_and_reports_every_fix_it_held() {
        let rt = test_runtime();
        rt.block_on(async {
            let harness = start_server_with_replies(vec![
                Reply::Fail(tonic::Code::Unauthenticated, "Invalid or expired token"),
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            // Queued before the loop runs, so two of them are still in the
            // channel when the first one's RPC is refused.
            let t0 = jitter_free_now_ms();
            for i in 0..3u8 {
                tx.send(queued_tagged("circle-1", t0 + i as i64, i)).await.expect("queue");
            }

            let token = Arc::new(Mutex::new("stale.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            let result = tokio::time::timeout(std::time::Duration::from_secs(20), loop_task)
                .await
                .expect("the upload task must end on a settled failure")
                .expect("no panic");
            assert!(result.is_err(), "a settled failure ends the loop with an error");

            let stream_errors = harness.stream_errors.lock().unwrap().clone();
            assert_eq!(stream_errors.len(), 1, "told once");
            assert!(
                stream_errors[0].contains("Unauthenticated") && stream_errors[0].contains("Invalid or expired token"),
                "both apps key their token refresh on these words: {}",
                stream_errors[0]
            );

            let rejections = harness.rejections.lock().unwrap().clone();
            assert_eq!(rejections.len(), 3, "the fix in flight AND the two still buffered");
            for (device, error) in &rejections {
                assert_eq!(device, "device-1");
                assert!(error.contains("Invalid or expired token"), "{}", error);
                assert!(error.contains(DropReason::StreamEnded.as_str()), "{}", error);
            }
            assert_eq!(harness.received.lock().unwrap().len(), 1, "a settled refusal is not retried");
            assert!(
                tx.try_send(queued("circle-1", "device-1", t0 + 9)).is_err(),
                "the channel is closed, so the app's next send fails loudly instead of rotting"
            );
        });
    }

    /// An eager connect would fail `run_streaming_loop` before it sent
    /// anything, and the spawned task would only log it: no callback, and the
    /// app's sends queued into a channel nobody reads. With a lazy channel an
    /// unreachable server is an ordinary transport failure — held, retried,
    /// and delivered once the server appears.
    #[test]
    fn an_unreachable_server_at_start_is_retried_not_a_silent_exit() {
        let rt = test_runtime();
        rt.block_on(async {
            // Reserve a port, then free it: nothing listens there yet.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let harness = harness_for(&listener);
            let addr = listener.local_addr().expect("addr");
            drop(listener);

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            tx.send(queued_tagged("circle-1", jitter_free_now_ms(), 7)).await.expect("queue");
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
            assert!(!loop_task.is_finished(), "no server yet, and the task must still be alive");
            assert!(harness.stream_errors.lock().unwrap().is_empty());

            // The server comes up on the same address.
            let listener = tokio::net::TcpListener::bind(addr).await.expect("rebind");
            serve_on(listener, vec![], Arc::clone(&harness.received));

            let received = Arc::clone(&harness.received);
            wait_for("the held fix to reach the late server", 30, || {
                received.lock().unwrap().len() >= 1
            })
            .await;
            assert_eq!(wire_tag(&harness.received.lock().unwrap()[0]), 7);
            assert!(harness.stream_errors.lock().unwrap().is_empty());
            assert!(harness.rejections.lock().unwrap().is_empty());

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime")
    }

    /// The wait must be allowed to run for the FULL requested timeout: a cap
    /// such as `timeout_ms.min(100)` would report anything slower as a clean
    /// drain when it had not finished.
    #[test]
    fn drain_wait_waits_for_work_that_outlasts_a_100ms_cap() {
        let rt = test_runtime();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        assert!(
            wait_for_runtime_drain(rt.handle(), std::time::Duration::from_millis(5_000)),
            "a 250ms task must drain inside a 5s budget"
        );
        assert!(
            finished.load(std::sync::atomic::Ordering::SeqCst),
            "the wait returned before the task had actually run"
        );
    }

    /// The documented `false` return has to be reachable. The real case is an
    /// upload loop still parked on a channel nobody closed: that is not a
    /// drain, and reporting it as one would hide every unclean shutdown.
    #[test]
    fn drain_wait_reports_false_when_a_task_never_finishes() {
        let rt = test_runtime();
        rt.spawn(async { std::future::pending::<()>().await });

        let start = std::time::Instant::now();
        let drained = wait_for_runtime_drain(rt.handle(), std::time::Duration::from_millis(120));

        assert!(!drained, "a task that never exits must report false");
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(120),
            "the full requested timeout must be honoured, not clamped"
        );
    }
    /// A late history point, hours old and refused once for a transient
    /// reason, is re-sent and lands. With the live shelf life (5 minutes) it
    /// would have been dropped as stale on that first refusal.
    #[test]
    fn a_refused_history_point_hours_old_is_re_sent_not_dropped() {
        let rt = test_runtime();
        rt.block_on(async {
            let harness = start_scripted_server(vec![
                Some("Rate limited: Too fast. Retry in 1s".to_string()),
                None,
            ])
            .await;

            let (tx, rx) = mpsc::channel::<LocationUpdateMessage>(8);
            let token = Arc::new(Mutex::new("test.jwt".to_string()));
            let callback = Arc::clone(&harness.error_callback);
            let endpoint = harness.endpoint.clone();
            let loop_task = tokio::spawn(async move {
                run_streaming_loop(&endpoint, &token, "device-1", rx, callback).await
            });

            let two_hours_ago = jitter_free_now_ms() - 2 * 60 * 60 * 1000;
            let point = LocationUpdateMessage { history_only: true, ..queued("circle-1", "device-1", two_hours_ago) };
            tx.send(point).await.expect("queue the history point");

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while harness.received.lock().unwrap().len() < 2 {
                assert!(
                    harness.rejections.lock().unwrap().is_empty(),
                    "the late point was dropped instead of re-sent"
                );
                assert!(std::time::Instant::now() < deadline, "the refused history point was never re-sent");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let received = harness.received.lock().unwrap().clone();
            assert_eq!(received.len(), 2, "sent once, then re-sent once");
            assert!(received.iter().all(|u| u.history_only && !u.liveness_only));
            assert!(harness.rejections.lock().unwrap().is_empty());

            drop(tx);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
        });
    }
}
