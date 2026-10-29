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

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// KEEPING A REDACTION ACROSS THE FFI
//
// Several records below carry raw key material and hand-write `Debug` so the
// secret field prints as "[REDACTED]". That protects Rust only. UniFFI does not
// look at Rust trait impls when it generates bindings, so on their own the
// Kotlin and Swift versions of the same record print everything:
//
//   Kotlin  data class KeyPair(var publicKey: String, var privateKey: String)
//           - a data class with no toString() override gets a compiler-generated
//             one that prints every property, so `Log.d(TAG, "$keyPair")` writes
//             the X25519 private key to logcat (and into any bug report).
//   Swift   public struct KeyPair: Equatable, Hashable
//           - no CustomStringConvertible, so `"\(keyPair)"` falls back to
//             reflection, which also dumps every stored property.
//
// `#[uniffi::export(Debug, Display)]` on a record closes that. UniFFI emits FFI
// shims for the two traits and the binding templates wire them up:
//
//   Kotlin  override fun toString() inside the data class - an explicit
//           toString() suppresses the data-class-generated one, so every
//           interpolation and every Log call routes into the Rust impl.
//   Swift   CustomDebugStringConvertible + CustomStringConvertible, i.e.
//           debugDescription and description, which is what String(describing:),
//           "\(x)", print() and debugPrint() all resolve to.
//
// So the redaction is the DEFAULT rendering on all three sides rather than
// something each call site has to get right. It is not a substitute for not
// logging key material: a caller that reaches for the field itself
// ("$data.privateKey") is still asking for the secret and still gets it.
//
// Both traits are exported deliberately. Debug alone would be enough for Kotlin
// (its template falls back to the Debug shim when Display is absent) and would
// mostly work for Swift, but only via Swift's CustomDebugStringConvertible
// fallback. Exporting both means `description` and `debugDescription` are each
// defined outright and neither printing path depends on a fallback.
// ---------------------------------------------------------------------------

/// Give a type a `Display` that is exactly its redacting `Debug`.
///
/// `#[uniffi::export(Debug, Display)]` requires both traits to exist on the Rust
/// side. Writing the redaction out a second time as a `Display` impl would only
/// create a second place to forget a field when one is added, so `Display`
/// forwards to `Debug` and each type's redaction keeps a single definition.
macro_rules! redacted_display_via_debug {
    ($($t:ty),+ $(,)?) => {$(
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(self, f)
            }
        }
    )+};
}
pub(crate) use redacted_display_via_debug;

/// Log levels for the SDK
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Encrypted data wrapper (nonce + ciphertext as hex strings)
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct EncryptedData {
    pub nonce: String,
    pub ciphertext: String,
}

/// Location data (plaintext before encryption)
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
    pub speed: Option<f64>,
    pub heading: Option<f64>,
    pub accuracy: Option<f64>,
    pub timestamp: i64, // Unix timestamp in milliseconds
    /// Battery level as percentage (0-100), provided by platform
    pub battery_level: Option<u8>,
    pub is_charging: Option<bool>,
}

/// A decrypted location plus whether the sender's per-circle USER pseudonym
/// was cryptographically verified (AAD-v3 sender-binding).
///
/// `sender_verified` is true ONLY when the ciphertext's AEAD tag validated under
/// the caller's `claimed_pseudonym` — proving a malicious server did NOT relabel
/// member A's ciphertext under member B's user pseudonym. false means the value
/// decrypted through the legacy (unbound v2/v1) fallback: still authentic circle
/// data, but the sender attribution is server-asserted, not cryptographically
/// bound. Confidentiality holds either way.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct BoundLocation {
    pub location: Location,
    pub sender_verified: bool,
    /// The circle-key version that opened this row: the version whose key
    /// opened the payload, or unwrapped its message key, or that its session
    /// key was opened under. The row is CURRENT only if
    /// `is_current_key_version` says so for its circle; else it is history:
    /// never live, never a "last seen", never place-alert input. The default
    /// is for constructors in app code only; the SDK always sets it.
    #[uniffi(default = 0)]
    #[serde(default)]
    pub key_version: i32,
}

/// A decrypted text (a field, a place key in hex, a place's payload) and the
/// circle-key version that opened it. For LIVE data, CURRENT only if
/// `is_current_key_version` says so; durable config (place keys, alert
/// rules, inactivity alerts, names) keeps its own app policy.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct OpenedText {
    pub text: String,
    pub key_version: i32,
}

/// A decrypted location and the circle-key version that opened it: CURRENT
/// only if `is_current_key_version` says so for its circle.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct OpenedLocation {
    pub location: Location,
    pub key_version: i32,
}

/// Encrypted location ready for transmission
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct EncryptedLocation {
    pub location: EncryptedData,
    pub timestamp: i64,
    pub user_id: String,
    pub device_id: String,
}

/// A single key wrap entry: the msg_key encrypted for a specific circle or self-tracking key.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct KeyWrap {
    /// Circle ID or "self" / nil UUID for self-tracking
    pub target_id: String,
    /// Hex-encoded nonce used for wrapping
    pub wrapped_key_nonce: String,
    /// Hex-encoded wrapped (encrypted) msg_key
    pub wrapped_key: String,
}

/// Result of envelope encryption: one ciphertext + per-target key wraps.
///
/// The location data is encrypted ONCE with a random msg_key.
/// The msg_key is then wrapped (encrypted) separately for each target (circle + self).
/// This is more efficient than encrypting the location N times.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct EnvelopeEncryptedLocation {
    /// The location ciphertext (encrypted once with msg_key)
    pub ciphertext: String,
    /// The nonce used for the location ciphertext
    pub ciphertext_nonce: String,
    /// The timestamp from the original location (for metadata)
    pub timestamp: i64,
    /// Per-target key wraps (one per circle + self)
    pub key_wraps: Vec<KeyWrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct Circle {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// The user's X25519 keypair, used for key sharing (ECDH wrapping). The
/// Ed25519 identity-signing keypair is `SigningKeyPair`.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// this file.
#[uniffi::export(Debug, Display)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

// SECURITY: Custom Debug impl to prevent private key leakage in logs/panics
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Ed25519 identity-signing keypair returned by `generate_signing_keypair`.
///
/// Distinct from `KeyPair` (which is X25519 for sharing). Encoded as
/// base64 standard alphabet for symmetry with the rest of the SDK's
/// cross-platform encoding.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// this file.
#[uniffi::export(Debug, Display)]
pub struct SigningKeyPair {
    /// 32-byte verifying key. Sent to the auth backend as `signing_public_key`.
    pub verifying_key_b64: String,
    /// 32-byte secret seed. Caller must encrypt this under the master key
    /// before shipping it to the auth backend as `encrypted_signing_private_key`.
    pub secret_seed_b64: String,
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("verifying_key_b64", &self.verifying_key_b64)
            .field("secret_seed_b64", &"[REDACTED]")
            .finish()
    }
}

/// User and device pseudonym pair for privacy-preserving location sharing
#[derive(Debug, Clone, uniffi::Record)]
pub struct PseudonymPair {
    pub user_pseudonym: String,
    pub device_pseudonym: String,
}

/// Entry for GDPR-compliant location deletion
/// Contains circle_id and the user's pseudonym for that circle
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeletionPseudonym {
    pub circle_id: String,
    pub user_pseudonym: String,
}

/// Data needed to create a new circle (client-side key generation)
#[derive(Debug, Clone, uniffi::Record)]
pub struct CircleCreationData {
    /// The circle key encrypted for the creator's public key
    pub encrypted_circle_key: EncryptedData,
    /// The ephemeral public key used for ECDH
    pub ephemeral_public_key: String,
    /// Temporary circle ID for local key storage until server returns real ID
    pub temp_circle_id: String,
}

/// Circle key wrapped for a specific member (used during key rotation)
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberKeyBundle {
    /// The circle key encrypted for this member's public key
    pub encrypted_circle_key: EncryptedData,
    /// The ephemeral public key used for ECDH key wrapping
    pub ephemeral_public_key: String,
    /// Hex-encoded Ed25519 signature (128 chars / 64 bytes) over the wrap context.
    /// Empty string for legacy installs that have no signing key loaded.
    pub wrap_signature: String,
}

/// Key derivation function parameters (Argon2id)
#[derive(Debug, Clone, uniffi::Record)]
pub struct KdfParams {
    /// Base64-encoded salt
    pub salt: String,
    /// Memory size in KiB (minimum 19 MiB = 19456 KiB for security)
    pub memory_kib: u32,
    /// Number of iterations (minimum 2 for security)
    pub iterations: u32,
    /// Degree of parallelism (1-8)
    pub parallelism: u32,
}

/// Minimum KDF parameters for security (OWASP 2024 recommendations)
pub const MIN_KDF_MEMORY_KIB: u32 = 19456;   // 19 MiB minimum (OWASP 2024 Argon2id floor)
pub const MIN_KDF_ITERATIONS: u32 = 2;       // Minimum iterations
pub const MAX_KDF_MEMORY_KIB: u32 = 262144;  // 256 MiB mobile ceiling (DoS prevention)
pub const MAX_KDF_ITERATIONS: u32 = 10;      // Maximum iterations (mobile ceiling, DoS prevention)
pub const MAX_KDF_PARALLELISM: u32 = 8;      // Maximum parallelism

impl KdfParams {
    /// # Errors
    /// Rejects parameters below the OWASP 2024 Argon2id floor (too weak) and
    /// above the mobile ceiling (a caller-supplied DoS vector).
    pub fn validate(&self) -> Result<(), MobileError> {
        if self.memory_kib < MIN_KDF_MEMORY_KIB {
            return Err(MobileError::InvalidInput(format!(
                "KDF memory too low: {} KiB (minimum {} KiB / 19 MiB)",
                self.memory_kib, MIN_KDF_MEMORY_KIB
            )));
        }
        if self.memory_kib > MAX_KDF_MEMORY_KIB {
            return Err(MobileError::InvalidInput(format!(
                "KDF memory too high: {} KiB (maximum {} KiB / 256 MiB)",
                self.memory_kib, MAX_KDF_MEMORY_KIB
            )));
        }
        if self.iterations < MIN_KDF_ITERATIONS {
            return Err(MobileError::InvalidInput(format!(
                "KDF iterations too low: {} (minimum {})",
                self.iterations, MIN_KDF_ITERATIONS
            )));
        }
        if self.iterations > MAX_KDF_ITERATIONS {
            return Err(MobileError::InvalidInput(format!(
                "KDF iterations too high: {} (maximum {})",
                self.iterations, MAX_KDF_ITERATIONS
            )));
        }
        if self.parallelism == 0 || self.parallelism > MAX_KDF_PARALLELISM {
            return Err(MobileError::InvalidInput(format!(
                "KDF parallelism must be 1-{} (got {})",
                MAX_KDF_PARALLELISM, self.parallelism
            )));
        }
        Ok(())
    }
}

/// Error types for the mobile SDK (exposed to Swift/Kotlin via UniFFI)
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key format")]
    InvalidKey,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Session key not found: {0}")]
    SessionKeyNotFound(String),

    #[error("Signature verification failed")]
    SignatureInvalid,
}

/// An error a platform callback threw that is not a `MobileError` (a Swift or
/// Kotlin error of its own, such as a Keychain status): UniFFI converts it
/// with this, and without it PANICS inside the SDK, which skips whatever the
/// failing call would have recorded (a load's LOAD_FAILED). A fixed text: the
/// platform's own words can quote what failed to decrypt.
impl From<uniffi::UnexpectedUniFFICallbackError> for MobileError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        MobileError::StorageError("the platform callback failed".to_string())
    }
}

impl From<serde_json::Error> for MobileError {
    fn from(e: serde_json::Error) -> Self {
        MobileError::SerializationError(e.to_string())
    }
}

impl From<base64::DecodeError> for MobileError {
    fn from(_: base64::DecodeError) -> Self {
        MobileError::InvalidKey
    }
}

impl From<hex::FromHexError> for MobileError {
    fn from(_: hex::FromHexError) -> Self {
        MobileError::InvalidKey
    }
}

/// Result of encrypting with session key (includes key_id for the location record)
#[derive(Debug, Clone, uniffi::Record)]
pub struct SessionEncryptedData {
    pub encrypted: EncryptedData,
    /// The key_id to include in the location record: "s:{uuid}" when a session
    /// key sealed it, "c:{version}" for the circle-key fallback. Pass it
    /// verbatim to `LocationManager::send_location`.
    pub key_id: String,
}

/// A member's wrapped key bundle with their user_id
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberKeyRotationEntry {
    pub user_id: String,
    pub bundle: MemberKeyBundle,
}

/// Result of preparing a key rotation
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyRotationBundle {
    /// The new key version
    pub new_key_version: i32,
    /// Circle name re-encrypted with the new key
    pub encrypted_name: EncryptedData,
    /// Wrapped keys for each member
    pub member_keys: Vec<MemberKeyRotationEntry>,
    /// The OUTGOING key sealed under the new one, so a member holding only the
    /// latest key can still walk back and read older ciphertext.
    ///
    /// Load-bearing, not an optimisation: without this link every rotation
    /// orphans everything sealed under earlier versions for anyone who does not
    /// already hold those keys — every web client, every fresh or reinstalled
    /// install, and every member who joins later. They could not even decrypt
    /// the circle name ("decryption failed with all key versions"), while the
    /// device that rotated reads it fine from keys it still holds locally.
    ///
    /// None only when there is no outgoing key to seal — a rotation of a circle
    /// whose current key this device does not hold.
    pub key_chain_link: Option<KeyChainLinkData>,
}

/// A key chain link: encrypts a previous key version with a newer key.
/// Lets new members derive old keys for historical data access.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyChainLinkData {
    pub from_version: i32,
    pub to_version: i32,
    pub encrypted_key: String, // hex-encoded
    pub nonce: String,         // hex-encoded
}

/// Data needed to publish a session key to the server
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishSessionKeyData {
    /// Unique session key identifier (UUID)
    pub session_key_id: String,
    /// Hex-encoded encrypted session key (encrypted with circle key)
    pub encrypted_session_key: String,
    /// Hex-encoded nonce used for encryption
    pub key_nonce: String,
    /// Circle key version this session key is encrypted under
    pub key_version: i32,
    /// Unix timestamp (seconds) when session key expires
    pub expires_at: i64,
}

/// What the last load of the key store found (`CryptoManager::key_store_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyStoreLoad {
    /// No load has run in this process.
    NotLoaded,
    /// Nothing is stored (a first launch).
    NothingStored,
    /// The store's contents are known: loaded, written here, or cleared.
    Loaded,
    /// The platform's read failed (the Keychain before the first unlock after
    /// a reboot, say). Load again later; nothing is written until a load
    /// succeeds.
    ReadFailed,
    /// The store was read but doesn't decode. Nothing is written over it. At an
    /// explicit sign-in, if a load again gives this, `clear_all_keys` and then
    /// import the account's keys.
    DoesNotDecode,
    /// `clear_all_keys` cleared memory but the platform's delete failed: the
    /// store may still hold what was cleared. Nothing is written or loaded until
    /// a clear succeeds. Remember that a wipe is owed, and call `clear_all_keys`
    /// again (at the next launch, before any load).
    DeleteFailed,
}

/// The key store's state for the app: what the last load found, and
/// whether this device keeps stored entries it could not read.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyStoreStatus {
    pub load: KeyStoreLoad,
    /// A stored signing seed that doesn't install is kept as stored: this
    /// device signs nothing until a seed is imported. Ask the person to sign
    /// in again.
    pub signing_seed_unreadable: bool,
    /// Stored entries that didn't read here are kept as stored, and what they
    /// guarded stays strict: a circle whose record state didn't read waits, a
    /// mark that didn't read marks every version of its circle, a circle key
    /// that didn't read keeps its version from other copies. Ask the person to
    /// sign in again; at that sign-in, `drop_unreadable_entries`.
    pub entries_unreadable: bool,
}

/// Stored key data for persistence
#[derive(Clone, Serialize, Deserialize, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// this file. This is the worst of the three to leak: private key, every circle
// key, and the Ed25519 seed in one record.
#[uniffi::export(Debug, Display)]
pub struct StoredKeyData {
    /// User's X25519 private key (base64)
    pub private_key: String,
    /// Circle keys: JSON map of circle_id -> { version -> base64-encoded key }
    pub circle_keys_json: String,
    /// TOFU-pinned per-member key records: JSON map of "{circle_id}:{user_id}" -> PinRecord.
    /// `None` on installs predating key pinning; those clients read as "no pins yet".
    #[serde(default)]
    pub pinned_keys_json: Option<String>,
    /// User's Ed25519 signing private key as 32-byte secret seed, base64-encoded.
    /// `None` on installs predating wrap signatures. Clients without a signing key
    /// emit empty `wrap_signature` strings.
    #[serde(default)]
    pub signing_private_key_b64: Option<String>,
}

// SECURITY: Custom Debug impl to prevent private key and circle key leakage in logs/panics
impl std::fmt::Debug for StoredKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKeyData")
            .field("private_key", &"[REDACTED]")
            .field("circle_keys_json", &"[REDACTED]")
            .field("pinned_keys_json", &if self.pinned_keys_json.is_some() { "<set>" } else { "<none>" })
            .field("signing_private_key_b64", &"[REDACTED]")
            .finish()
    }
}

redacted_display_via_debug!(KeyPair, SigningKeyPair, StoredKeyData);

/// TOFU-pinned record of a member's public keys for a specific circle.
///
/// Stored locally only — the server never sees pinned keys. On first sight of a member's
/// keys the SDK records them; subsequent sightings are compared. A divergence forces
/// the user to explicitly approve via `approve_member_key_change` before the new keys
/// are accepted.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct PinRecord {
    /// Hex-encoded X25519 sharing public key (64 chars / 32 bytes).
    pub sharing_pubkey_hex: String,
    /// Hex-encoded Ed25519 signing public key (64 chars / 32 bytes).
    pub signing_pubkey_hex: String,
    /// Unix timestamp (seconds) when the pin was first recorded.
    pub first_pinned_at: i64,
    /// Unix timestamp (seconds) of the last successful match (Matched state).
    pub last_verified_at: i64,
    /// Unix timestamp (seconds) of the last user-approved key change, if any.
    pub user_approved_change_at: Option<i64>,
}

/// State returned by `pin_member_keys` describing the outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, uniffi::Enum)]
pub enum PinState {
    /// First time any keys are seen for this (circle, user) — pin recorded.
    NewPinning,
    /// Both keys match the existing pin — `last_verified_at` was bumped.
    Matched,
    /// Sharing key differs from the pin (signing matches). User approval required.
    ChangedSharing,
    /// Signing key differs from the pin (sharing matches). User approval required.
    ChangedSigning,
    /// Both keys differ from the pin. User approval required.
    ChangedBoth,
}

/// Whether this device should adopt the server's copy of the account's
/// personal key and, if not, why not: the FIRST check that fails, in this
/// order: malformed input, nothing recorded, (a) a copy in use here
/// already matches, the record names a key retired here, (c) not signed by
/// this account, cannot be opened here, the copy IS a key retired here, (b)
/// not the recorded key, a newer version held here, an adoption less than 24
/// hours ago.
///
/// (a), (b) and (c) are the conditions listed on
/// `check_personal_key_adoption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PersonalKeyVerdict {
    /// (a), (b) and (c) all hold: adopt it with `adopt_personal_key`.
    Adopt,
    /// (a) A personal key in use here (either slot) derives the recorded
    /// pseudonym. Nothing to adopt.
    OwnCopyMatches,
    /// The record, or the served copy, is a key this device RETIRED. It is
    /// never adopted again.
    RetiredKey,
    /// The account has no recorded pseudonym, so there is nothing to check a
    /// copy against.
    NothingRecorded,
    /// This device does not hold the account's signing key, so (c) cannot be
    /// checked. The account's keys have to be unlocked here first.
    NoSigningKey,
    /// (c) The copy carries no signature. Refused.
    Unsigned,
    /// (c) The copy's signature does not verify under this account's own
    /// signing key: a key somebody else chose. Refused; log it.
    SignatureInvalid,
    /// The copy is not wrapped to this account's keys (current or recovered),
    /// so it cannot be opened here.
    CannotOpen,
    /// (b) The copy does not derive the recorded pseudonym.
    PseudonymMismatch,
    /// This device holds a newer personal-key version than the copy, so
    /// adopting it would not make it the key in use.
    NewerVersionHeld,
    /// This device adopted a copy less than 24 hours ago. Try again later.
    TooSoon,
    /// Malformed input: bad hex or lengths, or a version outside 1..=1000000.
    Malformed,
}

/// What the device whose personal key IS the recorded one finds in the
/// server's PUBLISHED copy (see `check_published_personal_copy`). Only
/// `CannotOpen` and `Unsigned` may lead to a republish or a signature,
/// and never of a key taken on trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PublishedCopyStatus {
    /// It opens to the key in use here and carries this account's valid
    /// signature. Nothing to do.
    Opens,
    /// It opens to the key in use here but carries no valid signature from
    /// this account: sign it (`sign_own_circle_key_wrap`) or republish.
    Unsigned,
    /// It does not open with this account's CURRENT keys: republish
    /// (`publishable_personal_key`).
    CannotOpen,
    /// It opens to a DIFFERENT key: adoption's business, never a republish.
    OpensToDifferentKey,
    /// This device holds no personal key.
    NoKeyHere,
    /// This device holds no signing key, so the signature cannot be checked.
    NoSigningKey,
    /// Malformed input: bad hex or lengths, or a version outside 1..=1000000.
    Malformed,
}

/// A copy of this device's personal key ready to PUBLISH: wrapped to the
/// account and signed by it, with the account's pseudonym under exactly
/// this key, for the server to store together with these bytes.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishablePersonalKey {
    /// The wrap: nonce and ciphertext, hex.
    pub encrypted_key: EncryptedData,
    /// The wrap's ephemeral X25519 public key, hex.
    pub ephemeral_public_key: String,
    /// The personal key's version (1).
    pub key_version: i32,
    /// This account's signature over the wrap, for the nil UUID. Never empty.
    pub wrap_signature: String,
    /// The account's pseudonym under exactly this key.
    pub user_pseudonym: String,
}

/// Result of a TOFU pin lookup for a circle member.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PinResult {
    pub state: PinState,
    /// Unix timestamp of the previous pin's `first_pinned_at`, or 0 if `state == NewPinning`.
    pub previous_pinned_at: i64,
}

/// Parameters describing the wrap context for the `pingolin.sig.v1.*` signature scheme.
///
/// All UUID-bearing fields are 32-char hex (Uuid hex form). `recipient_user_id`,
/// `circle_id`, and `place_id` may be empty strings when not applicable to a domain.
/// `key_version` is `0` when not applicable (e.g. place owner wrap, place share wrap).
/// `ephemeral_pubkey_hex` may be empty (e.g. circle member wrap uses ECDH-issued
/// ephemeral; place key wrap doesn't use one).
///
/// All hex strings are decoded via the same flexible decoder used elsewhere in the
/// SDK; the 16/32-byte length checks happen during signature input construction.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignWrapParams {
    /// Domain string (e.g. "pingolin.sig.v1.circle_member_wrap"); locked per call site.
    pub domain: String,
    /// Sender user ID (UUID, 32-char hex).
    pub sender_user_id: String,
    /// Recipient user ID (UUID, 32-char hex). Empty string if not applicable.
    pub recipient_user_id: String,
    /// Circle ID (UUID, 32-char hex). Empty string if not applicable.
    pub circle_id: String,
    /// Place ID (UUID, 32-char hex). Empty string if not applicable.
    pub place_id: String,
    /// Circle/place key version, or 0 if not applicable.
    pub key_version: u32,
    /// Hex-encoded ephemeral public key (32 bytes / 64 chars). Empty string if not applicable.
    pub ephemeral_pubkey_hex: String,
    /// Hex-encoded wrap nonce (24 bytes / 48 chars).
    pub wrap_nonce_hex: String,
    /// Hex-encoded wrap ciphertext (msg key 32B + AEAD tag 16B = 48 bytes / 96 chars).
    pub wrap_ciphertext_hex: String,
}

/// What a platform storage callback (`KeyStorageCallback`,
/// `SecureStorageCallback`) throws when it fails. Any other error it
/// throws, a `MobileError` included, reaches the SDK as `Failed` too,
/// never as a panic: this type is not flat, so UniFFI lifts it, and an
/// undeclared error converts to it. It carries no text: the platform's own
/// words can quote what failed to decrypt.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum StorageCallbackError {
    #[error("the platform's storage failed")]
    Failed,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for StorageCallbackError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        StorageCallbackError::Failed
    }
}

impl From<StorageCallbackError> for MobileError {
    fn from(_: StorageCallbackError) -> Self {
        MobileError::StorageError("the platform callback failed".to_string())
    }
}

/// Callback interface platforms implement to provide secure storage for the
/// SDK's cryptographic keys.
///
/// A failure THROWS, whatever the error (`StorageCallbackError.Failed` is the
/// declared one; any other arrives as it): a read that failed must never
/// return `None`, which means nothing is stored.
#[uniffi::export(callback_interface)]
pub trait KeyStorageCallback: Send + Sync {
    /// This carries private key material. The implementation MUST encrypt it
    /// at rest: EncryptedSharedPreferences with AES-256-GCM on Android,
    /// Keychain with kSecAttrAccessibleAfterFirstUnlock on iOS.
    fn store_keys(&self, data: StoredKeyData) -> Result<(), StorageCallbackError>;

    /// `None` means no keys are stored yet (first launch), not an error.
    fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError>;

    /// Delete all stored keys (logout)
    fn delete_keys(&self) -> Result<(), StorageCallbackError>;
}

/// Alert conditions for client-side evaluation
///
/// Contains all the parameters needed to determine if an alert should fire.
/// This struct is encrypted on the server and only decrypted by clients
/// with the circle key.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct AlertConditions {
    /// For place alerts: alert when entering geofence
    pub alert_on_arrival: Option<bool>,
    /// For place alerts: alert when leaving geofence
    pub alert_on_departure: Option<bool>,
    /// Days of week the alert is active (e.g., ["monday", "tuesday"])
    pub active_days: Option<Vec<String>>,
    /// Start time of active window (HH:MM format)
    pub active_start_time: Option<String>,
    /// End time of active window (HH:MM format)
    pub active_end_time: Option<String>,
    /// User's timezone for schedule evaluation
    pub timezone: Option<String>,
    /// For inactivity alerts: minutes of inactivity before alerting
    pub timeout_minutes: Option<i32>,
    /// For inactivity alerts: minimum minutes between alerts
    pub cooldown_minutes: Option<i32>,
}

/// Result of client-side alert evaluation
#[derive(Debug, Clone, uniffi::Record)]
pub struct AlertEvaluationResult {
    pub should_fire: bool,
    /// Human-readable explanation, for logs and debugging UI.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A storage callback's failure, whatever the platform throws, lifted the
    /// way UniFFI lifts it: never a panic.
    #[test]
    fn a_storage_callback_failure_lifts_whatever_is_thrown() {
        use uniffi::{Lift, LiftReturn, Lower, RustCallStatus, RustCallStatusCode};
        type Returned = Result<(), StorageCallbackError>;
        // The declared error, lowered as the foreign side lowers it.
        let thrown = <StorageCallbackError as Lower<crate::UniFfiTag>>::lower_into_rust_buffer(StorageCallbackError::Failed);
        let status = RustCallStatus { code: RustCallStatusCode::Error, error_buf: std::mem::ManuallyDrop::new(thrown) };
        assert!(matches!(<Returned as LiftReturn<crate::UniFfiTag>>::lift_foreign_return((), status), Err(StorageCallbackError::Failed)));
        // A MobileException, or any error of the platform's own: undeclared.
        for thrown in ["MobileException.StorageException: stored keys", "KeychainKeyStorageError.osStatus(-25308)"] {
            let lifted = <Returned as LiftReturn<crate::UniFfiTag>>::handle_callback_unexpected_error(
                uniffi::UnexpectedUniFFICallbackError::new(thrown),
            );
            assert!(matches!(lifted, Err(StorageCallbackError::Failed)), "{thrown}");
        }
        // Why the callbacks don't declare MobileError: a flat error thrown back
        // can't be lifted, and the lift panics.
        let flat = <MobileError as Lower<crate::UniFfiTag>>::lower_into_rust_buffer(MobileError::StorageError("x".into()));
        assert!(std::panic::catch_unwind(|| <MobileError as Lift<crate::UniFfiTag>>::try_lift_from_rust_buffer(flat)).is_err());
        // And the SDK reads the callback's failure as a storage error.
        assert!(matches!(MobileError::from(StorageCallbackError::Failed), MobileError::StorageError(ref text) if text == "the platform callback failed"));
    }

    /// A callback's own error, lifted the way UniFFI lifts it: a storage error
    /// with the fixed text, never a panic, and never the platform's words.
    #[test]
    fn a_callbacks_own_error_is_a_storage_error_never_a_panic() {
        use uniffi::LiftReturn;
        let lifted = <Result<Option<StoredKeyData>, MobileError> as LiftReturn<crate::UniFfiTag>>::handle_callback_unexpected_error(
            uniffi::UnexpectedUniFFICallbackError::new("osStatus(-25308): platform words"),
        );
        match lifted {
            Err(MobileError::StorageError(text)) => assert_eq!(text, "the platform callback failed"),
            other => panic!("not a storage error: {:?}", other.err()),
        }
    }

    /// Assert that every way a secret-bearing record can be rendered hides the
    /// given secrets and says it did.
    ///
    /// The four renderings are not redundant. `{:?}` and `{}` are the Rust
    /// traits; `uniffi_trait_debug`/`uniffi_trait_display` are the shims
    /// `#[uniffi::export(Debug, Display)]` generates, and those are what Kotlin's
    /// `toString()` and Swift's `description`/`debugDescription` actually call.
    /// Naming the shims here is the point of the test: delete the export
    /// attribute and this stops COMPILING, rather than silently going back to
    /// printing private keys on the phones.
    macro_rules! assert_redacted {
        ($value:expr, [$($secret:expr),+ $(,)?]) => {{
            let value = $value;
            let renderings = [
                ("Debug", format!("{:?}", value)),
                ("Display", format!("{}", value)),
                ("uniffi_trait_debug (Kotlin/Swift)", value.uniffi_trait_debug()),
                ("uniffi_trait_display (Kotlin/Swift)", value.uniffi_trait_display()),
            ];
            for (how, rendered) in &renderings {
                $(
                    assert!(
                        !rendered.contains($secret),
                        "{how} leaked {}: {rendered}",
                        stringify!($secret),
                    );
                )+
                assert!(
                    rendered.contains("[REDACTED]"),
                    "{how} produced no redaction marker: {rendered}",
                );
            }
        }};
    }

    // Long and distinctive so a `contains` check cannot collide with a field
    // name, a type name, or the redaction marker itself.
    const SECRET_A: &str = "aaaaSECRETPRIVATEKEYMATERIALaaaa";
    const SECRET_B: &str = "bbbbSECRETCIRCLEKEYMATERIALbbbb";
    const SECRET_C: &str = "ccccSECRETSIGNINGSEEDMATERIALcccc";

    #[test]
    fn key_pair_never_renders_its_private_key() {
        assert_redacted!(
            KeyPair {
                public_key: "public-key-is-fine-to-print".into(),
                private_key: SECRET_A.into(),
            },
            [SECRET_A]
        );
    }

    #[test]
    fn signing_key_pair_never_renders_its_seed() {
        assert_redacted!(
            SigningKeyPair {
                verifying_key_b64: "verifying-key-is-fine-to-print".into(),
                secret_seed_b64: SECRET_C.into(),
            },
            [SECRET_C]
        );
    }

    /// The worst of the three to leak: the X25519 private key, every circle key,
    /// and the Ed25519 seed all in one record.
    #[test]
    fn stored_key_data_never_renders_any_of_its_three_secrets() {
        assert_redacted!(
            StoredKeyData {
                private_key: SECRET_A.into(),
                circle_keys_json: SECRET_B.into(),
                // Pinned keys are public keys, but the Debug impl summarises
                // rather than printing them; hold that.
                pinned_keys_json: Some("dddd-PINNED-KEY-CONTENTS-dddd".into()),
                signing_private_key_b64: Some(SECRET_C.into()),
            },
            [SECRET_A, SECRET_B, SECRET_C, "dddd-PINNED-KEY-CONTENTS-dddd"]
        );
    }

    /// A redaction that hid everything would pass the tests above while making
    /// the records useless to debug with — and would hide a `KeyPair` whose
    /// public and private keys had been swapped. The public half must survive.
    #[test]
    fn redaction_still_leaves_the_public_fields_readable() {
        let rendered = format!(
            "{:?}",
            KeyPair {
                public_key: "eeee-PUBLIC-KEY-eeee".into(),
                private_key: SECRET_A.into(),
            }
        );
        assert!(rendered.contains("eeee-PUBLIC-KEY-eeee"), "{rendered}");
        assert!(rendered.contains("KeyPair"), "{rendered}");
    }
}
