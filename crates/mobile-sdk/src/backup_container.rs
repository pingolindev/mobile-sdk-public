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

//! The Pingolin encrypted-backup container, as the web writes it.
//!
//! WHY THIS IS HERE RATHER THAN IN EACH APP
//!   The format is a JSON envelope whose header is bound in as AEAD associated
//!   data — and the AAD is the header serialised by `JSON.stringify`, so it is
//!   sensitive to key ORDER and to exact byte output. Two hand-written ports,
//!   one in Kotlin and one in Swift, would each have to reproduce that byte for
//!   byte, and the failure mode when one does not is a file that opens on the
//!   platform that wrote it and silently refuses everywhere else. One
//!   implementation, shared by every app that links this SDK, removes the
//!   opportunity.
//!
//!   Keep in step with the web implementations of this format (the Track web
//!   app's and the Note web editor's).
//!
//! WHAT IT IS
//!   Payload sealed with XChaCha20-Poly1305 under a key derived from the
//!   passphrase with Argon2id. The KDF parameters travel in the header so
//!   raising them later does not orphan existing files. Sealing is OPT-IN: a
//!   plaintext export is what makes portability work, and a passphrase is what
//!   turns a portability export into a backup worth keeping.
//!
//! LIBSODIUM COMPATIBILITY
//!   The web calls libsodium's `crypto_pwhash` with ALG_ARGON2ID13. That is
//!   Argon2id v1.3 with parallelism fixed at 1, `opslimit` as the iteration
//!   count and `memlimit` in BYTES. The `argon2` crate takes `m_cost` in KiB,
//!   hence the header carrying `memoryKib` and this passing it straight
//!   through. Getting either wrong yields a different key and a file that never
//!   opens, which the round-trip test against a web-generated vector catches.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};

pub const CONTAINER_FORMAT: &str = "pingolin-encrypted-backup";
pub const CONTAINER_VERSION: u32 = 1;
/// Deliberately heavier than the login KDF: this runs once per export rather
/// than on every sign-in, and the file it protects outlives sessions and
/// travels.
pub const KDF_MEMORY_KIB: u32 = 65_536;
pub const KDF_ITERATIONS: u32 = 3;
/// The only KDF and cipher this build understands. Named once so `seal_backup`
/// and `open_backup` cannot drift apart, and so the strings written into the
/// header are literally the strings checked on the way back in.
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER: &str = "xchacha20poly1305-ietf";
/// Bounds on the KDF parameters a FILE may declare.
///
/// The header carries `memoryKib` and `iterations` so raising them later does
/// not orphan existing files — which also means both numbers are supplied by
/// whoever wrote the file, and a file arrives from a share sheet, not from us.
/// `Params::new` accepts an `m_cost` up to `u32::MAX`, so an unbounded header
/// is an instruction to allocate up to 4 TiB before the AEAD tag is ever
/// checked: on a phone the app is OOM-killed, which reads to the user as "the
/// importer crashes on this file" rather than as a hostile backup.
///
/// These MUST match the web implementation's bounds — two readers of one
/// format that disagree about which files are openable produce a backup
/// which opens on the web and not on the phone.
const MIN_KDF_MEMORY_KIB: u32 = 8_192;
const MAX_KDF_MEMORY_KIB: u32 = 1_048_576;
const MIN_KDF_ITERATIONS: u32 = 1;
const MAX_KDF_ITERATIONS: u32 = 10;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum BackupContainerError {
    #[error("A passphrase is required to encrypt a backup.")]
    MissingPassphrase,
    #[error("That file is not a Pingolin encrypted backup.")]
    NotAContainer,
    #[error("That backup was written by a newer version of Pingolin (format {0}). Update the app, then open it.")]
    FutureVersion(u32),
    #[error("This backup uses encryption this version does not understand.")]
    UnsupportedAlgorithm,
    #[error("This backup declares encryption settings outside the supported range.")]
    UnsupportedKdfParameters,
    #[error("That backup could not be opened. Check the passphrase.")]
    WrongPassphrase,
    #[error("That backup is malformed: {0}")]
    Malformed(String),
}

/// The KDF block, serialised in the order the web writes it.
///
/// Field order here IS the wire format: it feeds `serde_json::to_string`, which
/// preserves declaration order, and that string is the AAD. Reordering these
/// silently breaks every file this has ever written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfHeader {
    pub algorithm: String,
    #[serde(rename = "memoryKib")]
    pub memory_kib: u32,
    pub iterations: u32,
    pub salt: String,
}

/// The header exactly as it is bound into the AEAD.
///
/// `createdAt` is deliberately ABSENT: the web's `headerAad` omits it, so
/// including it here would produce a different AAD and refuse every web-written
/// file. It lives on the envelope but not in the authenticated bytes.
#[derive(Debug, Clone, Serialize)]
struct HeaderAad<'a> {
    format: &'a str,
    #[serde(rename = "formatVersion")]
    format_version: u32,
    product: &'a str,
    kdf: &'a KdfHeader,
    cipher: &'a str,
    nonce: &'a str,
}

/// The whole envelope, as written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedContainer {
    pub format: String,
    #[serde(rename = "formatVersion")]
    pub format_version: u32,
    /// Which product wrote it, so a reader can refuse a Note backup fed to Track.
    pub product: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub kdf: KdfHeader,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
) -> Result<[u8; KEY_BYTES], BackupContainerError> {
    // parallelism = 1 to match libsodium's crypto_pwhash, which fixes it.
    let params = Params::new(memory_kib, iterations, 1, Some(KEY_BYTES))
        .map_err(|e| BackupContainerError::Malformed(format!("bad KDF parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_BYTES];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| BackupContainerError::Malformed(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Whether a file's declared KDF parameters are ones this build will honour.
///
/// Split out from `open_backup` so the boundaries can be asserted directly
/// without standing up a container and paying for a derivation at each one.
fn kdf_params_supported(memory_kib: u32, iterations: u32) -> bool {
    (MIN_KDF_MEMORY_KIB..=MAX_KDF_MEMORY_KIB).contains(&memory_kib)
        && (MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&iterations)
}

fn aad_bytes(c: &EncryptedContainer) -> Result<Vec<u8>, BackupContainerError> {
    let h = HeaderAad {
        format: &c.format,
        format_version: c.format_version,
        product: &c.product,
        kdf: &c.kdf,
        cipher: &c.cipher,
        nonce: &c.nonce,
    };
    serde_json::to_vec(&h)
        .map_err(|e| BackupContainerError::Malformed(format!("could not build header: {e}")))
}

/// Seal a backup document under a passphrase.
///
/// `payload` is the ordinary backup JSON, already serialised — this does not
/// care what is inside it, only that it is the bytes to protect.
pub fn seal_backup(
    payload: &str,
    passphrase: &str,
    product: &str,
    created_at: &str,
) -> Result<String, BackupContainerError> {
    if passphrase.is_empty() {
        return Err(BackupContainerError::MissingPassphrase);
    }

    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
    }

    let key = derive_key(passphrase, &salt, KDF_MEMORY_KIB, KDF_ITERATIONS)?;

    let mut container = EncryptedContainer {
        format: CONTAINER_FORMAT.to_string(),
        format_version: CONTAINER_VERSION,
        product: product.to_string(),
        created_at: created_at.to_string(),
        kdf: KdfHeader {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            salt: B64.encode(salt),
        },
        cipher: CIPHER.to_string(),
        nonce: B64.encode(nonce),
        ciphertext: String::new(),
    };

    let aad = aad_bytes(&container)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| BackupContainerError::Malformed(e.to_string()))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: payload.as_bytes(), aad: &aad },
        )
        .map_err(|_| BackupContainerError::Malformed("encryption failed".into()))?;
    container.ciphertext = B64.encode(ct);

    serde_json::to_string(&container)
        .map_err(|e| BackupContainerError::Malformed(e.to_string()))
}

/// True when this text looks like a sealed container rather than a plain backup.
///
/// Branch on CONTENT, not on the filename: a sealed file comes from the same
/// picker as a plain one.
pub fn is_sealed_backup(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("format").and_then(|f| f.as_str()).map(|s| s == CONTAINER_FORMAT))
        .unwrap_or(false)
}

/// Open a sealed backup, returning the payload JSON.
pub fn open_backup(text: &str, passphrase: &str) -> Result<String, BackupContainerError> {
    let container: EncryptedContainer =
        serde_json::from_str(text).map_err(|_| BackupContainerError::NotAContainer)?;

    if container.format != CONTAINER_FORMAT {
        return Err(BackupContainerError::NotAContainer);
    }
    // A file from a FUTURE version is refused rather than half-read: opening one
    // this build does not understand produces a restore that looks whole and is
    // not.
    if container.format_version > CONTAINER_VERSION {
        return Err(BackupContainerError::FutureVersion(container.format_version));
    }
    // Refuse a KDF or cipher this build does not implement. Both are bound into
    // the AAD, so a swapped label would fail the tag anyway — but only AFTER the
    // derivation below, which is exactly the work being guarded here.
    if container.kdf.algorithm != KDF_ALGORITHM || container.cipher != CIPHER {
        return Err(BackupContainerError::UnsupportedAlgorithm);
    }
    if passphrase.is_empty() {
        return Err(BackupContainerError::MissingPassphrase);
    }
    // Refuse absurd parameters instead of trying to honour them: a hostile file
    // could otherwise ask for gigabytes of Argon2 memory and get the app killed
    // before the tag check ever runs. This must come BEFORE `derive_key` — the
    // point is that an out-of-range request is never attempted.
    if !kdf_params_supported(container.kdf.memory_kib, container.kdf.iterations) {
        return Err(BackupContainerError::UnsupportedKdfParameters);
    }

    let salt = B64
        .decode(&container.kdf.salt)
        .map_err(|_| BackupContainerError::Malformed("salt is not base64".into()))?;
    let nonce = B64
        .decode(&container.nonce)
        .map_err(|_| BackupContainerError::Malformed("nonce is not base64".into()))?;
    if nonce.len() != NONCE_BYTES {
        return Err(BackupContainerError::Malformed("nonce is the wrong length".into()));
    }
    let ct = B64
        .decode(&container.ciphertext)
        .map_err(|_| BackupContainerError::Malformed("ciphertext is not base64".into()))?;

    let key = derive_key(
        passphrase,
        &salt,
        container.kdf.memory_kib,
        container.kdf.iterations,
    )?;
    let aad = aad_bytes(&container)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| BackupContainerError::Malformed(e.to_string()))?;
    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: &aad })
        // A wrong passphrase and a tampered header are indistinguishable here,
        // and both should read as "check the passphrase" rather than as a
        // security accusation the user cannot act on.
        .map_err(|_| BackupContainerError::WrongPassphrase)?;

    String::from_utf8(pt).map_err(|_| BackupContainerError::Malformed("payload is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Written by the web implementation of this format, running under node with
    /// a fixed salt and nonce. This is the whole point of the module: if the
    /// AAD serialisation drifts by one byte — a reordered key, a space, an
    /// omitted field — this stops decrypting, and the alternative to catching
    /// it here is a user whose backup opens on one platform and not another.
    const WEB_VECTOR: &str = r#"{
      "format": "pingolin-encrypted-backup",
      "formatVersion": 1,
      "product": "pingolin-track",
      "createdAt": "2026-08-17T00:00:00.000Z",
      "kdf": {
        "algorithm": "argon2id",
        "memoryKib": 65536,
        "iterations": 3,
        "salt": "BwcHBwcHBwcHBwcHBwcHBw=="
      },
      "cipher": "xchacha20poly1305-ietf",
      "nonce": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ",
      "ciphertext": "gN1ALN222X9cBYMo/3FweyOvsVnyNMdlnIUnLe+XXQsv2oMgHXLrNg=="
    }"#;
    const WEB_PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn opens_a_file_the_web_wrote() {
        let payload = open_backup(WEB_VECTOR, WEB_PASSPHRASE).expect("web vector must open");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["hello"], "world");
        assert_eq!(v["n"], 42);
    }

    #[test]
    fn the_aad_matches_the_web_byte_for_byte() {
        let c: EncryptedContainer = serde_json::from_str(WEB_VECTOR).unwrap();
        let aad = String::from_utf8(aad_bytes(&c).unwrap()).unwrap();
        assert_eq!(
            aad,
            r#"{"format":"pingolin-encrypted-backup","formatVersion":1,"product":"pingolin-track","kdf":{"algorithm":"argon2id","memoryKib":65536,"iterations":3,"salt":"BwcHBwcHBwcHBwcHBwcHBw=="},"cipher":"xchacha20poly1305-ietf","nonce":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ"}"#,
            "the AAD is JSON.stringify of the header — key order and exact bytes are the wire format"
        );
    }

    #[test]
    fn round_trips_its_own_output() {
        let sealed = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "2026-08-17T00:00:00.000Z").unwrap();
        assert!(is_sealed_backup(&sealed));
        assert_eq!(open_backup(&sealed, "hunter2").unwrap(), r#"{"a":1}"#);
    }

    #[test]
    fn a_wrong_passphrase_is_refused_without_accusation() {
        let sealed = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();
        let err = open_backup(&sealed, "wrong").unwrap_err();
        assert!(matches!(err, BackupContainerError::WrongPassphrase), "got {err:?}");
    }

    /// The header is authenticated, so relabelling a Track backup as a Note one
    /// must not produce a file that still opens — that is how a backup ends up
    /// in the wrong product's parser.
    #[test]
    fn tampering_with_the_product_label_breaks_it() {
        let sealed = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();
        let tampered = sealed.replace("pingolin-track", "pingolin-note");
        assert!(open_backup(&tampered, "hunter2").is_err());
    }

    /// Rewrite the KDF numbers a file DECLARES, leaving everything else alone.
    ///
    /// This is what a hostile backup is: an ordinary-looking container whose
    /// header asks the reader to do something enormous. The edit invalidates the
    /// AAD, so a file that clears the gate then fails its tag — which is the
    /// point, because it makes the two outcomes tell apart cleanly. Refused at
    /// the gate is `UnsupportedKdfParameters`; anything else means the gate let
    /// it through and the derivation was attempted.
    fn with_declared_kdf(memory_kib: u32, iterations: u32) -> String {
        let sealed =
            seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();
        let out = sealed
            .replace(
                &format!(r#""memoryKib":{KDF_MEMORY_KIB}"#),
                &format!(r#""memoryKib":{memory_kib}"#),
            )
            .replace(
                &format!(r#""iterations":{KDF_ITERATIONS}"#),
                &format!(r#""iterations":{iterations}"#),
            );
        assert_ne!(out, sealed, "the header rewrite must actually have landed");
        out
    }

    /// A file may ask for any `memoryKib` that fits in a `u32`, and `Params::new`
    /// accepts up to `u32::MAX` — 4 TiB. Honouring that gets the app OOM-killed
    /// on a phone, and it happens BEFORE the AEAD tag would reject the file, so
    /// the tag is no defence at all.
    ///
    /// The assertion is deliberately two-part: the specific gate error, which
    /// nothing downstream can produce, AND a wall-clock budget. Together they say
    /// the request was refused rather than attempted — an attempted derivation
    /// cannot come back in milliseconds, and cannot come back with this variant.
    #[test]
    fn an_absurd_memory_cost_is_refused_rather_than_attempted() {
        for memory_kib in [MAX_KDF_MEMORY_KIB + 1, 4_194_304, u32::MAX] {
            let hostile = with_declared_kdf(memory_kib, KDF_ITERATIONS);
            let started = std::time::Instant::now();
            let err = open_backup(&hostile, "hunter2").unwrap_err();
            let elapsed = started.elapsed();
            assert!(
                matches!(err, BackupContainerError::UnsupportedKdfParameters),
                "memoryKib={memory_kib} reached the KDF instead of the gate: {err:?}"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(1),
                "memoryKib={memory_kib} took {elapsed:?} — that is a derivation, not a refusal"
            );
        }
    }

    /// The same for the iteration count, which is a time cost rather than a
    /// memory one: a file declaring millions of passes hangs the importer.
    #[test]
    fn an_absurd_iteration_count_is_refused_rather_than_attempted() {
        for iterations in [MAX_KDF_ITERATIONS + 1, u32::MAX] {
            let hostile = with_declared_kdf(KDF_MEMORY_KIB, iterations);
            let started = std::time::Instant::now();
            let err = open_backup(&hostile, "hunter2").unwrap_err();
            assert!(
                matches!(err, BackupContainerError::UnsupportedKdfParameters),
                "iterations={iterations} reached the KDF instead of the gate: {err:?}"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "iterations={iterations} was attempted, not refused"
            );
        }
    }

    /// Both sides of every boundary, on the predicate itself.
    ///
    /// Checked here rather than through `open_backup` because proving the TOP of
    /// the range is accepted means letting the derivation run, and at
    /// `MAX_KDF_MEMORY_KIB` that is a gibibyte of Argon2 in a debug build. The
    /// end-to-end tests below pin the gate to `open_backup`; this pins where the
    /// gate sits.
    #[test]
    fn the_supported_range_has_the_web_boundaries_on_both_sides() {
        assert_eq!((MIN_KDF_MEMORY_KIB, MAX_KDF_MEMORY_KIB), (8_192, 1_048_576));
        assert_eq!((MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS), (1, 10));

        // memoryKib: rejected just below, accepted at both ends, rejected above.
        assert!(!kdf_params_supported(MIN_KDF_MEMORY_KIB - 1, KDF_ITERATIONS));
        assert!(kdf_params_supported(MIN_KDF_MEMORY_KIB, KDF_ITERATIONS));
        assert!(kdf_params_supported(MAX_KDF_MEMORY_KIB, KDF_ITERATIONS));
        assert!(!kdf_params_supported(MAX_KDF_MEMORY_KIB + 1, KDF_ITERATIONS));
        assert!(!kdf_params_supported(0, KDF_ITERATIONS));

        // iterations: same, and 0 is rejected as well as the top+1.
        assert!(!kdf_params_supported(KDF_MEMORY_KIB, MIN_KDF_ITERATIONS - 1));
        assert!(kdf_params_supported(KDF_MEMORY_KIB, MIN_KDF_ITERATIONS));
        assert!(kdf_params_supported(KDF_MEMORY_KIB, MAX_KDF_ITERATIONS));
        assert!(!kdf_params_supported(KDF_MEMORY_KIB, MAX_KDF_ITERATIONS + 1));

        // What this SDK itself writes has to stay openable by its own gate.
        assert!(kdf_params_supported(KDF_MEMORY_KIB, KDF_ITERATIONS));
    }

    /// The cheap end of each boundary, end-to-end, so the gate is pinned to
    /// `open_backup` and not merely to the predicate. Inside the range the file
    /// gets as far as its tag — the header rewrite means that tag then fails,
    /// which is a `WrongPassphrase`, NOT a gate refusal.
    #[test]
    fn a_file_inside_the_range_is_not_refused_by_the_gate() {
        // The parameters this SDK writes are not rewritten at all, so that file
        // reaches its tag AND passes it.
        let untouched = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();
        assert_eq!(open_backup(&untouched, "hunter2").unwrap(), r#"{"a":1}"#);

        for (memory_kib, iterations) in [
            (MIN_KDF_MEMORY_KIB, MIN_KDF_ITERATIONS),
            (MIN_KDF_MEMORY_KIB, MAX_KDF_ITERATIONS),
            (MIN_KDF_MEMORY_KIB, KDF_ITERATIONS),
        ] {
            let file = with_declared_kdf(memory_kib, iterations);
            let err = open_backup(&file, "hunter2").unwrap_err();
            assert!(
                matches!(err, BackupContainerError::WrongPassphrase),
                "memoryKib={memory_kib} iterations={iterations} should have reached \
                 the tag, got {err:?}"
            );
        }
        // One below the floor is refused, through the same path, so the pair
        // above is a real boundary rather than a gate that never fires here.
        assert!(matches!(
            open_backup(&with_declared_kdf(MIN_KDF_MEMORY_KIB - 1, KDF_ITERATIONS), "hunter2")
                .unwrap_err(),
            BackupContainerError::UnsupportedKdfParameters
        ));
        assert!(matches!(
            open_backup(&with_declared_kdf(KDF_MEMORY_KIB, MIN_KDF_ITERATIONS - 1), "hunter2")
                .unwrap_err(),
            BackupContainerError::UnsupportedKdfParameters
        ));
    }

    /// A KDF or cipher this build does not implement is refused up front. Both
    /// labels are bound into the AAD, so an unsupported one would fail the tag
    /// eventually — but only after paying for the derivation, and reported as a
    /// wrong passphrase, which sends the user to look for a password that was
    /// never the problem.
    #[test]
    fn an_unknown_algorithm_or_cipher_is_refused_before_any_derivation() {
        let sealed = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();

        let other_kdf = sealed.replace(r#""algorithm":"argon2id""#, r#""algorithm":"scrypt""#);
        assert_ne!(other_kdf, sealed);
        assert!(matches!(
            open_backup(&other_kdf, "hunter2").unwrap_err(),
            BackupContainerError::UnsupportedAlgorithm
        ));

        let other_cipher = sealed.replace(
            r#""cipher":"xchacha20poly1305-ietf""#,
            r#""cipher":"aes-256-gcm""#,
        );
        assert_ne!(other_cipher, sealed);
        assert!(matches!(
            open_backup(&other_cipher, "hunter2").unwrap_err(),
            BackupContainerError::UnsupportedAlgorithm
        ));
    }

    /// The bounds must not narrow the format: the file the WEB wrote opens,
    /// unchanged. `opens_a_file_the_web_wrote` covers the happy path; this
    /// says so specifically about the parameters the web declares.
    #[test]
    fn the_web_vector_declares_parameters_inside_the_range() {
        let c: EncryptedContainer = serde_json::from_str(WEB_VECTOR).unwrap();
        assert_eq!(c.kdf.algorithm, KDF_ALGORITHM);
        assert_eq!(c.cipher, CIPHER);
        assert!(
            kdf_params_supported(c.kdf.memory_kib, c.kdf.iterations),
            "the gate would refuse a file the web wrote"
        );
        assert!(open_backup(WEB_VECTOR, WEB_PASSPHRASE).is_ok());
    }

    #[test]
    fn a_plain_backup_is_not_mistaken_for_a_sealed_one() {
        assert!(!is_sealed_backup(r#"{"export":{"product":"pingolin-track"},"places":[]}"#));
        assert!(!is_sealed_backup("not json at all"));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_half_read() {
        let sealed = seal_backup(r#"{"a":1}"#, "hunter2", "pingolin-track", "now").unwrap();
        let bumped = sealed.replace(r#""formatVersion":1"#, r#""formatVersion":99"#);
        assert!(matches!(
            open_backup(&bumped, "hunter2").unwrap_err(),
            BackupContainerError::FutureVersion(99)
        ));
    }
}


// ---------------------------------------------------------------------------
// UniFFI surface
//
// Thin wrappers rather than exporting the types above directly: the container
// struct is an implementation detail of the format, and what the apps need is
// three verbs over strings — seal this, is this sealed, open this. Errors are
// mapped onto the SDK's existing MobileError so an app has one error type to
// handle rather than two.
// ---------------------------------------------------------------------------

use crate::types::MobileError;

impl From<BackupContainerError> for MobileError {
    fn from(e: BackupContainerError) -> Self {
        // Flat error: the message is what the app shows, and every variant here
        // is already written for a person rather than a log.
        MobileError::CryptoError(e.to_string())
    }
}

/// Seal a backup document under a passphrase, returning the file to write.
///
/// `created_at` is passed in rather than read from the clock so the caller owns
/// the timestamp format and tests are deterministic.
#[uniffi::export]
pub fn seal_backup_file(
    payload: String,
    passphrase: String,
    product: String,
    created_at: String,
) -> Result<String, MobileError> {
    Ok(seal_backup(&payload, &passphrase, &product, &created_at)?)
}

/// Whether a file picked by the user is a sealed container.
///
/// Branch on this rather than on the filename — a sealed backup comes from the
/// same picker as a plain one.
#[uniffi::export]
pub fn is_sealed_backup_file(text: String) -> bool {
    is_sealed_backup(&text)
}

/// Open a sealed backup, returning the payload JSON to hand to the ordinary
/// restore path.
#[uniffi::export]
pub fn open_backup_file(text: String, passphrase: String) -> Result<String, MobileError> {
    Ok(open_backup(&text, &passphrase)?)
}
