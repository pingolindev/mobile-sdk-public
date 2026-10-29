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

//! SRP-6a client helpers exposed to mobile platforms.
//!
//! The auth backend implements the same SRP-6a + Proton-style bcrypt formulas;
//! the two sides MUST agree byte-for-byte or login fails. Having them here gives
//! iOS and Android one shared implementation instead of hand-rolled per-platform
//! SRP code.
//!
//! Contract:
//! - SRP-6a with 2048-bit group (RFC 5054), SHA-256
//! - The `srp` crate's simplified formulas: M1 = H(A | B | K), K = PAD(S)
//! - Password preprocessing: bcrypt(password, bcrypt_salt) before SRP, cost 12
//! - All inputs/outputs are base64 STANDARD (with padding) to match the
//!   server's `base64::engine::general_purpose::STANDARD` round-trips.

use crate::types::{redacted_display_via_debug, MobileError};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bcrypt::{hash_with_salt, DEFAULT_COST};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use srp::client::SrpClient;
use srp::groups::G_2048;
use zeroize::{Zeroize, Zeroizing};

/// Result of generating SRP credentials for registration.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// `types.rs`.
#[uniffi::export(Debug, Display)]
pub struct SrpRegistrationData {
    /// Base64-encoded random 32-byte SRP salt (standard SRP-6a salt `s`).
    pub salt: String,
    /// Base64-encoded verifier `v = g^x mod N`.
    pub verifier: String,
    /// Full bcrypt salt string in MCF form, e.g. `"$2b$12$<22charsalt>"`.
    /// Store this on the server and echo back during login so the client can
    /// reproduce the same preprocessed password.
    pub bcrypt_salt: String,
}

// SECURITY: Custom Debug impl to keep the SRP verifier (v = g^x) out of
// logs/panics. The verifier is password-equivalent (offline-crackable), so it
// must never be printed — even more sensitive than the session key redacted on
// SrpLoginProof below. `salt` and `bcrypt_salt` are public SRP parameters
// (server-stored, echoed back to the client at login), safe to log.
impl std::fmt::Debug for SrpRegistrationData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpRegistrationData")
            .field("salt", &self.salt)
            .field("verifier", &"[REDACTED]")
            .field("bcrypt_salt", &self.bcrypt_salt)
            .finish()
    }
}

/// Result of computing the client's SRP step-2 proof.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// `types.rs`.
#[uniffi::export(Debug, Display)]
pub struct SrpLoginProof {
    /// Base64-encoded client public ephemeral `A = g^a mod N`.
    pub client_public: String,
    /// Base64-encoded SRP client proof `M1 = H(A | B | K)`.
    pub client_proof: String,
    /// Base64-encoded shared session key `K`, derived from the SRP session
    /// and optionally usable for post-auth channel binding. Callers that
    /// don't need it can ignore this field.
    pub session_key: String,
}

// SECURITY: Custom Debug impl to prevent SRP proof (M1) and shared session key
// leakage in logs/panics. `client_public` (A) is a public ephemeral, safe to log.
impl std::fmt::Debug for SrpLoginProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpLoginProof")
            .field("client_public", &self.client_public)
            .field("client_proof", &"[REDACTED]")
            .field("session_key", &"[REDACTED]")
            .finish()
    }
}

redacted_display_via_debug!(SrpRegistrationData, SrpLoginProof);

/// All new SRP registrations use `$2a$` as the bcrypt variant prefix so the
/// server-stored bcrypt_salt matches what the Android client's jBCrypt
/// (`BCrypt.gensalt(12)` → `$2a$…`) produces. The underlying hash bytes are
/// byte-identical across `$2a` / `$2b` / `$2y` variants for the passwords this
/// client can ever receive (UTF-8 ≤ 72 bytes through the UniFFI String path),
/// so only the label needs to be normalized.
const CANONICAL_BCRYPT_PREFIX: &str = "$2a$";

/// Generate SRP-6a registration data for a new account.
///
/// Produces the three values the server's SRP registration request expects:
/// `srp_salt`, `srp_verifier`, and `bcrypt_salt`.
#[uniffi::export]
pub fn srp_generate_registration(
    email: String,
    password: String,
) -> Result<SrpRegistrationData, MobileError> {
    // Wipe the plaintext password from memory when this function returns.
    let password = Zeroizing::new(password);
    // Random 16-byte bcrypt salt. The crate wraps it into a `$2y$<cost>$…`
    // MCF string; we rewrite the prefix below so the preprocessed-password
    // input to SRP matches what Android's jBCrypt would emit for the same
    // salt, guaranteeing cross-platform login.
    let mut bcrypt_salt_bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bcrypt_salt_bytes)
        .map_err(|e| MobileError::CryptoError(format!("rng failed: {e}")))?;

    let raw = Zeroizing::new(
        hash_with_salt(password.as_bytes(), DEFAULT_COST, bcrypt_salt_bytes)
            .map_err(|e| MobileError::CryptoError(format!("bcrypt failed: {e}")))?
            .to_string(),
    );
    let bcrypt_hash = Zeroizing::new(rewrite_mcf_prefix(&raw, CANONICAL_BCRYPT_PREFIX)?);

    // 32-byte SRP salt, matching the Android client.
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let client = SrpClient::<Sha256>::new(&G_2048);
    let identity = email.to_lowercase();
    let verifier = client.compute_verifier(identity.as_bytes(), bcrypt_hash.as_bytes(), &salt);

    let bcrypt_salt_mcf = bcrypt_salt_prefix(&bcrypt_hash).to_string();

    Ok(SrpRegistrationData {
        salt: B64.encode(&salt),
        verifier: B64.encode(&verifier),
        bcrypt_salt: bcrypt_salt_mcf,
    })
}

/// Compute the client proof for SRP login step 2.
///
/// Inputs are the values the server returned in step 1:
/// `salt`, `server_public`, and `bcrypt_salt`. Output is what the client
/// POSTs in step 2 (`client_public`, `client_proof`).
#[uniffi::export]
pub fn srp_compute_login_proof(
    email: String,
    password: String,
    salt_b64: String,
    bcrypt_salt: String,
    server_public_b64: String,
) -> Result<SrpLoginProof, MobileError> {
    // Wipe the plaintext password from memory when this function returns.
    let password = Zeroizing::new(password);
    let salt = decode_b64(&salt_b64, "salt")?;
    let b_pub = decode_b64(&server_public_b64, "server_public")?;

    // Re-run bcrypt with the server-provided salt to derive the same
    // preprocessed password we used during registration.
    let preprocessed = Zeroizing::new(bcrypt_with_mcf_salt(&password, &bcrypt_salt)?);

    let mut a = [0u8; 32];
    OsRng.fill_bytes(&mut a);

    let client = SrpClient::<Sha256>::new(&G_2048);
    let a_pub = client.compute_public_ephemeral(&a);

    let identity = email.to_lowercase();
    let verifier = client
        .process_reply(&a, identity.as_bytes(), preprocessed.as_bytes(), &salt, &b_pub)
        .map_err(|e| MobileError::CryptoError(format!("srp process_reply failed: {e:?}")));
    // Wipe the client ephemeral private scalar now that process_reply has
    // consumed it — on both the success and error paths.
    a.zeroize();
    let verifier = verifier?;

    Ok(SrpLoginProof {
        client_public: B64.encode(&a_pub),
        client_proof: B64.encode(verifier.proof()),
        session_key: B64.encode(verifier.key()),
    })
}

/// The byte encoding a client used for A, B and S when it computed M1. The
/// server answers M2 in the same encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SrpProofEncoding {
    /// The `srp` crate's minimal big-endian bytes, leading zeros dropped: what
    /// `srp_compute_login_proof` uses (both iOS apps).
    Minimal,
    /// Every value left-padded with zeros to the modulus length (256 bytes):
    /// what the web portal and both Android apps use.
    Padded,
}

/// Check the server's proof M2 from SRP step 2 (sign-in, including the
/// two-factor branch, and reauth) BEFORE using anything else the reply
/// carries.
///
/// `client_public_b64` (A), `client_proof_b64` (M1) and `session_key_b64` (S)
/// are this client's own values, e.g. `srp_compute_login_proof`'s
/// `client_public`, `client_proof` and `session_key`. A and S may carry any
/// number of leading zero bytes: they are re-encoded as `encoding` says, which
/// must be the encoding this client's M1 used. `server_proof_b64` is the
/// reply's `server_proof`.
///
/// Returns true only when it is exactly H(A | M1 | S) in that encoding,
/// compared in constant time; a missing, malformed or different M2 is false.
/// An error means this client's own values are malformed.
#[uniffi::export]
pub fn srp_verify_server_proof(
    client_public_b64: String,
    client_proof_b64: String,
    session_key_b64: String,
    server_proof_b64: String,
    encoding: SrpProofEncoding,
) -> Result<bool, MobileError> {
    let a = proof_bytes(&decode_b64(&client_public_b64, "client_public")?, encoding, "client_public")?;
    let m1 = decode_b64(&client_proof_b64, "client_proof")?;
    if m1.len() != 32 {
        return Err(MobileError::InvalidInput("client_proof is not a SHA-256 proof".into()));
    }
    let s = Zeroizing::new(decode_b64(&session_key_b64, "session_key")?);
    let s = Zeroizing::new(proof_bytes(&s, encoding, "session_key")?);
    let Ok(server_m2) = B64.decode(&server_proof_b64) else {
        return Ok(false);
    };
    let expected = Sha256::new().chain_update(&a).chain_update(&m1).chain_update(&*s).finalize();
    Ok(crate::crypto::ct_eq(&expected[..], &server_m2))
}

/// Byte length of the 2048-bit modulus N.
const MODULUS_LEN: usize = 256;

/// `value` (big-endian, any leading zeros) as the proofs hash it: minimal, as
/// `BigUint::to_bytes_be` gives it, or left-padded to the modulus length. A
/// value is in 1..N, so an empty, zero or over-long one is an error.
fn proof_bytes(value: &[u8], encoding: SrpProofEncoding, field: &str) -> Result<Vec<u8>, MobileError> {
    let Some(first) = value.iter().position(|&b| b != 0) else {
        return Err(MobileError::InvalidInput(format!("{field} is empty or zero")));
    };
    let minimal = &value[first..];
    if minimal.len() > MODULUS_LEN {
        return Err(MobileError::InvalidInput(format!("{field} is longer than the modulus")));
    }
    Ok(match encoding {
        SrpProofEncoding::Minimal => minimal.to_vec(),
        SrpProofEncoding::Padded => {
            let mut padded = vec![0u8; MODULUS_LEN - minimal.len()];
            padded.extend_from_slice(minimal);
            padded
        }
    })
}

fn decode_b64(s: &str, field: &str) -> Result<Vec<u8>, MobileError> {
    B64.decode(s).map_err(|_| MobileError::InvalidInput(format!("invalid base64 in {field}")))
}

/// Extract the first three bcrypt "fields" (`$2b$12$<22chars>`) — everything
/// up to and including the 22-char salt portion. Callers store this and feed
/// it back into `hash_with_salt` during login.
fn bcrypt_salt_prefix(mcf: &str) -> &str {
    // MCF form: `$<id>$<cost>$<22-char salt><31-char hash>`.
    // Standard bcrypt salt length is 22 base64 chars, and the prefix before
    // it is always exactly 7 bytes ("$2a$12$"). Return the first 29 bytes.
    const PREFIX_LEN: usize = 7 + 22;
    debug_assert!(mcf.len() >= PREFIX_LEN);
    &mcf[..PREFIX_LEN.min(mcf.len())]
}

/// Parse an MCF-style bcrypt salt (`$2a$12$<22chars>`, `$2b$…`, `$2y$…`)
/// and re-run bcrypt with the given password, returning the full MCF hash
/// string (used as the "preprocessed password" input to SRP).
///
/// The output prefix is normalized to match the INPUT `mcf_salt` prefix.
/// Without this, the `bcrypt` 0.16 crate always returns `$2y$…`, which
/// would mismatch any user registered through jBCrypt (`$2a$…`) and
/// break SRP login for them — a 1-byte difference in the MCF string flows
/// into SRP `x` and the server's `M1` check.
fn bcrypt_with_mcf_salt(password: &str, mcf_salt: &str) -> Result<String, MobileError> {
    // MCF prefix is 7 bytes: `$2<id>$<cc>$`
    let parsed = mcf_salt.strip_prefix("$2").and_then(|s| {
        // The variant char (a/b/x/y) then `$`, then 2-digit cost, then `$`, then
        // salt. `mcf_salt` is server-supplied, so use char-safe operations
        // throughout: a crafted value (e.g. "$2", or a multi-byte char at what
        // would be a byte-split point) must return None, never panic.
        let mut chars = s.chars();
        let variant = chars.next()?; // None when s is empty (mcf_salt == "$2")
        let s = chars.as_str();
        let s = s.strip_prefix('$')?;
        let (cost_str, s) = s.split_at(s.find('$')?); // find('$') is an ASCII boundary
        let cost: u32 = cost_str.parse().ok()?;
        let salt = s.strip_prefix('$')?;
        let salt_b64: String = salt.chars().take(22).collect();
        let input_prefix = format!("$2{}$", variant);
        Some((cost, salt_b64, input_prefix))
    });
    let (cost, salt_b64, input_prefix) =
        parsed.ok_or_else(|| MobileError::InvalidInput("invalid bcrypt_salt format".into()))?;

    // bcrypt's MCF salt uses a non-standard "bcrypt base64" alphabet. The
    // `bcrypt` crate's `hash_with_salt` expects 16 raw bytes, so decode with
    // the bcrypt alphabet.
    let mut salt_bytes = [0u8; 16];
    bcrypt_b64_decode(&salt_b64, &mut salt_bytes)?;

    // SECURITY: `raw` is the full bcrypt MCF hash string — the effective
    // preprocessed SRP password input. Wipe it on drop, mirroring the
    // registration path in `srp_generate_registration`.
    let raw = Zeroizing::new(
        hash_with_salt(password.as_bytes(), cost, salt_bytes)
            .map_err(|e| MobileError::CryptoError(format!("bcrypt failed: {e}")))?
            .to_string(),
    );

    rewrite_mcf_prefix(&raw, &input_prefix)
}

/// Replace the 4-byte `$2x$` variant prefix on a bcrypt MCF string. The
/// hash bytes for `$2a`/`$2b`/`$2y` are identical for all inputs this API
/// can receive, so this is a safe pure-label rewrite.
fn rewrite_mcf_prefix(mcf: &str, desired_prefix: &str) -> Result<String, MobileError> {
    debug_assert_eq!(desired_prefix.len(), 4);
    if mcf.len() < 4 || !mcf.starts_with("$2") {
        return Err(MobileError::InvalidInput(
            "bcrypt output is not in MCF form".into(),
        ));
    }
    Ok(format!("{}{}", desired_prefix, &mcf[4..]))
}

/// Decode the 22-char bcrypt-flavoured base64 salt into 16 raw bytes.
/// The bcrypt alphabet is `./A-Za-z0-9` (yes, `.` and `/` are first).
fn bcrypt_b64_decode(src: &str, out: &mut [u8; 16]) -> Result<(), MobileError> {
    const ALPHA: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let src_bytes = src.as_bytes();
    if src_bytes.len() < 22 {
        return Err(MobileError::InvalidInput("bcrypt salt too short".into()));
    }

    let lookup = |b: u8| -> Result<u8, MobileError> {
        ALPHA
            .iter()
            .position(|&c| c == b)
            .map(|p| p as u8)
            .ok_or(MobileError::InvalidInput("bcrypt salt contains invalid char".into()))
    };

    // 22 bcrypt-base64 chars carry 132 bits; only the leading 128 (16 bytes)
    // are significant, so the trailing 4 bits are discarded.
    let mut bits = 0u32;
    let mut bit_count = 0u32;
    let mut out_idx = 0usize;
    for &b in &src_bytes[..22] {
        let v = lookup(b)?;
        bits = (bits << 6) | v as u32;
        bit_count += 6;
        while bit_count >= 8 && out_idx < 16 {
            bit_count -= 8;
            out[out_idx] = ((bits >> bit_count) & 0xFF) as u8;
            out_idx += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_then_login_round_trips() {
        let reg = srp_generate_registration("User@Example.Test".into(), "hunter2".into()).unwrap();
        // Simulate a server: verify the verifier recomputes the same from
        // the same preprocessed password.
        let preprocessed = bcrypt_with_mcf_salt("hunter2", &reg.bcrypt_salt).unwrap();
        let salt = B64.decode(&reg.salt).unwrap();
        let client = SrpClient::<Sha256>::new(&G_2048);
        let v = client.compute_verifier(b"user@example.test", preprocessed.as_bytes(), &salt);
        assert_eq!(B64.encode(&v), reg.verifier);
    }

    /// New SDK registrations must produce `$2a$` salts so the server-stored
    /// bcrypt_salt matches Android's jBCrypt convention; otherwise Android
    /// clients wouldn't be able to cleanly re-hash during login for users
    /// who registered via the SDK.
    #[test]
    fn registration_emits_dollar_2a_prefix() {
        let reg = srp_generate_registration("a@b.com".into(), "correcthorse".into()).unwrap();
        assert!(
            reg.bcrypt_salt.starts_with("$2a$12$"),
            "expected $2a$12$ prefix, got {}",
            reg.bcrypt_salt
        );
        assert_eq!(reg.bcrypt_salt.len(), 29, "MCF salt must be 4+3+22=29 chars");
    }

    /// An Android user whose server row has `$2a$12$…` must get the SAME
    /// preprocessed-password string back when the SDK runs login.
    /// `hash_with_salt` returns `$2y$…`: without rewriting the prefix, the
    /// string differs in 1 byte and SRP `x` mismatches, so login fails with
    /// 401.
    #[test]
    fn login_preserves_input_prefix() {
        // Synthetic salt: any well-formed 22-char bcrypt-base64 string works.
        let mcf_a = "$2a$12$abcdefghijklmnopqrstuu";
        let mcf_b = "$2b$12$abcdefghijklmnopqrstuu";
        let mcf_y = "$2y$12$abcdefghijklmnopqrstuu";

        let out_a = bcrypt_with_mcf_salt("hunter2", mcf_a).unwrap();
        let out_b = bcrypt_with_mcf_salt("hunter2", mcf_b).unwrap();
        let out_y = bcrypt_with_mcf_salt("hunter2", mcf_y).unwrap();

        assert!(out_a.starts_with("$2a$12$abcdefghijklmnopqrstuu"));
        assert!(out_b.starts_with("$2b$12$abcdefghijklmnopqrstuu"));
        assert!(out_y.starts_with("$2y$12$abcdefghijklmnopqrstuu"));

        // The 31-char trailing hash portion is identical across variants —
        // that's the property that makes prefix-rewriting safe.
        assert_eq!(&out_a[29..], &out_b[29..]);
        assert_eq!(&out_a[29..], &out_y[29..]);
    }

    /// Proves the full login path (not just the bcrypt helper): an Android
    /// user whose server row stores `$2a$12$<salt>` + a verifier derived
    /// from `$2a$12$<salt><hash>` can successfully complete an SRP handshake
    /// through `srp_compute_login_proof`. This is the test that catches a
    /// prefix mismatch end-to-end.
    #[test]
    fn login_against_android_style_registration() {
        use srp::server::SrpServer;

        let email = "android.user@example.test";
        let password = "hunter2";

        // Android-style registration: bcrypt produces $2a$ output, and the
        // full MCF string (prefix + hash) is the SRP password input.
        let android_preprocessed =
            bcrypt_with_mcf_salt(password, "$2a$12$abcdefghijklmnopqrstuu").unwrap();
        assert!(android_preprocessed.starts_with("$2a$12$abcdefghijklmnopqrstuu"));

        let mut srp_salt = [0u8; 32];
        OsRng.fill_bytes(&mut srp_salt);

        let client = SrpClient::<Sha256>::new(&G_2048);
        let identity = email.to_lowercase();
        let verifier = client.compute_verifier(
            identity.as_bytes(),
            android_preprocessed.as_bytes(),
            &srp_salt,
        );

        // Server side of the handshake.
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        let server = SrpServer::<Sha256>::new(&G_2048);
        let b_pub = server.compute_public_ephemeral(&b, &verifier);

        // Client side via the public SDK entry point.
        let proof = srp_compute_login_proof(
            email.to_string(),
            password.to_string(),
            B64.encode(&srp_salt),
            "$2a$12$abcdefghijklmnopqrstuu".to_string(),
            B64.encode(&b_pub),
        )
        .unwrap();

        // Server verifies M1.
        let a_pub = B64.decode(&proof.client_public).unwrap();
        let m1 = B64.decode(&proof.client_proof).unwrap();
        let verified = server
            .process_reply(&b, &verifier, &a_pub)
            .expect("server process_reply");
        verified
            .verify_client(&m1)
            .expect("server accepts client M1 — proves prefix preservation works");
    }

    /// End to end: the M2 the crate's own server sends for this SDK's proof
    /// verifies from the SrpLoginProof fields as they are; any other M2 does
    /// not.
    #[test]
    fn the_servers_m2_for_this_sdks_proof_verifies_and_nothing_else_does() {
        use srp::server::SrpServer;

        let email = "m2.check@example.test";
        let reg = srp_generate_registration(email.into(), "hunter2".into()).unwrap();
        let verifier = B64.decode(&reg.verifier).unwrap();
        let server = SrpServer::<Sha256>::new(&G_2048);
        let b = [7u8; 32];
        let b_pub = server.compute_public_ephemeral(&b, &verifier);
        let proof = srp_compute_login_proof(
            email.into(),
            "hunter2".into(),
            reg.salt.clone(),
            reg.bcrypt_salt.clone(),
            B64.encode(&b_pub),
        )
        .unwrap();
        let checked = server
            .process_reply(&b, &verifier, &B64.decode(&proof.client_public).unwrap())
            .unwrap();
        checked.verify_client(&B64.decode(&proof.client_proof).unwrap()).unwrap();
        let m2 = checked.proof().to_vec();

        let check = |m2: String| {
            srp_verify_server_proof(
                proof.client_public.clone(),
                proof.client_proof.clone(),
                proof.session_key.clone(),
                m2,
                SrpProofEncoding::Minimal,
            )
            .unwrap()
        };
        assert!(check(B64.encode(&m2)));
        for i in 0..m2.len() {
            let mut wrong = m2.clone();
            wrong[i] ^= 1;
            assert!(!check(B64.encode(&wrong)), "byte {i}");
        }
        assert!(!check(B64.encode(&m2[..31])));
        assert!(!check(String::new()));
        assert!(!check("not base64!".into()));
    }

    /// Malformed values of the client's OWN are errors, never an answer; a
    /// well-formed but wrong M2 is an answer (false). Leading zeros are not
    /// length: a 257-byte value whose first byte is zero is fine.
    #[test]
    fn malformed_client_values_are_errors_not_answers() {
        let (a, m1, s) = (B64.encode([7u8; 256]), B64.encode([1u8; 32]), B64.encode([9u8; 256]));
        let run = |a: &str, m1: &str, s: &str| {
            srp_verify_server_proof(a.into(), m1.into(), s.into(), B64.encode([0u8; 32]), SrpProofEncoding::Padded)
        };
        let is_input_error = |r: Result<bool, MobileError>| matches!(r, Err(MobileError::InvalidInput(_)));
        assert!(matches!(run(&a, &m1, &s), Ok(false)));
        assert!(is_input_error(run("not base64!", &m1, &s)), "A not base64");
        assert!(is_input_error(run(&a, &B64.encode([1u8; 31]), &s)), "M1 not 32 bytes");
        assert!(is_input_error(run(&a, &m1, "")), "S empty");
        assert!(is_input_error(run(&a, &m1, &B64.encode([0u8; 256]))), "S zero");
        assert!(is_input_error(run(&B64.encode([7u8; 257]), &m1, &s)), "A longer than N");
        let mut signed = vec![0u8];
        signed.extend([7u8; 256]);
        assert!(matches!(run(&B64.encode(&signed), &m1, &s), Ok(false)), "a sign byte is not length");
    }

    /// The SRP verifier is password-equivalent and the session key is a shared
    /// secret; neither may appear in any rendering of these records — including
    /// the `uniffi_trait_*` shims that Kotlin's `toString()` and Swift's
    /// `description`/`debugDescription` call. Referencing the shims means
    /// dropping `#[uniffi::export(Debug, Display)]` breaks this at COMPILE time.
    #[test]
    fn srp_records_never_render_their_secrets() {
        const VERIFIER: &str = "aaaaSECRETSRPVERIFIERaaaa";
        const PROOF: &str = "bbbbSECRETCLIENTPROOFbbbb";
        const SESSION_KEY: &str = "ccccSECRETSESSIONKEYcccc";

        let reg = SrpRegistrationData {
            salt: "salt-is-a-public-SRP-parameter".into(),
            verifier: VERIFIER.into(),
            bcrypt_salt: "$2a$12$bcrypt-salt-is-public".into(),
        };
        for (how, rendered) in [
            ("Debug", format!("{reg:?}")),
            ("Display", format!("{reg}")),
            ("uniffi_trait_debug", reg.uniffi_trait_debug()),
            ("uniffi_trait_display", reg.uniffi_trait_display()),
        ] {
            assert!(!rendered.contains(VERIFIER), "{how} leaked the verifier: {rendered}");
            assert!(rendered.contains("[REDACTED]"), "{how} has no redaction marker: {rendered}");
            // salt and bcrypt_salt are public SRP parameters and stay readable.
            assert!(rendered.contains("salt-is-a-public-SRP-parameter"), "{how}: {rendered}");
        }

        let proof = SrpLoginProof {
            client_public: "A-is-a-public-ephemeral".into(),
            client_proof: PROOF.into(),
            session_key: SESSION_KEY.into(),
        };
        for (how, rendered) in [
            ("Debug", format!("{proof:?}")),
            ("Display", format!("{proof}")),
            ("uniffi_trait_debug", proof.uniffi_trait_debug()),
            ("uniffi_trait_display", proof.uniffi_trait_display()),
        ] {
            assert!(!rendered.contains(PROOF), "{how} leaked M1: {rendered}");
            assert!(!rendered.contains(SESSION_KEY), "{how} leaked K: {rendered}");
            assert!(rendered.contains("[REDACTED]"), "{how} has no redaction marker: {rendered}");
            assert!(rendered.contains("A-is-a-public-ephemeral"), "{how}: {rendered}");
        }
    }
}
