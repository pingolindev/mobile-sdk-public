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

//! Privacy-preserving geocode tokens — VOPRF *client* (Privacy-Pass style).
//!
//! Companion to the track server's geocode-token issuance route. Splits "who
//! you are" from "where you are": the client blinds random nonces, the server
//! BlindEvaluates them (issuance), the client unblinds + verifies (finalize),
//! and later spends each `(nonce, W)` at the session-less reverse-geocode route
//! — which carries no identity, so the geocoder never sees a `user_id` next to
//! coordinates.
//!
//! Wire contract (MUST match the server byte-for-byte):
//!   - Ciphersuite: `voprf::Ristretto255` (RFC 9497 OPRF(ristretto255, SHA-512)).
//!     Element = 32 bytes, PRF output `W` = 64 bytes.
//!   - Everything base64 STANDARD (padded, the standard alphabet — as the
//!     server encodes it).
//!   - Issuance request element = `B64(BlindedElement::serialize())`.
//!   - Issuance response: `evaluated[i]` = `B64(EvaluationElement::serialize())`,
//!     `proofs[i]` = `B64(Proof::serialize())`, `public_key` =
//!     `B64(serialize_elem(pk))`, all in the request's batch order.
//!   - Redemption token = `{ nonce_b64: B64(nonce), evaluated_b64: B64(W) }`.
//!
//! SECURITY: `finalize` VERIFIES the issuance DLEQ proof against the pinned
//! public key. A proof produced under a *different* key fails to verify — this
//! is the property that stops a malicious server from tagging users with
//! per-user keys to deanonymize them at redemption. Nonces and finalized
//! outputs are bearer secrets (they ARE the spendable tokens); this module
//! never logs them.

use crate::types::{redacted_display_via_debug, MobileError};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use rand::RngCore;
use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};

/// VOPRF cipher suite — ristretto255-SHA512. MUST match the backend's suite.
type Cs = Ristretto255;

/// Random VOPRF input nonce length in bytes. The backend accepts up to 64,
/// but clients always use 32.
const NONCE_LEN: usize = 32;

/// `VoprfClient::serialize()` length for ristretto255: the blind scalar (32
/// bytes) concatenated with the blinded element (32 bytes).
const CLIENT_STATE_LEN: usize = 64;

/// Serialized per-credit blind state: `nonce (32) || VoprfClient::serialize()
/// (64)`. The nonce is stored alongside the client state because `finalize`
/// needs it as its `input` argument (the `VoprfClient` state itself does not
/// carry it) and it is also echoed as the redemption token's `nonce_b64`.
const BLIND_STATE_LEN: usize = NONCE_LEN + CLIENT_STATE_LEN;

/// Result of blinding a batch of geocode-token credits.
///
/// `blinded[i]` is sent to `POST /geocode/tokens`; `states[i]` is kept locally
/// and paired **by index** with the server's `evaluated[i]` / `proofs[i]` at
/// `geocode_finalize_tokens`.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// `types.rs`. Without this the generated `data class` / `struct` prints every
// field, so a single `Log.d(TAG, "$result")` writes the raw input nonces out.
#[uniffi::export(Debug, Display)]
pub struct GeocodeBlindResult {
    /// base64 `BlindedElement`s, one per requested credit, to POST to the server.
    pub blinded: Vec<String>,
    /// base64 opaque client states, index-paired with `blinded`. Opaque to the
    /// caller — pass them straight back into `geocode_finalize_tokens`.
    pub states: Vec<String>,
}

// SECURITY: `states` embeds the raw input nonces — keep them out of logs.
impl std::fmt::Debug for GeocodeBlindResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeocodeBlindResult")
            .field("blinded", &format_args!("<{} elements>", self.blinded.len()))
            .field("states", &format_args!("<{} REDACTED>", self.states.len()))
            .finish()
    }
}

/// A finalized, spendable geocode token — the `(nonce, W)` pair the session-less
/// `POST /geocode/reverse` route takes in its `token` field. On the wire `W` is
/// named `evaluated_b64`, so callers rename this field when serializing.
#[derive(Clone, uniffi::Record)]
// Carries the redaction below into Kotlin/Swift — see the block at the top of
// `types.rs`. This is the worse of the two to leak: the pair below IS the
// spendable token, so anything that prints it hands over the credential.
#[uniffi::export(Debug, Display)]
pub struct GeocodeToken {
    /// base64 VOPRF input nonce.
    pub nonce_b64: String,
    /// base64 finalized 64-byte VOPRF output `W`.
    pub output_b64: String,
}

// SECURITY: a finalized token is a bearer credential — never log it.
impl std::fmt::Debug for GeocodeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeocodeToken")
            .field("nonce_b64", &"[REDACTED]")
            .field("output_b64", &"[REDACTED]")
            .finish()
    }
}

redacted_display_via_debug!(GeocodeBlindResult, GeocodeToken);

/// Map a `voprf` error to a `MobileError` without leaking internals. A DLEQ
/// proof-verification failure (the anti-deanonymization check) is surfaced as
/// `SignatureInvalid`; a deserialization failure as `InvalidInput`; everything
/// else as a generic `CryptoError`.
fn map_voprf_err(e: voprf::Error) -> MobileError {
    match e {
        voprf::Error::ProofVerification => MobileError::SignatureInvalid,
        voprf::Error::Deserialization => {
            MobileError::InvalidInput("Malformed VOPRF element".to_string())
        }
        _ => MobileError::CryptoError("VOPRF operation failed".to_string()),
    }
}

/// Blind `count` fresh random nonces into VOPRF credits.
///
/// Returns `blinded` (POST to `/geocode/tokens`) and index-paired `states`
/// (kept locally, fed back into `geocode_finalize_tokens`). Each nonce is drawn
/// from the OS CSPRNG.
#[uniffi::export]
pub fn geocode_blind_tokens(count: u32) -> GeocodeBlindResult {
    let mut rng = OsRng;
    let mut blinded = Vec::with_capacity(count as usize);
    let mut states = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        // Infallible for a fixed 32-byte input: `blind` only errors on an empty
        // or > u16::MAX input (RFC 9497).
        let blind = VoprfClient::<Cs>::blind(&nonce, &mut rng)
            .expect("blinding a fixed 32-byte nonce is infallible");

        blinded.push(B64.encode(blind.message.serialize()));

        // State = nonce || client-state; see `BLIND_STATE_LEN` for why both
        // halves are needed at finalize.
        let client_state = blind.state.serialize();
        let mut state_blob = Vec::with_capacity(BLIND_STATE_LEN);
        state_blob.extend_from_slice(&nonce);
        state_blob.extend_from_slice(&client_state);
        states.push(B64.encode(&state_blob));
    }

    GeocodeBlindResult { blinded, states }
}

/// Finalize an issuance batch: verify each DLEQ proof against `public_key` and
/// unblind to redemption tokens `(nonce, W)`.
///
/// `states`, `evaluated`, and `proofs` are paired by index and MUST be the same
/// length; `public_key` is the base64 ristretto255 issuance key the client
/// pinned. Returns one `GeocodeToken` per credit, in order.
///
/// SECURITY CONTRACT — the caller MUST pin `public_key`. Verifying the DLEQ
/// proofs buys the anti-deanonymization property (the server cannot link a
/// redeemed token back to its issuance session) ONLY when the client
/// pins/hardcodes ONE known ristretto255 issuance key and always passes that
/// fixed value here. If the caller instead accepts a fresh `public_key` returned
/// by the server per issuance, the proof check is self-referential and worthless:
/// a malicious server can mint a per-client (or per-batch) key, prove honestly
/// against it, and later fingerprint redemptions by which key verifies. Treat
/// `public_key` as a build-time constant (or a value pinned out-of-band), never
/// as a value read from the issuance response.
///
/// Errors (never panics) on any length mismatch, malformed base64/element, or —
/// critically — a DLEQ proof that fails to verify (a proof under a different key
/// yields `SignatureInvalid`).
#[uniffi::export]
pub fn geocode_finalize_tokens(
    states: Vec<String>,
    evaluated: Vec<String>,
    proofs: Vec<String>,
    public_key: String,
) -> Result<Vec<GeocodeToken>, MobileError> {
    if states.len() != evaluated.len() || states.len() != proofs.len() {
        return Err(MobileError::InvalidInput(
            "geocode token batch length mismatch".to_string(),
        ));
    }

    // Pinned issuance public key, for DLEQ proof verification.
    let pk_bytes = B64
        .decode(public_key.as_bytes())
        .map_err(|_| MobileError::InvalidInput("Malformed public_key (base64)".to_string()))?;
    let pk = <Cs as Group>::deserialize_elem(&pk_bytes).map_err(map_voprf_err)?;

    let mut tokens = Vec::with_capacity(states.len());
    for ((state_b64, eval_b64), proof_b64) in
        states.iter().zip(evaluated.iter()).zip(proofs.iter())
    {
        // Recover the nonce + client state for this credit.
        let blob = B64.decode(state_b64.as_bytes()).map_err(|_| {
            MobileError::InvalidInput("Malformed token state (base64)".to_string())
        })?;
        if blob.len() != BLIND_STATE_LEN {
            return Err(MobileError::InvalidInput(
                "Malformed token state (length)".to_string(),
            ));
        }
        let (nonce, client_bytes) = blob.split_at(NONCE_LEN);
        let client = VoprfClient::<Cs>::deserialize(client_bytes).map_err(map_voprf_err)?;

        // The server's evaluation + DLEQ proof for this credit.
        let eval_raw = B64.decode(eval_b64.as_bytes()).map_err(|_| {
            MobileError::InvalidInput("Malformed evaluated element (base64)".to_string())
        })?;
        let evaluation = EvaluationElement::<Cs>::deserialize(&eval_raw).map_err(map_voprf_err)?;

        let proof_raw = B64
            .decode(proof_b64.as_bytes())
            .map_err(|_| MobileError::InvalidInput("Malformed proof (base64)".to_string()))?;
        let proof = Proof::<Cs>::deserialize(&proof_raw).map_err(map_voprf_err)?;

        // VERIFIES the DLEQ proof against the pinned `pk`, then unblinds to `W`.
        // A proof produced under a different key fails here — the property that
        // prevents per-user-key deanonymization at redemption.
        let output = client
            .finalize(nonce, &evaluation, &proof, pk)
            .map_err(map_voprf_err)?;

        tokens.push(GeocodeToken {
            nonce_b64: B64.encode(nonce),
            output_b64: B64.encode(&output[..]),
        });
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voprf::{BlindedElement, VoprfServer};

    /// Same DeriveKeyPair context string the server mixes in (bumping it
    /// rotates the key). MUST match the server's value.
    const KEY_INFO: &[u8] = b"pingolin-geocode-voprf-v1";

    fn test_server(seed: &[u8; 32]) -> VoprfServer<Cs> {
        VoprfServer::<Cs>::new_from_seed(seed, KEY_INFO).unwrap()
    }

    /// Run the server's issuance side over a batch of `blinded` elements exactly
    /// as `POST /geocode/tokens` does: BlindEvaluate each (own DLEQ proof) and
    /// publish the base64 public key. Returns `(evaluated, proofs, public_key)`.
    fn server_issue(
        server: &VoprfServer<Cs>,
        blinded: &[String],
    ) -> (Vec<String>, Vec<String>, String) {
        let mut rng = OsRng;
        let mut evaluated = Vec::with_capacity(blinded.len());
        let mut proofs = Vec::with_capacity(blinded.len());
        for b in blinded {
            let raw = B64.decode(b.as_bytes()).unwrap();
            let element = BlindedElement::<Cs>::deserialize(&raw).unwrap();
            let out = server.blind_evaluate(&mut rng, &element);
            evaluated.push(B64.encode(out.message.serialize()));
            proofs.push(B64.encode(out.proof.serialize()));
        }
        let pk = B64.encode(<Cs as Group>::serialize_elem(server.get_public_key()));
        (evaluated, proofs, pk)
    }

    /// (1) Full interop round-trip: blind → server BlindEvaluate → finalize →
    /// the server's redeem check `server.evaluate(nonce) == W` accepts every
    /// token. `n > 1` catches index-pairing (order) bugs — a mispaired
    /// state/evaluation would fail the per-credit DLEQ proof in `finalize`.
    #[test]
    fn interop_happy_path_backend_would_accept() {
        let server = test_server(&[42u8; 32]);
        let n = 5u32;
        let blind = geocode_blind_tokens(n);
        assert_eq!(blind.blinded.len(), n as usize);
        assert_eq!(blind.states.len(), n as usize);

        let (evaluated, proofs, pk) = server_issue(&server, &blind.blinded);
        let tokens = geocode_finalize_tokens(blind.states, evaluated, proofs, pk).unwrap();
        assert_eq!(tokens.len(), n as usize);

        for t in &tokens {
            let nonce = B64.decode(t.nonce_b64.as_bytes()).unwrap();
            let w = B64.decode(t.output_b64.as_bytes()).unwrap();
            assert_eq!(nonce.len(), NONCE_LEN);
            assert_eq!(w.len(), 64, "ristretto255-SHA512 output is 64 bytes");
            // Exactly the backend's redeem check: recompute VOPRF_sk(nonce).
            let expected = server.evaluate(&nonce).unwrap();
            assert_eq!(&expected[..], w.as_slice(), "backend would accept this token");
        }
    }

    /// (2) DLEQ anti-deanonymization: an evaluation + proof produced under a
    /// DIFFERENT key than the pinned `public_key` must fail `finalize`.
    #[test]
    fn dleq_proof_rejects_wrong_key() {
        let honest = test_server(&[42u8; 32]);
        let rogue = test_server(&[99u8; 32]);

        // Rogue server evaluates + proves under its own key...
        let blind = geocode_blind_tokens(2);
        let (evaluated, proofs, _rogue_pk) = server_issue(&rogue, &blind.blinded);
        // ...but the client verifies against the HONEST published key → reject.
        let honest_pk = B64.encode(<Cs as Group>::serialize_elem(honest.get_public_key()));
        let res = geocode_finalize_tokens(blind.states, evaluated, proofs, honest_pk);
        assert!(
            matches!(res, Err(MobileError::SignatureInvalid)),
            "a DLEQ proof under a different key must fail finalize, got {:?}",
            res
        );

        // Positive control: the SAME rogue-evaluated shape finalizes fine
        // against the rogue's OWN key — proving the rejection above is the key
        // mismatch, not a broken issuance path.
        let blind2 = geocode_blind_tokens(2);
        let (evaluated2, proofs2, rogue_pk) = server_issue(&rogue, &blind2.blinded);
        assert!(
            geocode_finalize_tokens(blind2.states, evaluated2, proofs2, rogue_pk).is_ok(),
            "rogue-evaluated tokens must finalize against the rogue's own key"
        );
    }

    /// (4) The blind states embed the raw input nonces and a finalized token IS
    /// the spendable bearer credential; neither may appear in ANY rendering of
    /// these records — including the `uniffi_trait_*` shims that Kotlin's
    /// `toString()` and Swift's `description`/`debugDescription` call.
    ///
    /// Naming the shims is the point of this test. A redacting Rust `Debug` on
    /// its own protects Rust only: UniFFI does not read Rust trait impls, so
    /// without `#[uniffi::export(Debug, Display)]` the generated Kotlin is a
    /// bare `data class` (compiler-generated `toString()` prints every property)
    /// and the generated Swift has no `CustomStringConvertible` (reflection
    /// dumps every stored property). Calling `uniffi_trait_debug()` here means
    /// dropping that attribute breaks this at COMPILE time rather than quietly
    /// putting geocode tokens back into logcat.
    #[test]
    fn geocode_records_never_render_their_secrets() {
        // Long and distinctive so a `contains` check cannot collide with a
        // field name, a type name, or the redaction marker itself.
        const SECRET_STATE: &str = "aaaaSECRETBLINDSTATEWITHNONCEaaaa";
        const SECRET_NONCE: &str = "bbbbSECRETTOKENNONCEbbbb";
        const SECRET_OUTPUT: &str = "ccccSECRETTOKENOUTPUTWccccc";

        let blind = GeocodeBlindResult {
            blinded: vec!["blinded-elements-go-to-the-server".into()],
            states: vec![SECRET_STATE.into()],
        };
        for (how, rendered) in [
            ("Debug", format!("{blind:?}")),
            ("Display", format!("{blind}")),
            ("uniffi_trait_debug", blind.uniffi_trait_debug()),
            ("uniffi_trait_display", blind.uniffi_trait_display()),
        ] {
            assert!(
                !rendered.contains(SECRET_STATE),
                "{how} leaked a blind state (it embeds the raw nonce): {rendered}"
            );
            assert!(
                rendered.contains("REDACTED"),
                "{how} has no redaction marker: {rendered}"
            );
        }

        let token = GeocodeToken {
            nonce_b64: SECRET_NONCE.into(),
            output_b64: SECRET_OUTPUT.into(),
        };
        for (how, rendered) in [
            ("Debug", format!("{token:?}")),
            ("Display", format!("{token}")),
            ("uniffi_trait_debug", token.uniffi_trait_debug()),
            ("uniffi_trait_display", token.uniffi_trait_display()),
        ] {
            assert!(!rendered.contains(SECRET_NONCE), "{how} leaked the nonce: {rendered}");
            assert!(!rendered.contains(SECRET_OUTPUT), "{how} leaked W: {rendered}");
            assert!(
                rendered.contains("[REDACTED]"),
                "{how} has no redaction marker: {rendered}"
            );
        }

        // Same again over values from the REAL pipeline rather than synthetic
        // ones, so the property is checked against what actually gets logged.
        let server = test_server(&[13u8; 32]);
        let real_blind = geocode_blind_tokens(1);
        let real_state = real_blind.states[0].clone();
        let (evaluated, proofs, pk) = server_issue(&server, &real_blind.blinded);
        let real = geocode_finalize_tokens(real_blind.states.clone(), evaluated, proofs, pk)
            .unwrap()
            .remove(0);
        for rendered in [
            format!("{real_blind:?}"),
            real_blind.uniffi_trait_display(),
            format!("{real:?}"),
            real.uniffi_trait_display(),
        ] {
            assert!(!rendered.contains(&real_state), "leaked a real blind state: {rendered}");
            assert!(!rendered.contains(&real.nonce_b64), "leaked a real nonce: {rendered}");
            assert!(!rendered.contains(&real.output_b64), "leaked a real W: {rendered}");
        }
    }

    /// (3) Malformed inputs are all rejected as errors, never panics.
    #[test]
    fn malformed_inputs_rejected_without_panic() {
        let server = test_server(&[7u8; 32]);
        let blind = geocode_blind_tokens(1);
        let (evaluated, proofs, pk) = server_issue(&server, &blind.blinded);

        // Batch length mismatch across the three vectors.
        assert!(matches!(
            geocode_finalize_tokens(blind.states.clone(), vec![], proofs.clone(), pk.clone()),
            Err(MobileError::InvalidInput(_))
        ));

        // Bad base64 public key.
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            evaluated.clone(),
            proofs.clone(),
            "!!!not base64!!!".to_string(),
        )
        .is_err());

        // Valid base64 but wrong-length public key (not a 32-byte element).
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            evaluated.clone(),
            proofs.clone(),
            B64.encode([0u8; 10]),
        )
        .is_err());

        // Bad base64 in the state slot.
        assert!(geocode_finalize_tokens(
            vec!["@@@".to_string()],
            evaluated.clone(),
            proofs.clone(),
            pk.clone(),
        )
        .is_err());

        // Valid base64 but wrong-length state blob.
        assert!(geocode_finalize_tokens(
            vec![B64.encode([1u8; 10])],
            evaluated.clone(),
            proofs.clone(),
            pk.clone(),
        )
        .is_err());

        // Bad base64 in the evaluated slot.
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            vec!["###".to_string()],
            proofs.clone(),
            pk.clone(),
        )
        .is_err());

        // Valid base64 but wrong-length evaluated element.
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            vec![B64.encode([2u8; 5])],
            proofs.clone(),
            pk.clone(),
        )
        .is_err());

        // Bad base64 in the proof slot.
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            evaluated.clone(),
            vec!["%%%".to_string()],
            pk.clone(),
        )
        .is_err());

        // Valid base64 but wrong-length proof.
        assert!(geocode_finalize_tokens(
            blind.states.clone(),
            evaluated.clone(),
            vec![B64.encode([3u8; 7])],
            pk.clone(),
        )
        .is_err());
    }
}
