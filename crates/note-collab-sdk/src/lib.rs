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

//! Yjs-compatible CRDT + AEAD helpers for the mobile note clients.
//!
//! The web UI ships real Yjs (JS) in the browser. Android and iOS need the
//! same CRDT semantics to interoperate through the relay. `yrs` is the
//! upstream Rust port of Yjs with a byte-identical wire format, so this
//! crate exposes it through UniFFI to Kotlin and Swift.
//!
//! Scope is deliberately narrow: text-only doc ("body"), plus enough
//! protocol helpers that the mobile side can speak the same sync steps
//! as the web `y-protocols/sync` module.
//!
//! AEAD helpers mirror the web client's collab crypto — XChaCha20-Poly1305
//! with a random nonce prefix, keyed on the per-note content key. The relay
//! stays provably blind to document contents.

use std::sync::Mutex;

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use crypto_secretbox::XSalsa20Poly1305;
use rand::RngCore;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Doc, GetString, OffsetKind, Options, ReadTxn, StateVector, Text, TextRef, Transact, Update,
};
use zeroize::{Zeroize, Zeroizing};

uniffi::include_scaffolding!("collab");

#[derive(Debug, thiserror::Error)]
pub enum CollabError {
    #[error("invalid state vector")]
    InvalidStateVector,
    #[error("invalid update bytes")]
    InvalidUpdate,
    #[error("aead: {0}")]
    Aead(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Live Yjs document. Holds a `yrs::Doc` plus a buffer of updates
/// produced by local mutations, which the Kotlin side drains and ships
/// through the relay. Thread-safe: every method takes `&self` and locks
/// internally so UniFFI can hand the instance across threads.
pub struct YjsDoc {
    inner: Mutex<Inner>,
}

struct Inner {
    doc: Doc,
    /// Cached root TextRef. `Doc::get_or_insert_text` internally acquires
    /// a write transaction, so we resolve the ref once during construction
    /// to avoid nested-lock deadlocks in `mutate`.
    text: TextRef,
    /// Accumulated encoded updates emitted by local mutations since the
    /// Kotlin caller last drained them. Each entry is a standalone v1
    /// update; the caller typically concatenates them into a single
    /// broadcast frame.
    pending_local_updates: Vec<Vec<u8>>,
}

impl YjsDoc {
    pub fn new() -> Self {
        // UTF-16 offsets to match Yjs JS in the web client and the Kotlin/Swift
        // editor callers — insert_text/remove_text document UTF-16 indices, but
        // Doc::new() defaults to BYTE offsets, which would mis-place edits on
        // non-ASCII text. The wire update format is offset-kind-independent, so
        // the choice is invisible to interop.
        let mut options = Options::default();
        options.offset_kind = OffsetKind::Utf16;
        let doc = Doc::with_options(options);
        let text = doc.get_or_insert_text("body");
        Self {
            inner: Mutex::new(Inner {
                doc,
                text,
                pending_local_updates: Vec::new(),
            }),
        }
    }

    /// Current state vector encoded as Yjs v1 bytes. Sent as the sync
    /// step-1 payload so remote peers know what updates we're missing.
    pub fn encode_state_vector(&self) -> Vec<u8> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let txn = inner.doc.transact();
        txn.state_vector().encode_v1()
    }

    /// Produce a v1 update containing everything we know that the peer
    /// (as described by their state vector) does not. Sent as the sync
    /// step-2 reply.
    pub fn encode_diff_since(&self, state_vector: Vec<u8>) -> Result<Vec<u8>, CollabError> {
        let sv =
            StateVector::decode_v1(&state_vector).map_err(|_| CollabError::InvalidStateVector)?;
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let txn = inner.doc.transact();
        Ok(txn.encode_state_as_update_v1(&sv))
    }

    /// Maximum accepted size of a single remote update frame, matching the collab
    /// relay's 2 MiB WebSocket `max_message_size`. A well-formed but oversized
    /// update (or one whose never-arriving predecessors would otherwise park
    /// unbounded in yrs's internal `store.pending` and be re-encoded into every
    /// subsequent outgoing frame) is rejected before decode, bounding per-frame
    /// memory and CPU. The limit applies per frame: it does not bound the total
    /// size of many small updates parked in `store.pending`.
    const MAX_UPDATE_BYTES: usize = 2 * 1024 * 1024;

    /// Apply a remote v1 update to the local doc. Idempotent: Yjs de-dups
    /// by client-id + clock.
    pub fn apply_update(&self, update: Vec<u8>) -> Result<(), CollabError> {
        if update.len() > Self::MAX_UPDATE_BYTES {
            return Err(CollabError::InvalidUpdate);
        }
        let update = Update::decode_v1(&update).map_err(|_| CollabError::InvalidUpdate)?;
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut txn = inner.doc.transact_mut();
        txn.apply_update(update)
            .map_err(|e| CollabError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Insert `content` into the "body" text at `index`, measured in UTF-16 code
    /// units. Emits a v1 update into the pending-local-updates buffer.
    pub fn insert_text(&self, index: u32, content: String) -> Result<(), CollabError> {
        self.mutate(|text, txn| {
            // Bounds-check against the current UTF-16 length: an out-of-range index
            // must return an error rather than panic inside yrs, which would unwind
            // across the UniFFI boundary and abandon the doc mid-transaction.
            if index > text.len(txn) {
                return Err(CollabError::InvalidUpdate);
            }
            text.insert(txn, index, &content);
            Ok(())
        })
    }

    /// Remove `length` UTF-16 code units starting at `index`. Yjs uses
    /// UTF-16 offsets internally to match JS strings.
    pub fn remove_text(&self, index: u32, length: u32) -> Result<(), CollabError> {
        self.mutate(|text, txn| {
            // Reject a range running past the end rather than panicking in yrs
            // (see `insert_text`). Saturating add so index == len or length == 0
            // stays a harmless no-op.
            let len = text.len(txn);
            if index > len || index.saturating_add(length) > len {
                return Err(CollabError::InvalidUpdate);
            }
            text.remove_range(txn, index, length);
            Ok(())
        })
    }

    /// Replace the entire body text with `content`, for editor callers that have
    /// no structured edit events to replay.
    ///
    /// NOT a seed path: the replacement is minted under this doc's own random
    /// client id, so two devices "seeding" the same body this way produce
    /// concurrent inserts that converge to a DUPLICATED body. Use
    /// [`deterministic_seed_update`] for an initial body.
    pub fn replace_text(&self, content: String) -> Result<(), CollabError> {
        self.mutate(|text, txn| {
            let current_len = text.len(txn);
            if current_len > 0 {
                text.remove_range(txn, 0, current_len);
            }
            text.insert(txn, 0, &content);
            Ok(())
        })
    }

    /// Current text as a plain UTF-8 string.
    pub fn get_text(&self) -> String {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let txn = inner.doc.transact();
        inner.text.get_string(&txn)
    }

    /// Drain every update produced locally since the last drain. Returns
    /// a list of v1 update frames that the caller should ship to the
    /// relay one-by-one (or concatenate if preferred).
    pub fn drain_local_updates(&self) -> Vec<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut inner.pending_local_updates)
    }

    fn mutate<F>(&self, f: F) -> Result<(), CollabError>
    where
        F: FnOnce(&TextRef, &mut yrs::TransactionMut) -> Result<(), CollabError>,
    {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshot the state vector before the mutation so we can compute
        // the update diff after commit — that's what we queue for the
        // relay. Cheaper and more robust than attaching/removing a
        // subscription on every call.
        let before_sv = {
            let txn = inner.doc.transact();
            txn.state_vector()
        };
        {
            let mut txn = inner.doc.transact_mut();
            f(&inner.text, &mut txn)?;
        }
        let update = {
            let txn = inner.doc.transact();
            txn.encode_state_as_update_v1(&before_sv)
        };
        if !update.is_empty() {
            inner.pending_local_updates.push(update);
        }
        Ok(())
    }
}

/// Build a deterministic v1 update that seeds `content` as the "body" text.
///
/// Apply it to a fresh [`YjsDoc`] via `apply_update` INSTEAD of `replace_text`
/// when opening a note for collaboration.
///
/// The seed's CRDT client id is DERIVED FROM THE CONTENT (BLAKE3), never a fixed
/// constant:
///   * Two devices that seed BYTE-IDENTICAL content mint the same items at the
///     same (client_id, clock), so Yjs/yrs de-dups them on merge — the note
///     converges to a single copy instead of duplicating the body.
///   * Two devices that seed DIVERGENT content get DIFFERENT client ids, so
///     their items occupy distinct coordinates. They merge as ordinary
///     concurrent inserts and CONVERGE to a (harmless) duplicate — the safe
///     failure.
///
/// A constant client id is NOT a safe alternative: it is correct only while
/// every device seeds byte-identical bytes. Two divergent seeds minting at the
/// same (client=const, clock=0..) with different content violate Yjs's
/// (client_id, clock) dedup and split the doc into a permanent divergence.
///
/// The derivation MUST stay byte-identical to the web client's
/// `deterministicSeedUpdate`: the low 53 bits of the little-endian u64 read from
/// the first 8 bytes of BLAKE3(content). 53 bits keeps the id inside JS's
/// safe-integer range so the Rust `u64` and the JS `number` agree EXACTLY;
/// a wider id would round in JS and identical-content seeds would stop de-duping
/// across web and mobile.
///
/// Returns an empty vec for empty content (nothing to seed → caller skips the
/// apply). Local edits keep using the live doc's own random client id, so
/// concurrent edits still diverge and merge normally.
pub fn deterministic_seed_update(content: String) -> Result<Vec<u8>, CollabError> {
    if content.is_empty() {
        return Ok(Vec::new());
    }
    // Content-derived seed client id — see the doc comment for the derivation
    // and for why a constant id is unsafe.
    let digest = blake3::hash(content.as_bytes());
    let b = digest.as_bytes();
    let n = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let client_id = n & ((1u64 << 53) - 1);

    let mut options = Options::default();
    // UTF-16 offsets to match `YjsDoc::new()`; the client id is the derived one.
    options.offset_kind = OffsetKind::Utf16;
    options.client_id = client_id;
    let doc = Doc::with_options(options);
    let text = doc.get_or_insert_text("body");
    {
        let mut txn = doc.transact_mut();
        text.insert(&mut txn, 0, &content);
    }
    let txn = doc.transact();
    // Full state (diff against an empty state vector) = the seed update.
    Ok(txn.encode_state_as_update_v1(&StateVector::default()))
}

// -----------------------------------------------------------------------
// AEAD framing — XChaCha20-Poly1305 with 24-byte random nonce prefix.
// Matches the web client's encryptCollabPayload / decryptCollabPayload.
// -----------------------------------------------------------------------

/// Encrypt a plaintext frame with the per-note session key. Output is
/// `nonce || ciphertext_with_tag`, same format the web expects.
pub fn encrypt_collab_frame(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, CollabError> {
    // SECURITY: wipe the session key on every return path (incl. the error below).
    let key = Zeroizing::new(key);
    if key.len() != 32 {
        return Err(CollabError::Aead("key must be 32 bytes".into()));
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| CollabError::Aead(e.to_string()))?;
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|e| CollabError::Aead(e.to_string()))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a frame produced by `encrypt_collab_frame`. Returns None on
/// authentication failure so the caller can silently drop stale frames.
pub fn decrypt_collab_frame(key: Vec<u8>, frame: Vec<u8>) -> Option<Vec<u8>> {
    // SECURITY: wipe the session key on every return path.
    let key = Zeroizing::new(key);
    if key.len() != 32 || frame.len() < 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce = XNonce::from_slice(&frame[..24]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &frame[24..],
                aad: &[],
            },
        )
        .ok()
}

// -----------------------------------------------------------------------
// Per-note content keys (wire-compatible with the web client)
// -----------------------------------------------------------------------
//
// Each note gets a 32-byte random content key. The item's encrypted_content
// is encrypted with it (XChaCha20-Poly1305). The content key itself is
// wrapped under the owner's vault key (NaCl secretbox) so the owner can
// still read across devices, and wrapped again for each share recipient
// with a sealed box (`seal_for_recipient`).

/// Generate a random 32-byte content key. One per note.
pub fn generate_content_key() -> Vec<u8> {
    use rand::RngCore;
    let mut out = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut out);
    let key = out.to_vec();
    // Wipe the stack copy; the returned Vec is the caller's to own.
    out.zeroize();
    key
}

/// A base64-encoded wrap result. Base64 keeps the wire format interchangeable
/// with the web client (which stores the same strings it received from the
/// backend) and keeps the bytes storable in a SQLite TEXT column, which raw
/// ciphertext containing NULs is not.
pub struct WrappedKey {
    pub wrapped_key_b64: String,
    pub nonce_b64: String,
}

/// Wrap a content key with the vault key via NaCl secretbox
/// (XSalsa20-Poly1305, 24-byte nonce). Identical wire bytes to the
/// web's `libsodium crypto_secretbox_easy`.
pub fn wrap_with_vault(
    content_key: Vec<u8>,
    vault_key: Vec<u8>,
) -> Result<WrappedKey, CollabError> {
    // SECURITY: wipe both the content key and the vault key on every return path.
    let content_key = Zeroizing::new(content_key);
    let vault_key = Zeroizing::new(vault_key);
    if vault_key.len() != 32 {
        return Err(CollabError::Aead("vault key must be 32 bytes".into()));
    }
    let cipher = XSalsa20Poly1305::new_from_slice(&vault_key)
        .map_err(|e| CollabError::Aead(e.to_string()))?;
    let mut nonce_bytes = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = crypto_secretbox::Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, content_key.as_slice())
        .map_err(|e| CollabError::Aead(e.to_string()))?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(WrappedKey {
        wrapped_key_b64: engine.encode(&ct),
        nonce_b64: engine.encode(nonce_bytes),
    })
}

/// Reverse of `wrap_with_vault`. Returns None on auth failure (wrong
/// vault key, tampered ciphertext, truncated input) so callers can
/// fall back gracefully without needing to catch an exception.
pub fn unwrap_with_vault(
    wrapped_key_b64: String,
    nonce_b64: String,
    vault_key: Vec<u8>,
) -> Option<Vec<u8>> {
    // SECURITY: wipe the owned vault key on every return path (mirrors
    // `wrap_with_vault`); the decrypted-but-rejected plaintext is wiped below.
    let vault_key = Zeroizing::new(vault_key);
    if vault_key.len() != 32 {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let ct = engine.decode(wrapped_key_b64.as_bytes()).ok()?;
    let nonce_bytes = engine.decode(nonce_b64.as_bytes()).ok()?;
    if nonce_bytes.len() != 24 {
        return None;
    }
    let cipher = XSalsa20Poly1305::new_from_slice(&vault_key).ok()?;
    let nonce = crypto_secretbox::Nonce::from_slice(&nonce_bytes);
    let mut pt = cipher.decrypt(nonce, ct.as_slice()).ok()?;
    if pt.len() != 32 {
        // Wipe the decrypted-but-rejected key material before dropping it.
        pt.zeroize();
        return None;
    }
    // Return value is raw by contract (the unwrapped content key); caller owns it.
    Some(pt)
}

/// Base64-encoded (nonce, ciphertext) produced by
/// `encrypt_note_with_content_key`. Both fields are STANDARD (not URL-safe)
/// base64 — the form the backend stores.
pub struct NoteCiphertext {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// AAD v2 write flag.
///
/// Set: note content is written under the v2 context-AAD that binds a ciphertext
/// to its item id. Cleared: writes use EMPTY AAD (v1), byte-compatible with the
/// oldest ciphertexts.
///
/// Reading does not depend on this flag — `decrypt_note_with_content_key_v2`
/// tries v2 and falls back to v1 — so legacy ciphertexts stay readable and
/// clearing the flag is a safe rollback for NEW writes only.
///
/// ORDERING CONSTRAINT: every client (web, Android, iOS) must be able to READ v2
/// before ANY client sets this flag. A v2 ciphertext whose AAD a client cannot
/// reproduce byte-for-byte is unreadable on that client, and no later flag
/// change makes it readable again.
const AAD_V2_WRITE_ENABLED: bool = true;

/// v2 context-AAD binding a note-content ciphertext to its `item_id`, so a
/// server can't present note A's ciphertext (+ its wrapped content key) as
/// note B. 32-byte BLAKE3 over a u16-length-prefixed TLV.
///
/// This MUST be byte-identical to the web client's implementation:
///   input       = u16le(0) || u32le(0) || u16le(len(item_id)) || item_id || u16le(0)
///   context_key = BLAKE3::derive_key("pingolin.aad.v2.context", "pingolin.aad.v2.note_content")
///   aad         = BLAKE3::keyed_hash(context_key, input)
/// (container id + extra are empty for note content; key_version is 0 — notes
/// don't per-note-version the content key.)
fn note_content_aad_v2(item_id: &str) -> [u8; 32] {
    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(&0u16.to_le_bytes()); // LP(container="")
    input.extend_from_slice(&0u32.to_le_bytes()); // key_version = 0
    let id = item_id.as_bytes();
    input.extend_from_slice(&(id.len() as u16).to_le_bytes()); // LP(item_id)
    input.extend_from_slice(id);
    input.extend_from_slice(&0u16.to_le_bytes()); // LP(extra="")
    let context_key =
        blake3::derive_key("pingolin.aad.v2.context", b"pingolin.aad.v2.note_content");
    *blake3::keyed_hash(&context_key, &input).as_bytes()
}

/// Encrypt note plaintext under a per-note content key
/// (XChaCha20-Poly1305, random 24-byte nonce, EMPTY AAD = v1). Byte-compatible
/// with the web's `encryptWithContentKey`.
///
/// No context binding: nothing stops a server presenting this ciphertext as
/// some other item's. Kept for existing callers; new callers want the `_v2`
/// variant below, which binds the item id.
pub fn encrypt_note_with_content_key(
    plaintext: String,
    content_key: Vec<u8>,
) -> Result<NoteCiphertext, CollabError> {
    let content_key = Zeroizing::new(content_key);
    encrypt_note_with_content_key_inner(&plaintext, &content_key, &[])
}

/// Inverse of `encrypt_note_with_content_key` (v1, empty AAD). Returns None on
/// auth failure. Reads v1 ciphertexts only — use `_v2` to also read v2.
pub fn decrypt_note_with_content_key(
    nonce_b64: String,
    ciphertext_b64: String,
    content_key: Vec<u8>,
) -> Option<String> {
    let content_key = Zeroizing::new(content_key);
    decrypt_note_with_content_key_inner(&nonce_b64, &ciphertext_b64, &content_key, None)
}

/// AAD v2 encrypt: binds the ciphertext to `item_id`. Writes v2 while
/// `AAD_V2_WRITE_ENABLED` is set; with it cleared this writes v1 (empty AAD),
/// so it is a drop-in for the v1 function either way.
pub fn encrypt_note_with_content_key_v2(
    plaintext: String,
    content_key: Vec<u8>,
    item_id: String,
) -> Result<NoteCiphertext, CollabError> {
    let content_key = Zeroizing::new(content_key);
    let aad_v2 = note_content_aad_v2(&item_id);
    let aad: &[u8] = if AAD_V2_WRITE_ENABLED { &aad_v2 } else { &[] };
    encrypt_note_with_content_key_inner(&plaintext, &content_key, aad)
}

/// AAD v2 decrypt: tries the v2 context-AAD (bound to `item_id`), then falls
/// back to v1 (empty AAD) for legacy ciphertexts. A ciphertext presented under
/// the wrong `item_id` fails BOTH (v2 mismatches; v1 fails because it was sealed
/// with a non-empty AAD) → None = tamper rejected.
pub fn decrypt_note_with_content_key_v2(
    nonce_b64: String,
    ciphertext_b64: String,
    content_key: Vec<u8>,
    item_id: String,
) -> Option<String> {
    let content_key = Zeroizing::new(content_key);
    let aad_v2 = note_content_aad_v2(&item_id);
    decrypt_note_with_content_key_inner(&nonce_b64, &ciphertext_b64, &content_key, Some(&aad_v2))
}

fn encrypt_note_with_content_key_inner(
    plaintext: &str,
    content_key: &[u8],
    aad: &[u8],
) -> Result<NoteCiphertext, CollabError> {
    if content_key.len() != 32 {
        return Err(CollabError::Aead("content key must be 32 bytes".into()));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|e| CollabError::Aead(e.to_string()))?;
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|e| CollabError::Aead(e.to_string()))?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(NoteCiphertext {
        nonce_b64: engine.encode(nonce_bytes),
        ciphertext_b64: engine.encode(&ct),
    })
}

/// `v2_aad = Some(..)` tries that context-AAD first then v1; `None` reads v1 only.
fn decrypt_note_with_content_key_inner(
    nonce_b64: &str,
    ciphertext_b64: &str,
    content_key: &[u8],
    v2_aad: Option<&[u8]>,
) -> Option<String> {
    if content_key.len() != 32 {
        return None;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let nonce_bytes = engine.decode(nonce_b64.as_bytes()).ok()?;
    let ct = engine.decode(ciphertext_b64.as_bytes()).ok()?;
    if nonce_bytes.len() != 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new_from_slice(content_key).ok()?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let pt = if let Some(aad) = v2_aad {
        match cipher.decrypt(
            nonce,
            Payload {
                msg: ct.as_slice(),
                aad,
            },
        ) {
            Ok(pt) => pt,
            // Legacy v1 ciphertext (empty AAD) — fall back.
            Err(_) => cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ct.as_slice(),
                        aad: &[],
                    },
                )
                .ok()?,
        }
    } else {
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct.as_slice(),
                    aad: &[],
                },
            )
            .ok()?
    };
    String::from_utf8(pt).ok()
}

// -----------------------------------------------------------------------
// Sealed-box wrapping for share recipients (NaCl crypto_box_seal)
// -----------------------------------------------------------------------
//
// Anonymous-sender wrap: generates an ephemeral X25519 keypair, computes
// a shared secret with the recipient's public key, and encrypts the
// content key under a keyed XSalsa20-Poly1305 AEAD. Wire format is
// identical to the web's `sodium.crypto_box_seal`.

fn parse_pub_key(raw: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    // Accept hex (64 chars) or base64. The web auth service returns a
    // hex string; our own `sharer_public_key` cache can be either.
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
        }
        return Some(out);
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine.decode(raw.as_bytes()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// SECURITY: reject small-order X25519 points before sealing to them. A
/// server-supplied recipient public key that is a small-order point forces the
/// sealed-box ECDH to a predictable (often all-zero) shared secret, letting a
/// malicious relay recover the wrapped content key. The Track mobile-sdk guards
/// every external pubkey with `reject_small_order_public`; this is the
/// note-collab equivalent.
///
/// We probe with several fixed non-trivial scalars via `mul_clamped`, which
/// applies x25519 cofactor clamping (scalar becomes a multiple of 8) so a point
/// of order dividing 8 maps to the all-zero u-coordinate. `mul_clamped` is
/// byte-identical to Track's `StaticSecret::diffie_hellman` probe. Multiple
/// probes catch the known small-order points (order 1, 2, 4, 8) that a single
/// scalar may miss.
fn reject_small_order_recipient(pk_bytes: &[u8; 32]) -> Result<(), CollabError> {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    const PROBES: [[u8; 32]; 4] = [
        [1u8; 32],
        [2u8; 32],
        [
            0x5a, 0xc1, 0x7b, 0x93, 0x42, 0x08, 0xff, 0xe1, 0x6d, 0xde, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f, 0x1e, 0x2d, 0x3c,
            0x4b, 0x5a, 0x69, 0x78,
        ],
        [
            0xa3, 0x11, 0x5c, 0x7e, 0xf0, 0x92, 0x04, 0x16, 0x28, 0x3a, 0x4c, 0x5e, 0x70, 0x82,
            0x94, 0xa6, 0xb8, 0xca, 0xdc, 0xee, 0x01, 0x13, 0x25, 0x37, 0x49, 0x5b, 0x6d, 0x7f,
            0x91, 0xa3, 0xb5, 0xc7,
        ],
    ];
    let point = MontgomeryPoint(*pk_bytes);
    for probe in &PROBES {
        // PartialEq on MontgomeryPoint is constant-time (ct_eq).
        if point.mul_clamped(*probe) == MontgomeryPoint([0u8; 32]) {
            return Err(CollabError::Aead(
                "recipient public key is a small-order point".into(),
            ));
        }
    }
    Ok(())
}

/// Wrap a content key for a specific recipient using their X25519
/// public key. Returns the sealed ciphertext base64-encoded — drop
/// this into the `wrapped_key` field of a `POST /items/{id}/share`
/// request.
pub fn seal_for_recipient(
    content_key: Vec<u8>,
    recipient_public_key: String,
) -> Result<String, CollabError> {
    // SECURITY: wipe the owned content key on every return path. We only ever
    // hand back the sealed ciphertext, never the key, so this is safe.
    let content_key = Zeroizing::new(content_key);
    if content_key.len() != 32 {
        return Err(CollabError::Aead("content key must be 32 bytes".into()));
    }
    let pk_bytes = parse_pub_key(&recipient_public_key).ok_or_else(|| {
        CollabError::Aead("recipient public key must be 32 bytes hex or base64".into())
    })?;
    // SECURITY: see `reject_small_order_recipient` — a small-order recipient key
    // would force a predictable shared secret.
    reject_small_order_recipient(&pk_bytes)?;
    let pk = crypto_box::PublicKey::from_bytes(pk_bytes);
    let sealed = pk
        .seal(&mut rand::thread_rng(), &content_key)
        .map_err(|e: crypto_box::aead::Error| CollabError::Aead(e.to_string()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&sealed))
}

/// Open a sealed-box wrapped content key with the recipient's own
/// 32-byte X25519 private scalar. Returns None on decryption failure
/// (wrong key, tampered ciphertext, malformed input).
pub fn open_seal(wrapped_b64: String, mut private_key: Vec<u8>) -> Option<Vec<u8>> {
    use blake2::Digest;
    use crypto_secretbox::{aead::generic_array::GenericArray, Kdf};
    use curve25519_dalek::{
        scalar::{clamp_integer, Scalar},
        MontgomeryPoint,
    };

    if private_key.len() != 32 {
        private_key.zeroize();
        return None;
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&private_key);
    private_key.zeroize();

    // Decode the sealed blob first; a malformed or too-short input returns
    // before we touch key material. A sealed box is `ephemeral_pk(32) || ct`.
    let engine = base64::engine::general_purpose::STANDARD;
    let sealed = match engine.decode(wrapped_b64.as_bytes()) {
        Ok(s) if s.len() > 32 => s,
        _ => {
            sk_bytes.zeroize();
            return None;
        }
    };

    // Reconstruct crypto_box 0.9's `SecretKey::unseal` WITHOUT constructing a
    // `crypto_box::SecretKey`, whose Drop zeroizes only its internal Scalar and
    // leaves the raw 32-byte `bytes` copy un-wiped in freed memory (the same leak
    // `derive_sharing_public_key` avoids). Every step below is byte-identical to
    // `SalsaBox::new(&ephemeral_pk, &secret_key)` + `decrypt`:
    //   scalar = from_bytes_mod_order(clamp_integer(sk))   (reduced, exactly as crypto_box)
    //   shared = scalar * ephemeral_pk                     (X25519 DH)
    //   key    = HSalsa20(shared, 0) via crypto_secretbox::Kdf  (SalsaBox's own KDF)
    //   nonce  = BLAKE2b-24(ephemeral_pk || recipient_pk)
    // and we wipe the scalar + shared secret before returning.
    let mut scalar = Scalar::from_bytes_mod_order(clamp_integer(sk_bytes));
    sk_bytes.zeroize();

    let mut eph_bytes = [0u8; 32];
    eph_bytes.copy_from_slice(&sealed[..32]);
    let ephemeral_pk = MontgomeryPoint(eph_bytes);
    let recipient_pk = MontgomeryPoint::mul_base(&scalar);

    let shared = Zeroizing::new(&scalar * &ephemeral_pk);
    scalar.zeroize();

    // HSalsa20 KDF over the shared secret with a zero 16-byte nonce == the SalsaBox key.
    let key = Zeroizing::new(<XSalsa20Poly1305 as Kdf>::kdf(
        GenericArray::from_slice(shared.as_bytes()),
        &GenericArray::default(),
    ));

    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U24>::new();
    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(recipient_pk.as_bytes());
    let nonce = hasher.finalize();

    XSalsa20Poly1305::new(&key)
        .decrypt(&nonce, &sealed[32..])
        .ok()
}

/// Derive the X25519 public key from a 32-byte private scalar. The web client
/// uses `sodium.crypto_scalarmult_base`; this is byte-equivalent, so a mobile
/// client can publish its own public key (hex-encoded) to peers.
pub fn derive_sharing_public_key(mut private_key: Vec<u8>) -> Option<String> {
    if private_key.len() != 32 {
        private_key.zeroize();
        return None;
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&private_key);
    private_key.zeroize();
    // Derive the public key WITHOUT constructing a crypto_box::SecretKey — same
    // un-wiped `bytes` leak described in `open_seal`. Clamped base-point
    // multiplication on curve25519-dalek is byte-equivalent (it matches
    // sodium.crypto_scalarmult_base and crypto_box's own public_key derivation)
    // and keeps no lingering owned copy; we wipe our own `sk` immediately after.
    let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(sk);
    sk.zeroize();
    let bytes = pk.to_bytes();
    let mut hex = String::with_capacity(64);
    for b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    Some(hex)
}

/// Derive the 32-byte per-note collab session key from a 32-byte shared secret
/// (the note's content key, which both peers already hold).
///
/// Keyed BLAKE2b-256 over `"pingolin-note-collab:{note_id}"` — an adequate KDF
/// because the key input is already 32 uniformly random bytes. Neither the
/// primitive nor the label is free to change: the web client derives the same
/// way, and the two sides must land on identical bytes or collab frames fail to
/// authenticate.
pub fn derive_collab_key(note_id: String, mut secret: Vec<u8>) -> Result<Vec<u8>, CollabError> {
    if secret.len() != 32 {
        secret.zeroize();
        return Err(CollabError::Aead("secret must be 32 bytes".into()));
    }
    use blake2::{
        digest::{FixedOutput, KeyInit as MacKey, Update as MacUpdate},
        Blake2bMac,
    };
    type Blake2b256 = Blake2bMac<blake2::digest::consts::U32>;
    let mac = <Blake2b256 as MacKey>::new_from_slice(&secret);
    // new_from_slice copies the key into the MAC state; wipe our input copy.
    secret.zeroize();
    let mut mac = mac.map_err(|e| CollabError::Aead(e.to_string()))?;
    MacUpdate::update(
        &mut mac,
        format!("pingolin-note-collab:{}", note_id).as_bytes(),
    );
    let mut out = mac.finalize_fixed();
    let v = out.to_vec();
    // SECURITY: `out` holds the same session-key bytes as the returned Vec, so
    // wipe it too (as `generate_content_key` does with its output array).
    // GenericArray derefs to [u8], which is Zeroize, so this is a volatile wipe.
    out.as_mut_slice().zeroize();
    Ok(v)
}

// ============================================================================
// Wrap signatures for share-invite rows.
//
// Threat: a malicious server inserts (or rewrites) a share row
// claiming a different sender, or substitutes wrapped_key with a key it
// controls. Sealed-box AEAD authenticates the channel content but not
// the sender identity — the recipient unwraps to either an attacker key
// or garbage with no way to distinguish it from a legitimate but stale
// share.
//
// Mitigation: every wrap is signed by the sender's Ed25519 identity
// key; the recipient verifies before trusting the share row. Same
// primitive as the Track mobile-sdk crate (Ed25519 over a BLAKE3 keyed
// hash); the canonical input shape is Note-specific because Note's wrap
// is a sealed_box rather than Track's crypto_box_easy.
//
// Wire format (locked — the web client reimplements this in TypeScript
// and must produce these bytes exactly; Android and iOS reach this code
// through the UniFFI bindings, so they get it for free):
//
//   ctx_key = blake3::derive_key("pingolin.sig.v1.context_key", DOMAIN)
//   msg = u8(16)|sender_uuid_bytes
//       ‖ u8(16)|recipient_uuid_bytes
//       ‖ u8(16)|item_uuid_bytes
//       ‖ u32_le(content_key_version)
//       ‖ u8(LEN)|wrapped_key_bytes
//   sig_input = blake3::keyed_hash(ctx_key, msg)
//   signature = Ed25519.sign(sig_input)  → 64 bytes, hex-encoded
//
// `wrapped_key_bytes` is the raw decoded base64 of the sealed_box blob
// (80 bytes for a 32-byte content key). u8 length prefix → max 255 B
// (sealed_box is at most 32-byte payload + 16-byte tag + 32-byte
// ephemeral pubkey = 80 bytes; well within range).
// ============================================================================

const NOTE_SHARE_INVITE_DOMAIN: &str = "pingolin.sig.v1.note_share_invite";

/// Parameters for the canonical Note share-invite sig_input.
/// Defined in collab.udl (the UniFFI codegen emits the Record derive
/// from there) so we don't add a duplicate proc-macro one here.
#[derive(Debug, Clone)]
pub struct NoteShareWrapParams {
    /// Sender (sharer) user_id, UUID hex form (with or without hyphens).
    pub sender_user_id: String,
    /// Recipient user_id, UUID hex form.
    pub recipient_user_id: String,
    /// Item being shared, UUID hex form.
    pub item_id: String,
    /// Content-key generation bound into the signature. Signers emit the item's
    /// real generation; signatures from older signers carry 0, which
    /// `verify_note_share_wrap_gen` still accepts (and reports back as 0).
    pub content_key_version: u32,
    /// Base64 sealed_box blob the recipient will unseal.
    pub wrapped_key_b64: String,
}

fn uuid_to_16_bytes(s: &str) -> Result<[u8; 16], CollabError> {
    uuid::Uuid::parse_str(s)
        .map(|u| *u.as_bytes())
        .map_err(|e| CollabError::Aead(format!("invalid UUID {}: {}", s, e)))
}

fn note_share_sig_input(params: &NoteShareWrapParams) -> Result<blake3::Hash, CollabError> {
    let ctx_key = blake3::derive_key(
        "pingolin.sig.v1.context_key",
        NOTE_SHARE_INVITE_DOMAIN.as_bytes(),
    );

    let sender = uuid_to_16_bytes(&params.sender_user_id)?;
    let recipient = uuid_to_16_bytes(&params.recipient_user_id)?;
    let item = uuid_to_16_bytes(&params.item_id)?;
    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(params.wrapped_key_b64.as_bytes())
        .map_err(|e| CollabError::Aead(format!("wrapped_key not base64: {}", e)))?;
    if wrapped.len() > u8::MAX as usize {
        return Err(CollabError::Aead(
            "wrapped_key exceeds u8 length prefix".into(),
        ));
    }

    let mut msg: Vec<u8> = Vec::with_capacity(1 + 16 + 1 + 16 + 1 + 16 + 4 + 1 + wrapped.len());
    msg.push(16);
    msg.extend_from_slice(&sender);
    msg.push(16);
    msg.extend_from_slice(&recipient);
    msg.push(16);
    msg.extend_from_slice(&item);
    msg.extend_from_slice(&params.content_key_version.to_le_bytes());
    msg.push(wrapped.len() as u8);
    msg.extend_from_slice(&wrapped);

    Ok(blake3::keyed_hash(&ctx_key, &msg))
}

/// Sign a Note share-invite wrap with the user's Ed25519 secret seed. Returns
/// the 64-byte signature as 128-char lowercase hex. The seed is what callers
/// should already have decrypted from the auth backend's
/// `encrypted_signing_private_key` blob.
///
/// Accepts two formats, matching the Track mobile-sdk crate's
/// `import_signing_private_key`:
///   - 32 bytes: the RFC 8032 seed (what `generate_note_signing_keypair`
///     emits and what ed25519-dalek prefers).
///   - 64 bytes: libsodium's expanded `secretKey` shape (32-byte seed
///     || 32-byte public key). Accounts whose seed was minted via the
///     web/account app's `sodium.crypto_sign_keypair()` land here — the
///     first 32 bytes are the seed, the rest is the public key glued on
///     for libsodium's API convenience. Strip the redundant suffix and
///     treat as a normal seed.
pub fn sign_note_share_wrap(
    mut secret_seed: Vec<u8>,
    params: NoteShareWrapParams,
) -> Result<String, CollabError> {
    // Compute the canonical sig_input first: a malformed `params` bails before
    // we copy any key material onto the stack, so no `?` sits between seed
    // creation and its zeroize.
    let sig_input = note_share_sig_input(&params)?;
    let mut seed = [0u8; 32];
    match secret_seed.len() {
        32 => seed.copy_from_slice(&secret_seed),
        64 => seed.copy_from_slice(&secret_seed[..32]),
        n => {
            secret_seed.zeroize();
            return Err(CollabError::Aead(format!(
                "signing seed must be 32 or 64 bytes (got {})",
                n
            )));
        }
    }
    secret_seed.zeroize();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    seed.zeroize();
    let sig = ed25519_dalek::Signer::sign(&sk, sig_input.as_bytes());
    Ok(hex::encode(sig.to_bytes()))
}

/// Mint a fresh Ed25519 identity signing keypair. Returns the raw
/// 32-byte secret seed plus the 32-byte verifying key encoded as a
/// 64-char lowercase hex string (matching `compute_note_safety_number`'s
/// pubkey-in-hex convention).
///
/// The seed is what callers should encrypt under the master key and ship
/// to the auth backend as `encrypted_signing_private_key`; the verifying
/// key is what gets stored as `signing_public_key`. Stateless on purpose
/// — note-collab-sdk does not own a key store the way Track's mobile-sdk
/// does, so the caller is responsible for persisting both halves.
pub fn generate_note_signing_keypair() -> NoteSigningKeyPair {
    use rand::rngs::OsRng;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());
    let secret_seed = seed.to_vec();
    // Wipe the stack copy; the returned seed is the caller's to persist.
    seed.zeroize();
    NoteSigningKeyPair {
        secret_seed,
        verifying_key_hex: vk_hex,
    }
}

pub struct NoteSigningKeyPair {
    pub secret_seed: Vec<u8>,
    pub verifying_key_hex: String,
}

/// Outcome of [`verify_note_share_wrap_gen`]: whether the signature verified,
/// and the content-key generation it ACTUALLY verified under — which is what
/// callers must feed into their rollback check, never the claimed generation.
pub struct WrapVerifyResult {
    pub verified: bool,
    pub effective_generation: u32,
}

/// Boolean form of [`verify_note_share_wrap_gen`]: `Ok(true)` for a valid
/// signature, `Ok(false)` for a well-formed but mathematically invalid one,
/// `Err` for parse/length failures.
///
/// A reader that enforces rollback protection must call
/// `verify_note_share_wrap_gen` instead and check monotonicity on
/// `effective_generation`, which this form discards.
pub fn verify_note_share_wrap(
    signing_pubkey_hex: String,
    signature_hex: String,
    params: NoteShareWrapParams,
) -> Result<bool, CollabError> {
    Ok(verify_note_share_wrap_gen(signing_pubkey_hex, signature_hex, params)?.verified)
}

/// Verify a share-invite wrap signature and report the content-key generation
/// it actually verified under. Callers enforcing rollback protection must
/// compare `effective_generation` — never the server-supplied version — against
/// the highest generation they have already accepted for the item.
pub fn verify_note_share_wrap_gen(
    signing_pubkey_hex: String,
    signature_hex: String,
    params: NoteShareWrapParams,
) -> Result<WrapVerifyResult, CollabError> {
    let not_verified = WrapVerifyResult {
        verified: false,
        effective_generation: 0,
    };
    let pk = hex::decode(&signing_pubkey_hex)
        .map_err(|e| CollabError::Aead(format!("pubkey hex: {}", e)))?;
    if pk.len() != 32 {
        return Err(CollabError::Aead(format!(
            "signing pubkey must be 32 bytes (got {})",
            pk.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CollabError::Aead(format!("invalid pubkey: {}", e)))?;
    let sig_bytes = hex::decode(&signature_hex)
        .map_err(|e| CollabError::Aead(format!("signature hex: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(CollabError::Aead(format!(
            "signature must be 64 bytes (got {})",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Verify-both. The sig_input binds `content_key_version`, and signatures come
    // in two vintages: current signers emit the item's REAL generation, older ones
    // hardcoded 0 — so a legacy signature does not pin a version at all, and a
    // malicious server can replay an older shared-note version past it. This
    // verifier accepts a signature valid under the PASSED version OR under legacy
    // 0, recomputing with 0 only when the passed version is non-zero and the first
    // check failed. Both vintages verify, with no flag day.
    //
    // CRUCIAL for rollback protection: we return the generation the signature
    // ACTUALLY verified under, not the caller/server-claimed one. A signature
    // that only validates via the legacy-0 fallback reports effective_generation
    // = 0 REGARDLESS of the claimed version. Otherwise a server could take an old
    // gen-0 wrap (a stale content key a removed member still knows), relabel it
    // "generation 99", and the fallback would happily verify it — laundering a
    // rollback past the reader's highest-seen floor. Reporting 0 pins it below
    // any real generation, so once the reader has seen gen >= 1 the launder fails.
    //
    // ORDERING CONSTRAINT for any change to what the version field carries:
    // every client (web, Android, iOS) must ACCEPT the new shape before ANY client
    // starts signing it. A verifier only ever checks the version it was passed
    // plus the legacy-0 fallback, so a signature over a scheme it does not know is
    // simply rejected. Ship the verifier everywhere first, then the signer.
    //
    // verify_strict rejects non-canonical R/A encodings, closing the Ed25519
    // signature-malleability window that the permissive `verify` leaves open.
    let sig_input = note_share_sig_input(&params)?;
    if vk.verify_strict(sig_input.as_bytes(), &signature).is_ok() {
        return Ok(WrapVerifyResult {
            verified: true,
            effective_generation: params.content_key_version,
        });
    }
    if params.content_key_version != 0 {
        let mut legacy = params.clone();
        legacy.content_key_version = 0;
        let legacy_input = note_share_sig_input(&legacy)?;
        if vk
            .verify_strict(legacy_input.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(WrapVerifyResult {
                verified: true,
                effective_generation: 0,
            });
        }
    }
    Ok(not_verified)
}

/// Compute the 60-decimal-digit safety number for out-of-band identity
/// verification with a peer (12 groups of 5 digits, single ASCII space
/// between groups). Symmetric: peer.compute(self) === self.compute(peer)
/// thanks to lex-min ordering of the two material blobs.
///
/// The digits are the MOST-significant 60 decimal digits of the big-endian
/// 240-bit SAS integer (BLAKE3 keyed hash, first 30 bytes); the exact digit
/// layout lives in `safety_number_from_sas_bytes`. This matches the Track
/// mobile-sdk crate's `compute_safety_number` and the web `computeSafetyNumber`,
/// and a locked shared test vector keeps all three byte-identical.
pub fn compute_note_safety_number(
    self_user_id: String,
    self_sharing_pubkey_hex: String,
    self_signing_pubkey_hex: String,
    peer_user_id: String,
    peer_sharing_pubkey_hex: String,
    peer_signing_pubkey_hex: String,
) -> Result<String, CollabError> {
    let self_uuid = uuid_to_16_bytes(&self_user_id)?;
    let peer_uuid = uuid_to_16_bytes(&peer_user_id)?;
    let self_sharing =
        hex::decode(&self_sharing_pubkey_hex).map_err(|e| CollabError::Aead(e.to_string()))?;
    let self_signing =
        hex::decode(&self_signing_pubkey_hex).map_err(|e| CollabError::Aead(e.to_string()))?;
    let peer_sharing =
        hex::decode(&peer_sharing_pubkey_hex).map_err(|e| CollabError::Aead(e.to_string()))?;
    let peer_signing =
        hex::decode(&peer_signing_pubkey_hex).map_err(|e| CollabError::Aead(e.to_string()))?;
    if [
        self_sharing.len(),
        self_signing.len(),
        peer_sharing.len(),
        peer_signing.len(),
    ]
    .iter()
    .any(|&n| n != 32)
    {
        return Err(CollabError::Aead("pubkeys must be 32 bytes each".into()));
    }

    let mut material_self = Vec::with_capacity(80);
    material_self.extend_from_slice(&self_uuid);
    material_self.extend_from_slice(&self_sharing);
    material_self.extend_from_slice(&self_signing);

    let mut material_peer = Vec::with_capacity(80);
    material_peer.extend_from_slice(&peer_uuid);
    material_peer.extend_from_slice(&peer_sharing);
    material_peer.extend_from_slice(&peer_signing);

    // Lex-min ordering keeps the SAS symmetric.
    let combined: Vec<u8> = if material_self < material_peer {
        let mut v = Vec::with_capacity(160);
        v.extend_from_slice(&material_self);
        v.extend_from_slice(&material_peer);
        v
    } else {
        let mut v = Vec::with_capacity(160);
        v.extend_from_slice(&material_peer);
        v.extend_from_slice(&material_self);
        v
    };

    let sas_key = blake3::derive_key("pingolin.sas.v1", b"safety_number");
    let full = blake3::keyed_hash(&sas_key, &combined);
    let sas_bytes = &full.as_bytes()[..30];

    Ok(safety_number_from_sas_bytes(sas_bytes))
}

/// Convert 30 SAS bytes to the canonical 60-decimal-digit safety number,
/// formatted as 12 space-separated groups of 5 digits.
///
/// Produces the MOST-significant 60 digits of the big-endian 240-bit integer's
/// full decimal expansion (left-zero-padded if the integer is somehow shorter
/// than 60 digits). This reproduces, byte-for-byte, Track mobile-sdk's
/// `safety_number_from_sas_bytes` (`num-bigint` `from_bytes_be` →
/// `format!("{:0>60}", to_str_radix(10))` → first 60 chars) and the web
/// `computeSafetyNumber`. We do the big-integer division by hand to avoid
/// pulling a `num-bigint` dependency into note-collab-sdk.
fn safety_number_from_sas_bytes(sas_bytes: &[u8]) -> String {
    // Full decimal expansion, least-significant digit first, by repeated
    // divide-by-10 until the running value reaches zero. A 240-bit integer is
    // at most 73 decimal digits.
    let mut value = [0u8; 30];
    value.copy_from_slice(sas_bytes);
    let mut lsd_first: Vec<u8> = Vec::with_capacity(80);
    loop {
        let mut carry: u32 = 0;
        let mut all_zero = true;
        for byte in value.iter_mut() {
            let cur = carry * 256 + (*byte as u32);
            *byte = (cur / 10) as u8;
            if *byte != 0 {
                all_zero = false;
            }
            carry = cur % 10;
        }
        lsd_first.push(carry as u8);
        if all_zero {
            break;
        }
    }

    // Take the most-significant 60 digits (matching `{:0>60}` then `[..60]`):
    // left-pad with zeros when there are fewer than 60 digits, otherwise drop
    // the least-significant overflow.
    let ndigits = lsd_first.len();
    let mut out = [0u8; 60];
    if ndigits >= 60 {
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = lsd_first[ndigits - 1 - i];
        }
    } else {
        let pad = 60 - ndigits;
        for i in 0..ndigits {
            out[pad + i] = lsd_first[ndigits - 1 - i];
        }
    }

    // 12 groups of 5, single ASCII space between groups.
    let mut s = String::with_capacity(60 + 11);
    for (i, d) in out.iter().enumerate() {
        if i != 0 && i % 5 == 0 {
            s.push(' ');
        }
        s.push((b'0' + d) as char);
    }
    s
}

#[cfg(test)]
mod safety_number_vectors {
    // LOCKED cross-language SAS vector. crates/mobile-sdk asserts these SAME
    // strings for the SAME 30 input bytes (see its `safety_number_vectors`
    // test), guaranteeing note-collab-sdk and Track mobile-sdk produce
    // byte-identical out-of-band safety numbers.
    #[test]
    fn safety_number_from_sas_bytes_matches_mobile_sdk() {
        // Vector A: 1..=30 ramp (70-digit integer).
        let ramp: [u8; 30] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30,
        ];
        assert_eq!(
            super::safety_number_from_sas_bytes(&ramp),
            "69559 83830 57695 33006 27822 53272 10632 84149 72514 57156 24041 20155",
        );

        // Vector B: all 0xFF (2^240 - 1, a 73-digit integer — exercises the
        // most-significant-60 truncation that drops the low ~13 digits).
        let max: [u8; 30] = [0xFF; 30];
        assert_eq!(
            super::safety_number_from_sas_bytes(&max),
            "17668 47064 77838 43295 83297 50074 29185 15827 48389 68756 18958 12160",
        );
    }
}

#[cfg(test)]
mod aad_v2_tests {
    use super::*;
    use rand::RngCore;

    fn key() -> Vec<u8> {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k.to_vec()
    }

    // Build a v2 (context-AAD-bound) ciphertext regardless of the write flag, so
    // the reader's v2 path and tamper rejection stay covered even if writes are v1.
    fn make_v2_ct(plaintext: &str, content_key: &[u8], item_id: &str) -> NoteCiphertext {
        let cipher = XChaCha20Poly1305::new_from_slice(content_key).unwrap();
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = note_content_aad_v2(item_id);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .unwrap();
        let engine = base64::engine::general_purpose::STANDARD;
        NoteCiphertext {
            nonce_b64: engine.encode(nonce_bytes),
            ciphertext_b64: engine.encode(&ct),
        }
    }

    // Cross-language SEMANTIC interop vector (this SDK ↔ the web client).
    // Byte-parity of the AAD alone (locked in `aad_v2_parity` below) proves only
    // that the AAD input matches; this locks the FULL encrypt path — AAD wired
    // into XChaCha20-Poly1305, the nonce||ct framing, base64 — so a v2 note
    // written on one platform decrypts on the other. The same fixed
    // (key, nonce, pt, item_id) must yield THIS exact ciphertext on the web.
    #[test]
    fn cross_language_v2_ciphertext_vector() {
        let key = [0x2au8; 32];
        let nonce_bytes = [0x07u8; 24];
        let plaintext = "pingolin aad-v2 interop";
        let item_id = "item-A";

        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = note_content_aad_v2(item_id);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .unwrap();
        let engine = base64::engine::general_purpose::STANDARD;
        let nonce_b64 = engine.encode(nonce_bytes);
        let ct_b64 = engine.encode(&ct);
        assert_eq!(nonce_b64, "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH");
        assert_eq!(
            ct_b64,
            "s4U7w5J5wVGIsFfH5UDugg7dbhIQX00xazjSx4T0iNZKNIzKFpoE"
        );

        // Round-trips through the v2 reader; a relocated id is rejected.
        assert_eq!(
            decrypt_note_with_content_key_v2(
                nonce_b64.clone(),
                ct_b64.clone(),
                key.to_vec(),
                item_id.into()
            )
            .as_deref(),
            Some(plaintext)
        );
        assert_eq!(
            decrypt_note_with_content_key_v2(nonce_b64, ct_b64, key.to_vec(), "item-B".into()),
            None
        );
    }

    #[test]
    fn v2_roundtrips_with_correct_item_id() {
        let k = key();
        let ct = make_v2_ct("secret note", &k, "item-A");
        let out =
            decrypt_note_with_content_key_v2(ct.nonce_b64, ct.ciphertext_b64, k, "item-A".into());
        assert_eq!(out.as_deref(), Some("secret note"));
    }

    #[test]
    fn v2_rejects_relocated_ciphertext() {
        // A v2 ciphertext for item-A presented as item-B must fail: v2 AAD
        // mismatches, and the v1 fallback fails too (it was sealed with AAD).
        let k = key();
        let ct = make_v2_ct("secret note", &k, "item-A");
        let out =
            decrypt_note_with_content_key_v2(ct.nonce_b64, ct.ciphertext_b64, k, "item-B".into());
        assert_eq!(out, None, "relocated v2 ciphertext must be rejected");
    }

    #[test]
    fn v1_legacy_ciphertext_still_decrypts_via_v2_reader() {
        // The v1 (empty-AAD) writer's output must still decrypt through the v2
        // reader's fallback, and through the plain v1 reader.
        let k = key();
        let ct = encrypt_note_with_content_key("legacy".into(), k.clone()).unwrap();
        assert_eq!(
            decrypt_note_with_content_key_v2(
                ct.nonce_b64.clone(),
                ct.ciphertext_b64.clone(),
                k.clone(),
                "item-A".into()
            )
            .as_deref(),
            Some("legacy")
        );
        assert_eq!(
            decrypt_note_with_content_key(ct.nonce_b64, ct.ciphertext_b64, k).as_deref(),
            Some("legacy")
        );
    }

    #[test]
    fn aad_is_deterministic_and_item_scoped() {
        assert_eq!(note_content_aad_v2("x"), note_content_aad_v2("x"));
        assert_ne!(note_content_aad_v2("x"), note_content_aad_v2("y"));
    }
}

#[cfg(test)]
mod aad_v2_parity {
    use super::*;
    /// Cross-LANGUAGE parity vector. The web client's `noteContentAadV2("item-1")`
    /// MUST produce these exact 32 bytes, or v2 note ciphertexts are unreadable
    /// across mobile/web. If this fails after a format change, update BOTH sides
    /// in lockstep.
    #[test]
    fn aad_matches_cross_language_vector() {
        assert_eq!(
            hex::encode(note_content_aad_v2("item-1")),
            "a40b78faec114481be36d3929dd9bebc1f521b66feb6d67291a2a2417813f207"
        );
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    // Mirrors `deterministic_seed_update`'s client-id derivation so a test can
    // assert the id directly instead of decoding it back out of the wire bytes.
    fn seed_client_id(content: &str) -> u64 {
        let b = *blake3::hash(content.as_bytes()).as_bytes();
        let n = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        n & ((1u64 << 53) - 1)
    }

    // Cross-LANGUAGE seed vector. The seed client id is DERIVED FROM THE CONTENT
    // (BLAKE3): for "hello world" it is the integer 3389416114571735, asserted
    // below so the web side can cross-check the id directly. The web client's
    // deterministic seed (Yjs) produces these EXACT bytes for the same content —
    // verified byte-identical against @noble/hashes + yjs — so a body seeded on
    // web and on mobile yields the SAME CRDT items and dedups on merge. If the
    // derivation changes, the web seed MUST change in lockstep or web↔mobile
    // collab duplicates the initial body.
    #[test]
    fn deterministic_seed_cross_language_vector() {
        assert_eq!(seed_client_id("hello world"), 3389416114571735);
        let u = deterministic_seed_update("hello world".to_string()).unwrap();
        assert_eq!(
            u.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "0101d79385fcfed4820600040104626f64790b68656c6c6f20776f726c6400"
        );
    }

    // Identical content → identical seed bytes, so two devices seeding the same
    // body mint byte-identical CRDT items that Yjs de-dups on merge.
    #[test]
    fn identical_content_yields_identical_seed_bytes() {
        let a = deterministic_seed_update("hello world".to_string()).unwrap();
        let b = deterministic_seed_update("hello world".to_string()).unwrap();
        assert_eq!(a, b);
    }

    // Divergent content → DIFFERENT client ids (no false dedup). This is the
    // point of the content-derived id: a shared constant id makes two divergent
    // seeds collide at (client=const, clock=0..) and split-brain, whereas
    // distinct ids merge as concurrent inserts — converging to a duplicate,
    // which is the safe failure.
    #[test]
    fn divergent_content_yields_different_client_ids() {
        assert_ne!(
            seed_client_id("hello world"),
            seed_client_id("goodbye world")
        );
        let a = deterministic_seed_update("hello world".to_string()).unwrap();
        let b = deterministic_seed_update("goodbye world".to_string()).unwrap();
        assert_ne!(a, b);
    }

    // A fresh doc's state vector is empty (it knows nothing), so a diff taken
    // against it returns the peer's full state.
    fn empty_sv() -> Vec<u8> {
        YjsDoc::new().encode_state_vector()
    }

    // The whole point of the deterministic seed: two devices seeding the SAME
    // body independently, then syncing, converge to ONE copy of the text.
    #[test]
    fn deterministic_seed_merges_idempotently() {
        let seed = deterministic_seed_update("hello world".to_string()).unwrap();
        let a = YjsDoc::new();
        a.apply_update(seed.clone()).unwrap();
        let b = YjsDoc::new();
        b.apply_update(seed).unwrap();

        // Full two-way sync.
        let a_full = a.encode_diff_since(empty_sv()).unwrap();
        let b_full = b.encode_diff_since(empty_sv()).unwrap();
        b.apply_update(a_full).unwrap();
        a.apply_update(b_full).unwrap();

        assert_eq!(a.get_text(), "hello world");
        assert_eq!(b.get_text(), "hello world");
    }

    // Contrast, and the hazard `replace_text`'s doc warns about: two plain
    // replace_text seeds carry different client ids, so merging duplicates.
    #[test]
    fn replace_text_seed_duplicates_on_merge() {
        let a = YjsDoc::new();
        a.replace_text("hello".to_string()).unwrap();
        let b = YjsDoc::new();
        b.replace_text("hello".to_string()).unwrap();

        let a_full = a.encode_diff_since(empty_sv()).unwrap();
        b.apply_update(a_full).unwrap();
        assert_eq!(b.get_text(), "hellohello");
    }

    // A deterministic seed is a normal doc afterward: a local edit still ships
    // and merges into a peer that seeded the same body.
    #[test]
    fn edit_after_deterministic_seed_syncs() {
        let seed = deterministic_seed_update("hi".to_string()).unwrap();
        let a = YjsDoc::new();
        a.apply_update(seed.clone()).unwrap();
        let b = YjsDoc::new();
        b.apply_update(seed).unwrap();

        a.insert_text(2, " there".to_string()).unwrap();
        for u in a.drain_local_updates() {
            b.apply_update(u).unwrap();
        }
        assert_eq!(b.get_text(), "hi there");
    }

    // Empty content seeds nothing (caller skips the apply).
    #[test]
    fn empty_content_yields_empty_seed() {
        assert!(deterministic_seed_update(String::new()).unwrap().is_empty());
    }
}

#[cfg(test)]
mod note_share_wrap_verify_both_tests {
    use super::*;
    use base64::Engine;

    fn params(version: u32) -> NoteShareWrapParams {
        NoteShareWrapParams {
            sender_user_id: "11111111-1111-1111-1111-111111111111".into(),
            recipient_user_id: "22222222-2222-2222-2222-222222222222".into(),
            item_id: "33333333-3333-3333-3333-333333333333".into(),
            content_key_version: version,
            wrapped_key_b64: base64::engine::general_purpose::STANDARD.encode([0x11u8; 80]),
        }
    }

    // A verifier that passes the REAL content_key_version accepts BOTH a legacy
    // signature (signed under 0) and a current one (signed under the real
    // version). That dual acceptance is what lets the signing side emit real
    // versions without breaking verifiers already in the field.
    #[test]
    fn accepts_real_or_legacy_version() {
        let kp = generate_note_signing_keypair();

        // A legacy signer signs under version 0.
        let legacy_sig = sign_note_share_wrap(kp.secret_seed.clone(), params(0)).unwrap();
        // Verifier passes the REAL version 5 → passed-version check fails, the
        // version-0 fallback succeeds.
        assert!(
            verify_note_share_wrap(kp.verifying_key_hex.clone(), legacy_sig.clone(), params(5))
                .unwrap(),
            "real-version verifier must accept a legacy version-0 sig (fallback)"
        );

        // A current signer signs under the real version 5.
        let real_sig = sign_note_share_wrap(kp.secret_seed.clone(), params(5)).unwrap();
        // Verifier passes version 5 → passed-version check succeeds directly.
        assert!(
            verify_note_share_wrap(kp.verifying_key_hex.clone(), real_sig, params(5)).unwrap(),
            "verifier must accept a sig signed under the passed version"
        );

        // Pure legacy path: a version-0 sig verified with a version-0 verifier
        // passes on the first check, with no fallback needed.
        assert!(
            verify_note_share_wrap(kp.verifying_key_hex, legacy_sig, params(0)).unwrap(),
            "legacy-0 sig must still verify under a legacy-0 verifier"
        );
    }

    // The fallback is NOT a blanket accept: only the PASSED version and legacy 0
    // are honored. A sig over version 5, verified with passed version 7, matches
    // neither 7 nor 0 → rejected. Proves verify-both keeps the pin's teeth: a
    // server cannot downgrade to an arbitrary non-zero version.
    #[test]
    fn rejects_mismatched_nonzero_version() {
        let kp = generate_note_signing_keypair();
        let sig5 = sign_note_share_wrap(kp.secret_seed.clone(), params(5)).unwrap();
        assert!(
            !verify_note_share_wrap(kp.verifying_key_hex, sig5, params(7)).unwrap(),
            "a version-5 sig must not verify when the verifier passes version 7"
        );
    }

    // The reader's rollback check keys on the generation the signature ACTUALLY
    // verified under, exposed via verify_note_share_wrap_gen. A real gen-5 sig
    // reports 5; a legacy gen-0 sig reports 0 EVEN WHEN the caller passes an
    // inflated version. That last case is the anti-laundering
    // guarantee: a server can't relabel an old gen-0 wrap as gen-99 to slip it
    // past a highest-seen floor, because verify reports 0, not 99.
    #[test]
    fn effective_generation_reports_verified_version_not_claimed() {
        let kp = generate_note_signing_keypair();

        // Sig under real gen 5, verified with 5 → effective 5.
        let real_sig = sign_note_share_wrap(kp.secret_seed.clone(), params(5)).unwrap();
        let r =
            verify_note_share_wrap_gen(kp.verifying_key_hex.clone(), real_sig, params(5)).unwrap();
        assert!(
            r.verified && r.effective_generation == 5,
            "real gen-5 sig must report effective 5"
        );

        // Legacy gen-0 sig, caller CLAIMS gen 99 → verifies via fallback but
        // effective_generation is 0 (the version it truly signed), not 99.
        let legacy_sig = sign_note_share_wrap(kp.secret_seed.clone(), params(0)).unwrap();
        let r = verify_note_share_wrap_gen(kp.verifying_key_hex.clone(), legacy_sig, params(99))
            .unwrap();
        assert!(r.verified, "legacy-0 sig must still verify via fallback");
        assert_eq!(
            r.effective_generation, 0,
            "fallback-verified sig must report gen 0, not the claimed 99"
        );

        // A sig that does not verify at all reports {false, 0}.
        let sig5 = sign_note_share_wrap(kp.secret_seed.clone(), params(5)).unwrap();
        let r = verify_note_share_wrap_gen(kp.verifying_key_hex, sig5, params(7)).unwrap();
        assert!(
            !r.verified && r.effective_generation == 0,
            "non-verifying sig must report {{false, 0}}"
        );
    }
}

#[cfg(test)]
mod seal_open_tests {
    use super::*;
    use base64::Engine;
    use rand::RngCore;

    fn rand32() -> [u8; 32] {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b
    }

    /// `open_seal` deliberately avoids `crypto_box::SecretKey` (whose `bytes`
    /// field is not zeroized on Drop), so it MUST stay byte-identical to
    /// `crypto_box::SecretKey::unseal`: it recovers the sealed key AND agrees
    /// with the reference unseal on the exact same ciphertext.
    #[test]
    fn open_seal_roundtrips_and_matches_crypto_box_unseal() {
        for _ in 0..32 {
            let sk = rand32();
            let content_key = rand32();

            // Recipient public key from the same secret, then seal via the public API.
            let pub_hex = derive_sharing_public_key(sk.to_vec()).expect("derive pub");
            let sealed_b64 = seal_for_recipient(content_key.to_vec(), pub_hex).expect("seal");

            // Our hand-rolled open returns the exact content key.
            let opened = open_seal(sealed_b64.clone(), sk.to_vec()).expect("open");
            assert_eq!(
                opened.as_slice(),
                &content_key[..],
                "open_seal must recover the sealed content key"
            );

            // ...and is byte-for-byte identical to the reference crypto_box unseal.
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(sealed_b64.as_bytes())
                .unwrap();
            let reference = crypto_box::SecretKey::from_bytes(sk).unseal(&sealed).ok();
            assert_eq!(
                Some(opened),
                reference,
                "open_seal must equal crypto_box::SecretKey::unseal byte-for-byte"
            );
        }
    }

    #[test]
    fn open_seal_rejects_wrong_key_and_malformed_input() {
        let sk = rand32();
        let other = rand32();
        let content_key = rand32();
        let pub_hex = derive_sharing_public_key(sk.to_vec()).unwrap();
        let sealed_b64 = seal_for_recipient(content_key.to_vec(), pub_hex).unwrap();

        // Wrong recipient secret: Poly1305 auth fails -> None.
        assert!(open_seal(sealed_b64.clone(), other.to_vec()).is_none());
        // Wrong private-key length -> None.
        assert!(open_seal(sealed_b64.clone(), vec![0u8; 31]).is_none());
        // Not base64 -> None.
        assert!(open_seal("!!!not base64!!!".to_string(), sk.to_vec()).is_none());
        // Decodes but too short (<= 32 bytes) -> None.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(open_seal(short, sk.to_vec()).is_none());
        // The correct key still works (sanity).
        assert_eq!(
            open_seal(sealed_b64, sk.to_vec()).unwrap().as_slice(),
            &content_key[..]
        );
    }
}
