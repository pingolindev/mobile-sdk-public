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

use note_collab_sdk::*;

#[test]
fn two_docs_sync_via_updates() {
    // Doc A writes "Hello"; Doc B starts empty; exchange updates and
    // confirm both converge on the same text.
    let a = YjsDoc::new();
    let b = YjsDoc::new();

    a.insert_text(0, "Hello".into()).unwrap();
    let updates_from_a = a.drain_local_updates();
    assert!(!updates_from_a.is_empty());

    for u in updates_from_a {
        b.apply_update(u).unwrap();
    }
    assert_eq!(b.get_text(), "Hello");

    // B now edits concurrently
    b.insert_text(5, ", world".into()).unwrap();
    let updates_from_b = b.drain_local_updates();
    for u in updates_from_b {
        a.apply_update(u).unwrap();
    }
    assert_eq!(a.get_text(), b.get_text());
    assert_eq!(a.get_text(), "Hello, world");
}

#[test]
fn aead_roundtrip() {
    let key = vec![42u8; 32];
    let ct = encrypt_collab_frame(key.clone(), b"hello".to_vec()).unwrap();
    assert!(ct.len() > 24, "frame must include nonce + ciphertext");
    let pt = decrypt_collab_frame(key, ct).unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn aead_wrong_key_rejects() {
    let key1 = vec![1u8; 32];
    let key2 = vec![2u8; 32];
    let ct = encrypt_collab_frame(key1, b"secret".to_vec()).unwrap();
    assert!(decrypt_collab_frame(key2, ct).is_none());
}

#[test]
fn content_key_wrap_unwrap_roundtrip() {
    let vault = vec![7u8; 32];
    let content_key = generate_content_key();
    assert_eq!(content_key.len(), 32);
    let wrapped = wrap_with_vault(content_key.clone(), vault.clone()).unwrap();
    let recovered = unwrap_with_vault(wrapped.wrapped_key_b64, wrapped.nonce_b64, vault).unwrap();
    assert_eq!(recovered, content_key);
}

#[test]
fn content_key_wrong_vault_rejects() {
    let wrapped = wrap_with_vault(generate_content_key(), vec![1u8; 32]).unwrap();
    assert!(unwrap_with_vault(wrapped.wrapped_key_b64, wrapped.nonce_b64, vec![2u8; 32]).is_none());
}

#[test]
fn note_payload_roundtrip() {
    let key = generate_content_key();
    let ct = encrypt_note_with_content_key("hello world".into(), key.clone()).unwrap();
    let pt = decrypt_note_with_content_key(ct.nonce_b64, ct.ciphertext_b64, key).unwrap();
    assert_eq!(pt, "hello world");
}

#[test]
fn seal_roundtrip_with_recipient_private_key() {
    // Simulate a recipient: generate a keypair, expose pub hex, seal, unseal.
    let priv_key = generate_content_key(); // 32 random bytes — good enough for a key
    let pub_hex = derive_sharing_public_key(priv_key.clone()).unwrap();
    let content_key = generate_content_key();
    let wrapped = seal_for_recipient(content_key.clone(), pub_hex).unwrap();
    let recovered = open_seal(wrapped, priv_key).unwrap();
    assert_eq!(recovered, content_key);
}

#[test]
fn seal_wrong_recipient_rejects() {
    let priv_a = generate_content_key();
    let priv_b = generate_content_key();
    let pub_a = derive_sharing_public_key(priv_a).unwrap();
    let wrapped = seal_for_recipient(generate_content_key(), pub_a).unwrap();
    assert!(open_seal(wrapped, priv_b).is_none());
}

#[test]
fn derive_key_is_stable_per_note() {
    let secret = vec![9u8; 32];
    let a = derive_collab_key("note-1".into(), secret.clone()).unwrap();
    let b = derive_collab_key("note-1".into(), secret.clone()).unwrap();
    let c = derive_collab_key("note-2".into(), secret).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 32);
}

#[test]
fn note_share_wrap_sign_verify_roundtrip() {
    // Mint a 32-byte Ed25519 seed.
    let seed = generate_content_key(); // 32 random bytes
                                       // Derive verifying key from the same seed, hex-encode for the verify path.
    use ed25519_dalek::SigningKey;
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let sk = SigningKey::from_bytes(&seed_arr);
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());

    let params = NoteShareWrapParams {
        sender_user_id: "11111111-2222-3333-4444-555555555555".into(),
        recipient_user_id: "66666666-7777-8888-9999-aaaaaaaaaaaa".into(),
        item_id: "deadbeef-dead-beef-dead-beefdeadbeef".into(),
        content_key_version: 0,
        // 80-byte sealed_box-shaped blob (32 ephemeral + 48 ciphertext).
        wrapped_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 80],
        ),
    };
    let sig = sign_note_share_wrap(seed.clone(), params.clone()).unwrap();
    assert_eq!(
        sig.len(),
        128,
        "Ed25519 signature should be 64 bytes / 128 hex chars"
    );
    assert!(verify_note_share_wrap(vk_hex.clone(), sig.clone(), params.clone()).unwrap());

    // Tamper with one byte of the wrapped key — verification must fail.
    let mut bad = params.clone();
    let mut wrapped_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        bad.wrapped_key_b64.as_bytes(),
    )
    .unwrap();
    wrapped_bytes[0] ^= 0x01;
    bad.wrapped_key_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wrapped_bytes);
    assert!(!verify_note_share_wrap(vk_hex, sig, bad).unwrap());
}

#[test]
fn generate_signing_keypair_mints_valid_ed25519_keys() {
    // Parity check with the mobile SDK's generate_signing_keypair —
    // the seed must produce a verifying key that round-trips through
    // sign + verify_note_share_wrap.
    let kp = generate_note_signing_keypair();
    assert_eq!(kp.secret_seed.len(), 32);
    assert_eq!(
        kp.verifying_key_hex.len(),
        64,
        "32-byte pubkey as lowercase hex"
    );

    // Derive the expected pubkey from the emitted seed and confirm the
    // emitted hex matches it. A drift here would silently make every
    // verify call fail.
    use ed25519_dalek::SigningKey;
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&kp.secret_seed);
    let sk = SigningKey::from_bytes(&seed_arr);
    assert_eq!(
        kp.verifying_key_hex,
        hex::encode(sk.verifying_key().to_bytes())
    );

    // End-to-end: sign with the emitted seed, verify with the emitted
    // pubkey.
    let params = NoteShareWrapParams {
        sender_user_id: "11111111-2222-3333-4444-555555555555".into(),
        recipient_user_id: "66666666-7777-8888-9999-aaaaaaaaaaaa".into(),
        item_id: "deadbeef-dead-beef-dead-beefdeadbeef".into(),
        content_key_version: 0,
        wrapped_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 80],
        ),
    };
    let sig = sign_note_share_wrap(kp.secret_seed, params.clone()).unwrap();
    assert!(verify_note_share_wrap(kp.verifying_key_hex, sig, params).unwrap());
}

#[test]
fn generate_signing_keypair_emits_unique_seeds() {
    // Tripwire against a pinned RNG silently giving every account
    // the same identity seed.
    let a = generate_note_signing_keypair();
    let b = generate_note_signing_keypair();
    assert_ne!(a.secret_seed, b.secret_seed);
    assert_ne!(a.verifying_key_hex, b.verifying_key_hex);
}

#[test]
fn sign_accepts_libsodium_64_byte_expanded_secret_key() {
    // Accounts whose signing seed was minted via the web/account app's
    // libsodium `crypto_sign_keypair` get a 64-byte secretKey (seed ||
    // pubkey). The mobile SDK's `import_signing_private_key` strips
    // the suffix, and so does signing here. A 32-byte-only path would
    // error out for those users, and they could never share notes.
    use ed25519_dalek::SigningKey;
    let kp = generate_note_signing_keypair();
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&kp.secret_seed);
    let sk = SigningKey::from_bytes(&seed_arr);
    let pub_bytes = sk.verifying_key().to_bytes();

    // Concatenate seed (32B) || pubkey (32B) — libsodium's secretKey layout.
    let mut libsodium_shape = Vec::with_capacity(64);
    libsodium_shape.extend_from_slice(&kp.secret_seed);
    libsodium_shape.extend_from_slice(&pub_bytes);
    assert_eq!(libsodium_shape.len(), 64);

    let params = NoteShareWrapParams {
        sender_user_id: "11111111-2222-3333-4444-555555555555".into(),
        recipient_user_id: "66666666-7777-8888-9999-aaaaaaaaaaaa".into(),
        item_id: "deadbeef-dead-beef-dead-beefdeadbeef".into(),
        content_key_version: 0,
        wrapped_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 80],
        ),
    };
    let sig_from_64 = sign_note_share_wrap(libsodium_shape, params.clone()).unwrap();
    let sig_from_32 = sign_note_share_wrap(kp.secret_seed, params.clone()).unwrap();
    // Both must produce the exact same Ed25519 signature — they're
    // deterministically signed from the same effective seed.
    assert_eq!(sig_from_64, sig_from_32);
    assert!(verify_note_share_wrap(kp.verifying_key_hex, sig_from_64, params).unwrap());
}

#[test]
fn sign_rejects_invalid_seed_lengths() {
    let params = NoteShareWrapParams {
        sender_user_id: "11111111-2222-3333-4444-555555555555".into(),
        recipient_user_id: "66666666-7777-8888-9999-aaaaaaaaaaaa".into(),
        item_id: "deadbeef-dead-beef-dead-beefdeadbeef".into(),
        content_key_version: 0,
        wrapped_key_b64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 80],
        ),
    };
    assert!(sign_note_share_wrap(vec![0u8; 16], params.clone()).is_err());
    assert!(sign_note_share_wrap(vec![0u8; 48], params.clone()).is_err());
    assert!(sign_note_share_wrap(vec![0u8; 128], params).is_err());
}

#[test]
fn safety_number_is_symmetric_and_60_digits() {
    let self_uuid = "11111111-2222-3333-4444-555555555555";
    let peer_uuid = "66666666-7777-8888-9999-aaaaaaaaaaaa";
    // Use generate_content_key for 32-byte material (good enough as test pubkeys).
    let self_sharing = hex::encode(generate_content_key());
    let self_signing = hex::encode(generate_content_key());
    let peer_sharing = hex::encode(generate_content_key());
    let peer_signing = hex::encode(generate_content_key());

    let from_self = compute_note_safety_number(
        self_uuid.into(),
        self_sharing.clone(),
        self_signing.clone(),
        peer_uuid.into(),
        peer_sharing.clone(),
        peer_signing.clone(),
    )
    .unwrap();
    let from_peer = compute_note_safety_number(
        peer_uuid.into(),
        peer_sharing,
        peer_signing,
        self_uuid.into(),
        self_sharing,
        self_signing,
    )
    .unwrap();
    assert_eq!(from_self, from_peer, "SAS must be symmetric");
    // 60 digits + 11 spaces = 71 chars.
    assert_eq!(from_self.len(), 71);
}
