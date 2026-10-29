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

//! Signed membership statements (format 2): the locked cross-platform
//! vectors, and everything a forger could try — every flipped bit, every field
//! swapped for another valid value, the wrong domain, kind and length
//! confusion. Only the public API is used, as the apps and the mirrors see it.

use base64::Engine;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use pingolin_mobile::{
    CryptoManager, MembershipStatement, MembershipStatementKind, MobileError, InvitationRenewalFacts,
    INVITATION_LIFETIME_SECS, MEMBERSHIP_STATEMENT_DOMAIN,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const SIGNER_PUB: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const CIRCLE: &str = "11111111-2222-4333-8444-555555555555";
const SIGNER: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";
const SUBJECT: &str = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
const ISSUED: i64 = 1_790_208_000;

const V1_STATEMENT: &str = "0201111111112222433384445555555555550f1e2d3c4b5a4987a6b5c4d3e2f1a0b966666666777748889999aaaaaaaaaaaa0068b46a0000000080a2bd6a0000000007000000bbbbbbbbcccc4ddd8eeeffffffffffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
const V1_SIGNATURE: &str = "2e344b8660536b8a820b187afb5a605da203e3515931c7f98d8891e6ba4d4f3fec2b9c2cb826b86ebb2d297d4570d9cd3daa791855bfa16bc96e6461164de804";
const V2_STATEMENT: &str = "020211111111222243338444555555555555a1b2c3d4e5f64a7b8c9d0e1f2a3b4c5d66666666777748889999aaaaaaaaaaaa0068b46a0000000080a2bd6a000000000100000013696e7669746565406578616d706c652e636f6d";
const V2_SIGNATURE: &str = "a1b897f4fcef800fc690f8f4577a25158aeec8ac9e8d66daeb22341b5c814edf93c422e0bf15281969a7834f9982862cbdca7b50e3eb66c4fd6d57e92b028a02";
const V3_STATEMENT: &str = "0203111111112222433384445555555555555a5a5a5a6b6b4c7c8d8d9e9e9e9e9e9e66666666777748889999aaaaaaaaaaaa0068b46a00000000000000000000000040420f00bbbbbbbbcccc4ddd8eeeffffffffffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
const V3_SIGNATURE: &str = "d346b7033fdc54b406daf9c1e6992000eb265a9b8726adf64a4c6d8610b6489421935f0df36c06ce80385bb651e37bd8eec88d07fbacb4670083a418e1564f00";
/// V4: kind 3 whose signer is its subject, an owner's or admin's admission of
/// its OWN keys after a password reset. The subject keys are the vector
/// signer's own: the X25519 key of seed 0x20..0x3f and SIGNER_PUB. Reproduced
/// independently with the @noble libraries.
const SIGNER_SHARING_PUB: &str = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
const V4_STATEMENT: &str = "0203111111112222433384445555555555557c7c7c7c8d8d4e9eafafb0b0b0b0b0b066666666777748889999aaaaaaaaaaaa0068b46a0000000000000000000000000200000066666666777748889999aaaaaaaaaaaa358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const V4_SIGNATURE: &str = "bfc123405c7f3a3e3323580880ae9820782403e537235926cc415bc10939e0fa07b6e9c567839857dec6b350faef9a297db2b178250a2d40b932e4b4b7e7a903";

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

/// A manager holding the vector signer's key (seed 00..1f).
fn vector_signer() -> std::sync::Arc<CryptoManager> {
    let m = CryptoManager::new();
    m.import_signing_private_key(base64::engine::general_purpose::STANDARD.encode(seed())).unwrap();
    assert_eq!(m.signing_public_key_hex().unwrap(), SIGNER_PUB);
    m
}

fn hexseq(start: u8) -> String {
    (0..32u8).map(|i| format!("{:02x}", start.wrapping_add(i))).collect()
}

fn v1() -> MembershipStatement {
    MembershipStatement {
        kind: MembershipStatementKind::InvitationToAccount,
        circle_id: CIRCLE.into(),
        statement_id: "0f1e2d3c-4b5a-4987-a6b5-c4d3e2f1a0b9".into(),
        signer_user_id: SIGNER.into(),
        issued_at: ISSUED,
        expires_at: ISSUED + INVITATION_LIFETIME_SECS,
        at_version: 7,
        subject_user_id: Some(SUBJECT.into()),
        subject_sharing_public_key_hex: Some(hexseq(0x40)),
        subject_signing_public_key_hex: Some(hexseq(0x60)),
        subject_email: None,
    }
}

fn v2() -> MembershipStatement {
    MembershipStatement {
        kind: MembershipStatementKind::InvitationToEmail,
        statement_id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".into(),
        at_version: 1,
        subject_user_id: None,
        subject_sharing_public_key_hex: None,
        subject_signing_public_key_hex: None,
        subject_email: Some("  Invitee@Example.COM \n".into()),
        ..v1()
    }
}

fn v3() -> MembershipStatement {
    MembershipStatement {
        kind: MembershipStatementKind::Admission,
        statement_id: "5a5a5a5a-6b6b-4c7c-8d8d-9e9e9e9e9e9e".into(),
        expires_at: 0,
        at_version: 1_000_000,
        ..v1()
    }
}

fn v4() -> MembershipStatement {
    MembershipStatement {
        kind: MembershipStatementKind::Admission,
        statement_id: "7c7c7c7c-8d8d-4e9e-afaf-b0b0b0b0b0b0".into(),
        expires_at: 0,
        at_version: 2,
        subject_user_id: Some(SIGNER.into()),
        subject_sharing_public_key_hex: Some(SIGNER_SHARING_PUB.into()),
        subject_signing_public_key_hex: Some(SIGNER_PUB.into()),
        ..v1()
    }
}

/// Give `m` a key for `circle` at `version` (a first-contact wrap, as a server
/// would deliver one), so the kind-specific signers have an active version.
fn holding_circle_key(m: &CryptoManager, circle: &str, version: i32) {
    m.generate_keypair();
    let recipient = base64::engine::general_purpose::STANDARD.decode(m.export_public_key().unwrap()).unwrap();
    let mut ra = [0u8; 32];
    ra.copy_from_slice(&recipient);
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let wrapping = blake3::derive_key("pingolin.circle_key_wrap", eph.diffie_hellman(&PublicKey::from(ra)).as_bytes());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let ct = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap().encrypt(&XNonce::from(nonce), key.as_slice()).unwrap();
    let wrap = format!("{}{}", hex::encode(nonce), hex::encode(ct));
    m.store_circle_key(circle.into(), wrap, hex::encode(PublicKey::from(&eph).as_bytes()), version, SIGNER.into(), SUBJECT.into(), None, None)
        .unwrap();
}

fn verifies(m: &CryptoManager, statement_hex: &str, signature_hex: &str) -> bool {
    m.verify_membership_statement(statement_hex.into(), signature_hex.into(), SIGNER_PUB.into())
        .unwrap_or(false)
}

#[test]
fn the_three_vectors_are_locked() {
    let m = vector_signer();
    for (statement, want_bytes, want_sig) in [
        (v1(), V1_STATEMENT, V1_SIGNATURE),
        (v2(), V2_STATEMENT, V2_SIGNATURE),
        (v3(), V3_STATEMENT, V3_SIGNATURE),
    ] {
        let signed = m.sign_membership_statement(statement.clone()).unwrap();
        assert_eq!(signed.statement_hex, want_bytes, "{:?}: canonical bytes", statement.kind);
        assert_eq!(signed.signature_hex, want_sig, "{:?}: signature", statement.kind);
        assert!(verifies(&m, want_bytes, want_sig));
        let parsed = m.parse_membership_statement(want_bytes.into()).unwrap();
        assert_eq!(parsed, signed.statement);
    }
    // The email is normalized into the bytes and read back normalized.
    let parsed = m.parse_membership_statement(V2_STATEMENT.into()).unwrap();
    assert_eq!(parsed.subject_email.as_deref(), Some("invitee@example.com"));
    // Verification needs no key of the verifier's own.
    let stranger = CryptoManager::new();
    assert!(verifies(&stranger, V1_STATEMENT, V1_SIGNATURE));
}

#[test]
fn the_self_admission_vector_is_locked() {
    let sharing_seed: [u8; 32] = std::array::from_fn(|i| 0x20 + i as u8);
    assert_eq!(hex::encode(PublicKey::from(&StaticSecret::from(sharing_seed)).as_bytes()), SIGNER_SHARING_PUB);
    let m = vector_signer();
    let signed = m.sign_membership_statement(v4()).unwrap();
    assert_eq!((signed.statement_hex.as_str(), signed.signature_hex.as_str()), (V4_STATEMENT, V4_SIGNATURE));
    assert!(verifies(&m, V4_STATEMENT, V4_SIGNATURE));
    let parsed = m.parse_membership_statement(V4_STATEMENT.into()).unwrap();
    assert_eq!(parsed, signed.statement);
    assert_eq!(parsed.subject_user_id.as_deref(), Some(SIGNER));
    // The kind-3 signer takes signer = subject as it is: the current key, at
    // the active version, never expiring.
    holding_circle_key(&m, CIRCLE, 2);
    let own = m
        .sign_membership_admission(CIRCLE.into(), SIGNER.into(), SIGNER.into(), SIGNER_SHARING_PUB.into(), SIGNER_PUB.into())
        .unwrap();
    let s = &own.statement;
    assert_eq!(
        (s.kind, s.at_version, s.expires_at, s.signer_user_id.as_str(), s.subject_user_id.as_deref()),
        (MembershipStatementKind::Admission, 2, 0, SIGNER, Some(SIGNER))
    );
    assert!(verifies(&m, &own.statement_hex, &own.signature_hex));
}

#[test]
fn every_flipped_bit_is_refused() {
    let m = CryptoManager::new();
    for (statement, sig) in [(V1_STATEMENT, V1_SIGNATURE), (V2_STATEMENT, V2_SIGNATURE), (V3_STATEMENT, V3_SIGNATURE)] {
        let bytes = hex::decode(statement).unwrap();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut tampered = bytes.clone();
                tampered[i] ^= 1 << bit;
                let r = m.verify_membership_statement(hex::encode(&tampered), sig.into(), SIGNER_PUB.into());
                assert!(!matches!(r, Ok(true)), "byte {i} bit {bit} of a signed statement still verifies");
            }
        }
        let sig_bytes = hex::decode(sig).unwrap();
        for i in 0..sig_bytes.len() {
            let mut tampered = sig_bytes.clone();
            tampered[i] ^= 0x01;
            assert!(!verifies(&m, statement, &hex::encode(&tampered)), "signature byte {i} flipped still verifies");
        }
    }
}

/// Swap each field for ANOTHER VALID value (so the statement still parses)
/// and present it with the original signature: every one must fail.
#[test]
fn every_field_swapped_for_another_valid_value_is_refused() {
    let m = vector_signer();
    // The forged bytes are produced by another signer so they are canonical;
    // the ORIGINAL signature is then checked against them.
    let forger = CryptoManager::new();
    forger.generate_signing_keypair();
    let other_uuid = "12345678-1234-4234-8234-123456789abc".to_string();
    let base = v1();
    let variants: Vec<(&str, MembershipStatement)> = vec![
        ("circle_id", MembershipStatement { circle_id: other_uuid.clone(), ..base.clone() }),
        ("statement_id", MembershipStatement { statement_id: other_uuid.clone(), ..base.clone() }),
        ("signer_user_id", MembershipStatement { signer_user_id: other_uuid.clone(), ..base.clone() }),
        ("issued_at", MembershipStatement { issued_at: ISSUED + 1, expires_at: ISSUED + 1 + INVITATION_LIFETIME_SECS, ..base.clone() }),
        ("at_version", MembershipStatement { at_version: 8, ..base.clone() }),
        ("subject_user_id", MembershipStatement { subject_user_id: Some(other_uuid.clone()), ..base.clone() }),
        ("subject_sharing_public_key", MembershipStatement { subject_sharing_public_key_hex: Some(hexseq(0x41)), ..base.clone() }),
        ("subject_signing_public_key", MembershipStatement { subject_signing_public_key_hex: Some(hexseq(0x61)), ..base.clone() }),
        ("kind 1 -> 3", MembershipStatement { kind: MembershipStatementKind::Admission, expires_at: 0, ..base.clone() }),
    ];
    for (field, forged) in variants {
        let forged_hex = forger.sign_membership_statement(forged).unwrap().statement_hex;
        assert_ne!(forged_hex, V1_STATEMENT);
        assert!(!verifies(&m, &forged_hex, V1_SIGNATURE), "V1's signature verifies with {field} changed");
    }
    let email_variant = MembershipStatement { subject_email: Some("invitee2@example.com".into()), ..v2() };
    let forged_hex = forger.sign_membership_statement(email_variant).unwrap().statement_hex;
    assert!(!verifies(&m, &forged_hex, V2_SIGNATURE), "V2's signature verifies with another email");
}

#[test]
fn a_signature_under_another_domain_is_refused() {
    let m = CryptoManager::new();
    let key = SigningKey::from_bytes(&seed());
    for (statement, genuine) in [(V1_STATEMENT, V1_SIGNATURE), (V2_STATEMENT, V2_SIGNATURE), (V3_STATEMENT, V3_SIGNATURE)] {
        let bytes = hex::decode(statement).unwrap();
        for domain in [
            "pingolin.sig.v1.circle_member_wrap",
            "pingolin.sig.v1.rotation_member_wrap",
            "pingolin.sig.v1.circle_invite_wrap",
        ] {
            let context_key = blake3::derive_key("pingolin.sig.v1.context_key", domain.as_bytes());
            let digest = blake3::keyed_hash(&context_key, &bytes);
            let sig = hex::encode(key.sign(digest.as_bytes()).to_bytes());
            assert!(!verifies(&m, statement, &sig), "a {domain} signature verifies as a statement");
        }
        // Positive control: the same construction under the statement domain is the genuine signature.
        let context_key = blake3::derive_key("pingolin.sig.v1.context_key", MEMBERSHIP_STATEMENT_DOMAIN.as_bytes());
        let digest = blake3::keyed_hash(&context_key, &bytes);
        assert_eq!(hex::encode(key.sign(digest.as_bytes()).to_bytes()), genuine);
        // Signing the raw bytes (no domain digest) is not a statement signature either.
        assert!(!verifies(&m, statement, &hex::encode(key.sign(&bytes).to_bytes())));
    }
}

#[test]
fn kind_and_length_confusion_is_refused() {
    let m = CryptoManager::new();
    let malformed = |bytes: &[u8]| {
        m.parse_membership_statement(hex::encode(bytes)).is_err()
            && m.verify_membership_statement(hex::encode(bytes), V1_SIGNATURE.into(), SIGNER_PUB.into()).is_err()
    };
    let v1b = hex::decode(V1_STATEMENT).unwrap();
    let v2b = hex::decode(V2_STATEMENT).unwrap();
    let v3b = hex::decode(V3_STATEMENT).unwrap();
    let with = |b: &[u8], at: usize, value: u8| { let mut c = b.to_vec(); c[at] = value; c };

    assert!(malformed(&with(&v1b, 1, 2)), "kind 1 bytes read as kind 2");
    assert!(malformed(&with(&v2b, 1, 1)), "kind 2 bytes read as kind 1");
    assert!(malformed(&with(&v2b, 1, 3)), "kind 2 bytes read as kind 3");
    assert!(malformed(&with(&v1b, 1, 3)), "kind 1 relabelled 3 keeps an invitation's expiry");
    assert!(malformed(&with(&v3b, 1, 1)), "kind 3 relabelled 1 has no invitation expiry");
    for kind in [0u8, 4, 0xff] {
        assert!(malformed(&with(&v1b, 1, kind)), "unknown kind {kind}");
    }
    for version in [0u8, 1, 3, 0xff] {
        assert!(malformed(&with(&v1b, 0, version)), "unknown format {version}");
    }
    // at_version outside 1..=1_000_000.
    for bad in [0u32, 1_000_001, u32::MAX] {
        let mut b = v1b.clone();
        b[66..70].copy_from_slice(&bad.to_le_bytes());
        assert!(malformed(&b), "at_version {bad}");
    }
    // Kind 3 relabelled 1 WITH a matching expiry parses — and then the signature fails.
    let mut relabelled = with(&v3b, 1, 1);
    relabelled[58..66].copy_from_slice(&((ISSUED + INVITATION_LIFETIME_SECS) as u64).to_le_bytes());
    assert!(m.parse_membership_statement(hex::encode(&relabelled)).is_ok());
    assert!(!verifies(&m, &hex::encode(&relabelled), V3_SIGNATURE));

    for b in [&v1b, &v2b, &v3b] {
        for len in 0..b.len() {
            assert!(malformed(&b[..len]), "truncated to {len} bytes");
        }
        let mut longer = b.to_vec();
        longer.push(0);
        assert!(malformed(&longer), "trailing byte");
    }
    // The email length prefix must match the bytes that follow.
    assert_eq!(v2b[70] as usize, v2b.len() - 71);
    assert!(malformed(&with(&v2b, 70, v2b[70] + 1)));
    assert!(malformed(&with(&v2b, 70, v2b[70] - 1)));
    assert!(malformed(&with(&v2b, 70, 0)));
    // A non-canonical email is malformed even with a matching length.
    let upper = with(&v2b, 71, b'I');
    assert!(malformed(&upper), "upper-case email");
    // Timestamps above i64::MAX, and a zero issued_at.
    let mut huge = v3b.clone();
    huge[50..58].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(malformed(&huge));
    let mut zero = v3b.clone();
    zero[50..58].copy_from_slice(&0u64.to_le_bytes());
    assert!(malformed(&zero));
}

/// Format-1 bytes are refused outright.
#[test]
fn a_format_1_statement_is_refused() {
    const FORMAT_1_V1: &str = "0101111111112222433384445555555555550f1e2d3c4b5a4987a6b5c4d3e2f1a0b966666666777748889999aaaaaaaaaaaa0068b46a0000000080a2bd6a00000000bbbbbbbbcccc4ddd8eeeffffffffffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    const FORMAT_1_V1_SIGNATURE: &str = "71558b4587a74fbe4af018e29d7b918ee7ca73f3b6472ab0db297a3317daec523ec3d8c8519defc41c950cac2f6d9bcbad59997c4afe23a00809ea5f0c16dc02";
    let m = CryptoManager::new();
    assert!(m.parse_membership_statement(FORMAT_1_V1.into()).is_err());
    assert!(m.verify_membership_statement(FORMAT_1_V1.into(), FORMAT_1_V1_SIGNATURE.into(), SIGNER_PUB.into()).is_err());
    // Relabelled as format 2 it is the wrong length for kind 1.
    let mut relabelled = hex::decode(FORMAT_1_V1).unwrap();
    relabelled[0] = 2;
    assert!(m.parse_membership_statement(hex::encode(&relabelled)).is_err());
}

#[test]
fn the_kind_specific_signers_fill_ids_and_times() {
    let m = CryptoManager::new();
    m.generate_signing_keypair();
    let me = m.signing_public_key_hex().unwrap();
    // No key for the circle: no active version to state, nothing is signed.
    assert!(matches!(
        m.sign_invitation_to_account(CIRCLE.into(), SIGNER.into(), SUBJECT.into(), hexseq(0x40), hexseq(0x60)),
        Err(MobileError::KeyNotFound(_))
    ));
    assert!(matches!(m.sign_invitation_to_email(CIRCLE.into(), SIGNER.into(), "a@b.c".into()), Err(MobileError::KeyNotFound(_))));
    assert!(matches!(
        m.sign_membership_admission(CIRCLE.into(), SIGNER.into(), SUBJECT.into(), hexseq(0x40), hexseq(0x60)),
        Err(MobileError::KeyNotFound(_))
    ));
    holding_circle_key(&m, CIRCLE, 3);
    let before = chrono::Utc::now().timestamp();
    let a = m.sign_invitation_to_account(CIRCLE.into(), SIGNER.into(), SUBJECT.into(), hexseq(0x40), hexseq(0x60)).unwrap();
    let b = m.sign_invitation_to_account(CIRCLE.into(), SIGNER.into(), SUBJECT.into(), hexseq(0x40), hexseq(0x60)).unwrap();
    let e = m.sign_invitation_to_email(CIRCLE.into(), SIGNER.into(), " Someone@Example.ORG ".into()).unwrap();
    let v = m.sign_membership_admission(CIRCLE.into(), SIGNER.into(), SUBJECT.into(), hexseq(0x40), hexseq(0x60)).unwrap();
    let after = chrono::Utc::now().timestamp();

    assert_ne!(a.statement.statement_id, b.statement.statement_id, "a fresh statement id per invitation");
    for s in [&a, &b, &e] {
        assert!((before..=after).contains(&s.statement.issued_at));
        assert_eq!(s.statement.expires_at, s.statement.issued_at + INVITATION_LIFETIME_SECS);
    }
    assert_eq!(a.statement.kind, MembershipStatementKind::InvitationToAccount);
    assert_eq!(e.statement.kind, MembershipStatementKind::InvitationToEmail);
    assert_eq!(e.statement.subject_email.as_deref(), Some("someone@example.org"));
    assert_eq!(v.statement.kind, MembershipStatementKind::Admission);
    assert_eq!(v.statement.expires_at, 0);
    for s in [&a, &b, &e, &v] {
        assert_eq!(s.statement.at_version, 3, "at_version = the device's active version");
        assert!(m.verify_membership_statement(s.statement_hex.clone(), s.signature_hex.clone(), me.clone()).unwrap());
        assert_eq!(m.parse_membership_statement(s.statement_hex.clone()).unwrap(), s.statement);
        assert!(!verifies(&m, &s.statement_hex, &s.signature_hex), "another signer's key does not verify it");
    }
}

#[test]
fn bad_input_is_refused() {
    let m = vector_signer();
    let invalid = |s: MembershipStatement| matches!(m.sign_membership_statement(s), Err(MobileError::InvalidInput(_)));
    assert!(invalid(MembershipStatement { circle_id: "not-a-uuid".into(), ..v1() }));
    assert!(invalid(MembershipStatement { statement_id: "".into(), ..v1() }));
    assert!(invalid(MembershipStatement { subject_sharing_public_key_hex: Some("40".repeat(31)), ..v1() }));
    assert!(invalid(MembershipStatement { subject_signing_public_key_hex: Some("zz".repeat(32)), ..v1() }));
    assert!(invalid(MembershipStatement { subject_signing_public_key_hex: None, ..v1() }));
    assert!(invalid(MembershipStatement { subject_email: Some("x@y.z".into()), ..v1() }), "kind 1 with an email");
    assert!(invalid(MembershipStatement { subject_user_id: Some(SUBJECT.into()), ..v2() }), "kind 2 with a subject");
    assert!(invalid(MembershipStatement { subject_email: None, ..v2() }));
    assert!(invalid(MembershipStatement { subject_email: Some("Ünïcode@example.com".into()), ..v2() }));
    assert!(invalid(MembershipStatement { subject_email: Some("   ".into()), ..v2() }));
    assert!(invalid(MembershipStatement { subject_email: Some("no-at-sign".into()), ..v2() }));
    assert!(invalid(MembershipStatement { subject_email: Some(format!("{}@example.com", "a".repeat(250))), ..v2() }));
    assert!(invalid(MembershipStatement { expires_at: ISSUED + INVITATION_LIFETIME_SECS + 1, ..v1() }));
    assert!(invalid(MembershipStatement { expires_at: ISSUED + INVITATION_LIFETIME_SECS, ..v3() }), "an admission never expires");
    assert!(invalid(MembershipStatement { issued_at: 0, expires_at: INVITATION_LIFETIME_SECS, ..v1() }));
    assert!(invalid(MembershipStatement { issued_at: -5, expires_at: -5 + INVITATION_LIFETIME_SECS, ..v1() }));
    for at_version in [0, -1, 1_000_001, i32::MAX, i32::MIN] {
        assert!(invalid(MembershipStatement { at_version, ..v1() }), "at_version {at_version}");
    }

    // No signing key loaded: nothing can be signed.
    let keyless = CryptoManager::new();
    assert!(matches!(keyless.sign_membership_statement(v1()), Err(MobileError::KeyNotFound(_))));

    // Verification inputs.
    assert!(m.verify_membership_statement("zz".into(), V1_SIGNATURE.into(), SIGNER_PUB.into()).is_err());
    assert!(m.verify_membership_statement(V1_STATEMENT.into(), "00".repeat(63), SIGNER_PUB.into()).is_err());
    assert!(m.verify_membership_statement(V1_STATEMENT.into(), V1_SIGNATURE.into(), "00".repeat(31)).is_err());
    let other = CryptoManager::new();
    other.generate_signing_keypair();
    assert!(
        matches!(
            m.verify_membership_statement(V1_STATEMENT.into(), V1_SIGNATURE.into(), other.signing_public_key_hex().unwrap()),
            Ok(false)
        ),
        "a well-formed statement under another key is false, not an error"
    );
}

/// `pinned_signing_key`: this circle's pin, else the person's identity pin —
/// the lookup `pinned_sharing_key` does, and what a statement's bound subject
/// keys are compared with ("this device's circle or identity pin for the
/// subject"). It names a key, never trust: a departed SIGNER is not
/// confirmed (its pins are retired first) whatever this returns. (A departed
/// member cannot sign circle keys either: e2ee_trust_rules
/// `removed_member_cannot_rekey_a_remaining_member`.)
#[test]
fn pinned_signing_key_is_the_circle_pin_else_the_identity_pin() {
    const OTHER_CIRCLE: &str = "22222222-3333-4444-8555-666666666666";
    const THIRD_CIRCLE: &str = "33333333-4444-4555-8666-777777777777";
    const STAYING: &str = "77777777-8888-4999-aaaa-bbbbbbbbbbbb";
    // V1 is signed by SIGNER, whose key is SIGNER_PUB.
    let verifies_on = |device: &CryptoManager, circle: &str| -> Option<bool> {
        let key = device.pinned_signing_key(circle.into(), SIGNER.into())?;
        Some(device.verify_membership_statement(V1_STATEMENT.into(), V1_SIGNATURE.into(), key).unwrap())
    };

    let device = CryptoManager::new();
    assert_eq!(device.pinned_signing_key(CIRCLE.into(), SIGNER.into()), None, "never seen: nothing to compare with");
    assert_eq!(verifies_on(&device, CIRCLE), None);

    // Pinned in this circle; stored and returned lower-case.
    device.pin_member_keys(CIRCLE.into(), SIGNER.into(), hexseq(0x20), SIGNER_PUB.to_uppercase()).unwrap();
    assert_eq!(device.pinned_signing_key(CIRCLE.into(), SIGNER.into()).as_deref(), Some(SIGNER_PUB));
    assert_eq!(verifies_on(&device, CIRCLE), Some(true));

    // They leave: the circle pin is retired and the identity pin answers, in
    // any circle and whatever the case of the user id, so keys a returning
    // member presents are compared with what this device knew.
    assert_eq!(device.retain_member_pins(CIRCLE.into(), vec![STAYING.into()]).unwrap(), 1);
    assert_eq!(device.pinned_signing_key(CIRCLE.into(), SIGNER.to_uppercase()).as_deref(), Some(SIGNER_PUB));
    assert_eq!(device.pinned_signing_key(THIRD_CIRCLE.into(), SIGNER.into()).as_deref(), Some(SIGNER_PUB));
    assert_eq!(device.pinned_sharing_key(THIRD_CIRCLE.into(), SIGNER.into()), Some(hexseq(0x20)));

    // A circle's own pin wins over the identity pin, as for the sharing key.
    // Their keys change (password reset) and the change is approved in another
    // circle: that circle and the identity move on, this one does not.
    let device = CryptoManager::new();
    let reset = CryptoManager::new();
    reset.generate_signing_keypair();
    let new_signing = reset.signing_public_key_hex().unwrap();
    device.pin_member_keys(CIRCLE.into(), SIGNER.into(), hexseq(0x20), SIGNER_PUB.into()).unwrap();
    device
        .approve_member_key_change(OTHER_CIRCLE.into(), SIGNER.into(), hexseq(0x80), new_signing.clone())
        .unwrap();
    assert_eq!(device.pinned_signing_key(CIRCLE.into(), SIGNER.into()).as_deref(), Some(SIGNER_PUB));
    assert_eq!(verifies_on(&device, CIRCLE), Some(true));
    assert_eq!(device.pinned_signing_key(OTHER_CIRCLE.into(), SIGNER.into()), Some(new_signing.clone()));
    assert_eq!(device.pinned_signing_key(THIRD_CIRCLE.into(), SIGNER.into()), Some(new_signing.clone()));
    assert_eq!(device.pinned_sharing_key(THIRD_CIRCLE.into(), SIGNER.into()), Some(hexseq(0x80)));

    // Once they leave this circle too, the fallback is their CURRENT key: a key
    // this device has replaced is never used again, so a statement signed
    // before the change does not verify here.
    assert_eq!(device.retain_member_pins(CIRCLE.into(), vec![STAYING.into()]).unwrap(), 1);
    assert_eq!(device.pinned_signing_key(CIRCLE.into(), SIGNER.into()), Some(new_signing));
    assert_eq!(verifies_on(&device, CIRCLE), Some(false));
}

// ---------------------------------------------------------------------------
// renew_invitation
// ---------------------------------------------------------------------------

const ADMIN_A: &str = "a1a1a1a1-1111-4111-8111-111111111111";
const ADMIN_B: &str = "b2b2b2b2-2222-4222-8222-222222222222";
const OTHER_CIRCLE_ID: &str = "c3c3c3c3-3333-4333-8333-333333333333";

fn facts_ok() -> InvitationRenewalFacts {
    InvitationRenewalFacts {
        original_signer_is_owner_or_admin_now: true,
        renewer_is_owner_or_admin: true,
        subject_departed_or_tombstoned: false,
        invitation_withdrawn_or_dead: false,
    }
}

/// An invitation `signer` signed at `at_version`, issued at `issued_at`.
fn original_invitation(signer: &CryptoManager, signer_uid: &str, kind: MembershipStatementKind, issued_at: i64, at_version: i32) -> (String, String, MembershipStatement) {
    let email = kind == MembershipStatementKind::InvitationToEmail;
    let signed = signer
        .sign_membership_statement(MembershipStatement {
            kind,
            circle_id: CIRCLE.into(),
            statement_id: "0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e".into(),
            signer_user_id: signer_uid.into(),
            issued_at,
            expires_at: if kind == MembershipStatementKind::Admission { 0 } else { issued_at + INVITATION_LIFETIME_SECS },
            at_version,
            subject_user_id: (!email).then(|| SUBJECT.into()),
            subject_sharing_public_key_hex: (!email).then(|| hexseq(0x40)),
            subject_signing_public_key_hex: (!email).then(|| hexseq(0x60)),
            subject_email: email.then(|| "invitee@example.com".into()),
        })
        .unwrap();
    (signed.statement_hex, signed.signature_hex, signed.statement)
}

/// Admin A (the original signer) and admin B (renews; holds the circle at
/// `b_version` and has A pinned).
fn two_admins(b_version: i32) -> (std::sync::Arc<CryptoManager>, std::sync::Arc<CryptoManager>) {
    let a = CryptoManager::new();
    a.generate_keypair();
    a.generate_signing_keypair();
    let b = CryptoManager::new();
    b.generate_signing_keypair();
    holding_circle_key(&b, CIRCLE, b_version);
    let a_sharing = hex::encode(base64::engine::general_purpose::STANDARD.decode(a.export_public_key().unwrap()).unwrap());
    b.pin_member_keys(CIRCLE.into(), ADMIN_A.into(), a_sharing, a.signing_public_key_hex().unwrap()).unwrap();
    (a, b)
}

/// The renewal after "It's them": the keys the question showed, at B's
/// version (the same or newer), signed by B; id, times and user copied.
#[test]
fn renew_binds_the_new_keys_and_keeps_the_rest() {
    let now = chrono::Utc::now().timestamp();
    for b_version in [3, 4] {
        let (a, b) = two_admins(b_version);
        let (st, sig, original) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToAccount, now - 3600, 3);
        let renewed = b
            .renew_invitation(CIRCLE.into(), ADMIN_B.into(), st, sig, hexseq(0x41).to_uppercase(), hexseq(0x61), facts_ok())
            .unwrap();
        assert_eq!(
            renewed.statement,
            MembershipStatement {
                at_version: b_version,
                signer_user_id: ADMIN_B.into(),
                subject_sharing_public_key_hex: Some(hexseq(0x41)),
                subject_signing_public_key_hex: Some(hexseq(0x61)),
                ..original
            },
            "at v{b_version}: new keys, same id, times and user"
        );
        assert!(b
            .verify_membership_statement(renewed.statement_hex.clone(), renewed.signature_hex.clone(), b.signing_public_key_hex().unwrap())
            .unwrap());
    }
    // B's own earlier invitation verifies under B's own key.
    let (_, b) = two_admins(4);
    let (st, sig, _) = original_invitation(&b, ADMIN_B, MembershipStatementKind::InvitationToAccount, now - 60, 2);
    assert_eq!(b.renew_invitation(CIRCLE.into(), ADMIN_B.into(), st, sig, hexseq(0x41), hexseq(0x61), facts_ok()).unwrap().statement.at_version, 4);
}

/// Everything else is refused: a version-only re-sign, an address invitation
/// (never renewed), an admission, expired, withdrawn, a departed subject, a
/// signer who is no longer an admin, a renewer who is not one, a forged or
/// unpinned signature, another circle, and a device behind the invitation.
#[test]
fn renew_refuses_what_it_must() {
    let (a, b) = two_admins(4);
    let now = chrono::Utc::now().timestamp();
    let renew = |st: &str, sig: &str, circle: &str, sharing: String, signing: String, facts: InvitationRenewalFacts| {
        b.renew_invitation(circle.into(), ADMIN_B.into(), st.into(), sig.into(), sharing, signing, facts)
    };
    let refused_for = |r: Result<pingolin_mobile::SignedMembershipStatement, MobileError>, why: &str| {
        matches!(r, Err(MobileError::InvalidInput(m)) if m.contains(why))
    };
    let (st, sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToAccount, now - 60, 3);
    let new = || (hexseq(0x41), hexseq(0x61));

    assert!(refused_for(renew(&st, &sig, CIRCLE, hexseq(0x40), hexseq(0x60), facts_ok()), "did not change"), "version-only");
    let (sharing, signing) = new();
    assert!(refused_for(renew(&st, &sig, CIRCLE, sharing, signing, InvitationRenewalFacts { invitation_withdrawn_or_dead: true, ..facts_ok() }), "withdrawn"));
    let (sharing, signing) = new();
    assert!(refused_for(renew(&st, &sig, CIRCLE, sharing, signing, InvitationRenewalFacts { subject_departed_or_tombstoned: true, ..facts_ok() }), "left"));
    let (sharing, signing) = new();
    assert!(refused_for(renew(&st, &sig, CIRCLE, sharing, signing, InvitationRenewalFacts { original_signer_is_owner_or_admin_now: false, ..facts_ok() }), "no longer an owner or admin"));
    let (sharing, signing) = new();
    assert!(refused_for(renew(&st, &sig, CIRCLE, sharing, signing, InvitationRenewalFacts { renewer_is_owner_or_admin: false, ..facts_ok() }), "renewer is not an owner or admin"));
    let (sharing, signing) = new();
    assert!(refused_for(renew(&st, &sig, OTHER_CIRCLE_ID, sharing, signing, facts_ok()), "another circle"));
    let mut bad = hex::decode(&sig).unwrap();
    bad[0] ^= 1;
    let (sharing, signing) = new();
    assert!(matches!(renew(&st, &hex::encode(bad), CIRCLE, sharing, signing, facts_ok()), Err(MobileError::SignatureInvalid)));

    let (old_st, old_sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToAccount, now - 8 * 24 * 3600, 3);
    let (sharing, signing) = new();
    assert!(refused_for(renew(&old_st, &old_sig, CIRCLE, sharing, signing, facts_ok()), "expired"));
    let (addr_st, addr_sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToEmail, now - 60, 3);
    let (sharing, signing) = new();
    assert!(refused_for(renew(&addr_st, &addr_sig, CIRCLE, sharing, signing, facts_ok()), "never renewed"));
    let (adm_st, adm_sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::Admission, now - 60, 3);
    let (sharing, signing) = new();
    assert!(refused_for(renew(&adm_st, &adm_sig, CIRCLE, sharing, signing, facts_ok()), "only an invitation"));
    let (ahead_st, ahead_sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToAccount, now - 60, 5);
    let (sharing, signing) = new();
    assert!(refused_for(renew(&ahead_st, &ahead_sig, CIRCLE, sharing, signing, facts_ok()), "behind"));
    let stranger = CryptoManager::new();
    stranger.generate_signing_keypair();
    let (st2, sig2, _) = original_invitation(&stranger, "d4d4d4d4-4444-4444-8444-444444444444", MembershipStatementKind::InvitationToAccount, now - 60, 3);
    let (sharing, signing) = new();
    assert!(matches!(renew(&st2, &sig2, CIRCLE, sharing, signing, facts_ok()), Err(MobileError::KeyNotFound(_))));
    // Positive control: the same invitation, new keys, clean facts.
    let (sharing, signing) = new();
    assert!(renew(&st, &sig, CIRCLE, sharing, signing, facts_ok()).is_ok());
}


/// The facts describe the circle NOW. An admin who has LEFT still verifies,
/// because their identity pin is kept when the roster retires their circle
/// pin; only the fact refuses them. A renewer who was demoted is refused,
/// even for an invitation it signed itself.
#[test]
fn renewal_facts_describe_the_signer_now() {
    let now = chrono::Utc::now().timestamp();
    let (a, b) = two_admins(4);
    let (st, sig, _) = original_invitation(&a, ADMIN_A, MembershipStatementKind::InvitationToAccount, now - 60, 3);
    assert_eq!(b.retain_member_pins(CIRCLE.into(), vec![ADMIN_B.into(), SUBJECT.into()]).unwrap(), 1, "A left");
    assert_eq!(b.pinned_signing_key(CIRCLE.into(), ADMIN_A.into()), Some(a.signing_public_key_hex().unwrap()), "identity pin kept");
    let departed = InvitationRenewalFacts { original_signer_is_owner_or_admin_now: false, ..facts_ok() };
    assert!(matches!(
        b.renew_invitation(CIRCLE.into(), ADMIN_B.into(), st.clone(), sig.clone(), hexseq(0x41), hexseq(0x61), departed),
        Err(MobileError::InvalidInput(m)) if m.contains("no longer an owner or admin")
    ));
    // The gap the fact closes: the departed signer's statement still verifies.
    assert!(b.renew_invitation(CIRCLE.into(), ADMIN_B.into(), st, sig, hexseq(0x41), hexseq(0x61), facts_ok()).is_ok());

    // B demoted: its own earlier invitation is not renewed either.
    let (own_st, own_sig, _) = original_invitation(&b, ADMIN_B, MembershipStatementKind::InvitationToAccount, now - 60, 2);
    let demoted = InvitationRenewalFacts { renewer_is_owner_or_admin: false, ..facts_ok() };
    assert!(matches!(
        b.renew_invitation(CIRCLE.into(), ADMIN_B.into(), own_st, own_sig, hexseq(0x41), hexseq(0x61), demoted),
        Err(MobileError::InvalidInput(m)) if m.contains("renewer is not an owner or admin")
    ));
}
