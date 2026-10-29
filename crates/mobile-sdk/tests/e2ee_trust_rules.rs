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

//! Circle-key trust rules.
//!
//! The first half is a set of proof-of-concept attacks, INVERTED: each test
//! plays a malicious relay (or a relay plus a removed member) through the
//! public API only — using nothing a relay does not legitimately hold: public
//! keys and ciphertext — and asserts the SDK refuses. The second half proves
//! the legitimate flows those refusals must not break: signed rotations, a lost
//! rotation race, re-imports on every sync, first contact, chain walks past the
//! five-version cap, personal-key slots, pins kept across a sign-out, and a key
//! store that could not be read.
//!
//! No network, no fixtures, no `#[ignore]`: these run with the crate's
//! ordinary `cargo test`.
#![allow(deprecated)]

use std::sync::{Arc, Mutex};

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use pingolin_mobile::{
    CryptoManager, KeyChainLinkData, KeyRotationBundle, KeyStorageCallback, Location,
    MemberKeyBundle, MobileError, PersonalKeyVerdict, PinState, PublishedCopyStatus, SignWrapParams,
    StorageCallbackError, StoredKeyData,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const ALICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const EVE: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const SERVER_ACCT: &str = "55555555-5555-4555-8555-555555555555";
const CIRCLE: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const CIRCLE_2: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
/// The personal key's id on the server and in the apps (the Android app
/// also knows a legacy "self" slot).
const SELF_CIRCLE: &str = "00000000-0000-0000-0000-000000000000";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn b64_to_hex(b64: &str) -> String {
    hex::encode(base64::engine::general_purpose::STANDARD.decode(b64).unwrap())
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

struct Member {
    m: Arc<CryptoManager>,
    uid: &'static str,
    private_b64: String,
    signing_seed_b64: String,
    sharing_b64: String,
    sharing_hex: String,
    signing_hex: String,
}

fn member(uid: &'static str) -> Member {
    let m = CryptoManager::new();
    let kp = m.generate_keypair();
    let sk = m.generate_signing_keypair();
    let sharing_b64 = m.export_public_key().unwrap();
    let sharing_hex = b64_to_hex(&sharing_b64);
    let signing_hex = m.signing_public_key_hex().unwrap();
    Member {
        m,
        uid,
        private_b64: kp.private_key,
        signing_seed_b64: sk.secret_seed_b64,
        sharing_b64,
        sharing_hex,
        signing_hex,
    }
}

/// Another device signed in to the same account: same X25519 identity and
/// signing key, nothing else (no circle keys, no pins).
fn same_account_device(who: &Member) -> Arc<CryptoManager> {
    let d = CryptoManager::new();
    d.import_private_key(who.private_b64.clone()).unwrap();
    d.import_signing_private_key(who.signing_seed_b64.clone()).unwrap();
    d
}

/// What any relay can build from a victim's PUBLIC key alone: an
/// ephemeral-static ECDH wrap of a key the relay chose.
fn forge_wrap(recipient_pub_b64: &str, key: &[u8; 32]) -> (String, String) {
    let rb = base64::engine::general_purpose::STANDARD.decode(recipient_pub_b64).unwrap();
    let mut ra = [0u8; 32];
    ra.copy_from_slice(&rb);
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(ra));
    let wk = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new_from_slice(&wk)
        .unwrap()
        .encrypt(&XNonce::from(nonce), key.as_slice())
        .unwrap();
    (format!("{}{}", hex::encode(nonce), hex::encode(ct)), hex::encode(eph_pub.as_bytes()))
}

/// A key-chain link sealing `old` under `new`, exactly as `create_key_chain_link`
/// builds one.
fn forge_link(new: &[u8; 32], old: &[u8; 32]) -> (String, String) {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new_from_slice(new)
        .unwrap()
        .encrypt(&XNonce::from(nonce), old.as_slice())
        .unwrap();
    (hex::encode(ct), hex::encode(nonce))
}

fn wrap_hex(bundle: &MemberKeyBundle) -> String {
    format!("{}{}", bundle.encrypted_circle_key.nonce, bundle.encrypted_circle_key.ciphertext)
}

fn loc(lat: f64, lon: f64) -> Location {
    Location {
        latitude: lat,
        longitude: lon,
        altitude: None,
        speed: None,
        heading: None,
        accuracy: Some(5.0),
        timestamp: 1_790_000_000_000,
        battery_level: Some(80),
        is_charging: None,
    }
}

/// A fresh manager holding `key` for `circle` at `version` (installed through
/// first contact), so a test can use the SDK's own readers to show who can
/// decrypt what.
fn holder_of(circle: &str, version: i32, key: &[u8; 32]) -> Arc<CryptoManager> {
    let h = CryptoManager::new();
    h.generate_keypair();
    let (ek, eph) = forge_wrap(&h.export_public_key().unwrap(), key);
    h.store_circle_key(circle.into(), ek, eph, version, SERVER_ACCT.into(), SERVER_ACCT.into(), None, None)
        .unwrap();
    h
}

/// Store `bundle` (a wrap made by `from` for `to`) on `to`'s device.
fn deliver(
    to: &CryptoManager,
    circle: &str,
    bundle: &MemberKeyBundle,
    version: i32,
    from: &str,
    to_uid: &str,
    signature: bool,
) -> Result<(), MobileError> {
    to.store_circle_key(
        circle.into(),
        wrap_hex(bundle),
        bundle.ephemeral_public_key.clone(),
        version,
        from.into(),
        to_uid.into(),
        signature.then(|| bundle.wrap_signature.clone()),
        None,
    )
}

fn pin(on: &CryptoManager, circle: &str, who: &Member) -> PinState {
    on.pin_member_keys(circle.into(), who.uid.into(), who.sharing_hex.clone(), who.signing_hex.clone())
        .unwrap()
        .state
}

/// Bob creates CIRCLE (v1) and hands Alice a SIGNED wrap; Alice pinned Bob first
/// (the roster pass), so for Alice the circle is ESTABLISHED.
fn established_circle() -> (Member, Member) {
    let alice = member(ALICE);
    let bob = member(BOB);
    let created = bob.m.prepare_circle_creation().unwrap();
    bob.m.finalize_circle_creation(created.temp_circle_id, CIRCLE.into()).unwrap();
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), alice.sharing_b64.clone(), BOB.into(), ALICE.into(), String::new())
        .unwrap();
    assert!(!w.wrap_signature.is_empty());
    assert!(matches!(pin(&alice.m, CIRCLE, &bob), PinState::NewPinning));
    deliver(&alice.m, CIRCLE, &w, 1, BOB, ALICE, true).unwrap();
    (alice, bob)
}

fn rotate(by: &Member, members: &[&Member]) -> KeyRotationBundle {
    by.m.prepare_key_rotation(
        CIRCLE.into(),
        by.uid.into(),
        members.iter().map(|m| m.uid.to_string()).collect(),
        members.iter().map(|m| m.sharing_hex.clone()).collect(),
        members.iter().map(|m| m.signing_hex.clone()).collect(),
        "Family".into(),
    )
    .unwrap()
}

fn entry_for<'a>(bundle: &'a KeyRotationBundle, uid: &str) -> &'a MemberKeyBundle {
    &bundle.member_keys.iter().find(|e| e.user_id == uid).unwrap().bundle
}

/// Bob removes Eve (who held v1) and rotates to v2 for Alice + Bob; Alice
/// installs v2 through the verified path.
fn rotate_out_eve() -> (Member, Member, Member, KeyChainLinkData) {
    let (alice, bob) = established_circle();
    let eve = member(EVE);
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), eve.sharing_b64.clone(), BOB.into(), EVE.into(), String::new())
        .unwrap();
    pin(&eve.m, CIRCLE, &bob);
    deliver(&eve.m, CIRCLE, &w, 1, BOB, EVE, true).unwrap();

    let bundle = rotate(&bob, &[&alice, &bob]);
    assert_eq!(bundle.new_key_version, 2);
    deliver(&alice.m, CIRCLE, entry_for(&bundle, ALICE), 2, BOB, ALICE, true).unwrap();
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 2);
    let link = bundle.key_chain_link.expect("rotation emits a v2->v1 chain link");
    (alice, bob, eve, link)
}

/// Alice's next location, sealed the way the apps seal it (v3 sender-bound).
fn alice_sends(alice: &Member, circle: &str, lat: f64) -> pingolin_mobile::EncryptedData {
    let pseudo = alice.m.derive_user_pseudonym(circle.into(), ALICE.into()).unwrap();
    alice.m.encrypt_location_bound(circle.into(), loc(lat, 2.2945), pseudo).unwrap()
}

fn assert_refused(r: Result<(), MobileError>, what: &str) {
    assert!(matches!(r, Err(MobileError::SignatureInvalid)), "{what}: expected SignatureInvalid, got {r:?}");
}

// ===========================================================================
// PART 1 — the attacks, inverted
// ===========================================================================

/// An unsigned "from me, to me" wrap never installs a relay-chosen key on an
/// established circle — as a new version, over the current one, or carrying
/// a signature that is not ours.
#[test]
fn relay_cannot_install_its_own_circle_key_via_a_self_labelled_wrap() {
    let (alice, bob) = established_circle();
    let k_evil = random_key();
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &k_evil);

    // Controls: the pin bar stops the same wrap labelled as
    // Bob with the signature stripped, or as an unpinned member.
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek.clone(), eph.clone(), 2, BOB.into(), ALICE.into(), None, None),
        "stripped pinned signer",
    );
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek.clone(), eph.clone(), 2, EVE.into(), ALICE.into(), None, None),
        "unpinned signer",
    );

    // The attack: sender == recipient == Alice, no signature — next version...
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek.clone(), eph.clone(), 2, ALICE.into(), ALICE.into(), None, None),
        "unsigned self-labelled wrap, new version",
    );
    // ...or over the version Alice holds...
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek.clone(), eph.clone(), 1, ALICE.into(), ALICE.into(), None, None),
        "unsigned self-labelled wrap, held version",
    );
    // ...or signed by the relay's own key (verified against OUR key, so it fails).
    let relay = member(SERVER_ACCT);
    let wrap = hex::decode(&ek).unwrap();
    let relay_sig = relay
        .m
        .sign_wrap(SignWrapParams {
            domain: "pingolin.sig.v1.rotation_member_wrap".into(),
            sender_user_id: ALICE.into(),
            recipient_user_id: ALICE.into(),
            circle_id: CIRCLE.into(),
            place_id: String::new(),
            key_version: 2,
            ephemeral_pubkey_hex: eph.clone(),
            wrap_nonce_hex: hex::encode(&wrap[..24]),
            wrap_ciphertext_hex: hex::encode(&wrap[24..]),
        })
        .unwrap();
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek, eph, 2, ALICE.into(), ALICE.into(), Some(relay_sig), None),
        "self-labelled wrap signed by another key",
    );
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 1, "the relay key is not active");

    // Alice's next location: the relay cannot read it, Bob can.
    let ct = alice_sends(&alice, CIRCLE, 48.8584);
    let relay_view = holder_of(CIRCLE, 2, &k_evil);
    assert!(relay_view.decrypt_location_bound_for_user(CIRCLE.into(), ct.clone(), ALICE.into()).is_err());
    let got = bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).unwrap();
    assert!(got.sender_verified && (got.location.latitude - 48.8584).abs() < 1e-6);
}

/// The relay cannot swap the personal ("self") key — labelled as ours, or
/// unlabelled as the server actually serves it — at a new version or over
/// the held one.
#[test]
fn relay_cannot_replace_the_personal_key() {
    let alice = member(ALICE);
    let k_self = random_key();
    // Genuine first contact on this device (an unsigned self key): accepted.
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &k_self);
    alice.m.store_circle_key(SELF_CIRCLE.into(), ek, eph, 1, ALICE.into(), ALICE.into(), None, None).unwrap();

    let k_evil = random_key();
    for (version, sender) in [(2, ALICE), (1, ALICE), (2, ""), (1, "")] {
        let (ek, eph) = forge_wrap(&alice.sharing_b64, &k_evil);
        assert_refused(
            alice.m.store_circle_key(SELF_CIRCLE.into(), ek, eph, version, sender.into(), ALICE.into(), None, None),
            &format!("personal key v{version} sender={sender:?}"),
        );
    }
    assert_eq!(alice.m.get_active_version(SELF_CIRCLE.into()).unwrap(), 1);

    let ct = alice.m.encrypt_location(SELF_CIRCLE.into(), loc(40.6892, -74.0445)).unwrap();
    assert!(holder_of(SELF_CIRCLE, 2, &k_evil).decrypt_location(SELF_CIRCLE.into(), ct.clone()).is_err());
    let genuine = holder_of(SELF_CIRCLE, 1, &k_self).decrypt_location(SELF_CIRCLE.into(), ct).unwrap();
    assert!((genuine.latitude - 40.6892).abs() < 1e-6);
}

/// A genuine key-chain link relabelled by the relay (2->1 served as 2->2,
/// or any label that does not step exactly one version down) is refused, so the
/// active key cannot be rolled back to one a removed member knows.
#[test]
fn relabelled_chain_link_is_refused() {
    let (alice, bob, eve, link) = rotate_out_eve();
    assert_eq!((link.from_version, link.to_version), (2, 1));

    for (from, to) in [(2, 2), (2, 0), (3, 1), (2, 3), (1, 0)] {
        let r = alice.m.import_key_chain_link(CIRCLE.into(), from, to, link.encrypted_key.clone(), link.nonce.clone());
        assert!(matches!(r, Err(MobileError::InvalidInput(_))), "link labelled v{from}->v{to} must be refused: {r:?}");
    }
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 2);

    // Eve (v1 only) cannot read Alice's next location; Bob can.
    let ct = alice_sends(&alice, CIRCLE, 51.5007);
    assert!(eve.m.decrypt_location_bound_for_user(CIRCLE.into(), ct.clone(), ALICE.into()).is_err());
    assert!(bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).unwrap().sender_verified);

    // Positive control: the genuine link still imports — twice, as every sync does.
    for _ in 0..2 {
        alice
            .m
            .import_key_chain_link(CIRCLE.into(), 2, 1, link.encrypted_key.clone(), link.nonce.clone())
            .unwrap();
    }
}

/// No-overwrite: a link that decrypts fine but carries a DIFFERENT
/// key for a version already held never replaces it.
#[test]
fn chain_link_never_overwrites_a_held_version() {
    let alice = member(ALICE);
    let k2 = random_key();
    let k1 = random_key();
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &k2);
    alice.m.store_circle_key(CIRCLE.into(), ek, eph, 2, SERVER_ACCT.into(), ALICE.into(), None, None).unwrap();

    let (ct, nonce) = forge_link(&k2, &k1);
    alice.m.import_key_chain_link(CIRCLE.into(), 2, 1, ct.clone(), nonce.clone()).unwrap();
    alice.m.import_key_chain_link(CIRCLE.into(), 2, 1, ct, nonce).unwrap(); // re-walk: same bytes, Ok

    let (ct, nonce) = forge_link(&k2, &random_key());
    let r = alice.m.import_key_chain_link(CIRCLE.into(), 2, 1, ct, nonce);
    assert!(matches!(r, Err(MobileError::InvalidInput(_))), "conflicting link must be refused: {r:?}");

    // v1 still opens what was sealed under the genuine k1.
    let sealed_under_k1 = holder_of(CIRCLE, 1, &k1).encrypt_data(CIRCLE.into(), "v1 data".into()).unwrap();
    assert_eq!(alice.m.decrypt_data(CIRCLE.into(), sealed_under_k1).unwrap(), "v1 data");
}

/// A removed member whose pin was never retired cannot re-key a remaining
/// member — neither over the version she holds, nor (once the roster
/// retires her pin) at a new version.
#[test]
fn removed_member_cannot_rekey_a_remaining_member() {
    let (alice, bob) = established_circle();
    let eve = member(EVE);
    // Eve was a member: Alice's roster pass pinned her, and she received v1.
    assert!(matches!(pin(&alice.m, CIRCLE, &eve), PinState::NewPinning));
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), eve.sharing_b64.clone(), BOB.into(), EVE.into(), String::new())
        .unwrap();
    pin(&eve.m, CIRCLE, &bob);
    deliver(&eve.m, CIRCLE, &w, 1, BOB, EVE, true).unwrap();

    // Eve is removed; Bob rotates for Alice + Bob; Alice installs v2.
    let bundle = rotate(&bob, &[&alice, &bob]);
    deliver(&alice.m, CIRCLE, entry_for(&bundle, ALICE), 2, BOB, ALICE, true).unwrap();

    // Eve's own "rotation" (her device is at v1, so it is labelled v2), signed
    // with her real key: refused — Alice already holds a v2.
    let evil = eve.m.prepare_key_rotation(
        CIRCLE.into(), EVE.into(),
        vec![ALICE.into()], vec![alice.sharing_hex.clone()], vec![alice.signing_hex.clone()], "x".into(),
    ).unwrap();
    assert_eq!(evil.new_key_version, 2);
    assert_refused(deliver(&alice.m, CIRCLE, &evil.member_keys[0].bundle, 2, EVE, ALICE, true), "Eve over held v2");

    // The roster no longer lists Eve: the app retires her pin...
    assert_eq!(alice.m.retain_member_pins(CIRCLE.into(), vec![ALICE.into(), BOB.into()]).unwrap(), 1);
    // ...and a signed wrap from Eve for a version Alice does NOT hold is refused too.
    let eve_device = same_account_device(&eve);
    let k3 = random_key();
    let (ek, eph) = forge_wrap(&eve.sharing_b64, &k3);
    // Eve's device holds k3 as its own (a key taken on trust is never delivered).
    let sig = own_signed(&eve_device, EVE, 3, &ek, &eph);
    eve_device.store_circle_key(CIRCLE.into(), ek, eph, 3, EVE.into(), EVE.into(), Some(sig), None).unwrap();
    let evil3 = eve_device
        .wrap_circle_key_for_member_full(CIRCLE.into(), alice.sharing_b64.clone(), EVE.into(), ALICE.into(), String::new())
        .unwrap();
    assert_refused(deliver(&alice.m, CIRCLE, &evil3, 3, EVE, ALICE, true), "retired signer at a new version");
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 2);

    let ct = alice_sends(&alice, CIRCLE, 41.8902);
    assert!(eve.m.decrypt_location_bound_for_user(CIRCLE.into(), ct.clone(), ALICE.into()).is_err());
    assert!(holder_of(CIRCLE, 3, &k3).decrypt_location_bound_for_user(CIRCLE.into(), ct.clone(), ALICE.into()).is_err());
    assert!(bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).unwrap().sender_verified);
}

/// First contact is not re-opened by a same-account sign-out (pins exported and restored), and a
/// known member's keys in a NEW circle are Matched or Changed — never a silent new pin.
///
/// Still accepted (see `genuine_first_contact_still_accepts_an_unsigned_wrap`): a device with no
/// pins and no keys for a circle takes an unsigned wrap — first contact has nothing to check it
/// against.
#[test]
fn known_members_are_not_first_contact_again() {
    let (alice, bob) = established_circle();

    // Same-account sign-out on this device: export, wipe, sign back in, restore.
    let blob = alice.m.export_member_pins(ALICE.into()).unwrap();
    alice.m.clear_all_keys();
    alice.m.import_private_key(alice.private_b64.clone()).unwrap();
    alice.m.import_signing_private_key(alice.signing_seed_b64.clone()).unwrap();
    // A blob for another account is refused.
    assert!(matches!(alice.m.import_member_pins(BOB.into(), blob.clone()), Err(MobileError::InvalidInput(_))));
    assert_eq!(alice.m.import_member_pins(ALICE.into(), blob).unwrap(), 2, "circle pin + identity pin");

    // The relay serves an unsigned wrap "from Bob" of its own key: refused,
    // because Bob is still pinned for this circle.
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &random_key());
    assert_refused(
        alice.m.store_circle_key(CIRCLE.into(), ek, eph, 1, BOB.into(), ALICE.into(), None, None),
        "unsigned wrap naming a pinned member after re-login",
    );
    // Bob's genuine signed wrap is accepted (positive control).
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), alice.sharing_b64.clone(), BOB.into(), ALICE.into(), String::new())
        .unwrap();
    deliver(&alice.m, CIRCLE, &w, 1, BOB, ALICE, true).unwrap();

    // A NEW circle with Bob: the relay substitutes his sharing key -> Changed,
    // and nothing is pinned for it.
    let eve = member(EVE);
    let st = alice
        .m
        .pin_member_keys(CIRCLE_2.into(), BOB.into(), eve.sharing_hex.clone(), bob.signing_hex.clone())
        .unwrap();
    assert!(matches!(st.state, PinState::ChangedSharing), "known user with a substituted key in a new circle");
    assert!(st.previous_pinned_at > 0);
    // Callers comparing against the pin (invite, rotation gate) see Bob's real key.
    assert_eq!(alice.m.pinned_sharing_key(CIRCLE_2.into(), BOB.into()), Some(bob.sharing_hex.clone()));
    // Bob's genuine keys in the new circle: Matched, not NewPinning.
    assert!(matches!(pin(&alice.m, CIRCLE_2, &bob), PinState::Matched));
}

/// A session key minted under the pre-rotation key is not used once the
/// device holds the rotated key, so the removed member cannot read the next
/// sends; a fresh session key under the new version works.
#[test]
fn pre_rotation_session_key_is_retired_by_the_rotation() {
    let (alice, bob) = established_circle();
    let eve = member(EVE);
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), eve.sharing_b64.clone(), BOB.into(), EVE.into(), String::new())
        .unwrap();
    pin(&eve.m, CIRCLE, &bob);
    deliver(&eve.m, CIRCLE, &w, 1, BOB, EVE, true).unwrap();

    // Alice publishes a 6 h session key under v1, as Android's ensureSessionKey does.
    let sk = alice.m.create_session_key(CIRCLE.into(), 21600).unwrap();
    assert_eq!(sk.key_version, 1);
    assert!(alice.m.has_active_session_key(CIRCLE.into()));

    // Bob removes Eve and rotates; Alice receives v2 through the verified path.
    let bundle = rotate(&bob, &[&alice, &bob]);
    deliver(&alice.m, CIRCLE, entry_for(&bundle, ALICE), 2, BOB, ALICE, true).unwrap();
    assert!(!alice.m.has_active_session_key(CIRCLE.into()), "the v1 session key is retired");

    let pseudo = alice.m.derive_user_pseudonym(CIRCLE.into(), ALICE.into()).unwrap();
    let sent = alice
        .m
        .encrypt_location_with_session_key_bound(CIRCLE.into(), loc(35.6586, 139.7454), pseudo.clone())
        .unwrap();
    assert_eq!(sent.key_id, "c:2", "falls back to the v2 circle key");

    // Eve opens the published v1 session-key blob — and still cannot read the row.
    eve.m
        .import_peer_session_key(CIRCLE.into(), sk.session_key_id.clone(), sk.encrypted_session_key.clone(), sk.key_nonce.clone(), 1, sk.expires_at)
        .unwrap();
    assert!(eve
        .m
        .decrypt_location_with_session_key_bound_for_user(CIRCLE.into(), sent.encrypted.clone(), sent.key_id.clone(), ALICE.into())
        .is_err());
    let got = bob
        .m
        .decrypt_location_with_session_key_bound_for_user(CIRCLE.into(), sent.encrypted, sent.key_id, ALICE.into())
        .unwrap();
    assert!(got.sender_verified && (got.location.latitude - 35.6586).abs() < 1e-6);

    // Positive control: a fresh session key is minted under v2 and used.
    let sk2 = alice.m.create_session_key(CIRCLE.into(), 21600).unwrap();
    assert_eq!(sk2.key_version, 2);
    assert!(alice.m.has_active_session_key(CIRCLE.into()));
    let sent2 = alice
        .m
        .encrypt_location_with_session_key_bound(CIRCLE.into(), loc(35.0, 139.0), pseudo)
        .unwrap();
    assert!(sent2.key_id.starts_with("s:"));
    bob.m
        .import_peer_session_key(CIRCLE.into(), sk2.session_key_id, sk2.encrypted_session_key, sk2.key_nonce, 2, sk2.expires_at)
        .unwrap();
    assert!(bob
        .m
        .decrypt_location_with_session_key_bound_for_user(CIRCLE.into(), sent2.encrypted, sent2.key_id, ALICE.into())
        .unwrap()
        .sender_verified);
}

/// An unbound (v1) ciphertext served under another member's name still
/// decrypts, and the reader reports it as unverified (`sender_verified`
/// false): that flag is the signal apps act on.
#[test]
fn unbound_ciphertext_under_another_name_is_reported_unverified() {
    let (_alice, bob) = established_circle();
    let bob_ct = bob.m.encrypt_location(CIRCLE.into(), loc(-33.8568, 151.2153)).unwrap();
    let got = bob.m.decrypt_location_bound_for_user(CIRCLE.into(), bob_ct, ALICE.into()).unwrap();
    assert!(!got.sender_verified, "an unbound row must never be reported as sender-verified");
}

// ---------------------------------------------------------------------------
// A key store that could not be read is never overwritten
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Disk {
    data: Mutex<Option<StoredKeyData>>,
    /// Simulates a locked Keychain / keystore error reported as an ERROR (the
    /// callback contract).
    read_error: Mutex<bool>,
    /// Simulates callbacks that report the same failure as "nothing
    /// stored".
    read_nothing: Mutex<bool>,
    writes: Mutex<usize>,
}

struct DiskHandle(Arc<Disk>);

impl KeyStorageCallback for DiskHandle {
    fn store_keys(&self, d: StoredKeyData) -> Result<(), StorageCallbackError> {
        *self.0.writes.lock().unwrap() += 1;
        *self.0.data.lock().unwrap() = Some(d);
        Ok(())
    }
    fn load_keys(&self) -> Result<Option<StoredKeyData>, StorageCallbackError> {
        if *self.0.read_error.lock().unwrap() {
            return Err(StorageCallbackError::Failed);
        }
        if *self.0.read_nothing.lock().unwrap() {
            return Ok(None);
        }
        Ok(self.0.data.lock().unwrap().clone())
    }
    fn delete_keys(&self) -> Result<(), StorageCallbackError> {
        *self.0.data.lock().unwrap() = None;
        Ok(())
    }
}

impl Disk {
    fn stored(&self) -> StoredKeyData {
        self.data.lock().unwrap().clone().expect("something stored")
    }
    fn writes(&self) -> usize {
        *self.writes.lock().unwrap()
    }
}

/// A healthy session on disk: Alice's circle key, her pin of Bob, her signing seed.
fn persisted_session() -> (Member, Arc<Disk>) {
    let (alice, _bob) = established_circle();
    let disk = Arc::new(Disk::default());
    alice.m.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    alice.m.persist_keys().unwrap();
    let before = disk.stored();
    assert!(before.circle_keys_json.contains(CIRCLE));
    assert!(before.pinned_keys_json.as_deref().unwrap_or("").contains(BOB));
    assert!(before.signing_private_key_b64.is_some());
    (alice, disk)
}

fn assert_session_intact(disk: &Disk) {
    let after = disk.stored();
    assert!(after.circle_keys_json.contains(CIRCLE), "circle keys kept: {}", after.circle_keys_json);
    assert!(after.pinned_keys_json.as_deref().unwrap_or("").contains(BOB), "pins kept");
    assert!(after.signing_private_key_b64.is_some(), "signing seed kept");
}

/// A failed read under the callback contract: the read fails with an error,
/// the app imports its private key the usual way — and the stored keys,
/// pins and signing seed survive. Writes resume after a successful load.
#[test]
fn failed_read_then_import_does_not_overwrite_the_store() {
    let (alice, disk) = persisted_session();
    let writes_before = disk.writes();

    *disk.read_error.lock().unwrap() = true;
    let cold = CryptoManager::new();
    cold.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(cold.load_persisted_keys().is_err());
    cold.import_private_key(alice.private_b64.clone()).unwrap();
    assert!(matches!(cold.persist_keys(), Err(MobileError::StorageError(_))));
    // A sync in the meantime (the apps close the bulk window in a `finally`):
    // its unsigned first copy is refused while the store can't be read (a key
    // this device held may be in it), and the window closes without an error,
    // unwritten.
    cold.begin_bulk_key_import();
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &random_key());
    assert!(cold.store_circle_key(CIRCLE_2.into(), ek.clone(), eph.clone(), 1, SERVER_ACCT.into(), ALICE.into(), None, None).is_err());
    cold.end_bulk_key_import().expect("an unreadable store is not a failed flush");
    assert_eq!(disk.writes(), writes_before, "nothing was written");
    assert_session_intact(&disk);

    // First unlock: the app reloads; the stored keys are back, a first copy is
    // a first contact again, and writes resume.
    *disk.read_error.lock().unwrap() = false;
    assert!(cold.load_persisted_keys().unwrap());
    assert!(cold.has_circle_key(CIRCLE.into()));
    cold.store_circle_key(CIRCLE_2.into(), ek, eph, 1, SERVER_ACCT.into(), ALICE.into(), None, None).unwrap();
    cold.persist_keys().unwrap();
    assert_session_intact(&disk);
    assert!(disk.stored().circle_keys_json.contains(CIRCLE_2));
}

/// A failed read reported as "nothing stored", as a callback may do: the
/// first write re-reads the store and keeps what it finds (the iOS case —
/// the Keychain is readable again by the time anything is written).
#[test]
fn store_reported_empty_at_launch_is_merged_not_overwritten() {
    let (alice, disk) = persisted_session();

    *disk.read_nothing.lock().unwrap() = true;
    let cold = CryptoManager::new();
    cold.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(!cold.load_persisted_keys().unwrap());
    *disk.read_nothing.lock().unwrap() = false;

    cold.import_private_key(alice.private_b64.clone()).unwrap();
    assert_session_intact(&disk);
    assert!(cold.has_circle_key(CIRCLE.into()), "the stored circle key is back in memory");
    assert!(cold.pinned_sharing_key(CIRCLE.into(), BOB.into()).is_some(), "the stored pin is back");
    assert!(cold.signing_public_key_hex().is_ok(), "the stored signing key is back");
}

/// A RELOAD (after a failed load, with keys imported at sign-in meanwhile) keeps
/// the identity and signing key in memory: the stored ones are older. A store
/// written for a different identity is not merged at all, and the next write
/// replaces it; one of the same identity is merged.
#[test]
fn reload_keeps_the_identity_and_signing_key_in_memory() {
    // Different identity: nothing crosses over.
    let (_alice, disk) = persisted_session();
    let bob = member(BOB);
    *disk.read_error.lock().unwrap() = true;
    let device = CryptoManager::new();
    device.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(device.load_persisted_keys().is_err());
    device.import_private_key(bob.private_b64.clone()).unwrap();
    *disk.read_error.lock().unwrap() = false;
    assert!(!device.load_persisted_keys().unwrap(), "another identity's store is not loaded");
    assert_eq!(device.export_public_key().unwrap(), bob.sharing_b64);
    assert!(!device.has_circle_key(CIRCLE.into()), "the other identity's circle keys are not merged");
    device.persist_keys().unwrap();
    assert!(
        !disk.stored().circle_keys_json.contains(CIRCLE),
        "the next write replaced the other identity's store"
    );

    // Same identity, a newer signing key imported at sign-in: kept; stored keys merged.
    let (alice, disk) = persisted_session();
    *disk.read_error.lock().unwrap() = true;
    let phone = CryptoManager::new();
    phone.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(phone.load_persisted_keys().is_err());
    phone.import_private_key(alice.private_b64.clone()).unwrap();
    let fresh = phone.generate_signing_keypair_detached();
    phone.import_signing_private_key(fresh.secret_seed_b64).unwrap();
    *disk.read_error.lock().unwrap() = false;
    assert!(phone.load_persisted_keys().unwrap());
    assert_eq!(phone.signing_public_key_hex().unwrap(), b64_to_hex(&fresh.verifying_key_b64));
    assert!(phone.has_circle_key(CIRCLE.into()));
}

/// Loading writes nothing: a load that wrote the store with an EMPTY circle
/// key map and pin set would lose them if the process died before its next
/// write.
#[test]
fn loading_the_key_store_writes_nothing() {
    let (_alice, disk) = persisted_session();
    let writes_before = disk.writes();
    let next = CryptoManager::new();
    next.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(next.load_persisted_keys().unwrap());
    assert_eq!(disk.writes(), writes_before);
    assert_session_intact(&disk);
    assert!(next.has_circle_key(CIRCLE.into()));
}

// ===========================================================================
// PART 2 — legitimate flows that must keep working
// ===========================================================================

/// A pinned member's signed rotation is accepted and interoperates; the
/// rotator's own signed slot confirms its rotation on re-import.
#[test]
fn signed_rotation_is_accepted() {
    let (alice, bob) = established_circle();
    pin(&bob.m, CIRCLE, &alice);
    let bundle = rotate(&bob, &[&alice, &bob]);
    deliver(&alice.m, CIRCLE, entry_for(&bundle, ALICE), 2, BOB, ALICE, true).unwrap();
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 2);
    // The rotator re-imports its own signed slot (every sync): a no-op...
    deliver(&bob.m, CIRCLE, entry_for(&bundle, BOB), 2, BOB, BOB, true).unwrap();
    // ...and data flows both ways under v2.
    let ct = alice_sends(&alice, CIRCLE, 12.5);
    assert!(bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).unwrap().sender_verified);
}

/// The rotator's own slot on ANOTHER device of the same account: accepted as a
/// new version because it verifies under the account's own signing key.
#[test]
fn own_rotation_slot_reaches_the_accounts_other_devices() {
    let (alice, bob) = established_circle();
    let bob_phone_2 = same_account_device(&bob);
    // The second phone got v1 through its own (unsigned) creation wrap: first contact.
    let w1 = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), String::new(), BOB.into(), BOB.into(), String::new())
        .unwrap();
    deliver(&bob_phone_2, CIRCLE, &w1, 1, BOB, BOB, false).unwrap();

    let bundle = rotate(&bob, &[&alice, &bob]);
    deliver(&bob_phone_2, CIRCLE, entry_for(&bundle, BOB), 2, BOB, BOB, true).unwrap();
    assert_eq!(bob_phone_2.get_active_version(CIRCLE.into()).unwrap(), 2);

    // Unsigned, the same slot would be refused (the device already holds v1).
    let bob_phone_3 = same_account_device(&bob);
    deliver(&bob_phone_3, CIRCLE, &w1, 1, BOB, BOB, false).unwrap();
    assert_refused(
        deliver(&bob_phone_3, CIRCLE, entry_for(&bundle, BOB), 2, BOB, BOB, false),
        "own slot with the signature stripped",
    );
}

/// A device whose signing key is not loaded cannot vouch for its own
/// account's rotation slot: the slot is never accepted unverified. With the
/// signing key loaded, it is accepted.
#[test]
fn own_rotation_slot_needs_the_signing_key_loaded() {
    let (alice, bob) = established_circle();
    let no_signing_key = CryptoManager::new();
    no_signing_key.import_private_key(bob.private_b64.clone()).unwrap();
    let w1 = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), String::new(), BOB.into(), BOB.into(), String::new())
        .unwrap();
    deliver(&no_signing_key, CIRCLE, &w1, 1, BOB, BOB, true).unwrap(); // first contact

    let bundle = rotate(&bob, &[&alice, &bob]);
    assert_refused(
        deliver(&no_signing_key, CIRCLE, entry_for(&bundle, BOB), 2, BOB, BOB, true),
        "signed own slot, own signing key not loaded",
    );
    no_signing_key.import_signing_private_key(bob.signing_seed_b64.clone()).unwrap();
    deliver(&no_signing_key, CIRCLE, entry_for(&bundle, BOB), 2, BOB, BOB, true).unwrap();
}

/// Re-importing the same wrap on every sync is a no-op — and does not
/// rewrite the whole key store each time.
#[test]
fn identical_reimport_is_a_no_op() {
    let (alice, bob) = established_circle();
    let disk = Arc::new(Disk::default());
    alice.m.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    alice.m.persist_keys().unwrap();
    let writes = disk.writes();

    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), alice.sharing_b64.clone(), BOB.into(), ALICE.into(), String::new())
        .unwrap();
    for _ in 0..3 {
        deliver(&alice.m, CIRCLE, &w, 1, BOB, ALICE, true).unwrap();
    }
    assert_eq!(disk.writes(), writes, "an identical re-import writes nothing");
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 1);
}

/// First contact keeps working: a fresh device takes the circle creator's
/// unsigned creation wrap (what the server serves) and an unsigned wrap
/// from a not-yet-pinned member (legacy).
#[test]
fn genuine_first_contact_still_accepts_an_unsigned_wrap() {
    let bob = member(BOB);
    let created = bob.m.prepare_circle_creation().unwrap();
    bob.m.finalize_circle_creation(created.temp_circle_id.clone(), CIRCLE.into()).unwrap();
    let bob_new_phone = same_account_device(&bob);
    bob_new_phone
        .store_circle_key(
            CIRCLE.into(),
            format!("{}{}", created.encrypted_circle_key.nonce, created.encrypted_circle_key.ciphertext),
            created.ephemeral_public_key.clone(),
            1,
            BOB.into(),
            BOB.into(),
            None,
            None,
        )
        .unwrap();
    assert!(bob_new_phone.has_circle_key(CIRCLE.into()));

    let alice = member(ALICE);
    let w = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), alice.sharing_b64.clone(), BOB.into(), ALICE.into(), String::new())
        .unwrap();
    deliver(&alice.m, CIRCLE, &w, 1, BOB, ALICE, false).unwrap();
    assert!(alice.m.has_circle_key(CIRCLE.into()));
}

/// Lost rotation race: two admins rotate v1 -> v2 at once; the server keeps
/// Bob's and tells Alice `already_rotated`. Alice's re-import adopts Bob's key
/// over her own unconfirmed one. Once each side holds the server's v2, no other
/// v2 can replace it.
#[test]
fn lost_rotation_race_adopts_the_winners_key() {
    let (alice, bob) = established_circle();
    pin(&bob.m, CIRCLE, &alice);
    let alices = rotate(&alice, &[&alice, &bob]); // loses
    let bobs = rotate(&bob, &[&alice, &bob]); // wins
    assert_eq!((alices.new_key_version, bobs.new_key_version), (2, 2));

    // Alice re-imports what the server holds for her: Bob's signed wrap.
    deliver(&alice.m, CIRCLE, entry_for(&bobs, ALICE), 2, BOB, ALICE, true).unwrap();
    assert_eq!(alice.m.get_active_version(CIRCLE.into()).unwrap(), 2);
    let ct = alice_sends(&alice, CIRCLE, 45.0);
    assert!(bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).unwrap().sender_verified);

    // Settled: Alice's own losing slot, replayed, replaces nothing.
    assert_refused(deliver(&alice.m, CIRCLE, entry_for(&alices, ALICE), 2, ALICE, ALICE, true), "replayed losing slot");
    // Bob confirms his rotation by re-importing his own slot; after that even a
    // pinned member's signed v2 cannot replace it.
    deliver(&bob.m, CIRCLE, entry_for(&bobs, BOB), 2, BOB, BOB, true).unwrap();
    assert_refused(deliver(&bob.m, CIRCLE, entry_for(&alices, BOB), 2, ALICE, BOB, true), "other v2 after confirmation");
}

/// The unconfirmed-rotation marker survives a process restart, so a device
/// killed between its rotation POST and the re-import still converges.
#[test]
fn lost_rotation_race_survives_a_restart() {
    let (alice, bob) = established_circle();
    pin(&bob.m, CIRCLE, &alice);
    let disk = Arc::new(Disk::default());
    bob.m.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    let bobs = rotate(&bob, &[&alice, &bob]); // persisted, unconfirmed
    let alices = rotate(&alice, &[&alice, &bob]); // the server keeps Alice's

    let bob_after_restart = CryptoManager::new();
    bob_after_restart.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(bob_after_restart.load_persisted_keys().unwrap());
    deliver(&bob_after_restart, CIRCLE, entry_for(&alices, BOB), 2, ALICE, BOB, true).unwrap();
    let ct = bob_after_restart.encrypt_data(CIRCLE.into(), "after the race".into()).unwrap();
    assert_eq!(alice.m.decrypt_data(CIRCLE.into(), ct).unwrap(), "after the race");
    let _ = bobs;
}

/// A rotation whose POST failed: `discard_unconfirmed_rotation` restores v1, the
/// retry is labelled v2 again (the server's next number), and a discarded
/// rotation the server DID take comes back on the next import.
#[test]
fn failed_rotation_can_be_discarded() {
    let (alice, bob) = established_circle();
    let _failed = rotate(&bob, &[&alice, &bob]);
    assert!(bob.m.discard_unconfirmed_rotation(CIRCLE.into()));
    assert_eq!(bob.m.get_active_version(CIRCLE.into()).unwrap(), 1);
    assert!(!bob.m.discard_unconfirmed_rotation(CIRCLE.into()), "nothing left to discard");

    let retry = rotate(&bob, &[&alice, &bob]);
    assert_eq!(retry.new_key_version, 2);
    deliver(&alice.m, CIRCLE, entry_for(&retry, ALICE), 2, BOB, ALICE, true).unwrap();

    // Outcome unknown (timeout) but the server took it: discard, then re-import.
    assert!(bob.m.discard_unconfirmed_rotation(CIRCLE.into()));
    deliver(&bob.m, CIRCLE, entry_for(&retry, BOB), 2, BOB, BOB, true).unwrap();
    assert_eq!(bob.m.get_active_version(CIRCLE.into()).unwrap(), 2);
    let ct = alice_sends(&alice, CIRCLE, 3.0);
    assert!(bob.m.decrypt_location_bound_for_user(CIRCLE.into(), ct, ALICE.into()).is_ok());
    // A confirmed rotation is never discarded.
    assert!(!bob.m.discard_unconfirmed_rotation(CIRCLE.into()));
}

/// A chain walk past the five-version cap, in both apps' orders, and again on
/// the next sync: every version comes back and v1-era data opens.
#[test]
fn chain_walk_past_the_version_cap_in_both_app_orders() {
    let (alice, bob) = established_circle();
    let v1_data = bob.m.encrypt_data(CIRCLE.into(), "written at v1".into()).unwrap();
    let mut links = Vec::new();
    let mut last = None;
    for _ in 0..7 {
        let bundle = rotate(&bob, &[&alice, &bob]);
        // The rotator's next sync re-imports its own slot (confirms the rotation).
        deliver(&bob.m, CIRCLE, entry_for(&bundle, BOB), bundle.new_key_version, BOB, BOB, true).unwrap();
        links.push(bundle.key_chain_link.clone().unwrap());
        last = Some(bundle);
    }
    let last = last.unwrap();
    assert_eq!(last.new_key_version, 8);

    // Android: server order (oldest link first), retried until no progress.
    let android = same_account_device(&alice);
    pin(&android, CIRCLE, &bob);
    deliver(&android, CIRCLE, entry_for(&last, ALICE), 8, BOB, ALICE, true).unwrap();
    let mut pending = links.clone();
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|l| {
            android
                .import_key_chain_link(CIRCLE.into(), l.from_version, l.to_version, l.encrypted_key.clone(), l.nonce.clone())
                .is_err()
        });
        assert!(pending.len() < before, "the walk must make progress");
    }
    assert_eq!(android.decrypt_data(CIRCLE.into(), v1_data.clone()).unwrap(), "written at v1");
    // The next sync walks the same chain again: all Ok.
    for l in &links {
        android
            .import_key_chain_link(CIRCLE.into(), l.from_version, l.to_version, l.encrypted_key.clone(), l.nonce.clone())
            .unwrap();
    }

    // iOS: newest link first.
    let ios = same_account_device(&alice);
    pin(&ios, CIRCLE, &bob);
    deliver(&ios, CIRCLE, entry_for(&last, ALICE), 8, BOB, ALICE, true).unwrap();
    for l in links.iter().rev() {
        ios.import_key_chain_link(CIRCLE.into(), l.from_version, l.to_version, l.encrypted_key.clone(), l.nonce.clone())
            .unwrap();
    }
    assert_eq!(ios.decrypt_data(CIRCLE.into(), v1_data).unwrap(), "written at v1");
}

/// Own wraps become signable: the creator signs its creation wrap after
/// finalize, the personal key is signed BEFORE finalize (publish-then-install),
/// and both verify on the account's other devices.
#[test]
fn creation_and_personal_key_wraps_are_signable() {
    let bob = member(BOB);
    let created = bob.m.prepare_circle_creation().unwrap();
    bob.m.finalize_circle_creation(created.temp_circle_id.clone(), CIRCLE.into()).unwrap();
    let sig = bob.m.sign_circle_creation_wrap(created.clone(), CIRCLE.into(), BOB.into()).unwrap();
    assert!(bob
        .m
        .verify_wrap(
            bob.signing_hex.clone(),
            sig.clone(),
            SignWrapParams {
                domain: "pingolin.sig.v1.circle_member_wrap".into(),
                sender_user_id: BOB.into(),
                recipient_user_id: BOB.into(),
                circle_id: CIRCLE.into(),
                place_id: String::new(),
                key_version: 1,
                ephemeral_pubkey_hex: created.ephemeral_public_key.clone(),
                wrap_nonce_hex: created.encrypted_circle_key.nonce.clone(),
                wrap_ciphertext_hex: created.encrypted_circle_key.ciphertext.clone(),
            },
        )
        .unwrap());
    // Another phone of Bob's imports the signed wrap — twice, as every sync does.
    let phone = same_account_device(&bob);
    let wrap = format!("{}{}", created.encrypted_circle_key.nonce, created.encrypted_circle_key.ciphertext);
    phone
        .store_circle_key(CIRCLE.into(), wrap.clone(), created.ephemeral_public_key.clone(), 1, BOB.into(), BOB.into(), Some(sig.clone()), None)
        .unwrap();
    phone
        .store_circle_key(CIRCLE.into(), wrap, created.ephemeral_public_key.clone(), 1, BOB.into(), BOB.into(), Some(sig), None)
        .unwrap();

    // Personal key, iOS order: sign while the key is still under the temp id,
    // publish, then finalize.
    let alice = member(ALICE);
    let personal = alice.m.prepare_circle_creation().unwrap();
    let psig = alice.m.sign_circle_creation_wrap(personal.clone(), SELF_CIRCLE.into(), ALICE.into()).unwrap();
    alice.m.finalize_circle_creation(personal.temp_circle_id.clone(), SELF_CIRCLE.into()).unwrap();
    let other = same_account_device(&alice);
    other
        .store_circle_key(
            SELF_CIRCLE.into(),
            format!("{}{}", personal.encrypted_circle_key.nonce, personal.encrypted_circle_key.ciphertext),
            personal.ephemeral_public_key.clone(),
            1,
            ALICE.into(),
            ALICE.into(),
            Some(psig),
            None,
        )
        .unwrap();

    // The migration signer never signs a key this device
    // does not hold.
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &random_key());
    assert_refused(
        alice.m.sign_own_circle_key_wrap(SELF_CIRCLE.into(), ALICE.into(), 1, ek, eph).map(|_| ()),
        "signing a relay-chosen key",
    );
    // A non-UUID slot (the Android app's legacy "self") cannot be
    // signed.
    let pending = alice.m.prepare_circle_creation().unwrap();
    assert!(matches!(
        alice.m.sign_circle_creation_wrap(pending, "self".into(), ALICE.into()),
        Err(MobileError::InvalidInput(_))
    ));
}

/// A held personal key is never replaced through store_circle_key: not by an
/// unsigned wrap, and not even by one this account signed. That is
/// adopt_personal_key's job, and it keeps the key it replaces.
#[test]
fn personal_key_is_replaced_only_by_adoption_which_keeps_the_old_key() {
    let alice = member(ALICE);
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &random_key());
    alice.m.store_circle_key(SELF_CIRCLE.into(), ek, eph, 1, ALICE.into(), ALICE.into(), None, None).unwrap();
    let before = alice.m.encrypt_data(SELF_CIRCLE.into(), "sealed before".into()).unwrap();

    // Our other device minted and signed its own personal key.
    let other = same_account_device(&alice);
    let minted = other.prepare_circle_creation().unwrap();
    let sig = other.sign_circle_creation_wrap(minted.clone(), SELF_CIRCLE.into(), ALICE.into()).unwrap();
    let wrap = format!("{}{}", minted.encrypted_circle_key.nonce, minted.encrypted_circle_key.ciphertext);
    other.finalize_circle_creation(minted.temp_circle_id.clone(), SELF_CIRCLE.into()).unwrap();

    assert_refused(
        alice.m.store_circle_key(SELF_CIRCLE.into(), wrap.clone(), minted.ephemeral_public_key.clone(), 1, ALICE.into(), ALICE.into(), None, None),
        "unsigned replacement",
    );
    assert_refused(
        alice.m.store_circle_key(SELF_CIRCLE.into(), wrap.clone(), minted.ephemeral_public_key.clone(), 1, ALICE.into(), ALICE.into(), Some(sig.clone()), None),
        "own-signed replacement outside adoption",
    );
    let recorded = other.derive_user_pseudonym(SELF_CIRCLE.into(), ALICE.into()).unwrap();
    assert_eq!(
        alice.m.adopt_personal_key(ALICE.into(), wrap, minted.ephemeral_public_key.clone(), 1, Some(sig), recorded).unwrap(),
        PersonalKeyVerdict::Adopt
    );
    let ct = alice.m.encrypt_data(SELF_CIRCLE.into(), "same key now".into()).unwrap();
    assert_eq!(other.decrypt_data(SELF_CIRCLE.into(), ct).unwrap(), "same key now");
    assert_eq!(alice.m.decrypt_data(SELF_CIRCLE.into(), before).unwrap(), "sealed before", "the old key is kept");
}

/// The Android app keeps the personal key in two slots ("self" and the nil
/// UUID). A diverged pair loaded from disk realigns through the app's own
/// re-wrap (copySelfKeySlot); a server key cannot enter the empty slot while
/// the other one holds a key; the server's copy of the SAME key can.
#[test]
fn android_personal_key_slots_realign_and_resist_injection() {
    let alice = member(ALICE);
    let k_good = random_key();
    let k_stale = random_key();
    let b64 = |k: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(k);
    let disk = Arc::new(Disk::default());
    *disk.data.lock().unwrap() = Some(StoredKeyData {
        private_key: alice.private_b64.clone(),
        circle_keys_json: format!(
            r#"{{"self":{{"1":"{}"}},"{}":{{"1":"{}"}}}}"#,
            b64(&k_good),
            SELF_CIRCLE,
            b64(&k_stale)
        ),
        pinned_keys_json: None,
        signing_private_key_b64: Some(alice.signing_seed_b64.clone()),
    });
    let device = CryptoManager::new();
    device.register_secure_storage(Box::new(DiskHandle(disk.clone())));
    assert!(device.load_persisted_keys().unwrap());

    // copySelfKeySlot(from = "self", to = nil UUID)
    let bundle = device
        .wrap_circle_key_for_member_full("self".into(), String::new(), ALICE.into(), ALICE.into(), String::new())
        .unwrap();
    deliver(&device, SELF_CIRCLE, &bundle, 1, ALICE, ALICE, false).unwrap();
    let ct = device.encrypt_data(SELF_CIRCLE.into(), "realigned".into()).unwrap();
    assert_eq!(holder_of(SELF_CIRCLE, 1, &k_good).decrypt_data(SELF_CIRCLE.into(), ct).unwrap(), "realigned");

    // An install holding only "self": the server's DIFFERENT key cannot seed the
    // nil slot (migratePersonalKeyToNilUuid), the server's copy of the same key can.
    let legacy = CryptoManager::new();
    legacy.import_private_key(alice.private_b64.clone()).unwrap();
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &k_good);
    legacy.store_circle_key("self".into(), ek, eph, 1, ALICE.into(), ALICE.into(), None, None).unwrap();
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &random_key());
    assert_refused(
        legacy.store_circle_key(SELF_CIRCLE.into(), ek, eph, 1, ALICE.into(), ALICE.into(), None, None),
        "server key into the empty personal slot",
    );
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &k_good);
    legacy.store_circle_key(SELF_CIRCLE.into(), ek, eph, 1, ALICE.into(), ALICE.into(), None, None).unwrap();
}

/// Retiring pins keeps identity knowledge; an empty roster is refused.
#[test]
fn retired_members_are_remembered_by_identity() {
    let (alice, bob) = established_circle();
    let eve = member(EVE);
    pin(&alice.m, CIRCLE, &eve);
    assert!(matches!(alice.m.retain_member_pins(CIRCLE.into(), vec![]), Err(MobileError::InvalidInput(_))));
    // Only the ids' one spelling: another is refused, and nothing is
    // retired. Only this circle.
    assert!(matches!(
        alice.m.retain_member_pins(CIRCLE.into(), vec![BOB.to_uppercase(), ALICE.into()]),
        Err(MobileError::InvalidInput(_))
    ));
    assert_eq!(alice.m.retain_member_pins(CIRCLE.into(), vec![BOB.into(), ALICE.into()]).unwrap(), 1);
    assert_eq!(alice.m.retain_member_pins(CIRCLE.into(), vec![BOB.into(), ALICE.into()]).unwrap(), 0);
    assert_eq!(alice.m.pinned_sharing_key(CIRCLE.into(), BOB.into()), Some(bob.sharing_hex.clone()));

    // Eve comes back (same keys): Matched, not NewPinning. With other keys: Changed.
    assert!(matches!(pin(&alice.m, CIRCLE, &eve), PinState::Matched));
    let other = member(SERVER_ACCT);
    let st = alice
        .m
        .pin_member_keys(CIRCLE_2.into(), EVE.into(), other.sharing_hex.clone(), other.signing_hex.clone())
        .unwrap();
    assert!(matches!(st.state, PinState::ChangedBoth));
    // Approving the change (user compared the safety number) updates the identity.
    alice
        .m
        .approve_member_key_change(CIRCLE_2.into(), EVE.into(), other.sharing_hex.clone(), other.signing_hex.clone())
        .unwrap();
    let st = alice
        .m
        .pin_member_keys("99999999-9999-4999-8999-999999999999".into(), EVE.into(), other.sharing_hex.clone(), other.signing_hex.clone())
        .unwrap();
    assert!(matches!(st.state, PinState::Matched));
}

/// `generate_signing_keypair_detached` installs nothing: the device keeps
/// signing with its current key until the new one is imported.
#[test]
fn detached_signing_keypair_installs_nothing() {
    let alice = member(ALICE);
    let before = alice.m.signing_public_key_hex().unwrap();
    let fresh = alice.m.generate_signing_keypair_detached();
    assert_eq!(alice.m.signing_public_key_hex().unwrap(), before);
    alice.m.import_signing_private_key(fresh.secret_seed_b64).unwrap();
    assert_eq!(alice.m.signing_public_key_hex().unwrap(), b64_to_hex(&fresh.verifying_key_b64));
}

// ===========================================================================
// PART 3 — a circle's FIRST key
// ===========================================================================

const CAROL: &str = "cacacaca-caca-4aca-8aca-cacacacacaca";
const MALLORY: &str = "3a3a3a3a-3a3a-4a3a-8a3a-3a3a3a3a3a3a";

/// `device`'s own signature over its own wrap (`ek`, `eph`) of a CIRCLE key.
fn own_signed(device: &CryptoManager, uid: &str, version: i32, ek: &str, eph: &str) -> String {
    let bytes = hex::decode(ek).unwrap();
    device
        .sign_wrap(SignWrapParams {
            domain: "pingolin.sig.v1.circle_member_wrap".into(),
            sender_user_id: uid.into(),
            recipient_user_id: uid.into(),
            circle_id: CIRCLE.into(),
            place_id: String::new(),
            key_version: version as u32,
            ephemeral_pubkey_hex: eph.into(),
            wrap_nonce_hex: hex::encode(&bytes[..24]),
            wrap_ciphertext_hex: hex::encode(&bytes[24..]),
        })
        .unwrap()
}

/// A member holding `key` for CIRCLE at `version`: what anyone who wants to
/// hand out a key of their own choosing starts from. It holds the key as its
/// OWN (its own signed wrap), so it can deliver it: a key taken on trust is
/// never delivered under our signature.
fn member_holding(uid: &'static str, key: &[u8; 32], version: i32) -> Member {
    let who = member(uid);
    let (ek, eph) = forge_wrap(&who.sharing_b64, key);
    let sig = own_signed(&who.m, uid, version, &ek, &eph);
    who.m
        .store_circle_key(CIRCLE.into(), ek, eph, version, uid.into(), uid.into(), Some(sig), None)
        .unwrap();
    who
}

/// Store `bundle` as `to`'s FIRST key for CIRCLE, naming `signer_hex` as the
/// confirmed sender's pinned signing key.
fn deliver_first(
    to: &Member,
    bundle: &MemberKeyBundle,
    version: i32,
    from: &str,
    signer_hex: &str,
    name: Option<pingolin_mobile::EncryptedData>,
) -> Result<(), MobileError> {
    to.m.store_first_circle_key(
        CIRCLE.into(),
        wrap_hex(bundle),
        bundle.ephemeral_public_key.clone(),
        version,
        from.into(),
        to.uid.into(),
        bundle.wrap_signature.clone(),
        signer_hex.into(),
        name,
    )
}

/// A newcomer takes its first key only under the signature of the member its
/// app confirmed — not the server's key unsigned, not signed by a signer the
/// server controls and labelled as that member.
#[test]
fn first_key_needs_the_confirmed_senders_signature() {
    let bob = member(BOB);
    let created = bob.m.prepare_circle_creation().unwrap();
    bob.m.finalize_circle_creation(created.temp_circle_id, CIRCLE.into()).unwrap();
    let carol = member(CAROL);
    assert!(matches!(pin(&carol.m, CIRCLE, &bob), PinState::NewPinning), "Carol's app confirmed Bob, her inviter");

    // The server's own key, unsigned (store_circle_key would take this).
    let (ek, eph) = forge_wrap(&carol.sharing_b64, &random_key());
    assert_refused(
        carol.m.store_first_circle_key(
            CIRCLE.into(), ek, eph, 1, BOB.into(), CAROL.into(), String::new(), bob.signing_hex.clone(), None,
        ),
        "unsigned first key",
    );
    // The server's own key, signed by a key the server holds, labelled as Bob.
    let server = member_holding(SERVER_ACCT, &random_key(), 1);
    let forged = server
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), carol.sharing_b64.clone(), BOB.into(), CAROL.into(), String::new())
        .unwrap();
    assert!(!forged.wrap_signature.is_empty());
    assert_refused(deliver_first(&carol, &forged, 1, BOB, &bob.signing_hex, None), "server-signed, labelled Bob");
    // Even an app that passes the server's key as "confirmed" is held to the pin.
    assert_refused(deliver_first(&carol, &forged, 1, BOB, &server.signing_hex, None), "server key passed as Bob's");
    assert!(!carol.m.has_circle_key(CIRCLE.into()), "nothing was stored");

    // Bob's genuine signed wrap is taken and opens what Bob seals.
    let real = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), carol.sharing_b64.clone(), BOB.into(), CAROL.into(), String::new())
        .unwrap();
    deliver_first(&carol, &real, 1, BOB, &bob.signing_hex, None).unwrap();
    assert_eq!(carol.m.get_active_version(CIRCLE.into()).unwrap(), 1);
    let sealed = bob.m.encrypt_data(CIRCLE.into(), "hello".into()).unwrap();
    assert_eq!(carol.m.decrypt_data(CIRCLE.into(), sealed).unwrap(), "hello");
    // Only the FIRST key: from then on every key goes through store_circle_key.
    assert!(matches!(
        deliver_first(&carol, &real, 1, BOB, &bob.signing_hex, None),
        Err(MobileError::InvalidInput(_))
    ));

    // A device that has pinned nobody in the circle yet (store_circle_key would
    // take any of these on first contact): the named key is the only bar.
    let fresh = member(CAROL);
    let (ek, eph) = forge_wrap(&fresh.sharing_b64, &random_key());
    assert_refused(
        fresh.m.store_first_circle_key(
            CIRCLE.into(), ek, eph, 1, BOB.into(), CAROL.into(), String::new(), bob.signing_hex.clone(), None,
        ),
        "unsigned, no pins",
    );
    let forged = server
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), fresh.sharing_b64.clone(), BOB.into(), CAROL.into(), String::new())
        .unwrap();
    assert_refused(deliver_first(&fresh, &forged, 1, BOB, &bob.signing_hex, None), "server-signed, no pins");
    let real = bob
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), fresh.sharing_b64.clone(), BOB.into(), CAROL.into(), String::new())
        .unwrap();
    assert!(deliver_first(&fresh, &real, 1, BOB, "", None).is_err(), "no confirmed key named");
    assert!(!fresh.m.has_circle_key(CIRCLE.into()));
    deliver_first(&fresh, &real, 1, BOB, &bob.signing_hex, None).unwrap();
}

/// Verify before adopting. A confirmed member handing out a key of their
/// own gets nothing stored when the app passes the circle's name — sealed
/// at creation (field-only AAD), after it (id-bound AAD) or by a rotation
/// (v1 empty AAD) — while the circle's real key opens every one.
#[test]
fn first_key_must_open_the_circles_name_when_given() {
    let bob = member(BOB);
    let created = bob.m.prepare_circle_creation().unwrap();
    let at_creation = bob.m.encrypt_data_v2(created.temp_circle_id.clone(), "Family".into(), "name".into()).unwrap();
    bob.m.finalize_circle_creation(created.temp_circle_id, CIRCLE.into()).unwrap();
    let renamed = bob.m.encrypt_data_v2(CIRCLE.into(), "Family".into(), "name".into()).unwrap();
    let mallory = member_holding(MALLORY, &random_key(), 1);

    for name in [&at_creation, &renamed] {
        let carol = member(CAROL);
        pin(&carol.m, CIRCLE, &bob);
        pin(&carol.m, CIRCLE, &mallory);
        let wrong = mallory
            .m
            .wrap_circle_key_for_member_full(CIRCLE.into(), carol.sharing_b64.clone(), MALLORY.into(), CAROL.into(), String::new())
            .unwrap();
        assert!(matches!(
            deliver_first(&carol, &wrong, 1, MALLORY, &mallory.signing_hex, Some(name.clone())),
            Err(MobileError::DecryptionFailed)
        ));
        assert!(!carol.m.has_circle_key(CIRCLE.into()), "the wrong key was not stored");
        let real = bob
            .m
            .wrap_circle_key_for_member_full(CIRCLE.into(), carol.sharing_b64.clone(), BOB.into(), CAROL.into(), String::new())
            .unwrap();
        deliver_first(&carol, &real, 1, BOB, &bob.signing_hex, Some(name.clone())).unwrap();
        assert_eq!(carol.m.decrypt_data_v2(CIRCLE.into(), name.clone(), "name".into()).unwrap(), "Family");
    }

    // Without the name the signature is all there is: a confirmed member's
    // wrong key is taken (the check is opt-in).
    let carol = member(CAROL);
    pin(&carol.m, CIRCLE, &mallory);
    let wrong = mallory
        .m
        .wrap_circle_key_for_member_full(CIRCLE.into(), carol.sharing_b64.clone(), MALLORY.into(), CAROL.into(), String::new())
        .unwrap();
    deliver_first(&carol, &wrong, 1, MALLORY, &mallory.signing_hex, None).unwrap();

    // A rotation re-seals the name under the new key with the v1 empty AAD: a
    // newcomer given v2 by the rotation opens it. A name still sealed under v1
    // refuses the genuine v2 key — pass the name only when it is sealed under
    // the version being delivered.
    let dave_uid = "dadadada-dada-4ada-8ada-dadadadadada";
    let dave = member(dave_uid);
    let bundle = rotate(&bob, &[&bob, &dave]);
    assert_eq!(bundle.new_key_version, 2);
    pin(&dave.m, CIRCLE, &bob);
    assert!(matches!(
        deliver_first(&dave, entry_for(&bundle, dave_uid), 2, BOB, &bob.signing_hex, Some(renamed.clone())),
        Err(MobileError::DecryptionFailed)
    ));
    deliver_first(&dave, entry_for(&bundle, dave_uid), 2, BOB, &bob.signing_hex, Some(bundle.encrypted_name.clone())).unwrap();
    assert_eq!(dave.m.get_active_version(CIRCLE.into()).unwrap(), 2);
}

/// Only for a circle's first key — never the personal key — and the same
/// version bound as store_circle_key.
#[test]
fn first_key_refuses_the_personal_key_and_implausible_versions() {
    let bob = member(BOB);
    let carol = member(CAROL);
    let attempt = |circle: &str, version: i32| {
        carol.m.store_first_circle_key(
            circle.into(), "00".repeat(72), carol.sharing_hex.clone(), version, BOB.into(), CAROL.into(),
            "00".repeat(64), bob.signing_hex.clone(), None,
        )
    };
    assert!(matches!(attempt(SELF_CIRCLE, 1), Err(MobileError::InvalidInput(_))));
    assert!(matches!(attempt("self", 1), Err(MobileError::InvalidInput(_))));
    assert!(matches!(attempt(CIRCLE, 0), Err(MobileError::InvalidInput(_))));
    assert!(matches!(attempt(CIRCLE, 1_000_001), Err(MobileError::InvalidInput(_))));
    assert!(matches!(attempt(CIRCLE, 1), Err(MobileError::SignatureInvalid)), "a signature that does not verify");
}

// ===========================================================================
// PART 4 — the personal key: adoption and provenance
// ===========================================================================

/// `dev` mints its OWN personal key, as a device that creates the account's
/// personal key does: never taken on trust.
fn mint_personal(dev: &CryptoManager) {
    let created = dev.prepare_circle_creation().unwrap();
    dev.finalize_circle_creation(created.temp_circle_id, SELF_CIRCLE.into()).unwrap();
}

/// The server's copy of `from`'s personal key as `from` publishes it: wrapped to
/// the account and signed by it (unless `from` holds it on trust). Returns
/// (wrap hex, ephemeral hex, signature, the pseudonym under that key).
fn served_personal_copy(from: &Member) -> (String, String, String, String) {
    let bundle = from
        .m
        .wrap_circle_key_for_member_full(SELF_CIRCLE.into(), String::new(), from.uid.into(), from.uid.into(), String::new())
        .unwrap();
    let recorded = from.m.derive_user_pseudonym(SELF_CIRCLE.into(), from.uid.into()).unwrap();
    (wrap_hex(&bundle), bundle.ephemeral_public_key.clone(), bundle.wrap_signature.clone(), recorded)
}

/// `dev` holds `key` as its personal key in `slot` at `version`, taken at an
/// unauthenticated first contact: ON TRUST.
fn hold_personal(dev: &CryptoManager, who: &Member, slot: &str, key: &[u8; 32], version: i32) {
    let (ek, eph) = forge_wrap(&who.sharing_b64, key);
    dev.store_circle_key(slot.into(), ek, eph, version, who.uid.into(), who.uid.into(), None, None).unwrap();
}

/// A device's pseudonym under the personal key in use.
fn personal_pseudonym(dev: &CryptoManager, uid: &str) -> Option<String> {
    dev.derive_user_pseudonym(SELF_CIRCLE.into(), uid.into()).ok()
}

fn adopt(dev: &CryptoManager, copy: &(String, String, String, String)) -> PersonalKeyVerdict {
    dev.adopt_personal_key(ALICE.into(), copy.0.clone(), copy.1.clone(), 1, Some(copy.2.clone()), copy.3.clone()).unwrap()
}

fn check(dev: &CryptoManager, copy: &(String, String, String, String)) -> PersonalKeyVerdict {
    dev.check_personal_key_adoption(ALICE.into(), copy.0.clone(), copy.1.clone(), 1, Some(copy.2.clone()), copy.3.clone())
}

/// A phone whose personal key is not the account's adopts the account's own
/// signed copy. The check stores nothing; the adoption ADDS: the old key
/// stays readable (and deletable), new rows go under the adopted one.
#[test]
fn adopts_the_accounts_own_copy_and_keeps_the_old_key() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    assert!(!copy.2.is_empty(), "a minted key is signed");
    let phone = same_account_device(&alice);
    hold_personal(&phone, &alice, SELF_CIRCLE, &random_key(), 1);
    let old_pseudonym = personal_pseudonym(&phone, ALICE).unwrap();
    let sealed_before = phone.encrypt_data(SELF_CIRCLE.into(), "sealed before".into()).unwrap();

    assert_eq!(check(&phone, &copy), PersonalKeyVerdict::Adopt);
    assert_eq!(personal_pseudonym(&phone, ALICE).as_deref(), Some(old_pseudonym.as_str()), "the check stores nothing");

    assert_eq!(adopt(&phone, &copy), PersonalKeyVerdict::Adopt);
    assert_eq!(personal_pseudonym(&phone, ALICE).as_deref(), Some(copy.3.as_str()), "the adopted key is in use");
    let from_alice = alice.m.encrypt_data(SELF_CIRCLE.into(), "history".into()).unwrap();
    assert_eq!(phone.decrypt_data(SELF_CIRCLE.into(), from_alice).unwrap(), "history");
    assert_eq!(phone.decrypt_data(SELF_CIRCLE.into(), sealed_before).unwrap(), "sealed before", "the old key is kept");
    let new_row = phone.encrypt_data(SELF_CIRCLE.into(), "after".into()).unwrap();
    assert_eq!(alice.m.decrypt_data(SELF_CIRCLE.into(), new_row).unwrap(), "after", "new rows under the adopted key");
    // One pseudonym per held personal key, for history queries and deletion.
    let all = phone.derive_user_pseudonyms_all_versions(SELF_CIRCLE.into(), ALICE.into()).unwrap();
    assert!(all.iter().any(|p| p.eq_ignore_ascii_case(&old_pseudonym)) && all.iter().any(|p| p.eq_ignore_ascii_case(&copy.3)));
    let deletion = phone.collect_deletion_pseudonyms(ALICE.into()).unwrap();
    for p in [&old_pseudonym, &copy.3] {
        assert!(deletion.iter().any(|d| d.circle_id == SELF_CIRCLE && d.user_pseudonym.eq_ignore_ascii_case(p)), "deletion names {p}");
    }
    assert_eq!(check(&phone, &copy), PersonalKeyVerdict::OwnCopyMatches);
}

/// A key the server chose is never signed or adopted. A fresh device takes
/// the server's unsigned copy on trust; it then refuses to sign it by every
/// route, so no copy "signed by the account" can exist, and another device
/// refuses it unsigned or server-signed even with the record pointed at it.
/// The mark clears only when an own-signed copy of the SAME key arrives.
#[test]
fn a_server_chosen_key_is_never_signed_nor_adopted() {
    let alice = member(ALICE);
    let server_key = random_key();
    let fresh = same_account_device(&alice);
    let (ek, eph) = forge_wrap(&alice.sharing_b64, &server_key);
    fresh
        .store_circle_key(SELF_CIRCLE.into(), ek.clone(), eph.clone(), 1, ALICE.into(), ALICE.into(), None, None)
        .unwrap();
    let server_recorded = personal_pseudonym(&fresh, ALICE).unwrap();

    // Every signing route refuses.
    assert!(matches!(
        fresh.sign_own_circle_key_wrap(SELF_CIRCLE.into(), ALICE.into(), 1, ek.clone(), eph.clone()),
        Err(MobileError::InvalidInput(_))
    ));
    // Never even a publishable copy, signed or not.
    assert!(matches!(
        fresh.wrap_circle_key_for_member_full(SELF_CIRCLE.into(), String::new(), ALICE.into(), ALICE.into(), String::new()),
        Err(MobileError::InvalidInput(_))
    ));
    assert!(matches!(fresh.publishable_personal_key(SELF_CIRCLE.into(), ALICE.into()), Err(MobileError::InvalidInput(_))));
    let wrap = hex::decode(&ek).unwrap();
    assert!(matches!(
        fresh.sign_wrap(SignWrapParams {
            domain: "pingolin.sig.v1.circle_member_wrap".into(),
            sender_user_id: ALICE.into(),
            recipient_user_id: ALICE.into(),
            circle_id: SELF_CIRCLE.into(),
            place_id: String::new(),
            key_version: 1,
            ephemeral_pubkey_hex: eph.clone(),
            wrap_nonce_hex: hex::encode(&wrap[..24]),
            wrap_ciphertext_hex: hex::encode(&wrap[24..]),
        }),
        Err(MobileError::InvalidInput(_))
    ));

    // Another device refuses it every way the server can present it.
    let phone = same_account_device(&alice);
    mint_personal(&phone);
    let mine = personal_pseudonym(&phone, ALICE);
    let unsigned = (ek.clone(), eph.clone(), String::new(), server_recorded.clone());
    assert_eq!(check(&phone, &unsigned), PersonalKeyVerdict::Unsigned);
    assert_eq!(adopt(&phone, &unsigned), PersonalKeyVerdict::Unsigned);
    let server = member(SERVER_ACCT);
    mint_personal(&server.m);
    let server_signed = server
        .m
        .wrap_circle_key_for_member_full(SELF_CIRCLE.into(), String::new(), ALICE.into(), ALICE.into(), String::new())
        .unwrap();
    let server_signed = (wrap_hex(&server_signed), server_signed.ephemeral_public_key.clone(), server_signed.wrap_signature.clone(), server_recorded);
    assert!(!server_signed.2.is_empty());
    assert_eq!(adopt(&phone, &server_signed), PersonalKeyVerdict::SignatureInvalid);
    assert_eq!(personal_pseudonym(&phone, ALICE), mine, "nothing was stored");

    // The mark: a device that took the GENUINE key on trust signs it only
    // after an own-signed copy of that same key arrives.
    let genuine = served_personal_copy(&Member { m: phone.clone(), ..member(ALICE) });
    let late = same_account_device(&alice);
    late.store_circle_key(SELF_CIRCLE.into(), genuine.0.clone(), genuine.1.clone(), 1, ALICE.into(), ALICE.into(), None, None)
        .unwrap();
    assert!(late.sign_own_circle_key_wrap(SELF_CIRCLE.into(), ALICE.into(), 1, genuine.0.clone(), genuine.1.clone()).is_err());
    late.store_circle_key(SELF_CIRCLE.into(), genuine.0.clone(), genuine.1.clone(), 1, ALICE.into(), ALICE.into(), Some(genuine.2.clone()), None)
        .unwrap();
    assert!(late.sign_own_circle_key_wrap(SELF_CIRCLE.into(), ALICE.into(), 1, genuine.0.clone(), genuine.1.clone()).is_ok());
}

/// Two genuine keys (two devices that each minted one) and a record that
/// follows whoever sent last. Each device adopts at most once, never
/// takes back a key it retired, and still reads both keys' history.
#[test]
fn two_genuine_keys_do_not_flip_flop() {
    let a = member(ALICE);
    mint_personal(&a.m);
    let b = Member { m: same_account_device(&a), ..member(ALICE) };
    mint_personal(&b.m);
    let copy_a = served_personal_copy(&a);
    let copy_b = served_personal_copy(&Member { m: b.m.clone(), ..member(ALICE) });
    assert_ne!(copy_a.3, copy_b.3);
    let from_a = a.m.encrypt_data(SELF_CIRCLE.into(), "a's".into()).unwrap();
    let from_b = b.m.encrypt_data(SELF_CIRCLE.into(), "b's".into()).unwrap();

    // The record names A's key: B adopts it.
    assert_eq!(adopt(&b.m, &copy_a), PersonalKeyVerdict::Adopt);
    // It flips to B's: B does not take its retired key back...
    assert_eq!(adopt(&b.m, &copy_b), PersonalKeyVerdict::RetiredKey);
    // ...A adopts B's key once...
    assert_eq!(adopt(&a.m, &copy_b), PersonalKeyVerdict::Adopt);
    // ...and neither moves again, whichever way the record points.
    assert_eq!(adopt(&a.m, &copy_a), PersonalKeyVerdict::RetiredKey);
    assert_eq!(adopt(&a.m, &copy_b), PersonalKeyVerdict::OwnCopyMatches);
    assert_eq!(adopt(&b.m, &copy_a), PersonalKeyVerdict::OwnCopyMatches);
    assert_eq!(adopt(&b.m, &copy_b), PersonalKeyVerdict::RetiredKey);
    // A retired key served under some other record is refused as such too.
    let elsewhere = (copy_b.0.clone(), copy_b.1.clone(), copy_b.2.clone(), "ab".repeat(32));
    assert_eq!(check(&b.m, &elsewhere), PersonalKeyVerdict::RetiredKey);
    // Nothing was deleted: both devices read both keys' history.
    for dev in [&a.m, &b.m] {
        assert_eq!(dev.decrypt_data(SELF_CIRCLE.into(), from_a.clone()).unwrap(), "a's");
        assert_eq!(dev.decrypt_data(SELF_CIRCLE.into(), from_b.clone()).unwrap(), "b's");
    }
    // At most one adoption per 24 hours: a third genuine key has to wait.
    let c = Member { m: same_account_device(&a), ..member(ALICE) };
    mint_personal(&c.m);
    let copy_c = served_personal_copy(&c);
    assert_eq!(check(&b.m, &copy_c), PersonalKeyVerdict::TooSoon);
    assert_eq!(adopt(&b.m, &copy_c), PersonalKeyVerdict::TooSoon);
    let fresh = same_account_device(&a);
    hold_personal(&fresh, &a, SELF_CIRCLE, &random_key(), 1);
    assert_eq!(check(&fresh, &copy_c), PersonalKeyVerdict::Adopt, "a device that never adopted may");
}

/// (a) A copy held here that matches, in either personal slot, means
/// there is nothing to adopt, and the store path stores nothing.
#[test]
fn nothing_to_adopt_when_a_copy_here_matches() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    let phone = same_account_device(&alice);
    phone
        .store_circle_key(SELF_CIRCLE.into(), copy.0.clone(), copy.1.clone(), 1, ALICE.into(), ALICE.into(), Some(copy.2.clone()), None)
        .unwrap();
    assert_eq!(adopt(&phone, &copy), PersonalKeyVerdict::OwnCopyMatches);
    // Android's legacy "self" slot counts too.
    let android = same_account_device(&alice);
    android
        .store_circle_key("self".into(), copy.0.clone(), copy.1.clone(), 1, ALICE.into(), ALICE.into(), None, None)
        .unwrap();
    assert_eq!(check(&android, &copy), PersonalKeyVerdict::OwnCopyMatches);
    assert!(!android.has_circle_key(SELF_CIRCLE.into()), "and nothing was stored");
}

/// Every other refusal names its reason, and stores nothing.
#[test]
fn adoption_refusals_name_their_reason() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    let phone = same_account_device(&alice);
    hold_personal(&phone, &alice, SELF_CIRCLE, &random_key(), 1);
    let before = personal_pseudonym(&phone, ALICE);
    let with = |ek: &str, eph: &str, v: i32, sig: &str, rec: &str| {
        phone.check_personal_key_adoption(ALICE.into(), ek.into(), eph.into(), v, Some(sig.into()), rec.into())
    };
    let (ek, eph, sig, recorded) = copy.clone();

    assert_eq!(with(&ek, &eph, 1, &sig, ""), PersonalKeyVerdict::NothingRecorded);
    assert_eq!(with(&ek, &eph, 1, &sig, &"ab".repeat(32)), PersonalKeyVerdict::PseudonymMismatch);
    // A device without the account's signing key cannot check (c).
    let keyless = CryptoManager::new();
    keyless.import_private_key(alice.private_b64.clone()).unwrap();
    assert_eq!(check(&keyless, &copy), PersonalKeyVerdict::NoSigningKey);
    // Signed by the account's key, but wrapped to another identity of it.
    let other_identity = CryptoManager::new();
    other_identity.generate_keypair();
    other_identity.import_signing_private_key(alice.signing_seed_b64.clone()).unwrap();
    mint_personal(&other_identity);
    let elsewhere = served_personal_copy(&Member { m: other_identity.clone(), ..member(ALICE) });
    assert_eq!(check(&phone, &elsewhere), PersonalKeyVerdict::CannotOpen);
    // Malformed.
    assert_eq!(with(&ek, &eph, 0, &sig, &recorded), PersonalKeyVerdict::Malformed);
    assert_eq!(with(&ek, &eph, 1_000_001, &sig, &recorded), PersonalKeyVerdict::Malformed);
    assert_eq!(with("zz", &eph, 1, &sig, &recorded), PersonalKeyVerdict::Malformed);
    assert_eq!(with(&ek, "00", 1, &sig, &recorded), PersonalKeyVerdict::Malformed);
    // A tampered signature is not the account's.
    let mut bad = hex::decode(&sig).unwrap();
    bad[0] ^= 1;
    assert_eq!(with(&ek, &eph, 1, &hex::encode(bad), &recorded), PersonalKeyVerdict::SignatureInvalid);
    // A newer version held here would stay in use: refuse rather than half-adopt.
    let newer = same_account_device(&alice);
    hold_personal(&newer, &alice, SELF_CIRCLE, &random_key(), 2);
    assert_eq!(check(&newer, &copy), PersonalKeyVerdict::NewerVersionHeld);
    assert_eq!(adopt(&newer, &copy), PersonalKeyVerdict::NewerVersionHeld);
    assert_eq!(personal_pseudonym(&phone, ALICE), before, "nothing stored on refusals");
}

/// The store path re-runs the check: a second adoption of the same copy finds
/// the key already in use and stores nothing.
#[test]
fn the_adoption_store_path_re_runs_the_check() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    let phone = same_account_device(&alice);
    hold_personal(&phone, &alice, SELF_CIRCLE, &random_key(), 1);
    assert_eq!(check(&phone, &copy), PersonalKeyVerdict::Adopt);
    assert_eq!(adopt(&phone, &copy), PersonalKeyVerdict::Adopt);
    assert_eq!(adopt(&phone, &copy), PersonalKeyVerdict::OwnCopyMatches);
}

/// The only way to PUBLISH a personal key. The copy is signed for the nil
/// UUID and carries the pseudonym of exactly that key, and another device
/// of the account can adopt it. A key taken on trust, a missing signing key
/// and a non-personal id are refused.
#[test]
fn a_publishable_personal_key_carries_its_pseudonym() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let publ = alice.m.publishable_personal_key(SELF_CIRCLE.into(), ALICE.into()).unwrap();
    assert!(!publ.wrap_signature.is_empty());
    assert_eq!(publ.key_version, 1);
    assert_eq!(Some(publ.user_pseudonym.clone()), personal_pseudonym(&alice.m, ALICE));
    let as_served = |p: &pingolin_mobile::PublishablePersonalKey| {
        (format!("{}{}", p.encrypted_key.nonce, p.encrypted_key.ciphertext), p.ephemeral_public_key.clone(), p.wrap_signature.clone(), p.user_pseudonym.clone())
    };
    let phone = same_account_device(&alice);
    hold_personal(&phone, &alice, SELF_CIRCLE, &random_key(), 1);
    assert_eq!(adopt(&phone, &as_served(&publ)), PersonalKeyVerdict::Adopt);

    // Publish-before-install: a creation's key, still under its temp id.
    let other = same_account_device(&alice);
    let created = other.prepare_circle_creation().unwrap();
    let publ = other.publishable_personal_key(created.temp_circle_id.clone(), ALICE.into()).unwrap();
    let fresh = same_account_device(&alice);
    hold_personal(&fresh, &alice, SELF_CIRCLE, &random_key(), 1);
    assert_eq!(adopt(&fresh, &as_served(&publ)), PersonalKeyVerdict::Adopt);
    other.finalize_circle_creation(created.temp_circle_id, SELF_CIRCLE.into()).unwrap();
    let sealed = other.encrypt_data(SELF_CIRCLE.into(), "same key".into()).unwrap();
    assert_eq!(fresh.decrypt_data(SELF_CIRCLE.into(), sealed).unwrap(), "same key");

    // Refusals.
    let on_trust = same_account_device(&alice);
    hold_personal(&on_trust, &alice, SELF_CIRCLE, &random_key(), 1);
    assert!(matches!(on_trust.publishable_personal_key(SELF_CIRCLE.into(), ALICE.into()), Err(MobileError::InvalidInput(_))));
    let keyless = CryptoManager::new();
    keyless.import_private_key(alice.private_b64.clone()).unwrap();
    mint_personal(&keyless);
    assert!(matches!(keyless.publishable_personal_key(SELF_CIRCLE.into(), ALICE.into()), Err(MobileError::KeyNotFound(_))));
    assert!(matches!(alice.m.publishable_personal_key(CIRCLE.into(), ALICE.into()), Err(MobileError::InvalidInput(_))));
}

/// Slots are realigned on the device itself, which works for a key taken
/// on trust (the mark follows it) and retires, never drops, what the other
/// slot held.
#[test]
fn copy_personal_key_realigns_slots_locally() {
    let alice = member(ALICE);
    let dev = same_account_device(&alice);
    hold_personal(&dev, &alice, "self", &random_key(), 1);
    let under_self = dev.encrypt_data("self".into(), "a personal place".into()).unwrap();

    // The nil slot gets the account's key by adoption, then "self" is realigned.
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    assert_eq!(adopt(&dev, &copy), PersonalKeyVerdict::Adopt);
    dev.copy_personal_key(SELF_CIRCLE.into(), "self".into()).unwrap();
    assert_eq!(dev.derive_user_pseudonym("self".into(), ALICE.into()).unwrap(), copy.3, "both slots use it");
    assert_eq!(dev.decrypt_data("self".into(), under_self).unwrap(), "a personal place", "the old key is kept");
    dev.copy_personal_key(SELF_CIRCLE.into(), "self".into()).unwrap(); // idempotent

    // A key taken on trust can be copied, and stays unpublishable in both slots.
    let trusting = same_account_device(&alice);
    hold_personal(&trusting, &alice, SELF_CIRCLE, &random_key(), 1);
    trusting.copy_personal_key(SELF_CIRCLE.into(), "self".into()).unwrap();
    assert!(matches!(trusting.publishable_personal_key("self".into(), ALICE.into()), Err(MobileError::InvalidInput(_))));
    // Only between the two personal slots.
    assert!(matches!(trusting.copy_personal_key(SELF_CIRCLE.into(), SELF_CIRCLE.into()), Err(MobileError::InvalidInput(_))));
    assert!(matches!(trusting.copy_personal_key(SELF_CIRCLE.into(), CIRCLE.into()), Err(MobileError::InvalidInput(_))));
}

/// While a personal key is held, a DIFFERENT one comes in only through
/// adoption, including into the empty slot beside it.
#[test]
fn only_adoption_changes_the_personal_key_in_use() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    let copy = served_personal_copy(&alice);
    let dev = same_account_device(&alice);
    hold_personal(&dev, &alice, "self", &random_key(), 1);
    assert_refused(
        dev.store_circle_key(SELF_CIRCLE.into(), copy.0.clone(), copy.1.clone(), 1, ALICE.into(), ALICE.into(), Some(copy.2.clone()), None),
        "an own-signed different key into the empty slot",
    );
    assert!(!dev.has_circle_key(SELF_CIRCLE.into()));
    assert_eq!(adopt(&dev, &copy), PersonalKeyVerdict::Adopt);
    assert_eq!(personal_pseudonym(&dev, ALICE).as_deref(), Some(copy.3.as_str()));
}

/// The device whose key IS the recorded one learns what the published copy
/// is. Only CannotOpen and Unsigned may lead to a republish or a signature;
/// a copy replaced by a DIFFERENT genuine key is adoption's business and
/// must NOT make the holder republish.
#[test]
fn the_holder_checks_the_published_copy() {
    let holder = member(ALICE);
    mint_personal(&holder.m);
    let publ = holder.m.publishable_personal_key(SELF_CIRCLE.into(), ALICE.into()).unwrap();
    let wrap = format!("{}{}", publ.encrypted_key.nonce, publ.encrypted_key.ciphertext);
    let status = |dev: &CryptoManager, wrap: &str, eph: &str, sig: Option<String>| {
        dev.check_published_personal_copy(ALICE.into(), wrap.into(), eph.into(), 1, sig)
    };
    let eph = publ.ephemeral_public_key.clone();

    assert_eq!(status(&holder.m, &wrap, &eph, Some(publ.wrap_signature.clone())), PublishedCopyStatus::Opens);
    assert_eq!(status(&holder.m, &wrap, &eph, None), PublishedCopyStatus::Unsigned);
    let mut bad = hex::decode(&publ.wrap_signature).unwrap();
    bad[0] ^= 1;
    assert_eq!(status(&holder.m, &wrap, &eph, Some(hex::encode(bad))), PublishedCopyStatus::Unsigned);

    // The server's copy replaced by ANOTHER genuine key of the account.
    let other = Member { m: same_account_device(&holder), ..member(ALICE) };
    mint_personal(&other.m);
    let theirs = served_personal_copy(&other);
    assert_eq!(status(&holder.m, &theirs.0, &theirs.1, Some(theirs.2.clone())), PublishedCopyStatus::OpensToDifferentKey);

    // Copies that do not open with the account's current keys.
    let other_identity = CryptoManager::new();
    other_identity.generate_keypair();
    other_identity.import_signing_private_key(holder.signing_seed_b64.clone()).unwrap();
    mint_personal(&other_identity);
    let elsewhere = served_personal_copy(&Member { m: other_identity.clone(), ..member(ALICE) });
    assert_eq!(status(&holder.m, &elsewhere.0, &elsewhere.1, Some(elsewhere.2.clone())), PublishedCopyStatus::CannotOpen);
    let mut corrupt = hex::decode(&wrap).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert_eq!(status(&holder.m, &hex::encode(corrupt), &eph, Some(publ.wrap_signature.clone())), PublishedCopyStatus::CannotOpen);

    // The rest.
    let empty = same_account_device(&holder);
    assert_eq!(status(&empty, &wrap, &eph, Some(publ.wrap_signature.clone())), PublishedCopyStatus::NoKeyHere);
    let keyless = CryptoManager::new();
    keyless.import_private_key(holder.private_b64.clone()).unwrap();
    keyless.store_circle_key(SELF_CIRCLE.into(), wrap.clone(), eph.clone(), 1, ALICE.into(), ALICE.into(), None, None).unwrap();
    assert_eq!(status(&keyless, &wrap, &eph, Some(publ.wrap_signature.clone())), PublishedCopyStatus::NoSigningKey);
    assert_eq!(status(&holder.m, "zz", &eph, None), PublishedCopyStatus::Malformed);
    assert_eq!(holder.m.check_published_personal_copy(ALICE.into(), wrap.clone(), eph.clone(), 0, None), PublishedCopyStatus::Malformed);
}

/// Apps can tell a key taken on trust up front, and skip republishing it.
#[test]
fn a_personal_key_taken_on_trust_is_visible() {
    let alice = member(ALICE);
    mint_personal(&alice.m);
    assert!(!alice.m.personal_key_taken_on_trust(), "a minted key");
    let copy = served_personal_copy(&alice);
    let late = same_account_device(&alice);
    assert!(!late.personal_key_taken_on_trust(), "no personal key at all");
    late.store_circle_key(SELF_CIRCLE.into(), copy.0.clone(), copy.1.clone(), 1, ALICE.into(), ALICE.into(), None, None).unwrap();
    assert!(late.personal_key_taken_on_trust(), "taken unsigned");
    late.store_circle_key(SELF_CIRCLE.into(), copy.0.clone(), copy.1.clone(), 1, ALICE.into(), ALICE.into(), Some(copy.2.clone()), None).unwrap();
    assert!(!late.personal_key_taken_on_trust(), "cleared by the account's own signed copy");
}

