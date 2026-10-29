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

//! `recipient_user_id` is part of the wrap signature, and a wrap signed without
//! it can never verify.
//!
//! Every verifier — `store_circle_key` included — reconstructs the message with
//! the CONCRETE recipient id, so a wrap signed with `recipient_user_id = ""`
//! can never verify. Any invitee who had already pinned that sender (i.e.
//! anyone REJOINING a circle) would silently refuse every such wrap, freeze on
//! the circle key version they last held, and see the circle as locked for
//! good.
//!
//! These run with the crate's ordinary tests (no `#[ignore]`, no network, no
//! fixtures) so the claim is checked rather than remembered.

use pingolin_mobile::CryptoManager;
use pingolin_mobile::SignWrapParams;

const DOMAIN: &str = "pingolin.sig.v1.circle_member_wrap";
const SENDER: &str = "11111111-1111-1111-1111-111111111111";
const RECIPIENT: &str = "22222222-2222-2222-2222-222222222222";
const CIRCLE: &str = "33333333-3333-3333-3333-333333333333";

fn params(recipient: &str) -> SignWrapParams {
    SignWrapParams {
        domain: DOMAIN.to_string(),
        sender_user_id: SENDER.to_string(),
        recipient_user_id: recipient.to_string(),
        circle_id: CIRCLE.to_string(),
        place_id: String::new(),
        key_version: 7,
        // Shapes the layout requires: 32 / 24 / 48 bytes.
        ephemeral_pubkey_hex: "aa".repeat(32),
        wrap_nonce_hex: "bb".repeat(24),
        wrap_ciphertext_hex: "cc".repeat(48),
    }
}

/// A manager with a signing key loaded, plus its public key as hex.
fn signer() -> (std::sync::Arc<CryptoManager>, String) {
    let cm = CryptoManager::new();
    let kp = cm.generate_signing_keypair();
    cm.import_signing_private_key(kp.secret_seed_b64.clone())
        .expect("import signing key");
    let pubkey = cm.signing_public_key_hex().expect("signing public key");
    (cm, pubkey)
}

/// The control: bound at signing, bound at verifying — verifies.
#[test]
fn a_wrap_signed_with_the_recipient_bound_verifies() {
    let (cm, pubkey) = signer();
    let sig = cm.sign_wrap(params(RECIPIENT)).expect("sign");
    assert!(
        cm.verify_wrap(pubkey, sig, params(RECIPIENT)).expect("verify"),
        "a correctly bound wrap must verify — if this fails the whole scheme is broken, \
         not just the binding"
    );
}

/// Empty at signing, concrete at verifying — cannot verify.
///
/// It is asserted as a FAILURE so that anyone tempted to "fix" a verification
/// problem by passing "" sees immediately that it produces a signature nobody
/// can check.
#[test]
fn a_wrap_signed_without_the_recipient_can_never_verify() {
    let (cm, pubkey) = signer();
    let sig = cm.sign_wrap(params("")).expect("sign with empty recipient");
    assert!(
        !cm.verify_wrap(pubkey, sig, params(RECIPIENT)).expect("verify"),
        "a wrap signed with recipient=\"\" verified against a concrete recipient. \
         If that ever becomes true the binding is gone and a wrap can be replayed \
         at a different member."
    );
}

/// And the binding is to THAT recipient, not merely to non-emptiness — otherwise
/// a wrap for one member could be replayed at another.
#[test]
fn a_wrap_is_bound_to_one_recipient_not_just_any() {
    let (cm, pubkey) = signer();
    let sig = cm.sign_wrap(params(RECIPIENT)).expect("sign");
    let someone_else = "44444444-4444-4444-4444-444444444444";
    assert!(
        !cm.verify_wrap(pubkey, sig, params(someone_else)).expect("verify"),
        "a wrap signed for one member verified for another — the recipient binding \
         is not actually binding"
    );
}
