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

//! Signed membership statements.
//!
//! A circle member is someone an owner/admin invited, or someone a member
//! vouched for — but the server decides who is on a circle's member list, and
//! without these statements nothing a client receives could tell a real
//! invitation from a row the server added on its own. A statement is signed on
//! the signer's device with their identity (Ed25519) signing key, stored and
//! relayed by the server, and verified by every other member's device against
//! the signer's PINNED key. Kinds:
//!
//!   1  invitation to an EXISTING account — binds the invitee's user id and the
//!      exact sharing + signing keys the inviter saw, so the server cannot swap
//!      the newcomer's keys for other members' deliveries;
//!   2  invitation to an email with no account yet — binds the normalized email;
//!   3  admission — an owner/admin confirms that this account, with these keys,
//!      belongs in the circle (legacy members, the backfill, promotion to admin).
//!
//! Every statement also carries `at_version`, the signer's active circle-key
//! version when signing, so a device can tell a statement made before a member
//! was removed from one made after.
//!
//! CANONICAL ENCODING (format 2). Fixed-width fields; the email is the only
//! variable field and carries a u8 length prefix, as the wrap-signature input
//! does for its variable fields. UUIDs are their 16 RFC 4122 bytes (the same
//! bytes `compute_sig_input` uses); integers are little-endian.
//!
//! ```text
//!   [0]        u8      format version = 2
//!   [1]        u8      kind: 1 | 2 | 3
//!   [2..18]    16      circle_id
//!   [18..34]   16      statement_id (random, single use)
//!   [34..50]   16      signer_user_id
//!   [50..58]   u64 LE  issued_at (unix seconds, > 0)
//!   [58..66]   u64 LE  expires_at (kinds 1/2: issued_at + 604800; kind 3: 0)
//!   [66..70]   u32 LE  at_version, 1..=1_000_000
//!   kinds 1, 3:
//!   [70..86]   16      subject_user_id
//!   [86..118]  32      subject X25519 sharing public key
//!   [118..150] 32      subject Ed25519 signing public key       (150 bytes total)
//!   kind 2:
//!   [70]       u8      L = email length, 1..=254
//!   [71..71+L] L       normalized email, ASCII                  (71 + L bytes total)
//! ```
//!
//! Format 1 (the same without `at_version`) is not accepted; the version byte
//! makes a decoder of either format refuse the other outright instead of
//! reading `at_version` as an email length.
//!
//! The signature is Ed25519 over the 32-byte
//! `BLAKE3_keyed(derive_key("pingolin.sig.v1.context_key", DOMAIN), statement)`,
//! the same construction as the wrap signatures, with a domain of its own —
//! a statement signature can never be taken for a wrap signature or back.
//! Parsing is strict: a wrong version or kind, a length that does not match
//! the kind, trailing bytes, an expiry that breaks the kind's rule, or a
//! non-canonical email are errors, never a best-effort read.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::crypto::CryptoManager;
use crate::types::MobileError;

/// Domain separator of membership statements (distinct from every
/// `pingolin.sig.v1.*_wrap` domain).
pub const MEMBERSHIP_STATEMENT_DOMAIN: &str = "pingolin.sig.v1.circle_membership_statement";
/// Context of the keyed-hash key derivation shared with the wrap signatures.
const SIG_CONTEXT: &str = "pingolin.sig.v1.context_key";
const FORMAT_VERSION: u8 = 2;
/// An invitation is valid for 7 days, matching the server's invitation expiry.
pub const INVITATION_LIFETIME_SECS: i64 = 7 * 24 * 60 * 60;
/// The bound `store_circle_key` puts on a circle-key version.
const MAX_AT_VERSION: i32 = 1_000_000;
const HEADER_LEN: usize = 70;
const SUBJECT_KEYS_LEN: usize = 16 + 32 + 32;
const MAX_EMAIL_LEN: usize = 254;

/// What a membership statement says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MembershipStatementKind {
    /// Wire code 1: an owner/admin invites an existing account (bound to its keys).
    InvitationToAccount,
    /// Wire code 2: an owner/admin invites an email address that has no account yet.
    InvitationToEmail,
    /// Wire code 3: an owner/admin admits this account, with these keys, into the circle.
    Admission,
}

impl MembershipStatementKind {
    fn code(self) -> u8 {
        match self {
            MembershipStatementKind::InvitationToAccount => 1,
            MembershipStatementKind::InvitationToEmail => 2,
            MembershipStatementKind::Admission => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(MembershipStatementKind::InvitationToAccount),
            2 => Some(MembershipStatementKind::InvitationToEmail),
            3 => Some(MembershipStatementKind::Admission),
            _ => None,
        }
    }
}

/// The fields of a membership statement. Kinds 1 and 3 carry the three
/// `subject_*` identity fields and no email; kind 2 carries `subject_email`
/// only. Ids are lower-case hyphenated UUIDs, keys lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MembershipStatement {
    pub kind: MembershipStatementKind,
    pub circle_id: String,
    /// Single-use identity of the statement (16 random bytes, as a UUID string).
    pub statement_id: String,
    pub signer_user_id: String,
    /// Unix seconds.
    pub issued_at: i64,
    /// Unix seconds; invitations: `issued_at + 604800`; admissions: 0 (never).
    pub expires_at: i64,
    /// The signer's active circle-key version when signing, 1..=1_000_000.
    pub at_version: i32,
    pub subject_user_id: Option<String>,
    /// The subject's X25519 sharing public key, 64 hex chars.
    pub subject_sharing_public_key_hex: Option<String>,
    /// The subject's Ed25519 signing public key, 64 hex chars.
    pub subject_signing_public_key_hex: Option<String>,
    /// Kind 2 only: the invitee's normalized (trimmed, lower-case, ASCII) email.
    pub subject_email: Option<String>,
}

/// A statement as it travels: the canonical bytes, the signature, and the
/// fields they encode (normalized).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedMembershipStatement {
    /// The canonical statement bytes, hex.
    pub statement_hex: String,
    /// Ed25519 signature (64 bytes), hex.
    pub signature_hex: String,
    pub statement: MembershipStatement,
}

/// Which of this account's signing keys a statement it signed verifies under
/// (see `verify_own_membership_statement`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OwnStatementSigner {
    /// This account's CURRENT signing key.
    CurrentKey,
    /// Only the signing key of an identity from before a password reset,
    /// restored on this device from the portal's v2 blob. It confirms like any
    /// statement, but never makes anyone "chosen" here: only a statement under
    /// the current key is this device's own action.
    PreviousKey,
    /// Neither.
    NotOurs,
}

/// What the app knows about the circle NOW, for `renew_invitation`. The SDK
/// renews only when these say it may.
#[derive(Debug, Clone, uniffi::Record)]
pub struct InvitationRenewalFacts {
    /// The ORIGINAL signer is an owner or admin NOW (it created the circle on
    /// this device, else the circle list's role) and has not departed, been
    /// removed or been tombstoned on this device. A signer who left still
    /// verifies (their identity pin is kept), so this is what refuses them.
    pub original_signer_is_owner_or_admin_now: bool,
    /// The renewer (this account) is an owner or admin NOW: it created the
    /// circle on this device, else the circle list's role. A kind-3 admission
    /// proves "admitted", not "admin".
    pub renewer_is_owner_or_admin: bool,
    /// The subject has left or was removed, or is tombstoned on this device.
    pub subject_departed_or_tombstoned: bool,
    /// The invitation was withdrawn, or its id is tombstoned or otherwise dead
    /// on this device.
    pub invitation_withdrawn_or_dead: bool,
}

fn invalid(what: impl Into<String>) -> MobileError {
    MobileError::InvalidInput(what.into())
}

fn uuid_bytes(field: &str, value: &str) -> Result<[u8; 16], MobileError> {
    uuid::Uuid::parse_str(value)
        .map(|u| *u.as_bytes())
        .map_err(|_| invalid(format!("{field} is not a UUID")))
}

fn uuid_string(bytes: &[u8]) -> String {
    let mut array = [0u8; 16];
    array.copy_from_slice(bytes);
    uuid::Uuid::from_bytes(array).hyphenated().to_string()
}

fn key_bytes(field: &str, hex_value: &str) -> Result<[u8; 32], MobileError> {
    let bytes = hex::decode(hex_value).map_err(|_| invalid(format!("{field} is not hex")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| invalid(format!("{field} must be 32 bytes")))
}

/// The server's normalization of an invitation email (trim, lower-case, then
/// refuse non-ASCII), made byte-identical across implementations by refusing
/// non-ASCII input BEFORE trimming: for ASCII text Rust's `trim()` and
/// JavaScript's `trim()` remove the same six characters (tab, LF, VT, FF, CR,
/// space).
pub fn normalize_invitation_email(raw: &str) -> Result<String, MobileError> {
    if !raw.is_ascii() {
        return Err(invalid("email must be ASCII"));
    }
    let email = raw.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > MAX_EMAIL_LEN || !email.contains('@') {
        return Err(invalid("not a usable email address"));
    }
    Ok(email)
}

fn check_expiry(kind: MembershipStatementKind, issued_at: i64, expires_at: i64) -> Result<(), MobileError> {
    if issued_at <= 0 {
        return Err(invalid("issued_at must be positive"));
    }
    let expected = match kind {
        MembershipStatementKind::Admission => 0,
        _ => issued_at
            .checked_add(INVITATION_LIFETIME_SECS)
            .ok_or_else(|| invalid("issued_at out of range"))?,
    };
    if expires_at != expected {
        return Err(invalid(format!(
            "expires_at must be {expected} for this kind (issued_at {issued_at})"
        )));
    }
    Ok(())
}

fn check_at_version(at_version: i64) -> Result<i32, MobileError> {
    i32::try_from(at_version)
        .ok()
        .filter(|v| (1..=MAX_AT_VERSION).contains(v))
        .ok_or_else(|| invalid(format!("at_version must be 1..={MAX_AT_VERSION}")))
}

/// Validate `statement` and produce its canonical bytes, plus the statement as
/// those bytes read back (normalized ids, keys and email).
pub(crate) fn encode_statement(
    statement: &MembershipStatement,
) -> Result<(Vec<u8>, MembershipStatement), MobileError> {
    check_expiry(statement.kind, statement.issued_at, statement.expires_at)?;
    let at_version = check_at_version(i64::from(statement.at_version))?;
    let mut out = Vec::with_capacity(HEADER_LEN + SUBJECT_KEYS_LEN);
    out.push(FORMAT_VERSION);
    out.push(statement.kind.code());
    out.extend_from_slice(&uuid_bytes("circle_id", &statement.circle_id)?);
    out.extend_from_slice(&uuid_bytes("statement_id", &statement.statement_id)?);
    out.extend_from_slice(&uuid_bytes("signer_user_id", &statement.signer_user_id)?);
    out.extend_from_slice(&(statement.issued_at as u64).to_le_bytes());
    out.extend_from_slice(&(statement.expires_at as u64).to_le_bytes());
    out.extend_from_slice(&(at_version as u32).to_le_bytes());
    match statement.kind {
        MembershipStatementKind::InvitationToEmail => {
            if statement.subject_user_id.is_some()
                || statement.subject_sharing_public_key_hex.is_some()
                || statement.subject_signing_public_key_hex.is_some()
            {
                return Err(invalid("an email invitation carries no subject account or keys"));
            }
            let raw = statement
                .subject_email
                .as_deref()
                .ok_or_else(|| invalid("an email invitation needs subject_email"))?;
            let email = normalize_invitation_email(raw)?;
            out.push(email.len() as u8);
            out.extend_from_slice(email.as_bytes());
        }
        _ => {
            if statement.subject_email.is_some() {
                return Err(invalid("this kind carries no email"));
            }
            let missing = || invalid("this kind needs subject_user_id and both subject keys");
            out.extend_from_slice(&uuid_bytes(
                "subject_user_id",
                statement.subject_user_id.as_deref().ok_or_else(missing)?,
            )?);
            out.extend_from_slice(&key_bytes(
                "subject_sharing_public_key_hex",
                statement.subject_sharing_public_key_hex.as_deref().ok_or_else(missing)?,
            )?);
            out.extend_from_slice(&key_bytes(
                "subject_signing_public_key_hex",
                statement.subject_signing_public_key_hex.as_deref().ok_or_else(missing)?,
            )?);
        }
    }
    let normalized = decode_statement(&out)?;
    Ok((out, normalized))
}

/// Strictly read canonical statement bytes back into their fields.
pub(crate) fn decode_statement(bytes: &[u8]) -> Result<MembershipStatement, MobileError> {
    if bytes.len() < HEADER_LEN + 1 {
        return Err(invalid("membership statement too short"));
    }
    if bytes[0] != FORMAT_VERSION {
        return Err(invalid(format!("unknown membership statement format {}", bytes[0])));
    }
    let kind = MembershipStatementKind::from_code(bytes[1])
        .ok_or_else(|| invalid(format!("unknown membership statement kind {}", bytes[1])))?;
    let read_u64 = |at: usize| {
        let mut le = [0u8; 8];
        le.copy_from_slice(&bytes[at..at + 8]);
        i64::try_from(u64::from_le_bytes(le)).map_err(|_| invalid("timestamp out of range"))
    };
    let issued_at = read_u64(50)?;
    let expires_at = read_u64(58)?;
    check_expiry(kind, issued_at, expires_at)?;
    let mut le = [0u8; 4];
    le.copy_from_slice(&bytes[66..70]);
    let at_version = check_at_version(i64::from(u32::from_le_bytes(le)))?;

    let mut statement = MembershipStatement {
        kind,
        circle_id: uuid_string(&bytes[2..18]),
        statement_id: uuid_string(&bytes[18..34]),
        signer_user_id: uuid_string(&bytes[34..50]),
        issued_at,
        expires_at,
        at_version,
        subject_user_id: None,
        subject_sharing_public_key_hex: None,
        subject_signing_public_key_hex: None,
        subject_email: None,
    };
    match kind {
        MembershipStatementKind::InvitationToEmail => {
            let len = bytes[HEADER_LEN] as usize;
            if len == 0 || len > MAX_EMAIL_LEN || bytes.len() != HEADER_LEN + 1 + len {
                return Err(invalid("email length does not match the statement"));
            }
            let email = std::str::from_utf8(&bytes[HEADER_LEN + 1..])
                .map_err(|_| invalid("email is not ASCII"))?;
            if normalize_invitation_email(email)? != email {
                return Err(invalid("email is not in canonical form"));
            }
            statement.subject_email = Some(email.to_string());
        }
        _ => {
            if bytes.len() != HEADER_LEN + SUBJECT_KEYS_LEN {
                return Err(invalid("statement length does not match its kind"));
            }
            statement.subject_user_id = Some(uuid_string(&bytes[70..86]));
            statement.subject_sharing_public_key_hex = Some(hex::encode(&bytes[86..118]));
            statement.subject_signing_public_key_hex = Some(hex::encode(&bytes[118..150]));
        }
    }
    Ok(statement)
}

/// The 32 bytes the signer's Ed25519 key signs.
pub(crate) fn statement_digest(bytes: &[u8]) -> [u8; 32] {
    let context_key = blake3::derive_key(SIG_CONTEXT, MEMBERSHIP_STATEMENT_DOMAIN.as_bytes());
    *blake3::keyed_hash(&context_key, bytes).as_bytes()
}

fn now_unix_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[uniffi::export]
impl CryptoManager {
    /// Sign an explicit membership statement with this account's signing key.
    /// Every field is the caller's; the kind-specific signers below fill the
    /// statement id, the times and `at_version` for you. Returns the canonical
    /// bytes, the signature and the normalized fields.
    pub fn sign_membership_statement(
        &self,
        statement: MembershipStatement,
    ) -> Result<SignedMembershipStatement, MobileError> {
        // A personal key slot is no circle: this account's signature never
        // names anyone into one, where it would confirm them for every member.
        // The kind signers and renewals all sign here.
        if crate::crypto::names_a_personal_slot(&statement.circle_id) {
            return Err(invalid("a personal key slot is no circle: no statement names it"));
        }
        let (bytes, normalized) = encode_statement(&statement)?;
        let signature = self.sign_with_identity_key(&statement_digest(&bytes))?;
        Ok(SignedMembershipStatement {
            statement_hex: hex::encode(&bytes),
            signature_hex: hex::encode(signature),
            statement: normalized,
        })
    }

    /// Kind 1: invite the existing account `subject_user_id`, bound to the keys
    /// this device looked up for it. Valid 7 days from now; a fresh random
    /// statement id; `at_version` = this device's active version for the
    /// circle (`KeyNotFound` when it holds no key for it).
    pub fn sign_invitation_to_account(
        &self,
        circle_id: String,
        signer_user_id: String,
        subject_user_id: String,
        subject_sharing_public_key_hex: String,
        subject_signing_public_key_hex: String,
    ) -> Result<SignedMembershipStatement, MobileError> {
        let at_version = self.get_active_version(circle_id.clone())?;
        let issued_at = now_unix_secs();
        self.sign_membership_statement(MembershipStatement {
            kind: MembershipStatementKind::InvitationToAccount,
            circle_id,
            statement_id: uuid::Uuid::new_v4().to_string(),
            signer_user_id,
            issued_at,
            expires_at: issued_at + INVITATION_LIFETIME_SECS,
            at_version,
            subject_user_id: Some(subject_user_id),
            subject_sharing_public_key_hex: Some(subject_sharing_public_key_hex),
            subject_signing_public_key_hex: Some(subject_signing_public_key_hex),
            subject_email: None,
        })
    }

    /// Kind 2: invite an email address that has no account yet. The email is
    /// normalized (trimmed, lower-case; non-ASCII refused). Valid 7 days;
    /// `at_version` as for kind 1.
    pub fn sign_invitation_to_email(
        &self,
        circle_id: String,
        signer_user_id: String,
        email: String,
    ) -> Result<SignedMembershipStatement, MobileError> {
        let at_version = self.get_active_version(circle_id.clone())?;
        let issued_at = now_unix_secs();
        self.sign_membership_statement(MembershipStatement {
            kind: MembershipStatementKind::InvitationToEmail,
            circle_id,
            statement_id: uuid::Uuid::new_v4().to_string(),
            signer_user_id,
            issued_at,
            expires_at: issued_at + INVITATION_LIFETIME_SECS,
            at_version,
            subject_user_id: None,
            subject_sharing_public_key_hex: None,
            subject_signing_public_key_hex: None,
            subject_email: Some(email),
        })
    }

    /// Kind 3 (owner/admin devices): admit `subject_user_id`, with exactly
    /// these keys, into the circle. Never expires; `at_version` as for kind 1.
    pub fn sign_membership_admission(
        &self,
        circle_id: String,
        signer_user_id: String,
        subject_user_id: String,
        subject_sharing_public_key_hex: String,
        subject_signing_public_key_hex: String,
    ) -> Result<SignedMembershipStatement, MobileError> {
        let at_version = self.get_active_version(circle_id.clone())?;
        self.sign_membership_statement(MembershipStatement {
            kind: MembershipStatementKind::Admission,
            circle_id,
            statement_id: uuid::Uuid::new_v4().to_string(),
            signer_user_id,
            issued_at: now_unix_secs(),
            expires_at: 0,
            at_version,
            subject_user_id: Some(subject_user_id),
            subject_sharing_public_key_hex: Some(subject_sharing_public_key_hex),
            subject_signing_public_key_hex: Some(subject_signing_public_key_hex),
            subject_email: None,
        })
    }

    /// Verify a statement THIS account signed: under its current signing key,
    /// else under a restored identity's signing key from the portal's v2 blob.
    /// Says which; `Err` for a malformed statement or signature, like
    /// `verify_membership_statement`.
    pub fn verify_own_membership_statement(
        &self,
        statement_hex: String,
        signature_hex: String,
    ) -> Result<OwnStatementSigner, MobileError> {
        if let Ok(own) = self.signing_public_key_hex() {
            if self.verify_membership_statement(statement_hex.clone(), signature_hex.clone(), own)? {
                return Ok(OwnStatementSigner::CurrentKey);
            }
        }
        for key in self.previous_signing_public_keys() {
            if self.verify_membership_statement(statement_hex.clone(), signature_hex.clone(), key)? {
                return Ok(OwnStatementSigner::PreviousKey);
            }
        }
        Ok(OwnStatementSigner::NotOurs)
    }

    /// Verify a statement's signature under `signer_signing_public_key_hex` —
    /// pass the signer's PINNED key, never a key the server supplied next to
    /// the statement. `Ok(true)` valid, `Ok(false)` a well-formed statement
    /// whose signature does not verify, `Err` a malformed statement, signature
    /// or key. Expiry is not checked here: an accepted invitation stays the
    /// member's proof after its 7 days; the server refuses expired accepts.
    pub fn verify_membership_statement(
        &self,
        statement_hex: String,
        signature_hex: String,
        signer_signing_public_key_hex: String,
    ) -> Result<bool, MobileError> {
        let bytes = hex::decode(&statement_hex).map_err(|_| invalid("statement is not hex"))?;
        decode_statement(&bytes)?;
        let key = key_bytes("signer_signing_public_key_hex", &signer_signing_public_key_hex)?;
        let verifying_key = VerifyingKey::from_bytes(&key).map_err(|_| MobileError::InvalidKey)?;
        let signature = hex::decode(&signature_hex).map_err(|_| invalid("signature is not hex"))?;
        let signature = <[u8; 64]>::try_from(signature.as_slice())
            .map_err(|_| invalid("signature must be 64 bytes"))?;
        Ok(verifying_key
            .verify_strict(&statement_digest(&bytes), &Signature::from_bytes(&signature))
            .is_ok())
    }

    /// Read a statement's fields without verifying it (e.g. to find which pin
    /// to verify it under). Strict: malformed bytes are an error.
    pub fn parse_membership_statement(
        &self,
        statement_hex: String,
    ) -> Result<MembershipStatement, MobileError> {
        let bytes = hex::decode(&statement_hex).map_err(|_| invalid("statement is not hex"))?;
        decode_statement(&bytes)
    }

    /// Renew a pending invitation to an account after this device's user
    /// answered "Is this really {email}?" with "It's them": the ONLY re-sign
    /// there is. It binds `new_subject_*` (the keys the question showed) at
    /// this device's active version, signed by `renewer_user_id`. The
    /// statement id, times and subject user id are copied from the ORIGINAL,
    /// which must first verify under its signer's PINNED key (ours, if the
    /// signer is us), be a kind-1 invitation for `circle_id`, be unexpired and
    /// not newer than this device's version, and `facts` must say the original
    /// signer and the renewer are owners or admins NOW and nothing is
    /// withdrawn, tombstoned or departed. The keys must change: a version-only
    /// re-sign is refused. An address invitation is never renewed.
    #[allow(clippy::too_many_arguments)]
    pub fn renew_invitation(
        &self,
        circle_id: String,
        renewer_user_id: String,
        original_statement_hex: String,
        original_signature_hex: String,
        new_subject_sharing_public_key_hex: String,
        new_subject_signing_public_key_hex: String,
        facts: InvitationRenewalFacts,
    ) -> Result<SignedMembershipStatement, MobileError> {
        let bytes = hex::decode(&original_statement_hex).map_err(|_| invalid("statement is not hex"))?;
        let original = decode_statement(&bytes)?;
        match original.kind {
            MembershipStatementKind::InvitationToAccount => {}
            // An address invitation's account accepts it as it is; turning it into
            // an invitation to an account would bind keys the server chose.
            MembershipStatementKind::InvitationToEmail => {
                return Err(invalid("address invitations are never renewed"));
            }
            MembershipStatementKind::Admission => return Err(invalid("only an invitation is renewed")),
        }
        if uuid_bytes("circle_id", &circle_id)? != uuid_bytes("circle_id", &original.circle_id)? {
            return Err(invalid("the invitation is for another circle"));
        }
        let signer_keys = if uuid_bytes("renewer_user_id", &renewer_user_id)?
            == uuid_bytes("signer_user_id", &original.signer_user_id)?
        {
            // Ours: our current key, or one of ours from before a password reset,
            // bound by the portal to an identity this device holds.
            let mut keys = vec![self.signing_public_key_hex()?];
            keys.extend(self.previous_signing_public_keys());
            keys
        } else {
            vec![self
                .pinned_signing_key(circle_id.clone(), original.signer_user_id.clone())
                .ok_or_else(|| MobileError::KeyNotFound("the original signer is not pinned on this device".to_string()))?]
        };
        let mut verified = false;
        for key in signer_keys {
            if self.verify_membership_statement(original_statement_hex.clone(), original_signature_hex.clone(), key)? {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(MobileError::SignatureInvalid);
        }
        if !facts.original_signer_is_owner_or_admin_now {
            return Err(invalid("the original signer is no longer an owner or admin"));
        }
        if !facts.renewer_is_owner_or_admin {
            return Err(invalid("the renewer is not an owner or admin"));
        }
        if facts.subject_departed_or_tombstoned {
            return Err(invalid("the invitation's subject has left, was removed or is tombstoned"));
        }
        if facts.invitation_withdrawn_or_dead {
            return Err(invalid("the invitation was withdrawn or its id is dead"));
        }
        if now_unix_secs() >= original.expires_at {
            return Err(invalid("the invitation has expired"));
        }
        let new_sharing = hex::encode(key_bytes("new_subject_sharing_public_key_hex", &new_subject_sharing_public_key_hex)?);
        let new_signing = hex::encode(key_bytes("new_subject_signing_public_key_hex", &new_subject_signing_public_key_hex)?);
        if original.subject_sharing_public_key_hex.as_deref() == Some(new_sharing.as_str())
            && original.subject_signing_public_key_hex.as_deref() == Some(new_signing.as_str())
        {
            return Err(invalid("the keys did not change: a version-only re-sign is not allowed"));
        }
        let active = self.get_active_version(circle_id)?;
        if active < original.at_version {
            return Err(invalid("this device is behind the invitation's version"));
        }
        self.sign_membership_statement(MembershipStatement {
            at_version: active,
            signer_user_id: renewer_user_id,
            subject_sharing_public_key_hex: Some(new_sharing),
            subject_signing_public_key_hex: Some(new_signing),
            ..original
        })
    }
}
