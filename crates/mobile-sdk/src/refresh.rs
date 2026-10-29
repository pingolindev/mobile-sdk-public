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

//! Refresh records on this device: what it knows of each circle's chain, the
//! two checks it makes on every record (R1 and R2), and the one eligibility
//! rule E that decides who may get a circle key.
//!
//! - R1: the record fits the chain this device holds (the format's rules, and
//!   the link to the record before it), and its signature verifies under the
//!   key of a member this device confirms. A record must also keep to the role
//!   and removal rules (`check_authority`).
//! - R2: everyone the record includes is a member this device confirms whom E
//!   allows here.
//! - E: (a) the chain counts them here, with exactly these keys; (b) an
//!   admission or (c) an invitation signed by an owner or admin in the chain;
//!   (d), for a delivery only, the chain names them and this device's person
//!   confirmed their changed keys.
//!
//! The byte format is in `refresh_record.rs`. Here:
//! - the per-circle state: the head this device accepted, the version it may
//!   seal under, and one fact per member code (the last record that named it:
//!   version, state, role, commitment), persisted as reserved PinRecord-shaped
//!   entries in the pins blob;
//! - the circle's secret S, from the key of the circle's anchor A (a genesis's
//!   own version, or the version before a transition), which must verify the
//!   circle's first record first. It is derived from the key this device holds
//!   for A or by walking the key chain down to it, and stored with the circle
//!   keys under `~rrs:{circle}`, never in the pins blob and never returned to
//!   the apps;
//! - R1, R2 and E, as pure functions of that state and of what the app
//!   confirms (confirmation, statements, the complete member list stay the
//!   apps').
//!
//! Nothing in this module touches S from an exported function: the exported
//! surface is the thin `#[uniffi::export]` block at the end of this file, and
//! it only calls the plain `impl CryptoManager` glue above it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::membership::{decode_statement, statement_digest, MembershipStatement, MembershipStatementKind};
use crate::refresh_record::{
    anchor_tag, circle_secret, key_commitment, key_tag, member_code, ChainRole, EntryState, RecordBody, RecordFormat,
    RecordKind, WireRecord,
};
use crate::crypto::CircleKey;
use crate::types::{KeyChainLinkData, MobileError, PinRecord};

/// The grace an invitation keeps after it expires, in seconds.
const INVITATION_EXPIRY_GRACE_SECS: i64 = 300;
/// How far in the future a record's `issued_at` may be and still date a
/// hand-over for E's rule (c), the invitation.
const ISSUED_AT_SKEW_SECS: i64 = 300;
/// The builder's caps: the server's own caps per rotation.
const MAX_INCLUDED: usize = 100;
const MAX_PENDING: usize = 100;

// ============================================================================
// Exported types
// ============================================================================

/// A member's role, in a circle's chain of refresh records or in this device's
/// member list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CircleRole {
    Owner,
    Admin,
    Member,
}

impl From<ChainRole> for CircleRole {
    fn from(role: ChainRole) -> Self {
        match role {
            ChainRole::Owner => CircleRole::Owner,
            ChainRole::Admin => CircleRole::Admin,
            ChainRole::Member => CircleRole::Member,
        }
    }
}

impl From<CircleRole> for ChainRole {
    fn from(role: CircleRole) -> Self {
        match role {
            CircleRole::Owner => ChainRole::Owner,
            CircleRole::Admin => ChainRole::Admin,
            CircleRole::Member => ChainRole::Member,
        }
    }
}

/// Where a refresh record stands on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecordVersionState {
    /// The record fits the chain, everyone it includes is allowed here,
    /// and this device's copy of the key verifies the record's tag: it
    /// may seal under this version.
    Accepted,
    /// The record fits the chain and everyone it includes is allowed here,
    /// but this device holds no copy of the key that verifies the tag. The
    /// record is the reference for the next one; nothing is sealed or read
    /// under this version until a verifying copy arrives.
    Reference,
    /// Not decided yet: a record, a link or a key is missing, or a member the
    /// record includes is not confirmed here yet. Checked again on the next
    /// import.
    Waiting,
    /// Refused. A refusal for whom the record includes (`R2_NOT_ALLOWED`,
    /// `R2_UNMATCHED_ENTRY`) or for its roles or removals (`ROLE`,
    /// `REMOVAL`) calls for a repair (a `REPAIR` record).
    Rejected,
}

/// Why a record is not accepted: a code for the apps to branch on. The text
/// behind it goes to the SDK's log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecordProblem {
    /// Nothing: the record is accepted or a reference.
    None,
    /// It does not parse, or breaks a rule of the record
    /// format, including the rules that read the record
    /// before it.
    Structure,
    /// It does not link to the record before it that this device holds.
    NotLinked,
    /// A second record for a version, a second first record, or a member's
    /// head that contradicts this device's chain.
    Fork,
    /// No member this device confirms matches the signer's entry.
    SignerUnknown,
    /// The signature does not verify under the matched signer's key.
    Signature,
    /// This device's copy of the key does not verify the record's tag. The copy
    /// is dropped; ask the members for a fresh one.
    KeyTag,
    /// The key chain could not be walked to the circle's anchor, or the anchor's
    /// key it reached does not verify the first record: no member code can be
    /// matched yet. Ask the members for a fresh copy (of the key for the first
    /// record, or of the link to the anchor).
    ChainWalk,
    /// This device's own key for the circle's anchor (the version before
    /// a transition) does not verify the transition's anchor tag: the
    /// transition was made over another key. The circle waits here,
    /// logged as a split. The key this device holds is kept, and it
    /// keeps reading with it; no fresh copy of it is asked for.
    AnchorMismatch,
    /// `link_to` is below the floor (the last version whose record
    /// included the signer) or below the anchor.
    Floor,
    /// The key-chain link the record names is missing.
    LinkMissing,
    /// A member the record includes is not eligible here (E, as
    /// `refresh_eligibility` reports it).
    R2NotAllowed,
    /// An entry the record includes matches no member this device confirms.
    R2UnmatchedEntry,
    /// A role changed without the right.
    Role,
    /// A "removed" entry without the right.
    Removal,
    /// A record before it is missing.
    RecordMissing,
    /// Signed with the key of another member this device confirms than the
    /// one its signer entry names, in a record whose bytes the record
    /// after it fixes (format 2): rejected and passed over, its removals
    /// counting by its signer code's role and nothing else moving. A
    /// repair is due, as for `R2_NOT_ALLOWED`: only an accepted record
    /// after it brings writes back.
    Misattributed,
}

/// A refresh record as the server serves it: `BODY || key_tag` (a
/// transition: `BODY || key_tag || anchor_tag`), and its signature, both hex.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedRefreshRecord {
    pub record_hex: String,
    pub signature_hex: String,
}

/// A membership statement the app holds for a member (invitation or
/// admission), as the server serves it. The SDK verifies it itself, under the
/// signer's key that `members` says this device confirms.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HeldStatement {
    pub statement_hex: String,
    pub signature_hex: String,
}

/// A member on this device's member list, as the app judges them. Confirmation
/// stays in the apps: the SDK trusts `confirmed` and the keys given with it,
/// and nothing else about who someone is.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecordMember {
    pub user_id: String,
    /// The keys this device confirms for them (or, when `confirmed` is false,
    /// the keys the server lists, used only to see whether the account's own
    /// head vouches for them). Both None for a listed member who has published
    /// no keys yet (one None reads as both): they count as listed and nothing
    /// more, never confirmed, matched, vouched for or named in a record.
    /// `confirmed` must then be false, or the call fails with InvalidInput. A
    /// key of all zeros is never a real one: it reads as None, and `confirmed`
    /// as false.
    pub sharing_public_key_hex: Option<String>,
    pub signing_public_key_hex: Option<String>,
    /// This device confirms them, with these keys.
    pub confirmed: bool,
    /// They are on this device's COMPLETE member list now.
    pub listed: bool,
    /// Their role in this device's member list (the server's word): used
    /// only for a transition's roles and for an admin's claim to be the
    /// owner, never for eligibility.
    pub listed_role: Option<CircleRole>,
    /// The invitations and admissions about them that the app holds.
    pub statements: Vec<HeldStatement>,
    /// DELIVER only: this device's own person confirmed these keys ("It's them").
    pub person_confirmed_keys: bool,
    /// DELIVER only: the server says they hold no key for the circle.
    pub server_says_keyless: bool,
}

/// An account head as the server serves it: an account's
/// signed word on the last record its device accepted in a
/// circle (see `sign_circle_head`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedCircleHead {
    pub head_hex: String,
    pub signature_hex: String,
}

/// A member's head, for comparing chains.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberHead {
    pub user_id: String,
    pub head: SignedCircleHead,
}

/// One record's outcome.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecordVersionStatus {
    pub version: i32,
    pub state: RecordVersionState,
    pub problem: RecordProblem,
    /// Members the record includes whom E does not allow here.
    pub not_allowed: Vec<String>,
    /// Entries the record includes that match no member this device confirms.
    pub unmatched_entries: u32,
    /// On a version this device rejected: every LISTED member its record
    /// names, included or pending, by user id (a superset of
    /// `not_allowed` and of the listed members behind
    /// `unmatched_entries`). A plan built on this record must name them
    /// all: the builder (`prepare_recorded_rotation`) refuses one that
    /// leaves a listed member out.
    pub named_listed: Vec<String>,
}

/// The outcome of `import_refresh_records`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RefreshRecordsReport {
    /// The records this import decided, oldest first.
    pub versions: Vec<RecordVersionStatus>,
    /// The version this device may seal under now (`get_active_version`).
    pub sealing_version: Option<i32>,
    /// A copy of a key was refused or dropped: ask the members for a fresh one.
    pub ask_for_fresh_copy: bool,
    /// The chain forked: the circle seals, delivers and rotates nothing
    /// until it settles. An import of the whole chain settles it
    /// (`refresh_head_versions` asks for it) when one side removed the
    /// other side's signer: a removal beats its target.
    pub forked: bool,
    /// Listed members that the account's own head vouches for: the app
    /// may confirm them with no first-sight step.
    pub head_confirmed_members: Vec<String>,
    /// The `named_listed` of the record a plan would be built on now: the
    /// newest record rejected here after the head (none: empty). Name them all
    /// in the next plan (carry pending those it can't include).
    pub tip_named_listed: Vec<String>,
}

/// What E is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EligibilityPurpose {
    /// Whom a rotation may give the new key (E_include).
    Include,
    /// Whom this device may hand the current key (E_deliver: E_include or (d)).
    Deliver,
}

/// Which of E's rules made a member eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EligibilityBasis {
    /// (a): the chain counts them here, with exactly these keys.
    CountedByChain,
    /// (b): an admission signed by an owner or admin in the chain.
    Admission,
    /// (c): an invitation signed by an owner or admin in the chain.
    Invitation,
    /// (d), DELIVER only: the chain names them, and this device's person
    /// confirmed their changed keys.
    PersonConfirmed,
}

/// E for one member: whether they may get the circle's key and
/// on what basis, with what the apps need to ask an owner or
/// admin about a member E does not allow.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MemberEligibility {
    pub user_id: String,
    pub eligible: bool,
    pub basis: Option<EligibilityBasis>,
    /// An invitation for them that no record named since expired before they
    /// got the key, whoever signed it.
    pub invitation_expired: bool,
    /// An unexpired invitation for them whose signer is not an owner or admin in
    /// the chain.
    pub invitation_signer_not_chain_admin: bool,
    /// The chain's last word on them is a removal an owner or admin made:
    /// never asked about when the inviter is not a chain owner or admin.
    pub removed_by_owner_or_admin: bool,
    /// The version of that removal: the one (b) and (c) are judged against
    /// (an eject in a record rejected here counts at that record's version
    /// until a repair). None when their last word is no removal that
    /// counts. A waiting change or an owed admission for them ends when
    /// this is above the highest version this device had ACCEPTED when the
    /// person decided (`get_active_version` then, never
    /// `newest_held_version`).
    pub removed_at_version: Option<i32>,
    /// An address (kind-2) invitation for them that can't count by (c): no
    /// kind-1 or kind-3 statement signed by an owner or admin in the chain
    /// binds their user id and keys. Asked about at once.
    pub email_invitation_without_signed_id: bool,
}

// ============================================================================
// This device's state per circle
// ============================================================================

/// What this device knows about one member code: the last record that named
/// it, as of the head (last(x)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberFact {
    pub version: u32,
    pub state: EntryState,
    pub role: ChainRole,
    pub commitment: [u8; 32],
    /// The last version whose record INCLUDED this code (0: never): the
    /// floor for `link_to`.
    pub last_included: u32,
    /// For a "departed" entry: false when it can't count (an owner's or
    /// admin's departure in a record that no owner or admin signed), so it
    /// reads as pending everywhere.
    pub departure_may_count: bool,
    /// The last version whose record this device accepted INCLUDED this
    /// code with `commitment` (0: none; a later entry with another
    /// commitment ends it). E (a) counts a member only through it: a
    /// pending carry of keys a rejected record named never does.
    pub included_with_keys: u32,
    /// The last version whose record named this code included, removed or
    /// departed (a pending carry spends nothing): (c)'s invitation is
    /// spent by a record after its `at_version`.
    pub last_spent: u32,
    /// The sharing and signing keys a confirmed row gave this code when a
    /// record this device accepted included it with `commitment` (None:
    /// none seen, or a later entry with another commitment ended it). R1
    /// finds with them a signer the app no longer lists (`signer_of`); a
    /// carry never sets them.
    pub vouched_keys: Option<([u8; 32], [u8; 32])>,
}

impl MemberFact {
    /// What `included_with_keys` and `last_spent` read as when nothing
    /// stored says more (a store written by an older SDK has neither): an
    /// inclusion only if this is one, and spent at this version, so that it
    /// fails closed.
    fn fail_closed_keyed_parts(&mut self) {
        self.included_with_keys = if self.state == EntryState::Included { self.version } else { 0 };
        self.last_spent = self.version;
    }

    /// The fact after `entry` at `version`, from `previous`: the keyed
    /// inclusion and its vouched keys go on only with the same commitment, and
    /// a pending carry spends nothing.
    fn keyed_after(previous: Option<&MemberFact>, entry: &crate::refresh_record::RecordEntry, version: u32) -> (u32, u32, Option<([u8; 32], [u8; 32])>) {
        let same_keys = previous.filter(|p| p.commitment == entry.commitment);
        let included_with_keys = if entry.state == EntryState::Included { version } else { same_keys.map_or(0, |p| p.included_with_keys) };
        let last_spent = if entry.state == EntryState::Pending { previous.map_or(0, |p| p.last_spent) } else { version };
        (included_with_keys, last_spent, same_keys.and_then(|p| p.vouched_keys))
    }
}

/// The head this device accepted: the latest record it counts as its reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainHead {
    pub version: u32,
    pub chain: [u8; 32],
    pub digest: [u8; 32],
}

/// The anchor check: what checks the key the circle's
/// secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorCheck {
    /// The version of the circle's first record.
    pub v0: u32,
    /// The anchor version A whose key S comes from: V0 for a genesis,
    /// and V0 - 1 for a transition.
    pub anchor: u32,
    /// The first record's digest, and the tag the anchor key must verify over
    /// it: a genesis's key_tag, or a transition's anchor_tag.
    pub digest: [u8; 32],
    pub tag: [u8; 32],
}

impl AnchorCheck {
    /// The anchor check: whether `key` is the circle's anchor key,
    /// in constant time.
    pub(crate) fn key_ok(&self, key: &[u8]) -> bool {
        let tag = if self.anchor < self.v0 { anchor_tag(key, &self.digest) } else { key_tag(key, &self.digest) };
        tag.map_or(false, |t| crate::crypto::ct_eq(&t, &self.tag))
    }
}

/// A record this device holds in this process.
#[derive(Debug, Clone)]
pub(crate) struct SeenRecord {
    pub wire: WireRecord,
    pub chain: [u8; 32],
    pub state: RecordVersionState,
    /// For a record rejected here: its removals that count (an owner's
    /// or admin's own act), as the importer judged them. The one
    /// overlay the importer, the builder and E apply until a repair.
    pub counting_removals: HashSet<[u8; 32]>,
    /// Its signature verified here, under the key of a signer this device
    /// confirms. Only the signature covers the key tag (the chain value
    /// covers the body alone), so only such a record, once taken, decides
    /// about a held copy of its key (`drop_contradicted_keys`).
    pub signed: bool,
    /// Its signature as served (this process only): checked again on a later
    /// import, against the members confirmed then, while it isn't `signed`.
    pub signature: Option<[u8; 64]>,
    /// Rejected here only for R2 (R1 and the role and removal rules
    /// held): its roles move the chain's, as its counting removals count.
    pub moves_roles: bool,
    /// Rejected here as MISATTRIBUTED: no inclusion in it moves, so none
    /// of them sets a repair's floor.
    pub misattributed: bool,
}

impl SeenRecord {
    pub(crate) fn new(wire: WireRecord, chain: [u8; 32], state: RecordVersionState) -> Self {
        SeenRecord { wire, chain, state, counting_removals: HashSet::new(), signed: false, signature: None, moves_roles: false, misattributed: false }
    }

    pub(crate) fn with_signature(mut self, signature: &[u8; 64]) -> Self {
        self.signature = Some(*signature);
        self
    }

    pub(crate) fn signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }

    /// Whether its tag decides about a held copy of its key: a record
    /// this device took (accepted or its reference) whose signature
    /// verified here. A record refused or waiting here never does, even
    /// when signed: someone the chain no longer counts can still sign
    /// one.
    pub(crate) fn vouches_for_its_tag(&self) -> bool {
        self.signed && matches!(self.state, RecordVersionState::Accepted | RecordVersionState::Reference)
    }
}

/// This device's own record, made by the builder and not yet served back.
#[derive(Debug, Clone)]
pub(crate) struct OwnRecord {
    pub wire: WireRecord,
}

/// One version of this device's chain, as the fork rule reads it: the
/// chain value after it, and who signed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainStep {
    pub chain: [u8; 32],
    pub signer: [u8; 32],
    /// Persisted (`~rrx`): the wire_chain of the copy this device took
    /// here (its signature verified here, or taken on the account's own
    /// head's word): what a format-2 record after it links. None: not
    /// known here (a store written by an older SDK has none); the head's
    /// is learned again from the head record served again
    /// (`refresh_head_versions`).
    pub wire: Option<[u8; 32]>,
    /// Persisted (`~rrv`, and with the wire in `~rrx`): the record's format:
    /// formats only go up within a circle.
    pub format: RecordFormat,
    /// Whether `format` is known here: false only for a step stored by an
    /// older SDK with no wire (its `~rrv` holds no format). Until its
    /// record is served again, nothing after it links.
    pub format_known: bool,
    /// What vouched for its key here: kept when its record vouched for its tag
    /// (taken, its signature verified), so that after a restart a copy served
    /// again vouches only with this tag, whoever signed it, and a copy of the
    /// version's key is checked against it, served again or not.
    pub kept: Option<KeptTag>,
}

/// A record's key tag and digest: enough to check a copy of its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptTag {
    pub tag: [u8; 32],
    pub digest: [u8; 32],
}

impl KeptTag {
    fn of(wire: &WireRecord) -> Self {
        KeptTag { tag: wire.key_tag, digest: wire.digest }
    }

    /// Whether `wire` is the record this was kept from (with the step's chain
    /// value, which covers the body): the same tag.
    fn is_of(&self, wire: &WireRecord) -> bool {
        self.tag == wire.key_tag && self.digest == wire.digest
    }
}

/// What a record this device passed over above its head counted, kept so that
/// after a restart that version waits for its own record and this still counts
/// meanwhile: see `CircleChain::carried`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Carried {
    /// The chain value of the record passed over: only that record decides the
    /// version again.
    pub chain: [u8; 32],
    /// Its removals that count, as the importer judged them: a removal in
    /// a rejected record counts at its version until a repair.
    pub removals: BTreeSet<[u8; 32]>,
    /// The roles it moved, when it was rejected only for R2; else none.
    pub roles: BTreeMap<[u8; 32], ChainRole>,
}

impl Carried {
    fn of(seen: &SeenRecord) -> Self {
        Carried {
            chain: seen.chain,
            removals: seen.counting_removals.iter().copied().collect(),
            roles: if seen.moves_roles { seen.wire.body.entries.iter().map(|e| (e.code, e.role)).collect() } else { BTreeMap::new() },
        }
    }

    /// Its removals and roles, stored: the number of removals (u16, little
    /// endian) and their codes, then the number of roles and each code with its
    /// role's code (one byte).
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 * self.removals.len() + 33 * self.roles.len());
        out.extend_from_slice(&(self.removals.len() as u16).to_le_bytes());
        for code in &self.removals {
            out.extend_from_slice(code);
        }
        out.extend_from_slice(&(self.roles.len() as u16).to_le_bytes());
        for (code, role) in &self.roles {
            out.extend_from_slice(code);
            out.push(role_code(*role) as u8);
        }
        out
    }

    /// The same, read back: exactly that shape, or nothing.
    fn decode(chain: [u8; 32], bytes: &[u8]) -> Option<Self> {
        let count = |at: usize| bytes.get(at..at + 2).map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])));
        let removals_count = count(0)?;
        let roles_at = 2 + 32 * removals_count;
        let roles_count = count(roles_at)?;
        if bytes.len() != roles_at + 2 + 33 * roles_count {
            return None;
        }
        let removals: BTreeSet<[u8; 32]> = bytes[2..roles_at].chunks_exact(32).map(|c| c.try_into().expect("32 bytes")).collect();
        let mut roles = BTreeMap::new();
        for item in bytes[roles_at + 2..].chunks_exact(33) {
            roles.insert(item[..32].try_into().expect("32 bytes"), role_of(i64::from(item[32]))?);
        }
        (removals.len() == removals_count && roles.len() == roles_count).then_some(Carried { chain, removals, roles })
    }
}

/// How many versions of its chain a device keeps for the fork rule.
const MAX_HISTORY: usize = 100;

/// Everything this device keeps about one circle's chain.
#[derive(Default)]
pub(crate) struct CircleChain {
    /// Persisted (`~rrh`). None: no record accepted yet.
    pub head: Option<ChainHead>,
    /// Persisted (`~rrh`): the version this device may seal under (0: none).
    pub sealing: u32,
    /// Persisted (`~rrh`): records exist for this circle (a head was seen,
    /// or a record held), so it is never legacy again.
    pub latched: bool,
    /// Persisted (`~rrh`): a fork was seen; the circle waits until it
    /// settles.
    pub forked: bool,
    /// Persisted (`~rrf`): two records were served for the version after
    /// the head with no winner (one that couldn't be judged, or two that
    /// stand and don't remove each other's signer). Set with `forked`,
    /// and nothing settles it: the circle waits until its state goes (a
    /// sign-out's clear, or the account leaving the circle).
    pub fork_latched: bool,
    /// Persisted (`~rra`).
    pub anchor: Option<AnchorCheck>,
    /// Persisted (`~rrm`), as of the head.
    pub facts: HashMap<[u8; 32], MemberFact>,
    /// Set only once the anchor key verified the circle's first record
    /// (`AnchorCheck::key_ok`). Persisted with the circle keys
    /// (`~rrs:`), never in the pins blob; never returned.
    pub secret: Option<Zeroizing<[u8; 32]>>,
    /// This process only: the records this device holds, by version.
    pub seen: BTreeMap<u32, SeenRecord>,
    /// This process only: the records were imported at least once.
    pub imported: bool,
    /// Persisted (`~rrw:`): every version above the head that an import saw
    /// and could not decide (its signature, a record missing under a served
    /// one, a link, a walk, a newcomer not confirmed yet), each with the
    /// chain value of the record that waits there (for a record missing, the
    /// one served above it). A wait found later never replaces one kept.
    /// Each lasts until that very record is judged here and doesn't wait
    /// (taken, or refused once it can be judged), or the head reaches its
    /// version through it: another record served at that version is a second
    /// candidate for it, and the version waits there as a fork. No record is
    /// built while any is kept: one on the head below would fork the chain,
    /// and could give the new key to a member a waiting version removes.
    /// After a restart it also holds each version this device passed over
    /// before it (`carried`), with that record's chain value unless another
    /// record was kept waiting there.
    pub waiting: BTreeMap<u32, [u8; 32]>,
    /// Persisted (`~rrp:`, with a `~rrw:` wait at the same version): each
    /// version above the head this device passed over (a record rejected
    /// here that a repair would link: for R2, for an owner claim that the
    /// role and removal rules refuse, ...), with what it counted. In this
    /// process the record itself is held (`seen`); after a restart the
    /// version waits for that very record (judged again when served, either
    /// copy of its body), no record is built meanwhile, and its removals and
    /// roles still count for E and the heads: a pass-over forgotten at a
    /// restart would let a server that withholds the record undo its
    /// removals. Each lasts while its version waits, whatever waits there:
    /// once an import decides the version, or the head passes it, it goes,
    /// and the record judged there counts instead.
    pub carried: BTreeMap<u32, Carried>,
    /// Persisted (`~rro`): this device's own record, until the server serves
    /// it back. A restart between the server taking it and serving it back
    /// keeps sealing under its version (with the unconfirmed rotation's key),
    /// never under the one before, which a member it removes knows.
    pub own: Option<OwnRecord>,
    /// Persisted (`~rrv`): the chain value and signer of each version of
    /// this device's chain up to its head, the last MAX_HISTORY of them,
    /// so a fork can be settled after a restart; and (`~rrv…:w`) the tag
    /// kept for each whose record vouched for its tag here.
    pub history: BTreeMap<u32, ChainStep>,
    /// While the store is read: kept tags, bound to their steps once all are in.
    pub loading_tags: BTreeMap<u32, KeptTag>,
    /// While the store is read: each step's wire, chain value and format,
    /// bound to the step with that chain value once all are in.
    pub loading_wires: BTreeMap<u32, ([u8; 32], [u8; 32], RecordFormat)>,
    /// While the store is read: the facts' keyed parts, by code, matched to
    /// their facts once all are in.
    pub loading_keyed: HashMap<[u8; 32], MemberFact>,
    /// While the store is read: the facts' vouched keys, by code, with the
    /// version they were stored at.
    pub loading_vouched: HashMap<[u8; 32], (u32, ([u8; 32], [u8; 32]))>,
    /// While the store is read: the versions passed over, by version, bound to
    /// their waits once all are in.
    pub loading_carried: BTreeMap<u32, Carried>,
    /// Persisted as it was read: every entry the store held for this circle,
    /// when one of its head, anchor, history or facts didn't read here
    /// (`load_persisted`). The circle is then latched and forked and nothing
    /// else, and these go back exactly as stored.
    pub as_stored: Vec<(String, PinRecord)>,
}

impl CircleChain {
    /// A circle with records, or latched by a head: never legacy.
    pub(crate) fn is_recorded(&self) -> bool {
        self.latched || self.head.is_some() || self.own.is_some()
    }

    /// Every version above the head that this device passed over, with what it
    /// counted: those it holds the record of (the run `Tip::after_rejected`
    /// walks), and those carried from before a restart that still wait.
    pub(crate) fn passed_over(&self) -> BTreeMap<u32, Carried> {
        let mut out = self.carried.clone();
        if let Some(head) = &self.head {
            let mut version = head.version + 1;
            while let Some(seen) = self.seen.get(&version).filter(|s| s.state == RecordVersionState::Rejected) {
                out.insert(version, Carried::of(seen));
                version += 1;
            }
        }
        out
    }

    /// What stays of a circle that had records here once this account's
    /// membership ends: its latch, and nothing else. Persisted like any
    /// latch; only `clear_all_keys` removes it, and the re-join's first
    /// accepted record takes its place.
    pub(crate) fn latched_only() -> Self {
        CircleChain { latched: true, ..Default::default() }
    }

    /// Whether this is only that mark.
    pub(crate) fn is_latched_only(&self) -> bool {
        self.latched
            && self.head.is_none()
            && self.own.is_none()
            && self.anchor.is_none()
            && self.secret.is_none()
            && self.facts.is_empty()
            && self.history.is_empty()
            && self.seen.is_empty()
            && !self.forked
            && !self.fork_latched
            && self.sealing == 0
    }

    /// Whether `key` is `version`'s key, by what vouches for that version
    /// here: up to the head, the tag kept of a record that vouched for it
    /// (after a restart too, served again or not); else a record held that
    /// vouches for its tag. None: nothing vouches for that version here.
    pub(crate) fn key_vouched(&self, version: u32, key: &[u8]) -> Option<bool> {
        // The tag kept up to the head comes first: a signed copy of the same
        // body with another tag (its signer equivocating) never outranks it.
        if self.head.as_ref().map_or(false, |head| version <= head.version) {
            if let Some(kept) = self.history.get(&version).and_then(|step| step.kept) {
                return Some(crate::refresh_record::key_tag_verifies(key, &kept.digest, &kept.tag));
            }
        }
        let seen = self.seen.get(&version).filter(|seen| seen.vouches_for_its_tag())?;
        Some(seen.wire.key_tag_matches(key))
    }

    /// Note a record this device placed in its chain. `vouches`: it vouches
    /// for its tag here, so its tag is kept. `taken_wire`: the wire_chain of
    /// the copy taken, when this device took that copy (its signature verified
    /// here, or on the account's own head's word). A step keeps the tag and
    /// the wire it has for the same chain value (a format-2 successor fixes
    /// one copy); another chain value (a settled fork) never takes the other
    /// branch's.
    pub(crate) fn note_step(&mut self, wire: &WireRecord, chain_value: [u8; 32], vouches: bool, taken_wire: Option<[u8; 32]>) {
        let version = wire.body.version;
        let same = self.history.get(&version).filter(|step| step.chain == chain_value).copied();
        let kept = same.and_then(|step| step.kept).or_else(|| vouches.then(|| KeptTag::of(wire)));
        let taken = same.and_then(|step| step.wire).or(taken_wire);
        let step = ChainStep { chain: chain_value, signer: wire.body.signer_code, kept, wire: taken, format: wire.body.format, format_known: true };
        self.history.insert(version, step);
        while self.history.len() > MAX_HISTORY {
            let oldest = *self.history.keys().next().expect("not empty");
            self.history.remove(&oldest);
        }
    }

    /// What this device holds at `version` (a record held in this
    /// process), in a head's `format`: format 1, its chain value; format
    /// 2, the wire_chain of the copy taken there (or held, above the
    /// head). None: no record held there, or its wire not known here:
    /// nothing to compare.
    pub(crate) fn value_at(&self, version: u32, format: RecordFormat) -> Option<[u8; 32]> {
        let seen = self.seen.get(&version)?;
        match format {
            RecordFormat::V1 => Some(seen.chain),
            RecordFormat::V2 => self
                .history
                .get(&version)
                .filter(|step| step.chain == seen.chain)
                .and_then(|step| step.wire)
                .or_else(|| seen.signature.map(|signature| seen.wire.wire_chain(&signature))),
        }
    }

    /// The anchor of the circle's first record as served. A different one than
    /// before drops the secret: it was derived for the other, and the anchor
    /// check runs again.
    pub(crate) fn set_anchor(&mut self, anchor: AnchorCheck) {
        if self.anchor.as_ref() != Some(&anchor) {
            self.secret = None;
        }
        self.anchor = Some(anchor);
    }
}

// ============================================================================
// Persistence (reserved keys in the pins blob; PinRecord-shaped, well-formed)
// ============================================================================

pub(crate) const HEAD_PREFIX: &str = "~rrh:";
pub(crate) const FACT_PREFIX: &str = "~rrm:";
pub(crate) const ANCHOR_PREFIX: &str = "~rra:";
pub(crate) const HISTORY_PREFIX: &str = "~rrv:";
/// This device's own record, until the server serves it back: `~rro:{circle}`,
/// the record's bytes in hex (an older SDK keeps it as a pin and writes it
/// back unchanged).
pub(crate) const OWN_PREFIX: &str = "~rro:";
/// A history step's kept tag: `~rrv:{circle}:{version}:w`.
pub(crate) const KEPT_TAG_SUFFIX: &str = ":w";
/// A fact's keyed parts (`included_with_keys`, `last_spent`):
/// `~rrk:{circle}:{code}`, bound to its fact by version and commitment. An
/// older SDK keeps it as a pin and writes it back unchanged; a fact that SDK
/// rewrote no longer matches it, and reads as
/// `MemberFact::fail_closed_keyed_parts` says.
pub(crate) const KEYED_PREFIX: &str = "~rrk:";
/// A fact's vouched keys (`MemberFact::vouched_keys`):
/// `~rrq:{circle}:{code}`, the member's sharing and signing public keys,
/// bound to its fact by version and used only when they give the fact's
/// commitment again. Absent: none (a signer who left then needs an app row,
/// or waits). An older SDK keeps it as a pin and writes it back unchanged.
pub(crate) const VOUCHED_PREFIX: &str = "~rrq:";
/// A kept wait (`CircleChain::waiting`): a version that waits here, with
/// the chain value of the record that waits there, `~rrw:{circle}:{version}`.
/// One that doesn't read leaves the circle waiting, as any stored part of
/// its state that doesn't read. An older SDK keeps it as a pin and writes
/// it back unchanged.
pub(crate) const WAIT_PREFIX: &str = "~rrw:";
/// A version this device passed over above its head, with what it counted
/// (`CircleChain::carried`): `~rrp:{circle}:{version}`, the record's chain
/// value and `Carried::encode`, written with a `~rrw:` wait at that version so
/// that an older SDK waits there too (it keeps this entry as a pin and
/// writes it back unchanged). One that doesn't read leaves the circle waiting.
pub(crate) const CARRIED_PREFIX: &str = "~rrp:";
/// A step's wire and format: `~rrx:{circle}:{version}`, the wire_chain of the
/// copy taken there and the step's chain value (it binds to that step only),
/// the format in `last_verified_at`. One that doesn't read leaves the circle
/// waiting, as any stored part of its state that doesn't read; one that binds
/// no step goes (its wire is then learned again). An older SDK keeps it as a
/// pin and writes it back unchanged.
pub(crate) const WIRE_PREFIX: &str = "~rrx:";
/// A fork above the head, latched: `~rrf:{circle}`. It holds nothing else:
/// whatever it reads as, it latches. An older SDK keeps it as a pin and writes
/// it back unchanged, so a fork that SDK settled is latched again here.
pub(crate) const FORK_PREFIX: &str = "~rrf:";

/// Whether a pins-blob key belongs to the refresh-record state.
pub(crate) fn is_refresh_key(key: &str) -> bool {
    key.starts_with(HEAD_PREFIX)
        || key.starts_with(FACT_PREFIX)
        || key.starts_with(ANCHOR_PREFIX)
        || key.starts_with(HISTORY_PREFIX)
        || key.starts_with(OWN_PREFIX)
        || key.starts_with(KEYED_PREFIX)
        || key.starts_with(VOUCHED_PREFIX)
        || key.starts_with(WAIT_PREFIX)
        || key.starts_with(CARRIED_PREFIX)
        || key.starts_with(FORK_PREFIX)
        || key.starts_with(WIRE_PREFIX)
}

/// The reserved id a circle's secret is stored under in `circle_keys_json`:
/// `{"0": base64(0x01 || S)}`, 33 bytes, never a key's 32. An older SDK reads
/// it as a circle's keys: one skips an entry that is not 32 bytes and makes
/// no circle of it; another keeps a keyless pseudo-circle at version 0 and
/// writes it back as `{}`, and S is then derived again.
pub(crate) const SECRET_PREFIX: &str = "~rrs:";
const SECRET_FORMAT: u8 = 1;

/// The `circle_keys_json` entries for the circles' secrets: circles with
/// records whose anchor this device checked (`AnchorCheck::key_ok`), and
/// nothing else.
pub(crate) fn persisted_secrets(chains: &HashMap<CircleKey, CircleChain>) -> Vec<(String, HashMap<String, String>)> {
    use base64::Engine as _;
    chains
        .iter()
        .filter(|(_, chain)| chain.is_recorded() && chain.anchor.is_some())
        .filter_map(|(circle_id, chain)| {
            let secret = chain.secret.as_ref()?;
            let mut bytes = Zeroizing::new([0u8; 33]);
            bytes[0] = SECRET_FORMAT;
            bytes[1..].copy_from_slice(secret.as_slice());
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes.as_slice());
            Some((format!("{SECRET_PREFIX}{circle_id}"), HashMap::from([("0".to_string(), encoded)])))
        })
        .collect()
}

/// Take a stored secret back into its circle's chain: exactly
/// `{"0": base64(0x01 || S)}`, for a circle whose records and anchor were
/// loaded and that holds no secret yet in this process. Anything else is
/// ignored (logged), and S is derived again.
pub(crate) fn absorb_secret(chains: &mut HashMap<CircleKey, CircleChain>, key: &str, versions: &HashMap<String, String>) {
    use base64::Engine as _;
    let Some(circle_id) = key.strip_prefix(SECRET_PREFIX) else {
        return;
    };
    let bytes = match (versions.len(), versions.get("0")) {
        (1, Some(encoded)) => base64::engine::general_purpose::STANDARD.decode(encoded).ok().map(Zeroizing::new),
        _ => None,
    };
    let secret = bytes.filter(|b| b.len() == 33 && b[0] == SECRET_FORMAT).map(|b| {
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&b[1..]);
        secret
    });
    let Some(secret) = secret else {
        tracing::warn!("Ignoring a stored circle secret for {} that is not 0x01 followed by 32 bytes", circle_id);
        return;
    };
    match chains.get_mut(&CircleKey::of(circle_id)).filter(|chain| chain.is_recorded() && chain.anchor.is_some()) {
        Some(chain) if chain.secret.is_none() => chain.secret = Some(secret),
        Some(_) => {}
        None => tracing::warn!("Ignoring a stored circle secret for {}: its records are not held here", circle_id),
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn u32_of(value: i64) -> Option<u32> {
    u32::try_from(value).ok().filter(|v| *v <= 1_000_000)
}

fn state_code(state: EntryState) -> i64 {
    match state {
        EntryState::Included => 1,
        EntryState::Pending => 2,
        EntryState::Removed => 3,
        EntryState::Departed => 4,
    }
}

fn state_of(code: i64) -> Option<EntryState> {
    match code {
        1 => Some(EntryState::Included),
        2 => Some(EntryState::Pending),
        3 => Some(EntryState::Removed),
        4 => Some(EntryState::Departed),
        _ => None,
    }
}

fn role_code(role: ChainRole) -> i64 {
    match role {
        ChainRole::Owner => 1,
        ChainRole::Admin => 2,
        ChainRole::Member => 3,
    }
}

fn role_of(code: i64) -> Option<ChainRole> {
    match code {
        1 => Some(ChainRole::Owner),
        2 => Some(ChainRole::Admin),
        3 => Some(ChainRole::Member),
        _ => None,
    }
}

/// The pins-blob entries for every circle's persisted state.
pub(crate) fn persisted_entries(chains: &HashMap<CircleKey, CircleChain>) -> Vec<(String, PinRecord)> {
    let mut out = Vec::new();
    for (circle_id, chain) in chains {
        if !chain.is_recorded() {
            continue;
        }
        // A circle whose stored state didn't read here: all of it goes back as
        // it was stored, and no fork marker of this device's own goes over it.
        if !chain.as_stored.is_empty() {
            out.extend(chain.as_stored.iter().cloned());
            continue;
        }
        let (version, chain_value, digest) = match &chain.head {
            Some(head) => (head.version, head.chain, head.digest),
            None => (0, [0u8; 32], [0u8; 32]),
        };
        out.push((
            format!("{HEAD_PREFIX}{circle_id}"),
            PinRecord {
                sharing_pubkey_hex: hex::encode(chain_value),
                signing_pubkey_hex: hex::encode(digest),
                first_pinned_at: i64::from(version),
                last_verified_at: if chain.forked { -1 } else { i64::from(chain.sealing) },
                user_approved_change_at: None,
            },
        ));
        let wait = |at: u32, waits: &[u8; 32]| {
            (
                format!("{WAIT_PREFIX}{circle_id}:{at}"),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(waits),
                    signing_pubkey_hex: String::new(),
                    first_pinned_at: i64::from(at),
                    last_verified_at: 0,
                    user_approved_change_at: None,
                },
            )
        };
        for (at, waits) in &chain.waiting {
            out.push(wait(*at, waits));
        }
        // Each version passed over above the head waits after a
        // restart, with what it counted. A wait kept at its version
        // stays as it is (a kept wait is never replaced).
        for (at, carried) in chain.passed_over() {
            if !chain.waiting.contains_key(&at) {
                out.push(wait(at, &carried.chain));
            }
            out.push((
                format!("{CARRIED_PREFIX}{circle_id}:{at}"),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(carried.chain),
                    signing_pubkey_hex: hex::encode(carried.encode()),
                    first_pinned_at: i64::from(at),
                    last_verified_at: 1,
                    user_approved_change_at: None,
                },
            ));
        }
        if chain.fork_latched {
            out.push((
                format!("{FORK_PREFIX}{circle_id}"),
                PinRecord {
                    sharing_pubkey_hex: String::new(),
                    signing_pubkey_hex: String::new(),
                    first_pinned_at: 0,
                    last_verified_at: 0,
                    user_approved_change_at: None,
                },
            ));
        }
        if let Some(own) = &chain.own {
            out.push((
                format!("{OWN_PREFIX}{circle_id}"),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(own.wire.to_bytes()),
                    signing_pubkey_hex: String::new(),
                    first_pinned_at: i64::from(own.wire.body.version),
                    last_verified_at: 0,
                    user_approved_change_at: None,
                },
            ));
        }
        if let Some(anchor) = &chain.anchor {
            out.push((
                format!("{ANCHOR_PREFIX}{circle_id}"),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(anchor.digest),
                    signing_pubkey_hex: hex::encode(anchor.tag),
                    first_pinned_at: i64::from(anchor.anchor),
                    last_verified_at: i64::from(anchor.v0),
                    user_approved_change_at: None,
                },
            ));
        }
        let head_version = chain.head.as_ref().map_or(0, |h| h.version);
        for (version, step) in chain.history.range(..=head_version) {
            if let Some(wire) = step.wire {
                out.push((
                    format!("{WIRE_PREFIX}{circle_id}:{version}"),
                    PinRecord {
                        sharing_pubkey_hex: hex::encode(wire),
                        signing_pubkey_hex: hex::encode(step.chain),
                        first_pinned_at: i64::from(*version),
                        last_verified_at: match step.format {
                            RecordFormat::V1 => 1,
                            RecordFormat::V2 => 2,
                        },
                        user_approved_change_at: None,
                    },
                ));
            }
            // The format on its own, wire or not (0: not known here). An older
            // SDK reads the chain value and signer only.
            out.push((
                format!("{HISTORY_PREFIX}{circle_id}:{version}"),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(step.chain),
                    signing_pubkey_hex: hex::encode(step.signer),
                    first_pinned_at: i64::from(*version),
                    last_verified_at: match (step.format_known, step.format) {
                        (false, _) => 0,
                        (true, RecordFormat::V1) => 1,
                        (true, RecordFormat::V2) => 2,
                    },
                    user_approved_change_at: None,
                },
            ));
            // Its own entry. An older SDK reads it as a malformed history
            // entry, ignores it and drops it; `~rrv:` is never a pin.
            if let Some(kept) = &step.kept {
                out.push((
                    format!("{HISTORY_PREFIX}{circle_id}:{version}{KEPT_TAG_SUFFIX}"),
                    PinRecord {
                        sharing_pubkey_hex: hex::encode(kept.tag),
                        signing_pubkey_hex: hex::encode(kept.digest),
                        first_pinned_at: i64::from(*version),
                        last_verified_at: 0,
                        user_approved_change_at: None,
                    },
                ));
            }
        }
        for (code, fact) in &chain.facts {
            out.push((
                format!("{FACT_PREFIX}{circle_id}:{}", hex::encode(code)),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(code),
                    signing_pubkey_hex: hex::encode(fact.commitment),
                    first_pinned_at: i64::from(fact.version),
                    last_verified_at: role_code(fact.role)
                        + 16 * state_code(fact.state)
                        + if fact.departure_may_count { 256 } else { 0 },
                    user_approved_change_at: Some(i64::from(fact.last_included)),
                },
            ));
            out.push((
                format!("{KEYED_PREFIX}{circle_id}:{}", hex::encode(code)),
                PinRecord {
                    sharing_pubkey_hex: hex::encode(code),
                    signing_pubkey_hex: hex::encode(fact.commitment),
                    first_pinned_at: i64::from(fact.version),
                    last_verified_at: i64::from(fact.last_spent),
                    user_approved_change_at: Some(i64::from(fact.included_with_keys)),
                },
            ));
            if let Some((sharing, signing)) = fact.vouched_keys {
                out.push((
                    format!("{VOUCHED_PREFIX}{circle_id}:{}", hex::encode(code)),
                    PinRecord {
                        sharing_pubkey_hex: hex::encode(sharing),
                        signing_pubkey_hex: hex::encode(signing),
                        first_pinned_at: i64::from(fact.version),
                        last_verified_at: 0,
                        user_approved_change_at: None,
                    },
                ));
            }
        }
    }
    out
}

/// Once the whole pins blob is read: each kept tag goes to its step when its
/// digest gives that step's chain value (from the step before it, or from
/// nothing for the circle's first record). Any other is dropped (logged).
pub(crate) fn finish_persisted(chains: &mut HashMap<CircleKey, CircleChain>) {
    for (circle_id, chain) in chains.iter_mut() {
        // A latched fork waits, whatever its head says (an older SDK may have
        // settled it).
        chain.forked |= chain.fork_latched;
        // This device's own record, once the head has reached it, was
        // served back.
        if chain.own.as_ref().zip(chain.head.as_ref()).map_or(false, |(own, head)| own.wire.body.version <= head.version) {
            chain.own = None;
        }
        // A fact's keyed parts, only if written with this very fact (its
        // version and commitment), and never past it.
        for (code, keyed) in std::mem::take(&mut chain.loading_keyed) {
            match chain.facts.get_mut(&code) {
                Some(fact)
                    if (fact.version, fact.commitment) == (keyed.version, keyed.commitment)
                        && keyed.included_with_keys <= fact.version
                        && keyed.last_spent <= fact.version =>
                {
                    fact.included_with_keys = keyed.included_with_keys;
                    fact.last_spent = keyed.last_spent;
                }
                _ => tracing::warn!("Ignoring a keyed refresh-record fact of circle {} that matches no stored fact", circle_id),
            }
        }
        for (code, (version, keys)) in std::mem::take(&mut chain.loading_vouched) {
            match chain.facts.get_mut(&code) {
                Some(fact) if fact.version == version => fact.vouched_keys = Some(keys),
                _ => tracing::warn!("Ignoring vouched keys of circle {} that match no stored fact", circle_id),
            }
        }
        // A version passed over above the head waits, for its own record
        // unless another was kept waiting there, its wait read or not (an
        // older SDK may have dropped it); one at or below the head was
        // decided.
        let head = chain.head.as_ref().map_or(0, |h| h.version);
        for (at, carried) in std::mem::take(&mut chain.loading_carried) {
            if at > head {
                chain.waiting.entry(at).or_insert(carried.chain);
                chain.carried.insert(at, carried);
            }
        }
        // A step's wire and format, only with the step it was written for.
        for (version, (wire, chain_value, format)) in std::mem::take(&mut chain.loading_wires) {
            match chain.history.get_mut(&version) {
                Some(step) if step.chain == chain_value => {
                    step.wire = Some(wire);
                    step.format = format;
                    step.format_known = true;
                }
                _ => tracing::warn!("Ignoring a refresh-record step wire of circle {} v{} that matches no step of its history", circle_id, version),
            }
        }
        let loading = std::mem::take(&mut chain.loading_tags);
        let Ok(circle) = uuid16("circle_id", circle_id.as_str()) else {
            continue;
        };
        let v0 = chain.anchor.as_ref().map(|a| a.v0);
        for (version, kept) in loading {
            // What the step's record linked: a format-2 record the wire of the
            // step before it, a format-1 record its chain value.
            let format = chain.history.get(&version).map_or(RecordFormat::V1, |step| step.format);
            let previous = if Some(version) == v0 {
                Some([0u8; 32])
            } else {
                chain.history.get(&(version - 1)).and_then(|step| match format {
                    RecordFormat::V2 => step.wire,
                    RecordFormat::V1 => Some(step.chain),
                })
            };
            match (previous, chain.history.get_mut(&version)) {
                (Some(previous), Some(step)) if crate::refresh_record::chain_value(&circle, &previous, &kept.digest) == step.chain => {
                    step.kept = Some(kept);
                }
                _ => tracing::warn!("Ignoring a kept record tag for circle {} v{} that matches no step of its history", circle_id, version),
            }
        }
    }
}

/// Read the refresh-record entries of the pins blob into chains, circle by
/// circle. A circle any of whose head, anchor, history or fact entries
/// doesn't read here (malformed, or written by an SDK that knows more), or
/// that has entries but no head (every write gives each circle one), is
/// latched and forked and holds nothing else: records stay required and it
/// waits. Its entries, all of them, go back exactly as stored (`as_stored`),
/// until it is left (`latched_only`) or the keys are cleared. A kept tag
/// that doesn't read or bind is dropped: that never loosens.
pub(crate) fn load_persisted(entries: Vec<(String, PinRecord)>) -> HashMap<CircleKey, CircleChain> {
    // By circle, in its one spelling (`CircleKey`), and within it by the
    // spelling each entry was stored under.
    let mut by_circle: HashMap<CircleKey, BTreeMap<String, Vec<(String, PinRecord)>>> = HashMap::new();
    for (key, record) in entries {
        let circle_id = circle_of_refresh_key(&key);
        // A personal key slot has no records: what an older SDK kept
        // for one, a latch included, is dropped here, so its rows
        // seal again. Its keys are no part of this state and stay as
        // they are.
        if crate::crypto::names_a_personal_slot(circle_id) {
            tracing::warn!("Dropping stored refresh-record state kept under a personal key slot");
            continue;
        }
        by_circle.entry(CircleKey::of(circle_id)).or_default().entry(circle_id.to_string()).or_default().push((key, record));
    }
    let mut chains = HashMap::new();
    for (circle, spellings) in by_circle {
        // Two spellings of one circle: their state is taken only if it
        // is the same state; a latch alone is carried by the other's
        // chain (every chain's head latches it). Anything else waits,
        // latched, as stored: a removal kept under any spelling
        // stands.
        let entries = match fold_spellings(&circle, spellings) {
            Ok(entries) => entries,
            Err(all) => {
                tracing::warn!(
                    "Two spellings of circle {} keep different record state: it waits, latched, and its entries are kept as stored",
                    circle
                );
                chains.insert(circle, CircleChain { latched: true, forked: true, as_stored: all, ..Default::default() });
                continue;
            }
        };
        let mut read = HashMap::new();
        let mut all_read = entries.iter().any(|(key, _)| key.starts_with(HEAD_PREFIX));
        for (key, record) in &entries {
            all_read &= absorb_persisted(&mut read, key, record);
        }
        if all_read && read.keys().all(|id| *id == circle) {
            chains.extend(read);
        } else {
            tracing::warn!(
                "The stored record state of circle {} doesn't read here: it waits, latched, and its entries are kept as stored",
                circle
            );
            chains.insert(circle, CircleChain { latched: true, forked: true, as_stored: entries, ..Default::default() });
        }
    }
    finish_persisted(&mut chains);
    chains
}

/// The entries one circle's record state is read from, when it was stored under
/// several spellings: the one spelling's, if every spelling kept the same state
/// (compared with each key in the one spelling) or a latch alone (a head at 0,
/// not forked, nothing else, exactly as a latch is written) that another's
/// chain carries. Anything else is an `Err` with every entry, to keep as
/// stored.
fn fold_spellings(circle: &CircleKey, spellings: BTreeMap<String, Vec<(String, PinRecord)>>) -> Result<Vec<(String, PinRecord)>, Vec<(String, PinRecord)>> {
    if spellings.len() == 1 {
        return Ok(spellings.into_values().next().unwrap_or_default());
    }
    let normalised = |spelled: &str, entries: &[(String, PinRecord)]| -> BTreeMap<String, (String, String, i64, i64, Option<i64>)> {
        entries
            .iter()
            .map(|(key, r)| {
                (
                    key.replacen(spelled, circle.as_str(), 1),
                    (r.sharing_pubkey_hex.clone(), r.signing_pubkey_hex.clone(), r.first_pinned_at, r.last_verified_at, r.user_approved_change_at),
                )
            })
            .collect()
    };
    // Exactly what `persisted_entries` writes for `CircleChain::latched_only`.
    let zeros = hex::encode([0u8; 32]);
    let latch_alone = |entries: &[(String, PinRecord)]| {
        matches!(entries, [(key, r)] if key.starts_with(HEAD_PREFIX)
            && r.sharing_pubkey_hex == zeros
            && r.signing_pubkey_hex == zeros
            && r.first_pinned_at == 0
            && r.last_verified_at == 0
            && r.user_approved_change_at.is_none())
    };
    let chains: Vec<(&String, &Vec<(String, PinRecord)>)> = spellings.iter().filter(|(_, entries)| !latch_alone(entries)).collect();
    let taken = match chains.as_slice() {
        // Latches alone: one latch.
        [] => spellings.iter().next(),
        [only] => Some(*only),
        [first, rest @ ..] => {
            let one = normalised(first.0, first.1);
            rest.iter().all(|(spelled, entries)| normalised(spelled, entries) == one).then_some(*first)
        }
    };
    match taken {
        Some((_, entries)) => Ok(entries.clone()),
        None => Err(spellings.into_values().flatten().collect()),
    }
}

/// The circle a refresh-record key names, whether its entry reads or not: the
/// id `absorb_persisted` files it under, and for a key that doesn't split, all
/// that follows the prefix.
fn circle_of_refresh_key(key: &str) -> &str {
    if let Some(circle_id) = key
        .strip_prefix(HEAD_PREFIX)
        .or_else(|| key.strip_prefix(ANCHOR_PREFIX))
        .or_else(|| key.strip_prefix(OWN_PREFIX))
        .or_else(|| key.strip_prefix(FORK_PREFIX))
    {
        return circle_id;
    }
    let rest = match key.strip_prefix(HISTORY_PREFIX) {
        Some(rest) => rest.strip_suffix(KEPT_TAG_SUFFIX).unwrap_or(rest),
        None => key
            .strip_prefix(FACT_PREFIX)
            .or_else(|| key.strip_prefix(KEYED_PREFIX))
            .or_else(|| key.strip_prefix(VOUCHED_PREFIX))
            .or_else(|| key.strip_prefix(WAIT_PREFIX))
            .or_else(|| key.strip_prefix(CARRIED_PREFIX))
            .or_else(|| key.strip_prefix(WIRE_PREFIX))
            .unwrap_or(key),
    };
    rest.rsplit_once(':').map_or(rest, |(circle_id, _)| circle_id)
}

/// Take a refresh-record entry of the pins blob into `chains`. False: a head,
/// anchor, history or fact entry that doesn't read (logged; see
/// `load_persisted`). A kept tag that doesn't read is dropped (logged).
pub(crate) fn absorb_persisted(chains: &mut HashMap<CircleKey, CircleChain>, key: &str, record: &PinRecord) -> bool {
    if let Some(circle_id) = key.strip_prefix(HEAD_PREFIX) {
        let (Some(chain_value), Some(digest), Some(version)) = (
            hex32(&record.sharing_pubkey_hex),
            hex32(&record.signing_pubkey_hex),
            u32_of(record.first_pinned_at),
        ) else {
            tracing::warn!("A malformed refresh-record head for {}", circle_id);
            return false;
        };
        let entry = chains.entry(CircleKey::of(circle_id)).or_default();
        entry.latched = true;
        entry.head = (version >= 1).then_some(ChainHead { version, chain: chain_value, digest });
        entry.forked = record.last_verified_at < 0;
        entry.sealing = u32_of(record.last_verified_at).unwrap_or(0);
        true
    } else if let Some(circle_id) = key.strip_prefix(ANCHOR_PREFIX) {
        let (Some(digest), Some(tag), Some(anchor), Some(v0)) = (
            hex32(&record.sharing_pubkey_hex),
            hex32(&record.signing_pubkey_hex),
            u32_of(record.first_pinned_at),
            u32_of(record.last_verified_at),
        ) else {
            tracing::warn!("A malformed refresh-record anchor for {}", circle_id);
            return false;
        };
        // A genesis anchors on its own version, a transition on the one before.
        if anchor == 0 || (anchor != v0 && anchor + 1 != v0) {
            tracing::warn!("A refresh-record anchor for {} that is neither V0 nor V0 - 1", circle_id);
            return false;
        }
        chains.entry(CircleKey::of(circle_id)).or_default().anchor = Some(AnchorCheck { v0, anchor, digest, tag });
        true
    } else if let Some(circle_id) = key.strip_prefix(OWN_PREFIX) {
        let wire = hex::decode(&record.sharing_pubkey_hex).ok().and_then(|bytes| WireRecord::parse(&bytes).ok());
        let circle = uuid16("circle_id", circle_id).ok();
        match wire.filter(|w| Some(w.body.circle_id) == circle && u32_of(record.first_pinned_at) == Some(w.body.version)) {
            Some(wire) => {
                chains.entry(CircleKey::of(circle_id)).or_default().own = Some(OwnRecord { wire });
                true
            }
            None => {
                tracing::warn!("A malformed own refresh record for {}", circle_id);
                false
            }
        }
    } else if let Some(rest) = key.strip_prefix(WIRE_PREFIX) {
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, version)| {
            let version: u32 = version.parse().ok()?;
            (u32_of(record.first_pinned_at) == Some(version) && version >= 1).then_some(())?;
            let format = u8::try_from(record.last_verified_at).ok().and_then(RecordFormat::from_code)?;
            Some((circle_id, version, (hex32(&record.sharing_pubkey_hex)?, hex32(&record.signing_pubkey_hex)?, format)))
        });
        let Some((circle_id, version, wire)) = parsed else {
            tracing::warn!("A malformed refresh-record step wire");
            return false;
        };
        chains.entry(CircleKey::of(circle_id)).or_default().loading_wires.insert(version, wire);
        true
    } else if let Some(circle_id) = key.strip_prefix(FORK_PREFIX) {
        // Whatever it holds: a latch that doesn't read still latches.
        chains.entry(CircleKey::of(circle_id)).or_default().fork_latched = true;
        true
    } else if let Some(rest) = key.strip_prefix(HISTORY_PREFIX).and_then(|rest| rest.strip_suffix(KEPT_TAG_SUFFIX)) {
        // A kept tag: bound to its step once the whole store is read.
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, version)| {
            let version: u32 = version.parse().ok()?;
            (u32_of(record.first_pinned_at) == Some(version) && version >= 1).then_some(())?;
            Some((circle_id, version, KeptTag { tag: hex32(&record.sharing_pubkey_hex)?, digest: hex32(&record.signing_pubkey_hex)? }))
        });
        match parsed {
            Some((circle_id, version, kept)) => {
                chains.entry(CircleKey::of(circle_id)).or_default().loading_tags.insert(version, kept);
            }
            None => tracing::warn!("Ignoring a malformed kept record tag"),
        }
        true
    } else if let Some(rest) = key.strip_prefix(HISTORY_PREFIX) {
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, version)| {
            let version: u32 = version.parse().ok()?;
            (u32_of(record.first_pinned_at) == Some(version) && version >= 1).then_some(())?;
            // Its format: 1 or 2; 0 from a store written by an older SDK:
            // not known (its `~rrx:`, if one binds, tells it); anything else
            // doesn't read.
            let format = match record.last_verified_at {
                0 => None,
                code => Some(RecordFormat::from_code(u8::try_from(code).ok()?)?),
            };
            Some((circle_id, version, hex32(&record.sharing_pubkey_hex)?, hex32(&record.signing_pubkey_hex)?, format))
        });
        match parsed {
            Some((circle_id, version, chain_value, signer, format)) => {
                let step = ChainStep {
                    chain: chain_value,
                    signer,
                    kept: None,
                    wire: None,
                    format: format.unwrap_or(RecordFormat::V1),
                    format_known: format.is_some(),
                };
                chains.entry(CircleKey::of(circle_id)).or_default().history.insert(version, step);
                true
            }
            None => {
                tracing::warn!("A malformed refresh-record history entry");
                false
            }
        }
    } else if let Some(rest) = key.strip_prefix(WAIT_PREFIX) {
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, version)| {
            let at: u32 = version.parse().ok()?;
            (u32_of(record.first_pinned_at) == Some(at) && at >= 1).then_some(())?;
            Some((circle_id, at, hex32(&record.sharing_pubkey_hex)?))
        });
        let Some((circle_id, at, waits)) = parsed else {
            tracing::warn!("A malformed refresh-record wait");
            return false;
        };
        chains.entry(CircleKey::of(circle_id)).or_default().waiting.insert(at, waits);
        true
    } else if let Some(rest) = key.strip_prefix(CARRIED_PREFIX) {
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, version)| {
            let at: u32 = version.parse().ok()?;
            (u32_of(record.first_pinned_at) == Some(at) && at >= 1 && record.last_verified_at == 1).then_some(())?;
            let chain_value = hex32(&record.sharing_pubkey_hex)?;
            Some((circle_id, at, Carried::decode(chain_value, &hex::decode(&record.signing_pubkey_hex).ok()?)?))
        });
        let Some((circle_id, at, carried)) = parsed else {
            tracing::warn!("A malformed refresh-record version passed over");
            return false;
        };
        chains.entry(CircleKey::of(circle_id)).or_default().loading_carried.insert(at, carried);
        true
    } else if let Some(rest) = key.strip_prefix(VOUCHED_PREFIX) {
        // Kept with its fact only at the same version; checked against the
        // fact's commitment where it's used. One that doesn't read is dropped.
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, code_hex)| {
            let keys = (hex32(&record.sharing_pubkey_hex)?, hex32(&record.signing_pubkey_hex)?);
            Some((circle_id, hex32(code_hex)?, u32_of(record.first_pinned_at).filter(|v| *v >= 1)?, keys))
        });
        match parsed {
            Some((circle_id, code, version, keys)) => {
                chains.entry(CircleKey::of(circle_id)).or_default().loading_vouched.insert(code, (version, keys));
            }
            None => tracing::warn!("Ignoring a malformed vouched-keys refresh-record entry"),
        }
        true
    } else if let Some(rest) = key.strip_prefix(KEYED_PREFIX) {
        // Read into a fact of its own, to be matched to the real one: one that
        // doesn't read is dropped, and its fact reads fail-closed.
        let parsed = rest.rsplit_once(':').and_then(|(circle_id, code_hex)| {
            let code = hex32(code_hex)?;
            (hex32(&record.sharing_pubkey_hex)? == code).then_some(())?;
            let keyed = MemberFact {
                version: u32_of(record.first_pinned_at).filter(|v| *v >= 1)?,
                commitment: hex32(&record.signing_pubkey_hex)?,
                last_spent: u32_of(record.last_verified_at)?,
                included_with_keys: u32_of(record.user_approved_change_at?)?,
                state: EntryState::Pending,
                role: ChainRole::Member,
                last_included: 0,
                departure_may_count: false,
                vouched_keys: None,
            };
            Some((circle_id, code, keyed))
        });
        match parsed {
            Some((circle_id, code, keyed)) => {
                chains.entry(CircleKey::of(circle_id)).or_default().loading_keyed.insert(code, keyed);
            }
            None => tracing::warn!("Ignoring a malformed keyed refresh-record fact"),
        }
        true
    } else if let Some(rest) = key.strip_prefix(FACT_PREFIX) {
        let Some((circle_id, code_hex)) = rest.rsplit_once(':') else {
            tracing::warn!("A malformed refresh-record fact");
            return false;
        };
        let packed = record.last_verified_at;
        let parsed = (|| {
            let code = hex32(code_hex)?;
            if hex32(&record.sharing_pubkey_hex)? != code {
                return None;
            }
            let mut fact = MemberFact {
                version: u32_of(record.first_pinned_at).filter(|v| *v >= 1)?,
                role: role_of(packed & 0xf)?,
                state: state_of((packed >> 4) & 0xf)?,
                departure_may_count: (packed >> 8) & 1 == 1,
                commitment: hex32(&record.signing_pubkey_hex)?,
                last_included: u32_of(record.user_approved_change_at.unwrap_or(0))?,
                included_with_keys: 0,
                last_spent: 0,
                vouched_keys: None,
            };
            // Until its `~rrk:` entry is matched to it (finish_persisted).
            fact.fail_closed_keyed_parts();
            Some((code, fact))
        })();
        match parsed {
            Some((code, fact)) if packed >> 9 == 0 => {
                chains.entry(CircleKey::of(circle_id)).or_default().facts.insert(code, fact);
                true
            }
            _ => {
                tracing::warn!("A malformed refresh-record fact for {}", circle_id);
                false
            }
        }
    } else {
        true
    }
}

// ============================================================================
// Members, statements and E
// ============================================================================

fn uuid16(field: &str, value: &str) -> Result<[u8; 16], MobileError> {
    uuid::Uuid::parse_str(value)
        .map(|u| *u.as_bytes())
        .map_err(|_| MobileError::InvalidInput(format!("{field} is not a UUID")))
}

fn key32(field: &str, value: &str) -> Result<[u8; 32], MobileError> {
    let bytes = hex::decode(value).map_err(|_| MobileError::InvalidInput(format!("{field} is not hex")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| MobileError::InvalidInput(format!("{field} must be 32 bytes")))
}

/// A statement the app holds, read.
#[derive(Debug, Clone)]
pub(crate) struct Statement {
    pub fields: MembershipStatement,
    pub bytes: Vec<u8>,
    pub signature: [u8; 64],
    pub signer: [u8; 16],
    pub subject: Option<[u8; 16]>,
}

/// A member, read (`RecordMember`).
#[derive(Debug, Clone)]
pub(crate) struct Member {
    pub user_id: String,
    pub uid: [u8; 16],
    pub sharing: [u8; 32],
    pub signing: [u8; 32],
    /// No published keys (a key None, read as zeros, or all zeros): listed,
    /// and nothing more. Neither key is used then, whatever the other holds.
    pub no_published_keys: bool,
    /// False with no published keys, whatever the app passed.
    pub confirmed: bool,
    pub listed: bool,
    pub listed_role: Option<ChainRole>,
    pub statements: Vec<Statement>,
    pub person_confirmed_keys: bool,
    pub server_says_keyless: bool,
}

impl Member {
    pub(crate) fn read(member: &RecordMember) -> Result<Self, MobileError> {
        let mut statements = Vec::new();
        for held in &member.statements {
            // A statement that does not even parse is simply not evidence.
            let (Ok(bytes), Ok(signature)) = (hex::decode(&held.statement_hex), hex::decode(&held.signature_hex)) else {
                continue;
            };
            let (Ok(fields), Ok(signature)) = (decode_statement(&bytes), <[u8; 64]>::try_from(signature.as_slice())) else {
                continue;
            };
            let Ok(signer) = uuid16("signer_user_id", &fields.signer_user_id) else {
                continue;
            };
            let subject = fields.subject_user_id.as_deref().and_then(|s| uuid16("subject_user_id", s).ok());
            statements.push(Statement { fields, bytes, signature, signer, subject });
        }
        let key = |field: &str, value: &Option<String>| value.as_deref().map(|hex| key32(field, hex)).transpose();
        let sharing = key("sharing_public_key_hex", &member.sharing_public_key_hex)?.unwrap_or([0u8; 32]);
        let signing = key("signing_public_key_hex", &member.signing_public_key_hex)?.unwrap_or([0u8; 32]);
        let no_published_keys = sharing == [0u8; 32] || signing == [0u8; 32];
        Ok(Member {
            user_id: member.user_id.clone(),
            uid: uuid16("user_id", &member.user_id)?,
            sharing,
            signing,
            no_published_keys,
            confirmed: member.confirmed && !no_published_keys,
            listed: member.listed,
            listed_role: member.listed_role.map(ChainRole::from),
            statements,
            person_confirmed_keys: member.person_confirmed_keys,
            server_says_keyless: member.server_says_keyless,
        })
    }
}

/// The removals that count in the records rejected here since the head, each
/// with the version of the latest record that made it: x's last word
/// (last(x)) at that version until a repair is accepted.
pub(crate) type Overlay = HashMap<[u8; 32], u32>;

/// Roles a record rejected here only for R2 gave its members: the record after
/// it is built and judged against them. A record rejected for anything else
/// moves no role.
pub(crate) type RoleOverlay = HashMap<[u8; 32], ChainRole>;

/// This account's own keys from before a password reset, recovered in the
/// account portal, with its own row. A record the account signed before the
/// reset commits to those keys, so its OWN entry, and only that, is also
/// matched through them, by the chain's commitment alone: as the signer, and
/// in R2 and `reinclusions_eligible` for its own inclusion. Never to verify a
/// head or a statement (a statement verifies only under its signer's
/// confirmed key), and never to confirm, vouch for or attribute anything to
/// anyone else.
pub(crate) struct OwnRestored {
    /// The own row: the one confirmed, listed row carrying this device's
    /// CURRENT keys.
    pub row: Member,
    /// Each recovered identity's (sharing, signing) public keys
    /// (`previous_key_pairs`).
    pub pairs: Vec<([u8; 32], [u8; 32])>,
}

impl OwnRestored {
    /// The own row with a recovered pair's keys in place of the current ones,
    /// when `code` is this account's and `commitment` is that pair's: who the
    /// chain committed to there. E and `reinclusions_eligible` judge that row,
    /// so the chain's own count (or an admission binding those keys) holds
    /// for it.
    pub(crate) fn as_committed(&self, secret: &[u8; 32], code: &[u8; 32], commitment: &[u8; 32]) -> Option<Member> {
        if member_code(secret, &self.row.uid) != *code {
            return None;
        }
        self.pairs
            .iter()
            .find(|(sharing, signing)| key_commitment(secret, code, sharing, signing) == *commitment)
            .map(|(sharing, signing)| Member { sharing: *sharing, signing: *signing, ..self.row.clone() })
    }
}

/// The chain as a reference R: the facts as of a record, and what reads them.
pub(crate) struct View<'a> {
    pub circle: [u8; 16],
    pub secret: &'a [u8; 32],
    /// The version of the circle's first record.
    pub v0: u32,
    pub facts: &'a HashMap<[u8; 32], MemberFact>,
    /// Removals that count in a rejected record the next one repairs, at
    /// their versions: the repair is judged with both records' removals
    /// applied.
    pub removed_overlay: &'a Overlay,
    /// Roles moved by the records rejected here only for R2 since the
    /// head: the chain's roles, over the last accepted record's.
    pub role_overlay: &'a RoleOverlay,
    pub members: &'a [Member],
    /// This account's recovered pre-reset pairs (`OwnRestored`), for its
    /// own entry in R2 and `reinclusions_eligible`. None where nothing is
    /// judged (E for the app, the builder).
    pub own: Option<&'a OwnRestored>,
}

impl<'a> View<'a> {
    pub(crate) fn code_of(&self, uid: &[u8; 16]) -> [u8; 32] {
        member_code(self.secret, uid)
    }

    pub(crate) fn commitment_of(&self, code: &[u8; 32], member: &Member) -> [u8; 32] {
        key_commitment(self.secret, code, &member.sharing, &member.signing)
    }

    fn fact(&self, code: &[u8; 32]) -> Option<&'a MemberFact> {
        self.facts.get(code)
    }

    fn listed(&self, uid: &[u8; 16]) -> bool {
        self.members.iter().any(|m| &m.uid == uid && m.listed)
    }

    /// Whether the chain counts this code here: its last word is not a
    /// removal that counts, nor a departure while they are off this device's
    /// complete list.
    fn counts(&self, code: &[u8; 32], listed: bool) -> bool {
        if self.removed_overlay.contains_key(code) {
            return false;
        }
        match self.fact(code) {
            None => false,
            Some(fact) => match fact.state {
                EntryState::Removed => false,
                EntryState::Departed => listed || !fact.departure_may_count,
                EntryState::Included | EntryState::Pending => true,
            },
        }
    }

    /// Whether the chain counts this code here, with the listed flag of the
    /// member this device knows by it (none known: off the list).
    fn counts_code(&self, code: &[u8; 32]) -> bool {
        let listed = self.members.iter().any(|m| m.listed && &self.code_of(&m.uid) == code);
        self.counts(code, listed)
    }

    /// The chain role of the member coded `code`, counted or not: the one
    /// a record rejected here only for R2 gave them since the head, else
    /// their last accepted record's. None: the chain never named them.
    fn role_here(&self, code: &[u8; 32]) -> Option<ChainRole> {
        self.role_overlay.get(code).copied().or_else(|| self.fact(code).map(|f| f.role))
    }

    /// The role an entry for `code` carries over when the record names none:
    /// the chain's role here, or "member" for someone it never named.
    pub(crate) fn carried_role(&self, code: &[u8; 32]) -> ChainRole {
        self.role_here(code).unwrap_or(ChainRole::Member)
    }

    /// The chain role of the member with user id `uid`, if the chain counts them.
    pub(crate) fn role_of(&self, uid: &[u8; 16]) -> Option<ChainRole> {
        let code = self.code_of(uid);
        self.counts(&code, self.listed(uid)).then(|| self.role_here(&code)).flatten()
    }

    /// The chain role of the member coded `code`, if the chain counts them.
    pub(crate) fn role_of_code(&self, code: &[u8; 32]) -> Option<ChainRole> {
        self.counts_code(code).then(|| self.role_here(code)).flatten()
    }

    fn is_owner_or_admin(&self, uid: &[u8; 16]) -> bool {
        matches!(self.role_of(uid), Some(ChainRole::Owner | ChainRole::Admin))
    }

    /// Whether `statement` verifies under the signing key this device confirms
    /// for its signer. A statement that verifies only under an older key of its
    /// signer does not: it never satisfies (b) or (c).
    fn verifies(&self, statement: &Statement) -> bool {
        let Some(signer) = self.members.iter().find(|m| m.uid == statement.signer && m.confirmed) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&signer.signing) else {
            return false;
        };
        key.verify_strict(&statement_digest(&statement.bytes), &Signature::from_bytes(&statement.signature))
            .is_ok()
    }

    /// Whether `statement` is about `member`, with exactly their keys, in this circle.
    fn binds(&self, statement: &Statement, member: &Member) -> bool {
        let fields = &statement.fields;
        uuid16("circle_id", &fields.circle_id).map_or(false, |c| c == self.circle)
            && statement.subject == Some(member.uid)
            && fields.subject_sharing_public_key_hex.as_deref().and_then(|k| key32("k", k).ok()) == Some(member.sharing)
            && fields.subject_signing_public_key_hex.as_deref().and_then(|k| key32("k", k).ok()) == Some(member.signing)
    }

    /// E for `member`.
    /// - `when`: the moment the key is handed over (for R2, the record's
    ///   `issued_at`; None when that is too far in the future to date
    ///   anything).
    /// - `deliver`: E_deliver instead of E_include.
    pub(crate) fn eligibility(&self, member: &Member, when: Option<i64>, deliver: bool) -> MemberEligibility {
        let code = self.code_of(&member.uid);
        let fact = self.fact(&code);
        let counted = self.counts(&code, member.listed);
        // last(x): the last record that named them, or a counting removal in a
        // record rejected here since, at its version.
        let overlay_removal = self.removed_overlay.get(&code).copied();
        let last_named = fact.map_or(0, |f| f.version).max(overlay_removal.unwrap_or(0));
        let mut out = MemberEligibility {
            user_id: member.user_id.clone(),
            eligible: false,
            basis: None,
            invitation_expired: false,
            invitation_signer_not_chain_admin: false,
            removed_by_owner_or_admin: fact.map_or(false, |f| f.state == EntryState::Removed)
                || overlay_removal.is_some(),
            removed_at_version: fact
                .filter(|f| f.state == EntryState::Removed)
                .map(|f| f.version)
                .into_iter()
                .chain(overlay_removal)
                .max()
                .and_then(|v| i32::try_from(v).ok()),
            email_invitation_without_signed_id: false,
        };
        if !member.confirmed {
            return out;
        }
        // Only now: a member with no published keys is never confirmed, and
        // gets no commitment.
        let commitment = self.commitment_of(&code, member);
        // (a) the chain counts them here, with exactly these keys,
        // which a record this device accepted included: a pending
        // carry of keys a rejected record named never counts on its
        // own.
        if counted && fact.map_or(false, |f| f.commitment == commitment && f.included_with_keys > 0) {
            out.eligible = true;
            out.basis = Some(EligibilityBasis::CountedByChain);
            return out;
        }
        // (b) an admission for these keys, by an owner or admin in the chain,
        // made at or after the last record that named them, and at or after
        // the circle's first record.
        for statement in &member.statements {
            if statement.fields.kind == MembershipStatementKind::Admission
                && self.binds(statement, member)
                && self.verifies(statement)
                && self.is_owner_or_admin(&statement.signer)
                && statement.fields.at_version >= 0
                && statement.fields.at_version as u32 >= last_named
                && statement.fields.at_version as u32 >= self.v0
            {
                out.eligible = true;
                out.basis = Some(EligibilityBasis::Admission);
                return out;
            }
        }
        // (c) an invitation for these keys, by an owner or admin in the chain,
        // that no record since its `at_version` names included, removed or
        // departed, unexpired (with the grace) when the key is handed over,
        // and, for a delivery, the server says they hold no key. An address
        // (kind-2) invitation signs no user id, and the absence needs one: it
        // counts only alongside a kind-1 or kind-3 statement that an owner or
        // admin in the chain signed, binding their user id and keys, and that
        // holds up here; its keys are the ones recorded for them.
        let in_circle = |statement: &Statement| uuid16("circle_id", &statement.fields.circle_id).map_or(false, |c| c == self.circle);
        // A record that named them included, removed or departed
        // after the invitation's `at_version` spends it; a pending
        // carry doesn't, its writer had no key to give.
        let spent_at = fact.map_or(0, |f| f.last_spent).max(overlay_removal.unwrap_or(0));
        let signed_id = member.statements.iter().any(|statement| {
            matches!(statement.fields.kind, MembershipStatementKind::InvitationToAccount | MembershipStatementKind::Admission)
                && self.binds(statement, member)
                && self.verifies(statement)
                && self.is_owner_or_admin(&statement.signer)
        });
        for statement in &member.statements {
            let about_them = match statement.fields.kind {
                MembershipStatementKind::InvitationToAccount => self.binds(statement, member),
                MembershipStatementKind::InvitationToEmail => in_circle(statement),
                MembershipStatementKind::Admission => false,
            };
            if !about_them || !self.verifies(statement) || spent_at > statement.fields.at_version.max(0) as u32 {
                continue;
            }
            if statement.fields.kind == MembershipStatementKind::InvitationToEmail && !signed_id {
                out.email_invitation_without_signed_id = true;
                continue;
            }
            let unexpired = when.map_or(false, |t| t <= statement.fields.expires_at + INVITATION_EXPIRY_GRACE_SECS);
            if !unexpired {
                out.invitation_expired = true;
                continue;
            }
            if !self.is_owner_or_admin(&statement.signer) {
                out.invitation_signer_not_chain_admin = true;
                continue;
            }
            if deliver && !member.server_says_keyless {
                continue;
            }
            out.eligible = true;
            out.basis = Some(EligibilityBasis::Invitation);
            return out;
        }
        // (d) DELIVER only: the chain still counts them, with other keys, and
        // this device's own person confirmed their current keys.
        if deliver && counted && member.person_confirmed_keys {
            out.eligible = true;
            out.basis = Some(EligibilityBasis::PersonConfirmed);
        }
        out
    }
}

// ============================================================================
// R1 and R2 on one record
// ============================================================================

/// What the record before this one looked like, for the rules that read it.
pub(crate) struct Previous<'a> {
    pub version: u32,
    /// Its format: formats only go up within a circle.
    pub format: RecordFormat,
    /// The record itself when this device holds it (always, for a rejected one).
    pub body: Option<&'a RecordBody>,
    /// Whether that record was rejected here (a repair links to it).
    pub rejected: bool,
    /// Rejected here as MISATTRIBUTED: no inclusion in it moves.
    pub misattributed: bool,
}

/// The entry for `code` in the chain before this record: the facts, or the
/// rejected record this one repairs.
fn named<'a>(facts: &'a HashMap<[u8; 32], MemberFact>, previous: &'a Previous, code: &[u8; 32]) -> Option<[u8; 32]> {
    if previous.rejected {
        if let Some(entry) = previous.body.and_then(|b| b.entry(code)) {
            return Some(entry.commitment);
        }
    }
    facts.get(code).map(|f| f.commitment)
}

/// The list a record must cover: everyone the record before included or
/// carried pending (from the record when this device holds it, else from
/// the facts it left).
fn named_before(facts: &HashMap<[u8; 32], MemberFact>, previous: &Previous) -> Vec<[u8; 32]> {
    match previous.body {
        Some(prev) => prev
            .entries
            .iter()
            .filter(|e| matches!(e.state, EntryState::Included | EntryState::Pending))
            .map(|e| e.code)
            .collect(),
        None => facts
            .iter()
            .filter(|(_, f)| f.version == previous.version && matches!(f.state, EntryState::Included | EntryState::Pending))
            .map(|(c, _)| *c)
            .collect(),
    }
}

/// The format's rules that need the chain before this record (everyone
/// the record before named appears; who may be carried over, removed or
/// seen gone; what a departure may name; and the floor for `link_to`, with
/// the anchor's), and the rule that formats only go up within a circle.
pub(crate) fn check_against_previous(
    body: &RecordBody,
    facts: &HashMap<[u8; 32], MemberFact>,
    removed_overlay: &Overlay,
    previous: &Previous,
    anchor: u32,
) -> Result<(), RecordProblem> {
    if body.format < previous.format {
        tracing::warn!("refresh record v{} is in format 1 after a format-2 record: refused", body.version);
        return Err(RecordProblem::Structure);
    }
    // Everyone included or pending in the record before appears.
    if named_before(facts, previous).iter().any(|code| body.entry(code).is_none()) {
        tracing::warn!("refresh record v{} drops a member of the record before it", body.version);
        return Err(RecordProblem::Structure);
    }
    // Anyone carried over, removed or seen gone must be someone the chain
    // has named, with its last commitment, and a pending entry never carries
    // someone a counting removal took out.
    for entry in &body.entries {
        if entry.state == EntryState::Included {
            continue;
        }
        match named(facts, previous, &entry.code) {
            Some(commitment) if commitment == entry.commitment => {}
            _ => {
                tracing::warn!("refresh record v{} carries a member the chain never named with those keys", body.version);
                return Err(RecordProblem::Structure);
            }
        }
        let removed = facts.get(&entry.code).map_or(false, |f| f.state == EntryState::Removed)
            || removed_overlay.contains_key(&entry.code);
        if entry.state == EntryState::Pending && removed {
            tracing::warn!("refresh record v{} carries a removed member over as pending", body.version);
            return Err(RecordProblem::Structure);
        }
    }
    // The floor on link_to: at least the last version whose record included
    // the signer, and never below the anchor.
    // A record rejected as MISATTRIBUTED moves no inclusion: its key may
    // reach nobody, and a repair then goes from below.
    let mut floor = facts.get(&body.signer_code).map_or(0, |f| f.last_included);
    if previous.rejected
        && !previous.misattributed
        && previous.body.and_then(|b| b.entry(&body.signer_code)).map_or(false, |e| e.state == EntryState::Included)
    {
        floor = previous.version;
    }
    if body.link_to < floor.max(anchor) {
        tracing::warn!(
            "refresh record v{} links down to v{}, below its floor v{} (anchor v{})",
            body.version, body.link_to, floor, anchor
        );
        return Err(RecordProblem::Floor);
    }
    Ok(())
}

/// The removals that count in a record refused for its roles or removals: when
/// only this device's list kept its owner claim from holding (the list doesn't
/// show its signer as owner: the server's word), those its signer may make as
/// an admin, of anyone but the chain's owner, counting at its version as a
/// rejected record's removals do; else none. The claim and its role changes
/// move nothing.
fn removals_of_a_refused_claim(view: &View, body: &RecordBody) -> HashSet<[u8; 32]> {
    if check_authority(view, body, Some(ChainRole::Owner)).is_err()
        || !matches!(view.role_of_code(&body.signer_code), Some(ChainRole::Owner | ChainRole::Admin))
    {
        return HashSet::new();
    }
    body.entries
        .iter()
        .filter(|e| e.state == EntryState::Removed && view.role_here(&e.code) != Some(ChainRole::Owner))
        .map(|e| e.code)
        .collect()
}

/// The member this device confirms, other than the signer it found (whose
/// signing key is `found`), whose key verifies `signature` over `wire`: a
/// misattribution.
fn misattributed_to<'m>(members: &'m [Member], wire: &WireRecord, signature: &[u8; 64], found: &[u8; 32]) -> Option<&'m Member> {
    members.iter().filter(|m| m.confirmed && m.signing != *found).find(|m| wire.signature_verifies(signature, &m.signing))
}

/// The removals that count in a misattributed record: those the role and
/// removal rules give its signer CODE by that code's role in the chain (with
/// no listed role: the list is the server's word), counting at its version as
/// a rejected record's removals do; beyond that right, only an admin's, as for
/// a refused owner claim. Nothing else in it moves.
fn removals_by_its_signer_code(view: &View, body: &RecordBody) -> HashSet<[u8; 32]> {
    match check_authority(view, body, None) {
        Ok(()) if matches!(view.role_of_code(&body.signer_code), Some(ChainRole::Owner | ChainRole::Admin)) => {
            body.entries.iter().filter(|e| e.state == EntryState::Removed).map(|e| e.code).collect()
        }
        Ok(()) => HashSet::new(),
        Err(_) => removals_of_a_refused_claim(view, body),
    }
}

/// Roles and removals: a hard refusal when they fail. `signer_listed_role`:
/// the role this device's list gives the signer, when it can match them (an
/// owner claim needs it; none: no claim).
pub(crate) fn check_authority(view: &View, body: &RecordBody, signer_listed_role: Option<ChainRole>) -> Result<(), RecordProblem> {
    let signer_role = view.role_of_code(&body.signer_code);
    let signer_is_owner = signer_role == Some(ChainRole::Owner);
    let signer_may_remove = matches!(signer_role, Some(ChainRole::Owner | ChainRole::Admin));
    // The chain's owner before this record: the owner entry the chain
    // still counts here, if any (an owner that is gone leaves none). One
    // named only by a record rejected here for R2 is the owner too, and
    // not gone: the chain here never named them, so only a counting
    // removal (the removed overlay) could have taken them out.
    let old_owner = view
        .facts
        .keys()
        .chain(view.role_overlay.keys())
        .filter(|c| view.role_here(c) == Some(ChainRole::Owner))
        .copied()
        .find(|c| view.counts_code(c) || (view.fact(c).is_none() && !view.removed_overlay.contains_key(c)));
    // The owner claim (`owner_claim`): an admin in the chain who is the
    // owner in this device's list may name ITSELF owner, in the record
    // that removes the old owner or once the old owner is gone, and
    // change roles in that record.
    let removes_old_owner = old_owner.map_or(false, |c| body.entry(&c).map_or(false, |e| e.state == EntryState::Removed));
    let old_owner_gone = old_owner.is_none();
    let owner_claim = signer_role == Some(ChainRole::Admin)
        && signer_listed_role == Some(ChainRole::Owner)
        && (removes_old_owner || old_owner_gone)
        && body.entry(&body.signer_code).map_or(false, |e| e.role == ChainRole::Owner);
    if !signer_is_owner && !owner_claim {
        for entry in &body.entries {
            let expected = view.carried_role(&entry.code);
            if entry.role != expected {
                tracing::warn!("refresh record v{} changes a role without the right", body.version);
                return Err(RecordProblem::Role);
            }
        }
    }
    for entry in body.entries.iter().filter(|e| e.state == EntryState::Removed) {
        let target_is_owner = view.role_here(&entry.code) == Some(ChainRole::Owner);
        if !signer_may_remove || (target_is_owner && !owner_claim) {
            tracing::warn!("refresh record v{} removes a member without the right", body.version);
            return Err(RecordProblem::Removal);
        }
    }
    Ok(())
}

/// What R2 found, besides the hard refusals.
#[derive(Debug, Default)]
pub(crate) struct R2Outcome {
    pub not_allowed: Vec<String>,
    /// The codes of the entries in `not_allowed`.
    pub not_allowed_codes: Vec<[u8; 32]>,
    pub unmatched: u32,
}

/// R2: everyone the record includes matches a member this device confirms,
/// who is eligible here (E_include, as of the record). For a first record,
/// confirmed (and not tombstoned, which the app's `confirmed` already means)
/// is enough.
pub(crate) fn check_included(view: &View, body: &RecordBody, now: i64) -> R2Outcome {
    let mut out = R2Outcome::default();
    let when = record_when(body, now);
    let first = matches!(body.kind, RecordKind::Genesis | RecordKind::Transition);
    for entry in body.entries.iter().filter(|e| e.state == EntryState::Included) {
        let row = view.members.iter().filter(|m| m.confirmed).find(|m| {
            let code = view.code_of(&m.uid);
            code == entry.code && view.commitment_of(&code, m) == entry.commitment
        });
        // Recovered pre-reset pairs (`OwnRestored`): this account's own entry
        // under such a pair, by the commitment alone; E then judges the own row
        // with that pair's keys, the ones the chain committed to.
        let pair_row = if row.is_none() { view.own.and_then(|own| own.as_committed(view.secret, &entry.code, &entry.commitment)) } else { None };
        let matched = row.or(pair_row.as_ref());
        // An entry that continues this device's own count passes with
        // no row: a code this device counts by E (a), with the same
        // commitment, through an inclusion taken here. It names no one
        // new, and a member who has left since is on no list.
        let continues_the_count = || {
            view.counts(&entry.code, false)
                && view.fact(&entry.code).map_or(false, |f| f.commitment == entry.commitment && f.included_with_keys > 0)
        };
        match matched {
            None if !first && continues_the_count() => {}
            None => out.unmatched += 1,
            Some(member) if !first && !view.eligibility(member, when, false).eligible => {
                out.not_allowed.push(member.user_id.clone());
                out.not_allowed_codes.push(entry.code);
            }
            Some(_) => {}
        }
    }
    out
}

/// Apply an accepted (or reference) record to the facts.
///
/// A "removed" fact counts (every record that carries one passed the role
/// and removal check), and only an `included` entry, which passed R2,
/// replaces it: a later "departed" or "pending" entry for that code changes
/// nothing.
pub(crate) fn apply(facts: &mut HashMap<[u8; 32], MemberFact>, body: &RecordBody, signer_role_before: Option<ChainRole>, roles_before: &RoleOverlay) {
    let signer_may_remove = matches!(signer_role_before, Some(ChainRole::Owner | ChainRole::Admin))
        || matches!(body.kind, RecordKind::Genesis | RecordKind::Transition);
    for entry in &body.entries {
        let previous = facts.get(&entry.code).cloned();
        if previous.as_ref().map_or(false, |p| p.state == EntryState::Removed)
            && matches!(entry.state, EntryState::Departed | EntryState::Pending)
        {
            continue;
        }
        let role_before = roles_before.get(&entry.code).copied().or_else(|| previous.as_ref().map(|p| p.role)).unwrap_or(entry.role);
        let departure_may_count =
            entry.state != EntryState::Departed || signer_may_remove || role_before == ChainRole::Member;
        let (included_with_keys, last_spent, vouched_keys) = MemberFact::keyed_after(previous.as_ref(), entry, body.version);
        facts.insert(
            entry.code,
            MemberFact {
                version: body.version,
                state: entry.state,
                role: entry.role,
                commitment: entry.commitment,
                last_included: if entry.state == EntryState::Included {
                    body.version
                } else {
                    previous.map_or(0, |p| p.last_included)
                },
                departure_may_count,
                included_with_keys,
                last_spent,
                vouched_keys,
            },
        );
    }
}

/// Apply a record accepted after `after` (the last accepted version), and
/// with it the removals that count in the records rejected in between, as
/// "removed" at their own version, unless this record includes the member
/// (it passed R2): the importer keeps them, whoever repairs.
pub(crate) fn apply_accepted(
    facts: &mut HashMap<[u8; 32], MemberFact>,
    seen: &BTreeMap<u32, SeenRecord>,
    after: u32,
    body: &RecordBody,
    signer_role_before: Option<ChainRole>,
) {
    // The roles it was judged against: those the records rejected in
    // between only for R2 moved.
    let roles_before: RoleOverlay = seen
        .range(after.saturating_add(1)..body.version)
        .map(|(_, record)| record)
        .filter(|record| record.state == RecordVersionState::Rejected && record.moves_roles)
        .flat_map(|record| record.wire.body.entries.iter().map(|e| (e.code, e.role)))
        .collect();
    apply(facts, body, signer_role_before, &roles_before);
    for rejected in seen
        .range(after.saturating_add(1)..body.version)
        .map(|(_, record)| record)
        .filter(|record| record.state == RecordVersionState::Rejected)
    {
        for code in &rejected.counting_removals {
            if body.entry(code).map_or(false, |e| e.state == EntryState::Included) {
                continue;
            }
            let Some(entry) = rejected.wire.body.entry(code) else {
                continue;
            };
            let last_included = facts.get(code).map_or(0, |f| f.last_included);
            let (included_with_keys, last_spent, vouched_keys) = MemberFact::keyed_after(facts.get(code), &crate::refresh_record::RecordEntry { state: EntryState::Removed, ..entry.clone() }, rejected.wire.body.version);
            facts.insert(
                *code,
                MemberFact {
                    version: rejected.wire.body.version,
                    state: EntryState::Removed,
                    role: entry.role,
                    commitment: entry.commitment,
                    last_included,
                    departure_may_count: true,
                    included_with_keys,
                    last_spent,
                    vouched_keys,
                },
            );
        }
    }
}

/// Keep, for each code a record this device accepted includes, the keys of the
/// confirmed row that entry matched (its code and commitment): R1 finds with
/// them a signer the app no longer lists (`signer_of`).
pub(crate) fn vouch_included_keys(facts: &mut HashMap<[u8; 32], MemberFact>, body: &RecordBody, secret: &[u8; 32], members: &[Member]) {
    for entry in body.entries.iter().filter(|e| e.state == EntryState::Included) {
        let Some(fact) = facts.get_mut(&entry.code).filter(|f| f.version == body.version && f.commitment == entry.commitment) else {
            continue;
        };
        let row = members.iter().filter(|m| m.confirmed && !m.no_published_keys).find(|m| {
            let code = member_code(secret, &m.uid);
            code == entry.code && key_commitment(secret, &code, &m.sharing, &m.signing) == entry.commitment
        });
        if let Some(row) = row {
            fact.vouched_keys = Some((row.sharing, row.signing));
        }
    }
}

/// Every entry `body` includes whose code the chain has as a counting
/// "removed" (or a record it follows removed, the overlay) is a member this
/// device lists and confirms who is eligible by E's (b) or (c): an admission
/// or invitation made after the removal. ((a) never holds for a removed
/// member, and (d) is for deliveries.)
pub(crate) fn reinclusions_eligible(view: &View, body: &RecordBody, when: Option<i64>) -> bool {
    body.entries.iter().filter(|e| e.state == EntryState::Included).all(|entry| {
        let removed = view.facts.get(&entry.code).map_or(false, |f| f.state == EntryState::Removed)
            || view.removed_overlay.contains_key(&entry.code);
        if !removed {
            return true;
        }
        let row = view.members
            .iter()
            .filter(|m| m.listed && m.confirmed)
            .find(|m| view.code_of(&m.uid) == entry.code && view.commitment_of(&entry.code, m) == entry.commitment);
        // As in R2: the own entry under a recovered pre-reset pair
        // (`OwnRestored`), judged with that pair's keys; a statement
        // still verifies only under its signer's confirmed key.
        let pair_row = if row.is_none() { view.own.and_then(|own| own.as_committed(view.secret, &entry.code, &entry.commitment)) } else { None };
        row.or(pair_row.as_ref()).map_or(false, |member| view.eligibility(member, when, false).eligible)
    })
}

/// R2's "when" for a record: its `issued_at`, unless that is more than the
/// skew ahead of `now`.
fn record_when(body: &RecordBody, now: i64) -> Option<i64> {
    (i64::try_from(body.issued_at).map_or(false, |t| t <= now + ISSUED_AT_SKEW_SECS)).then(|| body.issued_at as i64)
}

// ============================================================================
// The key-chain walk and the circle's secret
// ============================================================================

/// Open a key-chain link with the key it is sealed under.
pub(crate) fn open_link(from_key: &[u8], link: &KeyChainLinkData) -> Option<Zeroizing<Vec<u8>>> {
    let nonce = <[u8; 24]>::try_from(hex::decode(&link.nonce).ok()?.as_slice()).ok()?;
    let cipher = XChaCha20Poly1305::new_from_slice(from_key).ok()?;
    let plain = Zeroizing::new(cipher.decrypt(&XNonce::from(nonce), hex::decode(&link.encrypted_key).ok()?.as_ref()).ok()?);
    (plain.len() == 32).then_some(plain)
}

/// Whether a link from `from` down to `to` may be taken: one version down, or
/// the step a record this device holds names in `link_to`, and never
/// below the anchor for more than one step.
pub(crate) fn step_allowed(seen: &BTreeMap<u32, SeenRecord>, anchor: u32, from: u32, to: u32) -> bool {
    if to == 0 || to >= from {
        return false;
    }
    if from - 1 == to {
        return true;
    }
    to >= anchor && seen.get(&from).map_or(false, |r| r.wire.body.link_to == to)
}

/// A key the walk reached. `checked`: its version's record is held here and
/// its tag verified the key; only such a key may be stored.
pub(crate) struct WalkedKey {
    pub version: u32,
    pub key: Zeroizing<Vec<u8>>,
    pub checked: bool,
}

/// Walk the chain down from the held keys to the anchor. Every step whose
/// version has a record this device holds must verify that record's tag;
/// the anchor's key must verify the anchor check. Returns the anchor's
/// key and every key the walk reached on the way, or None; `checked`
/// marks the ones a record's tag or the anchor check verified.
pub(crate) fn walk_to_anchor(
    anchor: &AnchorCheck,
    held: &[(u32, Zeroizing<Vec<u8>>)],
    links: &[KeyChainLinkData],
    seen: &BTreeMap<u32, SeenRecord>,
) -> Option<(Zeroizing<Vec<u8>>, Vec<WalkedKey>)> {
    let anchor_ok = |key: &[u8]| anchor.key_ok(key);
    let record_ok = |version: u32, key: &[u8]| seen.get(&version).map_or(true, |r| r.wire.key_tag_matches(key));
    // Newest held key first.
    let mut starts: Vec<&(u32, Zeroizing<Vec<u8>>)> = held.iter().filter(|(v, _)| *v >= anchor.anchor).collect();
    starts.sort_by(|a, b| b.0.cmp(&a.0));
    for (start_version, start_key) in starts {
        if !record_ok(*start_version, start_key) {
            continue;
        }
        let mut version = *start_version;
        let mut key = start_key.clone();
        let mut walked: Vec<WalkedKey> = Vec::new();
        loop {
            if version == anchor.anchor {
                if anchor_ok(&key) {
                    // A transition's anchor has no record:
                    // its anchor tag vouches for the key
                    // instead.
                    if let Some(reached) = walked.last_mut().filter(|w| w.version == anchor.anchor) {
                        reached.checked = true;
                    }
                    return Some((key, walked));
                }
                break;
            }
            let mut next = None;
            for link in links.iter().filter(|l| l.from_version >= 1 && l.from_version as u32 == version) {
                let Ok(to) = u32::try_from(link.to_version) else { continue };
                if to < anchor.anchor || !step_allowed(seen, anchor.anchor, version, to) {
                    continue;
                }
                if let Some(opened) = open_link(&key, link) {
                    if record_ok(to, &opened) {
                        next = Some((to, opened));
                        break;
                    }
                }
            }
            let Some((to, opened)) = next else { break };
            walked.push(WalkedKey { version: to, key: opened.clone(), checked: seen.contains_key(&to) });
            version = to;
            key = opened;
        }
    }
    None
}

/// S from the anchor key.
pub(crate) fn secret_from(anchor_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, MobileError> {
    circle_secret(anchor_key)
}

// ============================================================================
// The CryptoManager side: key maps, the secret, the import (internal)
// ============================================================================

use crate::crypto::CryptoManager;
use crate::refresh_record::Head;

/// What `import_key_chain_link` may do with a link on this device.
pub(crate) enum LinkRule {
    /// A legacy circle, or a step into a version below the circle's anchor:
    /// a link steps exactly one version down.
    Legacy,
    /// Refused, and why (for the log).
    Refuse(&'static str),
    /// Allowed; the key it yields must pass this check.
    Checked(LinkCheck),
}

/// What vouches for the key a link yields: the tag of the version's record,
/// or, for a step onto the anchor, the anchor tag.
pub(crate) enum LinkCheck {
    /// The tag of the version's own record.
    Record(WireRecord),
    /// A transition's anchor tag: a step onto the anchor A, which has no record.
    Anchor(AnchorCheck),
}

impl LinkCheck {
    pub(crate) fn verifies(&self, key: &[u8]) -> bool {
        match self {
            LinkCheck::Record(wire) => wire.key_tag_matches(key),
            LinkCheck::Anchor(anchor) => anchor.key_ok(key),
        }
    }
}

/// The anchor of a chain whose first record is `first`: a genesis anchors on
/// its own version (A = V0 = 1), checked by its key_tag; a transition on the
/// version before it (A = V0 - 1), which every member held when it was
/// written, checked by its anchor_tag.
fn anchor_check(first: &WireRecord) -> AnchorCheck {
    match (first.body.kind, first.anchor_tag) {
        (RecordKind::Transition, Some(tag)) => {
            AnchorCheck { v0: first.body.version, anchor: first.body.version - 1, digest: first.digest, tag }
        }
        _ => AnchorCheck { v0: first.body.version, anchor: first.body.version, digest: first.digest, tag: first.key_tag },
    }
}

/// Why the circle's secret could not be derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretProblem {
    /// No path from a held key to an anchor key that verifies
    /// the anchor check.
    ChainWalk,
    /// This device's own anchor key fails the anchor check: the
    /// circle waits (`RecordProblem::AnchorMismatch`).
    AnchorMismatch,
}

impl From<SecretProblem> for RecordProblem {
    fn from(problem: SecretProblem) -> Self {
        match problem {
            SecretProblem::ChainWalk => RecordProblem::ChainWalk,
            SecretProblem::AnchorMismatch => RecordProblem::AnchorMismatch,
        }
    }
}

fn read_record(record: &SignedRefreshRecord, circle: &[u8; 16]) -> Result<(WireRecord, [u8; 64]), u32> {
    let bytes = hex::decode(&record.record_hex).map_err(|_| 0u32)?;
    let version_hint = || {
        bytes.get(18..22).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let wire = WireRecord::parse(&bytes).map_err(|e| {
        tracing::warn!("refresh records: a record that does not parse: {}", e);
        version_hint()
    })?;
    if &wire.body.circle_id != circle {
        tracing::warn!("refresh records: a record for another circle");
        return Err(wire.body.version);
    }
    let signature = hex::decode(&record.signature_hex)
        .ok()
        .and_then(|s| <[u8; 64]>::try_from(s.as_slice()).ok())
        .ok_or(wire.body.version)?;
    Ok((wire, signature))
}

fn status(version: u32, state: RecordVersionState, problem: RecordProblem) -> RecordVersionStatus {
    RecordVersionStatus {
        version: i32::try_from(version).unwrap_or(0),
        state,
        problem,
        not_allowed: Vec::new(),
        unmatched_entries: 0,
        named_listed: Vec::new(),
    }
}

/// A prefix of the chain, judged without R2 (but with
/// `reinclusions_eligible`).
struct PrefixOutcome {
    facts: HashMap<[u8; 32], MemberFact>,
    seen: BTreeMap<u32, SeenRecord>,
    head: Option<ChainHead>,
    /// The records refused on the way, and a signature that failed.
    rows: Vec<RecordVersionStatus>,
    /// Taken on the account's own head's word (`by_account`).
    by_account: bool,
}

/// Judge a prefix of the chain as a device that holds no record judges it:
/// R1's signature for a signer it can match (unless the account's own head
/// vouches: `by_account`), the chain-only rules (the format's rules with the
/// floors, the role and removal rules), and the rule for a removed member
/// included again (`reinclusions_eligible`). A record that fails them is
/// refused as every judging device refuses it: not applied, its removals not
/// counting unless an owner's or admin's, and the chain goes on through it. A
/// signature that fails ends the prefix before that record: the chain waits
/// there, as on a judging device. Pure: nothing on the device changes.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn judge_prefix(
    circle: &[u8; 16],
    secret: &[u8; 32],
    anchor: &AnchorCheck,
    prefix: &[(u32, WireRecord, [u8; 64], [u8; 32])],
    members: &[Member],
    own: Option<&OwnRestored>,
    by_account: bool,
    waiting: &BTreeMap<u32, [u8; 32]>,
    now: i64,
) -> PrefixOutcome {
    let mut out = PrefixOutcome { facts: HashMap::new(), seen: BTreeMap::new(), head: None, rows: Vec::new(), by_account };
    let mut accepted_to: Option<u32> = None;
    // The record the next one is checked against, as on a judging device: a
    // record refused here stays in the chain, with the removals that count in
    // it.
    let mut previous: Option<Tip> = None;
    for (at, (version, wire, signature, chain_value)) in prefix.iter().enumerate() {
        // Another record where one waits here (`waiting`): the version waits,
        // as a fork, and the prefix ends before it.
        if waiting.get(version).map_or(false, |kept| chain_value != kept) {
            out.rows.push(status(*version, RecordVersionState::Waiting, RecordProblem::Fork));
            break;
        }
        let signer = signer_of(secret, &out.facts, members, &wire.body, previous.as_ref(), own);
        let signed = signer.as_ref().map_or(false, |signer| wire.signature_verifies(signature, &signer.signing));
        // Signed with another confirmed member's key, while a record
        // after it fixes these very bytes (format 2): rejected and
        // passed over, as on a judging device. Never a first record.
        let successor_fixes = wire.body.format == RecordFormat::V2
            || prefix.get(at + 1).map_or(false, |(_, next, ..)| next.body.format == RecordFormat::V2);
        let misattributed = !by_account
            && !signed
            && previous.is_some()
            && successor_fixes
            && signer.as_ref().map_or(false, |signer| misattributed_to(members, wire, signature, &signer.signing).is_some());
        if !by_account && signer.is_some() && !signed && !misattributed {
            // R1's signature, for a signer this device can match: never passed
            // over, the chain waits here.
            out.rows.push(status(*version, RecordVersionState::Waiting, RecordProblem::Signature));
            break;
        }
        out.seen.insert(
            *version,
            SeenRecord::new(wire.clone(), *chain_value, RecordVersionState::Reference).signed(signed).with_signature(signature),
        );
        let mut refused: Option<(RecordProblem, HashSet<[u8; 32]>)> = None;
        if let Some(tip) = &previous {
            let overlay = &tip.overlay;
            let prev = Previous { version: tip.version, format: tip.format, body: tip.body.as_ref(), rejected: tip.rejected, misattributed: tip.misattributed };
            let view = View { circle: *circle, secret, v0: anchor.v0, facts: &out.facts, removed_overlay: overlay, role_overlay: &tip.roles, members, own };
            let listed_role = signer.and_then(|m| m.listed_role);
            if let Err(problem) = check_against_previous(&wire.body, &out.facts, overlay, &prev, anchor.anchor) {
                refused = Some((problem, HashSet::new()));
            } else if misattributed {
                tracing::warn!("refresh records: v{} is signed with another member's key than its signer entry names: rejected, passed over", version);
                refused = Some((RecordProblem::Misattributed, removals_by_its_signer_code(&view, &wire.body)));
            } else if let Err(problem) = check_authority(&view, &wire.body, listed_role) {
                refused = Some((problem, removals_of_a_refused_claim(&view, &wire.body)));
            } else if !reinclusions_eligible(&view, &wire.body, record_when(&wire.body, now)) {
                let counting = if matches!(view.role_of_code(&wire.body.signer_code), Some(ChainRole::Owner | ChainRole::Admin)) {
                    wire.body.entries.iter().filter(|e| e.state == EntryState::Removed).map(|e| e.code).collect()
                } else {
                    HashSet::new()
                };
                refused = Some((RecordProblem::R2NotAllowed, counting));
            }
        }
        match refused {
            Some((problem, counting_removals)) => {
                tracing::warn!("refresh records: v{} is refused here, as on every device that judged it", version);
                out.rows.push(status(*version, RecordVersionState::Rejected, problem));
                // Refused only for R2: its roles move the
                // chain's.
                let moves_roles = problem == RecordProblem::R2NotAllowed;
                let empty = Tip::none();
                let misattributed = problem == RecordProblem::Misattributed;
                let tip = previous.as_ref().unwrap_or(&empty).then_rejected(*version, *chain_value, Some(wire.wire_chain(signature)), &wire.body, &counting_removals, moves_roles, misattributed);
                if let Some(seen) = out.seen.get_mut(version) {
                    seen.state = RecordVersionState::Rejected;
                    seen.counting_removals = counting_removals;
                    seen.moves_roles = moves_roles;
                    seen.misattributed = misattributed;
                }
                previous = Some(tip);
            }
            None => {
                let signer_role = previous.as_ref().and_then(|tip| tip.roles.get(&wire.body.signer_code).copied())
                    .or_else(|| out.facts.get(&wire.body.signer_code).map(|f: &MemberFact| f.role));
                apply_accepted(&mut out.facts, &out.seen, accepted_to.unwrap_or(0), &wire.body, signer_role);
                vouch_included_keys(&mut out.facts, &wire.body, secret, members);
                accepted_to = Some(*version);
                out.head = Some(ChainHead { version: *version, chain: *chain_value, digest: wire.digest });
                previous = Some(Tip::accepted(*version, *chain_value, wire, signature));
            }
        }
    }
    // Records past the last one taken: kept (a repair links them), not part
    // of this device's chain yet.
    out
}

/// What every device can say of one of two records for a version.
pub(crate) enum Candidate {
    /// Refused on every device: the format's rules, the role and removal
    /// rules, or not on this chain.
    Refused(RecordProblem),
    /// Its signer isn't found, or its signature fails under the one found: it
    /// can't be judged yet, and is never passed over. Beside it no candidate
    /// wins: the version waits as a fork.
    Unjudged,
    /// It stands.
    Stands,
}

/// A record's signer, as this device found it.
pub(crate) struct Signer {
    pub signing: [u8; 32],
    /// The role this device's list gives them (the owner claim needs
    /// it); None for a signer found through the chain alone.
    pub listed_role: Option<ChainRole>,
    /// Found among the rows this device confirms: not through the record
    /// before's inclusion, nor through a recovered pair (`OwnRestored`).
    pub by_row: bool,
}

/// `body`'s signer, found by matching:
/// - a member this device confirms whose code and commitment match the signer's
///   entry. An unlisted row counts only with the keys an inclusion this device
///   accepted gave that code: a carry vouches for nothing, and the last mention
///   may be a pending carry from a rejected tip;
/// - else, with no row, one that `previous` (the record before, accepted here)
///   includes with that commitment, by the keys this device kept when it
///   accepted that inclusion, checked against the commitment again: a member
///   who has left since is still found.
fn signer_of(
    secret: &[u8; 32],
    facts: &HashMap<[u8; 32], MemberFact>,
    members: &[Member],
    body: &RecordBody,
    previous: Option<&Tip>,
    own: Option<&OwnRestored>,
) -> Option<Signer> {
    let entry = body.entry(&body.signer_code)?;
    let row = members.iter().filter(|m| m.confirmed).find(|m| {
        let code = member_code(secret, &m.uid);
        let commitment = key_commitment(secret, &code, &m.sharing, &m.signing);
        code == body.signer_code
            && commitment == entry.commitment
            && (m.listed || facts.get(&code).map_or(false, |f| f.included_with_keys > 0 && f.commitment == commitment))
    });
    if let Some(row) = row {
        return Some(Signer { signing: row.signing, listed_role: row.listed_role, by_row: true });
    }
    // Recovered pre-reset pairs (`OwnRestored`): this account's own record
    // signed before a password reset, its signer entry committing to a
    // recovered pair: the signature then has to verify under that pair's
    // signing key. Only the own code (`as_committed`).
    if let Some(own) = own.and_then(|own| own.as_committed(secret, &body.signer_code, &entry.commitment)) {
        return Some(Signer { signing: own.signing, listed_role: own.listed_role, by_row: false });
    }
    let previous = previous.filter(|p| !p.rejected)?;
    let fact = facts
        .get(&body.signer_code)
        .filter(|f| f.version == previous.version && f.state == EntryState::Included && f.commitment == entry.commitment)?;
    let (sharing, signing) = fact.vouched_keys?;
    (key_commitment(secret, &body.signer_code, &sharing, &signing) == entry.commitment).then_some(Signer { signing, listed_role: None, by_row: false })
}

/// Whether `wire`'s signature verifies under the key of the signer this device
/// confirms, found by matching (`signer_of`). Only the signature covers a
/// record's tags: its chain value covers the body alone.
fn signature_verified_here(
    secret: &[u8; 32],
    facts: &HashMap<[u8; 32], MemberFact>,
    wire: &WireRecord,
    signature: &[u8; 64],
    members: &[Member],
    own: Option<&OwnRestored>,
) -> bool {
    signer_of(secret, facts, members, &wire.body, None, own).map_or(false, |signer| wire.signature_verifies(signature, &signer.signing))
}

/// Whether `body` links `tip`: a format-2 record the copy this device holds
/// there, by its wire_chain; a format-1 record its chain value (after a
/// format-2 tip, the rule that formats only go up then refuses it). None: not
/// known here (a format-2 record after a tip whose wire this device doesn't
/// know; any record after a tip whose format isn't known yet, so a format-1
/// record never passes the format rule by default).
fn links_to(body: &RecordBody, tip: &Tip) -> Option<bool> {
    if body.prev_version != tip.version {
        return Some(false);
    }
    if !tip.format_known {
        return None;
    }
    match body.format {
        RecordFormat::V2 => tip.wire.map(|wire| wire == body.prev_chain),
        RecordFormat::V1 => Some(body.prev_chain == tip.chain),
    }
}

/// The record before the next one, as the next one is judged against.
#[derive(Clone)]
struct Tip {
    version: u32,
    chain: [u8; 32],
    /// The wire_chain of the copy this device holds there: what a format-2
    /// record after it links (None: not known here).
    wire: Option<[u8; 32]>,
    format: RecordFormat,
    /// False: a head from a store written by an older SDK, its format
    /// not known yet.
    format_known: bool,
    body: Option<RecordBody>,
    rejected: bool,
    /// Rejected here as MISATTRIBUTED: its inclusions set no floor.
    misattributed: bool,
    /// Removals that count in a rejected tip, at their versions.
    overlay: Overlay,
    /// Roles the records rejected only for R2 since the head moved.
    roles: RoleOverlay,
}

impl Tip {
    /// The head this device accepted.
    fn at_head(chain: &CircleChain) -> Option<Tip> {
        let head = chain.head.as_ref()?;
        let step = chain.history.get(&head.version).filter(|step| step.chain == head.chain);
        Some(Tip {
            version: head.version,
            chain: head.chain,
            wire: step.and_then(|step| step.wire),
            format: step.map_or(RecordFormat::V1, |step| step.format),
            format_known: step.map_or(false, |step| step.format_known),
            body: chain.seen.get(&head.version).map(|s| s.wire.body.clone()),
            rejected: false,
            misattributed: false,
            overlay: Overlay::new(),
            roles: RoleOverlay::new(),
        })
    }

    /// Where the next record goes: the head, then every record this
    /// device rejected after it in a row (a repair links the last one),
    /// with the removals that count in them, and the roles those
    /// rejected only for R2 moved, as the importer judged them.
    fn after_rejected(chain: &CircleChain) -> Option<Tip> {
        let mut tip = Tip::at_head(chain)?;
        while let Some(next) = chain.seen.get(&(tip.version + 1)).filter(|s| s.state == RecordVersionState::Rejected) {
            let wire = next.signature.map(|signature| next.wire.wire_chain(&signature));
            tip = tip.then_rejected(next.wire.body.version, next.chain, wire, &next.wire.body, &next.counting_removals, next.moves_roles, next.misattributed);
        }
        Some(tip)
    }

    /// The tip after a record rejected here, after this one.
    #[allow(clippy::too_many_arguments)]
    fn then_rejected(
        &self,
        version: u32,
        chain: [u8; 32],
        wire: Option<[u8; 32]>,
        body: &RecordBody,
        counting_removals: &HashSet<[u8; 32]>,
        moves_roles: bool,
        misattributed: bool,
    ) -> Tip {
        let (mut overlay, mut roles) = if self.rejected { (self.overlay.clone(), self.roles.clone()) } else { (Overlay::new(), RoleOverlay::new()) };
        overlay.extend(counting_removals.iter().map(|code| (*code, version)));
        if moves_roles {
            roles.extend(body.entries.iter().map(|e| (e.code, e.role)));
        }
        Tip { version, chain, wire, format: body.format, format_known: true, body: Some(body.clone()), rejected: true, misattributed, overlay, roles }
    }

    /// The tip after a record accepted here, as served (`wire` with `signature`).
    fn accepted(version: u32, chain: [u8; 32], wire: &WireRecord, signature: &[u8; 64]) -> Tip {
        Tip {
            version,
            chain,
            wire: Some(wire.wire_chain(signature)),
            format: wire.body.format,
            format_known: true,
            body: Some(wire.body.clone()),
            rejected: false,
            misattributed: false,
            overlay: Overlay::new(),
            roles: RoleOverlay::new(),
        }
    }

    /// Before any record.
    fn none() -> Tip {
        Tip { version: 0, chain: [0; 32], wire: None, format: RecordFormat::V1, format_known: true, body: None, rejected: false, misattributed: false, overlay: Overlay::new(), roles: RoleOverlay::new() }
    }
}

/// The removals that count and the roles that move in what this device
/// rejected above its head: the records it passed over in this process
/// (`Tip::after_rejected`), and each version passed over before a restart
/// while it waits for its record (`CircleChain::carried`). E, the chain role
/// and the heads read them; the importer judges each record from the head.
fn rejected_overlays(chain: &CircleChain) -> (Overlay, RoleOverlay) {
    let (mut overlay, mut roles) = Tip::after_rejected(chain).map(|t| (t.overlay, t.roles)).unwrap_or_default();
    // In version order, above that run, as the importer's tip adds them.
    for (at, carried) in &chain.carried {
        for code in &carried.removals {
            overlay.insert(*code, *at);
        }
        roles.extend(carried.roles.iter().map(|(code, role)| (*code, *role)));
    }
    (overlay, roles)
}

impl CryptoManager {
    /// Whether something vouches here for (`circle_id`, `version`)'s key
    /// (a record held that vouches for its tag, or the tag kept of one)
    /// and `key` fails it: then the copy is refused. A record made up for
    /// the version never refuses the real copy.
    pub(crate) fn copy_contradicts_record(&self, circle_id: &str, version: i32, key: &[u8]) -> bool {
        let Ok(version) = u32::try_from(version) else {
            return false;
        };
        self.refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .and_then(|chain| chain.key_vouched(version, key))
            == Some(false)
    }

    /// Whether a record this device holds vouches for `key` as `version`'s
    /// (its tag, kept or seen).
    pub(crate) fn copy_vouched_by_record(&self, circle_id: &str, version: i32, key: &[u8]) -> bool {
        let Ok(version) = u32::try_from(version) else {
            return false;
        };
        self.refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&CircleKey::of(&circle_id))
            .and_then(|chain| chain.key_vouched(version, key))
            == Some(true)
    }

    /// A version this device took as its reference without a verified key is
    /// accepted once a copy that verifies the tag is held.
    pub(crate) fn accept_reference_with_key(&self, circle_id: &str, version: i32) {
        let Ok(version) = u32::try_from(version) else {
            return;
        };
        let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
        let Some(chain) = chains.get_mut(&CircleKey::of(&circle_id)) else {
            return;
        };
        self.accept_reference_in(circle_id, chain, version);
    }

    /// The same, with the chain already in hand.
    fn accept_reference_in(&self, circle_id: &str, chain: &mut CircleChain, version: u32) {
        let head_version = chain.head.as_ref().map_or(0, |h| h.version);
        // Only what vouches for the version here opens it (the kept tag
        // counts): a made-up copy's tag and a wrap never pick the key sealed
        // under.
        let opens = self.held_keys(circle_id).iter().any(|(v, key)| *v == version && chain.key_vouched(version, key) == Some(true));
        let Some(seen) = chain.seen.get_mut(&version) else {
            return;
        };
        if seen.state != RecordVersionState::Reference || version > head_version {
            return;
        }
        if opens {
            seen.state = RecordVersionState::Accepted;
            if version > chain.sealing {
                chain.sealing = version;
                tracing::info!("refresh records: circle {} v{} accepted now that its key is held", circle_id, version);
            }
        }
    }

    /// See `LinkRule`.
    pub(crate) fn chain_link_rule(&self, circle_id: &str, from_version: i32, to_version: i32) -> LinkRule {
        let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
        let Some(chain) = chains.get(&CircleKey::of(&circle_id)).filter(|c| c.is_recorded()) else {
            if self.latched_until_the_store_reads(circle_id) {
                return LinkRule::Refuse("the key store can't be read: this circle waits");
            }
            return LinkRule::Legacy;
        };
        let Some(anchor) = &chain.anchor else {
            return LinkRule::Refuse("this circle's records are not held here yet");
        };
        let (Ok(from), Ok(to)) = (u32::try_from(from_version), u32::try_from(to_version)) else {
            return LinkRule::Refuse("a link steps down between versions >= 1");
        };
        if to < anchor.anchor {
            return LinkRule::Legacy;
        }
        if !step_allowed(&chain.seen, anchor.anchor, from, to) {
            return LinkRule::Refuse("no record held here names this step");
        }
        if to == anchor.anchor && anchor.anchor < anchor.v0 {
            // A step onto a transition's anchor: its anchor_tag vouches.
            return LinkRule::Checked(LinkCheck::Anchor(anchor.clone()));
        }
        match chain.seen.get(&to) {
            Some(seen) => LinkRule::Checked(LinkCheck::Record(seen.wire.clone())),
            None => LinkRule::Refuse("the record for the version it leads to is not held here yet"),
        }
    }

    /// Drop every held key of `circle_id` that fails what vouches for its
    /// version here: a record taken here with its signature verified, or
    /// the tag kept of one. A record that failed R1 or R2 here never drops
    /// a key. Returns the versions.
    fn drop_contradicted_keys(&self, circle_id: &str, chain: &CircleChain) -> Vec<u32> {
        let mut dropped = Vec::new();
        for (version, key) in self.held_keys(circle_id) {
            if chain.key_vouched(version, &key) == Some(false) && self.drop_held_key(circle_id, version) {
                tracing::warn!(
                    "refresh records: DROPPED this device's copy of circle {} v{}: it does not verify the record's tag",
                    circle_id, version
                );
                dropped.push(version);
            }
        }
        dropped
    }

    /// The input for matching this account's own entry through recovered
    /// pre-reset pairs, for one import (`OwnRestored`): the own row, the
    /// ONE confirmed, listed row carrying this device's current keys
    /// (none, or two, and nothing is matched through old keys: an
    /// incomplete list fails closed), with the recovered identities'
    /// pairs (`previous_key_pairs`). None while no pair is held.
    fn own_restored(&self, members: &[Member]) -> Option<OwnRestored> {
        let (sharing, signing) = self.own_keys()?;
        let mut rows = members.iter().filter(|m| m.confirmed && m.listed && m.sharing == sharing && m.signing == signing);
        let row = rows.next()?.clone();
        if rows.next().is_some() {
            return None;
        }
        let pairs = self.previous_key_pairs();
        (!pairs.is_empty()).then_some(OwnRestored { row, pairs })
    }

    /// This device's CURRENT keys: (sharing, signing).
    fn own_keys(&self) -> Option<([u8; 32], [u8; 32])> {
        let sharing = self.own_sharing_public_key()?;
        let signing = key32("own signing key", &self.signing_public_key_hex().ok()?).ok()?;
        Some((sharing, signing))
    }

    /// The members the app listed, read for one circle. A statement whose
    /// signer is its subject is kept only as an admission (it counts
    /// through E's (b) and nowhere else), and only in a row whose keys
    /// this device knows for that member itself: its pin for them in this
    /// circle (the identity pin when the circle has none, as
    /// `pinned_sharing_key` reads it), or, in its OWN row, its current
    /// keys (nobody holds a pin for themselves). An app may pass a
    /// confirmed member with no pin with the server's listed keys: a key
    /// the server made up would otherwise count on its own statement.
    fn read_members_here(&self, circle_id: &str, members: &[RecordMember]) -> Result<Vec<Member>, MobileError> {
        let mut read = read_members(members)?;
        let own = self.own_keys();
        for member in &mut read {
            if !member.statements.iter().any(|s| s.subject == Some(s.signer)) {
                continue;
            }
            let keys = (member.sharing, member.signing);
            let known = !member.no_published_keys && (own == Some(keys) || self.pinned_keys_of(circle_id, &member.user_id) == Some(keys));
            member
                .statements
                .retain(|s| s.subject != Some(s.signer) || (known && s.fields.kind == MembershipStatementKind::Admission));
        }
        Ok(read)
    }

    /// This device's pin for `user_id` in `circle_id`, the identity pin when
    /// the circle has none (`pinned_sharing_key`, `pinned_signing_key`).
    fn pinned_keys_of(&self, circle_id: &str, user_id: &str) -> Option<([u8; 32], [u8; 32])> {
        let sharing = self.pinned_sharing_key(circle_id.to_string(), user_id.to_string())?;
        let signing = self.pinned_signing_key(circle_id.to_string(), user_id.to_string())?;
        Some((key32("pin", &sharing).ok()?, key32("pin", &signing).ok()?))
    }

    /// Derive the circle's secret if this device has not yet: check the
    /// anchor key, from the key this device holds for the anchor if it
    /// holds one, else by walking the chain down to it (each key on the
    /// way must verify its version's record, if held; the keys the walk
    /// verified are stored).
    /// A held anchor key that fails the anchor check is never replaced on
    /// the first record's word: the circle waits here.
    fn ensure_secret(&self, circle_id: &str, chain: &mut CircleChain, links: &[KeyChainLinkData]) -> Result<(), SecretProblem> {
        if chain.secret.is_some() {
            return Ok(());
        }
        let Some(anchor) = chain.anchor.clone() else {
            return Err(SecretProblem::ChainWalk);
        };
        let held = self.held_keys(circle_id);
        let anchor_key = match held.iter().find(|(v, _)| *v == anchor.anchor) {
            Some((_, own)) if anchor.key_ok(own) => own.clone(),
            Some(_) => {
                tracing::warn!(
                    "refresh records: circle {}'s first record was made over another key for v{} than this device's: the circle waits here (a split)",
                    circle_id, anchor.anchor
                );
                return Err(SecretProblem::AnchorMismatch);
            }
            None => {
                let Some((anchor_key, walked)) = walk_to_anchor(&anchor, &held, links, &chain.seen) else {
                    tracing::warn!("refresh records: circle {}'s key chain does not reach a key that verifies its anchor", circle_id);
                    return Err(SecretProblem::ChainWalk);
                };
                for walked_key in walked.iter().filter(|w| w.checked) {
                    self.add_verified_key(circle_id, walked_key.version, &walked_key.key);
                }
                anchor_key
            }
        };
        chain.secret = Some(secret_from(&anchor_key).map_err(|_| SecretProblem::ChainWalk)?);
        Ok(())
    }

    /// The import (`import_refresh_records`), with the
    /// clock passed in.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn import_refresh_records_at(
        &self,
        circle_id: &str,
        records: &[SignedRefreshRecord],
        key_chain: &[KeyChainLinkData],
        members: &[RecordMember],
        roster_complete: bool,
        own_head: Option<&SignedCircleHead>,
        member_heads: &[MemberHead],
        now: i64,
    ) -> Result<RefreshRecordsReport, MobileError> {
        // A personal key slot has no records: none a server
        // serves for it drops, adds or picks the key sealed
        // under there.
        if crate::crypto::names_a_personal_slot(circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it has no records".to_string()));
        }
        let circle = uuid16("circle_id", circle_id)?;
        let members = self.read_members_here(circle_id, members)?;
        // This account's recovered pre-reset pairs (`OwnRestored`), for its
        // own entry.
        let own = self.own_restored(&members);
        let mut report = RefreshRecordsReport {
            versions: Vec::new(),
            sealing_version: None,
            ask_for_fresh_copy: false,
            forked: false,
            head_confirmed_members: Vec::new(),
            tip_named_listed: Vec::new(),
        };

        // What was served, by version. Two different records for one version
        // are a fork.
        let mut served: BTreeMap<u32, (WireRecord, [u8; 64])> = BTreeMap::new();
        let mut alternatives: BTreeMap<u32, Vec<(WireRecord, [u8; 64])>> = BTreeMap::new();
        for record in records {
            match read_record(record, &circle) {
                Ok((wire, signature)) => match served.get(&wire.body.version) {
                    Some((held, _)) if held.to_bytes() != wire.to_bytes() => {
                        let others = alternatives.entry(wire.body.version).or_default();
                        if !others.iter().any(|(other, _)| other.to_bytes() == wire.to_bytes()) {
                            others.push((wire, signature));
                        }
                    }
                    Some(_) => {}
                    None => {
                        served.insert(wire.body.version, (wire, signature));
                    }
                },
                Err(version) => report.versions.push(status(version, RecordVersionState::Rejected, RecordProblem::Structure)),
            }
        }
        // The account's own head, under its CURRENT signing key.
        let own_head = own_head.and_then(|signed| {
            let own_key = self.signing_public_key_hex().ok().and_then(|hex| key32("own key", &hex).ok())?;
            let bytes = hex::decode(&signed.head_hex).ok()?;
            let head = Head::decode(&bytes).ok()?;
            let bytes: [u8; 69] = bytes.try_into().ok()?;
            let signature = <[u8; 64]>::try_from(hex::decode(&signed.signature_hex).ok()?.as_slice()).ok()?;
            VerifyingKey::from_bytes(&own_key)
                .ok()?
                .verify_strict(&Head::digest(&bytes), &Signature::from_bytes(&signature))
                .ok()?;
            (head.circle_id == circle).then_some(head)
        });

        {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            // While the store can't be read, a circle this process
            // holds no chain for is not read at first sight: its
            // stored state may hold a head, and a chain built now
            // would stand over it once the store reads. It waits.
            if !chains.contains_key(&CircleKey::of(&circle_id)) && self.latched_until_the_store_reads(circle_id) {
                if let Some(&first) = served.keys().next() {
                    report.versions.push(status(first, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                }
                return Ok(report);
            }
            let chain = chains.entry(CircleKey::of(&circle_id)).or_default();
            if !served.is_empty() || own_head.is_some() {
                chain.latched = true;
            }
            chain.imported = true;
            // Two records for one version: past this device's head, the loop
            // below settles it (a record refused on every device can't stand);
            // at or below it, or with no head, the circle waits.
            let head_version = chain.head.as_ref().map(|h| h.version);
            if alternatives.keys().any(|v| head_version.map_or(true, |h| *v <= h)) {
                tracing::warn!("refresh records: two different records for one version of circle {}", circle_id);
                chain.forked = true;
            }
            if !chain.forked {
                self.verify_served(
                    circle_id, &circle, chain, served.clone(), &alternatives, key_chain, &members, own.as_ref(), roster_complete,
                    own_head.clone(), now, &mut report,
                );
            }
            // A fork (seen now or before) is settled when the
            // server serves a chain whole that parts from this
            // device's.
            if chain.forked && self.settle_fork(circle_id, &circle, chain, &served, key_chain, &members, own.as_ref(), roster_complete, now, &mut report) {
                self.drop_contradicted_keys(circle_id, chain);
            }
            // Each version above the head that waits is kept with
            // the record that waits there, never replaced, until
            // that record is judged here and doesn't wait (the
            // loop decides it there) or the head reaches the
            // version through it (here). No other row decides it:
            // an import that serves nothing that far, or another
            // record there, decides nothing.
            if !chain.forked {
                let head = chain.head.as_ref().map_or(0, |h| h.version);
                let version_of = |row: &RecordVersionStatus| u32::try_from(row.version).unwrap_or(0);
                let history = &chain.history;
                chain.waiting.retain(|at, kept| !(head >= *at && history.get(at).map_or(false, |step| step.chain == *kept)));
                // A wait seen before the loop (the account's first device).
                for row in report.versions.iter().filter(|row| row.state == RecordVersionState::Waiting && version_of(row) > head) {
                    let at = version_of(row);
                    if let (false, Some((wire, _))) = (chain.waiting.contains_key(&at), served.get(&at)) {
                        chain.waiting.insert(at, wire.chain());
                    }
                }
            }
            // What a version passed over before a restart counted goes with its
            // wait: decided here (or passed by the head), the record judged
            // there counts instead.
            let waiting = &chain.waiting;
            chain.carried.retain(|at, _| waiting.contains_key(at));
            // The held-copy check (`drop_contradicted_keys`) on the tags kept up
            // to the head too, whether the server served those records again or
            // not (never while forked: a copy that fails this side's record may
            // be the other side's key).
            if !chain.forked {
                let dropped = self.drop_contradicted_keys(circle_id, chain);
                if !dropped.is_empty() {
                    report.ask_for_fresh_copy = true;
                    if dropped.contains(&chain.sealing) {
                        chain.sealing = 0;
                    }
                }
            }
            // The circle's secret, when this device has none yet for the chain
            // it holds (none stored, or a store an older SDK wrote back without
            // it): E and the heads below need it, and this call has the key
            // chain.
            if !chain.forked && chain.head.is_some() && chain.secret.is_none() {
                if let Err(problem) = self.ensure_secret(circle_id, chain, key_chain) {
                    report.ask_for_fresh_copy |= problem == SecretProblem::ChainWalk;
                }
            }
            if !chain.forked {
                self.compare_member_heads(circle_id, &circle, chain, member_heads, &members);
            }
            // This account's own served head, under its CURRENT
            // key, goes through the same comparison: another chain
            // value at a version seen here means this account's
            // own devices diverged, a fork. (An old key's head
            // never verifies.)
            if let Some(head) = own_head.as_ref().filter(|_| !chain.forked) {
                if chain.value_at(head.version, head.format).map_or(false, |ours| ours != head.chain) {
                    tracing::warn!(
                        "refresh records: this account's own head for circle {} v{} contradicts this device's chain: the circle waits",
                        circle_id, head.version
                    );
                    chain.forked = true;
                }
            }
            report.forked = chain.forked;
            // The listed members each record rejected here names
            // (included or pending), and those of the record a
            // plan would be built on: a plan must name them all.
            if let Some(secret) = chain.secret.clone() {
                let named_listed = |body: &RecordBody| -> Vec<String> {
                    body.entries
                        .iter()
                        .filter(|e| matches!(e.state, EntryState::Included | EntryState::Pending))
                        .filter_map(|e| members.iter().filter(|m| m.listed).find(|m| member_code(&secret, &m.uid) == e.code))
                        .map(|m| m.user_id.clone())
                        .collect()
                };
                for row in report.versions.iter_mut().filter(|r| r.state == RecordVersionState::Rejected) {
                    let rejected = u32::try_from(row.version).ok().and_then(|v| chain.seen.get(&v)).filter(|s| s.state == RecordVersionState::Rejected);
                    if let Some(seen) = rejected {
                        row.named_listed = named_listed(&seen.wire.body);
                    }
                }
                report.tip_named_listed = Tip::after_rejected(chain)
                    .filter(|tip| tip.rejected)
                    .and_then(|tip| tip.body)
                    .map(|body| named_listed(&body))
                    .unwrap_or_default();
            }
        }
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after importing refresh records: {}", e);
        }
        report.sealing_version = self.sealing_version(circle_id);
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_served(
        &self,
        circle_id: &str,
        circle: &[u8; 16],
        chain: &mut CircleChain,
        served: BTreeMap<u32, (WireRecord, [u8; 64])>,
        alternatives: &BTreeMap<u32, Vec<(WireRecord, [u8; 64])>>,
        links: &[KeyChainLinkData],
        members: &[Member],
        own: Option<&OwnRestored>,
        roster_complete: bool,
        own_head: Option<Head>,
        now: i64,
        report: &mut RefreshRecordsReport,
    ) {
        // Records at or below the head: this device's own history. They are
        // held (for tags and links) only when they chain up to the head it
        // accepted; a record AT the head that differs is a fork.
        let mut tip: Option<Tip> = None;
        let mut start = 1u32;
        if let Some(head) = chain.head.clone() {
            // A served record at or below the head that is not
            // this device's own: two records for one version.
            if served
                .range(..=head.version)
                .any(|(v, (wire, _))| chain.history.get(v).map_or(false, |step| step.chain != wire.chain()))
            {
                tracing::warn!("refresh records: circle {} serves another record for a version this device holds", circle_id);
                chain.forked = true;
                return;
            }
            if let Some((wire, _)) = served.get(&head.version) {
                if wire.digest != head.digest || wire.chain() != head.chain {
                    tracing::warn!("refresh records: circle {} serves another record at this device's head", circle_id);
                    chain.forked = true;
                    return;
                }
                // This device's own record, served back.
                if chain.own.as_ref().map_or(false, |own| own.wire.body.version <= head.version) {
                    chain.own = None;
                }
            }
            if let Some(run) = contiguous_run(&served, &chain.history, head.version) {
                for (version, wire, signature, chain_value) in run {
                    // The same body can come with another tag and signature (the
                    // chain value covers the body alone): a copy whose signature
                    // doesn't verify here never replaces one that did. (A tag
                    // kept for the version still decides about its key.)
                    let signed = chain.secret.as_ref().map_or(false, |secret| signature_verified_here(secret, &chain.facts, &wire, &signature, members, own));
                    chain.note_step(&wire, chain_value, signed, signed.then(|| wire.wire_chain(&signature)));
                    if !signed && chain.seen.get(&version).map_or(false, |held| held.chain == chain_value && held.signed) {
                        continue;
                    }
                    let state = if version <= chain.sealing && self.held_keys(circle_id).iter().any(|(v, k)| *v == version && wire.key_tag_matches(k)) {
                        RecordVersionState::Accepted
                    } else {
                        RecordVersionState::Reference
                    };
                    chain.seen.insert(version, SeenRecord::new(wire, chain_value, state).signed(signed).with_signature(&signature));
                    // A reference this copy now vouches for opens with its held
                    // key, as the pass below opens one that isn't served again:
                    // its signer was confirmed (or the recovered pre-reset pairs
                    // loaded) only after it was taken. Marked signed here, that
                    // pass would skip it, and the device would stay on the version
                    // below.
                    if signed {
                        self.accept_reference_in(circle_id, chain, version);
                    }
                }
                // Every copy held for a version below the head is checked too:
                // as soon as the device holds the record
                // (`drop_contradicted_keys`).
                let dropped = self.drop_contradicted_keys(circle_id, chain);
                if !dropped.is_empty() {
                    report.ask_for_fresh_copy = true;
                    if dropped.contains(&chain.sealing) {
                        // The version it sealed under is no longer held.
                        chain.sealing = 0;
                    }
                }
            }
            // A record held up to the head that no signature vouched for yet (a
            // signer not confirmed when it came, served or not since): checked
            // again against the members confirmed now. One that verifies now
            // vouches, keeps its tag, and a Reference it vouches for opens with
            // its held key, with no restart and no new record.
            if let Some(secret) = chain.secret.clone() {
                let now_signed: Vec<u32> = chain
                    .seen
                    .range(..=head.version)
                    .filter(|(_, seen)| !seen.signed && seen.state != RecordVersionState::Rejected)
                    .filter(|(_, seen)| seen.signature.map_or(false, |sig| signature_verified_here(&secret, &chain.facts, &seen.wire, &sig, members, own)))
                    .map(|(v, _)| *v)
                    .collect();
                for version in now_signed {
                    let Some(seen) = chain.seen.get_mut(&version) else { continue };
                    seen.signed = true;
                    let (wire, chain_value) = (seen.wire.clone(), seen.chain);
                    let taken = seen.signature.map(|signature| wire.wire_chain(&signature));
                    chain.note_step(&wire, chain_value, true, taken);
                    self.accept_reference_in(circle_id, chain, version);
                }
            }
            tip = Tip::at_head(chain);
            start = head.version + 1;
        } else if let Some((&first_version, (first, _))) = served.iter().next() {
            // No head yet. The chain must start with its first record.
            if !matches!(first.body.kind, RecordKind::Genesis | RecordKind::Transition) {
                report.versions.push(status(first_version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                return;
            }
            let last = served.keys().next_back().copied().unwrap_or(first_version);
            let run = contiguous_run(&served, &BTreeMap::new(), last).unwrap_or_default();
            let prefix_end = match &own_head {
                // The account's own head: the chain up to it is its own.
                Some(head) => match run.iter().find(|(v, ..)| *v == head.version) {
                    // In the head's own format: format 2 names that very copy.
                    Some((_, wire, signature, value))
                        if head.chain == if head.format == RecordFormat::V2 { wire.wire_chain(signature) } else { *value } =>
                    {
                        Some((head.version, true))
                    }
                    Some(_) => {
                        tracing::warn!("refresh records: circle {}'s served chain contradicts this account's own head", circle_id);
                        chain.forked = true;
                        return;
                    }
                    None => {
                        report.versions.push(status(head.version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                        return;
                    }
                },
                // While a stored signing seed that doesn't
                // install is kept, this account HAS a key
                // this device can't read, and so can't check
                // its own head: the chain is not taken by
                // R1. It waits until the person signs in
                // again.
                None if run.len() > 1 && self.signing_seed_unreadable() => {
                    report.versions.push(status(first_version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                    return;
                }
                // The account's first device in the circle: R1
                // over the whole served chain, anchored on the
                // latest record. A lone first record is judged
                // like any other, R2 included.
                None if run.len() > 1 => run.last().map(|(v, ..)| (*v, false)),
                None => None,
            };
            chain.set_anchor(anchor_check(first));
            match prefix_end {
                Some((end, by_account)) => {
                    let prefix: Vec<_> = run.into_iter().filter(|(v, ..)| *v <= end).collect();
                    if !self.accept_prefix(circle_id, circle, chain, prefix, links, members, own, by_account, own_head.as_ref(), now, report) {
                        return;
                    }
                    tip = Tip::at_head(chain);
                    start = chain.head.as_ref().expect("a prefix sets the head").version + 1;
                }
                None => start = first_version,
            }
        }

        // Every later record, in order: R1, then R2.
        for (version, (wire, signature)) in served.range(start..) {
            let version = *version;
            // Two records for this version: one that every device
            // refuses can't stand; of two that pass, the one that
            // removes the other's signer stands. Otherwise it is a
            // fork, and the circle waits.
            let (wire, signature) = match alternatives.get(&version) {
                None => (wire, signature),
                Some(others) => {
                    let candidates: Vec<(&WireRecord, &[u8; 64])> =
                        std::iter::once((wire, signature)).chain(others.iter().map(|(w, s)| (w, s))).collect();
                    let mut unjudged = false;
                    let mut standing: Vec<(&WireRecord, &[u8; 64])> = Vec::new();
                    for (candidate, candidate_signature) in candidates {
                        match self.candidate(chain, circle, tip.as_ref(), candidate, candidate_signature, members, own) {
                            Candidate::Refused(problem) => {
                                // A kept record refused once it can be judged
                                // decides its wait.
                                if chain.waiting.get(&version) == Some(&candidate.chain()) {
                                    chain.waiting.remove(&version);
                                }
                                report.versions.push(status(version, RecordVersionState::Rejected, problem));
                            }
                            Candidate::Unjudged => {
                                unjudged = true;
                                standing.push((candidate, candidate_signature));
                            }
                            Candidate::Stands => standing.push((candidate, candidate_signature)),
                        }
                    }
                    let removes = |one: &WireRecord, other: &WireRecord| {
                        one.body.entry(&other.body.signer_code).map_or(false, |e| e.state == EntryState::Removed)
                    };
                    // Beside a candidate that can't be judged, none wins,
                    // whatever the removes rule would pick.
                    let winner = match standing.as_slice() {
                        _ if unjudged => None,
                        [only] => Some(*only),
                        [a, b] if removes(a.0, b.0) && !removes(b.0, a.0) => Some(*a),
                        [a, b] if removes(b.0, a.0) && !removes(a.0, b.0) => Some(*b),
                        _ => None,
                    };
                    match winner {
                        Some(chosen) => chosen,
                        None => {
                            tracing::warn!("refresh records: two records stand for circle {} v{}: the circle waits", circle_id, version);
                            chain.forked = true;
                            // A fork above the head is
                            // never settled: one beside a
                            // candidate that can't be
                            // judged, or two that stand,
                            // is latched. (Every candidate
                            // refused: each served again
                            // alone is refused again.)
                            chain.fork_latched |= unjudged || standing.len() > 1;
                            report.versions.push(status(version, RecordVersionState::Waiting, RecordProblem::Fork));
                            return;
                        }
                    }
                }
            };
            // A version this device judged on one copy and
            // passed over keeps that copy: another copy of the
            // same record (another signature, verified or not)
            // never takes its place, and the record after it
            // links that copy or nothing.
            let held = chain
                .seen
                .get(&version)
                .filter(|held| held.state == RecordVersionState::Rejected && held.chain == wire.chain())
                .and_then(|held| held.signature.map(|signature| (held.wire.clone(), signature)));
            let held_copy;
            let (wire, signature, judged_before) = match held {
                Some(copy) => {
                    held_copy = copy;
                    (&held_copy.0, &held_copy.1, true)
                }
                None => (wire, signature, false),
            };
            // Only the record that waits at a version ends its
            // wait: another served there is a second candidate for
            // it, and while the kept one can't be judged the
            // version waits as a fork.
            if chain.waiting.get(&version).map_or(false, |kept| wire.chain() != *kept) {
                report.versions.push(status(version, RecordVersionState::Waiting, RecordProblem::Fork));
                break;
            }
            let is_first = matches!(wire.body.kind, RecordKind::Genesis | RecordKind::Transition);
            match &tip {
                Some(t) if version != t.version + 1 => {
                    chain.waiting.entry(version).or_insert_with(|| wire.chain());
                    report.versions.push(status(version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                    break;
                }
                Some(_) if is_first => {
                    tracing::warn!("refresh records: a second first record for circle {}", circle_id);
                    chain.forked = true;
                    report.versions.push(status(version, RecordVersionState::Rejected, RecordProblem::Fork));
                    return;
                }
                // A format going down is refused, and is never
                // the record at this version here: no step, no
                // wait, and nothing links it; the version stays
                // open for a format-2 record.
                Some(t) if wire.body.format < t.format => {
                    tracing::warn!("refresh records: circle {} v{} is in format 1 after a format-2 record: refused", circle_id, version);
                    report.versions.push(status(version, RecordVersionState::Rejected, RecordProblem::Structure));
                    break;
                }
                Some(t) if links_to(&wire.body, t) == Some(false) => {
                    tracing::warn!("refresh records: circle {} v{} links to a record this device does not hold", circle_id, version);
                    chain.forked = true;
                    report.versions.push(status(version, RecordVersionState::Rejected, RecordProblem::Fork));
                    return;
                }
                // A format-2 record after a copy whose wire this device doesn't
                // know (a store written by an older SDK): it waits, kept, until
                // the record below it is served again and tells it
                // (`refresh_head_versions` asks for it).
                Some(t) if links_to(&wire.body, t).is_none() => {
                    chain.waiting.entry(version).or_insert_with(|| wire.chain());
                    report.versions.push(status(version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                    break;
                }
                None if !is_first => {
                    chain.waiting.entry(version).or_insert_with(|| wire.chain());
                    report.versions.push(status(version, RecordVersionState::Waiting, RecordProblem::RecordMissing));
                    break;
                }
                _ => {}
            }
            if is_first {
                chain.set_anchor(anchor_check(wire));
            }
            let chain_value = wire.chain();
            chain.seen.insert(
                version,
                SeenRecord::new(wire.clone(), chain_value, RecordVersionState::Waiting).with_signature(signature),
            );
            // What the format-2 record served after it links; for a copy
            // judged and passed over before, that very copy.
            let successor = if judged_before {
                Some(wire.wire_chain(signature))
            } else {
                served.get(&(version + 1)).filter(|(next, _)| next.body.format == RecordFormat::V2).map(|(next, _)| next.body.prev_chain)
            };
            let outcome = self.judge(circle_id, circle, chain, tip.as_ref(), wire, signature, successor, links, members, own, roster_complete, now);
            // This record waits here, kept; or, kept, it is decided.
            if outcome.state == RecordVersionState::Waiting {
                chain.waiting.entry(version).or_insert(chain_value);
            } else if chain.waiting.get(&version) == Some(&chain_value) {
                chain.waiting.remove(&version);
            }
            if let Some(seen) = chain.seen.get_mut(&version) {
                seen.state = outcome.state;
                seen.counting_removals = outcome.counting_removals.clone();
                seen.signed = outcome.signed;
                seen.moves_roles = outcome.moves_roles;
                seen.misattributed = outcome.problem == RecordProblem::Misattributed;
            }
            // Held copies are checked only now: a held copy goes
            // only for a record this device took, with its
            // signature verified (R1 first). A record made up for
            // this version drops nothing, and the real copy stays.
            let dropped = self.drop_contradicted_keys(circle_id, chain);
            if !dropped.is_empty() {
                report.ask_for_fresh_copy = true;
            }
            let problem = if outcome.state == RecordVersionState::Reference && dropped.contains(&version) {
                RecordProblem::KeyTag
            } else {
                outcome.problem
            };
            let mut row = status(version, outcome.state, problem);
            row.not_allowed = outcome.not_allowed;
            row.unmatched_entries = outcome.unmatched;
            if outcome.problem == RecordProblem::ChainWalk || outcome.problem == RecordProblem::KeyTag {
                report.ask_for_fresh_copy = true;
            }
            report.versions.push(row);
            if outcome.state != RecordVersionState::Waiting {
                let vouches = chain.seen.get(&version).map_or(false, |seen| seen.vouches_for_its_tag());
                chain.note_step(wire, chain_value, vouches, Some(wire.wire_chain(signature)));
            }
            match outcome.state {
                RecordVersionState::Accepted | RecordVersionState::Reference => {
                    tip = Some(Tip::accepted(version, chain_value, wire, signature));
                }
                RecordVersionState::Rejected => {
                    // A repair keeps the counting removals
                    // of every rejected record since the
                    // last accepted one, and the roles of
                    // those rejected only for R2.
                    let empty = Tip::none();
                    let misattributed = outcome.problem == RecordProblem::Misattributed;
                    let next = tip.as_ref().unwrap_or(&empty).then_rejected(version, chain_value, Some(wire.wire_chain(signature)), &wire.body, &outcome.counting_removals, outcome.moves_roles, misattributed);
                    tip = Some(next);
                }
                RecordVersionState::Waiting => {
                    chain.seen.remove(&version);
                    break;
                }
            }
        }
    }

    /// Take a prefix of the chain without R2: the account's own head's (by its
    /// word), or the latest record for the account's first device (R1 over it
    /// all; a signer it cannot match is taken on first sight). Sets the head.
    #[allow(clippy::too_many_arguments)]
    fn accept_prefix(
        &self,
        circle_id: &str,
        circle: &[u8; 16],
        chain: &mut CircleChain,
        prefix: Vec<(u32, WireRecord, [u8; 64], [u8; 32])>,
        links: &[KeyChainLinkData],
        members: &[Member],
        own: Option<&OwnRestored>,
        by_account: bool,
        own_head: Option<&Head>,
        now: i64,
        report: &mut RefreshRecordsReport,
    ) -> bool {
        // Held for the anchor walk below; held copies are
        // checked only once the prefix is judged.
        for (version, wire, _signature, chain_value) in &prefix {
            chain.seen.insert(
                *version,
                SeenRecord::new(wire.clone(), *chain_value, RecordVersionState::Reference),
            );
        }
        // Nothing is taken before the anchor's key is checked and S derived.
        if let Err(problem) = self.ensure_secret(circle_id, chain, links) {
            let last = prefix.last().map_or(0, |(v, ..)| *v);
            report.versions.push(status(last, RecordVersionState::Waiting, problem.into()));
            report.ask_for_fresh_copy |= problem == SecretProblem::ChainWalk;
            chain.seen.clear();
            return false;
        }
        let anchor = chain.anchor.clone().expect("set before a prefix");
        let secret = chain.secret.clone().expect("derived above");
        let outcome = judge_prefix(circle, &secret, &anchor, &prefix, members, own, by_account, &chain.waiting, now);
        if outcome.head.is_none() {
            // The first record's signature failed: it waits, and nothing of
            // the prefix is held.
            report.versions.extend(outcome.rows);
            chain.seen.clear();
            return false;
        }
        self.take_prefix(circle_id, chain, outcome, report);
        // Who the account's own head vouches for: a listed member whose
        // code and commitment match an entry its record includes.
        if let (Some(head), Some(secret)) = (own_head, chain.secret.as_ref()) {
            if let Some(record) = chain.seen.get(&head.version) {
                for member in members.iter().filter(|m| m.listed && !m.no_published_keys) {
                    let code = member_code(secret, &member.uid);
                    let commitment = key_commitment(secret, &code, &member.sharing, &member.signing);
                    if record
                        .wire
                        .body
                        .entry(&code)
                        .map_or(false, |e| e.state == EntryState::Included && e.commitment == commitment)
                    {
                        report.head_confirmed_members.push(member.user_id.clone());
                    }
                }
            }
        }
        true
    }

    /// Make a judged prefix this device's chain: its facts, records, history
    /// and head, and the version it seals under: the highest one, not refused
    /// here, with a held copy that verifies its record's tag.
    fn take_prefix(&self, circle_id: &str, chain: &mut CircleChain, outcome: PrefixOutcome, report: &mut RefreshRecordsReport) {
        let head = outcome.head.expect("a prefix with a head");
        let outcome_by_account = outcome.by_account;
        // A record past the head is judged again, with R2, right after the
        // prefix: its row comes from there, once.
        let head_row = i32::try_from(head.version).unwrap_or(i32::MAX);
        report.versions.extend(outcome.rows.into_iter().filter(|row| row.version <= head_row));
        chain.facts = outcome.facts;
        chain.seen = outcome.seen;
        // A record whose tag this device kept vouches as before, whoever signed
        // it (the prefix could verify only the signers confirmed now).
        for (version, seen) in chain.seen.iter_mut() {
            let kept = chain.history.get(version).filter(|step| step.chain == seen.chain).and_then(|step| step.kept);
            if !seen.signed && kept.map_or(false, |kept| kept.is_of(&seen.wire)) {
                seen.signed = true;
            }
        }
        // The held-copy check, now that the prefix is judged: only its records
        // taken with their signature verified here drop a held copy.
        if !self.drop_contradicted_keys(circle_id, chain).is_empty() {
            report.ask_for_fresh_copy = true;
        }
        chain.history.clear();
        let steps: Vec<(u32, WireRecord, [u8; 32], bool, Option<[u8; 64]>)> = chain
            .seen
            .range(..=head.version)
            .map(|(v, record)| (*v, record.wire.clone(), record.chain, record.vouches_for_its_tag(), record.signature))
            .collect();
        for (_, wire, chain_value, vouches, signature) in &steps {
            chain.note_step(wire, *chain_value, *vouches, signature.map(|signature| wire.wire_chain(&signature)));
        }
        chain.head = Some(head.clone());
        if chain.own.as_ref().map_or(false, |own| own.wire.body.version <= head.version) {
            chain.own = None;
        }
        // A version is accepted, and sealed under, only with a held
        // copy that verifies its record's tag: a copy kept while its
        // record is unverified here opens nothing. On the account's
        // own head's word, only a record whose signature verified
        // here opens: the head covers the body alone, so a copy of it
        // with a tag made for another key and a wrap of that key
        // would pick the key sealed under. (An account's first device
        // still trusts what it sees first, as at any first contact.)
        let by_account = outcome_by_account;
        let held = self.held_keys(circle_id);
        let opens = |version: u32, seen: &SeenRecord| {
            seen.state != RecordVersionState::Rejected
                && (!by_account || seen.signed)
                && held.iter().any(|(v, key)| *v == version && seen.wire.key_tag_matches(key))
        };
        chain.sealing = chain.seen.iter().filter(|(v, seen)| **v <= head.version && opens(**v, seen)).map(|(v, _)| *v).max().unwrap_or(0);
        for (version, seen) in chain.seen.iter_mut() {
            if *version <= head.version && opens(*version, seen) {
                seen.state = RecordVersionState::Accepted;
            }
        }
        let head_opens = chain.seen.get(&head.version).map_or(false, |seen| seen.state == RecordVersionState::Accepted);
        report.versions.push(status(
            head.version,
            if head_opens { RecordVersionState::Accepted } else { RecordVersionState::Reference },
            RecordProblem::None,
        ));
    }

    /// Settle a fork between this device's chain and a chain the server
    /// served whole (from the same first record): a removal beats its target.
    /// The side whose chain removes, at the fork's version or later and with
    /// a removal that counts, the signer of the other side's record at that
    /// version stands. The other side's versions go, and a fresh copy is
    /// asked for. Otherwise the circle keeps waiting. Returns whether it
    /// settled. A fork latched above the head is never settled, and so never
    /// ended by the settlement of one at or below it.
    #[allow(clippy::too_many_arguments)]
    fn settle_fork(
        &self,
        circle_id: &str,
        circle: &[u8; 16],
        chain: &mut CircleChain,
        served: &BTreeMap<u32, (WireRecord, [u8; 64])>,
        links: &[KeyChainLinkData],
        members: &[Member],
        own: Option<&OwnRestored>,
        roster_complete: bool,
        now: i64,
        report: &mut RefreshRecordsReport,
    ) -> bool {
        if chain.fork_latched {
            return false;
        }
        let (Some(anchor), Some(head), Some(secret)) = (chain.anchor.clone(), chain.head.clone(), chain.secret.clone()) else {
            return false;
        };
        // The served chain, whole: it starts with the same first record.
        let Some((&first_version, (first, _))) = served.iter().next() else {
            return false;
        };
        if first_version != anchor.v0 || anchor_check(first) != anchor {
            return false;
        }
        let last = served.keys().next_back().copied().unwrap_or(first_version);
        let run = contiguous_run(served, &BTreeMap::new(), last).unwrap_or_default();
        // The fork's version: the first where the served chain parts from ours.
        let theirs: BTreeMap<u32, [u8; 32]> = run.iter().map(|(v, _, _, c)| (*v, *c)).collect();
        let Some((fork_version, ours)) = chain
            .history
            .range(..=head.version)
            .find(|(v, step)| theirs.get(*v).map_or(false, |c| *c != step.chain))
            .map(|(v, step)| (*v, *step))
        else {
            return false;
        };
        let Some(their_signer) = run.iter().find(|(v, ..)| *v == fork_version).map(|(_, wire, ..)| wire.body.signer_code) else {
            return false;
        };
        let outcome = judge_prefix(circle, &secret, &anchor, &run, members, own, false, &BTreeMap::new(), now);
        let removes = |facts: &HashMap<[u8; 32], MemberFact>, code: &[u8; 32]| {
            facts.get(code).map_or(false, |f| f.state == EntryState::Removed && f.version >= fork_version)
        };
        let ours_removes_theirs = removes(&chain.facts, &their_signer);
        let theirs_removes_ours = removes(&outcome.facts, &ours.signer);
        match (ours_removes_theirs, theirs_removes_ours) {
            (true, false) => {
                tracing::warn!(
                    "refresh records: circle {}'s fork at v{} is settled: this device's side removed the other side's signer",
                    circle_id, fork_version
                );
                chain.forked = false;
                report.versions.push(status(fork_version, RecordVersionState::Rejected, RecordProblem::Fork));
                true
            }
            (false, true) if outcome.head.is_some() => {
                tracing::warn!(
                    "refresh records: circle {}'s fork at v{} is settled: the other side removed this device's side's signer; its versions are dropped",
                    circle_id, fork_version
                );
                // This device's chain up to the fork, from the served records.
                let common: Vec<(u32, WireRecord, [u8; 64], [u8; 32])> =
                    run.iter().filter(|(v, ..)| *v < fork_version).cloned().collect();
                let base = judge_prefix(circle, &secret, &anchor, &common, members, own, false, &BTreeMap::new(), now);
                if base.head.is_none() {
                    return false;
                }
                // What this device's side removed from the fork
                // on stays removed: a removal that counts by
                // the roles before the fork (its signer an
                // owner or admin then), not signed by the
                // signer the standing side removed, and never
                // of the owner, kept at its own version. Both
                // the removals its accepted records made (the
                // facts) and those in its records rejected here
                // since its head (the overlay).
                let kept: Vec<([u8; 32], MemberFact)> = {
                    let before = View { circle: *circle, secret: &secret, v0: anchor.v0, facts: &base.facts, removed_overlay: &Overlay::new(), role_overlay: &RoleOverlay::new(), members, own };
                    let counts_before = |signer: &[u8; 32], code: &[u8; 32]| {
                        *signer != ours.signer
                            && matches!(before.role_of_code(signer), Some(ChainRole::Owner | ChainRole::Admin))
                            && base.facts.get(code).map_or(true, |f| f.role != ChainRole::Owner)
                    };
                    let mut kept: Vec<([u8; 32], MemberFact)> = chain
                        .facts
                        .iter()
                        .filter(|(_, fact)| fact.state == EntryState::Removed && fact.version >= fork_version)
                        .filter(|(code, fact)| chain.history.get(&fact.version).map_or(false, |step| counts_before(&step.signer, code)))
                        .map(|(code, fact)| (*code, fact.clone()))
                        .collect();
                    let mut version = head.version + 1;
                    while let Some(rejected) = chain.seen.get(&version).filter(|r| r.state == RecordVersionState::Rejected) {
                        for code in &rejected.counting_removals {
                            let Some(entry) = rejected.wire.body.entry(code) else {
                                continue;
                            };
                            if version >= fork_version && counts_before(&rejected.wire.body.signer_code, code) {
                                let last_included = chain.facts.get(code).map_or(0, |f| f.last_included);
                                let removed = crate::refresh_record::RecordEntry { state: EntryState::Removed, ..entry.clone() };
                                let (included_with_keys, last_spent, vouched_keys) = MemberFact::keyed_after(chain.facts.get(code), &removed, version);
                                let fact = MemberFact {
                                    version,
                                    state: EntryState::Removed,
                                    role: entry.role,
                                    commitment: entry.commitment,
                                    last_included,
                                    departure_may_count: true,
                                    included_with_keys,
                                    last_spent,
                                    vouched_keys,
                                };
                                kept.push((*code, fact));
                            }
                        }
                        version += 1;
                    }
                    kept
                };
                // The losing side's versions from the fork on: only a key the
                // standing side's records vouch for stays (as a lost rotation).
                for (version, key) in self.held_keys(circle_id) {
                    let vouched = outcome.seen.get(&version).map_or(false, |r| r.wire.key_tag_matches(&key));
                    if version >= fork_version && !vouched && self.drop_held_key(circle_id, version) {
                        self.forget_unconfirmed_rotation_at(circle_id, version);
                        tracing::warn!("refresh records: DROPPED circle {} v{}: the losing side's key", circle_id, version);
                    }
                }
                let mut scratch = RefreshRecordsReport {
                    versions: Vec::new(),
                    sealing_version: None,
                    ask_for_fresh_copy: false,
                    forked: false,
                    head_confirmed_members: Vec::new(),
                    tip_named_listed: Vec::new(),
                };
                chain.own = None;
                self.take_prefix(circle_id, chain, base, &mut scratch);
                for (code, fact) in kept {
                    chain.facts.insert(code, fact);
                }
                chain.forked = false;
                // What waited at the fork's version or
                // above was the losing side's.
                chain.waiting.retain(|at, _| *at < fork_version);
                // The standing side's records from the fork on, judged as every
                // device judges them (R1 and R2), against those removals too.
                self.verify_served(circle_id, circle, chain, served.clone(), &BTreeMap::new(), links, members, own, roster_complete, None, now, report);
                report.ask_for_fresh_copy = true;
                true
            }
            _ => false,
        }
    }

    /// What every device can say of `wire`, one of two records for a
    /// version, after `tip`, whatever its member list says (the format's
    /// rules, and the role and removal rules). Pure. A misattributed
    /// candidate is never dropped either: its removals would count, and
    /// beside another candidate it can't be told which of the two the
    /// record after them fixes, so it can't be judged here.
    fn candidate(
        &self,
        chain: &CircleChain,
        circle: &[u8; 16],
        tip: Option<&Tip>,
        wire: &WireRecord,
        signature: &[u8; 64],
        members: &[Member],
        own: Option<&OwnRestored>,
    ) -> Candidate {
        let (Some(anchor), Some(secret), Some(tip)) = (chain.anchor.as_ref(), chain.secret.as_ref(), tip) else {
            return Candidate::Stands;
        };
        match links_to(&wire.body, tip) {
            Some(true) => {}
            Some(false) => return Candidate::Refused(RecordProblem::Fork),
            // Whether it links isn't known here: it can't be judged.
            None => return Candidate::Unjudged,
        }
        let previous = Previous { version: tip.version, format: tip.format, body: tip.body.as_ref(), rejected: tip.rejected, misattributed: tip.misattributed };
        if let Err(problem) = check_against_previous(&wire.body, &chain.facts, &tip.overlay, &previous, anchor.anchor) {
            return Candidate::Refused(problem);
        }
        let view = View { circle: *circle, secret, v0: anchor.v0, facts: &chain.facts, removed_overlay: &tip.overlay, role_overlay: &tip.roles, members, own };
        match signer_of(secret, &chain.facts, members, &wire.body, Some(tip), own) {
            Some(signer) if wire.signature_verifies(signature, &signer.signing) => {
                check_authority(&view, &wire.body, signer.listed_role).map_or_else(Candidate::Refused, |()| Candidate::Stands)
            }
            _ => Candidate::Unjudged,
        }
    }

    /// R1 and R2 on one record above the head. `successor`: what the
    /// record served after it links, when that one is in format 2.
    #[allow(clippy::too_many_arguments)]
    fn judge(
        &self,
        circle_id: &str,
        circle: &[u8; 16],
        chain: &mut CircleChain,
        tip: Option<&Tip>,
        wire: &WireRecord,
        signature: &[u8; 64],
        successor: Option<[u8; 32]>,
        links: &[KeyChainLinkData],
        members: &[Member],
        own: Option<&OwnRestored>,
        roster_complete: bool,
        now: i64,
    ) -> Judgement {
        let body = &wire.body;
        let is_first = matches!(body.kind, RecordKind::Genesis | RecordKind::Transition);
        let empty = Overlay::new();
        let anchor = chain.anchor.clone().expect("set before judging");
        // R1: the rules that read the chain before it.
        if let Some(t) = tip {
            let previous = Previous { version: t.version, format: t.format, body: t.body.as_ref(), rejected: t.rejected, misattributed: t.misattributed };
            if let Err(problem) = check_against_previous(body, &chain.facts, &t.overlay, &previous, anchor.anchor) {
                return Judgement::refused(problem);
            }
            // The link the record names is served.
            if !links.iter().any(|l| l.from_version == body.version as i32 && l.to_version == body.link_to as i32) {
                return Judgement::waiting(RecordProblem::LinkMissing);
            }
        }
        // A transition's own link, down to the anchor, is served.
        if body.kind == RecordKind::Transition
            && !links.iter().any(|l| l.from_version == body.version as i32 && l.to_version == body.link_to as i32)
        {
            return Judgement::waiting(RecordProblem::LinkMissing);
        }
        // The secret, to match codes.
        if let Err(problem) = self.ensure_secret(circle_id, chain, links) {
            return Judgement::waiting(problem.into());
        }
        let secret = chain.secret.as_ref().expect("derived above");
        let overlay = tip.map_or(&empty, |t| &t.overlay);
        let empty_roles = RoleOverlay::new();
        let roles = tip.map_or(&empty_roles, |t| &t.roles);
        let view = View { circle: *circle, secret, v0: anchor.v0, facts: &chain.facts, removed_overlay: overlay, role_overlay: roles, members, own };
        // R1: the signer, found by matching, and its
        // signature.
        let signer = signer_of(secret, &chain.facts, members, body, tip, own);
        // No member this device confirms matches the signer: never
        // passed over, even on a complete list. A server that leaves
        // the signer off it (or serves them with other keys) would
        // otherwise make this device drop the record's removals. It
        // waits; a signer who left is still matched when the app
        // passes them unlisted, with the keys the chain commits to.
        let Some(signer) = signer else {
            return Judgement::waiting(RecordProblem::SignerUnknown);
        };
        // A signature that fails under the signer matched here is
        // never passed over: the chain value covers the body alone,
        // so a server can change the signature bytes without breaking
        // a link, and a record refused here moves nothing, its
        // removals included. The chain waits at this version, as for
        // a missing record, until a copy that verifies is served.
        if !wire.signature_verifies(signature, &signer.signing) {
            // Unless it is signed with the key of ANOTHER member
            // this device confirms, and a record after it fixes
            // these very bytes (it is in format 2, or the record
            // served after it is and links this copy): then it is
            // rejected and passed over, its removals counting by
            // its signer code's role and nothing else moving. A
            // copy the record after it doesn't link isn't the
            // chain's: it waits, as a spoiled copy does.
            let fixed = body.format == RecordFormat::V2 || successor.is_some();
            let this_copy = successor.map_or(true, |linked| linked == wire.wire_chain(signature));
            if fixed && this_copy && !is_first {
                if let Some(by) = misattributed_to(members, wire, signature, &signer.signing) {
                    tracing::warn!(
                        "refresh records: circle {} v{} is signed with {}'s key, not by the member its signer entry names: rejected, passed over",
                        circle_id, body.version, by.user_id
                    );
                    return Judgement { counting_removals: removals_by_its_signer_code(&view, body), ..Judgement::refused(RecordProblem::Misattributed) };
                }
            }
            return Judgement::waiting(RecordProblem::Signature);
        }
        // Roles and removals: hard refusals.
        if !is_first {
            if let Err(problem) = check_authority(&view, body, signer.listed_role) {
                return Judgement { counting_removals: removals_of_a_refused_claim(&view, body), ..Judgement::refused(problem).signed() };
            }
        }
        // R2: everyone it includes is allowed here.
        let r2 = check_included(&view, body, now);
        let signer_role = view.role_of_code(&body.signer_code);
        let counting_removals: HashSet<[u8; 32]> = if matches!(signer_role, Some(ChainRole::Owner | ChainRole::Admin)) {
            body.entries.iter().filter(|e| e.state == EntryState::Removed).map(|e| e.code).collect()
        } else {
            HashSet::new()
        };
        if r2.unmatched > 0 || !r2.not_allowed.is_empty() {
            let problem = if r2.unmatched > 0 { RecordProblem::R2UnmatchedEntry } else { RecordProblem::R2NotAllowed };
            // When the ONLY entry not allowed is its own signer's
            // (a first record has none: R2 asks it no E), that
            // signer matched among the rows this device confirms
            // and an owner or admin in the chain, it waits, on a
            // complete list too, and is judged again at the next
            // import: their admission of their own new keys after a
            // password reset may not be served here yet. Rejected,
            // the key change would be passed over. Nobody else's
            // own entry waits: a self-admission counts only for an
            // owner or admin, and a record by a member the chain
            // doesn't count (a newcomer, one removed) must not hold
            // the repair that passes it over.
            let own_signer_only = signer.by_row
                && matches!(signer_role, Some(ChainRole::Owner | ChainRole::Admin))
                && r2.unmatched == 0
                && r2.not_allowed_codes == [body.signer_code];
            let state = if roster_complete && !own_signer_only { RecordVersionState::Rejected } else { RecordVersionState::Waiting };
            // Rejected only for R2 (R1 and the role and removal rules
            // held): its roles move the chain's, as its counting
            // removals count.
            let moves_roles = state == RecordVersionState::Rejected;
            return Judgement { state, problem, not_allowed: r2.not_allowed, unmatched: r2.unmatched, counting_removals, signed: true, moves_roles };
        }
        // Accepted: the facts move on, and the version is sealed under when
        // this device holds a copy of its key that verifies the tag.
        let after = chain.head.as_ref().map_or(0, |h| h.version);
        apply_accepted(&mut chain.facts, &chain.seen, after, body, if is_first { None } else { signer_role });
        vouch_included_keys(&mut chain.facts, body, secret, members);
        chain.head = Some(ChainHead { version: body.version, chain: wire.chain(), digest: wire.digest });
        if chain.own.as_ref().map_or(false, |own| own.wire.body.version <= body.version) {
            chain.own = None;
        }
        let held = self.held_keys(circle_id).iter().any(|(v, key)| *v == body.version && wire.key_tag_matches(key));
        if held {
            chain.sealing = body.version;
            Judgement { state: RecordVersionState::Accepted, problem: RecordProblem::None, not_allowed: Vec::new(), unmatched: 0, counting_removals: HashSet::new(), signed: true, moves_roles: false }
        } else {
            Judgement { state: RecordVersionState::Reference, problem: RecordProblem::None, not_allowed: Vec::new(), unmatched: 0, counting_removals: HashSet::new(), signed: true, moves_roles: false }
        }
    }

    /// A head of a member the chain still counts, at a version this
    /// device holds, with another chain value, is a fork.
    fn compare_member_heads(
        &self,
        circle_id: &str,
        circle: &[u8; 16],
        chain: &mut CircleChain,
        member_heads: &[MemberHead],
        members: &[Member],
    ) {
        let Some(secret) = chain.secret.as_ref() else {
            return;
        };
        // A removal in a record rejected here is their last word too,
        // until a repair.
        let (overlay, _) = rejected_overlays(chain);
        for member_head in member_heads {
            // The member by their id's bytes: any spelling of it is them.
            let Ok(head_user) = uuid16("user_id", &member_head.user_id) else { continue };
            let Some(member) = members.iter().find(|m| m.confirmed && m.uid == head_user) else {
                continue;
            };
            let code = member_code(secret, &member.uid);
            if chain.facts.get(&code).map_or(false, |f| f.state == EntryState::Removed) || overlay.contains_key(&code) {
                continue;
            }
            let parsed = (|| {
                let bytes = hex::decode(&member_head.head.head_hex).ok()?;
                let head = Head::decode(&bytes).ok()?;
                let bytes: [u8; 69] = bytes.try_into().ok()?;
                let signature = <[u8; 64]>::try_from(hex::decode(&member_head.head.signature_hex).ok()?.as_slice()).ok()?;
                VerifyingKey::from_bytes(&member.signing)
                    .ok()?
                    .verify_strict(&Head::digest(&bytes), &Signature::from_bytes(&signature))
                    .ok()?;
                Some(head)
            })();
            let Some(head) = parsed else { continue };
            if &head.circle_id != circle || head.user_id != member.uid {
                continue;
            }
            if let Some(ours) = chain.value_at(head.version, head.format) {
                if ours != head.chain {
                    tracing::warn!(
                        "refresh records: a member's head for circle {} v{} contradicts this device's chain: the circle waits",
                        circle_id, head.version
                    );
                    chain.forked = true;
                    return;
                }
            }
        }
    }

    /// E for every member in `members`, with the clock passed in.
    pub(crate) fn refresh_eligibility_at(
        &self,
        circle_id: &str,
        members: &[RecordMember],
        purpose: EligibilityPurpose,
        now: i64,
    ) -> Result<Vec<MemberEligibility>, MobileError> {
        let circle = uuid16("circle_id", circle_id)?;
        let members = self.read_members_here(circle_id, members)?;
        let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
        let chain = chains
            .get_mut(&CircleKey::of(&circle_id))
            .filter(|c| c.is_recorded())
            .ok_or_else(|| {
                if self.latched_until_the_store_reads(circle_id) {
                    MobileError::StorageError("the key store can't be read: this circle waits".to_string())
                } else {
                    MobileError::InvalidInput("this circle has no refresh records: the rules for a circle without records apply".to_string())
                }
            })?;
        if chain.forked {
            return Ok(members
                .iter()
                .map(|m| MemberEligibility {
                    user_id: m.user_id.clone(),
                    eligible: false,
                    basis: None,
                    invitation_expired: false,
                    invitation_signer_not_chain_admin: false,
                    removed_by_owner_or_admin: false,
                    removed_at_version: None,
                    email_invitation_without_signed_id: false,
                })
                .collect());
        }
        if self.ensure_secret(circle_id, chain, &[]).is_err() {
            return Err(MobileError::KeyNotFound(
                "this circle's records are not imported in this process yet".to_string(),
            ));
        }
        // The same overlays the builder applies: removals that
        // count in the records rejected here since the head, and
        // the roles those rejected only for R2 moved; after a
        // restart, those of each version passed over that waits.
        let (overlay, roles) = rejected_overlays(chain);
        let secret = chain.secret.as_ref().expect("derived above");
        let v0 = chain.anchor.as_ref().map_or(1, |a| a.v0);
        let view = View { circle, secret, v0, facts: &chain.facts, removed_overlay: &overlay, role_overlay: &roles, members: &members, own: None };
        Ok(members.iter().map(|m| view.eligibility(m, Some(now), purpose == EligibilityPurpose::Deliver)).collect())
    }

    /// The chain's role for `user_id`, if the chain counts them: a removal in
    /// a record rejected here counts, and a departure counts as gone (this
    /// call has no member list).
    pub(crate) fn chain_role_of(&self, circle_id: &str, user_id: &str) -> Option<CircleRole> {
        let uid = uuid16("user_id", user_id).ok()?;
        let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
        let chain = chains.get(&CircleKey::of(&circle_id))?;
        let secret = chain.secret.as_ref()?;
        let code = member_code(secret, &uid);
        // A removal that counts in a record rejected here is their
        // last word until a repair; a role a record rejected here
        // only for R2 gave them is their role.
        let (overlay, roles) = rejected_overlays(chain);
        if overlay.contains_key(&code) {
            return None;
        }
        let fact = chain.facts.get(&code)?;
        let counted = match fact.state {
            EntryState::Removed => false,
            EntryState::Departed => !fact.departure_may_count,
            EntryState::Included | EntryState::Pending => true,
        };
        let role = roles.get(&code).copied().unwrap_or(fact.role);
        counted.then_some(role.into())
    }
}

/// The members the app listed, read. A member passed as confirmed with a key
/// missing fails the call: the app would be vouching for keys it doesn't have.
/// A row that does not read (a user id that is not a UUID, a key that is not
/// 32 bytes) is left out, and logged: it can match nothing.
fn read_members(members: &[RecordMember]) -> Result<Vec<Member>, MobileError> {
    if members.iter().any(|m| m.confirmed && (m.sharing_public_key_hex.is_none() || m.signing_public_key_hex.is_none())) {
        return Err(MobileError::InvalidInput("a member is confirmed with no keys: pass confirmed = false".into()));
    }
    Ok(members
        .iter()
        .filter_map(|member| match Member::read(member) {
            Ok(read) => Some(read),
            Err(e) => {
                tracing::warn!("refresh records: a member row that does not read: {}", e);
                None
            }
        })
        .collect())
}

/// The outcome of judging one record.
struct Judgement {
    state: RecordVersionState,
    problem: RecordProblem,
    not_allowed: Vec<String>,
    unmatched: u32,
    counting_removals: HashSet<[u8; 32]>,
    /// Its signature verified here (R1's signer check
    /// passed).
    signed: bool,
    /// Rejected here only for R2: its roles move the chain's.
    moves_roles: bool,
}

impl Judgement {
    fn refused(problem: RecordProblem) -> Self {
        Judgement { state: RecordVersionState::Rejected, problem, not_allowed: Vec::new(), unmatched: 0, counting_removals: HashSet::new(), signed: false, moves_roles: false }
    }
    fn waiting(problem: RecordProblem) -> Self {
        Judgement { state: RecordVersionState::Waiting, problem, not_allowed: Vec::new(), unmatched: 0, counting_removals: HashSet::new(), signed: false, moves_roles: false }
    }
    /// The same, for a record whose signature verified here.
    fn signed(mut self) -> Self {
        self.signed = true;
        self
    }
}

/// The served records that chain, contiguously, from the first record (or
/// from a step of this device's chain, `held`) up to `end`, each with its
/// chain value. Each links the one before by its format: a format-2 record
/// by that copy's wire_chain, a format-1 record by its chain value, and
/// never after a format-2 record.
fn contiguous_run(
    served: &BTreeMap<u32, (WireRecord, [u8; 64])>,
    held: &BTreeMap<u32, ChainStep>,
    end: u32,
) -> Option<Vec<(u32, WireRecord, [u8; 64], [u8; 32])>> {
    let links = |wire: &WireRecord, chain: &[u8; 32], taken_wire: Option<[u8; 32]>, format: RecordFormat| {
        wire.body.format >= format
            && match wire.body.format {
                RecordFormat::V2 => taken_wire == Some(wire.body.prev_chain),
                RecordFormat::V1 => *chain == wire.body.prev_chain,
            }
    };
    let mut run = Vec::new();
    // The one before: its version, chain value, wire_chain as served, format.
    let mut previous: Option<(u32, [u8; 32], [u8; 32], RecordFormat)> = None;
    for (version, (wire, signature)) in served.range(..=end) {
        let linked = match previous {
            Some((pv, pc, pw, pf)) => pv + 1 == *version && wire.body.prev_version == pv && links(wire, &pc, Some(pw), pf),
            None => {
                (matches!(wire.body.kind, RecordKind::Genesis | RecordKind::Transition) && wire.body.prev_chain == [0u8; 32])
                    || version
                        .checked_sub(1)
                        .and_then(|pv| held.get(&pv))
                        .map_or(false, |step| links(wire, &step.chain, step.wire, step.format))
            }
        };
        if !linked {
            // A break: what came before does not reach `end`.
            run.clear();
            previous = None;
            continue;
        }
        let value = wire.chain();
        run.push((*version, wire.clone(), *signature, value));
        previous = Some((*version, value, wire.wire_chain(signature), wire.body.format));
    }
    (previous.map(|(v, ..)| v) == Some(end)).then_some(run)
}

// ============================================================================
// The builder: this device's own records, and account heads
// ============================================================================

/// What a record this device builds
/// (`prepare_recorded_rotation`) says about one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RecordMemberState {
    /// Given the new key (the signer among them).
    Included,
    /// Still a member, without the new key.
    Pending,
    /// Removed by this device's OWN act: its eject, or its own revoke-access.
    Removed,
    /// Seen gone from this device's complete member list.
    Departed,
}

impl From<RecordMemberState> for EntryState {
    fn from(state: RecordMemberState) -> Self {
        match state {
            RecordMemberState::Included => EntryState::Included,
            RecordMemberState::Pending => EntryState::Pending,
            RecordMemberState::Removed => EntryState::Removed,
            RecordMemberState::Departed => EntryState::Departed,
        }
    }
}

/// The kind of key change a record is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RefreshRecordKind {
    /// With the circle (`prepare_recorded_circle_creation`).
    Genesis,
    /// The first record of a circle created without one (a legacy
    /// circle).
    Transition,
    /// Every rotate-keys and eject-and-rotate.
    Rotation,
    /// A rotation made because this device rejected the record before it.
    Repair,
}

/// One member of a rotation this device plans. `role`: only the chain's owner
/// (or an admin claiming the owner's role, whom this device's list shows as
/// the owner) sets one; for anyone else it is carried over, and a newcomer
/// comes in as a member. A transition sets every role from the list.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PlannedEntry {
    pub user_id: String,
    pub state: RecordMemberState,
    pub role: Option<CircleRole>,
}

/// A rotation with its refresh record, for rotate-keys or eject-and-rotate.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecordedRotationBundle {
    /// The wraps for everyone included, the name, and the link down to the
    /// version the record names.
    pub rotation: crate::types::KeyRotationBundle,
    pub refresh_record: SignedRefreshRecord,
}

/// A new circle with its genesis record: create it under `circle_id` (the id
/// the server reserved), sending `genesis` with it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecordedCircleCreation {
    pub circle_id: String,
    /// The creator's wrap. Its `temp_circle_id` is `circle_id`: nothing to finalize.
    pub creation: crate::types::CircleCreationData,
    pub genesis: SignedRefreshRecord,
}

/// An account head, as `verify_circle_head` reads it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CircleHead {
    pub circle_id: String,
    pub user_id: String,
    pub version: i32,
    pub chain_hex: String,
}

/// Seal `older` under `newer`: a key-chain link from `from` down to `to`.
fn seal_link(newer: &[u8; 32], older: &[u8], from: u32, to: u32) -> Result<KeyChainLinkData, MobileError> {
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(newer).map_err(|_| MobileError::EncryptionFailed)?;
    let encrypted = cipher.encrypt(&XNonce::from(nonce), older).map_err(|_| MobileError::EncryptionFailed)?;
    Ok(KeyChainLinkData {
        from_version: from as i32,
        to_version: to as i32,
        encrypted_key: hex::encode(encrypted),
        nonce: hex::encode(nonce),
    })
}

impl CryptoManager {
    /// Sign `body` with this account's key: the key tag computed with the
    /// new key `key_v`, and for a transition the anchor tag with the anchor
    /// key `key_a`. Then check the record as every other device will, before
    /// anything goes out: its signature under `committed_signing`, the
    /// signing key its signer's entry commits to, its key tag under `key_v`,
    /// and a transition's anchor tag under `key_a`. A record that fails one
    /// would freeze its version on every device (a signature that fails is
    /// never passed over), so it is an error here, and nothing is sent.
    fn sign_record(
        &self,
        body: &RecordBody,
        key_v: &[u8; 32],
        key_a: Option<&[u8]>,
        committed_signing: &[u8; 32],
    ) -> Result<(WireRecord, [u8; 64]), MobileError> {
        let bytes = body.encode()?;
        let digest = crate::refresh_record::record_digest(&bytes);
        let tag = key_tag(key_v, &digest)?;
        #[cfg(test)]
        let tag = tests::tag_corrupted_if_asked(tag, &digest);
        let anchor = key_a.map(|k| anchor_tag(k, &digest)).transpose()?;
        let signature = self.sign_with_identity_key(&crate::refresh_record::signed_digest(&bytes, &tag, anchor.as_ref()))?;
        #[cfg(test)]
        let signature = tests::corrupted_if_asked(signature);
        let mut wire = bytes;
        wire.extend_from_slice(&tag);
        if let Some(anchor) = &anchor {
            wire.extend_from_slice(anchor);
        }
        let wire = WireRecord::parse(&wire)?;
        let anchor_ok = key_a.map_or(true, |key_a| anchor_check(&wire).key_ok(key_a));
        if !wire.signature_verifies(&signature, committed_signing) || !wire.key_tag_matches(key_v) || !anchor_ok {
            tracing::error!("refresh records: the record just made for v{} does not verify here: nothing is sent", body.version);
            return Err(MobileError::CryptoError("the record this device made does not verify: nothing is sent".to_string()));
        }
        Ok((wire, signature))
    }

    /// The builder (`prepare_recorded_rotation`), with the
    /// clock passed in.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_recorded_rotation_at(
        &self,
        circle_id: &str,
        sender_user_id: &str,
        kind: RefreshRecordKind,
        planned: &[PlannedEntry],
        members: &[RecordMember],
        roster_complete: bool,
        circle_name_plaintext: &str,
        now: i64,
    ) -> Result<RecordedRotationBundle, MobileError> {
        let invalid = |what: &str| MobileError::InvalidInput(what.to_string());
        // A personal key slot is no circle: no record of any kind is
        // built on it, so no link seals the personal key for
        // members.
        if crate::crypto::names_a_personal_slot(circle_id) {
            return Err(invalid("a personal key slot is no circle: it is never rotated as one"));
        }
        let circle = uuid16("circle_id", circle_id)?;
        let sender = uuid16("sender_user_id", sender_user_id)?;
        // Everyone the app lists, a row that doesn't read included: the fill
        // below never writes a listed member as departed.
        let listed_uids: Vec<[u8; 16]> =
            members.iter().filter(|m| m.listed).filter_map(|m| uuid16("user_id", &m.user_id).ok()).collect();
        let members = self.read_members_here(circle_id, members)?;
        let own_signing = key32("own signing key", &self.signing_public_key_hex()?)?;
        let own_sharing = self.own_sharing_public_key().ok_or_else(|| MobileError::KeyNotFound("no key pair".into()))?;
        if kind == RefreshRecordKind::Genesis {
            return Err(invalid("a genesis comes with prepare_recorded_circle_creation"));
        }
        let issued_at = u64::try_from(now).map_err(|_| invalid("the clock is before 1970"))?;
        let mut new_key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, new_key.as_mut());

        let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
        let chain = chains.entry(CircleKey::of(&circle_id)).or_default();
        if chain.forked {
            return Err(invalid("this circle's chain forked: it waits"));
        }
        // A record goes only on a chain this process has read from
        // the server, and never on the head below a version that
        // waits here.
        if kind != RefreshRecordKind::Transition {
            if !chain.imported {
                return Err(invalid("import this circle's records first, then rotate"));
            }
            if let Some(at) = chain.waiting.keys().next() {
                return Err(invalid(&format!("v{at} of this circle waits here: no record is built until it's decided")));
            }
        }
        let held = self.held_keys(circle_id);
        // Where the record goes: after the head, or after a record this device
        // rejected there (a repair links it); a transition starts the chain.
        let (version, prev_version, prev_chain, link_to, tip) = if kind == RefreshRecordKind::Transition {
            if chain.is_recorded() {
                return Err(invalid("this circle has records: import them, then rotate"));
            }
            // A keyless listed owner: no transition. It needs
            // exactly one owner entry, as the list shows the roles,
            // and the owner can't be named with no keys; never name
            // someone else owner instead. The circle stays legacy.
            if members.iter().any(|m| m.listed && m.no_published_keys && m.listed_role == Some(ChainRole::Owner)) {
                return Err(invalid("the circle's owner has no published keys yet: no transition until they do"));
            }
            // A transition records the roles on its writer's list
            // at that moment, so its plan is held to the list
            // it's given: the complete roster; every listed
            // member with keys in it (one with no keys is the
            // only omission); and, as each entry is written
            // below, a listed member with exactly their listed
            // role.
            if !roster_complete {
                return Err(invalid("a transition needs the complete roster"));
            }
            let planned_uids = planned.iter().map(|entry| uuid16("user_id", &entry.user_id)).collect::<Result<HashSet<_>, _>>()?;
            if listed_uids.iter().any(|uid| !planned_uids.contains(uid) && !members.iter().any(|m| &m.uid == uid && m.no_published_keys)) {
                return Err(invalid("a transition names every listed member with keys: a listed member is missing"));
            }
            let current = held.iter().map(|(v, _)| *v).max().ok_or_else(|| invalid("no key held for this circle"))?;
            (current + 1, 0, [0u8; 32], current, None)
        } else {
            let tip = Tip::after_rejected(chain).ok_or_else(|| invalid("no record of this circle is accepted here yet"))?;
            // The link goes down to the highest version this device holds.
            let link_to = held.iter().map(|(v, _)| *v).filter(|v| *v <= tip.version).max().ok_or_else(|| invalid("no key held at or below the chain's head"))?;
            // A record in format 2 links the copy below it by
            // its whole wire, which a store written by an older
            // SDK may not hold.
            let prev_chain = tip.wire.ok_or_else(|| invalid("import this circle's records first, then rotate"))?;
            (tip.version + 1, tip.version, prev_chain, link_to, Some(tip))
        };
        let older = held.iter().find(|(v, _)| *v == link_to).map(|(_, k)| k.clone()).ok_or_else(|| invalid("the key to link down to is not held"))?;
        // The circle's secret: for a transition, from the key it links down to,
        // the circle's anchor; else the one this device derived.
        let transition_secret;
        let secret: &[u8; 32] = if kind == RefreshRecordKind::Transition {
            transition_secret = crate::refresh_record::circle_secret(older.as_slice())?;
            &transition_secret
        } else {
            if self.ensure_secret(circle_id, chain, &[]).is_err() {
                return Err(MobileError::KeyNotFound("import this circle's records first".into()));
            }
            chain.secret.as_ref().expect("derived above")
        };
        let empty = Overlay::new();
        let overlay = tip.as_ref().map_or(&empty, |t| &t.overlay);
        let empty_roles = RoleOverlay::new();
        let roles = tip.as_ref().map_or(&empty_roles, |t| &t.roles);
        let view = View { circle, secret, v0: chain.anchor.as_ref().map_or(version, |a| a.v0), facts: &chain.facts, removed_overlay: overlay, role_overlay: roles, members: &members, own: None };
        let previous = tip.as_ref().map(|t| Previous { version: t.version, format: t.format, body: t.body.as_ref(), rejected: t.rejected, misattributed: t.misattributed });

        // The entries.
        let mut entries = Vec::with_capacity(planned.len());
        let mut wrap_to: Vec<(String, [u8; 32])> = Vec::new();
        for plan in planned {
            let uid = uuid16("user_id", &plan.user_id)?;
            let code = view.code_of(&uid);
            let state = EntryState::from(plan.state);
            let row = members.iter().find(|m| m.uid == uid);
            let commitment = match (state, &previous) {
                (EntryState::Included, _) => {
                    let (sharing, signing) = if uid == sender {
                        (own_sharing, own_signing)
                    } else {
                        let member = row.filter(|m| m.confirmed).ok_or_else(|| invalid("an included member must be one this device confirms"))?;
                        (member.sharing, member.signing)
                    };
                    wrap_to.push((plan.user_id.clone(), sharing));
                    key_commitment(secret, &code, &sharing, &signing)
                }
                (_, None) => {
                    // A transition: pending with the keys this device has for
                    // them. A member with no keys yet is left out of the plan;
                    // they come in later by (b) or (c).
                    let member = row.ok_or_else(|| invalid("a pending member must be on the list"))?;
                    if member.no_published_keys {
                        return Err(invalid("a member with no published keys can't be named in a transition: leave them out"));
                    }
                    key_commitment(secret, &code, &member.sharing, &member.signing)
                }
                (_, Some(previous)) => named(&chain.facts, previous, &code).ok_or_else(|| invalid("the chain never named this member"))?,
            };
            let carried = view.carried_role(&code);
            let role = plan.role.map(ChainRole::from).unwrap_or(carried);
            // In a transition, the role written here (after any default) is
            // the one the list shows.
            if previous.is_none() {
                let listed = row.filter(|m| m.listed).ok_or_else(|| invalid("a transition names only members on the list"))?;
                if listed.listed_role != Some(role) {
                    return Err(invalid("a transition records each member's role as the list shows it"));
                }
            }
            entries.push(crate::refresh_record::RecordEntry { code, state, role, commitment });
        }
        // The members the record before included or carried pending
        // whom the plan doesn't name. An app holds no user id for a
        // member who left unseen, so the builder fills them in from
        // the codes, and only with a complete roster (else the record
        // would drop a member of the record before it and be refused):
        // "departed" with their last commitment, or "pending" for an
        // owner or admin when this account is a plain member here (a
        // plain member's record can't make their departure count). A
        // code that is this account's or a listed member's is the
        // plan's omission: refused, never written as a departure.
        // Roles carry over; a filled code is never "removed" (that
        // stays the app's own eject, by user id).
        if let (Some(previous), true) = (&previous, roster_complete) {
            let named_here: HashSet<[u8; 32]> = entries.iter().map(|e| e.code).collect();
            let listed: HashSet<[u8; 32]> = listed_uids.iter().chain(std::iter::once(&sender)).map(|uid| view.code_of(uid)).collect();
            let plain_signer = !matches!(view.role_of(&sender), Some(ChainRole::Owner | ChainRole::Admin));
            for code in named_before(&chain.facts, previous).into_iter().filter(|c| !named_here.contains(c)) {
                if listed.contains(&code) {
                    return Err(invalid("a listed member is missing from the plan: name everyone on the list"));
                }
                let commitment = named(&chain.facts, previous, &code).ok_or_else(|| invalid("the chain never named this member"))?;
                let role = view.carried_role(&code);
                let state = if plain_signer && matches!(role, ChainRole::Owner | ChainRole::Admin) {
                    EntryState::Pending
                } else {
                    EntryState::Departed
                };
                entries.push(crate::refresh_record::RecordEntry { code, state, role, commitment });
            }
        }
        entries.sort_by(|a, b| a.code.cmp(&b.code));
        if entries.iter().filter(|e| e.state == EntryState::Included).count() > MAX_INCLUDED
            || entries.iter().filter(|e| e.state == EntryState::Pending).count() > MAX_PENDING
        {
            return Err(invalid("at most 100 members included and 100 pending"));
        }
        let signer_code = view.code_of(&sender);
        // Every record this device writes is in format 2.
        let body = RecordBody {
            format: RecordFormat::V2,
            kind: match kind {
                RefreshRecordKind::Transition => RecordKind::Transition,
                RefreshRecordKind::Repair => RecordKind::Repair,
                _ => RecordKind::Rotation,
            },
            circle_id: circle,
            version,
            prev_version,
            prev_chain,
            link_to,
            signer_code,
            issued_at,
            entries,
        };
        body.encode()?;
        // The record must pass every check another device will run.
        if let Some(previous) = &previous {
            let anchor = chain.anchor.as_ref().map_or(1, |a| a.anchor);
            check_against_previous(&body, &chain.facts, overlay, previous, anchor)
                .map_err(|p| MobileError::InvalidInput(format!("the plan breaks a record rule ({p:?})")))?;
            let listed_role = members.iter().find(|m| m.uid == sender).and_then(|m| m.listed_role);
            check_authority(&view, &body, listed_role).map_err(|p| MobileError::InvalidInput(format!("the plan needs a right this device lacks ({p:?})")))?;
            let r2 = check_included(&view, &body, now);
            if r2.unmatched > 0 || !r2.not_allowed.is_empty() {
                return Err(MobileError::InvalidInput(format!("the plan includes members not eligible here: {:?}", r2.not_allowed)));
            }
        }

        // The key material, then the record.
        let mut member_keys = Vec::with_capacity(wrap_to.len());
        for (user_id, sharing) in wrap_to {
            member_keys.push(self.wrap_rotation_key(circle_id, sender_user_id, version as i32, &new_key, user_id, &hex::encode(sharing))?);
        }
        let encrypted_name = self.seal_circle_name(&new_key, circle_name_plaintext)?;
        let link = seal_link(&new_key, &older, version, link_to)?;
        let anchor_key = (kind == RefreshRecordKind::Transition).then(|| older.as_slice());
        let (wire, signature) = self.sign_record(&body, &new_key, anchor_key, &own_signing)?;
        if kind == RefreshRecordKind::Transition {
            chain.anchor = Some(anchor_check(&wire));
            chain.secret = Some(Zeroizing::new(*secret));
        }
        chain.own = Some(OwnRecord { wire: wire.clone() });
        self.commit_own_rotation(circle_id, version as i32, &new_key);
        drop(chains);
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after a recorded rotation: {}", e);
        }
        Ok(RecordedRotationBundle {
            rotation: crate::types::KeyRotationBundle {
                new_key_version: version as i32,
                encrypted_name,
                member_keys,
                key_chain_link: Some(link),
            },
            refresh_record: SignedRefreshRecord { record_hex: hex::encode(wire.to_bytes()), signature_hex: hex::encode(signature) },
        })
    }

    /// A new circle with its genesis record, under the id the server
    /// reserved for it, with the clock passed in.
    pub(crate) fn prepare_recorded_circle_creation_at(
        &self,
        creator_user_id: &str,
        reserved_circle_id: &str,
        now: i64,
    ) -> Result<RecordedCircleCreation, MobileError> {
        let creator = uuid16("creator_user_id", creator_user_id)?;
        // A fresh version-4 RFC 4122 id: never the nil UUID, every client's
        // personal-slot sentinel, and never one this device already knows.
        let reserved = uuid::Uuid::parse_str(reserved_circle_id)
            .map_err(|_| MobileError::InvalidInput("the reserved circle id is not a UUID".into()))?;
        if reserved.is_nil() || reserved.get_version_num() != 4 || reserved.get_variant() != uuid::Variant::RFC4122 {
            return Err(MobileError::InvalidInput("the reserved circle id must be a fresh version-4 UUID".into()));
        }
        let circle_id = reserved.hyphenated().to_string();
        if self.has_circle_key(circle_id.clone()) || self.circle_is_recorded_here(&circle_id) {
            return Err(MobileError::InvalidInput("this device already knows that circle id".into()));
        }
        let own_signing = key32("own signing key", &self.signing_public_key_hex()?)?;
        let own_sharing = self.own_sharing_public_key().ok_or_else(|| MobileError::KeyNotFound("no key pair".into()))?;
        let issued_at = u64::try_from(now).map_err(|_| MobileError::InvalidInput("the clock is before 1970".into()))?;
        let creation = self.prepare_circle_creation()?;
        self.finalize_circle_creation(creation.temp_circle_id.clone(), circle_id.clone())?;
        let key = self
            .held_keys(&circle_id)
            .into_iter()
            .find(|(v, _)| *v == 1)
            .map(|(_, k)| k)
            .ok_or_else(|| MobileError::KeyNotFound("the new circle key".into()))?;
        let key: [u8; 32] = key.as_slice().try_into().map_err(|_| MobileError::InvalidKey)?;
        let key = Zeroizing::new(key);
        let secret = crate::refresh_record::circle_secret(key.as_slice())?;
        let code = member_code(&secret, &creator);
        let body = RecordBody {
            format: RecordFormat::V2,
            kind: RecordKind::Genesis,
            circle_id: *uuid::Uuid::parse_str(&circle_id).expect("a UUID").as_bytes(),
            version: 1,
            prev_version: 0,
            prev_chain: [0u8; 32],
            link_to: 0,
            signer_code: code,
            issued_at,
            entries: vec![crate::refresh_record::RecordEntry {
                code,
                state: EntryState::Included,
                role: ChainRole::Owner,
                commitment: key_commitment(&secret, &code, &own_sharing, &own_signing),
            }],
        };
        let (wire, signature) = match self.sign_record(&body, &key, None, &own_signing) {
            Ok(signed) => signed,
            Err(e) => {
                // Nothing goes out, and the key made for it goes too.
                self.forget_circle_keys(&circle_id);
                if let Err(e) = self.persist_keys() {
                    tracing::warn!("Failed to persist keys after dropping a circle whose genesis failed: {}", e);
                }
                return Err(e);
            }
        };
        {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            let chain = chains.entry(CircleKey::of(&circle_id)).or_default();
            chain.latched = true;
            chain.anchor = Some(anchor_check(&wire));
            chain.facts.clear();
            apply(&mut chain.facts, &wire.body, None, &RoleOverlay::new());
            if let Some(fact) = chain.facts.get_mut(&code) {
                fact.vouched_keys = Some((own_sharing, own_signing));
            }
            chain.head = Some(ChainHead { version: 1, chain: wire.chain(), digest: wire.digest });
            chain.sealing = 1;
            chain.secret = Some(secret);
            chain.seen.insert(1, SeenRecord::new(wire.clone(), wire.chain(), RecordVersionState::Accepted).signed(true).with_signature(&signature));
            chain.note_step(&wire, wire.chain(), true, Some(wire.wire_chain(&signature)));
            chain.own = Some(OwnRecord { wire: wire.clone() });
            // This device made the whole chain: as good as imported here.
            chain.imported = true;
        }
        if let Err(e) = self.persist_keys() {
            tracing::warn!("Failed to persist keys after creating a circle: {}", e);
        }
        Ok(RecordedCircleCreation {
            circle_id: circle_id.clone(),
            creation: crate::types::CircleCreationData { temp_circle_id: circle_id, ..creation },
            genesis: SignedRefreshRecord { record_hex: hex::encode(wire.to_bytes()), signature_hex: hex::encode(signature) },
        })
    }

    /// Drop a circle this device just created (`prepare_recorded_circle_creation`)
    /// that the server did not take. Nothing else can be dropped this way.
    pub(crate) fn discard_circle_creation_of(&self, circle_id: &str) -> bool {
        // A personal key slot is never a circle made here: nothing
        // here drops a personal key.
        if crate::crypto::names_a_personal_slot(circle_id) {
            return false;
        }
        let ours = {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            let ours = chains.get(&CircleKey::of(&circle_id)).map_or(false, |chain| {
                chain.head.as_ref().map_or(false, |h| h.version == 1)
                    && chain.own.as_ref().map_or(false, |own| own.wire.body.kind == RecordKind::Genesis)
            });
            if ours {
                chains.remove(&CircleKey::of(&circle_id));
            }
            ours
        };
        if ours {
            self.forget_circle_keys(circle_id);
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after discarding a circle: {}", e);
            }
        }
        ours
    }

    /// This account's head for `circle_id`, signed, in format 2: the
    /// wire_chain of the copy it took at its head.
    pub(crate) fn sign_circle_head_of(&self, circle_id: &str, user_id: &str) -> Result<SignedCircleHead, MobileError> {
        // A personal key slot has no records, so no head.
        if crate::crypto::names_a_personal_slot(circle_id) {
            return Err(MobileError::InvalidInput("a personal key slot is no circle: it has no head".to_string()));
        }
        let circle = uuid16("circle_id", circle_id)?;
        let user = uuid16("user_id", user_id)?;
        let (version, wire) = {
            let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
            let chain = chains.get(&CircleKey::of(&circle_id)).filter(|chain| chain.head.is_some());
            let head = chain.and_then(|chain| chain.head.clone()).ok_or_else(|| MobileError::KeyNotFound("no record of this circle is accepted here".into()))?;
            let wire = chain
                .and_then(|chain| chain.history.get(&head.version))
                .filter(|step| step.chain == head.chain)
                .and_then(|step| step.wire)
                .ok_or_else(|| MobileError::InvalidInput("the head's record isn't known here in full yet: import this circle's records first".into()))?;
            (head.version, wire)
        };
        let bytes = Head { format: RecordFormat::V2, circle_id: circle, user_id: user, version, chain: wire }.encode()?;
        let signature = self.sign_with_identity_key(&Head::digest(&bytes))?;
        Ok(SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(signature) })
    }
}

/// Read a head and check its signature under `signing_public_key`.
pub(crate) fn verify_head(head_hex: &str, signature_hex: &str, signing_public_key_hex: &str) -> Result<Option<CircleHead>, MobileError> {
    let bytes = hex::decode(head_hex).map_err(|_| MobileError::InvalidInput("head is not hex".into()))?;
    let head = Head::decode(&bytes)?;
    let bytes: [u8; 69] = bytes.try_into().map_err(|_| MobileError::InvalidInput("a head is 69 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&key32("signing_public_key_hex", signing_public_key_hex)?).map_err(|_| MobileError::InvalidKey)?;
    let signature = hex::decode(signature_hex).map_err(|_| MobileError::InvalidInput("signature is not hex".into()))?;
    let signature = <[u8; 64]>::try_from(signature.as_slice()).map_err(|_| MobileError::InvalidInput("signature must be 64 bytes".into()))?;
    if key.verify_strict(&Head::digest(&bytes), &Signature::from_bytes(&signature)).is_err() {
        return Ok(None);
    }
    Ok(Some(CircleHead {
        circle_id: uuid::Uuid::from_bytes(head.circle_id).hyphenated().to_string(),
        user_id: uuid::Uuid::from_bytes(head.user_id).hyphenated().to_string(),
        version: head.version as i32,
        chain_hex: hex::encode(head.chain),
    }))
}

// ============================================================================
// The exported surface (thin: every rule above stays out of the bindings)
// ============================================================================

#[uniffi::export]
impl CryptoManager {
    /// Verify a circle's refresh records, right after every key import,
    /// with the records call's reply for that circle (all of it, the first
    /// time in a process: `refresh_head_versions`). `key_chain` is the
    /// circle's chain of links from the key import. `members`: everyone on
    /// this device's member list, with what it confirms about them (this
    /// account included). `roster_complete`: the list is complete, so a
    /// member a record includes that is still not allowed here makes it
    /// REJECTED, not WAITING. `own_head`: this account's own head for the
    /// circle, if the server served one (compared like a member's: under
    /// this account's current key, another chain value at a version seen
    /// here is a fork); `member_heads`: the circle's members' heads. The
    /// report says what each new record is, the version this device now
    /// seals under, whether to ask the members for a fresh copy, and
    /// whether the chain forked.
    #[allow(clippy::too_many_arguments)]
    pub fn import_refresh_records(
        &self,
        circle_id: String,
        records: Vec<SignedRefreshRecord>,
        key_chain: Vec<KeyChainLinkData>,
        members: Vec<RecordMember>,
        roster_complete: bool,
        own_head: Option<SignedCircleHead>,
        member_heads: Vec<MemberHead>,
    ) -> Result<RefreshRecordsReport, MobileError> {
        self.import_refresh_records_at(
            &circle_id,
            &records,
            &key_chain,
            &members,
            roster_complete,
            own_head.as_ref(),
            &member_heads,
            chrono::Utc::now().timestamp(),
        )
    }

    /// Who may get the circle's key, for every member in `members` (the
    /// whole list, as for `import_refresh_records`). INCLUDE: whom a
    /// rotation may give the new key. DELIVER: whom this device may hand
    /// the current key. An error on a circle with no refresh records (the
    /// rules for a circle without records apply there:
    /// `circle_has_refresh_records`), or before its records were imported
    /// in this process.
    pub fn refresh_eligibility(
        &self,
        circle_id: String,
        members: Vec<RecordMember>,
        purpose: EligibilityPurpose,
    ) -> Result<Vec<MemberEligibility>, MobileError> {
        self.refresh_eligibility_at(&circle_id, &members, purpose, chrono::Utc::now().timestamp())
    }

    /// The role the chain of refresh records gives `user_id` in `circle_id`,
    /// if the chain counts them. For the question the apps ask about a
    /// member who may not get the key: who is asked, and whether "{inviter}
    /// invited them." is shown. None when the chain doesn't count them (a
    /// removal in a record rejected here counts), or before this device
    /// knows the circle's secret.
    pub fn chain_role(&self, circle_id: String, user_id: String) -> Option<CircleRole> {
        self.chain_role_of(&circle_id, &user_id)
    }

    /// The `since` map for the records call: each circle with refresh records,
    /// and the version to ask from (0 until its records were imported in this
    /// process, and while its chain is forked; then the head this device
    /// accepted).
    pub fn refresh_head_versions(&self) -> HashMap<String, i32> {
        self.refresh
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, chain)| chain.is_recorded())
            .map(|(circle_id, chain)| {
                // A forked circle asks for the whole chain: that is
                // what settles it. A head whose wire this device
                // doesn't know (a store written by an older SDK) asks
                // for its own record again: a format-2 record links it
                // by that wire.
                let head = chain.head.as_ref().map_or(0, |h| {
                    let wire_known = chain.history.get(&h.version).map_or(false, |step| step.chain == h.chain && step.wire.is_some());
                    if wire_known { h.version } else { h.version - 1 }
                });
                let since = if chain.imported && !chain.forked { head } else { 0 };
                (circle_id.as_str().to_owned(), i32::try_from(since).unwrap_or(0))
            })
            .collect()
    }

    /// A head was seen for this circle (the account's own, or a member's),
    /// so records exist. The circle is never legacy again here, and
    /// nothing is sealed for it until its records are verified.
    pub fn note_circle_has_records(&self, circle_id: String) {
        // A personal key slot has no records: a head "seen" for
        // one latches nothing, so personal rows still seal.
        if crate::crypto::names_a_personal_slot(&circle_id) {
            tracing::warn!("refresh records: a head for a personal key slot latches nothing");
            return;
        }
        let changed = {
            let mut chains = self.refresh.write().unwrap_or_else(|e| e.into_inner());
            let chain = chains.entry(CircleKey::of(&circle_id)).or_default();
            let changed = !chain.latched;
            chain.latched = true;
            changed
        };
        if changed {
            if let Err(e) = self.persist_keys() {
                tracing::warn!("Failed to persist keys after latching a circle: {}", e);
            }
        }
    }

    /// Whether `circle_id` has refresh records here (or a head latched it):
    /// then E decides deliveries and rotations, and a rotation carries a record.
    pub fn circle_has_refresh_records(&self, circle_id: String) -> bool {
        self.circle_is_recorded_here(&circle_id) || self.latched_until_the_store_reads(&circle_id)
    }

    /// Whether this device is behind on `circle_id` by its own knowledge,
    /// whatever key version the server lists for the circle: a version
    /// above what it seals under waits here or was passed over and is
    /// kept, its head was taken without opening it (a reference) and is
    /// above the version it seals under, its chain forked, records exist
    /// and none is taken here, or its key store can't be read. Every
    /// write gate refuses, and queues, while this is true, besides
    /// comparing `get_active_version` with the circle's key version;
    /// `get_active_version` itself doesn't change, so an SOS alert, which
    /// the write gates let through, still seals under it. A rotation of
    /// its own not served back yet is what it seals under: the versions
    /// below it that it passed over don't make it behind. False for a
    /// circle with no records here.
    pub fn is_behind(&self, circle_id: String) -> bool {
        let known = {
            let chains = self.refresh.read().unwrap_or_else(|e| e.into_inner());
            chains.get(&CircleKey::of(&circle_id)).filter(|chain| chain.is_recorded()).map(|chain| {
                let head = chain.head.as_ref().map(|h| h.version);
                let own = chain.own.as_ref().map(|own| own.wire.body.version).filter(|v| head.map_or(true, |h| *v > h));
                match own.or(head) {
                    None => true,
                    Some(top) => {
                        chain.forked
                            || chain.waiting.keys().any(|v| *v > top)
                            || chain.passed_over().keys().any(|v| *v > top)
                            // A head taken without opening
                            // it (a reference: its key not
                            // held, or on the account's
                            // own head's word its record
                            // not verified here) above the
                            // version sealed under, with
                            // nothing of this device's own
                            // above it. What is sealed
                            // under (get_active_version)
                            // stays.
                            || (own.is_none() && head.map_or(false, |h| h > chain.sealing))
                    }
                }
            })
        };
        known.unwrap_or(false) || self.latched_until_the_store_reads(&circle_id)
    }

    /// The newest version of `circle_id`'s key this device HOLDS,
    /// whether or not it may seal under it: for "is my copy current?"
    /// checks, never for sealing (that is `get_active_version`).
    pub fn newest_held_version(&self, circle_id: String) -> Option<i32> {
        self.held_version(&circle_id)
    }

    /// Build a rotation of a circle with refresh records (kind ROTATION or
    /// REPAIR, eject included), or a circle's first record (TRANSITION, by
    /// an owner or admin of a legacy circle, one created without records).
    /// `planned`: the members the app names (this account included, as
    /// INCLUDED): those it includes, those pending by E, its own removals
    /// and the owner's role changes. `members` and `roster_complete`: as
    /// for `import_refresh_records`. With a complete roster, the builder
    /// names the rest of the record before from its codes: a code that
    /// matches nobody listed is "departed" (on a plain member's device, an
    /// owner or admin is carried as "pending" instead); a listed member
    /// the plan leaves out is refused. A TRANSITION records the list as it
    /// is: it needs `roster_complete`, names every listed member who has
    /// keys, each with exactly their listed role, and leaves out only a
    /// member with no keys; a listed owner with no keys means no
    /// transition yet. The record is checked as every other device will
    /// check it, and refused (InvalidInput) otherwise. The new key is this
    /// device's unconfirmed rotation, as with `prepare_key_rotation`: send
    /// the wraps, the link and the record with rotate-keys or
    /// eject-and-rotate, and `discard_unconfirmed_rotation` if the server
    /// does not take them.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recorded_rotation(
        &self,
        circle_id: String,
        sender_user_id: String,
        kind: RefreshRecordKind,
        planned: Vec<PlannedEntry>,
        members: Vec<RecordMember>,
        roster_complete: bool,
        current_circle_name_plaintext: String,
    ) -> Result<RecordedRotationBundle, MobileError> {
        self.prepare_recorded_rotation_at(
            &circle_id,
            &sender_user_id,
            kind,
            &planned,
            &members,
            roster_complete,
            &current_circle_name_plaintext,
            chrono::Utc::now().timestamp(),
        )
    }

    /// A new circle, under `circle_id`, the id the server reserved for it (a
    /// fresh version-4 UUID; never the nil one), with its genesis record signed
    /// by its creator (this account). Create it on the server with the genesis;
    /// if the server does not take it, `discard_circle_creation`.
    pub fn prepare_recorded_circle_creation(
        &self,
        creator_user_id: String,
        circle_id: String,
    ) -> Result<RecordedCircleCreation, MobileError> {
        self.prepare_recorded_circle_creation_at(&creator_user_id, &circle_id, chrono::Utc::now().timestamp())
    }

    /// Drop a circle `prepare_recorded_circle_creation` made that the server
    /// did not take. Returns whether anything was dropped: nothing else can be.
    pub fn discard_circle_creation(&self, circle_id: String) -> bool {
        self.discard_circle_creation_of(&circle_id)
    }

    /// This user's membership of `circle_id` has ended (they left or
    /// deleted it, were removed, or withdrew consent): forget the circle
    /// on this device. Every key held for it goes, with its refresh-record
    /// state and the circle's secret; its members' pins stay. A circle
    /// that had records keeps only a mark of that: re-joined, it waits for
    /// its records whatever the server serves, and nothing is sealed or
    /// delivered on it until one is accepted here. Only `clear_all_keys`
    /// removes the mark. Returns whether anything was held. Never the
    /// personal key slot.
    pub fn forget_circle(&self, circle_id: String) -> bool {
        self.forget_circle_entirely(&circle_id)
    }

    /// This account's head for `circle_id` (the record this device accepted
    /// last), signed with its current key, to publish after each import
    /// that moves it.
    pub fn sign_circle_head(&self, circle_id: String, user_id: String) -> Result<SignedCircleHead, MobileError> {
        self.sign_circle_head_of(&circle_id, &user_id)
    }

    /// Read a head and check it under `signer_signing_public_key_hex` (pass
    /// the key this device confirms for that account). None: the signature
    /// does not verify. An error for malformed bytes.
    pub fn verify_circle_head(
        &self,
        head_hex: String,
        signature_hex: String,
        signer_signing_public_key_hex: String,
    ) -> Result<Option<CircleHead>, MobileError> {
        verify_head(&head_hex, &signature_hex, &signer_signing_public_key_hex)
    }
}

#[cfg(test)]
mod tests {
    //! The refresh-record cases at the SDK level, over real
    //! signed records.

    use super::*;
    use crate::membership::{encode_statement, INVITATION_LIFETIME_SECS};
    use crate::refresh_record::{key_tag, signed_digest, RecordEntry};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use x25519_dalek::{PublicKey, StaticSecret};

    const CIRCLE: &str = "c1c1c1c1-2222-4333-8444-555555555555";
    const NOW: i64 = 1_790_300_000;

    thread_local! {
        /// The next record this thread signs gets a signature that doesn't
        /// verify, as a signing key swapped mid-build or a buggy signer gives.
        static CORRUPT_NEXT_SIGNATURE: std::cell::Cell<bool> = std::cell::Cell::new(false);
    }

    /// `sign_record`'s signature, corrupted when a test asked for it.
    pub(super) fn corrupted_if_asked(mut signature: [u8; 64]) -> [u8; 64] {
        if CORRUPT_NEXT_SIGNATURE.with(|corrupt| corrupt.replace(false)) {
            signature[0] ^= 0x01;
        }
        signature
    }

    thread_local! {
        /// The next record this thread signs gets a key tag made with another
        /// key (and signed as such), as a key mixed up mid-build gives.
        static CORRUPT_NEXT_TAG: std::cell::Cell<bool> = std::cell::Cell::new(false);
    }

    /// `sign_record`'s key tag over `digest`, made with another key when a
    /// test asked for it.
    pub(super) fn tag_corrupted_if_asked(tag: [u8; 32], digest: &[u8; 32]) -> [u8; 32] {
        if CORRUPT_NEXT_TAG.with(|corrupt| corrupt.replace(false)) {
            key_tag(&[0x5a; 32], digest).unwrap()
        } else {
            tag
        }
    }

    /// An account: its user id and keys.
    struct Acct {
        uid: String,
        signing: SigningKey,
        sharing: StaticSecret,
    }

    impl Acct {
        fn new(n: u8) -> Self {
            Acct {
                uid: format!("{n:02x}{n:02x}{n:02x}{n:02x}-0000-4000-8000-0000000000{n:02x}"),
                signing: SigningKey::from_bytes(&[n; 32]),
                sharing: StaticSecret::from([n ^ 0x5a; 32]),
            }
        }
        fn uid16(&self) -> [u8; 16] {
            *uuid::Uuid::parse_str(&self.uid).unwrap().as_bytes()
        }
        fn sharing_pk(&self) -> [u8; 32] {
            PublicKey::from(&self.sharing).to_bytes()
        }
        fn signing_pk(&self) -> [u8; 32] {
            self.signing.verifying_key().to_bytes()
        }
        /// This account's device: its keys loaded, nothing else.
        fn device(&self) -> Arc<CryptoManager> {
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD;
            let cm = CryptoManager::new();
            cm.import_private_key(b64.encode(self.sharing.to_bytes())).unwrap();
            cm.import_signing_private_key(b64.encode(self.signing.to_bytes())).unwrap();
            cm
        }
        /// As a device that confirms them sees them, on the list, as a member.
        fn member(&self) -> RecordMember {
            RecordMember {
                user_id: self.uid.clone(),
                sharing_public_key_hex: Some(hex::encode(self.sharing_pk())),
                signing_public_key_hex: Some(hex::encode(self.signing_pk())),
                confirmed: true,
                listed: true,
                listed_role: Some(CircleRole::Member),
                statements: Vec::new(),
                person_confirmed_keys: false,
                server_says_keyless: false,
            }
        }
        fn statement(&self, kind: MembershipStatementKind, subject: &Acct, at_version: i32, issued_at: i64) -> HeldStatement {
            self.statement_in(CIRCLE, kind, subject, at_version, issued_at)
        }
        fn statement_in(&self, circle: &str, kind: MembershipStatementKind, subject: &Acct, at_version: i32, issued_at: i64) -> HeldStatement {
            self.signed_statement(MembershipStatement {
                kind,
                circle_id: circle.into(),
                statement_id: uuid::Uuid::new_v4().to_string(),
                signer_user_id: self.uid.clone(),
                issued_at,
                expires_at: if kind == MembershipStatementKind::Admission { 0 } else { issued_at + INVITATION_LIFETIME_SECS },
                at_version,
                subject_user_id: Some(subject.uid.clone()),
                subject_sharing_public_key_hex: Some(hex::encode(subject.sharing_pk())),
                subject_signing_public_key_hex: Some(hex::encode(subject.signing_pk())),
                subject_email: None,
            })
        }
        /// An address (kind-2) invitation from this account: it signs the
        /// address, and no user id or keys.
        fn email_invite(&self, email: &str, at_version: i32, issued_at: i64) -> HeldStatement {
            self.signed_statement(MembershipStatement {
                kind: MembershipStatementKind::InvitationToEmail,
                circle_id: CIRCLE.into(),
                statement_id: uuid::Uuid::new_v4().to_string(),
                signer_user_id: self.uid.clone(),
                issued_at,
                expires_at: issued_at + INVITATION_LIFETIME_SECS,
                at_version,
                subject_user_id: None,
                subject_sharing_public_key_hex: None,
                subject_signing_public_key_hex: None,
                subject_email: Some(email.into()),
            })
        }
        fn signed_statement(&self, statement: MembershipStatement) -> HeldStatement {
            let (bytes, _) = encode_statement(&statement).unwrap();
            HeldStatement {
                statement_hex: hex::encode(&bytes),
                signature_hex: hex::encode(self.signing.sign(&statement_digest(&bytes)).to_bytes()),
            }
        }
        /// An invitation from this account, fresh (issued an hour ago).
        fn invite(&self, subject: &Acct, at_version: i32) -> HeldStatement {
            self.statement(MembershipStatementKind::InvitationToAccount, subject, at_version, NOW - 3600)
        }
        fn admit(&self, subject: &Acct, at_version: i32) -> HeldStatement {
            self.statement(MembershipStatementKind::Admission, subject, at_version, NOW - 60)
        }
    }

    fn with(mut member: RecordMember, edit: impl FnOnce(&mut RecordMember)) -> RecordMember {
        edit(&mut member);
        member
    }

    fn circle16() -> [u8; 16] {
        *uuid::Uuid::parse_str(CIRCLE).unwrap().as_bytes()
    }

    /// A circle's history as the server holds it. `format`: the format of the
    /// records pushed from now on.
    #[derive(Clone)]
    struct History {
        format: RecordFormat,
        keys: BTreeMap<u32, [u8; 32]>,
        secret: [u8; 32],
        records: BTreeMap<u32, (WireRecord, [u8; 64])>,
        links: Vec<KeyChainLinkData>,
    }

    fn key_of(version: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&version.to_le_bytes());
        key[4] = 0xc1;
        key
    }

    impl History {
        fn genesis(creator: &Acct) -> Self {
            let secret = *crate::refresh_record::circle_secret(&key_of(1)).unwrap();
            let mut history = History { format: RecordFormat::V1, keys: BTreeMap::new(), secret, records: BTreeMap::new(), links: Vec::new() };
            history.keys.insert(1, key_of(1));
            let entry = history.entry(creator, EntryState::Included, ChainRole::Owner);
            history.push(RecordKind::Genesis, 1, 0, [0; 32], 0, creator, vec![entry]);
            history
        }
        fn code(&self, a: &Acct) -> [u8; 32] {
            member_code(&self.secret, &a.uid16())
        }
        fn entry(&self, a: &Acct, state: EntryState, role: ChainRole) -> RecordEntry {
            let code = self.code(a);
            RecordEntry { code, state, role, commitment: key_commitment(&self.secret, &code, &a.sharing_pk(), &a.signing_pk()) }
        }
        fn latest(&self) -> u32 {
            *self.records.keys().next_back().unwrap()
        }
        #[allow(clippy::too_many_arguments)]
        fn push(
            &mut self,
            kind: RecordKind,
            version: u32,
            prev_version: u32,
            prev_chain: [u8; 32],
            link_to: u32,
            signer: &Acct,
            mut entries: Vec<RecordEntry>,
        ) -> u32 {
            entries.sort_by(|a, b| a.code.cmp(&b.code));
            let body = RecordBody {
                format: self.format,
                kind,
                circle_id: circle16(),
                version,
                prev_version,
                prev_chain,
                link_to,
                signer_code: self.code(signer),
                issued_at: (NOW - 1000) as u64 + u64::from(version),
                entries,
            };
            let bytes = body.encode().unwrap();
            let key = *self.keys.entry(version).or_insert_with(|| key_of(version));
            let digest = crate::refresh_record::record_digest(&bytes);
            let tag = key_tag(&key, &digest).unwrap();
            // A transition also carries the anchor tag, over the key it links to.
            let anchor = (kind == RecordKind::Transition).then(|| anchor_tag(&self.keys[&link_to], &digest).unwrap());
            let signature = signer.signing.sign(&signed_digest(&bytes, &tag, anchor.as_ref())).to_bytes();
            let mut wire_bytes = bytes;
            wire_bytes.extend_from_slice(&tag);
            if let Some(anchor) = &anchor {
                wire_bytes.extend_from_slice(anchor);
            }
            self.records.insert(version, (WireRecord::parse(&wire_bytes).unwrap(), signature));
            if link_to >= 1 {
                self.add_link(version, link_to);
            }
            version
        }
        fn add_link(&mut self, from: u32, to: u32) {
            let (from_key, to_key) = (self.keys[&from], self.keys[&to]);
            self.add_raw_link(from, to, &from_key, &to_key);
        }
        fn add_raw_link(&mut self, from: u32, to: u32, from_key: &[u8; 32], carried: &[u8; 32]) {
            let nonce = [from as u8 ^ to as u8; 24];
            let cipher = XChaCha20Poly1305::new_from_slice(from_key).unwrap();
            let encrypted = cipher.encrypt(&XNonce::from(nonce), carried.as_ref()).unwrap();
            self.links.push(KeyChainLinkData {
                from_version: from as i32,
                to_version: to as i32,
                encrypted_key: hex::encode(encrypted),
                nonce: hex::encode(nonce),
            });
        }
        /// A rotation (or repair) by `signer` to the next version.
        fn rotate(&mut self, kind: RecordKind, signer: &Acct, entries: Vec<RecordEntry>, link_to: Option<u32>) -> u32 {
            let prev = self.latest();
            // A format-2 record links the record before by its whole wire.
            let (prev_wire, prev_signature) = &self.records[&prev];
            let prev_chain = match self.format {
                RecordFormat::V2 => prev_wire.wire_chain(prev_signature),
                RecordFormat::V1 => prev_wire.chain(),
            };
            self.push(kind, prev + 1, prev, prev_chain, link_to.unwrap_or(prev), signer, entries)
        }
        fn signed(&self) -> Vec<SignedRefreshRecord> {
            self.records
                .values()
                .map(|(wire, signature)| SignedRefreshRecord {
                    record_hex: hex::encode(wire.to_bytes()),
                    signature_hex: hex::encode(signature),
                })
                .collect()
        }
    }

    /// Give `device` the key for `version`, as a wrap would.
    fn give(device: &CryptoManager, history: &History, version: u32) {
        assert!(device.add_verified_key(CIRCLE, version, &history.keys[&version]) || device.held_keys(CIRCLE).iter().any(|(v, _)| *v == version));
    }

    fn import(device: &CryptoManager, history: &History, members: &[RecordMember], complete: bool) -> RefreshRecordsReport {
        device
            .import_refresh_records_at(CIRCLE, &history.signed(), &history.links, members, complete, None, &[], NOW)
            .unwrap()
    }

    fn state_of_version(report: &RefreshRecordsReport, version: u32) -> (RecordVersionState, RecordProblem) {
        let row = report
            .versions
            .iter()
            .find(|r| r.version == version as i32)
            .unwrap_or_else(|| panic!("v{version} in {:?}", report.versions));
        (row.state, row.problem)
    }

    fn eligible(device: &CryptoManager, members: &[RecordMember], who: &Acct, purpose: EligibilityPurpose) -> MemberEligibility {
        device
            .refresh_eligibility_at(CIRCLE, members, purpose, NOW)
            .unwrap()
            .into_iter()
            .find(|e| e.user_id == who.uid)
            .unwrap()
    }

    /// The owner A, admin C, members B and D: a circle at v2 that the owner's
    /// device verified, with invitations for the newcomers.
    struct Fixture {
        a: Acct,
        b: Acct,
        c: Acct,
        d: Acct,
        history: History,
    }

    fn fixture() -> Fixture {
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let mut history = History::genesis(&a);
        let entries = vec![
            history.entry(&a, EntryState::Included, ChainRole::Owner),
            history.entry(&b, EntryState::Included, ChainRole::Member),
            history.entry(&c, EntryState::Included, ChainRole::Admin),
        ];
        history.rotate(RecordKind::Rotation, &a, entries, None);
        Fixture { a, b, c, d, history }
    }

    /// The members as a device that confirms everyone sees them, with the
    /// owner's invitations for the newcomers of v2.
    fn members_of(f: &Fixture) -> Vec<RecordMember> {
        vec![
            with(f.a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(f.b.member(), |m| m.statements = vec![f.a.invite(&f.b, 1)]),
            with(f.c.member(), |m| {
                m.statements = vec![f.a.invite(&f.c, 1)];
                m.listed_role = Some(CircleRole::Admin);
            }),
            f.d.member(),
        ]
    }

    /// A copy of `key` for `version`, wrapped to `acct` and signed by `acct`'s
    /// own device (sender = recipient = acct), as a rotation's self-wrap is.
    fn own_copy(device: &CryptoManager, acct: &Acct, version: u32, key: &[u8; 32]) -> Result<(), MobileError> {
        let ephemeral = StaticSecret::from([version as u8 ^ 0x33; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(acct.sharing_pk()));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = [0x44u8; 24];
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap();
        let ciphertext = cipher.encrypt(&XNonce::from(nonce), key.as_ref()).unwrap();
        let eph_hex = hex::encode(PublicKey::from(&ephemeral).as_bytes());
        let signature = device
            .sign_wrap(crate::types::SignWrapParams {
                domain: "pingolin.sig.v1.circle_member_wrap".into(),
                sender_user_id: acct.uid.clone(),
                recipient_user_id: acct.uid.clone(),
                circle_id: CIRCLE.into(),
                place_id: String::new(),
                key_version: version,
                ephemeral_pubkey_hex: eph_hex.clone(),
                wrap_nonce_hex: hex::encode(nonce),
                wrap_ciphertext_hex: hex::encode(&ciphertext),
            })
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        device.store_circle_key(
            CIRCLE.into(),
            hex::encode(blob),
            eph_hex,
            version as i32,
            acct.uid.clone(),
            acct.uid.clone(),
            Some(signature),
            None,
        )
    }

    /// A copy of `key` for `version` of `circle`, wrapped to `acct` by someone
    /// else and unsigned: taken on trust at first contact (a provenance mark).
    fn unsigned_first_contact(device: &CryptoManager, acct: &Acct, circle: &str, version: u32, key: &[u8; 32]) -> Result<(), MobileError> {
        let ephemeral = StaticSecret::from([version as u8 ^ 0x77; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(acct.sharing_pk()));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = [0x55u8; 24];
        let ciphertext = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap().encrypt(&XNonce::from(nonce), key.as_ref()).unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        device.store_circle_key(
            circle.into(),
            hex::encode(blob),
            hex::encode(PublicKey::from(&ephemeral).as_bytes()),
            version as i32,
            Acct::new(0x5e).uid,
            acct.uid.clone(),
            None,
            None,
        )
    }

    /// A device of `acct` that accepted v1 as the lone first record, then
    /// imports `history` up to `upto` holding the keys in `keys`.
    fn device_at(acct: &Acct, creator: &Acct, history: &History, members: &[RecordMember], keys: &[u32]) -> (Arc<CryptoManager>, RefreshRecordsReport) {
        let device = acct.device();
        give(&device, history, 1);
        let mut genesis_only = History::genesis(creator);
        genesis_only.links.clear();
        // The genesis as it was taken: its creator on the list then (an
        // unlisted signer is found only through an inclusion taken here).
        let then: Vec<RecordMember> = members.iter().map(|m| with(m.clone(), |m| m.listed = true)).collect();
        let first = import(&device, &genesis_only, &then, true);
        assert_eq!(state_of_version(&first, 1).0, RecordVersionState::Accepted);
        for version in keys {
            give(&device, history, *version);
        }
        let report = import(&device, history, members, true);
        (device, report)
    }

    /// Seal `plain` under `key` the way the circle's data is (v2 AAD for a
    /// field), for the read-side checks.
    fn sealed_under(key: &[u8; 32], plain: &str) -> crate::types::EncryptedData {
        crate::crypto::encrypt_for_tests(key, CIRCLE, plain.as_bytes())
    }

    #[test]
    fn a_lone_genesis_is_judged_and_sealed_under() {
        let a = Acct::new(0xa1);
        let history = History::genesis(&a);
        let device = a.device();
        give(&device, &history, 1);
        let report = import(&device, &history, &[a.member()], true);
        assert_eq!(state_of_version(&report, 1), (RecordVersionState::Accepted, RecordProblem::None));
        assert_eq!(report.sealing_version, Some(1));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 1);
        assert!(device.circle_has_refresh_records(CIRCLE.into()));
        assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
        let e = eligible(&device, &[a.member()], &a, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (true, Some(EligibilityBasis::CountedByChain)));
    }

    #[test]
    fn newcomers_need_an_owner_or_admins_invitation() {
        let f = fixture();
        let device = f.b.device();
        give(&device, &f.history, 2);
        // With the owner's invitations: v1 and v2 accepted, as a first device
        // would anchor, and then again with R2 on a device that held v1.
        let report = import(&device, &f.history, &members_of(&f), true);
        assert_eq!(state_of_version(&report, 2).0, RecordVersionState::Accepted);

        // A device that held v1's record judges v2 with R2.
        let owner = f.a.device();
        give(&owner, &f.history, 1);
        let mut genesis_only = History::genesis(&f.a);
        genesis_only.links.clear();
        import(&owner, &genesis_only, &members_of(&f), true);
        give(&owner, &f.history, 2);
        let report = import(&owner, &f.history, &members_of(&f), true);
        assert_eq!(state_of_version(&report, 2), (RecordVersionState::Accepted, RecordProblem::None));
        assert_eq!(report.sealing_version, Some(2));

        // Without them: waiting on an incomplete list, rejected on a complete one.
        let no_statements: Vec<RecordMember> =
            members_of(&f).into_iter().map(|m| with(m, |m| m.statements.clear())).collect();
        let fresh = f.a.device();
        give(&fresh, &f.history, 1);
        import(&fresh, &genesis_only, &no_statements, true);
        give(&fresh, &f.history, 2);
        let report = import(&fresh, &f.history, &no_statements, false);
        assert_eq!(state_of_version(&report, 2), (RecordVersionState::Waiting, RecordProblem::R2NotAllowed));
        assert_eq!(report.sealing_version, Some(1), "nothing is sealed under v2");
        let report = import(&fresh, &f.history, &no_statements, true);
        let row = report.versions.iter().find(|r| r.version == 2).unwrap();
        assert_eq!((row.state, row.problem), (RecordVersionState::Rejected, RecordProblem::R2NotAllowed));
        let mut not_allowed = row.not_allowed.clone();
        not_allowed.sort();
        assert_eq!(not_allowed, vec![f.b.uid.clone(), f.c.uid.clone()]);
        assert_eq!(fresh.get_active_version(CIRCLE.into()).unwrap(), 1);
        assert_eq!(fresh.newest_held_version(CIRCLE.into()), Some(2), "held for reading, not sealed under");

        // A plain member's invitation doesn't make anyone eligible.
        let by_member: Vec<RecordMember> = members_of(&f)
            .into_iter()
            .map(|m| if m.user_id == f.c.uid { with(m, |m| m.statements = vec![f.b.invite(&f.c, 1)]) } else { m })
            .collect();
        let other = f.a.device();
        give(&other, &f.history, 1);
        import(&other, &genesis_only, &by_member, true);
        give(&other, &f.history, 2);
        let report = import(&other, &f.history, &by_member, true);
        assert_eq!(state_of_version(&report, 2).1, RecordProblem::R2NotAllowed);
    }

    use EntryState::{Departed, Included, Pending, Removed};
    use RecordVersionState::{Accepted, Reference, Rejected, Waiting};

    /// A chain of four: owner A, member B, admin C and member D, all invited by
    /// the owner at v1 and included at v2.
    fn four() -> (Acct, Acct, Acct, Acct, History) {
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let mut history = History::genesis(&a);
        let entries = vec![
            history.entry(&a, Included, ChainRole::Owner),
            history.entry(&b, Included, ChainRole::Member),
            history.entry(&c, Included, ChainRole::Admin),
            history.entry(&d, Included, ChainRole::Member),
        ];
        history.rotate(RecordKind::Rotation, &a, entries, None);
        (a, b, c, d, history)
    }

    fn four_members(a: &Acct, b: &Acct, c: &Acct, d: &Acct) -> Vec<RecordMember> {
        vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(b.member(), |m| m.statements = vec![a.invite(b, 1)]),
            with(c.member(), |m| {
                m.statements = vec![a.invite(c, 1)];
                m.listed_role = Some(CircleRole::Admin);
            }),
            with(d.member(), |m| m.statements = vec![a.invite(d, 1)]),
        ]
    }

    fn rows(h: &History, rows: &[(&Acct, EntryState, ChainRole)]) -> Vec<RecordEntry> {
        rows.iter().map(|(acct, state, role)| h.entry(acct, *state, *role)).collect()
    }

    fn same(a: &Acct) -> Acct {
        Acct { uid: a.uid.clone(), signing: a.signing.clone(), sharing: a.sharing.clone() }
    }

    #[test]
    fn a_removed_member_never_comes_back_by_old_statements() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        // v3: the owner ejects X.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let members = |x_statements: Vec<HeldStatement>| {
            vec![
                with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.statements = vec![a.invite(&b, 1)]),
                with(c.member(), |m| {
                    m.statements = vec![a.invite(&c, 1)];
                    m.listed_role = Some(CircleRole::Admin);
                }),
                // The server keeps listing X ("keep"), with X's old invitation ("re-add").
                with(x.member(), |m| m.statements = x_statements),
            ]
        };
        let old = members(vec![a.invite(&x, 1)]);
        let (device, report) = device_at(&a, &a, &h, &old, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        let e = eligible(&device, &old, &x, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin, "{e:?}");
        assert!(!eligible(&device, &old, &x, EligibilityPurpose::Deliver).eligible);
        // A record that includes X again on its old invitation is refused.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        give(&device, &h, 4);
        let report = import(&device, &h, &old, true);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3, "nothing is sealed under v4");
        // A NEW admission by an admin in the chain, at or after the removal,
        // brings X back; one before it, or by a plain member, does not.
        assert_eq!(
            eligible(&device, &members(vec![c.admit(&x, 3)]), &x, EligibilityPurpose::Include).basis,
            Some(EligibilityBasis::Admission)
        );
        assert!(!eligible(&device, &members(vec![c.admit(&x, 2)]), &x, EligibilityPurpose::Include).eligible);
        assert!(!eligible(&device, &members(vec![b.admit(&x, 3)]), &x, EligibilityPurpose::Include).eligible);
        // A new invitation by the owner after the removal counts (c).
        assert_eq!(
            eligible(&device, &members(vec![a.invite(&x, 3)]), &x, EligibilityPurpose::Include).basis,
            Some(EligibilityBasis::Invitation)
        );
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids
    }

    /// A listed newcomer this device doesn't confirm, included by a record
    /// it rejects: the version's row and the report's tip name every
    /// listed member that record names, the newcomer among them and not an
    /// off-list one; a plan built on it that carries the newcomer pending
    /// is taken, and one that leaves them out is still refused.
    #[test]
    fn an_unconfirmed_listed_newcomer_is_named_and_a_plan_carries_them_pending() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let (n, gone) = (Acct::new(0x6e), Acct::new(0x6f));
        let v3 = rows(
            &h,
            &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&n, Included, Member), (&gone, Included, Member)],
        );
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let mut members = four_members(&a, &b, &c, &d);
        let mut unconfirmed = n.member();
        unconfirmed.confirmed = false;
        members.push(unconfirmed);
        // Known here, but off the list: not a member a plan must name.
        let mut unlisted = gone.member();
        (unlisted.confirmed, unlisted.listed) = (false, false);
        members.push(unlisted);
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        let row = report.versions.iter().find(|r| r.version == 3).unwrap();
        assert_eq!((row.state, row.problem, row.unmatched_entries), (Rejected, RecordProblem::R2UnmatchedEntry, 2));
        let listed = sorted(vec![a.uid.clone(), b.uid.clone(), c.uid.clone(), d.uid.clone(), n.uid.clone()]);
        assert_eq!(sorted(row.named_listed.clone()), listed);
        assert_eq!(sorted(report.tip_named_listed.clone()), listed, "the tip is v3");
        assert!(row.not_allowed.is_empty());
        // The owner ejects D on that tip: without the newcomer, refused.
        let eject = |with_newcomer: bool| {
            let mut rows = vec![(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)];
            if with_newcomer {
                rows.push((&n, S::Pending, None));
            }
            device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &plan(&rows), &members, true, "n", NOW)
        };
        assert!(matches!(eject(false), Err(MobileError::InvalidInput(ref why)) if why.contains("a listed member is missing from the plan")));
        assert_eq!(eject(true).unwrap().rotation.new_key_version, 4);
    }

    /// v3 includes a newcomer N whom E doesn't allow here, and v4 carries N
    /// pending and includes another, M. Both are rejected here, so the tip is
    /// v4, where N appears in no `not_allowed`: only `named_listed` names N,
    /// and a plan must carry both.
    #[test]
    fn a_rejected_tips_pending_entry_is_named_too() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let (n, m) = (Acct::new(0x6e), Acct::new(0x6d));
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&n, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(
            &h,
            &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&n, Pending, Member), (&m, Included, Member)],
        );
        h.rotate(RecordKind::Rotation, &c, v4, None);
        // N and M are listed and confirmed, with nothing that lets E allow them.
        let mut members = four_members(&a, &b, &c, &d);
        members.push(n.member());
        members.push(m.member());
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        let row = |v: i32| report.versions.iter().find(|r| r.version == v).unwrap();
        assert_eq!((row(3).state, row(3).problem, row(3).not_allowed.clone()), (Rejected, RecordProblem::R2NotAllowed, vec![n.uid.clone()]));
        assert_eq!((row(4).state, row(4).problem, row(4).not_allowed.clone()), (Rejected, RecordProblem::R2NotAllowed, vec![m.uid.clone()]));
        let listed_v4 = sorted(vec![a.uid.clone(), b.uid.clone(), c.uid.clone(), d.uid.clone(), n.uid.clone(), m.uid.clone()]);
        assert_eq!(sorted(row(4).named_listed.clone()), listed_v4);
        assert_eq!(sorted(report.tip_named_listed.clone()), listed_v4, "the tip is v4");
        let rotate = |with_n: bool| {
            let mut rows = vec![(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None), (&m, S::Pending, None)];
            if with_n {
                rows.push((&n, S::Pending, None));
            }
            device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &plan(&rows), &members, true, "n", NOW)
        };
        assert!(matches!(rotate(false), Err(MobileError::InvalidInput(ref why)) if why.contains("a listed member is missing from the plan")));
        assert_eq!(rotate(true).unwrap().rotation.new_key_version, 5);
        // With the tip accepted (v2), the report names nobody.
        let (a, b, c, d, h) = four();
        let (_, clean) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
        assert!(clean.versions.iter().all(|r| r.state != Rejected) && clean.tip_named_listed.is_empty());
    }

    #[test]
    fn an_invented_member_is_refused_and_a_repair_follows() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        let row = report.versions.iter().find(|r| r.version == 3).unwrap();
        assert_eq!((row.state, row.problem, row.unmatched_entries), (Rejected, RecordProblem::R2UnmatchedEntry, 1));
        assert!(!row.named_listed.contains(&ghost.uid), "the ghost is on nobody's list");
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2, "nothing is sealed under v3");
        assert_eq!(device.newest_held_version(CIRCLE.into()), Some(3), "held, for reading");
        // On an incomplete list it only waits.
        let other = a.device();
        give(&other, &h, 1);
        let mut genesis_only = History::genesis(&a);
        genesis_only.links.clear();
        import(&other, &genesis_only, &members, true);
        give(&other, &h, 2);
        give(&other, &h, 3);
        let report = other.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, false, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::R2UnmatchedEntry));
        assert_eq!(other.get_active_version(CIRCLE.into()).unwrap(), 2);
        // The owner's repair links the rejected record and names the ghost
        // departed (it is on nobody's list).
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        give(&device, &h, 4);
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 4);
    }

    #[test]
    fn a_copy_that_fails_its_records_tag_is_never_used_and_a_right_one_resumes() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h2) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h2, &members, &[2]);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        let mut h3 = h2.clone();
        let v3 = rows(&h3, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h3.rotate(RecordKind::Rotation, &a, v3, None);
        let right = h3.keys[&3];
        // The server hands this device ITS OWN key as v3, before the record:
        // with no record yet, reads go on.
        let swapped = [0x99u8; 32];
        assert!(device.add_verified_key(CIRCLE, 3, &swapped));
        let forged = sealed_under(&swapped, "a forged location");
        assert_eq!(device.decrypt_data_v2(CIRCLE.into(), forged.clone(), "test".into()).unwrap(), "a forged location");
        // With the record held, the copy is dropped: nothing reads or seals under it.
        let report = import(&device, &h3, &members, true);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::KeyTag));
        assert!(report.ask_for_fresh_copy);
        assert!(device.decrypt_data_v2(CIRCLE.into(), forged, "test".into()).is_err(), "a forged location no longer decrypts");
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        assert_eq!(device.newest_held_version(CIRCLE.into()), Some(2));
        // Another wrong copy is refused; the right one is stored, and v3 is accepted.
        assert!(matches!(own_copy(&device, &a, 3, &swapped), Err(MobileError::SignatureInvalid)));
        own_copy(&device, &a, 3, &right).unwrap();
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        let genuine = sealed_under(&right, "a member's location");
        assert_eq!(device.decrypt_data_v2(CIRCLE.into(), genuine, "test".into()).unwrap(), "a member's location");
    }

    #[test]
    fn a_wrong_key_at_the_anchor_derives_no_secret() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v2's link carries another key than v1's.
        let mut bad = h.clone();
        bad.links.clear();
        let key2 = bad.keys[&2];
        bad.add_raw_link(2, 1, &key2, &[0x77; 32]);
        let device = d.device();
        give(&device, &h, 2);
        let report = import(&device, &bad, &members, true);
        assert_eq!(state_of_version(&report, 2), (Waiting, RecordProblem::ChainWalk));
        assert!(report.ask_for_fresh_copy);
        assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing is sealed");
        assert!(device.refresh_eligibility_at(CIRCLE, &members, EligibilityPurpose::Include, NOW).is_err());
        assert!(device.held_keys(CIRCLE).iter().all(|(v, _)| *v != 1), "the wrong key is not stored");
        // The right link: the secret, and v2 accepted.
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 1 && k.as_slice() == h.keys[&1]), "v1's key, checked, is stored");
    }

    #[test]
    fn a_link_below_the_signers_floor_is_refused() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let mut low = h.clone();
        low.rotate(RecordKind::Rotation, &c, v3.clone(), Some(1));
        let (_, report) = device_at(&a, &a, &low, &four_members(&a, &b, &c, &d), &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Floor));
        h.rotate(RecordKind::Rotation, &c, v3, Some(2));
        let (_, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
    }

    #[test]
    fn a_version_never_received_is_the_reference_for_the_next() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, mut h) = four();
        // v3: admin C ejects X and leaves the owner pending; A never gets key 3.
        let v3 = rows(&h, &[(&a, Pending, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        // v4: the owner rotates from below, down to v2, the last it was included in.
        let mut back = h.clone();
        let v4 = rows(&back, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        back.rotate(RecordKind::Rotation, &a, v4, Some(2));
        let members = four_members(&a, &b, &c, &x);
        let (device, report) = device_at(&a, &a, &back, &members, &[2, 4]);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 4);
        assert!(!eligible(&device, &members, &x, EligibilityPurpose::Include).eligible, "v3's removal holds");
        // A from-below rotation that brings X back on its old invitation is refused.
        let v4_with_x = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v4_with_x, Some(2));
        let (_, report) = device_at(&a, &a, &h, &members, &[2, 4]);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
    }

    #[test]
    fn links_on_a_recorded_circle_are_named_and_checked() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Pending, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v4, Some(2));
        // A fresh device holding only key 4: the walk takes the named 4 -> 2
        // step and the one-step 2 -> 1, each checked, and stores them.
        let device = d.device();
        give(&device, &h, 4);
        let report = import(&device, &h, &four_members(&a, &b, &c, &d), true);
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        let held: Vec<u32> = device.held_keys(CIRCLE).iter().map(|(v, _)| *v).collect();
        assert!(held.contains(&2) && held.contains(&1), "{held:?}");
        let link = |from: u32, to: u32, carried: &[u8; 32]| {
            let mut one = History { links: Vec::new(), ..h.clone() };
            let from_key = h.keys[&from];
            one.add_raw_link(from, to, &from_key, carried);
            one.links.remove(0)
        };
        let try_link = |l: KeyChainLinkData| {
            device.import_key_chain_link(CIRCLE.into(), l.from_version, l.to_version, l.encrypted_key, l.nonce)
        };
        // An unnamed multi-step link is refused.
        assert!(try_link(link(4, 1, &h.keys[&1])).is_err());
        // The named step carrying another version's key is refused.
        assert!(try_link(link(4, 2, &h.keys[&1])).is_err());
        // A one-step link carrying another key is refused, the right key is taken.
        assert!(try_link(link(4, 3, &[0x31; 32])).is_err());
        try_link(link(4, 3, &h.keys[&3])).unwrap();
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 3 && k.as_slice() == h.keys[&3]));
    }

    /// One record by a signer on top of `four()`'s v2, judged by the owner's
    /// device with the members as `members_edit` leaves them.
    fn judged(
        signer_of: impl Fn(&Acct, &Acct, &Acct, &Acct) -> Acct,
        entries: impl Fn(&History, &Acct, &Acct, &Acct, &Acct) -> Vec<RecordEntry>,
        members_edit: impl Fn(&mut Vec<RecordMember>),
    ) -> (RecordVersionState, RecordProblem, Arc<CryptoManager>, Vec<RecordMember>, Acct) {
        let (a, b, c, d, mut h) = four();
        let v3 = entries(&h, &a, &b, &c, &d);
        let signer = signer_of(&a, &b, &c, &d);
        h.rotate(RecordKind::Rotation, &signer, v3, None);
        let mut members = four_members(&a, &b, &c, &d);
        members_edit(&mut members);
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        let (state, problem) = state_of_version(&report, 3);
        (state, problem, device, members, d)
    }

    #[test]
    fn removals_need_an_owner_or_admin_and_never_touch_the_owner() {
        use ChainRole::{Admin, Member, Owner};
        // A plain member's record removing the owner: refused.
        let (state, problem, ..) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Removed, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Member)])
        }, |_| {});
        assert_eq!((state, problem), (Rejected, RecordProblem::Removal));
        // A plain member's record removing a member still listed: refused.
        let (state, problem, ..) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Removed, Member)])
        }, |_| {});
        assert_eq!((state, problem), (Rejected, RecordProblem::Removal));
        // An admin's record removing the owner: refused.
        let (state, problem, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Removed, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Member)])
        }, |_| {});
        assert_eq!((state, problem), (Rejected, RecordProblem::Removal));
        // An admin's eject: it counts, and sticks while the server lists D.
        let (state, _, device, members, d) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Removed, Member)])
        }, |_| {});
        assert_eq!(state, Accepted);
        let e = eligible(&device, &members, &d, EligibilityPurpose::Deliver);
        assert!(!e.eligible && e.removed_by_owner_or_admin);
        // A plain member's record naming a member who left (off this list): the departure counts.
        let (state, _, device, members, d) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Departed, Member)])
        }, |m| m[3].listed = false);
        assert_eq!(state, Accepted);
        assert!(!eligible(&device, &members, &d, EligibilityPurpose::Include).eligible);
        // An honest departure this device's list hasn't caught up with: pending here, no refusal.
        let (state, _, device, members, d) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Departed, Member)])
        }, |_| {});
        assert_eq!(state, Accepted);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
    }

    #[test]
    fn only_the_chain_owner_changes_roles() {
        use ChainRole::{Admin, Member, Owner};
        // A plain member's record promoting D: refused.
        let (state, problem, ..) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Admin)])
        }, |_| {});
        assert_eq!((state, problem), (Rejected, RecordProblem::Role));
        // An admin changing a role: refused.
        let (state, problem, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Admin), (c, Included, Admin), (d, Included, Member)])
        }, |_| {});
        assert_eq!((state, problem), (Rejected, RecordProblem::Role));
        // The owner's promotion: accepted, and the chain carries it.
        let (state, _, device, _, d) = judged(|a, _, _, _| same(a), |h, a, b, c, d| {
            rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Admin)])
        }, |_| {});
        assert_eq!(state, Accepted);
        assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Admin));
        // A newcomer comes in as "member" unless the owner signs.
        let n = Acct::new(0x70);
        let (state, problem, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            let mut v3 = rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Member)]);
            v3.push(h.entry(&Acct::new(0x70), Included, Admin));
            v3
        }, |m| m.push(with(n.member(), |r| r.statements = vec![Acct::new(0xc1).invite(&n, 2)])));
        assert_eq!((state, problem), (Rejected, RecordProblem::Role));
    }

    #[test]
    fn a_plain_members_record_never_removes_an_owner_or_admin() {
        use ChainRole::{Admin, Member, Owner};
        // The owner and the admin "departed" in a plain member's record, with a
        // hostile list that drops them: neither departure counts; both read as
        // pending, and the record is not refused.
        let (state, _, device, members, _) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Departed, Owner), (b, Included, Member), (c, Departed, Admin), (d, Included, Member)])
        }, |m| {
            m[0].listed = false;
            m[2].listed = false;
        });
        assert_eq!(state, Accepted);
        let (a, c) = (Acct::new(0xa1), Acct::new(0xc1));
        assert_eq!(eligible(&device, &members, &a, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        assert_eq!(eligible(&device, &members, &c, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
    }

    #[test]
    fn only_a_chain_admin_listed_as_owner_takes_the_chain_with_the_old_owners_removal() {
        use ChainRole::{Admin, Member, Owner};
        // A plain member listed as owner names itself owner: refused.
        let (state, ..) = judged(|_, b, _, _| same(b), |h, a, b, c, d| {
            rows(h, &[(a, Removed, Member), (b, Included, Owner), (c, Included, Admin), (d, Included, Member)])
        }, |m| m[1].listed_role = Some(CircleRole::Owner));
        assert_eq!(state, Rejected);
        // The admin listed as owner, without removing the old owner: refused.
        let (state, problem, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Included, Member), (b, Included, Member), (c, Included, Owner), (d, Included, Member)])
        }, |m| m[2].listed_role = Some(CircleRole::Owner));
        assert_eq!((state, problem), (Rejected, RecordProblem::Role));
        // The admin listed as owner, in the record that removes the old owner
        // (whose entry no longer says owner: a record names one owner): accepted.
        let (state, _, device, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Removed, Member), (b, Included, Member), (c, Included, Owner), (d, Included, Member)])
        }, |m| m[2].listed_role = Some(CircleRole::Owner));
        assert_eq!(state, Accepted);
        assert_eq!(device.chain_role(CIRCLE.into(), Acct::new(0xc1).uid), Some(CircleRole::Owner));
        assert_eq!(device.chain_role(CIRCLE.into(), Acct::new(0xa1).uid), None);
        // The same record where the list does not show the admin as owner: refused.
        let (state, ..) = judged(|_, _, c, _| same(c), |h, a, b, c, d| {
            rows(h, &[(a, Removed, Member), (b, Included, Member), (c, Included, Owner), (d, Included, Member)])
        }, |_| {});
        assert_eq!(state, Rejected);
    }

    #[test]
    fn membership_follows_the_last_record_that_names_someone() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        // B marks D departed, then omits D: on a device that still lists D, D stays in.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Departed, Member)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        h.rotate(RecordKind::Rotation, &b, v4, None);
        let members = four_members(&a, &b, &c, &d);
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        // Off this device's list, the departure counts; listed again, it undoes itself.
        let off: Vec<RecordMember> =
            members.iter().cloned().map(|m| if m.user_id == d.uid { with(m, |m| m.listed = false) } else { m }).collect();
        assert!(!eligible(&device, &off, &d, EligibilityPurpose::Include).eligible);
        assert!(eligible(&device, &members, &d, EligibilityPurpose::Include).eligible);
        // An eject never undoes itself, whatever the list says later. (D is
        // carried as pending by the owner first: a removal must name someone
        // the chain has named, by last(x).)
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v5, None);
        give(&device, &h, 5);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 5).0, Accepted);
        assert!(!eligible(&device, &members, &d, EligibilityPurpose::Include).eligible);
    }

    #[test]
    fn a_statement_under_an_older_key_never_admits() {
        let (a, b, c, d, h) = four();
        let n = Acct::new(0x70);
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        // The admin C reset its keys; this device confirms the NEW ones. An
        // admission signed with C's OLD key does not count.
        let c_new = Acct { uid: c.uid.clone(), signing: SigningKey::from_bytes(&[0xc9; 32]), sharing: StaticSecret::from([0xca; 32]) };
        let with_new_c = |statement: HeldStatement| {
            let mut m = members.clone();
            m[2] = with(c_new.member(), |r| r.listed_role = Some(CircleRole::Admin));
            m.push(with(n.member(), |r| r.statements = vec![statement]));
            m
        };
        assert!(!eligible(&device, &with_new_c(c.admit(&n, 2)), &n, EligibilityPurpose::Include).eligible);
        assert_eq!(
            eligible(&device, &with_new_c(c_new.admit(&n, 2)), &n, EligibilityPurpose::Include).basis,
            Some(EligibilityBasis::Admission)
        );
    }

    #[test]
    fn a_persons_confirmation_delivers_but_never_to_someone_removed() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        // B reset its keys; this device's person confirmed the new ones.
        let b_new = Acct { uid: b.uid.clone(), signing: SigningKey::from_bytes(&[0xb9; 32]), sharing: StaticSecret::from([0xba; 32]) };
        let changed = |confirmed: bool| {
            let mut m = members.clone();
            m[1] = with(b_new.member(), |r| r.person_confirmed_keys = confirmed);
            m
        };
        assert_eq!(eligible(&device, &changed(true), &b_new, EligibilityPurpose::Deliver).basis, Some(EligibilityBasis::PersonConfirmed));
        assert!(!eligible(&device, &changed(true), &b_new, EligibilityPurpose::Include).eligible, "a rotation needs (a) to (c)");
        assert!(!eligible(&device, &changed(false), &b_new, EligibilityPurpose::Deliver).eligible);
        // Removed: never.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Removed, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        give(&device, &h, 3);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 3).0, Accepted);
        assert!(!eligible(&device, &changed(true), &b_new, EligibilityPurpose::Deliver).eligible);
    }

    #[test]
    fn an_absence_rests_on_the_statements_signed_subject() {
        let (a, b, c, d, h) = four();
        let n = Acct::new(0x70);
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let invited = |row: RecordMember| {
            let mut m = members.clone();
            m.push(row);
            m
        };
        let n_row = with(n.member(), |r| r.statements = vec![a.invite(&n, 2)]);
        assert_eq!(eligible(&device, &invited(n_row.clone()), &n, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Invitation));
        // The server names N with another user id, same keys: the invitation is
        // not about that id, and makes nobody eligible.
        let other_id = "70707070-0000-4000-8000-00000000ffff".to_string();
        let relabelled = with(n_row, |r| r.user_id = other_id.clone());
        let e = device.refresh_eligibility_at(CIRCLE, &invited(relabelled), EligibilityPurpose::Include, NOW).unwrap();
        assert!(!e.iter().find(|e| e.user_id == other_id).unwrap().eligible);
    }

    #[test]
    fn the_eligibility_flags_say_why_an_invitation_does_not_count() {
        let (a, b, c, d, h) = four();
        let n = Acct::new(0x70);
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let with_n = |statement: HeldStatement| {
            let mut m = members.clone();
            m.push(with(n.member(), |r| r.statements = vec![statement]));
            m
        };
        // The owner's invitation, 8 days old: expired.
        let old = a.statement(MembershipStatementKind::InvitationToAccount, &n, 2, NOW - 8 * 86_400);
        let e = eligible(&device, &with_n(old), &n, EligibilityPurpose::Include);
        assert!(!e.eligible && e.invitation_expired && !e.invitation_signer_not_chain_admin, "{e:?}");
        // A plain member's fresh invitation: its signer is not an
        // owner or admin in the chain.
        let e = eligible(&device, &with_n(b.invite(&n, 2)), &n, EligibilityPurpose::Include);
        assert!(!e.eligible && e.invitation_signer_not_chain_admin && !e.invitation_expired, "{e:?}");
        // DELIVER also needs the server to say N holds no key.
        let fresh = with_n(a.invite(&n, 2));
        assert!(!eligible(&device, &fresh, &n, EligibilityPurpose::Deliver).eligible);
        let keyless: Vec<RecordMember> =
            fresh.into_iter().map(|m| if m.user_id == n.uid { with(m, |m| m.server_says_keyless = true) } else { m }).collect();
        assert_eq!(eligible(&device, &keyless, &n, EligibilityPurpose::Deliver).basis, Some(EligibilityBasis::Invitation));
    }

    #[test]
    fn an_unknown_signer_waits() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let stranger = Acct::new(0x5e);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&stranger, Included, Member)]);
        h.rotate(RecordKind::Rotation, &stranger, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (_, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::SignerUnknown));
    }

    #[test]
    fn a_fork_makes_the_circle_wait() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let same_rows = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let mut one = h.clone();
        one.rotate(RecordKind::Rotation, &a, same_rows(&h), None);
        let mut two = h.clone();
        two.rotate(RecordKind::Rotation, &c, same_rows(&h), None);
        // Two different records for v3.
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let mut both = one.signed();
        both.extend(two.signed());
        let report = device.import_refresh_records_at(CIRCLE, &both, &one.links, &members, true, None, &[], NOW).unwrap();
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing is sealed");
        assert!(!eligible(&device, &members, &b, EligibilityPurpose::Deliver).eligible, "nothing is delivered");
        // A member's head that contradicts this device's chain.
        let (device, _) = device_at(&a, &a, &one, &members, &[2, 3]);
        let theirs = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: b.uid16(), version: 3, chain: two.records[&3].0.chain() };
        let bytes = theirs.encode().unwrap();
        let signed = SignedCircleHead {
            head_hex: hex::encode(bytes),
            signature_hex: hex::encode(b.signing.sign(&Head::digest(&bytes)).to_bytes()),
        };
        let heads = [MemberHead { user_id: b.uid.clone(), head: signed }];
        let report = device.import_refresh_records_at(CIRCLE, &one.signed(), &one.links, &members, true, None, &heads, NOW).unwrap();
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err());
    }

    #[test]
    fn a_fresh_install_anchors_on_its_accounts_own_head() {
        let (a, b, c, d, h) = four();
        // Nobody confirmed and no statements: the head vouches for the chain up to v2.
        let bare: Vec<RecordMember> = four_members(&a, &b, &c, &d)
            .into_iter()
            .map(|m| {
                with(m, |m| {
                    m.statements.clear();
                    if m.user_id != a.uid {
                        m.confirmed = false;
                    }
                })
            })
            .collect();
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version: 2, chain: h.records[&2].0.chain() };
        let bytes = head.encode().unwrap();
        let signed = |key: &SigningKey| SignedCircleHead {
            head_hex: hex::encode(bytes),
            signature_hex: hex::encode(key.sign(&Head::digest(&bytes)).to_bytes()),
        };
        let device = a.device();
        give(&device, &h, 2);
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &bare, true, Some(&signed(&a.signing)), &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        let mut vouched = report.head_confirmed_members.clone();
        vouched.sort();
        let mut expected = vec![a.uid.clone(), b.uid.clone(), c.uid.clone(), d.uid.clone()];
        expected.sort();
        assert_eq!(vouched, expected);
        // A head signed by another key (an old one, after a reset) is ignored.
        let other = a.device();
        give(&other, &h, 2);
        let report = other
            .import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &bare, true, Some(&signed(&SigningKey::from_bytes(&[0x01; 32]))), &[], NOW)
            .unwrap();
        assert!(report.head_confirmed_members.is_empty());
    }

    /// An in-memory key store, for restarts.
    #[derive(Clone, Default)]
    struct MemStore(Arc<std::sync::Mutex<Option<crate::types::StoredKeyData>>>);
    impl crate::types::KeyStorageCallback for MemStore {
        fn store_keys(&self, data: crate::types::StoredKeyData) -> Result<(), crate::types::StorageCallbackError> {
            *self.0.lock().unwrap() = Some(data);
            Ok(())
        }
        fn load_keys(&self) -> Result<Option<crate::types::StoredKeyData>, crate::types::StorageCallbackError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn delete_keys(&self) -> Result<(), crate::types::StorageCallbackError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    /// The blob a device's store holds, as the platform keeps it.
    fn stored(store: &MemStore) -> crate::types::StoredKeyData {
        store.0.lock().unwrap().clone().expect("something stored")
    }

    fn circle_keys_of(store: &MemStore) -> HashMap<String, HashMap<String, String>> {
        serde_json::from_str(&stored(store).circle_keys_json).unwrap()
    }

    /// Rewrite the stored `circle_keys_json`, as another SDK's write would.
    fn rewrite_circle_keys(store: &MemStore, edit: impl FnOnce(&mut HashMap<String, HashMap<String, String>>)) {
        let mut keys = circle_keys_of(store);
        edit(&mut keys);
        store.0.lock().unwrap().as_mut().unwrap().circle_keys_json = serde_json::to_string(&keys).unwrap();
    }

    /// A device of `a` that took the four-member chain (v1, v2), with a store.
    fn stored_device(a: &Acct, h: &History, members: &[RecordMember]) -> (Arc<CryptoManager>, MemStore) {
        let store = MemStore::default();
        let device = a.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, h, 1);
        let mut genesis_only = History::genesis(a);
        genesis_only.links.clear();
        import(&device, &genesis_only, members, true);
        give(&device, h, 2);
        import(&device, h, members, true);
        device.persist_keys().unwrap();
        (device, store)
    }

    fn restarted(store: &MemStore) -> Arc<CryptoManager> {
        let device = CryptoManager::new();
        device.register_secure_storage(Box::new(store.clone()));
        assert!(device.load_persisted_keys().unwrap());
        device
    }

    fn secret_entry(h: &History) -> HashMap<String, String> {
        use base64::Engine as _;
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&h.secret);
        HashMap::from([("0".to_string(), base64::engine::general_purpose::STANDARD.encode(bytes))])
    }

    #[test]
    fn the_chain_and_the_secret_survive_a_restart() {
        use base64::Engine as _;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        let pins_json = stored(&store).pinned_keys_json.unwrap();
        let blob: HashMap<String, PinRecord> = serde_json::from_str(&pins_json).unwrap();
        let reserved: Vec<&String> = blob.keys().filter(|k| is_refresh_key(k)).collect();
        assert!(reserved.iter().any(|k| k.starts_with(HEAD_PREFIX)) && reserved.iter().any(|k| k.starts_with(ANCHOR_PREFIX)));
        assert_eq!(reserved.iter().filter(|k| k.starts_with(FACT_PREFIX)).count(), 4);
        for key in &reserved {
            let record = &blob[*key];
            let well_formed = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
            assert!(well_formed(&record.sharing_pubkey_hex) && well_formed(&record.signing_pubkey_hex), "{key}");
        }
        // S is stored with the circle keys only, as 0x01 || S (33 bytes).
        let b64 = base64::engine::general_purpose::STANDARD;
        let entry = secret_entry(&h);
        for never in [hex::encode(h.secret), b64.encode(h.secret), entry["0"].clone()] {
            assert!(!pins_json.contains(&never), "S is never in the pins blob");
        }
        let keys = circle_keys_of(&store);
        assert_eq!(keys[&format!("{SECRET_PREFIX}{CIRCLE}")], entry);
        assert_eq!(b64.decode(&entry["0"]).unwrap().len(), 33);
        assert_eq!(keys.len(), 2, "the circle and its secret: {:?}", keys.keys().collect::<Vec<_>>());

        let restarted = restarted(&store);
        assert_eq!(restarted.get_active_version(CIRCLE.into()).unwrap(), 2);
        assert!(restarted.circle_has_refresh_records(CIRCLE.into()));
        assert_eq!(restarted.refresh_head_versions().get(CIRCLE), Some(&0), "all records, once per process");
        assert_eq!(
            restarted.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.as_deref(),
            Some(&h.secret),
            "S is restored"
        );
        // Nothing that goes through circles meets it.
        let secret_id = format!("{SECRET_PREFIX}{CIRCLE}");
        assert!(!restarted.has_circle_key(secret_id.clone()));
        assert!(restarted.get_active_version(secret_id.clone()).is_err());
        assert!(restarted.held_keys(&secret_id).is_empty());
        let pseudonyms = restarted.collect_deletion_pseudonyms(a.uid.clone()).unwrap();
        assert!(pseudonyms.iter().all(|p| p.circle_id == CIRCLE), "{pseudonyms:?}");
        let exported = restarted.export_member_pins(a.uid.clone()).unwrap();
        assert!(!exported.contains(&entry["0"]) && !exported.contains(&hex::encode(h.secret)) && !exported.contains(SECRET_PREFIX));
        // E works at once, with no import in this process.
        assert_eq!(eligible(&restarted, &members, &d, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        // Written back unchanged.
        restarted.persist_keys().unwrap();
        assert_eq!(circle_keys_of(&store)[&secret_id], entry);

        // Reserved keys never come in through importMemberPins.
        let head_key = format!("{HEAD_PREFIX}{CIRCLE}");
        let mut pins = HashMap::new();
        pins.insert(head_key.clone(), blob[&head_key].clone());
        pins.insert(format!("~ctrust:{CIRCLE}:9"), blob[&head_key].clone());
        let export = serde_json::json!({
            "format": "pingolin.member_pins.v1",
            "owner_user_id": a.uid,
            "pins": pins,
            "identity_pins": {}
        });
        let fresh = a.device();
        assert_eq!(fresh.import_member_pins(a.uid.clone(), export.to_string()).unwrap(), 0);
        assert!(!fresh.circle_has_refresh_records(CIRCLE.into()));
    }

    fn stored_pins(store: &MemStore) -> HashMap<String, PinRecord> {
        serde_json::from_str(&stored(store).pinned_keys_json.unwrap()).unwrap()
    }

    fn set_stored_pins(store: &MemStore, pins: &HashMap<String, PinRecord>) {
        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = Some(serde_json::to_string(pins).unwrap());
    }

    /// The refresh-record entries of a pins blob, compared as stored.
    fn refresh_entries_of(pins: &HashMap<String, PinRecord>) -> BTreeMap<String, String> {
        pins.iter().filter(|(k, _)| is_refresh_key(k)).map(|(k, r)| (k.clone(), serde_json::to_string(r).unwrap())).collect()
    }

    /// A stored head, anchor, history step or fact that doesn't read
    /// here: the circle is latched and forked and holds nothing else,
    /// takes nothing served, and its entries go back exactly as stored,
    /// until it is left.
    #[test]
    fn a_circle_whose_stored_state_doesnt_read_waits_latched_and_keeps_it_as_stored() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // Each kind garbled; the head missing (every write gives a circle one);
        // a fact that names no member.
        for (prefix, how) in [
            (HEAD_PREFIX, "garbled"),
            (ANCHOR_PREFIX, "garbled"),
            (HISTORY_PREFIX, "garbled"),
            (FACT_PREFIX, "garbled"),
            (HEAD_PREFIX, "missing"),
            (FACT_PREFIX, "no member"),
        ] {
            let (_, store) = stored_device(&a, &h, &members);
            let mut pins = stored_pins(&store);
            let key = pins.keys().filter(|k| k.starts_with(prefix) && !k.ends_with(KEPT_TAG_SUFFIX)).min().unwrap().clone();
            match how {
                "missing" => {
                    pins.remove(&key);
                }
                "no member" => {
                    let fact = pins[&key].clone();
                    pins.insert(format!("{FACT_PREFIX}{CIRCLE}"), fact);
                }
                _ => pins.get_mut(&key).unwrap().sharing_pubkey_hex = "zz".into(),
            }
            set_stored_pins(&store, &pins);
            let as_stored = refresh_entries_of(&pins);
            assert!(as_stored.keys().any(|k| k.ends_with(KEPT_TAG_SUFFIX)), "kept tags go back too");

            let device = restarted(&store);
            {
                let chains = device.refresh.read().unwrap();
                let chain = &chains[&CircleKey::of(CIRCLE)];
                assert!(chain.latched && chain.forked, "{prefix}");
                assert!(chain.head.is_none() && chain.anchor.is_none() && chain.facts.is_empty() && chain.history.is_empty(), "{prefix}");
            }
            assert!(device.circle_has_refresh_records(CIRCLE.into()), "{prefix}");
            assert_eq!(device.sealing_version(CIRCLE), None, "{prefix}");
            // Its own records served again: it still waits and takes none.
            let report = import(&device, &h, &members, true);
            assert!(report.forked && report.sealing_version.is_none() && report.versions.is_empty(), "{prefix}");
            device.persist_keys().unwrap();
            assert_eq!(refresh_entries_of(&stored_pins(&store)), as_stored, "{prefix}: exactly as stored, no fork marker of ours");
            // And again after another restart.
            restarted(&store).persist_keys().unwrap();
            assert_eq!(refresh_entries_of(&stored_pins(&store)), as_stored, "{prefix}");
            // Leaving the circle ends it: the latch alone stays.
            assert!(device.forget_circle_entirely(CIRCLE));
            let left: Vec<String> = refresh_entries_of(&stored_pins(&store)).into_keys().collect();
            assert_eq!(left, vec![format!("{HEAD_PREFIX}{CIRCLE}")], "{prefix}");
        }
    }

    /// A stored key of a circle with records that isn't 32 bytes: nothing
    /// seals under its version, no copy is taken for it that no record
    /// vouches for, and the one its record's tag vouches for is.
    #[test]
    fn a_stored_key_that_isnt_32_bytes_comes_back_only_by_its_records_tag() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        rewrite_circle_keys(&store, |keys| {
            keys.get_mut(CIRCLE).unwrap().insert("2".into(), b64.encode([2u8; 16]));
        });
        // No tag kept either: only the records served again vouch.
        let mut pins = stored_pins(&store);
        pins.retain(|k, _| !k.ends_with(KEPT_TAG_SUFFIX));
        set_stored_pins(&store, &pins);

        let device = restarted(&store);
        assert_eq!(device.sealing_version(CIRCLE), None);
        assert!(own_copy(&device, &a, 2, &h.keys[&2]).is_err(), "nothing vouches for it yet");
        import(&device, &h, &members, true);
        assert!(own_copy(&device, &a, 2, &[7; 32]).is_err(), "not the key its record's tag names");
        own_copy(&device, &a, 2, &h.keys[&2]).unwrap();
        assert_eq!(device.sealing_version(CIRCLE), Some(2));
        assert!(!device.holds_unreadable_copy(CIRCLE, 2), "the copy that didn't read is gone");
        device.persist_keys().unwrap();
        assert_eq!(circle_keys_of(&store)[CIRCLE]["2"], b64.encode(h.keys[&2]));
        // A key the chain walk verified takes its place too.
        rewrite_circle_keys(&store, |keys| {
            keys.get_mut(CIRCLE).unwrap().insert("2".into(), b64.encode([2u8; 16]));
        });
        let walked = restarted(&store);
        assert!(walked.holds_unreadable_copy(CIRCLE, 2));
        give(&walked, &h, 2);
        assert!(!walked.holds_unreadable_copy(CIRCLE, 2));
        assert_eq!(walked.sealing_version(CIRCLE), Some(2));
    }

    /// While the store can't be read, a circle this device holds no chain
    /// for is not read at first sight: the chain it would build would
    /// stand over the stored one once the store reads. It waits, and
    /// nothing is built; once the store reads, the circle is read.
    #[test]
    fn while_the_store_cant_be_read_a_first_sight_builds_nothing() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let store = MemStore::default();
        let first = a.device();
        first.register_secure_storage(Box::new(store.clone()));
        first.persist_keys().unwrap();
        let good = stored(&store).pinned_keys_json;
        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = Some("{\"cut short".into());

        let device = a.device();
        device.register_secure_storage(Box::new(store.clone()));
        assert!(device.load_persisted_keys().is_err());
        give(&device, &h, 1);
        give(&device, &h, 2);
        let report = import(&device, &h, &members, true);
        assert_eq!(report.versions.iter().map(|v| (v.state, v.problem)).collect::<Vec<_>>(), vec![(RecordVersionState::Waiting, RecordProblem::RecordMissing)]);
        assert!(device.refresh.read().unwrap().get(&CircleKey::of(CIRCLE)).is_none(), "nothing built");
        assert!(device.circle_has_refresh_records(CIRCLE.into()) && device.sealing_version(CIRCLE).is_none());

        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = good;
        assert!(device.load_persisted_keys().unwrap());
        import(&device, &h, &members, true);
        assert!(device.refresh.read().unwrap().get(&CircleKey::of(CIRCLE)).map_or(false, |chain| chain.head.is_some()), "read once the store reads");
    }

    /// While a stored signing seed that doesn't install is kept, a first
    /// sight of a chain waits instead of taking it by R1: the account's
    /// own head can't be checked without the seed. With the seed readable,
    /// the own head takes the chain.
    #[test]
    fn while_an_unreadable_seed_is_kept_a_first_sight_waits() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (other, _) = stored_device(&a, &h, &members);
        let own_head = other.sign_circle_head_of(CIRCLE, &a.uid).unwrap();
        let store = MemStore::default();
        let first = a.device();
        first.register_secure_storage(Box::new(store.clone()));
        first.persist_keys().unwrap();
        store.0.lock().unwrap().as_mut().unwrap().signing_private_key_b64 = Some("AAAA".into());
        let (records, links) = (h.signed(), h.links.clone());
        for with_head in [false, true] {
            let seedless = CryptoManager::new();
            seedless.register_secure_storage(Box::new(store.clone()));
            assert!(seedless.load_persisted_keys().unwrap());
            assert!(seedless.key_store_status().signing_seed_unreadable);
            give(&seedless, &h, 1);
            give(&seedless, &h, 2);
            let head = with_head.then_some(&own_head);
            let report = seedless.import_refresh_records_at(CIRCLE, &records, &links, &members, true, head, &[], NOW).unwrap();
            assert_eq!(
                report.versions.iter().map(|v| (v.state, v.problem)).collect::<Vec<_>>(),
                vec![(RecordVersionState::Waiting, RecordProblem::RecordMissing)],
                "with its own head: {with_head}"
            );
            assert!(seedless.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].head.is_none());
        }
        // A lone first record is judged like any other (R1 and R2), not taken
        // by R1 over a chain: it doesn't wait.
        let seedless = CryptoManager::new();
        seedless.register_secure_storage(Box::new(store.clone()));
        assert!(seedless.load_persisted_keys().unwrap());
        give(&seedless, &h, 1);
        let mut genesis_only = History::genesis(&a);
        genesis_only.links.clear();
        let report = import(&seedless, &genesis_only, &members, true);
        assert_ne!(report.versions.first().map(|v| (v.state, v.problem)), Some((RecordVersionState::Waiting, RecordProblem::RecordMissing)));
        // The seed readable: its own head takes the chain.
        let device = a.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        device.import_refresh_records_at(CIRCLE, &records, &links, &members, true, Some(&own_head), &[], NOW).unwrap();
        assert_eq!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].head.as_ref().map(|head| head.version), Some(2));
    }

    /// An eject the server took but hasn't served back yet, and a restart
    /// in between: the owner keeps sealing under its own new version,
    /// never under the one before, which the removed member knows. Served
    /// back, the record is accepted like any other and the own record
    /// goes. An own record the head has passed doesn't come back; one that
    /// doesn't read makes the circle wait, as any record state that
    /// doesn't read.
    #[test]
    fn an_own_record_survives_a_restart_until_it_is_served_back() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (owner, store) = stored_device(&a, &h, &members);
        let eject_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &eject_d, &members, true, "n", NOW).unwrap();
        assert_eq!(owner.get_active_version(CIRCLE.into()).unwrap(), 3);
        let as_written = stored_pins(&store);

        // The server took it; the process restarts before it is served back.
        let after_restart = restarted(&store);
        assert_eq!(after_restart.get_active_version(CIRCLE.into()).unwrap(), 3, "never v2, which D knows");
        let (records, links) = served_with(&h, &bundle);
        let report = after_restart.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert!(after_restart.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].own.is_none());
        after_restart.persist_keys().unwrap();
        assert!(!stored_pins(&store).keys().any(|k| k.starts_with(OWN_PREFIX)), "gone once served back");
        assert_eq!(restarted(&store).get_active_version(CIRCLE.into()).unwrap(), 3);

        // An own record the head has already passed is not taken back.
        let mut stale = stored_pins(&store);
        stale.insert(format!("{OWN_PREFIX}{CIRCLE}"), as_written[&format!("{OWN_PREFIX}{CIRCLE}")].clone());
        set_stored_pins(&store, &stale);
        let reloaded = restarted(&store);
        let chains = reloaded.refresh.read().unwrap();
        assert!(chains[&CircleKey::of(CIRCLE)].own.is_none() && !chains[&CircleKey::of(CIRCLE)].forked);
        drop(chains);
        // One that doesn't read: the circle waits.
        let mut garbled = as_written.clone();
        garbled.get_mut(&format!("{OWN_PREFIX}{CIRCLE}")).unwrap().sharing_pubkey_hex = "zz".into();
        set_stored_pins(&store, &garbled);
        let waiting = restarted(&store);
        assert!(waiting.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].forked && waiting.sealing_version(CIRCLE).is_none());
        // Kept, but the stored copy of its key doesn't read (a cut-short
        // write): nothing is sealed, never v2, which D knows.
        let mut keys = circle_keys_of(&store);
        keys.get_mut(CIRCLE).unwrap().insert("3".into(), "AAAA".into());
        set_stored_pins(&store, &as_written);
        rewrite_circle_keys(&store, |stored| *stored = keys);
        let keyless = restarted(&store);
        assert_eq!(keyless.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].own.as_ref().map(|own| own.wire.body.version), Some(3));
        assert_eq!(keyless.sealing_version(CIRCLE), None);
        assert!(keyless.get_active_version(CIRCLE.into()).is_err());
        // Nor one filed under another circle: that circle waits.
        const OTHER: &str = "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f";
        let mut misfiled = as_written.clone();
        let own = misfiled.remove(&format!("{OWN_PREFIX}{CIRCLE}")).unwrap();
        misfiled.insert(format!("{OWN_PREFIX}{OTHER}"), own);
        misfiled.insert(format!("{HEAD_PREFIX}{OTHER}"), misfiled[&format!("{HEAD_PREFIX}{CIRCLE}")].clone());
        set_stored_pins(&store, &misfiled);
        let chains = restarted(&store).refresh.read().unwrap().get(&CircleKey::of(OTHER)).map(|chain| (chain.forked, chain.own.is_some()));
        assert_eq!(chains, Some((true, false)));
    }

    /// A kept tag that doesn't read is dropped: that loosens
    /// nothing, so the circle reads on unchanged.
    #[test]
    fn a_kept_tag_that_doesnt_read_is_dropped_and_the_circle_reads_on() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        let mut pins = stored_pins(&store);
        let key = pins.keys().filter(|k| k.ends_with(KEPT_TAG_SUFFIX)).min().unwrap().clone();
        pins.get_mut(&key).unwrap().sharing_pubkey_hex = "zz".into();
        set_stored_pins(&store, &pins);
        let device = restarted(&store);
        let chains = device.refresh.read().unwrap();
        let chain = &chains[&CircleKey::of(CIRCLE)];
        assert!(!chain.forked && chain.as_stored.is_empty());
        assert_eq!(chain.head.as_ref().map(|head| head.version), Some(2));
        assert_eq!(chain.history.values().filter(|step| step.kept.is_some()).count(), 1, "the other tag is kept");
    }

    #[test]
    fn the_secret_is_stored_only_after_the_anchor_check() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let store = MemStore::default();
        let device = d.device();
        device.register_secure_storage(Box::new(store.clone()));
        // A legacy circle has none.
        assert!(device.add_verified_key("d0d0d0d0-2222-4333-8444-555555555555", 3, &[3; 32]));
        device.persist_keys().unwrap();
        assert!(circle_keys_of(&store).keys().all(|k| !k.starts_with(SECRET_PREFIX)));
        // v2's link carries another key than v1's: the anchor check fails,
        // and nothing is stored.
        let mut bad = h.clone();
        bad.links.clear();
        let key2 = bad.keys[&2];
        bad.add_raw_link(2, 1, &key2, &[0x77; 32]);
        give(&device, &h, 2);
        assert_eq!(state_of_version(&import(&device, &bad, &members, true), 2), (Waiting, RecordProblem::ChainWalk));
        assert!(device.circle_has_refresh_records(CIRCLE.into()));
        assert!(circle_keys_of(&store).keys().all(|k| !k.starts_with(SECRET_PREFIX)), "no S before the anchor check");
        // The right link: the anchor check holds, and S is stored.
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 2).0, Accepted);
        assert_eq!(circle_keys_of(&store)[&format!("{SECRET_PREFIX}{CIRCLE}")], secret_entry(&h));
        // An own transition the server did not take leaves the circle legacy,
        // and its secret is never stored.
        use RecordMemberState as S;
        let legacy_circle = "b0b0b0b0-2222-4333-8444-555555555555";
        let owner = a.device();
        let owner_store = MemStore::default();
        owner.register_secure_storage(Box::new(owner_store.clone()));
        for v in 1..=4u32 {
            assert!(owner.add_verified_key(legacy_circle, v, &key_of(v)));
        }
        let alone = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        owner
            .prepare_recorded_rotation_at(legacy_circle, &a.uid, RefreshRecordKind::Transition, &plan(&[(&a, S::Included, Some(CircleRole::Owner))]), &alone, true, "n", NOW)
            .unwrap();
        assert!(circle_keys_of(&owner_store).contains_key(&format!("{SECRET_PREFIX}{legacy_circle}")), "while it is ours, unconfirmed");
        assert!(owner.discard_unconfirmed_rotation(legacy_circle.into()));
        assert!(!owner.circle_has_refresh_records(legacy_circle.into()));
        assert!(circle_keys_of(&owner_store).keys().all(|k| !k.starts_with(SECRET_PREFIX)));
    }

    #[test]
    fn a_circles_record_state_under_two_spellings_is_taken_only_when_the_same() {
        // An older SDK may keep one circle's record state under two
        // spellings. The same state is one chain; a latch alone rides on
        // the other's chain; anything else waits, latched and forked, as
        // stored, so a removal kept under either spelling stands.
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        let original = stored(&store);
        let pins: HashMap<String, PinRecord> = serde_json::from_str(original.pinned_keys_json.as_deref().unwrap()).unwrap();
        let upper = CIRCLE.to_uppercase();
        assert!(upper != CIRCLE);
        let with = |extra: Vec<(String, PinRecord)>| {
            let mut all = pins.clone();
            all.extend(extra);
            let copy = MemStore::default();
            let mut blob = original.clone();
            blob.pinned_keys_json = Some(serde_json::to_string(&all).unwrap());
            *copy.0.lock().unwrap() = Some(blob);
            (restarted(&copy), copy)
        };
        let respelled = |edit: &dyn Fn(&str, &mut PinRecord)| -> Vec<(String, PinRecord)> {
            pins.iter()
                .filter(|(key, _)| is_refresh_key(key) && circle_of_refresh_key(key) == CIRCLE)
                .map(|(key, record)| {
                    let mut record = record.clone();
                    edit(key, &mut record);
                    (key.replacen(CIRCLE, &upper, 1), record)
                })
                .collect()
        };
        let head_of = |device: &CryptoManager| {
            let chains = device.refresh.read().unwrap();
            let chain = &chains[&CircleKey::of(CIRCLE)];
            (chain.forked, chain.latched, chain.as_stored.is_empty(), chain.head.as_ref().map(|h| h.version))
        };
        // The same state under both spellings: one chain.
        let (same, _) = with(respelled(&|_, _| {}));
        assert_eq!(head_of(&same), (false, true, true, Some(2)));
        assert!(!same.is_behind(CIRCLE.into()));
        // A latch alone under the other spelling rides on the chain.
        let latch = PinRecord {
            sharing_pubkey_hex: hex::encode([0u8; 32]),
            signing_pubkey_hex: hex::encode([0u8; 32]),
            first_pinned_at: 0,
            last_verified_at: 0,
            user_approved_change_at: None,
        };
        let (latched, _) = with(vec![(format!("{HEAD_PREFIX}{upper}"), latch.clone())]);
        assert_eq!(head_of(&latched), (false, true, true, Some(2)));
        // A head at 0 that is not exactly a latch is state: another state.
        for odd in [
            PinRecord { sharing_pubkey_hex: hex::encode([1u8; 32]), ..latch.clone() },
            PinRecord { signing_pubkey_hex: hex::encode([1u8; 32]), ..latch.clone() },
            PinRecord { user_approved_change_at: Some(1), ..latch.clone() },
        ] {
            let (waits, _) = with(vec![(format!("{HEAD_PREFIX}{upper}"), odd)]);
            assert_eq!(head_of(&waits), (true, true, false, None));
        }
        // Another state (the other spelling's head names v1): it waits, as stored.
        let (different, copy) = with(respelled(&|key, record| {
            if key.starts_with(HEAD_PREFIX) {
                record.first_pinned_at = 1;
            }
        }));
        assert_eq!(head_of(&different), (true, true, false, None));
        assert!(different.is_behind(CIRCLE.into()) && different.sealing_version(CIRCLE).is_none(), "nothing is sealed");
        // What it writes back loads the same, both spellings kept as stored.
        different.persist_keys().unwrap();
        assert_eq!(head_of(&restarted(&copy)), (true, true, false, None));
        let written: HashMap<String, PinRecord> = serde_json::from_str(stored(&copy).pinned_keys_json.as_deref().unwrap()).unwrap();
        assert!(written.contains_key(&format!("{HEAD_PREFIX}{upper}")) && written.contains_key(&format!("{HEAD_PREFIX}{CIRCLE}")));
    }

    #[test]
    fn a_stored_secret_serves_e_without_the_chain_and_a_bad_one_is_derived_again() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        let secret_id = format!("{SECRET_PREFIX}{CIRCLE}");
        // Without the anchor key (v1 retired from the store), E still works:
        // no walk, no import (iOS's notification extension, read-only).
        rewrite_circle_keys(&store, |keys| {
            keys.get_mut(CIRCLE).unwrap().remove("1");
        });
        let device = restarted(&store);
        assert!(device.held_keys(CIRCLE).iter().all(|(v, _)| *v != 1));
        assert_eq!(eligible(&device, &members, &b, EligibilityPurpose::Deliver).basis, Some(EligibilityBasis::CountedByChain));
        // What an old SDK writes back (`{}`), or any other shape, is ignored:
        // without the anchor key and the chain, E then waits for the import.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let shapes: Vec<HashMap<String, String>> = vec![
            HashMap::new(),
            HashMap::from([("0".to_string(), b64.encode(h.secret))]),
            HashMap::from([("1".to_string(), secret_entry(&h)["0"].clone())]),
            HashMap::from([("0".to_string(), b64.encode([&[2u8][..], &h.secret[..]].concat()))]),
            HashMap::from([("0".to_string(), secret_entry(&h)["0"].clone()), ("1".to_string(), secret_entry(&h)["0"].clone())]),
            HashMap::from([("0".to_string(), "not base64".to_string())]),
        ];
        for shape in shapes {
            rewrite_circle_keys(&store, |keys| {
                keys.insert(secret_id.clone(), shape.clone());
                keys.get_mut(CIRCLE).unwrap().remove("1");
            });
            let device = restarted(&store);
            assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.is_none(), "{shape:?} is not a secret");
            assert!(device.refresh_eligibility_at(CIRCLE, &members, EligibilityPurpose::Include, NOW).is_err());
            assert!(!device.has_circle_key(secret_id.clone()));
            // The records again: S is derived again, and stored as it should be.
            import(&device, &h, &members, true);
            assert_eq!(eligible(&device, &members, &b, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
            assert_eq!(circle_keys_of(&store)[&secret_id], secret_entry(&h));
        }
        // A reload keeps the secret this process holds: a stored one never replaces it.
        rewrite_circle_keys(&store, |keys| {
            use base64::Engine as _;
            let other = base64::engine::general_purpose::STANDARD.encode([&[1u8][..], &[0x42; 32][..]].concat());
            keys.insert(secret_id.clone(), HashMap::from([("0".to_string(), other)]));
        });
        let device = restarted(&store);
        assert_ne!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.as_deref(), Some(&h.secret), "the stored bytes, taken on load");
        let reloading = restarted(&store);
        {
            let mut chains = reloading.refresh.write().unwrap();
            chains.get_mut(&CircleKey::of(CIRCLE)).unwrap().secret = Some(Zeroizing::new(h.secret));
        }
        assert!(reloading.load_persisted_keys().unwrap());
        assert_eq!(reloading.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.as_deref(), Some(&h.secret), "a reload keeps its own");
        // A secret for a circle whose records are not held here is ignored.
        let other = "e0e0e0e0-2222-4333-8444-555555555555";
        rewrite_circle_keys(&store, |keys| {
            keys.insert(format!("{SECRET_PREFIX}{other}"), secret_entry(&h));
        });
        let device = restarted(&store);
        assert!(device.refresh.read().unwrap().get(&CircleKey::of(&other)).map_or(true, |c| c.secret.is_none()));
        assert!(!device.circle_has_refresh_records(other.into()));
        // Kept under two spellings of the circle, the secret is taken
        // only if it is the same one; else S is derived again.
        let upper_id = format!("{SECRET_PREFIX}{}", CIRCLE.to_uppercase());
        rewrite_circle_keys(&store, |keys| {
            keys.insert(secret_id.clone(), secret_entry(&h));
            keys.insert(upper_id.clone(), secret_entry(&h));
        });
        let taken = restarted(&store).refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.as_deref().copied();
        assert!(taken == Some(h.secret), "the same secret under both: taken");
        rewrite_circle_keys(&store, |keys| {
            use base64::Engine as _;
            let different = base64::engine::general_purpose::STANDARD.encode([&[1u8][..], &[0x42; 32][..]].concat());
            keys.insert(upper_id.clone(), HashMap::from([("0".to_string(), different)]));
        });
        assert!(restarted(&store).refresh.read().unwrap()[&CircleKey::of(CIRCLE)].secret.is_none(), "two secrets: neither is taken");
    }

    #[test]
    fn leaving_the_circle_and_clear_all_keys_remove_the_secret() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let secret_id = format!("{SECRET_PREFIX}{CIRCLE}");
        let (device, store) = stored_device(&a, &h, &members);
        let legacy = "d0d0d0d0-2222-4333-8444-555555555555";
        assert!(device.add_verified_key(legacy, 3, &[3; 32]));
        device.persist_keys().unwrap();
        assert!(circle_keys_of(&store).contains_key(&secret_id));
        // Leaving: keys, records and S go, all but the latched mark;
        // the other circle stays.
        assert!(device.forget_circle(CIRCLE.into()));
        assert!(!device.has_circle_key(CIRCLE.into()) && device.circle_has_refresh_records(CIRCLE.into()));
        assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].is_latched_only());
        let keys = circle_keys_of(&store);
        assert!(!keys.contains_key(&secret_id) && !keys.contains_key(CIRCLE) && keys.contains_key(legacy), "{:?}", keys.keys().collect::<Vec<_>>());
        let pins: HashMap<String, PinRecord> = serde_json::from_str(&stored(&store).pinned_keys_json.unwrap()).unwrap();
        let left: Vec<&String> = pins.keys().filter(|k| is_refresh_key(k) && k.contains(CIRCLE)).collect();
        assert_eq!(left, vec![&format!("{HEAD_PREFIX}{CIRCLE}")], "the latch alone");
        assert!(!device.forget_circle(CIRCLE.into()), "nothing left to forget: the mark alone isn't held");
        // The provenance marks of a forgotten circle's keys go with them.
        let trusted = "f0f0f0f0-2222-4333-8444-555555555555";
        unsigned_first_contact(&device, &a, trusted, 1, &[0x31; 32]).unwrap();
        let marks = |store: &MemStore| {
            let pins: HashMap<String, PinRecord> = serde_json::from_str(&stored(store).pinned_keys_json.unwrap()).unwrap();
            pins.keys().filter(|k| k.starts_with("~ctrust:") && k.contains(trusted)).count()
        };
        assert_eq!(marks(&store), 1, "taken on trust");
        assert!(device.forget_circle(trusted.into()));
        assert_eq!(marks(&store), 0);
        // Never the personal slots.
        for personal in ["00000000-0000-0000-0000-000000000000", "self"] {
            assert!(device.add_verified_key(personal, 1, &[0x41; 32]));
            assert!(!device.forget_circle(personal.into()), "never the personal slot");
            assert!(device.has_circle_key(personal.into()));
        }
        // Re-joined, it starts again from its records.
        give(&device, &h, 2);
        import(&device, &h, &members, true);
        assert!(circle_keys_of(&store).contains_key(&secret_id));
        // clear_all_keys: everything, the store included.
        device.clear_all_keys();
        assert!(device.refresh.read().unwrap().is_empty());
        assert!(store.0.lock().unwrap().is_none());
    }

    #[test]
    fn another_first_record_drops_the_secret_of_the_last() {
        let (_, b, _, _, h) = four();
        let mut chain = CircleChain::default();
        chain.set_anchor(anchor_check(&h.records[&1].0));
        chain.secret = Some(Zeroizing::new(h.secret));
        chain.set_anchor(anchor_check(&h.records[&1].0));
        assert!(chain.secret.is_some(), "the same first record keeps it");
        chain.set_anchor(anchor_check(&History::genesis(&b).records[&1].0));
        assert!(chain.secret.is_none(), "another first record: the anchor check runs again");
    }

    #[test]
    fn a_recorded_circle_seals_only_under_accepted_versions_and_legacy_ones_are_unchanged() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        give(&device, &h, 3);
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, false, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3).0, Waiting);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        assert_eq!(device.newest_held_version(CIRCLE.into()), Some(3));
        assert!(device.has_circle_key_in_use(CIRCLE.into()));
        // Sealed under v2, readable with key 2 only.
        let sealed = device.encrypt_data_v2(CIRCLE.into(), "hello".into(), "test".into()).unwrap();
        let reader = d.device();
        assert!(reader.add_verified_key(CIRCLE, 2, &h.keys[&2]));
        assert_eq!(reader.decrypt_data_v2(CIRCLE.into(), sealed.clone(), "test".into()).unwrap(), "hello");
        let other = d.device();
        assert!(other.add_verified_key(CIRCLE, 3, &h.keys[&3]));
        assert!(other.decrypt_data_v2(CIRCLE.into(), sealed, "test".into()).is_err());
        // The legacy calls refuse a recorded circle.
        assert!(device.prepare_key_rotation(CIRCLE.into(), a.uid.clone(), vec![], vec![], vec![], "n".into()).is_err());
        assert!(device.create_key_chain_link(CIRCLE.into()).is_err());
        // Erasure covers the held and the sealing version.
        let pseudonyms = device.collect_deletion_pseudonyms(a.uid.clone()).unwrap();
        let ours: Vec<_> = pseudonyms.iter().filter(|p| p.circle_id == CIRCLE).collect();
        assert_eq!(ours.len(), 2, "{ours:?}");
        // A legacy circle is unaffected: its newest key seals,
        // and it has no records.
        let legacy = "d0d0d0d0-2222-4333-8444-555555555555";
        assert!(device.add_verified_key(legacy, 4, &[4; 32]));
        assert_eq!(device.get_active_version(legacy.into()).unwrap(), 4);
        assert!(!device.circle_has_refresh_records(legacy.into()));
        // Latching a circle by a head: nothing sealed until records verify.
        let latched = "e0e0e0e0-2222-4333-8444-555555555555";
        assert!(device.add_verified_key(latched, 1, &[1; 32]));
        assert_eq!(device.get_active_version(latched.into()).unwrap(), 1);
        device.note_circle_has_records(latched.into());
        assert!(device.get_active_version(latched.into()).is_err());
        assert!(device.has_circle_key(latched.into()) && !device.has_circle_key_in_use(latched.into()));
    }

    #[test]
    fn two_circles_give_a_member_different_codes() {
        let a = Acct::new(0xa1);
        let s1 = crate::refresh_record::circle_secret(&[1; 32]).unwrap();
        let s2 = crate::refresh_record::circle_secret(&[2; 32]).unwrap();
        assert_ne!(member_code(&s1, &a.uid16()), member_code(&s2, &a.uid16()));
    }

    #[test]
    fn the_shared_vector_chain_anchors_a_first_device() {
        const VECTORS: &str = include_str!("../tests/data/refresh_record_v1.txt");
        let v: HashMap<&str, &str> = VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').unwrap())
            .collect();
        let acct = |n: &str, sign: u8, share: u8| Acct {
            uid: v[format!("{n}_user_id").as_str()].to_string(),
            signing: SigningKey::from_bytes(&[sign; 32]),
            sharing: StaticSecret::from([share; 32]),
        };
        let (a, b, c, d, e) = (acct("A", 0xa1, 0xa2), acct("B", 0xb1, 0xb2), acct("C", 0xc1, 0xc2), acct("D", 0xd1, 0xd2), acct("E", 0xe1, 0xe2));
        let records: Vec<SignedRefreshRecord> = (1..=4)
            .map(|i| SignedRefreshRecord {
                record_hex: v[format!("r{i}_record_wire").as_str()].to_string(),
                signature_hex: v[format!("r{i}_signature").as_str()].to_string(),
            })
            .collect();
        let links: Vec<KeyChainLinkData> = [(2, 1), (3, 2), (4, 2)]
            .iter()
            .map(|(f, t)| KeyChainLinkData {
                from_version: *f,
                to_version: *t,
                encrypted_key: v[format!("link_{f}_{t}_encrypted_key").as_str()].to_string(),
                nonce: v[format!("link_{f}_{t}_nonce").as_str()].to_string(),
            })
            .collect();
        let circle = v["circle_id"];
        let device = d.device();
        assert!(device.add_verified_key(circle, 4, &hex32(v["key_v4"]).unwrap()));
        let members: Vec<RecordMember> = [&a, &c, &d].iter().map(|m| m.member()).collect();
        let report = device.import_refresh_records_at(circle, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        assert_eq!(device.get_active_version(circle.into()).unwrap(), 4);
        // The walk took the named 4 -> 2 step and 2 -> 1, and stored both keys.
        let held: Vec<u32> = device.held_keys(circle).iter().map(|(v, _)| *v).collect();
        assert!(held.contains(&2) && held.contains(&1), "{held:?}");
        // The chain says: A owner, C admin, D member; B removed; E departed.
        assert_eq!(device.chain_role(circle.into(), a.uid.clone()), Some(CircleRole::Owner));
        assert_eq!(device.chain_role(circle.into(), c.uid.clone()), Some(CircleRole::Admin));
        assert_eq!(device.chain_role(circle.into(), b.uid.clone()), None);
        let everyone: Vec<RecordMember> = [&a, &b, &c, &d, &e].iter().map(|m| m.member()).collect();
        let e_of = |who: &Acct| {
            device
                .refresh_eligibility_at(circle, &everyone, EligibilityPurpose::Include, NOW)
                .unwrap()
                .into_iter()
                .find(|x| x.user_id == who.uid)
                .unwrap()
        };
        assert!(e_of(&d).eligible && e_of(&a).eligible);
        assert!(!e_of(&b).eligible && e_of(&b).removed_by_owner_or_admin);
    }

    // ------------------------------------------------------------------
    // Every R1 rule on its own
    // ------------------------------------------------------------------

    /// `four()` plus one record by `signer` whose entries `edit` may change
    /// after they are made from `rows`, judged by the owner's device.
    fn one_more(signer_of: for<'x> fn(&'x Acct, &'x Acct, &'x Acct, &'x Acct) -> &'x Acct, edit: impl Fn(&History, &mut Vec<RecordEntry>)) -> RecordVersionStatus {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let mut v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        edit(&h, &mut v3);
        let signer = same(signer_of(&a, &b, &c, &d));
        h.rotate(RecordKind::Rotation, &signer, v3, None);
        let (_, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3]);
        report.versions.into_iter().find(|r| r.version == 3).unwrap()
    }

    #[test]
    fn nobody_is_dropped_silently() {
        let row = one_more(|a, _, _, _| a, |h, v3| v3.retain(|e| e.code != h.code(&Acct::new(0xd1))));
        assert_eq!((row.state, row.problem), (Rejected, RecordProblem::Structure));
    }

    #[test]
    fn a_carried_member_is_one_the_chain_named_with_its_last_keys() {
        // Someone the chain never named, carried as pending.
        let row = one_more(|a, _, _, _| a, |h, v3| v3.push(h.entry(&Acct::new(0x71), Pending, ChainRole::Member)));
        assert_eq!((row.state, row.problem), (Rejected, RecordProblem::Structure));
        // D carried as pending with other keys than the chain's.
        let row = one_more(|a, _, _, _| a, |h, v3| {
            let d = h.code(&Acct::new(0xd1));
            for e in v3.iter_mut().filter(|e| e.code == d) {
                e.state = Pending;
                e.commitment = [0x42; 32];
            }
        });
        assert_eq!((row.state, row.problem), (Rejected, RecordProblem::Structure));
    }

    #[test]
    fn nobody_removed_is_carried_back_as_pending() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Pending, Member)]);
        h.rotate(RecordKind::Rotation, &a, v4, None);
        let (_, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::Structure));
    }

    #[test]
    fn a_record_whose_link_is_not_served_waits() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        h.links.retain(|l| l.from_version != 3);
        let (_, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::LinkMissing));
    }

    #[test]
    fn a_bad_signature_waits() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        h.records.get_mut(&3).unwrap().1[7] ^= 1;
        let (_, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Signature));
    }

    #[test]
    fn the_signer_is_matched_by_code_and_commitment() {
        // C signs, but its entry commits to other keys than those this device
        // confirms for C: no confirmed member matches the signer.
        let row = one_more(|_, _, c, _| c, |h, v3| {
            let c = h.code(&Acct::new(0xc1));
            for e in v3.iter_mut().filter(|e| e.code == c) {
                e.commitment = key_commitment(&h.secret, &c, &[0x12; 32], &Acct::new(0xc1).signing_pk());
            }
        });
        assert_eq!((row.state, row.problem), (Waiting, RecordProblem::SignerUnknown));
    }

    #[test]
    fn a_record_that_links_elsewhere_is_a_fork() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.push(RecordKind::Rotation, 3, 2, [0x5c; 32], 2, &a, v3);
        let (device, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &d), &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Fork));
        assert!(report.forked && device.get_active_version(CIRCLE.into()).is_err());
    }

    #[test]
    fn another_record_at_this_devices_head_is_a_fork() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        // The same v2, signed by the admin instead: another record at the head.
        let mut other = History::genesis(&a);
        let v2 = rows(&other, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        other.rotate(RecordKind::Rotation, &c, v2, None);
        let report = import(&device, &other, &members, true);
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err());
    }

    #[test]
    fn a_first_devices_prefix_stops_at_a_signature_that_fails() {
        const VECTORS: &str = include_str!("../tests/data/refresh_record_v1.txt");
        let v: HashMap<&str, &str> = VECTORS.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).map(|l| l.split_once('=').unwrap()).collect();
        let acct = |n: &str, sign: u8, share: u8| Acct {
            uid: v[format!("{n}_user_id").as_str()].to_string(),
            signing: SigningKey::from_bytes(&[sign; 32]),
            sharing: StaticSecret::from([share; 32]),
        };
        let (a, c, d) = (acct("A", 0xa1, 0xa2), acct("C", 0xc1, 0xc2), acct("D", 0xd1, 0xd2));
        let mut records: Vec<SignedRefreshRecord> = (1..=4)
            .map(|i| SignedRefreshRecord {
                record_hex: v[format!("r{i}_record_wire").as_str()].to_string(),
                signature_hex: v[format!("r{i}_signature").as_str()].to_string(),
            })
            .collect();
        // r3's signature, one bit off.
        let mut bad = hex::decode(&records[2].signature_hex).unwrap();
        bad[5] ^= 1;
        records[2].signature_hex = hex::encode(bad);
        let links: Vec<KeyChainLinkData> = [(2, 1), (3, 2), (4, 2)]
            .iter()
            .map(|(f, t)| KeyChainLinkData {
                from_version: *f,
                to_version: *t,
                encrypted_key: v[format!("link_{f}_{t}_encrypted_key").as_str()].to_string(),
                nonce: v[format!("link_{f}_{t}_nonce").as_str()].to_string(),
            })
            .collect();
        let circle = v["circle_id"];
        let device = d.device();
        assert!(device.add_verified_key(circle, 4, &hex32(v["key_v4"]).unwrap()));
        let members: Vec<RecordMember> = [&a, &c, &d].iter().map(|m| m.member()).collect();
        let report = device.import_refresh_records_at(circle, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Signature));
        assert_eq!(device.get_active_version(circle.into()).unwrap(), 2, "anchored before the bad record, not on r4");
    }

    #[test]
    fn an_admission_counts_only_at_or_after_the_circles_first_record() {
        use ChainRole::{Admin, Member, Owner};
        // A legacy circle, at key version 4; its transition at v5.
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let mut h = History {
            format: RecordFormat::V1,
            keys: (1..=5u32).map(|v| (v, key_of(v))).collect(),
            secret: *crate::refresh_record::circle_secret(&key_of(4)).unwrap(),
            records: BTreeMap::new(),
            links: Vec::new(),
        };
        for v in 2..=4 {
            h.add_link(v, v - 1);
        }
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.push(RecordKind::Transition, 5, 0, [0; 32], 4, &a, v5);
        let members = four_members(&a, &b, &c, &d);
        let device = a.device();
        give(&device, &h, 5);
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None));
        let n = Acct::new(0x70);
        let with_n = |statement: HeldStatement| {
            let mut m = members.clone();
            m.push(with(n.member(), |r| r.statements = vec![statement]));
            m
        };
        assert!(!eligible(&device, &with_n(c.admit(&n, 3)), &n, EligibilityPurpose::Include).eligible, "made before the first record");
        assert_eq!(eligible(&device, &with_n(c.admit(&n, 5)), &n, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
    }

    #[test]
    fn the_walk_never_takes_a_key_its_record_does_not_vouch_for() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        // A rogue link from v3 carries another key for v2, and a link under that
        // key carries the real v1: without the check that each walked key
        // verifies its record's tag, the walk would reach the anchor.
        let wrong = [0x5b; 32];
        let mut rogue = h.clone();
        rogue.links.clear();
        let key3 = h.keys[&3];
        let key1 = h.keys[&1];
        rogue.add_raw_link(3, 2, &key3, &wrong);
        rogue.add_raw_link(2, 1, &wrong, &key1);
        let device = d.device();
        give(&device, &h, 3);
        let report = import(&device, &rogue, &four_members(&a, &b, &c, &d), true);
        assert_eq!(report.versions.last().map(|r| (r.state, r.problem)), Some((Waiting, RecordProblem::ChainWalk)));
        assert!(device.held_keys(CIRCLE).iter().all(|(v, _)| *v != 2), "the unvouched key is not stored");
        assert!(device.get_active_version(CIRCLE.into()).is_err());
    }

    #[test]
    fn the_anchor_key_is_checked_even_without_the_records() {
        let (a, _, _, _, h) = four();
        let first = &h.records[&1].0;
        let anchor = anchor_check(first);
        let links: Vec<KeyChainLinkData> = Vec::new();
        let seen = BTreeMap::new();
        let right = vec![(1u32, Zeroizing::new(h.keys[&1].to_vec()))];
        assert!(walk_to_anchor(&anchor, &right, &links, &seen).is_some());
        let wrong = vec![(1u32, Zeroizing::new([0x13u8; 32].to_vec()))];
        assert!(walk_to_anchor(&anchor, &wrong, &links, &seen).is_none(), "the anchor check refuses a wrong anchor key");
        let _ = a;
    }

    // ------------------------------------------------------------------
    // The builder and heads
    // ------------------------------------------------------------------

    /// Open `acct`'s wrap in a rotation bundle, as its device would.
    fn open_wrap(acct: &Acct, bundle: &crate::types::KeyRotationBundle) -> [u8; 32] {
        let entry = bundle.member_keys.iter().find(|e| e.user_id == acct.uid).expect("a wrap for them");
        let eph = <[u8; 32]>::try_from(hex::decode(&entry.bundle.ephemeral_public_key).unwrap().as_slice()).unwrap();
        let shared = acct.sharing.diffie_hellman(&PublicKey::from(eph));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = <[u8; 24]>::try_from(hex::decode(&entry.bundle.encrypted_circle_key.nonce).unwrap().as_slice()).unwrap();
        let plain = XChaCha20Poly1305::new_from_slice(&wrapping)
            .unwrap()
            .decrypt(&XNonce::from(nonce), hex::decode(&entry.bundle.encrypted_circle_key.ciphertext).unwrap().as_ref())
            .unwrap();
        plain.try_into().unwrap()
    }

    fn plan(rows: &[(&Acct, RecordMemberState, Option<CircleRole>)]) -> Vec<PlannedEntry> {
        rows.iter().map(|(a, state, role)| PlannedEntry { user_id: a.uid.clone(), state: *state, role: *role }).collect()
    }

    /// What the server holds after it takes `bundle`: the history plus the record and its link.
    fn served_with(h: &History, bundle: &RecordedRotationBundle) -> (Vec<SignedRefreshRecord>, Vec<KeyChainLinkData>) {
        let mut records = h.signed();
        records.push(bundle.refresh_record.clone());
        let mut links = h.links.clone();
        links.push(bundle.rotation.key_chain_link.clone().expect("a link"));
        (records, links)
    }

    #[test]
    fn the_builders_record_is_accepted_by_every_device_and_served_back() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (owner, _) = device_at(&a, &a, &h, &members, &[2]);
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Rotation,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]),
                &members, true, "the circle", NOW,
            )
            .unwrap();
        assert_eq!(bundle.rotation.new_key_version, 3);
        assert_eq!(bundle.rotation.member_keys.len(), 4);
        let link = bundle.rotation.key_chain_link.clone().unwrap();
        assert_eq!((link.from_version, link.to_version), (3, 2));
        // The owner seals under its own new version until the server serves it back.
        assert_eq!(owner.get_active_version(CIRCLE.into()).unwrap(), 3);
        // Another member's device: its wrap opens, and the record is accepted.
        let key3 = open_wrap(&b, &bundle.rotation);
        let (records, links) = served_with(&h, &bundle);
        let member = b.device();
        assert!(member.add_verified_key(CIRCLE, 3, &key3));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert_eq!(member.get_active_version(CIRCLE.into()).unwrap(), 3);
        // Served back to the owner: accepted like any other, its own mark gone.
        let report = owner.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert!(owner.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].own.is_none());
        assert_eq!(owner.get_active_version(CIRCLE.into()).unwrap(), 3);
        // Its head, signed and checked: in format 2, the wire_chain of
        // the copy taken.
        let head = owner.sign_circle_head_of(CIRCLE, &a.uid).unwrap();
        let read = verify_head(&head.head_hex, &head.signature_hex, &hex::encode(a.signing_pk())).unwrap().unwrap();
        assert_eq!((read.version, read.user_id.as_str(), read.circle_id.as_str()), (3, a.uid.as_str(), CIRCLE));
        assert_eq!(hex::decode(&head.head_hex).unwrap()[0], 2);
        let own = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        let signature: [u8; 64] = hex::decode(&bundle.refresh_record.signature_hex).unwrap().try_into().unwrap();
        assert_eq!((own.body.format, read.chain_hex), (RecordFormat::V2, hex::encode(own.wire_chain(&signature))));
        assert_eq!(verify_head(&head.head_hex, &head.signature_hex, &hex::encode(b.signing_pk())).unwrap(), None);
        assert!(verify_head("00", &head.signature_hex, &hex::encode(a.signing_pk())).is_err());
    }

    #[test]
    fn the_builder_refuses_what_other_devices_would_refuse() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (member, _) = device_at(&b, &a, &h, &members, &[2]);
        let build = |rows: &[(&Acct, S, Option<CircleRole>)]| {
            member.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &plan(rows), &members, true, "n", NOW)
        };
        // A plain member removes nobody,
        assert!(build(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)]).is_err());
        // changes no role,
        assert!(build(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, Some(CircleRole::Admin))]).is_err());
        // drops nobody silently,
        assert!(build(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]).is_err());
        // and includes nobody this device doesn't allow.
        let n = Acct::new(0x70);
        let mut with_n = members.clone();
        with_n.push(n.member());
        let refused = member.prepare_recorded_rotation_at(
            CIRCLE, &b.uid, RefreshRecordKind::Rotation,
            &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None), (&n, S::Included, None)]),
            &with_n, true, "n", NOW,
        );
        assert!(refused.is_err());
        assert_eq!(member.get_active_version(CIRCLE.into()).unwrap(), 2, "nothing was taken in");
        // A plain member's plan that carries everyone is fine.
        assert!(build(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Pending, None)]).is_ok());
    }

    #[test]
    fn a_rotation_from_below_links_to_the_highest_version_held() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Pending, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2]);
        assert_eq!(state_of_version(&report, 3).0, Reference);
        // D was ejected at v3: the owner's plan cannot bring D back...
        let refused = owner.prepare_recorded_rotation_at(
            CIRCLE, &a.uid, RefreshRecordKind::Rotation,
            &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]),
            &members, true, "n", NOW,
        );
        assert!(refused.is_err());
        // ... and its own rotation goes down to v2, the highest it holds.
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Rotation,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]),
                &members, true, "n", NOW,
            )
            .unwrap();
        let link = bundle.rotation.key_chain_link.clone().unwrap();
        assert_eq!((bundle.rotation.new_key_version, link.from_version, link.to_version), (4, 4, 2));
        let key4 = open_wrap(&c, &bundle.rotation);
        let (records, links) = served_with(&h, &bundle);
        let admin = c.device();
        assert!(admin.add_verified_key(CIRCLE, 4, &key4));
        let report = admin.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4).0, Accepted);
    }

    #[test]
    fn a_repair_links_the_record_it_repairs() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Rejected);
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Repair,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None), (&ghost, S::Departed, None)]),
                &members, true, "n", NOW,
            )
            .unwrap();
        assert_eq!(bundle.rotation.new_key_version, 4);
        let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        // In format 2 it links the rejected record's whole wire.
        let (rejected, rejected_signature) = &h.records[&3];
        assert_eq!(
            (record.body.format, record.body.kind, record.body.prev_version, record.body.prev_chain),
            (RecordFormat::V2, RecordKind::Repair, 3, rejected.wire_chain(rejected_signature))
        );
        let key4 = open_wrap(&d, &bundle.rotation);
        let (records, links) = served_with(&h, &bundle);
        let other = d.device();
        give(&other, &h, 2);
        assert!(other.add_verified_key(CIRCLE, 4, &key4));
        let report = other.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        assert_eq!(other.get_active_version(CIRCLE.into()).unwrap(), 4);
    }

    #[test]
    fn a_transition_starts_the_chain_of_a_circle_made_before() {
        use RecordMemberState as S;
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        let owner = a.device();
        for v in 1..=4u32 {
            assert!(owner.add_verified_key(CIRCLE, v, &key_of(v)));
        }
        assert!(!owner.circle_has_refresh_records(CIRCLE.into()));
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Transition,
                &plan(&[
                    (&a, S::Included, Some(CircleRole::Owner)),
                    (&b, S::Included, Some(CircleRole::Member)),
                    (&c, S::Included, Some(CircleRole::Admin)),
                    (&d, S::Pending, Some(CircleRole::Member)),
                ]),
                &members, true, "n", NOW,
            )
            .unwrap();
        let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        assert_eq!((record.body.kind, record.body.version, record.body.link_to, record.body.prev_version), (RecordKind::Transition, 5, 4, 0));
        assert_eq!(owner.get_active_version(CIRCLE.into()).unwrap(), 5);
        // Another member's device takes it as the circle's first record.
        let key5 = open_wrap(&b, &bundle.rotation);
        let member = b.device();
        assert!(member.add_verified_key(CIRCLE, 5, &key5));
        let report = member
            .import_refresh_records_at(CIRCLE, &[bundle.refresh_record.clone()], &[bundle.rotation.key_chain_link.clone().unwrap()], &members, true, None, &[], NOW)
            .unwrap();
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        assert_eq!(member.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        // A circle with records never gets a second transition.
        assert!(member
            .prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Transition, &plan(&[(&b, S::Included, Some(CircleRole::Owner))]), &members, true, "n", NOW)
            .is_err());
        // The owner discards its rotation if the server refuses it: legacy again.
        let fresh = a.device();
        for v in 1..=4u32 {
            assert!(fresh.add_verified_key(CIRCLE, v, &key_of(v)));
        }
        let alone = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        fresh
            .prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &plan(&[(&a, S::Included, Some(CircleRole::Owner))]), &alone, true, "n", NOW)
            .unwrap();
        assert!(fresh.discard_unconfirmed_rotation(CIRCLE.into()));
        assert!(!fresh.circle_has_refresh_records(CIRCLE.into()));
        assert_eq!(fresh.get_active_version(CIRCLE.into()).unwrap(), 4);
    }

    #[test]
    fn a_personal_slot_has_no_records() {
        // A personal key slot is no circle. No record is built on
        // one, none is imported for one, and a head "seen" for one
        // latches nothing: its rows still seal. Every spelling of
        // the nil id, and "self".
        use RecordMemberState as S;
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        let rows = plan(&[
            (&a, S::Included, Some(CircleRole::Owner)),
            (&b, S::Included, Some(CircleRole::Member)),
            (&c, S::Included, Some(CircleRole::Admin)),
            (&d, S::Pending, Some(CircleRole::Member)),
        ]);
        // On a legacy circle this plan goes, and a member it
        // includes opens the key its record links down to: on a
        // personal slot, that would be the personal key.
        let owner = a.device();
        for v in 1..=4u32 {
            assert!(owner.add_verified_key(CIRCLE, v, &key_of(v)));
        }
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &rows, &members, true, "n", NOW).unwrap();
        let link = bundle.rotation.key_chain_link.clone().unwrap();
        assert!(open_link(&open_wrap(&b, &bundle.rotation), &link).map_or(false, |older| older.as_slice() == key_of(4)));
        let nil = uuid::Uuid::nil();
        for slot in [nil.hyphenated().to_string(), nil.simple().to_string(), nil.braced().to_string(), nil.urn().to_string(), "self".to_string()] {
            let owner = a.device();
            for v in 1..=4u32 {
                assert!(owner.add_verified_key(&slot, v, &key_of(v)));
            }
            for kind in [RefreshRecordKind::Transition, RefreshRecordKind::Rotation, RefreshRecordKind::Repair] {
                let built = owner.prepare_recorded_rotation_at(&slot, &a.uid, kind, &rows, &members, true, "n", NOW);
                assert!(
                    matches!(&built, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is no circle: it is never rotated as one"),
                    "{slot}: {:?}",
                    built.as_ref().err()
                );
            }
            let imported = owner.import_refresh_records_at(&slot, &[bundle.refresh_record.clone()], &[link.clone()], &members, true, None, &[], NOW);
            assert!(
                matches!(&imported, Err(MobileError::InvalidInput(why)) if why == "a personal key slot is no circle: it has no records"),
                "{slot}: {:?}",
                imported.as_ref().err()
            );
            owner.note_circle_has_records(slot.clone());
            assert!(owner.refresh.read().unwrap().get(&CircleKey::of(&slot)).is_none(), "{slot}: no chain here");
            assert!(!owner.circle_has_refresh_records(slot.clone()) && !owner.is_behind(slot.clone()), "{slot}");
            assert_eq!(owner.get_active_version(slot.clone()).unwrap(), 4, "{slot}");
            assert!(owner.encrypt_data(slot.clone(), "a personal row".into()).is_ok(), "{slot}: its rows still seal");
        }
    }

    #[test]
    fn a_new_circle_comes_with_its_genesis() {
        let (a, b) = (Acct::new(0xa1), Acct::new(0xb1));
        let creator = a.device();
        let created = creator.prepare_recorded_circle_creation_at(&a.uid, &uuid::Uuid::new_v4().to_string(), NOW).unwrap();
        assert_eq!(created.creation.temp_circle_id, created.circle_id);
        assert_eq!(creator.get_active_version(created.circle_id.clone()).unwrap(), 1);
        assert!(creator.circle_has_refresh_records(created.circle_id.clone()));
        let genesis = WireRecord::parse(&hex::decode(&created.genesis.record_hex).unwrap()).unwrap();
        assert_eq!((genesis.body.kind, genesis.body.version), (RecordKind::Genesis, 1));
        assert_eq!(genesis.body.circle_id, *uuid::Uuid::parse_str(&created.circle_id).unwrap().as_bytes());
        // A member who gets key 1 accepts the genesis as the lone first record.
        let key1 = creator.held_keys(&created.circle_id).into_iter().find(|(v, _)| *v == 1).unwrap().1;
        let member = b.device();
        assert!(member.add_verified_key(&created.circle_id, 1, &key1));
        let report = member
            .import_refresh_records_at(&created.circle_id, &[created.genesis.clone()], &[], &[a.member(), b.member()], true, None, &[], NOW)
            .unwrap();
        assert_eq!(state_of_version(&report, 1).0, Accepted);
        assert_eq!(member.chain_role(created.circle_id.clone(), a.uid.clone()), Some(CircleRole::Owner));
        // Refused by the server: discarded, keys and all. Nothing else can be.
        assert!(creator.discard_circle_creation_of(&created.circle_id));
        assert!(!creator.has_circle_key(created.circle_id.clone()));
        assert!(!creator.circle_has_refresh_records(created.circle_id.clone()));
        assert!(!member.discard_circle_creation_of(&created.circle_id), "not this device's own creation");
        // Once the server serves the genesis back, it is no longer discardable.
        let again = creator.prepare_recorded_circle_creation_at(&a.uid, &uuid::Uuid::new_v4().to_string(), NOW).unwrap();
        creator
            .import_refresh_records_at(&again.circle_id, &[again.genesis.clone()], &[], &[a.member()], true, None, &[], NOW)
            .unwrap();
        assert!(!creator.discard_circle_creation_of(&again.circle_id));
    }

    #[test]
    fn a_transition_includes_only_members_this_device_confirms_and_at_most_100() {
        use RecordMemberState as S;
        let (a, b) = (Acct::new(0xa1), Acct::new(0xb1));
        let owner = a.device();
        for v in 1..=4u32 {
            assert!(owner.add_verified_key(CIRCLE, v, &key_of(v)));
        }
        // B is listed but not confirmed here: pending, never included.
        let members = vec![with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)), with(b.member(), |m| m.confirmed = false)];
        let include_b = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member))]);
        assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &include_b, &members, true, "n", NOW).is_err());
        let pending_b = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Pending, Some(CircleRole::Member))]);
        owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &pending_b, &members, true, "n", NOW).unwrap();
        assert!(owner.discard_unconfirmed_rotation(CIRCLE.into()));
        // 101 included: refused by the cap.
        let many: Vec<Acct> = (0..100u8).map(|n| Acct::new(n.wrapping_add(0x10))).collect();
        let mut rows: Vec<(&Acct, S, Option<CircleRole>)> = vec![(&a, S::Included, Some(CircleRole::Owner))];
        rows.extend(many.iter().map(|m| (m, S::Included, Some(CircleRole::Member))));
        let mut listed = vec![with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        listed.extend(many.iter().map(|m| m.member()));
        match owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &plan(&rows), &listed, true, "n", NOW) {
            Err(MobileError::InvalidInput(why)) => assert!(why.contains("at most 100"), "{why}"),
            other => panic!("refused by the cap, got {:?}", other.map(|b| b.rotation.new_key_version)),
        }
    }

    #[test]
    fn nothing_is_built_on_a_forked_chain() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let same_rows = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let mut one = h.clone();
        one.rotate(RecordKind::Rotation, &a, same_rows(&h), None);
        let mut two = h.clone();
        two.rotate(RecordKind::Rotation, &c, same_rows(&h), None);
        let mut both = one.signed();
        both.extend(two.signed());
        assert!(device.import_refresh_records_at(CIRCLE, &both, &one.links, &members, true, None, &[], NOW).unwrap().forked);
        let refused = device.prepare_recorded_rotation_at(
            CIRCLE, &a.uid, RefreshRecordKind::Rotation,
            &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]),
            &members, true, "n", NOW,
        );
        assert!(refused.is_err());
    }

    // ------------------------------------------------------------------
    // A transition's anchor
    // ------------------------------------------------------------------

    impl History {
        /// A legacy circle, at key version `v0 - 1`, whose first
        /// record is `writer`'s transition at `v0`, made over
        /// `anchor_key` as the writer's key for `v0 - 1` (S comes
        /// from it).
        fn transition_over(writer: &Acct, v0: u32, anchor_key: [u8; 32], rows: &[(&Acct, EntryState, ChainRole)]) -> Self {
            let secret = *crate::refresh_record::circle_secret(&anchor_key).unwrap();
            let mut history = History { format: RecordFormat::V1, keys: BTreeMap::new(), secret, records: BTreeMap::new(), links: Vec::new() };
            for version in 1..v0 {
                history.keys.insert(version, key_of(version));
            }
            history.keys.insert(v0 - 1, anchor_key);
            for version in 2..v0 {
                history.add_link(version, version - 1);
            }
            let entries = rows.iter().map(|(acct, state, role)| history.entry(acct, *state, *role)).collect();
            history.push(RecordKind::Transition, v0, 0, [0; 32], v0 - 1, writer, entries);
            history
        }
        fn transition(writer: &Acct, v0: u32, rows: &[(&Acct, EntryState, ChainRole)]) -> Self {
            Self::transition_over(writer, v0, key_of(v0 - 1), rows)
        }
    }

    /// A device of `acct` that held the circle's keys `1..=held` before its records.
    fn legacy_device(acct: &Acct, held: u32) -> Arc<CryptoManager> {
        let device = acct.device();
        for version in 1..=held {
            assert!(device.add_verified_key(CIRCLE, version, &key_of(version)));
        }
        device
    }

    #[test]
    fn a_transition_whose_writer_is_wiped_is_carried_on_from_below() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        // A's transition at v5 includes only A; then A's phone is wiped, and
        // nobody else ever gets key 5.
        let h = History::transition(&a, 5, &[(&a, Included, Owner), (&b, Pending, Member), (&c, Pending, Admin), (&d, Pending, Member)]);
        // C, pending at v5, held v4: its own key for the anchor verifies the
        // anchor tag, so it derives S and takes v5 as its reference.
        let admin = legacy_device(&c, 4);
        let report = import(&admin, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Reference, RecordProblem::None));
        assert!(admin.get_active_version(CIRCLE.into()).is_err(), "no accepted version with its key: nothing is sealed");
        // C rotates from below: v6, its link down to the anchor, v4.
        let bundle = admin
            .prepare_recorded_rotation_at(
                CIRCLE, &c.uid, RefreshRecordKind::Rotation,
                &plan(&[(&a, S::Pending, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]),
                &members, true, "n", NOW,
            )
            .unwrap();
        let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        assert_eq!((record.body.version, record.body.prev_version, record.body.link_to), (6, 5, 4));
        assert_eq!(admin.get_active_version(CIRCLE.into()).unwrap(), 6);
        let (records, links) = served_with(&h, &bundle);
        let key6 = open_wrap(&b, &bundle.rotation);
        // Accepted everywhere: by B (pending at v5 too, holding v4, then v6),
        // by D seeing both records at once, and by C's own device when the
        // server serves it back.
        let member = legacy_device(&b, 4);
        assert_eq!(state_of_version(&import(&member, &h, &members, true), 5), (Reference, RecordProblem::None));
        assert!(member.add_verified_key(CIRCLE, 6, &key6));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 6), (Accepted, RecordProblem::None));
        assert_eq!(member.get_active_version(CIRCLE.into()).unwrap(), 6);
        let other = legacy_device(&d, 4);
        assert!(other.add_verified_key(CIRCLE, 6, &open_wrap(&d, &bundle.rotation)));
        let report = other.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 6), (Accepted, RecordProblem::None));
        let report = admin.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 6), (Accepted, RecordProblem::None));
        // A later joiner E holds key 6 only: it walks 6 -> 4, the step v6
        // names, the anchor tag verifies key 4, and it derives S.
        let e = Acct::new(0xe1);
        let mut with_e = members.clone();
        with_e.push(with(e.member(), |m| m.statements = vec![c.admit(&e, 6)]));
        let joiner = e.device();
        assert!(joiner.add_verified_key(CIRCLE, 6, &key6));
        let report = joiner.import_refresh_records_at(CIRCLE, &records, &links, &with_e, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 6), (Accepted, RecordProblem::None));
        assert_eq!(joiner.get_active_version(CIRCLE.into()).unwrap(), 6);
        assert_eq!(joiner.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        assert!(joiner.held_keys(CIRCLE).iter().any(|(v, k)| *v == 4 && k.as_slice() == key_of(4)), "the anchor key, checked, is stored");
        assert_eq!(eligible(&joiner, &with_e, &b, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        assert_eq!(eligible(&joiner, &with_e, &e, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
    }

    #[test]
    fn an_anchor_that_fails_this_devices_own_key_waits_and_keeps_it() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        // A holds another key for v4 than the circle's (fooled at first
        // contact, or a rogue), and writes the transition over it.
        let foreign = [0x4f; 32];
        let h = History::transition_over(&a, 5, foreign, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let device = legacy_device(&d, 4);
        give(&device, &h, 5);
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::AnchorMismatch));
        assert!(!report.ask_for_fresh_copy, "never a fresh copy of the anchor key on the tag's word");
        assert!(device.circle_has_refresh_records(CIRCLE.into()));
        // This device keeps its key for v4 and reads with it, derives no S,
        // accepts nothing and seals nothing.
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 4 && k.as_slice() == key_of(4)));
        let old = sealed_under(&key_of(4), "a location from before");
        assert_eq!(device.decrypt_data_v2(CIRCLE.into(), old.clone(), "test".into()).unwrap(), "a location from before");
        assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing is sealed, under v5 or anything else");
        assert!(device.refresh_eligibility_at(CIRCLE, &members, EligibilityPurpose::Include, NOW).is_err());
        assert!(device.sign_circle_head_of(CIRCLE, &d.uid).is_err(), "no head: nothing was accepted");
        // Break: the key for v4 that verifies the anchor is never taken in
        // place of this device's own: not from the transition's link, not as
        // a copy, not from a walk.
        let link = h.links.iter().find(|l| l.from_version == 5 && l.to_version == 4).unwrap().clone();
        assert!(device
            .import_key_chain_link(CIRCLE.into(), 5, 4, link.encrypted_key.clone(), link.nonce.clone())
            .is_err());
        assert!(own_copy(&device, &d, 4, &foreign).is_err());
        assert!(!device.add_verified_key(CIRCLE, 4, &foreign));
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::AnchorMismatch));
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 4 && k.as_slice() == key_of(4)), "still the circle's key");
        assert_eq!(device.decrypt_data_v2(CIRCLE.into(), old, "test".into()).unwrap(), "a location from before");
        // Only a device that never held v4 walks to the writer's key and
        // accepts (as at any first contact, it trusts what it sees first).
        let joiner = b.device();
        give(&joiner, &h, 5);
        let report = import(&joiner, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None));
    }

    #[test]
    fn after_a_transition_no_link_goes_below_the_anchor() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        // C is pending at v5: its own floor is 0, so only the anchor's holds.
        let h = History::transition(&a, 5, &[(&a, Included, Owner), (&b, Included, Member), (&c, Pending, Admin), (&d, Included, Member)]);
        let v6 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        // B took v5 when it was served, then judges v6.
        let device_with = |h: &History| {
            let device = legacy_device(&b, 4);
            give(&device, h, 5);
            let mut first = h.clone();
            first.records.retain(|v, _| *v == 5);
            assert_eq!(state_of_version(&import(&device, &first, &members, true), 5).0, Accepted);
            give(&device, h, 6);
            import(&device, h, &members, true)
        };
        let mut below = h.clone();
        below.rotate(RecordKind::Rotation, &c, v6.clone(), Some(3));
        assert_eq!(state_of_version(&device_with(&below), 6), (Rejected, RecordProblem::Floor));
        let mut at = h.clone();
        at.rotate(RecordKind::Rotation, &c, v6, Some(4));
        assert_eq!(state_of_version(&device_with(&at), 6), (Accepted, RecordProblem::None));
        // A link below the anchor is refused on the device too: v6 -> v3
        // spans versions no record names.
        let device = legacy_device(&d, 2);
        give(&device, &at, 5);
        import(&device, &at, &members, true);
        give(&device, &at, 6);
        let mut skip = at.clone();
        skip.links.clear();
        skip.add_link(6, 3);
        let link = skip.links[0].clone();
        assert!(device.import_key_chain_link(CIRCLE.into(), 6, 3, link.encrypted_key, link.nonce).is_err());
        // On a genesis circle, a record after the genesis never links to 0:
        // it does not even parse.
        let (a, b, c, d, h) = four();
        let mut bytes = h.records[&2].0.to_bytes();
        bytes[58..62].fill(0);
        let served = vec![
            h.signed()[0].clone(),
            SignedRefreshRecord { record_hex: hex::encode(bytes), signature_hex: hex::encode(h.records[&2].1) },
        ];
        let device = a.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        let report = device
            .import_refresh_records_at(CIRCLE, &served, &h.links, &four_members(&a, &b, &c, &d), true, None, &[], NOW)
            .unwrap();
        assert_eq!(state_of_version(&report, 2), (Rejected, RecordProblem::Structure));
    }

    #[test]
    fn kind_2_counts_only_beside_a_statement_that_signs_the_user_id() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        // v3: the owner ejects X, within the 7 days of an address invitation
        // the owner signed for X at v1.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let by_address = a.email_invite("x@example.com", 1, NOW - 3600);
        // The server names X's new account, with the keys recorded for X.
        let x2 = Acct { uid: "e2e2e2e2-0000-4000-8000-0000000000e2".into(), signing: x.signing.clone(), sharing: x.sharing.clone() };
        let members = |statements: Vec<HeldStatement>| {
            vec![
                with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.statements = vec![a.invite(&b, 1)]),
                with(c.member(), |m| {
                    m.statements = vec![a.invite(&c, 1)];
                    m.listed_role = Some(CircleRole::Admin);
                }),
                with(x2.member(), |m| {
                    m.statements = statements;
                    m.server_says_keyless = true;
                }),
            ]
        };
        let only_address = members(vec![by_address.clone()]);
        let (device, report) = device_at(&a, &a, &h, &only_address, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        // Not included, and nothing delivered.
        let e = eligible(&device, &only_address, &x2, EligibilityPurpose::Include);
        assert!(!e.eligible && e.email_invitation_without_signed_id, "{e:?}");
        assert!(!eligible(&device, &only_address, &x2, EligibilityPurpose::Deliver).eligible);
        // A record that includes X's new account on it is refused.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x2, Included, Member)]);
        let mut next = h.clone();
        next.rotate(RecordKind::Rotation, &c, v4, None);
        give(&device, &next, 4);
        assert_eq!(state_of_version(&import(&device, &next, &only_address, true), 4), (Rejected, RecordProblem::R2NotAllowed));
        // An admission that signs the new id counts.
        let admitted = members(vec![by_address.clone(), a.admit(&x2, 3)]);
        assert_eq!(eligible(&device, &admitted, &x2, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
        // And the address invitation itself counts once a statement that holds
        // up here signs the id: the owner's own expired account invitation.
        let expired = a.statement(MembershipStatementKind::InvitationToAccount, &x2, 1, NOW - 8 * 86_400);
        let beside = members(vec![by_address.clone(), expired.clone()]);
        let e = eligible(&device, &beside, &x2, EligibilityPurpose::Include);
        assert_eq!(e.basis, Some(EligibilityBasis::Invitation), "{e:?}");
        assert!(!e.email_invitation_without_signed_id);
        assert_eq!(eligible(&device, &beside, &x2, EligibilityPurpose::Deliver).basis, Some(EligibilityBasis::Invitation));
        // A statement about someone else, or in another circle, signs no id of theirs.
        let about_b = members(vec![by_address.clone(), a.statement(MembershipStatementKind::InvitationToAccount, &b, 1, NOW - 8 * 86_400)]);
        assert!(!eligible(&device, &about_b, &x2, EligibilityPurpose::Include).eligible);
        let elsewhere = members(vec![by_address.clone(), a.statement_in("d0d0d0d0-2222-4333-8444-555555555555", MembershipStatementKind::Admission, &x2, 3, NOW - 60)]);
        assert!(!eligible(&device, &elsewhere, &x2, EligibilityPurpose::Include).eligible);
        // A plain member's statement never supplies the id; the same one
        // signed by an admin does.
        let by_plain = members(vec![by_address.clone(), b.statement(MembershipStatementKind::InvitationToAccount, &x2, 3, NOW - 60)]);
        let e = eligible(&device, &by_plain, &x2, EligibilityPurpose::Include);
        assert!(!e.eligible && e.email_invitation_without_signed_id, "{e:?}");
        assert!(!eligible(&device, &by_plain, &x2, EligibilityPurpose::Deliver).eligible);
        let by_admin = members(vec![by_address.clone(), c.statement(MembershipStatementKind::InvitationToAccount, &x2, 3, NOW - 8 * 86_400)]);
        assert_eq!(eligible(&device, &by_admin, &x2, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Invitation));
        // Nor does one that binds other keys.
        let other_keys = Acct { uid: x2.uid.clone(), signing: SigningKey::from_bytes(&[0x99; 32]), sharing: x2.sharing.clone() };
        let wrong_keys = members(vec![by_address.clone(), a.statement(MembershipStatementKind::InvitationToAccount, &other_keys, 1, NOW - 8 * 86_400)]);
        assert!(!eligible(&device, &wrong_keys, &x2, EligibilityPurpose::Include).eligible);
        // Nor does one that does not hold up here: its signer is nobody this device confirms.
        let stranger = Acct::new(0x5e);
        let unconfirmed = members(vec![by_address, stranger.statement(MembershipStatementKind::InvitationToAccount, &x2, 3, NOW - 60)]);
        let e = eligible(&device, &unconfirmed, &x2, EligibilityPurpose::Include);
        assert!(!e.eligible && e.email_invitation_without_signed_id, "{e:?}");
        let _ = expired;
    }

    #[test]
    fn a_walk_that_reaches_another_anchor_key_derives_nothing() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        let h = History::transition(&a, 5, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        // A joiner holding key 5 only; the served link 5 -> 4 carries another key.
        let mut bad = h.clone();
        bad.links.retain(|l| l.from_version != 5);
        let key5 = bad.keys[&5];
        bad.add_raw_link(5, 4, &key5, &[0x4e; 32]);
        let joiner = b.device();
        give(&joiner, &h, 5);
        let report = import(&joiner, &bad, &members, true);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::ChainWalk));
        assert!(report.ask_for_fresh_copy, "a fresh copy of the link or of key 5");
        assert!(joiner.held_keys(CIRCLE).iter().all(|(v, _)| *v != 4), "the wrong key is not stored");
        assert!(joiner.get_active_version(CIRCLE.into()).is_err());
        // The same link as a single import is refused too: its key fails the anchor tag.
        let link = bad.links.iter().find(|l| l.from_version == 5).unwrap().clone();
        assert!(joiner.import_key_chain_link(CIRCLE.into(), 5, 4, link.encrypted_key, link.nonce).is_err());
        assert!(joiner.held_keys(CIRCLE).iter().all(|(v, _)| *v != 4));
        // The right link: S, v5 accepted, and key 4 stored for reading.
        let report = import(&joiner, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None));
        assert!(joiner.held_keys(CIRCLE).iter().any(|(v, k)| *v == 4 && k.as_slice() == key_of(4)));
        let old = sealed_under(&key_of(4), "from before the transition");
        assert_eq!(joiner.decrypt_data_v2(CIRCLE.into(), old, "test".into()).unwrap(), "from before the transition");
        // Below the anchor, links keep the one-step rule.
        let link = h.links.iter().find(|l| l.from_version == 4 && l.to_version == 3).unwrap().clone();
        joiner.import_key_chain_link(CIRCLE.into(), 4, 3, link.encrypted_key, link.nonce).unwrap();
        assert!(joiner.held_keys(CIRCLE).iter().any(|(v, k)| *v == 3 && k.as_slice() == key_of(3)));
    }

    #[test]
    fn a_new_circle_takes_only_a_fresh_version_4_id() {
        let a = Acct::new(0xa1);
        let creator = a.device();
        for refused in [
            "00000000-0000-0000-0000-000000000000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "a1a1a1a1-2222-4333-c444-555555555555",
            "not a uuid",
            "",
        ] {
            assert!(
                matches!(creator.prepare_recorded_circle_creation_at(&a.uid, refused, NOW), Err(MobileError::InvalidInput(_))),
                "{refused:?} must be refused"
            );
        }
        assert!(creator.add_verified_key(CIRCLE, 1, &key_of(1)));
        assert!(creator.prepare_recorded_circle_creation_at(&a.uid, CIRCLE, NOW).is_err(), "a circle this device already holds");
        let created = creator.prepare_recorded_circle_creation_at(&a.uid, "B2B2B2B2-2222-4333-8444-555555555555", NOW).unwrap();
        assert_eq!(created.circle_id, "b2b2b2b2-2222-4333-8444-555555555555");
        assert!(creator.prepare_recorded_circle_creation_at(&a.uid, &created.circle_id, NOW).is_err(), "never the same id twice");
    }

    #[test]
    fn a_persisted_anchor_is_v0_or_the_version_before() {
        let record = |anchor: i64, v0: i64| PinRecord {
            sharing_pubkey_hex: hex::encode([1u8; 32]),
            signing_pubkey_hex: hex::encode([2u8; 32]),
            first_pinned_at: anchor,
            last_verified_at: v0,
            user_approved_change_at: None,
        };
        let key = format!("{ANCHOR_PREFIX}{CIRCLE}");
        for (anchor, v0, kept) in [(1, 1, true), (4, 5, true), (3, 5, false), (5, 4, false), (0, 1, false), (0, 0, false), (6, 5, false)] {
            let mut chains = HashMap::new();
            assert_eq!(absorb_persisted(&mut chains, &key, &record(anchor, v0)), kept, "read: anchor {anchor}, V0 {v0}");
            assert_eq!(chains.get(&CircleKey::of(CIRCLE)).and_then(|c| c.anchor.as_ref()).is_some(), kept, "anchor {anchor}, V0 {v0}");
        }
    }

    #[test]
    fn a_transition_waits_for_its_own_link_to_the_anchor() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let members = four_members(&a, &b, &c, &d);
        let h = History::transition(&a, 5, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        // B held v4 and got v5: it needs no link for S, but later joiners do.
        let device = legacy_device(&b, 4);
        give(&device, &h, 5);
        let mut unlinked = h.clone();
        unlinked.links.retain(|l| l.from_version != 5);
        assert_eq!(state_of_version(&import(&device, &unlinked, &members, true), 5), (Waiting, RecordProblem::LinkMissing));
        assert!(device.get_active_version(CIRCLE.into()).is_err());
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 5), (Accepted, RecordProblem::None));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 5);
    }

    #[test]
    fn a_walk_never_follows_a_named_step_below_the_anchor() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let mut h = History::transition(&a, 5, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        // v6 names a step to v3, below the anchor v4; v6 -> v5 is served too, after it.
        let v6 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v6, Some(3));
        h.add_link(6, 5);
        let seen: BTreeMap<u32, SeenRecord> = h
            .records
            .iter()
            .map(|(v, (wire, _))| (*v, SeenRecord::new(wire.clone(), wire.chain(), RecordVersionState::Reference)))
            .collect();
        let anchor = anchor_check(&h.records[&5].0);
        let held = vec![(6u32, Zeroizing::new(h.keys[&6].to_vec()))];
        let (key, walked) = walk_to_anchor(&anchor, &held, &h.links, &seen).expect("6 -> 5 -> 4 reaches the anchor");
        assert_eq!(key.as_slice(), key_of(4));
        assert_eq!(walked.iter().map(|w| (w.version, w.checked)).collect::<Vec<_>>(), vec![(5, true), (4, true)]);
        assert!(!step_allowed(&seen, 4, 6, 3), "a named step below the anchor");
        assert!(step_allowed(&seen, 4, 6, 5) && step_allowed(&seen, 4, 4, 3), "one version down, at or below the anchor");
    }

    // ------------------------------------------------------------------
    // One overlay: the removals that count in a rejected record, as the
    // importer judged them, for the importer, the builder and E alike
    // ------------------------------------------------------------------

    #[test]
    fn one_overlay_a_plain_members_refused_removal_of_the_owner_blocks_nothing() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: plain member B "removes" the owner. Refused hard, on every device.
        let v3 = rows(&h, &[(&a, Removed, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let (admin, report) = device_at(&c, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Removal));
        // The owner still counts, for E and for the repair's builder.
        let e = eligible(&admin, &members, &a, EligibilityPurpose::Include);
        assert_eq!(e.basis, Some(EligibilityBasis::CountedByChain), "{e:?}");
        assert!(!e.removed_by_owner_or_admin);
        let bundle = admin
            .prepare_recorded_rotation_at(
                CIRCLE, &c.uid, RefreshRecordKind::Repair,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]),
                &members, true, "n", NOW,
            )
            .expect("the owner is included in the repair");
        let (records, links) = served_with(&h, &bundle);
        let other = d.device();
        give(&other, &h, 2);
        assert!(other.add_verified_key(CIRCLE, 4, &open_wrap(&d, &bundle.rotation)));
        let report = other.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(other.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
    }

    #[test]
    fn one_overlay_an_admins_removal_in_a_rejected_record_counts_for_e_and_the_builder() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: admin C ejects D, and includes a member nobody confirms: R2 refuses it.
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        // The ejection counts: D is neither included nor delivered to.
        let e = eligible(&owner, &members, &d, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin, "{e:?}");
        assert!(!eligible(&owner, &members, &d, EligibilityPurpose::Deliver).eligible);
        assert_eq!(eligible(&owner, &members, &b, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
        // The repair can't include D or carry D as pending; it keeps the removal.
        let with_d = |state: S| plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, state, None), (&ghost, S::Departed, None)]);
        assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &with_d(S::Included), &members, true, "n", NOW).is_err());
        assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &with_d(S::Pending), &members, true, "n", NOW).is_err());
        let bundle = owner
            .prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &with_d(S::Removed), &members, true, "n", NOW)
            .unwrap();
        let (records, links) = served_with(&h, &bundle);
        let other = b.device();
        give(&other, &h, 2);
        assert!(other.add_verified_key(CIRCLE, 4, &open_wrap(&b, &bundle.rotation)));
        let report = other.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert!(!eligible(&other, &members, &d, EligibilityPurpose::Include).eligible);
        // Once the repair is accepted, the overlay is gone with the rejected record behind the head.
        assert!(owner
            .import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW)
            .unwrap()
            .versions
            .iter()
            .any(|r| r.version == 4 && r.state == Accepted));
        let e = eligible(&owner, &members, &d, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin, "the repair's own removal: {e:?}");
    }

    // ------------------------------------------------------------------
    // A version passed over is never forgotten at a restart: it waits
    // for its own record, and what it counted still counts meanwhile
    // ------------------------------------------------------------------

    /// v3 by admin C ejects D and includes a member nobody confirms: R2 refuses
    /// it, and D's ejection counts. The owner A's device, stored, holds v1-v3
    /// and passed v3 over.
    #[allow(clippy::type_complexity)]
    fn an_ejection_passed_over() -> (Acct, Acct, Acct, Acct, Acct, History, Vec<RecordMember>, Arc<CryptoManager>, MemStore) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let (owner, store) = stored_device(&a, &up_to(&h, 2), &members);
        give(&owner, &h, 3);
        assert_eq!(state_of_version(&import(&owner, &h, &members, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        (a, b, c, d, ghost, h, members, owner, store)
    }

    /// `h` as a server serves it that withholds every version above `version`,
    /// its links too.
    fn withheld_above(h: &History, version: u32) -> History {
        let mut part = up_to(h, version);
        part.links.retain(|l| l.from_version <= version as i32);
        part
    }

    /// `who`'s head at v2, with a chain value nobody holds.
    fn contradicting_head(who: &Acct) -> MemberHead {
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: who.uid16(), version: 2, chain: [0x2d; 32] };
        let bytes = head.encode().unwrap();
        MemberHead {
            user_id: who.uid.clone(),
            head: SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(who.signing.sign(&Head::digest(&bytes)).to_bytes()) },
        }
    }

    #[test]
    fn a_version_passed_over_waits_after_a_restart_and_what_it_counted_still_counts() {
        use RecordMemberState as S;
        let (a, b, c, d, ghost, h, members, owner, store) = an_ejection_passed_over();
        let d_out = |device: &CryptoManager| {
            for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
                let e = eligible(device, &members, &d, purpose);
                assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{purpose:?}: {e:?}");
            }
            assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), None);
        };
        d_out(&owner);
        // A restart; the server then withholds v3 and lists the circle at v2.
        let withheld = withheld_above(&h, 2);
        let again = restarted(&store);
        let report = import(&again, &withheld, &members, true);
        assert!(report.versions.is_empty() && !report.forked, "{report:?}");
        // v3 waits for its own record, and what it counted still
        // counts.
        assert_eq!(again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.get(&3), Some(&h.records[&3].0.chain()));
        d_out(&again);
        // D's word doesn't count either (a removal in a rejected record
        // counts until a repair); B's same head is a fork. (A second
        // restart reads what the first one stored again.)
        let forked_by = |who: &Acct| {
            let device = restarted(&store);
            let report = device.import_refresh_records_at(CIRCLE, &withheld.signed(), &withheld.links, &members, true, None, &[contradicting_head(who)], NOW);
            report.unwrap().forked
        };
        assert!(!forked_by(&d), "D's head, once D's ejection is passed over");
        assert!(forked_by(&b), "B's head");
        // A copy of v3 whose signature doesn't verify can't be judged:
        // v3 still waits, and what it counted still counts.
        let mut spoiled = h.clone();
        spoiled.records.get_mut(&3).unwrap().1[0] ^= 0x01;
        assert_eq!(state_of_version(&import(&again, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
        d_out(&again);
        // Nothing is built on v2 while v3 waits.
        let repair = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None), (&ghost, S::Departed, None)]);
        let refused = again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &repair, &members, true, "n", NOW);
        assert!(matches!(&refused, Err(MobileError::InvalidInput(m)) if m.contains("v3 of this circle waits here")), "{refused:?}");
        // Served again, v3 is judged afresh: refused again, passed over, and
        // the repair goes on it.
        assert_eq!(state_of_version(&import(&again, &h, &members, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert!(again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.is_empty() && again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].carried.is_empty());
        d_out(&again);
        let bundle = again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &repair, &members, true, "n", NOW).expect("the repair");
        assert_eq!(parsed(&bundle).body.prev_version, 3, "the repair links the record it repairs");
    }

    #[test]
    fn every_version_passed_over_waits_after_a_restart_not_only_the_latest() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: admin C ejects D; v4 on it: C ejects B. Each includes a member
        // nobody confirms: R2 refuses both, and both ejections count.
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Removed, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let (owner, store) = stored_device(&a, &up_to(&h, 2), &members);
        give(&owner, &h, 3);
        give(&owner, &h, 4);
        let report = import(&owner, &h, &members, true);
        assert_eq!((state_of_version(&report, 3), state_of_version(&report, 4)), ((Rejected, RecordProblem::R2UnmatchedEntry), (Rejected, RecordProblem::R2UnmatchedEntry)));
        // D's latest removal counts at v4 (v4 names it again), B's at v4.
        let out_at = |device: &CryptoManager, who: &Acct| eligible(device, &members, who, EligibilityPurpose::Deliver).removed_at_version;
        assert_eq!((out_at(&owner, &d), out_at(&owner, &b)), (Some(4), Some(4)));
        let again = restarted(&store);
        import(&again, &withheld_above(&h, 2), &members, true);
        let waiting: Vec<u32> = again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect();
        assert_eq!(waiting, vec![3, 4]);
        assert_eq!((out_at(&again, &d), out_at(&again, &b)), (Some(4), Some(4)));
        // v3 served again alone: judged and passed over in this process, with
        // v4 still waiting above it; the same removals count.
        import(&again, &up_to(&h, 3), &members, true);
        let waiting: Vec<u32> = again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect();
        assert_eq!(waiting, vec![4]);
        assert_eq!((out_at(&again, &d), out_at(&again, &b)), (Some(4), Some(4)));
    }

    #[test]
    fn what_a_version_passed_over_counted_goes_once_it_is_judged_again_or_the_head_passes_it() {
        // What is carried stands for the judgment made before the restart,
        // nothing more: judged again, the new judgment counts instead. (Here
        // the stored marker also names B, a removal v3 never made.)
        let (_a, b, c, d, ghost, h, members, _owner, store) = an_ejection_passed_over();
        let key = format!("{CARRIED_PREFIX}{CIRCLE}:3");
        let mut pins = stored_pins(&store);
        let marker = pins.get_mut(&key).unwrap();
        let mut carried = Carried::decode(h.records[&3].0.chain(), &hex::decode(&marker.signing_pubkey_hex).unwrap()).unwrap();
        assert!(carried.removals == BTreeSet::from([h.code(&d)]), "v3 counted D's ejection only");
        carried.removals.insert(h.code(&b));
        marker.signing_pubkey_hex = hex::encode(carried.encode());
        let b_counted = |device: &CryptoManager, list: &[RecordMember]| eligible(device, list, &b, EligibilityPurpose::Include).eligible;
        let d_counted = |device: &CryptoManager, list: &[RecordMember]| eligible(device, list, &d, EligibilityPurpose::Include).eligible;
        // Judged again and refused again: what that judgment counts replaces it.
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        import(&again, &withheld_above(&h, 2), &members, true);
        assert!(!b_counted(&again, &members) && !d_counted(&again, &members), "carried, while v3 waits");
        assert_eq!(state_of_version(&import(&again, &h, &members, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert!(b_counted(&again, &members) && !d_counted(&again, &members));
        // Taken, now that C's admission of the newcomer is held: the head passes
        // v3, and what it carried goes with its wait.
        set_stored_pins(&store, &pins);
        let with_ghost: Vec<RecordMember> = members.iter().cloned().chain([with(ghost.member(), |m| m.statements = vec![c.admit(&ghost, 2)])]).collect();
        let again = restarted(&store);
        assert!(!b_counted(&again, &with_ghost));
        assert_eq!(state_of_version(&import(&again, &h, &with_ghost, true), 3), (Accepted, RecordProblem::None));
        assert!(again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].carried.is_empty());
        assert!(b_counted(&again, &with_ghost) && !d_counted(&again, &with_ghost));
    }

    #[test]
    fn the_roles_a_version_passed_over_moved_still_count_after_a_restart() {
        use ChainRole::{Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: the owner makes admin C a plain member and includes
        // a member nobody confirms. Refused only for R2: its
        // roles move.
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Member), (&d, Included, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let (device, store) = stored_device(&a, &up_to(&h, 2), &members);
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        give(&device, &h, 3);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Member));
        let again = restarted(&store);
        import(&again, &withheld_above(&h, 2), &members, true);
        assert_eq!(again.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Member), "while v3 waits");
        assert_eq!(again.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
    }

    #[test]
    fn a_version_passed_over_is_stored_with_a_wait_and_read_fail_closed() {
        let (_a, _b, _c, d, _ghost, h, members, _owner, store) = an_ejection_passed_over();
        let chain3 = h.records[&3].0.chain();
        let (wait_key, carried_key) = (format!("{WAIT_PREFIX}{CIRCLE}:3"), format!("{CARRIED_PREFIX}{CIRCLE}:3"));
        let pins = stored_pins(&store);
        assert_eq!(pins[&wait_key].sharing_pubkey_hex, hex::encode(chain3), "an older SDK reading this store waits at v3 too");
        let carried = &pins[&carried_key];
        assert_eq!((carried.sharing_pubkey_hex.as_str(), carried.first_pinned_at, carried.last_verified_at), (hex::encode(chain3).as_str(), 3, 1));
        let d_counted = |device: &CryptoManager| {
            let e = eligible(device, &members, &d, EligibilityPurpose::Include);
            !e.eligible && e.removed_at_version == Some(3)
        };
        let chain_of = |device: &CryptoManager| {
            let chains = device.refresh.read().unwrap();
            (chains[&CircleKey::of(CIRCLE)].waiting.clone(), chains[&CircleKey::of(CIRCLE)].carried.keys().copied().collect::<Vec<u32>>(), chains[&CircleKey::of(CIRCLE)].forked)
        };
        let restarted_with = |edit: &dyn Fn(&mut HashMap<String, PinRecord>)| {
            let mut edited = pins.clone();
            edit(&mut edited);
            set_stored_pins(&store, &edited);
            let device = restarted(&store);
            (device, edited)
        };
        // Its wait dropped (by an older SDK): v3 still waits, and D's ejection counts.
        let (device, _) = restarted_with(&|p| {
            p.remove(&wait_key);
        });
        assert_eq!(chain_of(&device), (BTreeMap::from([(3, chain3)]), vec![3], false));
        import(&device, &withheld_above(&h, 2), &members, true);
        assert!(d_counted(&device));
        // Another record kept waiting at v3: that wait stays, and D's ejection still counts.
        let (device, _) = restarted_with(&|p| p.get_mut(&wait_key).unwrap().sharing_pubkey_hex = hex::encode([0x77u8; 32]));
        assert_eq!(chain_of(&device), (BTreeMap::from([(3, [0x77u8; 32])]), vec![3], false));
        import(&device, &withheld_above(&h, 2), &members, true);
        assert!(d_counted(&device));
        // At or below the head it was decided: dropped, no wait.
        let (device, _) = restarted_with(&|p| {
            let mut moved = p.remove(&carried_key).unwrap();
            moved.first_pinned_at = 2;
            p.insert(format!("{CARRIED_PREFIX}{CIRCLE}:2"), moved);
            p.remove(&wait_key);
        });
        assert_eq!(chain_of(&device), (BTreeMap::new(), vec![], false));
        // One that doesn't read: the circle waits, latched, and its entries go back as stored.
        for garbled in ["zz", "0100", "", "00000000ff"] {
            let (device, edited) = restarted_with(&|p| p.get_mut(&carried_key).unwrap().signing_pubkey_hex = garbled.into());
            assert!(chain_of(&device).2, "{garbled:?}");
            device.persist_keys().unwrap();
            let after = stored_pins(&store);
            let json = |p: &PinRecord| serde_json::to_value(p).unwrap();
            assert!(edited.iter().filter(|(k, _)| k.starts_with("~rr")).all(|(k, v)| after.get(k).map(json) == Some(json(v))), "{garbled:?}");
        }
        let (device, _) = restarted_with(&|p| p.get_mut(&carried_key).unwrap().last_verified_at = 2);
        assert!(chain_of(&device).2, "a format this SDK doesn't know");
    }

    // ------------------------------------------------------------------
    // Behind is this device's own knowledge, not the server's list
    // ------------------------------------------------------------------

    #[test]
    fn behind_while_a_version_above_the_head_waits_whatever_the_server_lists() {
        // The server spoils the owner's eject of D (v3 waits here)
        // and lists the circle at v2: the version sealed under
        // stays v2 (an SOS alert still seals under it), and the
        // device is behind.
        let (a, b, c, _d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let store = MemStore::default();
        let device = b.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        give(&device, &h, 2);
        import(&device, &h, &members, true);
        assert!(!device.is_behind(CIRCLE.into()));
        give(&device, &real, 3);
        assert_eq!(state_of_version(&import(&device, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
        assert!(device.is_behind(CIRCLE.into()));
        assert_eq!(device.get_active_version(CIRCLE.into()).ok(), Some(2));
        // After a restart, before any import and with v3 withheld: behind.
        device.persist_keys().unwrap();
        let again = restarted(&store);
        assert!(again.is_behind(CIRCLE.into()), "its kept wait, before any import");
        import(&again, &h, &members, true);
        assert!(again.is_behind(CIRCLE.into()));
        // A record missing under a served one waits too.
        let mut gap = real.clone();
        let v4 = rows(&gap, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin)]);
        gap.rotate(RecordKind::Rotation, &a, v4, None);
        let (fresh, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&fresh, &gap, 4);
        let mut only_v4 = gap.clone();
        only_v4.records.remove(&3);
        assert_eq!(state_of_version(&import(&fresh, &only_v4, &members, true), 4), (Waiting, RecordProblem::RecordMissing));
        assert!(fresh.is_behind(CIRCLE.into()));
        // The eject, served well, ends it.
        assert_eq!(state_of_version(&import(&again, &real, &members, true), 3).0, Accepted);
        assert!(!again.is_behind(CIRCLE.into()));
    }

    #[test]
    fn behind_while_a_version_passed_over_is_kept_until_a_rotation_of_its_own_or_the_repair() {
        use RecordMemberState as S;
        let (a, b, c, d, ghost, h, members, owner, store) = an_ejection_passed_over();
        // Passed over in this process (R2): behind; the version sealed under stays v2.
        assert!(owner.is_behind(CIRCLE.into()));
        assert_eq!(owner.get_active_version(CIRCLE.into()).ok(), Some(2));
        // After a restart, v3 withheld: behind.
        let again = restarted(&store);
        assert!(again.is_behind(CIRCLE.into()));
        import(&again, &withheld_above(&h, 2), &members, true);
        assert!(again.is_behind(CIRCLE.into()));
        // Served again, and repaired: its own rotation (v4, not served back yet)
        // is what it seals under, and v3 below it no longer makes it behind.
        import(&again, &h, &members, true);
        assert!(again.is_behind(CIRCLE.into()));
        let repair = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None), (&ghost, S::Departed, None)]);
        let bundle = again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &repair, &members, true, "n", NOW).unwrap();
        assert!(!again.is_behind(CIRCLE.into()));
        assert_eq!(again.get_active_version(CIRCLE.into()).ok(), Some(4));
        // Served back and taken: not behind.
        let (records, links) = served_with(&h, &bundle);
        assert_eq!(state_of_version(&again.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap(), 4).0, Accepted);
        assert!(!again.is_behind(CIRCLE.into()));
        // A device that can't repair stays behind until the repair comes.
        let (other, _) = device_at(&b, &a, &up_to(&h, 2), &members, &[2]);
        give(&other, &h, 3);
        assert_eq!(state_of_version(&import(&other, &h, &members, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert!(other.is_behind(CIRCLE.into()));
        assert!(other.add_verified_key(CIRCLE, 4, &open_wrap(&b, &bundle.rotation)));
        assert_eq!(state_of_version(&other.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap(), 4).0, Accepted);
        assert!(!other.is_behind(CIRCLE.into()));
    }

    #[test]
    fn behind_on_a_fork_on_records_none_taken_and_while_the_key_store_cant_be_read() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // No records here: not behind, and an unknown circle neither.
        let legacy = a.device();
        give(&legacy, &h, 1);
        give(&legacy, &h, 2);
        assert!(!legacy.is_behind(CIRCLE.into()) && !legacy.is_behind("3b0000ad-0000-4000-8000-00000000ffff".into()));
        // A head proves records exist, and none is taken here: behind.
        legacy.note_circle_has_records(CIRCLE.into());
        assert!(legacy.is_behind(CIRCLE.into()));
        // A fork: behind.
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        assert!(!device.is_behind(CIRCLE.into()));
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &[contradicting_head(&b)], NOW).unwrap();
        assert!(report.forked && device.is_behind(CIRCLE.into()));
        // A key store that can't be read: behind, until it reads.
        let store = MemStore::default();
        let first = a.device();
        first.register_secure_storage(Box::new(store.clone()));
        first.persist_keys().unwrap();
        let good = stored(&store).pinned_keys_json;
        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = Some("{\"cut short".into());
        let unread = a.device();
        unread.register_secure_storage(Box::new(store.clone()));
        assert!(unread.load_persisted_keys().is_err());
        assert!(unread.is_behind(CIRCLE.into()));
        store.0.lock().unwrap().as_mut().unwrap().pinned_keys_json = good;
        assert!(unread.load_persisted_keys().unwrap());
        assert!(!unread.is_behind(CIRCLE.into()));
    }

    // ------------------------------------------------------------------
    // The eject-revival rule: an ejected member comes back only by an
    // admission or invitation made after the removal
    // ------------------------------------------------------------------

    /// The owner A, admin C, members B and X at v2; the owner ejects X at v3.
    fn with_x_ejected() -> (Acct, Acct, Acct, Acct, History) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        (a, b, c, x, h)
    }

    /// Everyone listed and confirmed, X with only its old invitation.
    fn listed_with_x(a: &Acct, b: &Acct, c: &Acct, x: &Acct, x_statements: Vec<HeldStatement>) -> Vec<RecordMember> {
        vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(b.member(), |m| m.statements = vec![a.invite(b, 1)]),
            with(c.member(), |m| {
                m.statements = vec![a.invite(c, 1)];
                m.listed_role = Some(CircleRole::Admin);
            }),
            with(x.member(), |m| {
                m.statements = x_statements;
                m.server_says_keyless = true;
            }),
        ]
    }

    #[test]
    fn an_ejected_member_named_departed_later_stays_out() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, x, mut h) = with_x_ejected();
        // v4: plain member B names X "departed", with X's last commitment.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Departed, Member)]);
        h.rotate(RecordKind::Rotation, &b, v4, None);
        // The server lists X again.
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None), "not refused");
        let first = Acct::new(0x71).device();
        give(&first, &h, 4);
        import(&first, &h, &members, true);
        for device in [&owner, &first] {
            assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None, "not counted");
            let e = eligible(device, &members, &x, EligibilityPurpose::Include);
            assert!(!e.eligible && e.removed_by_owner_or_admin, "{e:?}");
            assert!(!eligible(device, &members, &x, EligibilityPurpose::Deliver).eligible);
        }
        // Never given a key: the owner's next rotation can't include X.
        let with_x = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&x, S::Included, None)]);
        assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &with_x, &members, true, "n", NOW).is_err());
        let without_x = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &without_x, &members, true, "n", NOW).unwrap();
        assert!(bundle.rotation.member_keys.iter().all(|k| k.user_id != x.uid));
        // A new admission after the removal is still what brings X back.
        let admitted = listed_with_x(&a, &b, &c, &x, vec![a.admit(&x, 4)]);
        assert_eq!(eligible(&owner, &admitted, &x, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
    }

    #[test]
    fn a_plain_members_repair_keeps_an_admins_counting_removal() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: admin C ejects D and includes a member nobody confirms (R2 refuses it).
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        // v4: plain member B's repair leaves D out.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &b, v4, Some(3));
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        let first = Acct::new(0x71).device();
        give(&first, &h, 4);
        import(&first, &h, &members, true);
        for device in [&owner, &first] {
            assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), None, "D is removed after the repair");
            let e = eligible(device, &members, &d, EligibilityPurpose::Include);
            assert!(!e.eligible && e.removed_by_owner_or_admin, "{e:?}");
            assert!(!eligible(device, &members, &d, EligibilityPurpose::Deliver).eligible);
            assert_eq!(device.chain_role(CIRCLE.into(), b.uid.clone()), Some(CircleRole::Member));
        }
    }

    #[test]
    fn a_first_device_refuses_what_every_judging_device_refused() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let everyone = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, everyone(&h), None);
        // v3: plain member B "removes" the owner (refused on every device);
        // v4: admin C's repair.
        let v3 = rows(&h, &[(&a, Removed, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        h.rotate(RecordKind::Repair, &c, everyone(&h), Some(3));
        // v5: the owner ejects X; v6: B, fooled, includes X again (R2 refuses
        // it); v7: the owner's repair.
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v5, None);
        h.rotate(RecordKind::Rotation, &b, everyone(&h), None);
        h.rotate(RecordKind::Repair, &a, v5_again(&h, &a, &b, &c, &x), Some(6));
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (judging, report) = device_at(&a, &a, &h, &members, &[2, 3, 4, 5, 6, 7]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Removal));
        assert_eq!(state_of_version(&report, 6), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(state_of_version(&report, 7).0, Accepted);
        // The first device sees it all at once: it refuses v3 and v6 too.
        let first = Acct::new(0x71).device();
        give(&first, &h, 7);
        let report = import(&first, &h, &members, true);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Removal));
        assert_eq!(state_of_version(&report, 6), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(state_of_version(&report, 7).0, Accepted);
        for device in [&judging, &first] {
            assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
            assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None);
            assert!(!eligible(device, &members, &x, EligibilityPurpose::Include).eligible);
        }
        assert_eq!(first.get_active_version(CIRCLE.into()).unwrap(), 7);
        // Never sealing under a version refused here: holding v6's key but not v7's.
        let behind = Acct::new(0x74).device();
        give(&behind, &h, 6);
        import(&behind, &h, &members, true);
        assert_eq!(behind.get_active_version(CIRCLE.into()).unwrap(), 5);
        // Up to v6 only: without an admission after the removal, v6 is refused
        // and the head stays at v5; with one, v6 is taken and X counts.
        let mut to_six = h.clone();
        to_six.records.retain(|v, _| *v <= 6);
        let without = Acct::new(0x72).device();
        give(&without, &h, 6);
        let report = import(&without, &to_six, &members, true);
        assert_eq!(state_of_version(&report, 6), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(without.chain_role(CIRCLE.into(), x.uid.clone()), None);
        assert_eq!(without.get_active_version(CIRCLE.into()).unwrap(), 5, "never under the refused v6");
        let admitted = listed_with_x(&a, &b, &c, &x, vec![a.admit(&x, 5)]);
        let with = Acct::new(0x73).device();
        give(&with, &h, 6);
        let report = import(&with, &to_six, &admitted, true);
        assert_eq!(state_of_version(&report, 6).0, Accepted);
        assert_eq!(with.chain_role(CIRCLE.into(), x.uid.clone()), Some(CircleRole::Member));
    }

    /// v7 of the test above: the owner's repair of v6, keeping X removed.
    fn v5_again(h: &History, a: &Acct, b: &Acct, c: &Acct, x: &Acct) -> Vec<RecordEntry> {
        use ChainRole::{Admin, Member, Owner};
        rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (x, Removed, Member)])
    }

    #[test]
    fn a_repair_that_includes_the_removed_member_again_is_their_later_word() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        // v3: admin C ejects D and includes a ghost (R2 refuses it); v4: the
        // owner's repair includes D again, on an admission made after v3.
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        let mut members = four_members(&a, &b, &c, &d);
        members[3].statements = vec![a.admit(&d, 3)];
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(owner.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member));
        assert_eq!(eligible(&owner, &members, &d, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain));
    }

    #[test]
    fn a_first_device_keeps_the_counting_removals_of_a_record_it_refuses() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, mut h) = with_x_ejected();
        // v4: admin C includes the ejected X again (no admission after the
        // removal) and ejects B; v5: the owner's repair leaves B out.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Removed, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let v5 = rows(&h, &[(&a, Included, Owner), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Repair, &a, v5, Some(4));
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (judging, report) = device_at(&a, &a, &h, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        let first = Acct::new(0x71).device();
        give(&first, &h, 5);
        let report = import(&first, &h, &members, true);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        for device in [&judging, &first] {
            assert_eq!(device.chain_role(CIRCLE.into(), b.uid.clone()), None, "C's ejection of B counts");
            assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None);
            assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        }
    }

    #[test]
    fn a_first_device_checks_a_re_inclusion_against_the_records_it_refused() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, mut h) = with_x_ejected();
        // v4: admin C ejects B and includes the ejected X (refused: X has no
        // admission after its removal); v5: the owner's repair includes B
        // again, with no admission after C's ejection either (refused too).
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Removed, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Repair, &a, v5, Some(4));
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (judging, report) = device_at(&a, &a, &h, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::R2NotAllowed));
        let first = Acct::new(0x71).device();
        give(&first, &h, 5);
        let report = import(&first, &h, &members, true);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::R2NotAllowed));
        for device in [&judging, &first] {
            assert_eq!(device.refresh_head_versions().get(CIRCLE).copied(), Some(3));
            assert!(!eligible(device, &members, &b, EligibilityPurpose::Include).eligible, "C's ejection of B counts");
        }
    }

    #[test]
    fn member_pins_come_back_unchanged_and_no_reserved_entry_comes_in_with_them() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = stored_device(&a, &h, &members);
        for who in [&b, &d] {
            device
                .pin_member_keys(CIRCLE.into(), who.uid.clone(), hex::encode(who.sharing_pk()), hex::encode(who.signing_pk()))
                .unwrap();
        }
        unsigned_first_contact(&device, &a, "f0f0f0f0-2222-4333-8444-555555555555", 1, &[0x31; 32]).unwrap();
        let exported = device.export_member_pins(a.uid.clone()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&exported).unwrap();
        let pins = parsed["pins"].as_object().unwrap().clone();
        let identity = parsed["identity_pins"].as_object().unwrap().clone();
        assert_eq!((pins.len(), identity.len()), (2, 2));
        assert!(pins.keys().all(|k| !k.starts_with('~') && !k.starts_with("*:")), "no reserved entry is exported");
        // A same-account sign-out: export, clear, sign back in, import.
        device.clear_all_keys();
        device.import_private_key(b64.encode(a.sharing.to_bytes())).unwrap();
        device.import_signing_private_key(b64.encode(a.signing.to_bytes())).unwrap();
        assert_eq!(device.import_member_pins(a.uid.clone(), exported.clone()).unwrap(), 4);
        let again: serde_json::Value = serde_json::from_str(&device.export_member_pins(a.uid.clone()).unwrap()).unwrap();
        assert_eq!(again["pins"].as_object().unwrap(), &pins, "circle pins unchanged");
        assert_eq!(again["identity_pins"].as_object().unwrap(), &identity, "identity pins unchanged");
        // Every reserved entry planted in an export is refused, well-formed or not.
        let record = serde_json::json!({
            "sharing_pubkey_hex": hex::encode([0x11u8; 32]),
            "signing_pubkey_hex": hex::encode([0x22u8; 32]),
            "first_pinned_at": 3,
            "last_verified_at": 2,
            "user_approved_change_at": 1
        });
        let planted = [
            format!("~ctrust:{CIRCLE}:3"),
            format!("~trust:{}", hex::encode([0x33u8; 32])),
            format!("~prev:{CIRCLE}:2"),
            "~adopted:personal".to_string(),
            format!("{HEAD_PREFIX}{CIRCLE}"),
            format!("{FACT_PREFIX}{CIRCLE}:{}", hex::encode([0x11u8; 32])),
            format!("{ANCHOR_PREFIX}{CIRCLE}"),
            format!("{SECRET_PREFIX}{CIRCLE}"),
            format!("{HISTORY_PREFIX}{CIRCLE}:3"),
            format!("~rot:{CIRCLE}"),
            format!("*:{}", b.uid),
        ];
        let mut planted_pins = serde_json::Map::new();
        for key in &planted {
            planted_pins.insert(key.clone(), record.clone());
        }
        let export = serde_json::json!({
            "format": "pingolin.member_pins.v1",
            "owner_user_id": a.uid,
            "pins": planted_pins,
            "identity_pins": {}
        });
        assert_eq!(device.import_member_pins(a.uid.clone(), export.to_string()).unwrap(), 0);
        // ... and is no mark after a restart either.
        let restarted = restarted(&store);
        restarted.persist_keys().unwrap();
        let blob: HashMap<String, PinRecord> = serde_json::from_str(&stored(&store).pinned_keys_json.unwrap()).unwrap();
        for key in &planted {
            match blob.get(key) {
                // B's own identity pin, from the genuine import: never the planted record.
                Some(pin) if key.starts_with("*:") => assert_eq!(pin.sharing_pubkey_hex, hex::encode(b.sharing_pk()), "{key} replaced"),
                found => assert!(found.is_none(), "{key} came in"),
            }
        }
        assert!(!restarted.circle_has_refresh_records(CIRCLE.into()));
        assert!(restarted.refresh_head_versions().is_empty());
        let again: serde_json::Value = serde_json::from_str(&restarted.export_member_pins(a.uid.clone()).unwrap()).unwrap();
        assert_eq!(again["pins"].as_object().unwrap(), &pins);
    }

    // ------------------------------------------------------------------
    // Forks and how they settle (a removal beats its target)
    // ------------------------------------------------------------------

    /// The real chain: v2 with A (owner), B, C (admin) and X; v3, A ejects X.
    /// The insider fork: X's own v3 (under another key), including everyone.
    fn real_and_fork() -> (Acct, Acct, Acct, Acct, History, History) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, real) = with_x_ejected();
        let mut fork = real.clone();
        fork.records.remove(&3);
        fork.links.retain(|l| l.from_version != 3);
        fork.keys.insert(3, [0x3f; 32]);
        let v3 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        fork.rotate(RecordKind::Rotation, &x, v3, None);
        (a, b, c, x, real, fork)
    }

    fn owners_head(a: &Acct, h: &History, version: u32) -> MemberHead {
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version, chain: h.records[&version].0.chain() };
        let bytes = head.encode().unwrap();
        MemberHead {
            user_id: a.uid.clone(),
            head: SignedCircleHead {
                head_hex: hex::encode(bytes),
                signature_hex: hex::encode(a.signing.sign(&Head::digest(&bytes)).to_bytes()),
            },
        }
    }

    #[test]
    fn fork_an_insider_fork_is_taken_then_the_real_side_stands_once_served() {
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        // B's device never saw the eject: it takes X's v3, as
        // nothing it holds contradicts it.
        let mut before = real.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        give(&device, &fork, 3);
        let report = import(&device, &fork, &members, true);
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None), "taken: nothing this device holds contradicts it");
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        // The owner's head on the real chain: the conflict is seen, and the circle waits.
        let heads = [owners_head(&a, &real, 3)];
        let report = device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &members, true, None, &heads, NOW).unwrap();
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing is sealed");
        assert_eq!(device.refresh_head_versions().get(CIRCLE), Some(&0), "a forked circle asks for the whole chain");
        // The real chain, served whole: it removed the fork's signer, so it stands.
        let report = import(&device, &real, &members, true);
        assert!(!report.forked);
        assert!(report.ask_for_fresh_copy, "a fresh copy of the real key");
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        assert!(device.held_keys(CIRCLE).iter().all(|(v, _)| *v != 3), "the fork's key is dropped");
        assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None, "X is out");
        assert!(!eligible(&device, &members, &x, EligibilityPurpose::Deliver).eligible);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2, "never under the fork's key");
        // A fresh, right copy of the real key 3: sealed under.
        own_copy(&device, &b, 3, &real.keys[&3]).unwrap();
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        // The fork's key is refused from now on.
        assert!(own_copy(&device, &b, 3, &fork.keys[&3]).is_err());
    }

    #[test]
    fn fork_this_devices_side_stands_against_the_removed_members_fork() {
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (device, report) = device_at(&c, &a, &real, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        // The server serves X's fork whole: this device's side removed X.
        let report = import(&device, &fork, &members, true);
        assert!(!report.forked);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Fork));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 3 && k.as_slice() == real.keys[&3]));
        assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None);
    }

    #[test]
    fn fork_neither_side_removes_the_other_and_the_circle_waits() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let same_rows = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let mut one = h.clone();
        one.rotate(RecordKind::Rotation, &a, same_rows(&h), None);
        let mut two = h.clone();
        two.keys.insert(3, [0x3e; 32]);
        two.rotate(RecordKind::Rotation, &c, same_rows(&h), None);
        let (device, _) = device_at(&b, &a, &one, &members, &[2, 3]);
        let report = import(&device, &two, &members, true);
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err());
        // Still waiting on the next import of either side.
        assert!(import(&device, &one, &members, true).forked);
        assert!(import(&device, &two, &members, true).forked);
    }

    #[test]
    fn fork_a_rogue_record_removing_the_real_sides_signer_loses_in_one_import() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        // X "removes" the owner in its own v3: refused on every device.
        let mut rogue = h.clone();
        rogue.keys.insert(3, [0x3d; 32]);
        let v3 = rows(&rogue, &[(&a, Removed, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        rogue.rotate(RecordKind::Rotation, &x, v3, None);
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        for rogue_first in [true, false] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            give(&device, &real, 3);
            let mut records = if rogue_first { rogue.signed() } else { real.signed() };
            records.extend(if rogue_first { real.signed() } else { rogue.signed() });
            let mut links = real.links.clone();
            links.extend(rogue.links.iter().filter(|l| l.from_version == 3).cloned());
            let report = device.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
            assert!(!report.forked, "rogue first: {rogue_first}");
            assert!(report.versions.iter().any(|r| r.version == 3 && r.state == Rejected && r.problem == RecordProblem::Removal));
            assert!(report.versions.iter().any(|r| r.version == 3 && r.state == Accepted));
            assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
            assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
            assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None);
        }
    }

    #[test]
    fn fork_settles_after_a_restart_from_the_stored_history() {
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let store = MemStore::default();
        let device = b.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &fork, 1);
        let mut genesis_only = History::genesis(&a);
        genesis_only.links.clear();
        import(&device, &genesis_only, &members, true);
        for v in [2, 3] {
            give(&device, &fork, v);
        }
        assert_eq!(state_of_version(&import(&device, &fork, &members, true), 3).0, Accepted);
        let pins: HashMap<String, PinRecord> = serde_json::from_str(&stored(&store).pinned_keys_json.unwrap()).unwrap();
        let history = |kept: bool| pins.keys().filter(|k| k.starts_with(HISTORY_PREFIX) && k.ends_with(KEPT_TAG_SUFFIX) == kept).count();
        assert_eq!(history(false), 3, "v1..v3 of its chain");
        assert_eq!(history(true), 3, "each with its tag kept: all three vouched here");
        // Restarted: the server serves the real chain whole. The stored
        // history finds the fork at v3 and its signer, X, whom the real side removed.
        let restarted = restarted(&store);
        let report = import(&restarted, &real, &members, true);
        assert!(!report.forked && report.ask_for_fresh_copy);
        assert_eq!(restarted.chain_role(CIRCLE.into(), x.uid.clone()), None);
        assert!(restarted.held_keys(CIRCLE).iter().all(|(v, _)| *v != 3));
        assert_eq!(restarted.refresh_head_versions().get(CIRCLE), Some(&3));
    }

    #[test]
    fn a_history_entry_names_its_own_version() {
        let key = |v: &str| format!("{HISTORY_PREFIX}{CIRCLE}:{v}");
        let record = |at: i64| PinRecord {
            sharing_pubkey_hex: hex::encode([1u8; 32]),
            signing_pubkey_hex: hex::encode([2u8; 32]),
            first_pinned_at: at,
            last_verified_at: 0,
            user_approved_change_at: None,
        };
        for (name, at, kept) in [("3", 3, true), ("3", 4, false), ("0", 0, false), ("x", 3, false), ("", 3, false)] {
            let mut chains = HashMap::new();
            assert_eq!(absorb_persisted(&mut chains, &key(name), &record(at)), kept, "read: {name} at {at}");
            assert_eq!(chains.get(&CircleKey::of(CIRCLE)).map_or(false, |c| !c.history.is_empty()), kept, "{name} at {at}");
        }
        let mut chains = HashMap::new();
        assert!(!absorb_persisted(&mut chains, &key("3"), &PinRecord { sharing_pubkey_hex: "zz".into(), ..record(3) }));
        assert!(chains.get(&CircleKey::of(CIRCLE)).map_or(true, |c| c.history.is_empty()));
    }

    #[test]
    fn fork_the_eject_beats_the_insiders_record_in_one_import() {
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let mut before = real.clone();
        before.records.retain(|v, _| *v <= 2);
        for insider_first in [true, false] {
            let (device, _) = device_at(&b, &a, &before, &members, &[2]);
            give(&device, &real, 3);
            // Both pass every device's hard checks; the owner's removes X, the other's signer.
            let mut records = if insider_first { fork.signed() } else { real.signed() };
            records.extend(if insider_first { real.signed() } else { fork.signed() });
            let mut links = real.links.clone();
            links.extend(fork.links.iter().filter(|l| l.from_version == 3).cloned());
            let report = device.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
            assert!(!report.forked, "insider first: {insider_first}");
            assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
            assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None);
        }
    }

    #[test]
    fn fork_the_standing_sides_records_are_judged_with_r2_and_a_lost_own_rotation_goes() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, x, mut real, fork) = real_and_fork();
        // The real v3 also includes someone nobody here confirms.
        let ghost = Acct::new(0x66);
        real.records.remove(&3);
        real.links.retain(|l| l.from_version != 3);
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member), (&ghost, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let store = MemStore::default();
        let mut before = real.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &fork, 3);
        assert_eq!(state_of_version(&import(&device, &fork, &members, true), 3).0, Accepted);
        // B's own rotation on the fork, unconfirmed.
        let bundle = device
            .prepare_recorded_rotation_at(
                CIRCLE, &b.uid, RefreshRecordKind::Rotation,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&x, S::Included, None)]),
                &members, true, "n", NOW,
            )
            .unwrap();
        assert_eq!(bundle.rotation.new_key_version, 4);
        let rotation_marker = |store: &MemStore| {
            let pins: HashMap<String, PinRecord> = serde_json::from_str(&stored(store).pinned_keys_json.unwrap()).unwrap();
            pins.contains_key(&format!("~rot:{CIRCLE}"))
        };
        assert!(rotation_marker(&store));
        let heads = [owners_head(&a, &real, 3)];
        assert!(device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &members, true, None, &heads, NOW).unwrap().forked);
        // The real side stands (it removed X), and its v3 is judged here as
        // any device judges it: R2 refuses the member nobody confirms.
        let report = import(&device, &real, &members, true);
        assert!(!report.forked && report.ask_for_fresh_copy);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert!(!eligible(&device, &members, &x, EligibilityPurpose::Include).eligible, "X's removal counts");
        // B's own v4 on the losing side is dropped, with its marker.
        assert!(device.held_keys(CIRCLE).iter().all(|(v, _)| *v < 3));
        assert!(!rotation_marker(&store));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    #[test]
    fn fork_a_removal_before_the_fork_settles_nothing() {
        use ChainRole::{Admin, Member, Owner};
        // X is ejected at v3 on both sides. On this device's side, X signs a v4
        // (refused: X is out) and the owner repairs it at v5; the other side's
        // v4 is the admin's, and names X no more. X's removal is older than the
        // fork: it settles nothing.
        let (a, b, c, x, h) = with_x_ejected();
        let everyone_but_x = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        let mut ours = h.clone();
        let v4 = rows(&ours, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        ours.rotate(RecordKind::Rotation, &x, v4, None);
        ours.rotate(RecordKind::Repair, &a, everyone_but_x(&ours), Some(4));
        // The admin's v4 leaves X out (X's last word stays v3's removal).
        let mut theirs = h.clone();
        theirs.keys.insert(4, [0x4d; 32]);
        let v4 = rows(&theirs, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        theirs.rotate(RecordKind::Rotation, &c, v4, None);
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (device, report) = device_at(&b, &a, &ours, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 4).0, Rejected);
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        let report = import(&device, &theirs, &members, true);
        assert!(report.forked, "neither side removed the other's signer at the fork or later: {:?}", report.versions);
        assert!(device.get_active_version(CIRCLE.into()).is_err());
    }

    #[test]
    fn fork_another_first_record_never_settles() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1));
        let members = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            b.member(),
            with(c.member(), |m| m.listed_role = Some(CircleRole::Admin)),
        ];
        // This device's chain: A's transition at v5 (over the legacy key 4).
        let owner = legacy_device(&a, 4);
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Transition,
                &plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member)), (&c, S::Included, Some(CircleRole::Admin))]),
                &members, true, "n", NOW,
            )
            .unwrap();
        let device = legacy_device(&b, 4);
        assert!(device.add_verified_key(CIRCLE, 5, &open_wrap(&b, &bundle.rotation)));
        let report = device
            .import_refresh_records_at(CIRCLE, &[bundle.refresh_record.clone()], &[bundle.rotation.key_chain_link.clone().unwrap()], &members, true, None, &[], NOW)
            .unwrap();
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        // Served: C's own transition over the same key 4 (C owner, A admin),
        // then C removing A. Another first record: a fork that never settles.
        let mut other = History::transition(&c, 5, &[(&c, Included, Owner), (&a, Included, Admin), (&b, Included, Member)]);
        let v6 = rows(&other, &[(&c, Included, Owner), (&a, Removed, Admin), (&b, Included, Member)]);
        other.rotate(RecordKind::Rotation, &c, v6, None);
        let report = import(&device, &other, &members, true);
        assert!(report.forked);
        assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner), "this device keeps its own head");
        assert!(device.get_active_version(CIRCLE.into()).is_err());
    }

    // ------------------------------------------------------------------
    // A rejected record's removal is their last word at its version
    // ------------------------------------------------------------------

    /// v3: admin C ejects D and includes a ghost nobody confirms: R2 refuses it
    /// here, and D's ejection counts at v3.
    fn rejected_ejection() -> (Acct, Acct, Acct, Acct, Acct, History) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        (a, b, c, d, ghost, h)
    }

    /// The owner's repair of v3, including D again.
    fn repair_including_d(h: &mut History, a: &Acct, b: &Acct, c: &Acct, d: &Acct, ghost: &Acct) {
        use ChainRole::{Admin, Member, Owner};
        let v4 = rows(h, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Member), (ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, a, v4, Some(3));
    }

    #[test]
    fn an_admission_from_before_a_rejected_ejection_does_not_bring_them_back() {
        let (a, b, c, d, ghost, mut h) = rejected_ejection();
        let mut members = four_members(&a, &b, &c, &d);
        members[3].statements = vec![a.admit(&d, 2)];
        // Before any repair: not eligible, and a repair can't include D.
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        let e = eligible(&owner, &members, &d, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin, "{e:?}");
        assert_eq!(e.removed_at_version, Some(3));
        assert!(!eligible(&owner, &members, &d, EligibilityPurpose::Deliver).eligible);
        use RecordMemberState as S;
        let with_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None), (&ghost, S::Departed, None)]);
        assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &with_d, &members, true, "n", NOW).is_err());
        // A repair that includes D anyway is refused everywhere.
        repair_including_d(&mut h, &a, &b, &c, &d, &ghost);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(owner.chain_role(CIRCLE.into(), d.uid.clone()), None);
        let first = Acct::new(0x71).device();
        give(&first, &h, 4);
        let report = import(&first, &h, &members, true);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(first.chain_role(CIRCLE.into(), d.uid.clone()), None);
    }

    #[test]
    fn an_invitation_from_before_a_rejected_ejection_counts_neither() {
        let (a, b, c, d, ghost, mut h) = rejected_ejection();
        let mut members = four_members(&a, &b, &c, &d);
        // A fresh invitation, but made at v2: before the ejection.
        members[3].statements = vec![a.invite(&d, 2)];
        members[3].server_says_keyless = true;
        let (owner, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert!(!eligible(&owner, &members, &d, EligibilityPurpose::Include).eligible);
        assert!(!eligible(&owner, &members, &d, EligibilityPurpose::Deliver).eligible);
        repair_including_d(&mut h, &a, &b, &c, &d, &ghost);
        let (_, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2NotAllowed));
        // An invitation made at the ejection's version lets D in; the repair's
        // inclusion is then D's later word.
        members[3].statements = vec![a.invite(&d, 3)];
        let (owner, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(owner.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member));
        assert_eq!(eligible(&owner, &members, &d, EligibilityPurpose::Include).removed_at_version, None);
    }

    #[test]
    fn removed_at_version_is_the_version_e_judges_against() {
        use ChainRole::{Admin, Member, Owner};
        // An accepted eject: the fact's version.
        let (a, b, c, x, h) = with_x_ejected();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (device, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(eligible(&device, &members, &x, EligibilityPurpose::Include).removed_at_version, Some(3));
        assert_eq!(eligible(&device, &members, &b, EligibilityPurpose::Include).removed_at_version, None);
        // Still the removal after an admission made after it: eligible by (b),
        // and the last word stays the removal until a record includes them.
        let admitted = listed_with_x(&a, &b, &c, &x, vec![a.admit(&x, 3)]);
        let e = eligible(&device, &admitted, &x, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis, e.removed_at_version), (true, Some(EligibilityBasis::Admission), Some(3)));
        // A removal in a record rejected here: that record's version, before
        // and after a repair that leaves them out.
        let (a, b, c, d, ghost, mut h) = rejected_ejection();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        give(&device, &h, 4);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 4).0, Accepted);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
        // Someone the chain never named: none.
        let newcomer = Acct::new(0x70);
        let mut with_n = members.clone();
        with_n.push(with(newcomer.member(), |m| m.statements = vec![a.invite(&newcomer, 4)]));
        assert_eq!(eligible(&device, &with_n, &newcomer, EligibilityPurpose::Include).removed_at_version, None);
    }

    #[test]
    fn a_repair_on_an_admission_made_before_the_ejection_is_rejected() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        // v3: admin C ejects D and includes a ghost (R2 refuses it); v4: the
        // owner's repair includes D again, on an admission made BEFORE v3 (at v2).
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        let mut members = four_members(&a, &b, &c, &d);
        members[3].statements = vec![a.admit(&d, 2)];
        let (_, report) = device_at(&a, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 4).0, Rejected, "an admission from before the ejection must not re-include D");
    }

    #[test]
    fn before_any_repair_an_admission_made_before_the_ejection_does_not_make_them_eligible() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let ghost = Acct::new(0x66);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let mut members = four_members(&a, &b, &c, &d);
        members[3].statements = vec![a.admit(&d, 2)];
        let (owner, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        let e = eligible(&owner, &members, &d, EligibilityPurpose::Include);
        assert!(!e.eligible, "an admission from before the ejection must not make D eligible");
    }

    #[test]
    fn a_first_device_judges_a_re_inclusion_at_the_refused_records_version() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, mut h) = with_x_ejected();
        // v4: admin C ejects B and includes the ejected X (refused on every
        // device); v5: the owner's repair includes B again. B holds an admission
        // made at v3: after B's last accepted word, but before C's ejection.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Removed, Member), (&c, Included, Admin), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Member)]);
        h.rotate(RecordKind::Repair, &a, v5, Some(4));
        let mut members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        members[1].statements = vec![a.admit(&b, 3)];
        let (judging, report) = device_at(&a, &a, &h, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::R2NotAllowed));
        let first = Acct::new(0x71).device();
        give(&first, &h, 5);
        let report = import(&first, &h, &members, true);
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::R2NotAllowed));
        for device in [&judging, &first] {
            let e = eligible(device, &members, &b, EligibilityPurpose::Include);
            assert!(!e.eligible, "{e:?}");
            assert_eq!(e.removed_at_version, Some(4));
        }
        // An admission at v4 lets B in, on both.
        members[1].statements = vec![a.admit(&b, 4)];
        let (_, report) = device_at(&a, &a, &h, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        let first = Acct::new(0x72).device();
        give(&first, &h, 5);
        assert_eq!(state_of_version(&import(&first, &h, &members, true), 5).0, Accepted);
    }

    #[test]
    fn a_head_from_a_member_a_rejected_record_removed_is_ignored() {
        let (a, b, c, d, _ghost, h) = rejected_ejection();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        // D, ejected by C's (rejected) v3, publishes a head that contradicts v2.
        let theirs = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: d.uid16(), version: 2, chain: [0x2d; 32] };
        let bytes = theirs.encode().unwrap();
        let heads = [MemberHead {
            user_id: d.uid.clone(),
            head: SignedCircleHead {
                head_hex: hex::encode(bytes),
                signature_hex: hex::encode(d.signing.sign(&Head::digest(&bytes)).to_bytes()),
            },
        }];
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &heads, NOW).unwrap();
        assert!(!report.forked, "D's word no longer counts here");
        // B's same head would be a fork.
        let theirs = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: b.uid16(), version: 2, chain: [0x2d; 32] };
        let bytes = theirs.encode().unwrap();
        let heads = [MemberHead {
            user_id: b.uid.clone(),
            head: SignedCircleHead {
                head_hex: hex::encode(bytes),
                signature_hex: hex::encode(b.signing.sign(&Head::digest(&bytes)).to_bytes()),
            },
        }];
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &heads, NOW).unwrap();
        assert!(report.forked);
    }

    #[test]
    fn a_members_head_is_theirs_under_any_spelling_of_their_id() {
        let (a, b, c, d, _ghost, h) = rejected_ejection();
        let members = four_members(&a, &b, &c, &d);
        // B's head contradicts v2. The server names B in another spelling: it is still B's word.
        let theirs = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: b.uid16(), version: 2, chain: [0x2d; 32] };
        let bytes = theirs.encode().unwrap();
        let head = SignedCircleHead {
            head_hex: hex::encode(bytes),
            signature_hex: hex::encode(b.signing.sign(&Head::digest(&bytes)).to_bytes()),
        };
        let simple = b.uid.replace('-', "");
        for (spelling, forked) in [
            (b.uid.to_ascii_uppercase(), true),
            (simple.clone(), true),
            (format!("{{{}}}", b.uid), true),
            (format!("urn:uuid:{}", b.uid), true),
            // Not a UUID: nobody's head.
            (format!("{simple}0"), false),
        ] {
            let (device, _) = device_at(&a, &a, &h, &members, &[2, 3]);
            let heads = [MemberHead { user_id: spelling.clone(), head: head.clone() }];
            let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &heads, NOW).unwrap();
            assert_eq!(report.forked, forked, "{spelling}");
        }
    }

    #[test]
    fn a_settlement_keeps_what_the_losing_side_removed() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, y, z) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1), Acct::new(0xf1), Acct::new(0x91));
        let mut h = History::genesis(&a);
        let everyone = [(&a, Owner), (&b, Member), (&c, Admin), (&x, Admin), (&y, Member), (&z, Member)];
        let v2: Vec<RecordEntry> = everyone.iter().map(|(who, role)| h.entry(who, Included, *role)).collect();
        h.rotate(RecordKind::Rotation, &a, v2, None);
        // The owner's side: v3 ejects the admin X; v4 keeps everyone else. Y is never removed there.
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Admin), (&y, Included, Member), (&z, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&y, Included, Member), (&z, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v4, None);
        // X's side: X's v3; X ejects Z at v4; admin C ejects Y at v5.
        let mut fork = h.clone();
        for (v, byte) in [(3u32, 0x3au8), (4, 0x4a), (5, 0x5a)] {
            fork.keys.insert(v, [byte; 32]);
        }
        let all: Vec<RecordEntry> = everyone.iter().map(|(who, role)| fork.entry(who, Included, *role)).collect();
        fork.rotate(RecordKind::Rotation, &x, all, None);
        let v4 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&y, Included, Member), (&z, Removed, Member)]);
        fork.rotate(RecordKind::Rotation, &x, v4, None);
        let v5 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&y, Removed, Member)]);
        fork.rotate(RecordKind::Rotation, &c, v5, None);
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let members = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            listed(&b),
            with(listed(&c), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&x), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&y), |m| m.server_says_keyless = true),
            listed(&z),
        ];
        // B's device took X's side.
        let mut before = h.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        for v in [3, 4, 5] {
            give(&device, &fork, v);
        }
        let report = import(&device, &fork, &members, true);
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        let heads = [owners_head(&a, &real, 3)];
        assert!(device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &members, true, None, &heads, NOW).unwrap().forked);
        // The owner's side stands (it removed X). C's ejection of Y stays: the
        // owner's v3, which includes Y, is refused here; X's own ejection of Z
        // is not kept.
        let report = import(&device, &real, &members, true);
        assert!(!report.forked && report.ask_for_fresh_copy);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2NotAllowed));
        let e = eligible(&device, &members, &y, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(5), "{e:?}");
        assert!(!eligible(&device, &members, &y, EligibilityPurpose::Deliver).eligible, "nothing is sealed or handed to Y");
        let e = eligible(&device, &members, &z, EligibilityPurpose::Include);
        assert_eq!((e.basis, e.removed_at_version), (Some(EligibilityBasis::CountedByChain), None), "{e:?}");
        assert_eq!(device.chain_role(CIRCLE.into(), y.uid.clone()), None);
        assert_eq!(device.chain_role(CIRCLE.into(), z.uid.clone()), Some(CircleRole::Member));
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2, "behind: never a version it refused");
        // With an admission for Y made at or after C's ejection, the owner's side's records are taken.
        let mut admitted = members.clone();
        admitted[4].statements.push(c.admit(&y, 5));
        let (device, _) = device_at(&b, &a, &before, &admitted, &[2]);
        for v in [3, 4, 5] {
            give(&device, &fork, v);
        }
        assert_eq!(state_of_version(&import(&device, &fork, &admitted, true), 5).0, Accepted);
        assert!(device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &admitted, true, None, &heads, NOW).unwrap().forked);
        let report = import(&device, &real, &admitted, true);
        assert_eq!(state_of_version(&report, 3).0, Reference);
        assert_eq!(device.chain_role(CIRCLE.into(), y.uid.clone()), Some(CircleRole::Member));
    }

    #[test]
    fn a_removal_by_someone_promoted_after_the_fork_is_not_kept() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, m, y) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0x81), Acct::new(0xf1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&m, Included, Member), (&y, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        // This device's side: the owner A rotates, promotes M, and M (an admin
        // only since v4) ejects Y at v5.
        let mut ours = h.clone();
        let v3 = rows(&ours, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&m, Included, Member), (&y, Included, Member)]);
        ours.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&ours, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&m, Included, Admin), (&y, Included, Member)]);
        ours.rotate(RecordKind::Rotation, &a, v4, None);
        let v5 = rows(&ours, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&m, Included, Admin), (&y, Removed, Member)]);
        ours.rotate(RecordKind::Rotation, &m, v5, None);
        // The other side: admin C, the owner on this device's list,
        // takes the chain by removing A at v3 (the owner claim).
        let mut theirs = h.clone();
        theirs.keys.insert(3, [0x3c; 32]);
        let v3 = rows(&theirs, &[(&a, Removed, Member), (&b, Included, Member), (&c, Included, Owner), (&m, Included, Member), (&y, Included, Member)]);
        theirs.rotate(RecordKind::Rotation, &c, v3, None);
        let listed = |who: &Acct| with(who.member(), |r| r.statements = vec![a.invite(who, 1)]);
        let members = vec![
            with(a.member(), |r| r.listed_role = Some(CircleRole::Admin)),
            listed(&b),
            with(listed(&c), |r| r.listed_role = Some(CircleRole::Owner)),
            listed(&m),
            listed(&y),
        ];
        let (device, report) = device_at(&b, &a, &ours, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        assert_eq!(eligible(&device, &members, &y, EligibilityPurpose::Include).removed_at_version, Some(5));
        // C's side removed A, this side's signer at v3, and this side never
        // removed C: C's side stands. M's ejection of Y is not kept: M was a
        // plain member in the chain before the fork.
        let report = import(&device, &theirs, &members, true);
        assert!(!report.forked && report.ask_for_fresh_copy);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None), "this side's key 3 is dropped");
        own_copy(&device, &b, 3, &theirs.keys[&3]).unwrap();
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Owner));
        assert_eq!(device.chain_role(CIRCLE.into(), y.uid.clone()), Some(CircleRole::Member));
        assert_eq!(eligible(&device, &members, &y, EligibilityPurpose::Include).removed_at_version, None);
    }

    #[test]
    fn a_settlement_keeps_an_ejection_from_a_record_rejected_here_for_another_reason() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, y, z) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1), Acct::new(0xf1), Acct::new(0x91));
        let ghost = Acct::new(0x66);
        let mut h = History::genesis(&a);
        let everyone = [(&a, Owner), (&b, Member), (&c, Admin), (&x, Admin), (&y, Member), (&z, Member)];
        let v2: Vec<RecordEntry> = everyone.iter().map(|(who, role)| h.entry(who, Included, *role)).collect();
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Admin), (&y, Included, Member), (&z, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&y, Included, Member), (&z, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v4, None);
        let mut fork = h.clone();
        for (v, byte) in [(3u32, 0x3au8), (4, 0x4a), (5, 0x5a)] {
            fork.keys.insert(v, [byte; 32]);
        }
        let all: Vec<RecordEntry> = everyone.iter().map(|(who, role)| fork.entry(who, Included, *role)).collect();
        fork.rotate(RecordKind::Rotation, &x, all, None);
        let v4 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&y, Included, Member), (&z, Included, Member)]);
        fork.rotate(RecordKind::Rotation, &x, v4, None);
        // Admin C ejects Y at v5, and v5 also includes someone B can't match: B rejects v5 (R2), and C's ejection counts (the overlay).
        let v5 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&y, Removed, Member), (&z, Included, Member), (&ghost, Included, Member)]);
        fork.rotate(RecordKind::Rotation, &c, v5, None);
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let members = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            listed(&b),
            with(listed(&c), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&x), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&y), |m| m.server_says_keyless = true),
            listed(&z),
        ];
        let mut before = h.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        for v in [3, 4, 5] {
            give(&device, &fork, v);
        }
        import(&device, &fork, &members, true);
        let heads = [owners_head(&a, &real, 3)];
        device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &members, true, None, &heads, NOW).unwrap();
        import(&device, &real, &members, true);
        let e = eligible(&device, &members, &y, EligibilityPurpose::Include);
        assert!(!e.eligible, "C's counting ejection of Y, rejected here for another reason, must be kept by the switch");
    }

    #[test]
    fn a_settlement_keeps_a_removal_from_a_record_this_side_rejected() {
        use ChainRole::{Admin, Member, Owner};
        // C's ejection of Y sits in a v5 that B rejected (it includes a ghost),
        // so only the overlay holds it.
        let (a, b, c, x, y, z) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1), Acct::new(0xf1), Acct::new(0x91));
        let ghost = Acct::new(0x66);
        let mut h = History::genesis(&a);
        let everyone = [(&a, Owner), (&b, Member), (&c, Admin), (&x, Admin), (&y, Member), (&z, Member)];
        let v2: Vec<RecordEntry> = everyone.iter().map(|(who, role)| h.entry(who, Included, *role)).collect();
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Removed, Admin), (&y, Included, Member), (&z, Included, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let mut fork = h.clone();
        for (v, byte) in [(3u32, 0x3au8), (4, 0x4a), (5, 0x5a)] {
            fork.keys.insert(v, [byte; 32]);
        }
        let all: Vec<RecordEntry> = everyone.iter().map(|(who, role)| fork.entry(who, Included, *role)).collect();
        fork.rotate(RecordKind::Rotation, &x, all, None);
        let v4: Vec<RecordEntry> = everyone.iter().map(|(who, role)| fork.entry(who, Included, *role)).collect();
        fork.rotate(RecordKind::Rotation, &x, v4, None);
        // v5: admin C ejects Y; v6, a repair of it by X, ejects Z. B rejects both
        // (each includes the ghost): their ejections are in the overlay only.
        // X's is not kept: X is the signer the owner's side removed.
        fork.keys.insert(6, [0x6a; 32]);
        let v5 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&y, Removed, Member), (&z, Included, Member), (&ghost, Included, Member)]);
        fork.rotate(RecordKind::Rotation, &c, v5, None);
        let v6 = rows(&fork, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&z, Removed, Member), (&ghost, Included, Member)]);
        fork.rotate(RecordKind::Repair, &x, v6, Some(5));
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let members = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            listed(&b),
            with(listed(&c), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&x), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&y), |m| m.server_says_keyless = true),
            listed(&z),
        ];
        let mut before = h.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        for v in [3, 4, 5, 6] {
            give(&device, &fork, v);
        }
        let report = import(&device, &fork, &members, true);
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 6), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(eligible(&device, &members, &y, EligibilityPurpose::Include).removed_at_version, Some(5));
        assert_eq!(eligible(&device, &members, &z, EligibilityPurpose::Include).removed_at_version, Some(6));
        let heads = [owners_head(&a, &real, 3)];
        assert!(device.import_refresh_records_at(CIRCLE, &fork.signed(), &fork.links, &members, true, None, &heads, NOW).unwrap().forked);
        let report = import(&device, &real, &members, true);
        assert!(!report.forked);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2NotAllowed), "the owner's v3 includes Y");
        let e = eligible(&device, &members, &y, EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_at_version == Some(5), "{e:?}");
        assert!(!eligible(&device, &members, &y, EligibilityPurpose::Deliver).eligible);
        assert_eq!(device.chain_role(CIRCLE.into(), y.uid.clone()), None);
        let e = eligible(&device, &members, &z, EligibilityPurpose::Include);
        assert_eq!((e.basis, e.removed_at_version), (Some(EligibilityBasis::CountedByChain), None), "X's ejection of Z is not kept: {e:?}");
    }

    #[test]
    fn a_first_device_reports_each_version_once() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v3: plain member B "removes" D (refused on every device); v4: C's repair.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let first = Acct::new(0x71).device();
        give(&first, &h, 3);
        let report = import(&first, &h, &members, true);
        let rows_for = |v: i32| report.versions.iter().filter(|r| r.version == v).count();
        assert_eq!(rows_for(3), 1, "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Removal));
        assert_eq!(rows_for(2), 1);
        // A repair after it: v3 once, v4 once.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Repair, &c, v4, Some(3));
        let first = Acct::new(0x72).device();
        give(&first, &h, 4);
        let report = import(&first, &h, &members, true);
        let rows_for = |v: i32| report.versions.iter().filter(|r| r.version == v).count();
        assert_eq!((rows_for(3), rows_for(4)), (1, 1), "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 4).0, Accepted);
    }

    /// A web vector file's chain, imported by a first device holding
    /// `held_key`: the web's importer is held to the SDK's refusals.
    fn import_web_chain(text: &str, versions: &[u32], held_key: u32, links: &[(u32, u32)]) -> (Arc<CryptoManager>, RefreshRecordsReport, HashMap<String, String>) {
        let v: HashMap<String, String> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').unwrap())
            .map(|(k, val)| (k.to_string(), val.to_string()))
            .collect();
        let circle = v["circle_id"].clone();
        let member = |n: &str, role: Option<CircleRole>| RecordMember {
            user_id: v[&format!("{n}_user_id")].clone(),
            sharing_public_key_hex: Some(v[&format!("{n}_sharing_pk")].clone()),
            signing_public_key_hex: Some(v[&format!("{n}_signing_pk")].clone()),
            confirmed: true,
            listed: true,
            listed_role: role,
            statements: vec![],
            person_confirmed_keys: false,
            server_says_keyless: false,
        };
        let members = vec![member("A", Some(CircleRole::Owner)), member("B", None), member("C", None)];
        let records: Vec<SignedRefreshRecord> = versions
            .iter()
            .map(|r| SignedRefreshRecord { record_hex: v[&format!("r{r}_record_wire")].clone(), signature_hex: v[&format!("r{r}_signature")].clone() })
            .collect();
        let links: Vec<KeyChainLinkData> = links
            .iter()
            .map(|(from, to)| KeyChainLinkData {
                from_version: *from as i32,
                to_version: *to as i32,
                encrypted_key: v[&format!("link_{from}_{to}_encrypted_key")].clone(),
                nonce: v[&format!("link_{from}_{to}_nonce")].clone(),
            })
            .collect();
        let device = CryptoManager::new();
        assert!(device.add_verified_key(&circle, held_key, &hex::decode(&v[&format!("key_v{held_key}")]).unwrap()));
        let report = device.import_refresh_records_at(&circle, &records, &links, &members, true, None, &[], NOW).unwrap();
        (device, report, v)
    }

    #[test]
    fn the_webs_vector_chains_are_taken_by_a_first_device() {
        // The web's genesis chain: A owner; B admin and C member at r2; admin B
        // removes C at r3.
        let (device, report, v) = import_web_chain(
            include_str!("../tests/data/refresh_record_v1_web.txt"),
            &[1, 2, 3],
            3,
            &[(2, 1), (3, 2)],
        );
        assert!(report.versions.iter().all(|r| r.problem == RecordProblem::None), "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert!(!report.forked);
        assert_eq!(report.sealing_version, Some(3));
        let role = |n: &str| device.chain_role(v["circle_id"].clone(), v[&format!("{n}_user_id")].clone());
        assert_eq!((role("A"), role("B"), role("C")), (Some(CircleRole::Owner), Some(CircleRole::Admin), None));
        // The web's transition chain: r3 by admin B (C pending), r4 by C,
        // linking down to the anchor.
        let (device, report, v) = import_web_chain(
            include_str!("../tests/data/refresh_record_v1_web_transition.txt"),
            &[3, 4],
            4,
            &[(2, 1), (3, 2), (4, 2)],
        );
        // A first device reports the prefix's head; v3, inside it, is its reference.
        assert!(report.versions.iter().all(|r| r.problem == RecordProblem::None), "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert!(!report.forked);
        assert_eq!(report.sealing_version, Some(4));
        let role = |n: &str| device.chain_role(v["circle_id"].clone(), v[&format!("{n}_user_id")].clone());
        assert_eq!((role("A"), role("B"), role("C")), (Some(CircleRole::Owner), Some(CircleRole::Admin), Some(CircleRole::Member)));
    }

    #[test]
    fn the_webs_vector_chains_are_refused_where_the_chain_rules_say() {
        // The web's first genesis chain: r2 carries C as pending, whom no
        // record named before; r3, by B, then changes a role without the
        // right.
        let (device, report, v) = import_web_chain(
            include_str!("../tests/data/refresh_record_v1_web_negative.txt"),
            &[1, 2, 3],
            3,
            &[(2, 1), (3, 2)],
        );
        assert_eq!(state_of_version(&report, 1).0, Accepted);
        assert_eq!(state_of_version(&report, 2), (Rejected, RecordProblem::Structure));
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Role));
        assert_eq!(report.versions.iter().filter(|r| r.version == 2).count(), 1);
        let role = |n: &str| device.chain_role(v["circle_id"].clone(), v[&format!("{n}_user_id")].clone());
        assert_eq!((role("A"), role("B"), role("C")), (Some(CircleRole::Owner), None, None));
        // The web's first transition chain: r4, by A, links down to
        // 2, below A's own floor 3 (A is included at r3).
        let (device, report, v) = import_web_chain(
            include_str!("../tests/data/refresh_record_v1_web_transition_negative.txt"),
            &[3, 4],
            4,
            &[(2, 1), (3, 2), (4, 2)],
        );
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::Floor));
        let role = |n: &str| device.chain_role(v["circle_id"].clone(), v[&format!("{n}_user_id")].clone());
        assert_eq!((role("A"), role("B"), role("C")), (Some(CircleRole::Owner), Some(CircleRole::Admin), Some(CircleRole::Member)));
    }

    // ------------------------------------------------------------------
    // Records the web client's builder made (refresh_record.rs checks
    // every value and pins the files): imported by the devices each file's
    // header names, as the web's own browsers import them, at the file's
    // own `now`.
    // ------------------------------------------------------------------

    /// A web-built vector file's values.
    struct WebBuilt(HashMap<String, String>);

    impl WebBuilt {
        fn new(text: &str) -> Self {
            WebBuilt(
                text.lines()
                    .filter(|l| !l.starts_with('#') && !l.is_empty())
                    .map(|l| l.split_once('=').unwrap())
                    .map(|(k, val)| (k.to_string(), val.to_string()))
                    .collect(),
            )
        }
        /// A copy with one byte of `name`'s value flipped.
        fn flipped(&self, name: &str, at: usize) -> WebBuilt {
            let mut bytes = hex::decode(&self.0[name]).unwrap();
            bytes[at] ^= 0x01;
            let mut copy = WebBuilt(self.0.clone());
            copy.0.insert(name.to_string(), hex::encode(bytes));
            copy
        }
        fn circle(&self) -> String {
            self.0["circle_id"].clone()
        }
        /// The clock every import and E check runs at: the invitations in the
        /// file are fresh then, whatever the date.
        fn now(&self) -> i64 {
            self.0["now"].parse().unwrap()
        }
        fn uid(&self, n: &str) -> String {
            self.0[&format!("{n}_user_id")].clone()
        }
        fn key(&self, version: u32) -> Vec<u8> {
            hex::decode(&self.0[&format!("key_v{version}")]).unwrap()
        }
        /// `n` on a device's list as the web's `listed()` makes them: listed,
        /// confirmed with their keys in the file, holding no statement.
        fn listed(&self, n: &str, role: CircleRole) -> RecordMember {
            RecordMember {
                user_id: self.uid(n),
                sharing_public_key_hex: Some(self.0[&format!("{n}_sharing_pk")].clone()),
                signing_public_key_hex: Some(self.0[&format!("{n}_signing_pk")].clone()),
                confirmed: true,
                listed: true,
                listed_role: Some(role),
                statements: Vec::new(),
                person_confirmed_keys: false,
                server_says_keyless: false,
            }
        }
        /// The same, holding their invitation from the file.
        fn invited(&self, n: &str, role: CircleRole) -> RecordMember {
            with(self.listed(n, role), |m| {
                m.statements = vec![HeldStatement {
                    statement_hex: self.0[&format!("{n}_invitation")].clone(),
                    signature_hex: self.0[&format!("{n}_invitation_signature")].clone(),
                }]
            })
        }
        /// An admission of `subject` by `signer` at `at_version`, a minute
        /// before `now`, signed with the signer's seed in the file.
        fn admission(&self, signer: &str, subject: &str, at_version: i32) -> HeldStatement {
            let (bytes, _) = encode_statement(&MembershipStatement {
                kind: MembershipStatementKind::Admission,
                circle_id: self.circle(),
                statement_id: "3b0000ad-0000-4000-8000-0000000000ad".into(),
                signer_user_id: self.uid(signer),
                issued_at: self.now() - 60,
                expires_at: 0,
                at_version,
                subject_user_id: Some(self.uid(subject)),
                subject_sharing_public_key_hex: Some(self.0[&format!("{subject}_sharing_pk")].clone()),
                subject_signing_public_key_hex: Some(self.0[&format!("{subject}_signing_pk")].clone()),
                subject_email: None,
            })
            .unwrap();
            let seed: [u8; 32] = hex::decode(&self.0[&format!("{signer}_signing_seed")]).unwrap().try_into().unwrap();
            HeldStatement {
                statement_hex: hex::encode(&bytes),
                signature_hex: hex::encode(SigningKey::from_bytes(&seed).sign(&statement_digest(&bytes)).to_bytes()),
            }
        }
        fn records(&self, versions: impl Iterator<Item = u32>) -> Vec<SignedRefreshRecord> {
            versions
                .map(|r| SignedRefreshRecord {
                    record_hex: self.0[&format!("r{r}_record_wire")].clone(),
                    signature_hex: self.0[&format!("r{r}_signature")].clone(),
                })
                .collect()
        }
        /// The links `v -> v - 1` up to `top`.
        fn links(&self, top: u32) -> Vec<KeyChainLinkData> {
            (2..=top)
                .map(|from| KeyChainLinkData {
                    from_version: from as i32,
                    to_version: from as i32 - 1,
                    encrypted_key: self.0[&format!("link_{from}_{}_encrypted_key", from - 1)].clone(),
                    nonce: self.0[&format!("link_{from}_{}_nonce", from - 1)].clone(),
                })
                .collect()
        }
        fn import(&self, device: &CryptoManager, records: &[SignedRefreshRecord], top: u32, members: &[RecordMember], own_head: Option<&SignedCircleHead>) -> RefreshRecordsReport {
            device.import_refresh_records_at(&self.circle(), records, &self.links(top), members, true, own_head, &[], self.now()).unwrap()
        }
        /// A device holding only the keys for `versions`.
        fn device(&self, versions: impl Iterator<Item = u32>) -> Arc<CryptoManager> {
            let device = CryptoManager::new();
            for v in versions {
                assert!(device.add_verified_key(&self.circle(), v, &self.key(v)));
            }
            device
        }
        /// A device holding key_vN from step N on, served r1..rN at step N
        /// with the links below them and `lists[N - 1]`: each step's report.
        fn step_by_step(&self, lists: &[Vec<RecordMember>]) -> (Arc<CryptoManager>, Vec<RefreshRecordsReport>) {
            let device = CryptoManager::new();
            let mut reports = Vec::new();
            for (list, v) in lists.iter().zip(1u32..) {
                assert!(device.add_verified_key(&self.circle(), v, &self.key(v)));
                reports.push(self.import(&device, &self.records(1..=v), v, list, None));
            }
            (device, reports)
        }
        /// Served the same records again, `device` changes nothing: the same
        /// report but for its rows (it decides no record twice), the same
        /// head, the same sealing version.
        fn second_import_changes_nothing(&self, device: &CryptoManager, records: &[SignedRefreshRecord], top: u32, list: &[RecordMember], last: &RefreshRecordsReport) {
            let state = || {
                let head = device.refresh.read().unwrap().get(&CircleKey::of(&self.circle())).and_then(|chain| chain.head.clone());
                (head, device.refresh_head_versions(), device.get_active_version(self.circle()).ok())
            };
            let before = state();
            assert!(before.0.is_some());
            let again = self.import(device, records, top, list, None);
            assert_eq!(again, RefreshRecordsReport { versions: Vec::new(), ..last.clone() });
            assert_eq!(state(), before);
        }
        fn role(&self, device: &CryptoManager, n: &str) -> Option<CircleRole> {
            device.chain_role(self.circle(), self.uid(n))
        }
        fn eligibility(&self, device: &CryptoManager, members: &[RecordMember], n: &str, purpose: EligibilityPurpose) -> MemberEligibility {
            let uid = self.uid(n);
            device.refresh_eligibility_at(&self.circle(), members, purpose, self.now()).unwrap().into_iter().find(|e| e.user_id == uid).unwrap()
        }
        /// Whether record `r` has an entry for `user_id` (S from key_v1).
        fn names(&self, r: u32, user_id: &str) -> bool {
            let secret = crate::refresh_record::circle_secret(&self.key(1)).unwrap();
            let code = member_code(&secret, uuid::Uuid::parse_str(user_id).unwrap().as_bytes());
            let wire = WireRecord::parse(&hex::decode(&self.0[&format!("r{r}_record_wire")]).unwrap()).unwrap();
            wire.body.entries.iter().any(|e| e.code == code)
        }
    }

    /// `names`' user ids, sorted.
    fn sorted_uids(f: &WebBuilt, names: &[&str]) -> Vec<String> {
        sorted(names.iter().map(|n| f.uid(n)).collect())
    }

    fn held_versions(device: &CryptoManager, f: &WebBuilt) -> Vec<u32> {
        let mut versions: Vec<u32> = device.held_keys(&f.circle()).iter().map(|(v, _)| *v).collect();
        versions.sort();
        versions
    }

    #[test]
    fn the_webs_built_chain_is_taken_as_its_header_says() {
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built.txt"));
        let four = vec![
            f.listed("A", CircleRole::Owner),
            f.invited("B", CircleRole::Member),
            f.invited("C", CircleRole::Admin),
            f.invited("D", CircleRole::Member),
        ];
        let three = four[..3].to_vec();
        let with_n = |confirmed: bool| [three.clone(), vec![with(f.invited("N", CircleRole::Member), |m| m.confirmed = confirmed)]].concat();
        // B's device, step by step, N confirmed by C's invitation: every version accepted.
        let (b, reports) = f.step_by_step(&[four.clone(), four.clone(), three.clone(), with_n(true), with_n(true)]);
        for (report, v) in reports.iter().zip(1u32..) {
            assert_eq!(state_of_version(report, v), (Accepted, RecordProblem::None), "B's device, v{v}");
        }
        assert_eq!(
            (f.role(&b, "C"), f.role(&b, "D"), f.role(&b, "N")),
            (Some(CircleRole::Admin), None, Some(CircleRole::Member)),
            "C admin, D not counted, N a member (pending)"
        );
        f.second_import_changes_nothing(&b, &f.records(1..=5), 5, &with_n(true), &reports[4]);
        // A device that lists N unconfirmed: r4 rejected, the repair accepted.
        let (a, reports) = f.step_by_step(&[four.clone(), four.clone(), three.clone(), with_n(false), with_n(false)]);
        for (report, v) in reports.iter().zip(1u32..) {
            let want = if v == 4 { (Rejected, RecordProblem::R2UnmatchedEntry) } else { (Accepted, RecordProblem::None) };
            assert_eq!(state_of_version(report, v), want, "N unconfirmed, v{v}");
        }
        assert_eq!(reports[4].sealing_version, Some(5));
        assert_eq!(a.get_active_version(f.circle()).unwrap(), 5);
        // What the rejected r4 asks the next plan to name, and the web's repair names it all.
        assert_eq!(sorted(reports[3].tip_named_listed.clone()), sorted_uids(&f, &["A", "B", "C", "N"]));
        assert!(reports[3].tip_named_listed.iter().all(|uid| f.names(5, uid)));
        f.second_import_changes_nothing(&a, &f.records(1..=5), 5, &with_n(false), &reports[4]);
        // r3's maker: A's fresh install, which confirms nobody yet,
        // on its own head at v2, D off its list. The head vouches for
        // A, B and C; without it, the same chain vouches for nobody.
        let fresh = |head: Option<&SignedCircleHead>| {
            use base64::Engine as _;
            let device = f.device(1..=2);
            let seed = hex::decode(&f.0["A_signing_seed"]).unwrap();
            device.import_signing_private_key(base64::engine::general_purpose::STANDARD.encode(seed)).unwrap();
            let unconfirmed: Vec<RecordMember> = three.iter().map(|m| with(m.clone(), |m| m.confirmed = m.user_id == f.uid("A"))).collect();
            f.import(&device, &f.records(1..=2), 2, &unconfirmed, head)
        };
        let head = SignedCircleHead { head_hex: f.0["head_A_v2"].clone(), signature_hex: f.0["head_A_v2_signature"].clone() };
        let report = fresh(Some(&head));
        assert_eq!(state_of_version(&report, 2), (Accepted, RecordProblem::None), "{:?}", report.versions);
        assert!(!report.forked);
        assert_eq!(sorted(report.head_confirmed_members), sorted_uids(&f, &["A", "B", "C"]));
        assert!(fresh(None).head_confirmed_members.is_empty());
    }

    #[test]
    fn the_webs_built_transition_is_taken_as_its_header_says() {
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_transition.txt"));
        let members = vec![
            f.listed("A", CircleRole::Owner),
            f.listed("B", CircleRole::Admin),
            with(f.listed("C", CircleRole::Member), |m| m.confirmed = false),
        ];
        // B's device, holding the circle's keys 1-5.
        let b = f.device(1..=5);
        let report = f.import(&b, &f.records(5..=5), 5, &members, None);
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None), "{:?}", report.versions);
        assert_eq!(report.sealing_version, Some(5));
        assert_eq!(
            (f.role(&b, "A"), f.role(&b, "B"), f.role(&b, "C")),
            (Some(CircleRole::Owner), Some(CircleRole::Admin), Some(CircleRole::Member))
        );
        f.second_import_changes_nothing(&b, &f.records(5..=5), 5, &members, &report);
        // A fresh device of C's, holding key_v5 only, everyone listed confirmed:
        // it walks 5 -> 4 and checks the anchor tag.
        let c = f.device(5..=5);
        let confirmed: Vec<RecordMember> = members.iter().map(|m| with(m.clone(), |m| m.confirmed = true)).collect();
        let report = f.import(&c, &f.records(5..=5), 5, &confirmed, None);
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None), "{:?}", report.versions);
        assert_eq!(report.sealing_version, Some(5));
        assert_eq!(held_versions(&c, &f), vec![4, 5], "the anchor's key, walked to");
        f.second_import_changes_nothing(&c, &f.records(5..=5), 5, &confirmed, &report);
    }

    #[test]
    fn the_webs_built_ejects_are_taken_as_their_header_says() {
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_ejects.txt"));
        let (a, b, c) = (f.listed("A", CircleRole::Owner), f.invited("B", CircleRole::Member), f.invited("C", CircleRole::Admin));
        let six = vec![
            a.clone(),
            b.clone(),
            c.clone(),
            f.invited("D", CircleRole::Member),
            f.invited("E", CircleRole::Member),
            f.invited("F", CircleRole::Member),
        ];
        let five: Vec<RecordMember> = six.iter().filter(|m| m.user_id != f.uid("D")).cloned().collect();
        // E after a password reset: the same account, new keys, nobody confirms them yet.
        let e_new = with(f.listed("E", CircleRole::Member), |m| {
            m.sharing_public_key_hex = Some(f.0["E_new_sharing_pk"].clone());
            m.signing_public_key_hex = Some(f.0["E_new_signing_pk"].clone());
            m.confirmed = false;
        });
        let n = |confirmed: bool| with(f.invited("N", CircleRole::Member), |m| m.confirmed = confirmed);
        let m = |confirmed: bool| with(f.invited("M", CircleRole::Member), |m| m.confirmed = confirmed);
        // B's device, step by step, N and M confirmed by C's invitations while listed.
        let after_reset = vec![a.clone(), b.clone(), c.clone(), e_new.clone(), n(true)];
        let (b_device, reports) = f.step_by_step(&[
            six.clone(),
            six.clone(),
            five.clone(),
            [five.clone(), vec![n(true)]].concat(),
            after_reset.clone(),
            [after_reset.clone(), vec![m(true)]].concat(),
            after_reset.clone(),
        ]);
        for (report, v) in reports.iter().zip(1u32..) {
            assert_eq!(state_of_version(report, v), (Accepted, RecordProblem::None), "B's device, v{v}");
        }
        assert_eq!(
            ["D", "F", "M", "N", "E"].map(|who| f.role(&b_device, who)),
            [None, None, None, Some(CircleRole::Member), Some(CircleRole::Member)],
            "D and M removed, F departed off the list, N and E counted"
        );
        f.second_import_changes_nothing(&b_device, &f.records(1..=7), 7, &after_reset, &reports[6]);
        // D and M, ejected by the owner (r3, r7): listed again with
        // their old invitations, they stay out, for a rotation and
        // for a delivery. An admission after the removal is what
        // brings one back (E's rule (b)).
        let with_one = |member: RecordMember| [after_reset.clone(), vec![member]].concat();
        for (who, at) in [("D", 3), ("M", 7)] {
            for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
                let e = f.eligibility(&b_device, &with_one(f.invited(who, CircleRole::Member)), who, purpose);
                assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(at), "{who} {purpose:?}: {e:?}");
            }
        }
        let admitted = with_one(with(f.invited("D", CircleRole::Member), |m| m.statements.push(f.admission("A", "D", 7))));
        assert_eq!(f.eligibility(&b_device, &admitted, "D", EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
        // F, filled in departed at r5 (a departure, no removal): off the list,
        // out; listed again, counted as before, as someone the chain included.
        let (off, back) = (with_one(with(f.invited("F", CircleRole::Member), |m| m.listed = false)), with_one(f.invited("F", CircleRole::Member)));
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = f.eligibility(&b_device, &off, "F", purpose);
            assert!(!e.eligible && !e.removed_by_owner_or_admin && e.removed_at_version.is_none(), "F {purpose:?}: {e:?}");
            let e = f.eligibility(&b_device, &back, "F", purpose);
            assert!(e.eligible && e.basis == Some(EligibilityBasis::CountedByChain), "F listed again, {purpose:?}: {e:?}");
        }
        // A device like A's, N and M unconfirmed: r4 and r6 rejected, the builder's records accepted.
        let a5 = vec![a.clone(), b.clone(), c.clone(), e_new.clone(), n(false)];
        let a6 = [a5.clone(), vec![m(false)]].concat();
        let (a_device, reports) = f.step_by_step(&[six.clone(), six, five, a5.clone(), a5.clone(), a6, a5.clone()]);
        for (report, v) in reports.iter().zip(1u32..) {
            let want = if v == 4 || v == 6 { (Rejected, RecordProblem::R2UnmatchedEntry) } else { (Accepted, RecordProblem::None) };
            assert_eq!(state_of_version(report, v), want, "A's device, v{v}");
        }
        assert_eq!(reports[6].sealing_version, Some(7));
        assert_eq!(a_device.get_active_version(f.circle()).unwrap(), 7);
        // What each rejected tip asks the next plan to name (F is off the
        // list), and the web's repair and eject after it name them all.
        assert_eq!(sorted(reports[3].tip_named_listed.clone()), sorted_uids(&f, &["A", "B", "C", "E", "N"]));
        assert!(reports[3].tip_named_listed.iter().all(|uid| f.names(5, uid)));
        assert_eq!(sorted(reports[5].tip_named_listed.clone()), sorted_uids(&f, &["A", "B", "C", "E", "M", "N"]));
        assert!(reports[5].tip_named_listed.iter().all(|uid| f.names(7, uid)));
        f.second_import_changes_nothing(&a_device, &f.records(1..=7), 7, &a5, &reports[6]);
    }

    /// A first device holding only the newest key, `top`, served the records
    /// from `first`: with the links as served it takes the chain; with `link`
    /// flipped it can't walk down to the anchor, so it takes nothing, asks for
    /// a fresh copy, and keeps no key it walked to.
    fn a_first_device_needs_the_link(f: &WebBuilt, first: u32, top: u32, list: &[RecordMember], link: &str) {
        let import = |f: &WebBuilt| {
            let device = f.device(top..=top);
            let report = f.import(&device, &f.records(first..=top), top, list, None);
            (device, report)
        };
        let (_, report) = import(f);
        assert_eq!(state_of_version(&report, top), (Accepted, RecordProblem::None), "{:?}", report.versions);
        let (device, report) = import(&f.flipped(link, 0));
        assert!(!report.versions.is_empty() && report.versions.iter().all(|r| (r.state, r.problem) == (Waiting, RecordProblem::ChainWalk)), "{link}: {:?}", report.versions);
        assert!(report.ask_for_fresh_copy && report.sealing_version.is_none(), "{link}: {report:?}");
        assert_eq!(held_versions(&device, f), vec![top], "{link}");
    }

    /// B's lists, step by step, for the built file (its header).
    fn built_lists(f: &WebBuilt) -> Vec<Vec<RecordMember>> {
        let four = vec![
            f.listed("A", CircleRole::Owner),
            f.invited("B", CircleRole::Member),
            f.invited("C", CircleRole::Admin),
            f.invited("D", CircleRole::Member),
        ];
        let with_n = [four[..3].to_vec(), vec![f.invited("N", CircleRole::Member)]].concat();
        vec![four.clone(), four.clone(), four[..3].to_vec(), with_n.clone(), with_n]
    }

    /// E after a password reset, in the ejects file: the same account, new
    /// keys, nobody confirms them yet.
    fn e_after_reset(f: &WebBuilt) -> RecordMember {
        with(f.listed("E", CircleRole::Member), |m| {
            m.sharing_public_key_hex = Some(f.0["E_new_sharing_pk"].clone());
            m.signing_public_key_hex = Some(f.0["E_new_signing_pk"].clone());
            m.confirmed = false;
        })
    }

    /// B's lists, step by step, for the ejects file (its header), with
    /// `extra` listed from step 3 on.
    fn ejects_lists(f: &WebBuilt, extra: &[RecordMember]) -> Vec<Vec<RecordMember>> {
        let (a, b, c) = (f.listed("A", CircleRole::Owner), f.invited("B", CircleRole::Member), f.invited("C", CircleRole::Admin));
        let six = vec![
            a.clone(),
            b.clone(),
            c.clone(),
            f.invited("D", CircleRole::Member),
            f.invited("E", CircleRole::Member),
            f.invited("F", CircleRole::Member),
        ];
        let five: Vec<RecordMember> = six.iter().filter(|m| m.user_id != f.uid("D")).cloned().collect();
        let after_reset = vec![a, b, c, e_after_reset(f), f.invited("N", CircleRole::Member)];
        let with_extra = |list: Vec<RecordMember>| [list, extra.to_vec()].concat();
        vec![
            six.clone(),
            six,
            with_extra(five.clone()),
            with_extra([five, vec![f.invited("N", CircleRole::Member)]].concat()),
            with_extra(after_reset.clone()),
            with_extra([after_reset.clone(), vec![f.invited("M", CircleRole::Member)]].concat()),
            with_extra(after_reset),
        ]
    }

    /// `f` with one byte of record `r`'s signature, or of its key tag
    /// (`tag`), flipped.
    fn with_a_byte_flipped(f: &WebBuilt, r: u32, tag: bool) -> WebBuilt {
        if tag {
            let wire = format!("r{r}_record_wire");
            let trailer = if f.0[&format!("r{r}_kind")] == "transition" { 64 } else { 32 };
            f.flipped(&wire, f.0[&wire].len() / 2 - trailer)
        } else {
            f.flipped(&format!("r{r}_signature"), 0)
        }
    }

    /// Record `r` of `f` served step by step with a byte of its signature or
    /// key tag flipped: from its step on, the chain waits there on the
    /// signature, nothing after it is taken, no key copy is dropped or asked
    /// for, and a good copy served next is taken.
    fn a_flipped_record_waits(f: &WebBuilt, lists: &[Vec<RecordMember>], r: u32, tag: bool) {
        let what = if tag { "key tag" } else { "signature" };
        let (device, reports) = with_a_byte_flipped(f, r, tag).step_by_step(lists);
        for (report, step) in reports.iter().zip(1u32..).skip(r as usize - 1) {
            let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|x| (x.version, x.state, x.problem)).collect();
            assert_eq!(rows, vec![(r as i32, Waiting, RecordProblem::Signature)], "r{r}'s {what} flipped, step {step}");
            assert!(report.sealing_version.map_or(true, |v| v < r as i32), "r{r}'s {what} flipped, step {step}: {report:?}");
            assert!(!report.forked && !report.ask_for_fresh_copy, "r{r}'s {what} flipped, step {step}: {report:?}");
        }
        assert!(held_versions(&device, f).contains(&r), "r{r}'s {what} flipped: the key held for v{r} stays");
        let last = lists.len() as u32;
        let report = f.import(&device, &f.records(1..=last), last, &lists[last as usize - 1], None);
        assert_ne!(state_of_version(&report, r).0, Waiting, "a good copy of r{r}");
        assert_eq!(state_of_version(&report, last), (Accepted, RecordProblem::None), "a good copy of r{r}: {:?}", report.versions);
        assert_eq!(report.sealing_version, Some(last as i32));
    }

    #[test]
    fn the_webs_built_records_with_a_byte_flipped_are_never_passed_over() {
        // A tamper check on each file: a record's signature, its key tag
        // (the anchor tag for the transition), and a link.
        let built = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built.txt"));
        let ejects = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_ejects.txt"));
        for tag in [false, true] {
            // r3: the builder's fill-in of the members a plan doesn't name; r5: the
            // repair carrying pending-only names. Both by the web's builder.
            a_flipped_record_waits(&built, &built_lists(&built), 3, tag);
            a_flipped_record_waits(&ejects, &ejects_lists(&ejects, &[]), 5, tag);
        }
        let list = &built_lists(&built)[4];
        a_first_device_needs_the_link(&built, 1, 5, list, "link_3_2_encrypted_key");
        // The account's first device, served the whole chain with r1's
        // signature flipped: it waits at v1, and takes and holds nothing of it.
        let tampered = with_a_byte_flipped(&built, 1, false);
        let first = tampered.device(5..=5);
        let report = tampered.import(&first, &tampered.records(1..=5), 5, list, None);
        let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|x| (x.version, x.state, x.problem)).collect();
        assert_eq!(rows, vec![(1, Waiting, RecordProblem::Signature)]);
        assert!(first.refresh.read().unwrap()[&CircleKey::of(&built.circle())].seen.is_empty());
        assert!(report.sealing_version.is_none() && first.chain_role(built.circle(), built.uid("A")).is_none());
        let list = &ejects_lists(&ejects, &[])[6];
        a_first_device_needs_the_link(&ejects, 1, 7, list, "link_4_3_encrypted_key");

        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_transition.txt"));
        let members = [f.listed("A", CircleRole::Owner), f.listed("B", CircleRole::Admin), f.listed("C", CircleRole::Member)];
        a_first_device_needs_the_link(&f, 5, 5, &members, "link_5_4_encrypted_key");
        // The transition's signature or key tag flipped: B (keys 1-5) waits on
        // the signature, its keys kept. C's fresh device (key_v5 only) waits on
        // the signature too, or, with the key tag flipped, can't start its walk
        // from its copy of key_v5: it asks for a fresh copy and keeps the one
        // it has. A good copy is taken by both.
        for tag in [false, true] {
            let tampered = with_a_byte_flipped(&f, 5, tag);
            let b = tampered.device(1..=5);
            let report = tampered.import(&b, &tampered.records(5..=5), 5, &members, None);
            assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::Signature), "tag flipped: {tag}");
            assert!(report.sealing_version.is_none() && !report.ask_for_fresh_copy, "{report:?}");
            assert_eq!(held_versions(&b, &f), vec![1, 2, 3, 4, 5]);
            assert_eq!(state_of_version(&f.import(&b, &f.records(5..=5), 5, &members, None), 5), (Accepted, RecordProblem::None));
            let c = tampered.device(5..=5);
            let report = tampered.import(&c, &tampered.records(5..=5), 5, &members, None);
            let want = if tag { (Waiting, RecordProblem::ChainWalk) } else { (Waiting, RecordProblem::Signature) };
            assert_eq!(state_of_version(&report, 5), want, "tag flipped: {tag}");
            assert!(report.sealing_version.is_none() && report.ask_for_fresh_copy == tag, "{report:?}");
            assert!(held_versions(&c, &f).contains(&5));
            assert_eq!(state_of_version(&f.import(&c, &f.records(5..=5), 5, &members, None), 5), (Accepted, RecordProblem::None));
        }
        // The anchor tag flipped. B holds key_v4 itself: the
        // transition reads as made over another key, a split, and the
        // circle waits with B's keys kept. C's fresh device can't
        // verify the key its walk reaches: it asks for a fresh copy.
        let len = f.0["r5_record_wire"].len() / 2;
        let tampered = f.flipped("r5_record_wire", len - 32);
        let b = tampered.device(1..=5);
        let report = tampered.import(&b, &tampered.records(5..=5), 5, &members, None);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::AnchorMismatch), "{:?}", report.versions);
        assert!(report.sealing_version.is_none() && !report.ask_for_fresh_copy, "{report:?}");
        assert_eq!(held_versions(&b, &f), vec![1, 2, 3, 4, 5]);
        let c = tampered.device(5..=5);
        let report = tampered.import(&c, &tampered.records(5..=5), 5, &members, None);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::ChainWalk), "{:?}", report.versions);
        assert!(report.sealing_version.is_none() && report.ask_for_fresh_copy, "{report:?}");
        assert_eq!(held_versions(&c, &f), vec![5]);
    }

    #[test]
    fn a_flipped_signature_on_the_webs_eject_never_lets_the_ejected_member_back() {
        // r3 is A's eject of D. With a byte of r3's signature flipped
        // and D kept on the list, the chain waits at v3, on B's
        // device and on the account's first device: taking v4-v7 over
        // the refused r3 would count D again. A good copy of r3
        // brings the removal.
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_ejects.txt"));
        let lists = ejects_lists(&f, &[f.invited("D", CircleRole::Member)]);
        let tampered = f.flipped("r3_signature", 0);
        let (b, reports) = tampered.step_by_step(&lists);
        for (report, step) in reports.iter().zip(1u32..).skip(2) {
            let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|x| (x.version, x.state, x.problem)).collect();
            assert_eq!(rows, vec![(3, Waiting, RecordProblem::Signature)], "step {step}");
        }
        let first = tampered.device(7..=7);
        let report = tampered.import(&first, &tampered.records(1..=7), 7, &lists[6], None);
        let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|x| (x.version, x.state, x.problem)).collect();
        assert_eq!(rows, vec![(2, Accepted, RecordProblem::None), (3, Waiting, RecordProblem::Signature)]);
        for device in [&b, &first] {
            let report = f.import(device, &f.records(1..=7), 7, &lists[6], None);
            assert_eq!(state_of_version(&report, 7), (Accepted, RecordProblem::None), "{:?}", report.versions);
            assert_eq!(f.role(device, "D"), None);
            for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
                let e = f.eligibility(device, &lists[6], "D", purpose);
                assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{purpose:?}: {e:?}");
            }
        }
    }

    #[test]
    fn nothing_is_built_on_the_head_below_a_version_that_waits() {
        // r3, A's eject of D, spoiled (a byte of its signature) or
        // withheld (r4-r7 served without it). B waits: nothing
        // above v2 is taken, nothing is sealed or handed out above
        // v2 (a wrap takes the active key), and no record is built
        // on v2 until an import decides the version that waits,
        // even when the server then serves nothing that far.
        use base64::Engine as _;
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built_ejects.txt"));
        let lists = ejects_lists(&f, &[f.invited("D", CircleRole::Member)]);
        let list = &lists[6];
        let everyone: Vec<PlannedEntry> = list
            .iter()
            .filter(|m| m.confirmed)
            .map(|m| PlannedEntry { user_id: m.user_id.clone(), state: RecordMemberState::Included, role: None })
            .collect();
        let waits = |built: &Result<RecordedRotationBundle, MobileError>| matches!(built, Err(MobileError::InvalidInput(m)) if m.contains("waits here"));
        for (spoiled, want) in [(true, (3, RecordProblem::Signature)), (false, (4, RecordProblem::RecordMissing))] {
            let served = if spoiled {
                f.flipped("r3_signature", 0).records(1..=7)
            } else {
                f.records([1, 2, 4, 5, 6, 7].into_iter())
            };
            let (b, _) = f.step_by_step(&lists[..2]);
            // B signs as itself; its sharing key isn't in the file, and the
            // refusal comes before the builder uses it.
            let b64 = base64::engine::general_purpose::STANDARD;
            b.import_signing_private_key(b64.encode(hex::decode(&f.0["B_signing_seed"]).unwrap())).unwrap();
            b.import_private_key(b64.encode([0x4b; 32])).unwrap();
            for v in 3..=5 {
                assert!(b.add_verified_key(&f.circle(), v, &f.key(v)));
            }
            let build = || b.prepare_recorded_rotation_at(&f.circle(), &f.uid("B"), RefreshRecordKind::Rotation, &everyone, list, true, "n", f.now());
            let report = f.import(&b, &served, 7, list, None);
            let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|x| (x.version, x.state, x.problem)).collect();
            assert_eq!(rows, vec![(want.0, Waiting, want.1)], "spoiled: {spoiled}");
            assert!(report.sealing_version.map_or(true, |v| v <= 2) && b.get_active_version(f.circle()).map_or(true, |v| v <= 2), "{report:?}");
            assert!(waits(&build()), "spoiled: {spoiled}");
            // The server serves nothing above v2 now: that decides nothing.
            let report = f.import(&b, &f.records(1..=2), 2, list, None);
            assert!(report.versions.is_empty(), "{:?}", report.versions);
            assert!(waits(&build()), "spoiled: {spoiled}, then withheld");
            // A good copy decides it: D's removal counts, and B may build again.
            let report = f.import(&b, &f.records(1..=7), 7, list, None);
            assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None), "{:?}", report.versions);
            assert_eq!(f.eligibility(&b, list, "D", EligibilityPurpose::Deliver).removed_at_version, Some(3));
            assert!(!waits(&build()), "spoiled: {spoiled}, then a good copy");
        }
    }

    /// The owner A's eject of D at v3, with a copy whose signature is spoiled.
    fn an_eject_and_its_spoiled_copy() -> (Acct, Acct, Acct, Acct, History, History, History, Vec<RecordMember>) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let mut spoiled = real.clone();
        spoiled.records.get_mut(&3).unwrap().1[0] ^= 1;
        let members = four_members(&a, &b, &c, &d);
        (a, b, c, d, h, real, spoiled, members)
    }

    #[test]
    fn a_wait_survives_a_restart_and_a_withheld_record() {
        // The wait is kept with the chain's state. After a restart
        // and an import that serves nothing above v2, B still builds
        // nothing; a good copy of v3 ends the wait.
        use RecordMemberState as S;
        let (a, b, c, d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let waits = |built: Result<RecordedRotationBundle, MobileError>| matches!(built, Err(MobileError::InvalidInput(m)) if m.contains("waits here"));
        let store = MemStore::default();
        let device = b.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        give(&device, &h, 2);
        import(&device, &h, &members, true);
        give(&device, &real, 3);
        let report = import(&device, &spoiled, &members, true);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Signature));
        assert!(waits(device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW)));
        device.persist_keys().unwrap();
        let again = restarted(&store);
        assert!(import(&again, &h, &members, true).versions.is_empty());
        assert!(waits(again.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW)));
        assert_eq!(state_of_version(&import(&again, &real, &members, true), 3).0, Accepted);
        let without_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        assert!(again.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &without_d, &members, true, "n", NOW).is_ok());
        assert_eq!(eligible(&again, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
        // A stored wait that doesn't read: the circle waits, latched, as for
        // any part of its stored state that doesn't read.
        device.persist_keys().unwrap();
        let mut pins = stored_pins(&store);
        pins.get_mut(&format!("{WAIT_PREFIX}{CIRCLE}:3")).unwrap().sharing_pubkey_hex = "zz".into();
        set_stored_pins(&store, &pins);
        let garbled = restarted(&store);
        assert!(garbled.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].forked);
        assert!(garbled.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).is_err());
    }

    #[test]
    fn only_the_record_that_waits_ends_the_wait() {
        // With v3 (the owner's eject of D) waiting on its signature,
        // the server serves another v3 in its place: an insider's that
        // every device rejects, or one that is valid. Each is a second
        // candidate for v3: the version waits as a fork, and no record
        // is built. The eject, served well, ends the wait.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let stranger = Acct::new(0x5f);
        let mut rejected = h.clone();
        rejected.keys.insert(3, [0x3f; 32]);
        let v3 = rows(&rejected, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&stranger, Included, Member)]);
        rejected.rotate(RecordKind::Rotation, &c, v3, None);
        let mut valid = h.clone();
        valid.keys.insert(3, [0x3e; 32]);
        let v3 = rows(&valid, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        valid.rotate(RecordKind::Rotation, &c, v3, None);
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &real, 3);
        assert_eq!(state_of_version(&import(&device, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
        for other in [&rejected, &valid] {
            let report = import(&device, other, &members, true);
            let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
            assert_eq!(rows, vec![(3, Waiting, RecordProblem::Fork)]);
            for kind in [RefreshRecordKind::Rotation, RefreshRecordKind::Repair] {
                let built = device.prepare_recorded_rotation_at(CIRCLE, &b.uid, kind, &everyone, &members, true, "n", NOW);
                assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("waits here")), "{kind:?}: {:?}", built.map(|_| ()));
            }
            assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member), "nothing of the other v3 taken");
        }
        assert_eq!(state_of_version(&import(&device, &real, &members, true), 3).0, Accepted);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
        let without_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        assert!(device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &without_d, &members, true, "n", NOW).is_ok());
    }

    #[test]
    fn a_later_wait_never_replaces_a_kept_one() {
        // The owner's eject v3 is served spoiled (kept: 3); then v3
        // is withheld and an insider's v4, over the insider's own
        // v3', is served (it waits too: kept 3 and 4); then v3'
        // comes with that v4. v3' is a second candidate for the kept
        // v3: the version waits as a fork, and nothing is built.
        // Only the real v3, served well, ends it.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let mut insider = h.clone();
        insider.keys.insert(3, [0x3e; 32]);
        insider.keys.insert(4, [0x4e; 32]);
        let v3 = rows(&insider, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        insider.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&insider, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        insider.rotate(RecordKind::Rotation, &c, v4, None);
        let without_v3 = {
            let mut withheld = insider.clone();
            withheld.records.remove(&3);
            withheld
        };
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let without_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &real, 3);
        assert_eq!(state_of_version(&import(&device, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
        assert_eq!(state_of_version(&import(&device, &without_v3, &members, true), 4), (Waiting, RecordProblem::RecordMissing));
        let kept: Vec<u32> = device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect();
        assert_eq!(kept, vec![3, 4], "a wait found later is added");
        let report = import(&device, &insider, &members, true);
        let seen: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
        assert_eq!(seen, vec![(3, Waiting, RecordProblem::Fork)]);
        for plan in [&everyone, &without_d] {
            let built = device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, plan, &members, true, "n", NOW);
            assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("waits here")), "{:?}", built.map(|_| ()));
        }
        // The real v3, served well, ends its wait, with the owner's v4 after
        // it served too: that v4 is a second candidate for the kept one (the
        // insider's), so it waits there as a fork. Only the insider's v4 can
        // end that wait: a stall, never an under-removal.
        let mut real_on = real.clone();
        let v4 = rows(&real_on, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        real_on.rotate(RecordKind::Rotation, &a, v4, None);
        give(&device, &real_on, 4);
        let report = import(&device, &real_on, &members, true);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert_eq!(state_of_version(&report, 4), (Waiting, RecordProblem::Fork));
        let kept: Vec<u32> = device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect();
        assert_eq!(kept, vec![4]);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
    }

    #[test]
    fn a_first_device_keeps_its_wait_against_another_first_record() {
        // A first device, served the chain with its genesis's signature
        // spoiled, waits at v1 (kept: v1 with that genesis). Another chain
        // served later, from another genesis, is a second candidate for v1: it
        // waits there as a fork, and nothing of it is taken.
        let (a, b, _, _, h) = four();
        let members = four_members(&a, &b, &Acct::new(0xc1), &Acct::new(0xd1));
        let mut spoiled = h.clone();
        spoiled.records.get_mut(&1).unwrap().1[0] ^= 1;
        let other = {
            let mut other = History::genesis(&b);
            let v2 = rows(&other, &[(&b, Included, ChainRole::Owner), (&a, Included, ChainRole::Member)]);
            other.rotate(RecordKind::Rotation, &b, v2, None);
            other
        };
        let device = CryptoManager::new();
        give(&device, &h, 2);
        let report = import(&device, &spoiled, &members, true);
        assert_eq!(state_of_version(&report, 1), (Waiting, RecordProblem::Signature), "{:?}", report.versions);
        let report = import(&device, &other, &members, true);
        let rows: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
        assert_eq!(rows, vec![(1, Waiting, RecordProblem::Fork)]);
        assert!(device.chain_role(CIRCLE.into(), b.uid.clone()).is_none(), "nothing of the other chain taken");
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 2).0, Accepted, "the kept genesis, served well");
    }

    /// Admin C's own v3 in the place of the owner's eject: valid, D kept.
    fn an_insiders_v3(h: &History, a: &Acct, b: &Acct, c: &Acct, d: &Acct) -> History {
        use ChainRole::{Admin, Member, Owner};
        let mut insider = h.clone();
        insider.keys.insert(3, [0x3e; 32]);
        let v3 = rows(&insider, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin), (d, Included, Member)]);
        insider.rotate(RecordKind::Rotation, c, v3, None);
        insider
    }

    /// On `real_and_fork`'s real chain (A ejected X at v3): the owner A's
    /// eject of admin C at v4, a copy of it with its signature spoiled, and
    /// C's own v4, keeping everyone.
    fn an_eject_of_c_above_the_head(real: &History, a: &Acct, b: &Acct, c: &Acct) -> (History, History, History) {
        use ChainRole::{Admin, Member, Owner};
        let mut eject = real.clone();
        let v4 = rows(&eject, &[(a, Included, Owner), (b, Included, Member), (c, Removed, Admin)]);
        eject.rotate(RecordKind::Rotation, a, v4, None);
        let mut spoiled = eject.clone();
        spoiled.records.get_mut(&4).unwrap().1[0] ^= 1;
        let mut insider = real.clone();
        insider.keys.insert(4, [0x4e; 32]);
        let v4 = rows(&insider, &[(a, Included, Owner), (b, Included, Member), (c, Included, Admin)]);
        insider.rotate(RecordKind::Rotation, c, v4, None);
        (eject, spoiled, insider)
    }

    /// With a fork above B's head (v3) latched: `alone` served by itself is
    /// never taken and nothing is built, in this process and after a restart,
    /// before and after X's fork at v3 is served whole. That fork, below the
    /// head, would settle (this device's side removed X): it isn't settled
    /// while the latch is set, so it never ends it.
    fn never_taken_while_latched(
        device: &Arc<CryptoManager>,
        store: &MemStore,
        alone: &History,
        fork: &History,
        members: &[RecordMember],
        b: &Acct,
        everyone: &[PlannedEntry],
    ) {
        device.persist_keys().unwrap();
        for (again, restart) in [(device.clone(), false), (restarted(store), true)] {
            for (served, what) in [(alone, "alone"), (fork, "the fork below the head"), (alone, "alone after it")] {
                let report = import(&again, served, members, true);
                assert!(report.forked && report.versions.is_empty(), "{what}, restart: {restart}: {:?}", report.versions);
                {
                    let chains = again.refresh.read().unwrap();
                    assert!(chains[&CircleKey::of(CIRCLE)].fork_latched, "{what}, restart: {restart}");
                    assert_eq!(chains[&CircleKey::of(CIRCLE)].head.as_ref().map(|h| h.version), Some(3), "{what}, restart: {restart}");
                }
                let built = again.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, everyone, members, true, "n", NOW);
                assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("forked")), "{what}, restart: {restart}: {:?}", built.map(|_| ()));
            }
        }
    }

    #[test]
    fn a_fork_above_the_head_is_latched_and_never_settled() {
        // A fork above the head is never settled. B's head is v3 (A's
        // eject of X). The owner's eject of admin C at v4, spoiled,
        // and C's own v4, served together either way round: a fork
        // with no winner (one candidate can't be judged), latched, and
        // nothing kept for its candidates. C's v4 served alone
        // afterwards is never taken and nothing is built: in this
        // process, after a restart, and after X's fork at v3 is served
        // whole (never_taken_while_latched).
        use RecordMemberState as S;
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (_, spoiled, insider) = an_eject_of_c_above_the_head(&real, &a, &b, &c);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let together = |first: &History, second: &History| -> Vec<SignedRefreshRecord> {
            first.signed().into_iter().chain(second.signed().into_iter().skip(3)).collect()
        };
        for served in [together(&spoiled, &insider), together(&insider, &spoiled)] {
            let (device, _) = device_at(&b, &a, &real, &members, &[2, 3]);
            let store = MemStore::default();
            device.register_secure_storage(Box::new(store.clone()));
            let report = device.import_refresh_records_at(CIRCLE, &served, &real.links, &members, true, None, &[], NOW).unwrap();
            let seen: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
            assert!(report.forked && seen == vec![(4, Waiting, RecordProblem::Fork)], "{seen:?}");
            assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.is_empty(), "nothing is kept for the candidates");
            never_taken_while_latched(&device, &store, &insider, &fork, &members, &b, &everyone);
        }
    }

    #[test]
    fn two_records_that_stand_above_the_head_with_no_winner_latch_the_fork() {
        // Above B's head (v3), the owner's v4 and admin C's own v4,
        // both valid, neither removing the other's signer, served
        // together either way round. Neither wins, and the fork is
        // latched, as one with a candidate that can't be judged is:
        // the other one served alone later is never taken, in this
        // process, after a restart, and after X's fork at v3.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (_, _, insider) = an_eject_of_c_above_the_head(&real, &a, &b, &c);
        let mut owners = real.clone();
        let v4 = rows(&owners, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        owners.rotate(RecordKind::Rotation, &a, v4, None);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let together = |first: &History, second: &History| -> Vec<SignedRefreshRecord> {
            first.signed().into_iter().chain(second.signed().into_iter().skip(3)).collect()
        };
        for (served, alone) in [(together(&owners, &insider), &insider), (together(&insider, &owners), &owners)] {
            let (device, _) = device_at(&b, &a, &real, &members, &[2, 3]);
            let store = MemStore::default();
            device.register_secure_storage(Box::new(store.clone()));
            let report = device.import_refresh_records_at(CIRCLE, &served, &real.links, &members, true, None, &[], NOW).unwrap();
            let seen: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
            assert!(report.forked && seen == vec![(4, Waiting, RecordProblem::Fork)], "{seen:?}");
            never_taken_while_latched(&device, &store, alone, &fork, &members, &b, &everyone);
        }
    }

    #[test]
    fn the_latch_holds_whatever_its_stored_entry_reads_as() {
        // The latch reads fail-closed: an entry that doesn't read
        // still latches. And an older SDK, which may settle
        // the fork (its head then no longer says forked), keeps
        // `~rrf:` as a pin: the latch holds again here, and the
        // circle waits.
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let (_, spoiled, insider) = an_eject_of_c_above_the_head(&real, &a, &b, &c);
        let (device, _) = device_at(&b, &a, &real, &members, &[2, 3]);
        let store = MemStore::default();
        device.register_secure_storage(Box::new(store.clone()));
        let served: Vec<SignedRefreshRecord> = spoiled.signed().into_iter().chain(insider.signed().into_iter().skip(3)).collect();
        assert!(device.import_refresh_records_at(CIRCLE, &served, &real.links, &members, true, None, &[], NOW).unwrap().forked);
        device.persist_keys().unwrap();
        let mut pins = stored_pins(&store);
        let latch = format!("{FORK_PREFIX}{CIRCLE}");
        assert!(pins.contains_key(&latch));
        pins.insert(
            latch,
            PinRecord { sharing_pubkey_hex: "zz".into(), signing_pubkey_hex: "not hex".into(), first_pinned_at: -7, last_verified_at: i64::MAX, user_approved_change_at: Some(-1) },
        );
        pins.get_mut(&format!("{HEAD_PREFIX}{CIRCLE}")).unwrap().last_verified_at = 3;
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        {
            let chains = again.refresh.read().unwrap();
            assert!(chains[&CircleKey::of(CIRCLE)].fork_latched && chains[&CircleKey::of(CIRCLE)].forked && chains[&CircleKey::of(CIRCLE)].as_stored.is_empty());
        }
        for served in [&insider, &fork] {
            let report = import(&again, served, &members, true);
            assert!(report.forked && report.versions.is_empty(), "{:?}", report.versions);
        }
        assert_eq!(again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].head.as_ref().map(|h| h.version), Some(3));
    }

    #[test]
    fn waits_add_up_and_the_good_chain_decides_each() {
        // r3 spoiled (kept at 3); then r4 alone (it waits too: kept
        // at 3 and 4); then admin C's v3' alone: a fork at 3. The
        // good r1-r4 decide both, and the builder builds again.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let mut real_on = real.clone();
        let v4 = rows(&real_on, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        real_on.rotate(RecordKind::Rotation, &a, v4, None);
        let only_r4 = {
            let mut only = real_on.clone();
            only.records.retain(|v, _| *v == 4);
            only
        };
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &real_on, 3);
        give(&device, &real_on, 4);
        assert_eq!(state_of_version(&import(&device, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
        assert_eq!(state_of_version(&import(&device, &only_r4, &members, true), 4), (Waiting, RecordProblem::RecordMissing));
        let kept = |device: &CryptoManager| device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect::<Vec<u32>>();
        assert_eq!(kept(&device), vec![3, 4]);
        let insider = an_insiders_v3(&h, &a, &b, &c, &d);
        assert_eq!(state_of_version(&import(&device, &insider, &members, true), 3), (Waiting, RecordProblem::Fork));
        let report = import(&device, &real_on, &members, true);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted), "{:?}", report.versions);
        assert!(kept(&device).is_empty());
        let without_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        assert!(device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &without_d, &members, true, "n", NOW).is_ok());
        // A wait found while one above it is kept is added beside it: waits at
        // 3 (spoiled) and 5 (served alone); then r3 served well and r4 spoiled:
        // 3 is decided, 4 waits, and 5 stays.
        let mut on = real_on.clone();
        let v5 = rows(&on, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        on.rotate(RecordKind::Rotation, &a, v5, None);
        let only = |v: u32| {
            let mut one = on.clone();
            one.records.retain(|k, _| *k == v);
            one
        };
        let mut r4_spoiled = on.clone();
        r4_spoiled.records.retain(|k, _| *k <= 4);
        r4_spoiled.records.get_mut(&4).unwrap().1[0] ^= 1;
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        for v in 3..=5 {
            give(&device, &on, v);
        }
        import(&device, &spoiled, &members, true);
        import(&device, &only(5), &members, true);
        assert_eq!(kept(&device), vec![3, 5]);
        let report = import(&device, &r4_spoiled, &members, true);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4)), (Accepted, (Waiting, RecordProblem::Signature)));
        assert_eq!(kept(&device), vec![4, 5]);
    }

    #[test]
    fn a_kept_record_refused_beside_another_decides_its_wait() {
        // The kept record, served again beside another candidate, can
        // now be judged and is refused for its authority (plain member
        // B "removing" D). That refusal decides its wait, and the
        // other candidate, admin C's valid v3, is taken, served either
        // way round.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let mut plain = h.clone();
        let v3 = rows(&plain, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        plain.rotate(RecordKind::Rotation, &b, v3, None);
        let mut plain_spoiled = plain.clone();
        plain_spoiled.records.get_mut(&3).unwrap().1[0] ^= 1;
        let insider = an_insiders_v3(&h, &a, &b, &c, &d);
        let together = |first: &History, second: &History| -> Vec<SignedRefreshRecord> {
            first.signed().into_iter().chain(second.signed().into_iter().skip(2)).collect()
        };
        for served in [together(&plain, &insider), together(&insider, &plain)] {
            let (device, _) = device_at(&a, &a, &h, &members, &[2]);
            give(&device, &insider, 3);
            assert_eq!(state_of_version(&import(&device, &plain_spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
            let report = device.import_refresh_records_at(CIRCLE, &served, &insider.links, &members, true, None, &[], NOW).unwrap();
            assert!(!report.forked, "{:?}", report.versions);
            assert!(report.versions.contains(&status(3, Rejected, RecordProblem::Removal)), "{:?}", report.versions);
            assert_eq!(state_of_version(&report, 3).0, Rejected, "{:?}", report.versions);
            assert_eq!(report.versions.iter().filter(|r| r.version == 3 && r.state == Accepted).count(), 1, "{:?}", report.versions);
            assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.is_empty());
        }
    }

    #[test]
    fn a_kept_wait_above_a_fork_the_other_side_wins_goes_with_it() {
        use ChainRole::{Admin, Member, Owner};
        // B took X's fork v3 and waits at v4, the version after its
        // head, on that side (X's v4, its signature spoiled). The
        // real chain, served whole, removed X at v3: it stands, and
        // what waited at the fork's version or above goes with the
        // losing side. The real v4 is taken.
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let mut real4 = real.clone();
        let v4 = rows(&real4, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        real4.rotate(RecordKind::Rotation, &a, v4, None);
        let mut fork4 = fork.clone();
        fork4.keys.insert(4, [0x4f; 32]);
        let v4 = rows(&fork4, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Member)]);
        fork4.rotate(RecordKind::Rotation, &x, v4, None);
        fork4.records.get_mut(&4).unwrap().1[0] ^= 1;
        let mut before = real.clone();
        before.records.retain(|v, _| *v <= 2);
        let (device, _) = device_at(&b, &a, &before, &members, &[2]);
        give(&device, &fork, 3);
        assert_eq!(state_of_version(&import(&device, &fork, &members, true), 3).0, Accepted);
        give(&device, &fork4, 4);
        assert_eq!(state_of_version(&import(&device, &fork4, &members, true), 4), (Waiting, RecordProblem::Signature));
        assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.contains_key(&4));
        let report = import(&device, &real4, &members, true);
        assert!(!report.forked, "{:?}", report.versions);
        assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.is_empty());
        assert!(matches!(state_of_version(&report, 4).0, Accepted | Reference), "{:?}", report.versions);
        assert_eq!(device.chain_role(CIRCLE.into(), x.uid.clone()), None, "X is out");
    }

    #[test]
    fn a_record_that_doesnt_read_decides_no_wait() {
        // Real: v3, the owner ejects D; v4, the owner removes the
        // admin C. v3 served spoiled (kept at 3), then r4 alone (kept
        // at 4). Then C's other v3, r4, and a copy of r4 with a
        // 63-byte signature: that copy doesn't read (a row at 4 before
        // any judging), and decides nothing. The good r3 is taken; C's
        // own v4 on it (keeping C) is a second candidate for the kept
        // r4 and waits: C isn't passed over, and nothing is built. The
        // same without the copy.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let mut real = h.clone();
        let v3 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        real.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&real, &[(&a, Included, Owner), (&b, Included, Member), (&c, Removed, Admin)]);
        real.rotate(RecordKind::Rotation, &a, v4, None);
        let mut spoiled = real.clone();
        spoiled.records.get_mut(&3).unwrap().1[0] ^= 1;
        let mut other3 = h.clone();
        other3.keys.insert(3, [0x3c; 32]);
        let v3 = rows(&other3, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        other3.rotate(RecordKind::Rotation, &c, v3, None);
        let mut other4 = up_to(&real, 3);
        other4.keys.insert(4, [0x4c; 32]);
        let v4 = rows(&other4, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        other4.rotate(RecordKind::Rotation, &c, v4, None);
        let at = |hist: &History, v: u32| hist.signed().into_iter().nth((v - 1) as usize).unwrap();
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        for garbage_copy in [true, false] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            give(&device, &real, 3);
            give(&device, &real, 4);
            let import_ = |records: Vec<SignedRefreshRecord>| device.import_refresh_records_at(CIRCLE, &records, &real.links, &members, true, None, &[], NOW).unwrap();
            import_(vec![at(&h, 1), at(&h, 2), at(&spoiled, 3)]);
            import_(vec![at(&h, 1), at(&h, 2), at(&real, 4)]);
            let mut third = vec![at(&h, 1), at(&h, 2), at(&other3, 3), at(&real, 4)];
            if garbage_copy {
                let mut garbage = at(&real, 4);
                garbage.signature_hex.truncate(126);
                third.push(garbage);
            }
            let report = import_(third);
            assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Fork), "{:?}", report.versions);
            let kept: Vec<u32> = device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.keys().copied().collect();
            assert_eq!(kept, vec![3, 4], "garbage copy: {garbage_copy}");
            assert_eq!(state_of_version(&import_(vec![at(&h, 1), at(&h, 2), at(&real, 3)]), 3).0, Accepted);
            let report = import_(vec![at(&h, 1), at(&h, 2), at(&real, 3), at(&other4, 4)]);
            assert_eq!(state_of_version(&report, 4), (Waiting, RecordProblem::Fork), "garbage copy: {garbage_copy}");
            assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
            let built = device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
            assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("waits here")), "{:?}", built.map(|_| ()));
        }
    }

    #[test]
    fn another_records_refusal_beside_one_that_stands_decides_nothing() {
        // Only the kept record decides its wait. The owner's eject v3
        // is kept (served spoiled). Then two other v3s come together:
        // plain member B "removing" D (refused: its authority) and
        // admin C's valid v3, which stands, so it wins between the
        // two. The refusal decides nothing: C's v3 is a second
        // candidate for the kept eject and waits there as a fork (not
        // latched), and nothing is built. The eject, served well, is
        // taken.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h, real, spoiled, members) = an_eject_and_its_spoiled_copy();
        let insider = an_insiders_v3(&h, &a, &b, &c, &d);
        let mut plain = h.clone();
        plain.keys.insert(3, [0x3b; 32]);
        let v3 = rows(&plain, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        plain.rotate(RecordKind::Rotation, &b, v3, None);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let together = |first: &History, second: &History| -> Vec<SignedRefreshRecord> {
            first.signed().into_iter().chain(second.signed().into_iter().skip(2)).collect()
        };
        for served in [together(&plain, &insider), together(&insider, &plain)] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            give(&device, &real, 3);
            assert_eq!(state_of_version(&import(&device, &spoiled, &members, true), 3), (Waiting, RecordProblem::Signature));
            let report = device.import_refresh_records_at(CIRCLE, &served, &insider.links, &members, true, None, &[], NOW).unwrap();
            let seen: Vec<(i32, RecordVersionState, RecordProblem)> = report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect();
            assert_eq!(seen, vec![(3, Rejected, RecordProblem::Removal), (3, Waiting, RecordProblem::Fork)]);
            assert!(!report.forked && !device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].fork_latched);
            assert_eq!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.get(&3), Some(&real.records[&3].0.chain()));
            assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member), "nothing of C's v3 taken");
            let built = device.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
            assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("waits here")), "{:?}", built.map(|_| ()));
            assert_eq!(state_of_version(&import(&device, &real, &members, true), 3).0, Accepted);
            assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].waiting.is_empty());
        }
    }

    #[test]
    fn a_restarted_device_imports_before_it_builds() {
        // What waits above the head is known in this process only: after a
        // restart, no record is built before the records are imported again.
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let (_, store) = stored_device(&a, &h, &members);
        let again = restarted(&store);
        let refused = again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
        assert!(matches!(&refused, Err(MobileError::InvalidInput(m)) if m.contains("import this circle's records first")), "{:?}", refused.map(|_| ()));
        import(&again, &h, &members, true);
        assert!(again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).is_ok());
        // A new circle's creator made its whole chain: it may build at once.
        let creator = a.device();
        let created = creator.prepare_recorded_circle_creation_at(&a.uid, &uuid::Uuid::new_v4().to_string(), NOW).unwrap();
        let alone = plan(&[(&a, S::Included, None)]);
        let owner = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        assert!(creator.prepare_recorded_rotation_at(&created.circle_id, &a.uid, RefreshRecordKind::Rotation, &alone, &owner, true, "n", NOW).is_ok());
    }

    /// Admin X ejects D at v3; admin C's v4 carries X pending (so v4 needs no
    /// match for X). Everyone listed as the owner A's invitations say.
    fn an_admins_eject_then_a_record_carrying_them() -> (Acct, Acct, Acct, Acct, Acct, History, Vec<RecordMember>) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, x, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xe1), Acct::new(0xd1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &x, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Pending, Admin)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let everyone = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            listed(&b),
            with(listed(&c), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&x), |m| m.listed_role = Some(CircleRole::Admin)),
            listed(&d),
        ];
        (a, b, x, d, c, h, everyone)
    }

    fn up_to(h: &History, version: u32) -> History {
        let mut part = h.clone();
        part.records.retain(|v, _| *v <= version);
        part
    }

    #[test]
    fn an_unknown_signer_is_never_passed_over_and_a_departed_one_is_found_unlisted() {
        // The server leaves X, the signer of v3 (its eject of D), off
        // B's list while v3 and v4 are imported. v4 carries X
        // pending, so only v3 needs X. Refusing v3 there and taking
        // v4 over it would drop D's removal for good. B took v2,
        // which includes X, with X's keys: v3 is judged by them (the
        // vouched keys), and X's own entry in it continues B's count:
        // v3 is taken, and its eject of D counts.
        let (a, b, x, d, c, h, everyone) = an_admins_eject_then_a_record_carrying_them();
        let without_x: Vec<RecordMember> = everyone.iter().filter(|m| m.user_id != x.uid).cloned().collect();
        let (device, _) = device_at(&b, &a, &up_to(&h, 2), &everyone, &[2]);
        give(&device, &h, 3);
        assert_eq!(state_of_version(&import(&device, &up_to(&h, 3), &without_x, true), 3), (Accepted, RecordProblem::None));
        give(&device, &h, 4);
        assert_eq!(state_of_version(&import(&device, &h, &without_x, true), 4), (Accepted, RecordProblem::None));
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = eligible(&device, &everyone, &d, purpose);
            assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{purpose:?}: {e:?}");
        }
        // X has really left: B, offline over v3 and v4, finds X among the rows
        // its app passes unlisted, with the keys the chain holds for X.
        let (device, _) = device_at(&b, &a, &up_to(&h, 2), &everyone, &[2]);
        give(&device, &h, 3);
        give(&device, &h, 4);
        let x_left: Vec<RecordMember> = everyone.iter().map(|m| if m.user_id == x.uid { with(m.clone(), |m| m.listed = false) } else { m.clone() }).collect();
        let report = import(&device, &h, &x_left, true);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None), "{:?}", report.versions);
        let e = eligible(&device, &x_left, &d, EligibilityPurpose::Deliver);
        assert!(!e.eligible && e.removed_at_version == Some(3), "{e:?}");
        // A record X signs after one that carries X only pending (v5 over v4):
        // no inclusion there vouches for X, so with no row it waits.
        use ChainRole::{Admin, Member, Owner};
        let mut later = h.clone();
        let v5 = rows(&later, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin)]);
        later.rotate(RecordKind::Rotation, &x, v5, None);
        let (device, _) = device_at(&b, &a, &up_to(&later, 2), &everyone, &[2]);
        for v in 3..=5 {
            give(&device, &later, v);
        }
        let report = import(&device, &later, &without_x, true);
        assert_eq!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 5), (Waiting, RecordProblem::SignerUnknown));
    }

    #[test]
    fn vouched_keys_are_kept_bound_and_read_fail_closed() {
        // B took v1-v2 (X included, listed and confirmed then) and
        // restarts. X's eject of D (v3) then comes with X off the
        // list and no row for X: the keys B kept at v2 find X after
        // a restart. A store without them (written by an older SDK),
        // a pair that doesn't give X's commitment, or one kept for
        // another version of the fact finds nobody, and v3 waits.
        let (_a, b, x, d, _c, h, everyone) = an_admins_eject_then_a_record_carrying_them();
        let without_x: Vec<RecordMember> = everyone.iter().filter(|m| m.user_id != x.uid).cloned().collect();
        let store = MemStore::default();
        let device = b.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        give(&device, &h, 2);
        assert_eq!(state_of_version(&import(&device, &up_to(&h, 2), &everyone, true), 2).0, Accepted);
        device.persist_keys().unwrap();
        let pins = stored_pins(&store);
        let x_key = format!("{VOUCHED_PREFIX}{CIRCLE}:{}", hex::encode(h.code(&x)));
        assert!(pins.contains_key(&x_key), "the keys B took X in with");
        let v3_after_a_restart = |pins: &HashMap<String, PinRecord>| {
            set_stored_pins(&store, pins);
            let device = restarted(&store);
            give(&device, &h, 3);
            let report = import(&device, &up_to(&h, 3), &without_x, true);
            (state_of_version(&report, 3), eligible(&device, &everyone, &d, EligibilityPurpose::Deliver).removed_at_version)
        };
        assert_eq!(v3_after_a_restart(&pins), ((Accepted, RecordProblem::None), Some(3)), "found; D's removal counts");
        let waits = ((Waiting, RecordProblem::SignerUnknown), None);
        let mut before = pins.clone();
        before.retain(|k, _| !k.starts_with(VOUCHED_PREFIX));
        assert_eq!(v3_after_a_restart(&before), waits, "a store without vouched keys");
        let mut other_pair = pins.clone();
        other_pair.get_mut(&x_key).unwrap().signing_pubkey_hex = hex::encode(Acct::new(0x5e).signing_pk());
        assert_eq!(v3_after_a_restart(&other_pair), waits, "a pair that doesn't give X's commitment");
        let mut other_version = pins.clone();
        other_version.get_mut(&x_key).unwrap().first_pinned_at += 1;
        assert_eq!(v3_after_a_restart(&other_version), waits, "kept for another version of the fact");
    }

    #[test]
    fn keys_older_than_the_ones_kept_find_nobody() {
        use ChainRole::{Admin, Member, Owner};
        // X is included at v2 with K1, then at v3 with K2 (a reset B
        // confirmed). v4 signed with K1 (a stolen old key) finds no signer:
        // the keys kept are K2's, and with no row that matches, it waits.
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let x1 = Acct::new(0xe1);
        let x2 = Acct { uid: x1.uid.clone(), signing: SigningKey::from_bytes(&[0xe9; 32]), sharing: StaticSecret::from([0xea; 32]) };
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x1, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x2, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x1, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &x1, v4, None);
        let list = |x: &Acct, statement: HeldStatement| {
            let mut members = four_members(&a, &b, &c, &d);
            members.push(with(x.member(), |m| (m.listed_role, m.statements) = (Some(CircleRole::Admin), vec![statement])));
            members
        };
        let (device, report) = device_at(&b, &a, &up_to(&h, 2), &list(&x1, a.invite(&x1, 1)), &[2]);
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        // X's new keys, admitted by the owner after v2.
        let after_reset = list(&x2, a.admit(&x2, 2));
        give(&device, &h, 3);
        assert_eq!(state_of_version(&import(&device, &up_to(&h, 3), &after_reset, true), 3).0, Accepted);
        give(&device, &h, 4);
        let report = import(&device, &h, &after_reset, true);
        assert_eq!(state_of_version(&report, 4), (Waiting, RecordProblem::SignerUnknown), "{:?}", report.versions);
    }

    #[test]
    fn an_entry_that_continues_this_devices_count_passes_with_no_row() {
        use ChainRole::{Admin, Member, Owner};
        // v3 by the owner A, everyone in; v4 by admin C, everyone in;
        // then C leaves, and the app passes no row for C.
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let everyone = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let v3 = everyone(&h);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = everyone(&h);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let without_c: Vec<RecordMember> = members.iter().filter(|m| m.user_id != c.uid).cloned().collect();
        // On time: B took v3 while C was listed, then imports v4. C is found by
        // the keys B kept, and C's own entry continues B's count.
        let (on_time, _) = device_at(&b, &a, &up_to(&h, 3), &members, &[2, 3]);
        give(&on_time, &h, 4);
        assert_eq!(state_of_version(&import(&on_time, &h, &without_c, true), 4), (Accepted, RecordProblem::None));
        // Late: B held v2 only, and imports v3 and v4 after C left. v3's entry
        // for C continues B's count, so v3 is taken, and then v4 as above.
        let (late, _) = device_at(&b, &a, &up_to(&h, 2), &members, &[2]);
        give(&late, &h, 3);
        give(&late, &h, 4);
        let report = import(&late, &h, &without_c, true);
        assert_eq!((state_of_version(&report, 3), state_of_version(&report, 4)), ((Accepted, RecordProblem::None), (Accepted, RecordProblem::None)));
        // A code this device doesn't count gets no pass: D, removed by the
        // owner at v5, included again at v6 with no row for D.
        let mut removed = h.clone();
        let v5 = rows(&removed, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        removed.rotate(RecordKind::Rotation, &a, v5, None);
        let v6 = everyone(&removed);
        removed.rotate(RecordKind::Rotation, &a, v6, None);
        let without_d: Vec<RecordMember> = members.iter().filter(|m| m.user_id != d.uid).cloned().collect();
        let (device, _) = device_at(&b, &a, &up_to(&removed, 5), &members, &[2, 3, 4, 5]);
        give(&device, &removed, 6);
        assert_eq!(state_of_version(&import(&device, &removed, &without_d, true), 6), (Rejected, RecordProblem::R2UnmatchedEntry));
        // Nor a code only carried here: a ghost only a record rejected here
        // included, carried pending by the repair, then included with no row.
        let ghost = Acct::new(0x66);
        let mut carried = h.clone();
        let v5 = [everyone(&carried), vec![carried.entry(&ghost, Included, Member)]].concat();
        carried.rotate(RecordKind::Rotation, &c, v5, None);
        let v6 = [everyone(&carried), vec![carried.entry(&ghost, Pending, Member)]].concat();
        carried.rotate(RecordKind::Repair, &a, v6, Some(5));
        let v7 = [everyone(&carried), vec![carried.entry(&ghost, Included, Member)]].concat();
        carried.rotate(RecordKind::Rotation, &a, v7, None);
        let (_, report) = device_at(&b, &a, &carried, &members, &[2, 3, 4, 5, 6, 7]);
        let states: Vec<(RecordVersionState, RecordProblem)> = (5..=7).map(|v| state_of_version(&report, v)).collect();
        assert_eq!(states[..2], [(Rejected, RecordProblem::R2UnmatchedEntry), (Accepted, RecordProblem::None)], "{:?}", report.versions);
        assert_eq!(states[2], (Rejected, RecordProblem::R2UnmatchedEntry));
    }

    #[test]
    fn kept_keys_find_no_signer_after_a_record_rejected_here() {
        use ChainRole::{Admin, Member, Owner};
        // X is included at v2 (B keeps X's keys). v3 by admin C
        // includes a ghost: rejected here. v4 is by X, who has left:
        // the record before it is rejected here, so the kept keys
        // don't find X, and v4 waits.
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let (x, ghost) = (Acct::new(0xe1), Acct::new(0x66));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&d, Included, Member), (&ghost, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&x, Included, Admin), (&d, Removed, Member), (&ghost, Departed, Member)]);
        h.rotate(RecordKind::Repair, &x, v4, Some(3));
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let members = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            listed(&b),
            with(listed(&c), |m| m.listed_role = Some(CircleRole::Admin)),
            with(listed(&x), |m| m.listed_role = Some(CircleRole::Admin)),
            listed(&d),
        ];
        let without_x: Vec<RecordMember> = members.iter().filter(|m| m.user_id != x.uid).cloned().collect();
        let (device, _) = device_at(&b, &a, &up_to(&h, 2), &members, &[2]);
        give(&device, &h, 3);
        give(&device, &h, 4);
        let report = import(&device, &h, &without_x, true);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Waiting, RecordProblem::SignerUnknown));
    }

    #[test]
    fn an_owner_claim_refused_on_the_listed_role_keeps_its_admin_removals() {
        // v3 by admin C: C names itself owner, removes the old
        // owner A, and ejects Y. v4 by C as owner.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, y) = (Acct::new(0xa2), Acct::new(0xb2), Acct::new(0xc2), Acct::new(0xd2), Acct::new(0xf2));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&y, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Removed, Member), (&b, Included, Member), (&c, Included, Owner), (&d, Included, Member), (&y, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&b, Included, Member), (&c, Included, Owner), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v4, None);
        let listed = |who: &Acct| with(who.member(), |m| m.statements = vec![a.invite(who, 1)]);
        let list = |c_role: CircleRole| {
            vec![
                with(a.member(), |m| (m.listed_role, m.listed) = (Some(CircleRole::Admin), c_role != CircleRole::Owner)),
                listed(&b),
                with(listed(&c), |m| m.listed_role = Some(c_role)),
                listed(&d),
                listed(&y),
            ]
        };
        // The list shows C as owner: the owner claim's record,
        // taken whole.
        let members = list(CircleRole::Owner);
        let (device, report) = device_at(&b, &a, &h, &members, &[2, 3, 4]);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted), "{:?}", report.versions);
        assert_eq!(eligible(&device, &members, &y, EligibilityPurpose::Include).removed_at_version, Some(3));
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Owner));
        // The list shows C as admin (the server's word): the claim is refused,
        // and with it the owner's removal and every role change; Y's removal,
        // which C may make as an admin, still counts, at v3.
        let members = list(CircleRole::Admin);
        let (device, report) = device_at(&b, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3).0, Rejected, "{:?}", report.versions);
        assert_ne!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = eligible(&device, &members, &y, purpose);
            assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{purpose:?}: {e:?}");
        }
        assert_eq!(device.chain_role(CIRCLE.into(), a.uid.clone()), Some(CircleRole::Owner));
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        assert_eq!(device.chain_role(CIRCLE.into(), y.uid.clone()), None);
        // A plain member's claim keeps nothing: B, not an admin, can't eject.
        let mut plain = up_to(&h, 2);
        let v3 = rows(&plain, &[(&a, Removed, Member), (&b, Included, Owner), (&c, Included, Admin), (&d, Included, Member), (&y, Removed, Member)]);
        plain.rotate(RecordKind::Rotation, &b, v3, None);
        let members = [&list(CircleRole::Admin)[..1], &[with(listed(&b), |m| m.listed_role = Some(CircleRole::Owner))], &list(CircleRole::Admin)[2..]].concat();
        let (device, report) = device_at(&d, &a, &plain, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Rejected, "{:?}", report.versions);
        let e = eligible(&device, &members, &y, EligibilityPurpose::Include);
        assert!(e.eligible && e.removed_at_version.is_none(), "{e:?}");
    }

    #[test]
    fn a_fork_candidate_that_cant_be_judged_is_never_passed_over() {
        // Two records for v3, served together: one whose signature
        // fails under its matched signer, or whose signer this device
        // can't match, stands here like any other, so the fork waits.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let mut eject = h.clone();
        let v3 = rows(&eject, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        eject.rotate(RecordKind::Rotation, &a, v3, None);
        let mut other = h.clone();
        other.keys.insert(3, [0x3c; 32]);
        let v3 = rows(&other, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        other.rotate(RecordKind::Rotation, &c, v3, None);
        let both = |first: &History, second: &History| -> Vec<SignedRefreshRecord> {
            first.signed().into_iter().chain(second.signed().into_iter().skip(2)).collect()
        };
        // The owner's eject with a byte of its signature spoiled,
        // beside admin C's v3 that keeps D: C's must not stand alone,
        // or D would stay in.
        let mut spoiled = eject.clone();
        spoiled.records.get_mut(&3).unwrap().1[0] ^= 1;
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &eject, 3);
        let report = device.import_refresh_records_at(CIRCLE, &both(&spoiled, &other), &eject.links, &members, true, None, &[], NOW).unwrap();
        assert!(report.forked, "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Fork));
        assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member), "nothing of either v3 taken");
        // The same beside a v3 whose signer this device can't match: it waits too.
        let stranger = Acct::new(0x5e);
        let mut unknown = h.clone();
        unknown.keys.insert(3, [0x3d; 32]);
        let v3 = rows(&unknown, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&stranger, Included, Member)]);
        unknown.rotate(RecordKind::Rotation, &stranger, v3, None);
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &eject, 3);
        let report = device.import_refresh_records_at(CIRCLE, &both(&eject, &unknown), &eject.links, &members, true, None, &[], NOW).unwrap();
        assert!(report.forked, "{:?}", report.versions);
        // A made-up v3 (the same body, another tag, a junk signature)
        // beside the real one: it isn't dropped for the real one to be
        // taken; the version stalls.
        let made_up = same_body_with_tag(&eject, 3, [0x77; 32], &a, true);
        let (device, _) = device_at(&b, &a, &h, &members, &[2]);
        give(&device, &eject, 3);
        let report = device.import_refresh_records_at(CIRCLE, &both(&eject, &made_up), &eject.links, &members, true, None, &[], NOW).unwrap();
        assert!(report.forked, "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Fork));
        // The removes rule never picks beside a candidate that can't
        // be judged: admin C's eject of D, spoiled, beside owner A's
        // valid v3 that removes C, served either way round.
        let mut c_eject = h.clone();
        let v3 = rows(&c_eject, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        c_eject.rotate(RecordKind::Rotation, &c, v3, None);
        let mut removes_c = h.clone();
        removes_c.keys.insert(3, [0x3c; 32]);
        let v3 = rows(&removes_c, &[(&a, Included, Owner), (&b, Included, Member), (&c, Removed, Admin), (&d, Included, Member)]);
        removes_c.rotate(RecordKind::Rotation, &a, v3, None);
        let mut c_spoiled = c_eject.clone();
        c_spoiled.records.get_mut(&3).unwrap().1[0] ^= 1;
        for served in [both(&c_spoiled, &removes_c), both(&removes_c, &c_spoiled)] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            give(&device, &c_eject, 3);
            let report = device.import_refresh_records_at(CIRCLE, &served, &c_eject.links, &members, true, None, &[], NOW).unwrap();
            assert!(report.forked, "{:?}", report.versions);
            assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Fork));
            assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin), "nothing of either v3 taken");
        }
    }

    #[test]
    fn e_a_counts_a_member_only_through_an_inclusion_accepted_here_with_their_keys() {
        use ChainRole::{Admin, Member, Owner};
        // Admin C's v3 includes a ghost no device allows (R2), and the
        // owner's repair v4 carries the ghost pending, or departed.
        // The ghost never gets in by (a), listed or not, on the
        // owner's device or B's.
        for carried in [Pending, Departed] {
            let (a, b, c, d, mut h) = four();
            let ghost = Acct::new(0x66);
            let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, Included, Member)]);
            h.rotate(RecordKind::Rotation, &c, v3, None);
            let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&ghost, carried, Member)]);
            h.rotate(RecordKind::Repair, &a, v4, Some(3));
            let listed = [four_members(&a, &b, &c, &d), vec![ghost.member()]].concat();
            let unlisted = [four_members(&a, &b, &c, &d), vec![with(ghost.member(), |m| m.listed = false)]].concat();
            let at_v4 = if carried == Pending { &listed } else { &unlisted };
            for who in [&a, &b] {
                let (device, report) = device_at(who, &a, &h, at_v4, &[2, 3, 4]);
                assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2NotAllowed));
                assert_eq!(state_of_version(&report, 4).0, Accepted);
                for members in [at_v4, &listed] {
                    for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
                        let e = eligible(&device, members, &ghost, purpose);
                        assert!(!e.eligible, "{carried:?} {purpose:?}: {e:?}");
                    }
                }
            }
        }
        // A known member with NEW keys in a record rejected here, carried
        // pending with them by the repair after it: those keys never count by (a).
        let (a, b, c, d, mut h) = four();
        let d_new = Acct { uid: d.uid.clone(), signing: SigningKey::from_bytes(&[0xd9; 32]), sharing: StaticSecret::from([0xda; 32]) };
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d_new, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d_new, Pending, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        let members = four_members(&a, &b, &c, &d);
        let (device, report) = device_at(&b, &a, &h, &members, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        let new_keys = [four_members(&a, &b, &c, &d)[..3].to_vec(), vec![d_new.member()]].concat();
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = eligible(&device, &new_keys, &d_new, purpose);
            assert!(!e.eligible, "{purpose:?}: {e:?}");
        }
        // A genuine carry: D included at v2, pending at v3 with the same keys.
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Pending, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&b, &a, &h, &members, &[2, 3]);
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            assert_eq!(eligible(&device, &members, &d, purpose).basis, Some(EligibilityBasis::CountedByChain), "{purpose:?}");
        }
    }

    #[test]
    fn a_pending_carry_doesnt_spend_an_invitation() {
        // The built vectors: on the owner's device r4 (admin C's,
        // including newcomer N) is rejected while N isn't confirmed
        // there, and the repair r5 carries N pending. Once A confirms
        // N, C's invitation (at v3) lets N in by (c), for a rotation
        // and, the server saying N holds no key, for a delivery.
        let f = WebBuilt::new(include_str!("../tests/data/refresh_record_v1_web_built.txt"));
        let lists = built_lists(&f);
        let unconfirmed_n = |list: &Vec<RecordMember>| {
            list.iter().map(|m| if m.user_id == f.uid("N") { with(m.clone(), |m| m.confirmed = false) } else { m.clone() }).collect::<Vec<_>>()
        };
        let a_lists = [lists[0].clone(), lists[1].clone(), lists[2].clone(), unconfirmed_n(&lists[3]), unconfirmed_n(&lists[4])];
        let (a, reports) = f.step_by_step(&a_lists);
        assert_eq!(state_of_version(&reports[4], 5).0, Accepted);
        let confirmed = lists[4].clone();
        let keyless = |list: &[RecordMember]| list.iter().map(|m| with(m.clone(), |m| m.server_says_keyless = true)).collect::<Vec<_>>();
        assert_eq!(f.eligibility(&a, &confirmed, "N", EligibilityPurpose::Include).basis, Some(EligibilityBasis::Invitation));
        assert_eq!(f.eligibility(&a, &keyless(&confirmed), "N", EligibilityPurpose::Deliver).basis, Some(EligibilityBasis::Invitation));
        // Its invitation expired (a week and the grace later): not until an
        // admission, made at or after r5.
        let later = f.now() + 8 * 24 * 3600;
        let at = |members: &[RecordMember], purpose| {
            a.refresh_eligibility_at(&f.circle(), members, purpose, later).unwrap().into_iter().find(|e| e.user_id == f.uid("N")).unwrap()
        };
        let e = at(&confirmed, EligibilityPurpose::Include);
        assert!(!e.eligible && e.invitation_expired, "{e:?}");
        let admitted: Vec<RecordMember> = confirmed
            .iter()
            .map(|m| if m.user_id == f.uid("N") { with(m.clone(), |m| m.statements.push(f.admission("A", "N", 5))) } else { m.clone() })
            .collect();
        assert_eq!(at(&admitted, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
    }

    #[test]
    fn a_removal_after_an_invitation_spends_it() {
        use ChainRole::{Admin, Member, Owner};
        // D, invited again by the owner at v3 (after its inclusion
        // at v2), is removed at v4: that invitation is spent by the
        // removal, and a later record carrying D pending is refused.
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v4, None);
        let mut carried = h.clone();
        let v5 = rows(&carried, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Pending, Member)]);
        carried.rotate(RecordKind::Rotation, &a, v5, None);
        let members = [four_members(&a, &b, &c, &d)[..3].to_vec(), vec![with(d.member(), |m| m.statements = vec![a.invite(&d, 3)])]].concat();
        let (device, report) = device_at(&b, &a, &carried, &members, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        assert_eq!(state_of_version(&report, 5), (Rejected, RecordProblem::Structure));
        let keyless: Vec<RecordMember> = members.iter().map(|m| with(m.clone(), |m| m.server_says_keyless = true)).collect();
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = eligible(&device, &keyless, &d, purpose);
            assert!(!e.eligible && e.removed_at_version == Some(4), "{purpose:?}: {e:?}");
        }
    }

    #[test]
    fn e_a_and_spent_invitations_read_fail_closed_from_a_store_without_them() {
        use ChainRole::{Admin, Member, Owner};
        // D included at v2, carried pending at v3 with the same keys: (a) holds.
        let (a, b, c, d, mut h) = four();
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Pending, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let members = four_members(&a, &b, &c, &d);
        let (_, store) = stored_device(&a, &h, &members);
        let pins = stored_pins(&store);
        let keyed = |pins: &HashMap<String, PinRecord>| pins.keys().filter(|k| k.starts_with(KEYED_PREFIX)).count();
        assert_eq!(keyed(&pins), 4, "a keyed entry for each fact");
        let basis = |device: &CryptoManager| eligible(device, &members, &d, EligibilityPurpose::Include).basis;
        // Written by this SDK, the keyed parts read back.
        assert_eq!(basis(&restarted(&store)), Some(EligibilityBasis::CountedByChain));
        // A store written by an older SDK: no keyed entries. D, pending, is not
        // counted by (a), and D's invitation (at v1) is judged at the fact's
        // version, v3: spent.
        let mut before = pins.clone();
        before.retain(|k, _| !k.starts_with(KEYED_PREFIX));
        set_stored_pins(&store, &before);
        let device = restarted(&store);
        let e = eligible(&device, &members, &d, EligibilityPurpose::Include);
        assert!(!e.eligible, "{e:?}");
        // Its next write keeps the fail-closed values: they round-trip.
        device.persist_keys().unwrap();
        assert_eq!(keyed(&stored_pins(&store)), 4);
        assert!(!eligible(&restarted(&store), &members, &d, EligibilityPurpose::Include).eligible);
        // After a downgrade, an older SDK keeps a keyed entry as a pin while
        // it rewrites the fact it was written with (another version or
        // commitment): the entry matches no fact, so D reads fail-closed,
        // never with the stale value.
        let downgraded = pins.clone();
        let fact_key = downgraded.keys().find(|k| k.starts_with(FACT_PREFIX) && k.ends_with(&hex::encode(h.code(&d)))).unwrap().clone();
        for rewrite in [|r: &mut PinRecord| r.first_pinned_at += 1, |r: &mut PinRecord| r.signing_pubkey_hex = hex::encode([0x5d; 32])] {
            let mut pins = downgraded.clone();
            rewrite(pins.get_mut(&fact_key).unwrap());
            set_stored_pins(&store, &pins);
            let device = restarted(&store);
            let fact = device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].facts[&h.code(&d)].clone();
            assert_eq!((fact.included_with_keys, fact.last_spent), (0, fact.version));
        }
    }

    #[test]
    fn an_unlisted_signer_is_found_only_through_an_inclusion_taken_here() {
        use ChainRole::{Admin, Member, Owner};
        // X, whom admin C's v3 includes, is refused here (R2) and only
        // carried pending by the owner's repair v4: never included
        // here. X signs v5. Passed unlisted with the carried keys, X is
        // not found as its signer: v5 waits (a carry vouches for
        // nothing). Listed, X is found, and v5 is judged as any record.
        let (a, b, c, d, mut h) = four();
        let x = Acct::new(0xe7);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Pending, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &x, v5, None);
        for (listed, want) in [(false, (Waiting, RecordProblem::SignerUnknown)), (true, (Rejected, RecordProblem::R2NotAllowed))] {
            let members = [four_members(&a, &b, &c, &d), vec![with(x.member(), |m| m.listed = listed)]].concat();
            let (_, report) = device_at(&b, &a, &h, &members, &[2, 3, 4, 5]);
            assert_eq!(state_of_version(&report, 3).0, Rejected);
            assert_eq!(state_of_version(&report, 4).0, Accepted);
            assert_eq!(state_of_version(&report, 5), want, "X listed: {listed}");
        }
    }

    #[test]
    fn a_carry_back_to_the_old_keys_never_brings_the_inclusion_back() {
        use ChainRole::{Admin, Member, Owner};
        // D is included at v2 with K1. A rejected tip (v3) names D
        // with K2 and the repair v4 carries D pending with K2; a
        // second rejected tip (v5) names D with K1 again, and the
        // repair v6 carries D pending with K1. The inclusion ended at
        // v4: D with K1 is not counted by (a), and their invitation is
        // spent.
        let (a, b, c, d, mut h) = four();
        let d_k2 = Acct { uid: d.uid.clone(), signing: SigningKey::from_bytes(&[0xd9; 32]), sharing: StaticSecret::from([0xda; 32]) };
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d_k2, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d_k2, Pending, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, Some(3));
        let v5 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &c, v5, None);
        let v6 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Pending, Member)]);
        h.rotate(RecordKind::Repair, &a, v6, Some(5));
        let members = four_members(&a, &b, &c, &d);
        let (device, report) = device_at(&b, &a, &h, &members, &[2, 3, 4, 5, 6]);
        let states: Vec<RecordVersionState> = (3..=6).map(|v| state_of_version(&report, v).0).collect();
        assert_eq!(states, vec![Rejected, Accepted, Rejected, Accepted], "{:?}", report.versions);
        for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
            let e = eligible(&device, &members, &d, purpose);
            assert!(!e.eligible, "{purpose:?}: {e:?}");
        }
    }

    #[test]
    fn a_record_that_does_not_verify_here_is_never_sent() {
        use RecordMemberState as S;
        // A signature that fails is never passed over, so a record
        // sent with one would freeze its version on every device. The
        // builder checks its own record first.
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (owner, _) = device_at(&a, &a, &h, &members, &[2]);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let before = (owner.get_active_version(CIRCLE.into()).unwrap(), owner.held_keys(CIRCLE).len());
        CORRUPT_NEXT_SIGNATURE.with(|corrupt| corrupt.set(true));
        let refused = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
        assert!(matches!(refused, Err(MobileError::CryptoError(_))), "{:?}", refused.map(|r| r.refresh_record.record_hex));
        // Nothing went out, and nothing changed here.
        assert_eq!((owner.get_active_version(CIRCLE.into()).unwrap(), owner.held_keys(CIRCLE).len()), before);
        assert!(owner.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].own.is_none());
        // A key tag made with another key, signed as it is: refused the same way.
        CORRUPT_NEXT_TAG.with(|corrupt| corrupt.set(true));
        let refused = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
        assert!(matches!(refused, Err(MobileError::CryptoError(_))), "{:?}", refused.map(|r| r.refresh_record.record_hex));
        assert_eq!((owner.get_active_version(CIRCLE.into()).unwrap(), owner.held_keys(CIRCLE).len()), before);
        // Signed as it should be, the same plan goes out, and a member takes it.
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).unwrap();
        let (records, links) = served_with(&h, &bundle);
        let (member, _) = device_at(&b, &a, &h, &members, &[2]);
        let key3 = owner.held_keys(CIRCLE).into_iter().find(|(v, _)| *v == 3).unwrap().1;
        assert!(member.add_verified_key(CIRCLE, 3, &key3));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        // A new circle's genesis the same way: refused, and the key made for it goes too.
        let creator = a.device();
        let reserved = uuid::Uuid::new_v4().to_string();
        CORRUPT_NEXT_SIGNATURE.with(|corrupt| corrupt.set(true));
        let refused = creator.prepare_recorded_circle_creation_at(&a.uid, &reserved, NOW);
        assert!(matches!(refused, Err(MobileError::CryptoError(_))), "{:?}", refused.map(|c| c.circle_id));
        assert!(!creator.has_circle_key(reserved.clone()) && !creator.circle_has_refresh_records(reserved.clone()));
        assert!(creator.prepare_recorded_circle_creation_at(&a.uid, &reserved, NOW).is_ok(), "the reserved id is still free here");
    }

    // ------------------------------------------------------------------
    // A listed member with no published keys
    // ------------------------------------------------------------------

    /// `acct` as listed with no keys published: None, and not confirmed.
    fn keyless(acct: &Acct) -> RecordMember {
        with(acct.member(), |m| {
            m.sharing_public_key_hex = None;
            m.signing_public_key_hex = None;
            m.confirmed = false;
        })
    }

    /// `acct` with both keys passed as all zeros, `confirmed` as given.
    fn zero_keys(acct: &Acct, confirmed: bool) -> RecordMember {
        with(acct.member(), |m| {
            m.sharing_public_key_hex = Some("00".repeat(32));
            m.signing_public_key_hex = Some("00".repeat(32));
            m.confirmed = confirmed;
        })
    }

    #[test]
    fn keyless_a_missing_or_all_zero_key_is_read_as_no_keys_and_never_confirmed() {
        let x = Acct::new(0xe1);
        let read = |m: RecordMember| Member::read(&m).unwrap();
        let none = read(keyless(&x));
        assert!(none.no_published_keys && !none.confirmed);
        assert_eq!((none.sharing, none.signing), ([0; 32], [0; 32]));
        let sharing_none = read(with(x.member(), |m| (m.sharing_public_key_hex, m.confirmed) = (None, false)));
        assert!(sharing_none.no_published_keys);
        let signing_none = read(with(x.member(), |m| (m.signing_public_key_hex, m.confirmed) = (None, false)));
        assert!(signing_none.no_published_keys);
        // All zeros: never a real key, and `confirmed` = true is overridden.
        let zeros = read(zero_keys(&x, true));
        assert!(zeros.no_published_keys && !zeros.confirmed, "confirmed = true is overridden");
        let sharing_zero = read(with(x.member(), |m| m.sharing_public_key_hex = Some("00".repeat(32))));
        assert!(sharing_zero.no_published_keys && !sharing_zero.confirmed);
        let signing_zero = read(with(x.member(), |m| m.signing_public_key_hex = Some("00".repeat(32))));
        assert!(signing_zero.no_published_keys && !signing_zero.confirmed);
        let real = read(x.member());
        assert!(!real.no_published_keys && real.confirmed);
    }

    #[test]
    fn keyless_a_member_confirmed_with_a_key_missing_fails_the_call() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let good = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &good, &[2]);
        let refused = |r: Result<(), MobileError>| matches!(r, Err(MobileError::InvalidInput(why)) if why.contains("confirmed with no keys"));
        let rows = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)]);
        for missing in [
            with(d.member(), |m| m.sharing_public_key_hex = None),
            with(d.member(), |m| m.signing_public_key_hex = None),
            with(d.member(), |m| (m.sharing_public_key_hex, m.signing_public_key_hex) = (None, None)),
        ] {
            let members = [&good[..3], &[missing]].concat();
            assert!(refused(device.refresh_eligibility_at(CIRCLE, &members, EligibilityPurpose::Include, NOW).map(|_| ())));
            assert!(refused(device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &[], NOW).map(|_| ())));
            assert!(refused(device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &rows, &members, true, "n", NOW).map(|_| ())));
        }
        // Not confirmed, the same list reads, and D is ejected under the chain's commitment.
        let members = [&good[..3], &[keyless(&d)]].concat();
        assert!(!eligible(&device, &members, &d, EligibilityPurpose::Include).eligible);
        device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &rows, &members, true, "n", NOW).unwrap();
    }

    #[test]
    fn keyless_a_listed_member_with_no_keys_counts_as_listed_and_nothing_more() {
        use ChainRole::{Admin, Member as Plain, Owner};
        let (a, b, c, d, mut h) = four();
        // v3: plain member B names D "departed", while D is off the list here.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Plain), (&c, Included, Admin), (&d, Departed, Plain)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let mut off_list = four_members(&a, &b, &c, &d);
        off_list[3].listed = false;
        let (device, report) = device_at(&a, &a, &h, &off_list, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        // Now listed again, with no keys published: D counts as listed (the seen
        // departure no longer counts), and nothing more. The same with zero keys
        // passed as confirmed.
        for listed_d in [keyless(&d), zero_keys(&d, true)] {
            let mut members = four_members(&a, &b, &c, &d);
            members[3] = with(listed_d, |m| m.statements = vec![a.admit(&d, 3)]);
            {
                let chains = device.refresh.read().unwrap();
                let chain = &chains[&CircleKey::of(CIRCLE)];
                let overlay = Overlay::new();
                let listed = read_members(&members).unwrap();
                let roles = RoleOverlay::new();
                let view = View { circle: circle16(), secret: chain.secret.as_ref().unwrap(), v0: 1, facts: &chain.facts, removed_overlay: &overlay, role_overlay: &roles, members: &listed, own: None };
                assert!(view.counts_code(&view.code_of(&d.uid16())), "listed: the seen departure doesn't count");
                let unlisted = read_members(&[with(keyless(&d), |m| m.listed = false)]).unwrap();
                let view = View { members: &unlisted, ..view };
                assert!(!view.counts_code(&view.code_of(&d.uid16())), "off the list, it does");
            }
            // An admission makes nobody with no keys eligible.
            let e = eligible(&device, &members, &d, EligibilityPurpose::Include);
            assert!(!e.eligible && e.basis.is_none(), "{e:?}");
            assert!(!eligible(&device, &members, &d, EligibilityPurpose::Deliver).eligible);
        }
    }

    #[test]
    fn keyless_a_transition_leaves_them_out_and_once_they_have_keys_only_b_or_c_brings_them_in() {
        use RecordMemberState as S;
        let (a, b, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xd1));
        let owner_row = with(a.member(), |m| m.listed_role = Some(CircleRole::Owner));
        // Owner A's transition leaves D, listed with no keys, out. B's device,
        // which lists D the same way, accepts it; the chain never named D.
        let listed = vec![owner_row.clone(), b.member(), keyless(&d)];
        let owner = legacy_device(&a, 4);
        let transition = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Transition,
                &plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member))]),
                &listed, true, "n", NOW,
            )
            .unwrap();
        let (records, links) = (vec![transition.refresh_record.clone()], vec![transition.rotation.key_chain_link.clone().unwrap()]);
        let key5 = open_wrap(&b, &transition.rotation);
        let member = b.device();
        assert!(member.add_verified_key(CIRCLE, 5, &key5));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &listed, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        assert_eq!(member.chain_role(CIRCLE.into(), d.uid.clone()), None, "neither dropped nor departed: never named");
        let report = owner.import_refresh_records_at(CIRCLE, &records, &links, &listed, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        // D publishes keys. Confirmed with them and nothing more, D can't be
        // included, by the builder or on another device.
        let bare = vec![owner_row.clone(), b.member(), d.member()];
        let include_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&d, S::Included, None)]);
        match owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &include_d, &bare, true, "n", NOW) {
            Err(MobileError::InvalidInput(why)) => assert!(why.contains("not eligible"), "{why}"),
            other => panic!("refused, got {:?}", other.map(|x| x.rotation.new_key_version)),
        }
        // (b) the owner's admission for D's keys, or (c) the owner's invitation: in.
        for statement in [a.admit(&d, 5), a.invite(&d, 5)] {
            let admitted = vec![owner_row.clone(), b.member(), with(d.member(), |m| m.statements = vec![statement.clone()])];
            let rotation = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &include_d, &admitted, true, "n", NOW).unwrap();
            assert_eq!(rotation.rotation.new_key_version, 6);
            let served = [records.clone(), vec![rotation.refresh_record.clone()]].concat();
            let served_links = [links.clone(), vec![rotation.rotation.key_chain_link.clone().unwrap()]].concat();
            let key6 = open_wrap(&b, &rotation.rotation);
            let at_v5 = |list: &[RecordMember]| {
                let device = b.device();
                assert!(device.add_verified_key(CIRCLE, 5, &key5));
                assert_eq!(state_of_version(&import_served(&device, &records, &links, list), 5).0, Accepted);
                assert!(device.add_verified_key(CIRCLE, 6, &key6));
                device
            };
            let other = at_v5(&admitted);
            assert_eq!(state_of_version(&import_served(&other, &served, &served_links, &admitted), 6).0, Accepted);
            assert_eq!(other.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member));
            // A device that holds no such statement for D refuses it.
            let unaware = at_v5(&bare);
            assert_eq!(state_of_version(&import_served(&unaware, &served, &served_links, &bare), 6), (Rejected, RecordProblem::R2NotAllowed));
            assert!(owner.discard_unconfirmed_rotation(CIRCLE.into()));
        }
    }

    fn import_served(device: &CryptoManager, records: &[SignedRefreshRecord], links: &[KeyChainLinkData], members: &[RecordMember]) -> RefreshRecordsReport {
        device.import_refresh_records_at(CIRCLE, records, links, members, true, None, &[], NOW).unwrap()
    }

    #[test]
    fn keyless_an_entry_is_never_matched_to_a_member_with_no_keys() {
        use ChainRole::{Member as Plain, Owner};
        // v2 includes X with a commitment over no keys (nobody honest writes one).
        let (a, b, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let code = h.code(&x);
        let zero = RecordEntry { code, state: Included, role: Plain, commitment: key_commitment(&h.secret, &code, &[0; 32], &[0; 32]) };
        let v2 = vec![h.entry(&a, Included, Owner), h.entry(&b, Included, Plain), zero];
        h.rotate(RecordKind::Rotation, &a, v2, None);
        for listed_x in [keyless(&x), zero_keys(&x, true)] {
            let members = vec![
                with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.statements = vec![a.invite(&b, 1)]),
                listed_x,
            ];
            let (_, report) = device_at(&b, &a, &h, &members, &[2]);
            assert_eq!(state_of_version(&report, 2), (Rejected, RecordProblem::R2UnmatchedEntry));
        }
    }

    #[test]
    fn keyless_the_accounts_own_head_never_vouches_for_a_member_with_no_keys() {
        use ChainRole::{Member as Plain, Owner};
        // A record that includes X with a commitment over no keys (nobody honest
        // writes one; a first device could take it at first sight).
        let (a, b, x) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xe1));
        let mut h = History::genesis(&a);
        let code = h.code(&x);
        let zero = RecordEntry { code, state: Included, role: Plain, commitment: key_commitment(&h.secret, &code, &[0; 32], &[0; 32]) };
        let v2 = vec![h.entry(&a, Included, Owner), h.entry(&b, Included, Plain), zero];
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version: 2, chain: h.records[&2].0.chain() };
        let bytes = head.encode().unwrap();
        let signed = SignedCircleHead {
            head_hex: hex::encode(bytes),
            signature_hex: hex::encode(a.signing.sign(&Head::digest(&bytes)).to_bytes()),
        };
        for listed_x in [keyless(&x), zero_keys(&x, false)] {
            let members = vec![
                with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.confirmed = false),
                listed_x,
            ];
            let device = a.device();
            give(&device, &h, 2);
            let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, Some(&signed), &[], NOW).unwrap();
            assert_eq!(state_of_version(&report, 2).0, Accepted);
            assert!(report.head_confirmed_members.contains(&b.uid), "B, with real keys, is vouched for");
            assert!(!report.head_confirmed_members.contains(&x.uid), "X, with no keys, never is");
        }
    }

    #[test]
    fn keyless_the_builder_never_names_a_member_with_no_keys_and_still_ejects_one() {
        use ChainRole::Member as Plain;
        use RecordMemberState as S;
        let (a, b, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xd1));
        // A transition: a member with no keys can be neither included nor pending.
        for listed_d in [keyless(&d), zero_keys(&d, true)] {
            let owner = legacy_device(&a, 4);
            let members = vec![with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)), b.member(), listed_d];
            let pending_d = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member)), (&d, S::Pending, Some(CircleRole::Member))]);
            match owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &pending_d, &members, true, "n", NOW) {
                Err(MobileError::InvalidInput(why)) => assert!(why.contains("no published keys"), "{why}"),
                other => panic!("refused, got {:?}", other.map(|b| b.rotation.new_key_version)),
            }
            let included_d = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member)), (&d, S::Included, Some(CircleRole::Member))]);
            assert!(owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &included_d, &members, true, "n", NOW).is_err());
            let without_d = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member))]);
            let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &without_d, &members, true, "n", NOW).unwrap();
            let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
            assert_eq!(record.body.entries.len(), 2);
        }
        // A rotation: a member the chain named, now listed with no keys, is still
        // carried (pending) or ejected (removed), under the chain's commitment.
        let (a, b, c, d, h) = four();
        let mut members = four_members(&a, &b, &c, &d);
        members[3] = keyless(&d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let eject_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)]);
        let bundle = device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &eject_d, &members, true, "n", NOW).unwrap();
        let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        let d_entry = record.body.entries.iter().find(|e| e.code == h.code(&d)).unwrap();
        assert_eq!((d_entry.state, d_entry.commitment), (Removed, h.entry(&d, Removed, Plain).commitment), "the chain's commitment, not zero keys");
        let carry_d = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Pending, None)]);
        assert!(device.discard_unconfirmed_rotation(CIRCLE.into()));
        device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &carry_d, &members, true, "n", NOW).unwrap();
    }

    #[test]
    fn keyless_a_keyless_listed_owner_means_no_transition() {
        use RecordMemberState as S;
        let (a, b) = (Acct::new(0xa1), Acct::new(0xb1));
        // Admin B's device would write the transition; the list's owner A has no keys.
        for listed_a in [keyless(&a), zero_keys(&a, true)] {
            let admin = legacy_device(&b, 4);
            let members = vec![
                with(listed_a, |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.listed_role = Some(CircleRole::Admin)),
            ];
            // Not with A left out and B named owner instead, nor any other way.
            for rows in [vec![(&b, S::Included, Some(CircleRole::Owner))], vec![(&b, S::Included, Some(CircleRole::Admin))]] {
                match admin.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Transition, &plan(&rows), &members, true, "n", NOW) {
                    Err(MobileError::InvalidInput(why)) => assert!(why.contains("owner has no published keys"), "{why}"),
                    other => panic!("refused, got {:?}", other.map(|x| x.rotation.new_key_version)),
                }
            }
            // Nothing written: no record, no new key, no rotation of its own.
            assert!(!admin.circle_has_refresh_records(CIRCLE.into()), "the circle stays legacy");
            let mut held: Vec<u32> = admin.held_keys(CIRCLE).iter().map(|(v, _)| *v).collect();
            held.sort();
            assert_eq!(held, vec![1, 2, 3, 4]);
            assert_eq!(admin.get_active_version(CIRCLE.into()).unwrap(), 4);
            assert!(!admin.discard_unconfirmed_rotation(CIRCLE.into()));
            // Once the owner has keys, the transition can be written.
            let members = vec![
                with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)),
                with(b.member(), |m| m.listed_role = Some(CircleRole::Admin)),
            ];
            let rows = plan(&[(&a, S::Pending, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Admin))]);
            admin.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Transition, &rows, &members, true, "n", NOW).unwrap();
        }
    }

    // ------------------------------------------------------------------
    // The builder fills in members the app can't name
    // ------------------------------------------------------------------

    fn parsed(bundle: &RecordedRotationBundle) -> WireRecord {
        WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap()
    }

    /// `acct`'s own head at `version` of `h`, as the server serves it.
    fn head_by(acct: &Acct, h: &History, version: u32) -> SignedCircleHead {
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: acct.uid16(), version, chain: h.records[&version].0.chain() };
        let bytes = head.encode().unwrap();
        SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(acct.signing.sign(&Head::digest(&bytes)).to_bytes()) }
    }

    /// `who`'s device, at v2 of four() with the whole list then, given the new
    /// key of `bundle` and served it with the list `now`: its report.
    fn served_to(who: &Acct, a: &Acct, h: &History, then: &[RecordMember], now: &[RecordMember], bundle: &RecordedRotationBundle) -> (Arc<CryptoManager>, RefreshRecordsReport) {
        let (device, report) = device_at(who, a, h, then, &[2]);
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        assert!(device.add_verified_key(CIRCLE, 3, &open_wrap(who, &bundle.rotation)));
        let (records, links) = served_with(h, bundle);
        let report = device.import_refresh_records_at(CIRCLE, &records, &links, now, true, None, &[], NOW).unwrap();
        (device, report)
    }

    #[test]
    fn a_fresh_install_fills_in_a_departure_it_never_saw() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let all = four_members(&a, &b, &c, &d);
        // D left before this install of A existed: off its list, no user id
        // held. It takes the chain up to the account's own head.
        let without_d = all[..3].to_vec();
        let fresh = a.device();
        give(&fresh, &h, 1);
        give(&fresh, &h, 2);
        let report = fresh.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &without_d, true, Some(&head_by(&a, &h, 2)), &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        let abc = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let bundle = fresh.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &abc, &without_d, true, "n", NOW).unwrap();
        let record = parsed(&bundle);
        assert_eq!(record.body.entries.len(), 4);
        let filled = record.body.entry(&h.code(&d)).unwrap();
        assert_eq!((filled.state, filled.role, filled.commitment), (Departed, ChainRole::Member, h.entry(&d, Departed, ChainRole::Member).commitment));
        // Accepted by other devices. The departure counts only where D is off the list.
        let d_off = [&without_d[..], &[with(all[3].clone(), |m| m.listed = false)]].concat();
        let (b_device, report) = served_to(&b, &a, &h, &all, &without_d, &bundle);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        let e = eligible(&b_device, &d_off, &d, EligibilityPurpose::Include);
        assert!(!e.eligible, "off B's list: the departure counts: {e:?}");
        let (c_device, report) = served_to(&c, &a, &h, &all, &all, &bundle);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        let e = eligible(&c_device, &all, &d, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (true, Some(EligibilityBasis::CountedByChain)), "on C's list: still counted");
    }

    #[test]
    fn a_plain_members_device_carries_a_departed_admin_as_pending() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let all = four_members(&a, &b, &c, &d);
        // Admin C and plain member D leave after v2.
        let ab = all[..2].to_vec();
        let plan_ab = plan(&[(&a, S::Included, None), (&b, S::Included, None)]);
        let state_role = |record: &WireRecord, who: &Acct| {
            let entry = record.body.entry(&h.code(who)).unwrap();
            (entry.state, entry.role, entry.commitment)
        };
        // Plain member B's device: C pending (an admin's
        // departure can't count in a plain member's record), D
        // departed; roles and commitments carried.
        let (member, _) = device_at(&b, &a, &h, &all, &[2]);
        let bundle = member.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &plan_ab, &ab, true, "n", NOW).unwrap();
        let record = parsed(&bundle);
        assert_eq!(state_role(&record, &c), (Pending, ChainRole::Admin, h.entry(&c, Pending, ChainRole::Admin).commitment));
        assert_eq!(state_role(&record, &d), (Departed, ChainRole::Member, h.entry(&d, Departed, ChainRole::Member).commitment));
        let (_, report) = served_to(&a, &a, &h, &all, &ab, &bundle);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        // The owner's device writes both as departed.
        let (owner, _) = device_at(&a, &a, &h, &all, &[2]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &plan_ab, &ab, true, "n", NOW).unwrap();
        let record = parsed(&bundle);
        assert_eq!(state_role(&record, &c).0, Departed);
        assert_eq!(state_role(&record, &c).1, ChainRole::Admin);
        assert_eq!(state_role(&record, &d).0, Departed);
        let (_, report) = served_to(&b, &a, &h, &all, &ab, &bundle);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
    }

    #[test]
    fn a_listed_member_the_plan_leaves_out_is_refused_never_written_departed() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (owner, _) = device_at(&a, &a, &h, &members, &[2]);
        let missing = |plan_rows: &[(&Acct, RecordMemberState, Option<CircleRole>)], list: &[RecordMember]| {
            match owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &plan(plan_rows), list, true, "n", NOW) {
                Err(MobileError::InvalidInput(why)) => assert!(why.contains("missing from the plan"), "{why}"),
                other => panic!("refused, got {:?}", other.map(|x| x.rotation.new_key_version)),
            }
        };
        let abc = [(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)];
        // D is listed.
        missing(&abc, &members);
        // Listed with a row that doesn't read (a key that isn't 32 bytes): still listed.
        missing(&abc, &[&members[..3], &[with(members[3].clone(), |m| m.sharing_public_key_hex = Some("00".repeat(31)))]].concat());
        // Listed with no keys: still listed.
        missing(&abc, &[&members[..3], &[keyless(&d)]].concat());
        // This account itself, even when the app doesn't list it.
        missing(&[(&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)], &members[1..]);
        assert!(!owner.discard_unconfirmed_rotation(CIRCLE.into()), "nothing built");
    }

    #[test]
    fn without_a_complete_roster_nothing_is_filled_and_the_plan_is_refused() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let all = four_members(&a, &b, &c, &d);
        let without_d = all[..3].to_vec();
        let (owner, _) = device_at(&a, &a, &h, &all, &[2]);
        let abc = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        match owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &abc, &without_d, false, "n", NOW) {
            Err(MobileError::InvalidInput(why)) => assert!(why.contains("Structure"), "nobody is dropped silently: {why}"),
            other => panic!("refused, got {:?}", other.map(|x| x.rotation.new_key_version)),
        }
        // Naming D (as an app can when it holds D's user id) needs no fill.
        let named = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Departed, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &named, &without_d, false, "n", NOW).unwrap();
        assert_eq!(parsed(&bundle).body.entry(&h.code(&d)).unwrap().state, Departed);
    }

    #[test]
    fn an_own_eject_still_names_removed_by_user_id() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let all = four_members(&a, &b, &c, &d);
        // Owner A ejects D, by user id; B left after v2, unseen.
        let mut without_b = all.clone();
        without_b.remove(1);
        let (owner, _) = device_at(&a, &a, &h, &all, &[2]);
        let eject_d = plan(&[(&a, S::Included, None), (&c, S::Included, None), (&d, S::Removed, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &eject_d, &without_b, true, "n", NOW).unwrap();
        let record = parsed(&bundle);
        assert_eq!(record.body.entry(&h.code(&d)).unwrap().state, Removed, "the app's own eject");
        assert_eq!(record.body.entry(&h.code(&b)).unwrap().state, Departed, "filled, never removed");
        let (_, report) = served_to(&c, &a, &h, &all, &without_b, &bundle);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
    }

    #[test]
    fn a_member_the_record_before_carried_pending_is_filled_too() {
        use ChainRole::{Admin, Member as Plain, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let all = four_members(&a, &b, &c, &d);
        // v3 carries D pending; then D leaves.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Plain), (&c, Included, Admin), (&d, Pending, Plain)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let (owner, report) = device_at(&a, &a, &h, &all, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        let without_d = all[..3].to_vec();
        let abc = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &abc, &without_d, true, "n", NOW).unwrap();
        assert_eq!(parsed(&bundle).body.entry(&h.code(&d)).map(|e| e.state), Some(Departed));
        // On another device, a record that drops a member carried pending is refused.
        let mut dropped = h.clone();
        let v4 = rows(&dropped, &[(&a, Included, Owner), (&b, Included, Plain), (&c, Included, Admin)]);
        dropped.rotate(RecordKind::Rotation, &a, v4, None);
        let (_, report) = device_at(&b, &a, &dropped, &all, &[2, 3, 4]);
        assert_eq!((state_of_version(&report, 2).0, state_of_version(&report, 3).0), (Accepted, Accepted));
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::Structure));
    }

    // ------------------------------------------------------------------
    // A transition's plan is held to the list it's given
    // ------------------------------------------------------------------

    #[test]
    fn a_transition_records_the_list_as_it_is() {
        use CircleRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        // A owner, B member, C admin, D member.
        let listed = four_members(&a, &b, &c, &d);
        let as_listed = [(&a, S::Included, Some(Owner)), (&b, S::Included, Some(Member)), (&c, S::Included, Some(Admin)), (&d, S::Pending, Some(Member))];
        let refused = |writer: &Acct, rows: &[(&Acct, RecordMemberState, Option<CircleRole>)], list: &[RecordMember], complete: bool, why: &str| {
            let device = legacy_device(writer, 4);
            match device.prepare_recorded_rotation_at(CIRCLE, &writer.uid, RefreshRecordKind::Transition, &plan(rows), list, complete, "n", NOW) {
                Err(MobileError::InvalidInput(got)) => assert!(got.contains(why), "{why}: {got}"),
                other => panic!("refused ({why}), got {:?}", other.map(|x| x.rotation.new_key_version)),
            }
            assert!(!device.circle_has_refresh_records(CIRCLE.into()), "nothing written");
        };
        let role_as_listed = "role as the list shows it";
        // Someone else named owner: admin C's device names itself owner.
        refused(&c, &[(&a, S::Included, Some(Admin)), (&b, S::Included, Some(Member)), (&c, S::Included, Some(Owner)), (&d, S::Pending, Some(Member))], &listed, true, role_as_listed);
        // A listed member promoted to admin.
        refused(&a, &[(&a, S::Included, Some(Owner)), (&b, S::Included, Some(Admin)), (&c, S::Included, Some(Admin)), (&d, S::Pending, Some(Member))], &listed, true, role_as_listed);
        // A role left out is "member": C is listed admin, and the owner is never
        // recorded as a member.
        refused(&a, &[(&a, S::Included, Some(Owner)), (&b, S::Included, Some(Member)), (&c, S::Included, None), (&d, S::Pending, Some(Member))], &listed, true, role_as_listed);
        refused(&a, &[(&a, S::Included, None), (&b, S::Included, Some(Member)), (&c, S::Included, Some(Admin)), (&d, S::Pending, Some(Member))], &listed, true, role_as_listed);
        refused(&c, &[(&a, S::Pending, None), (&b, S::Included, Some(Member)), (&c, S::Included, Some(Admin)), (&d, S::Pending, Some(Member))], &listed, true, role_as_listed);
        // Not the complete roster.
        refused(&a, &as_listed, &listed, false, "complete roster");
        // A listed member with keys left out.
        refused(&a, &as_listed[..3], &listed, true, "a listed member is missing");
        // Someone who isn't on the list.
        let x = Acct::new(0xe1);
        let off_list = [&listed[..], &[with(x.member(), |m| m.listed = false)]].concat();
        refused(&a, &[&as_listed[..], &[(&x, S::Pending, Some(Member))]].concat(), &off_list, true, "only members on the list");
        // A member with no keys is the one omission allowed.
        let keyless_d = [&listed[..3], &[keyless(&d)]].concat();
        legacy_device(&a, 4)
            .prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &plan(&as_listed[..3]), &keyless_d, true, "n", NOW)
            .unwrap();
        // The roles exactly as listed: built, and accepted by other devices.
        let bundle = legacy_device(&a, 4)
            .prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &plan(&as_listed), &listed, true, "n", NOW)
            .unwrap();
        let other = b.device();
        assert!(other.add_verified_key(CIRCLE, 5, &open_wrap(&b, &bundle.rotation)));
        let report = import_served(&other, &[bundle.refresh_record.clone()], &[bundle.rotation.key_chain_link.clone().unwrap()], &listed);
        assert_eq!(state_of_version(&report, 5).0, Accepted);
        let role = |who: &Acct| other.chain_role(CIRCLE.into(), who.uid.clone());
        assert_eq!((role(&a), role(&b), role(&c), role(&d)), (Some(Owner), Some(Member), Some(Admin), Some(Member)));
    }

    // ------------------------------------------------------------------
    // This account's own head, compared like a member's
    // ------------------------------------------------------------------

    #[test]
    fn the_accounts_own_head_goes_through_the_head_comparison() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let head_under = |key: &SigningKey, version: u32, chain: [u8; 32]| {
            let bytes = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version, chain }.encode().unwrap();
            SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(key.sign(&Head::digest(&bytes)).to_bytes()) }
        };
        let diverged = head_under(&a.signing, 2, [0x2d; 32]);
        let import = |device: &CryptoManager, own: &SignedCircleHead, heads: &[MemberHead]| {
            device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, Some(own), heads, NOW).unwrap()
        };
        let (device, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        // The same chain: nothing. A version not seen here: nothing.
        assert!(!import(&device, &head_by(&a, &h, 3), &[]).forked);
        assert!(!import(&device, &head_under(&a.signing, 9, [0x2d; 32]), &[]).forked);
        // Another chain value at v2 under an OLD key of this account: no evidence.
        assert!(!import(&device, &head_under(&SigningKey::from_bytes(&[0x77; 32]), 2, [0x2d; 32]), &[]).forked);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 3);
        // Under the CURRENT key: a fork. Nothing is sealed, and it stays when
        // the same head as ours is served next.
        let report = import(&device, &diverged, &[]);
        assert!(report.forked);
        assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing is sealed");
        assert!(import(&device, &head_by(&a, &h, 3), &[]).forked, "latched");
        // The same head also among the member heads (the app passes it twice):
        // one fork, reported the same way as once.
        let own_row = MemberHead { user_id: a.uid.clone(), head: diverged.clone() };
        let (once, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        let (twice, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        let (once, twice) = (import(&once, &diverged, &[]), import(&twice, &diverged, &[own_row.clone()]));
        assert!(once.forked && twice.forked);
        assert_eq!(format!("{:?}", once.versions), format!("{:?}", twice.versions));
        assert_eq!((once.sealing_version, twice.sealing_version), (None, None));
        // And a head that agrees, passed twice: no fork.
        let (agrees, _) = device_at(&a, &a, &h, &members, &[2, 3]);
        let same = head_by(&a, &h, 3);
        assert!(!import(&agrees, &same, &[MemberHead { user_id: a.uid.clone(), head: same.clone() }]).forked);
    }

    // ------------------------------------------------------------------
    // The held-copy check acts only on a record taken here with its
    // signature verified, since only the signature covers the key tag
    // ------------------------------------------------------------------

    /// `h`'s record for `version`, served with another key tag and a junk
    /// signature: the same body, so the same chain value.
    fn with_junk_tag(h: &History, version: u32) -> SignedRefreshRecord {
        let mut bytes = h.records[&version].0.to_bytes();
        let n = bytes.len();
        bytes[n - 32..].copy_from_slice(&[0x42; 32]);
        SignedRefreshRecord { record_hex: hex::encode(bytes), signature_hex: hex::encode([0x11u8; 64]) }
    }

    #[test]
    fn a_record_made_up_for_a_version_never_drops_the_held_key_or_refuses_the_real_copy() {
        let a = Acct::new(0xa1);
        let owner = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        let genesis = History::genesis(&a);
        let mut real = genesis.clone();
        let v2 = vec![real.entry(&a, Included, ChainRole::Owner)];
        real.rotate(RecordKind::Rotation, &a, v2, None);
        // The server makes up v2: linked to v1, with a tag over another key and a junk signature.
        let mut fake = genesis.clone();
        fake.keys.insert(2, [0x99; 32]);
        let v2 = vec![fake.entry(&a, Included, ChainRole::Owner)];
        fake.rotate(RecordKind::Rotation, &a, v2, None);
        fake.records.get_mut(&2).unwrap().1 = [0x11; 64];
        let held_v2 = |device: &CryptoManager| device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 2 && k.as_slice() == real.keys[&2]);
        // A device holding the real v2 key: the record is rejected, and the key stays.
        let (device, _) = device_at(&a, &a, &genesis, &owner, &[]);
        assert!(device.add_verified_key(CIRCLE, 2, &real.keys[&2]));
        let report = import(&device, &fake, &owner, true);
        assert_eq!(state_of_version(&report, 2), (Waiting, RecordProblem::Signature));
        assert!(held_v2(&device), "the held v2 key is kept");
        assert!(!report.ask_for_fresh_copy);
        // The real record, served next, is accepted with it.
        assert_eq!(state_of_version(&import(&device, &real, &owner, true), 2).0, Accepted);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        // A device without it: the real copy, arriving after the made-up record, is taken.
        let (device, _) = device_at(&a, &a, &genesis, &owner, &[]);
        assert_eq!(state_of_version(&import(&device, &fake, &owner, true), 2), (Waiting, RecordProblem::Signature));
        own_copy(&device, &a, 2, &real.keys[&2]).unwrap();
        assert!(held_v2(&device));
        assert_eq!(state_of_version(&import(&device, &real, &owner, true), 2).0, Accepted);
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    #[test]
    fn a_record_someone_uncounted_signed_drops_nothing() {
        // X, whom this device confirms but the chain never counted, signs a v2
        // with a tag over another key. The signature verifies; R2 refuses it.
        let (a, x) = (Acct::new(0xa1), Acct::new(0xe1));
        let members = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner)), x.member()];
        let genesis = History::genesis(&a);
        let mut fake = genesis.clone();
        fake.keys.insert(2, [0x99; 32]);
        let v2 = vec![fake.entry(&a, Included, ChainRole::Owner), fake.entry(&x, Included, ChainRole::Member)];
        fake.rotate(RecordKind::Rotation, &x, v2, None);
        let (device, _) = device_at(&a, &a, &genesis, &members, &[]);
        assert!(device.add_verified_key(CIRCLE, 2, &key_of(2)));
        let report = import(&device, &fake, &members, true);
        assert_eq!(state_of_version(&report, 2), (Rejected, RecordProblem::R2NotAllowed));
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 2 && k.as_slice() == key_of(2)), "kept");
        assert!(!report.ask_for_fresh_copy);
    }

    #[test]
    fn a_copy_of_a_taken_record_with_another_tag_does_not_displace_it() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // v2 taken as the reference: no copy of its key yet.
        let (device, report) = device_at(&a, &a, &h, &members, &[]);
        assert_eq!(state_of_version(&report, 2), (Reference, RecordProblem::None));
        // The server serves v2's body again, with another tag and a junk signature.
        let mut served = h.signed();
        served[1] = with_junk_tag(&h, 2);
        let report = device.import_refresh_records_at(CIRCLE, &served, &h.links, &members, true, None, &[], NOW).unwrap();
        assert!(!report.forked && !report.ask_for_fresh_copy);
        // The real key still opens the record this device took.
        own_copy(&device, &a, 2, &h.keys[&2]).unwrap();
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    #[test]
    fn a_record_taken_on_first_sight_drops_nothing_and_opens_only_with_its_tag() {
        // A first device takes v1-v2 on first sight; v2's signer is nobody it
        // can match, and its tag is over another key than the one held.
        let (a, x) = (Acct::new(0xa1), Acct::new(0xe1));
        let owner = [with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))];
        let mut h = History::genesis(&a);
        h.keys.insert(2, [0x99; 32]);
        let v2 = vec![h.entry(&a, Included, ChainRole::Owner), h.entry(&x, Included, ChainRole::Member)];
        h.rotate(RecordKind::Rotation, &x, v2, None);
        let device = a.device();
        give(&device, &h, 1);
        assert!(device.add_verified_key(CIRCLE, 2, &key_of(2)));
        let report = import(&device, &h, &owner, true);
        assert!(report.versions.iter().all(|r| r.state != Rejected), "{:?}", report.versions);
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 2 && k.as_slice() == key_of(2)), "kept");
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 1, "a copy that fails v2's tag opens nothing");
    }

    #[test]
    fn after_a_restart_a_record_taken_unverified_vouches_once_its_signature_verifies() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // A first device takes v1-v2 on first sight: A, who signed both, is not
        // confirmed here yet, so nothing vouches and no tag is kept.
        let device = d.device();
        let store = MemStore::default();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        let report = import(&device, &h, &unconfirmed(&members, &a), true);
        assert_eq!(state_of_version(&report, 2), (Reference, RecordProblem::None));
        assert_eq!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&2].kept, None);
        device.persist_keys().unwrap();
        // After a restart, with A confirmed now, a wrong copy of v2 gets in.
        let restarted = restarted(&store);
        assert!(restarted.add_verified_key(CIRCLE, 2, &[0x99; 32]));
        // v2's body again with another tag: it vouches for nothing, and drops nothing.
        let mut served = h.signed();
        served[1] = with_junk_tag(&h, 2);
        let report = restarted.import_refresh_records_at(CIRCLE, &served, &h.links, &members, true, None, &[], NOW).unwrap();
        assert!(!report.ask_for_fresh_copy);
        assert!(restarted.held_keys(CIRCLE).iter().any(|(v, _)| *v == 2));
        // The record itself, its signature verified now: the wrong copy goes, its
        // tag is kept from now on, and the right copy opens it.
        let report = import(&restarted, &h, &members, true);
        assert!(report.ask_for_fresh_copy);
        assert!(restarted.held_keys(CIRCLE).iter().all(|(v, _)| *v != 2), "the wrong copy is dropped");
        assert!(restarted.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&2].kept.is_some());
        own_copy(&restarted, &d, 2, &h.keys[&2]).unwrap();
        assert_eq!(restarted.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    // ------------------------------------------------------------------
    // The kept tag: what vouched for a version's key here still does
    // after a restart
    // ------------------------------------------------------------------

    /// `members` with `acct`'s row no longer confirmed (they reset their keys).
    fn unconfirmed(members: &[RecordMember], acct: &Acct) -> Vec<RecordMember> {
        members.iter().map(|m| if m.user_id == acct.uid { with(m.clone(), |m| m.confirmed = false) } else { m.clone() }).collect()
    }

    /// D's device holding v2 of `h` (by A) as its reference, verified, with no
    /// copy of its key: its store.
    fn kept_reference(a: &Acct, d: &Acct, h: &History, members: &[RecordMember]) -> (Arc<CryptoManager>, MemStore) {
        let device = d.device();
        let store = MemStore::default();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, h, 1);
        let mut genesis_only = History::genesis(a);
        genesis_only.links.clear();
        import(&device, &genesis_only, members, true);
        assert_eq!(state_of_version(&import(&device, h, members, true), 2), (Reference, RecordProblem::None));
        device.persist_keys().unwrap();
        (device, store)
    }

    #[test]
    fn kept_the_tag_of_a_verified_record_still_decides_after_a_restart_whoever_signed_it() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = kept_reference(&a, &d, &h, &members);
        let wrong = [0x99u8; 32];
        // A wrong copy of v2 is refused before a restart, after one
        // with A confirmed, and after one with A no longer confirmed,
        // before any record is served again.
        assert!(device.copy_contradicts_record(CIRCLE, 2, &wrong));
        let restarted = restarted(&store);
        assert!(restarted.copy_contradicts_record(CIRCLE, 2, &wrong));
        let a_reset = unconfirmed(&members, &a);
        // A wrong copy that got in is dropped on the next import, with nothing served.
        assert!(restarted.add_verified_key(CIRCLE, 2, &wrong));
        let report = restarted.import_refresh_records_at(CIRCLE, &[], &[], &a_reset, true, None, &[], NOW).unwrap();
        assert!(report.ask_for_fresh_copy);
        assert!(restarted.held_keys(CIRCLE).iter().all(|(v, _)| *v != 2), "dropped");
        // v2's body served again with another tag, A unconfirmed: it vouches for
        // nothing, and the kept tag still refuses the wrong copy.
        let mut served = h.signed();
        served[1] = with_junk_tag(&h, 2);
        restarted.import_refresh_records_at(CIRCLE, &served, &h.links, &a_reset, true, None, &[], NOW).unwrap();
        assert!(!restarted.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].seen[&2].vouches_for_its_tag());
        assert!(restarted.copy_contradicts_record(CIRCLE, 2, &wrong));
        // The right copy is taken, and it opens v2 by the kept tag.
        own_copy(&restarted, &d, 2, &h.keys[&2]).unwrap();
        assert_eq!(restarted.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    #[test]
    fn kept_tags_are_stored_bound_to_their_step_and_never_pins() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = kept_reference(&a, &d, &h, &members);
        let pins: HashMap<String, PinRecord> = serde_json::from_str(&stored(&store).pinned_keys_json.unwrap()).unwrap();
        let kept_key = format!("{HISTORY_PREFIX}{CIRCLE}:2{KEPT_TAG_SUFFIX}");
        let v2 = &h.records[&2].0;
        let kept = &pins[&kept_key];
        assert_eq!(
            (kept.sharing_pubkey_hex.clone(), kept.signing_pubkey_hex.clone(), kept.first_pinned_at),
            (hex::encode(v2.key_tag), hex::encode(v2.digest), 2)
        );
        assert!(is_refresh_key(&kept_key));
        assert!(!device.export_member_pins(d.uid.clone()).unwrap().contains(KEPT_TAG_SUFFIX));
        let reloaded = restarted(&store);
        assert_eq!(reloaded.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&2].kept, Some(KeptTag::of(v2)));
        // One whose digest doesn't give its step's chain value is dropped on load.
        let mut tampered = pins.clone();
        tampered.get_mut(&kept_key).unwrap().signing_pubkey_hex = hex::encode([0x5a; 32]);
        let other = MemStore::default();
        let mut blob = stored(&store);
        blob.pinned_keys_json = Some(serde_json::to_string(&tampered).unwrap());
        *other.0.lock().unwrap() = Some(blob);
        let reloaded = restarted(&other);
        let chains = reloaded.refresh.read().unwrap();
        assert_eq!(chains[&CircleKey::of(CIRCLE)].history[&2].kept, None);
        assert_eq!(chains[&CircleKey::of(CIRCLE)].history[&1].kept, Some(KeptTag::of(&h.records[&1].0)));
    }

    #[test]
    fn kept_a_made_up_tag_and_a_wrap_never_open_a_reference() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // A first device takes v1-v2 on first sight, A not confirmed here: v2 is
        // its reference, and nothing vouches for it.
        let device = d.device();
        let store = MemStore::default();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        assert_eq!(state_of_version(&import(&device, &h, &unconfirmed(&members, &a), true), 2), (Reference, RecordProblem::None));
        device.persist_keys().unwrap();
        // After a restart the server serves v2's body with a tag made for K', and
        // a member left pending by E wraps K' for v2.
        let restarted = restarted(&store);
        let k_prime = [0x77u8; 32];
        let mut made_up = h.clone();
        made_up.keys.insert(2, k_prime);
        let body = h.records[&2].0.body.clone();
        made_up.records.remove(&2);
        made_up.push(RecordKind::Rotation, 2, 1, h.records[&1].0.chain(), 1, &a, body.entries.clone());
        made_up.records.get_mut(&2).unwrap().1 = [0x11; 64];
        restarted.import_refresh_records_at(CIRCLE, &made_up.signed(), &h.links, &unconfirmed(&members, &a), true, None, &[], NOW).unwrap();
        own_copy(&restarted, &d, 2, &k_prime).unwrap();
        // Its tag matches K', but nothing vouches for v2 here: never sealed under.
        assert!(restarted.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].seen[&2].wire.key_tag_matches(&k_prime));
        assert_eq!(restarted.get_active_version(CIRCLE.into()).unwrap(), 1);
    }

    #[test]
    fn kept_a_settled_fork_takes_the_replaced_steps_tag_with_it() {
        let (a, b, c, x, real, fork) = real_and_fork();
        let members = listed_with_x(&a, &b, &c, &x, vec![a.invite(&x, 1)]);
        let store = MemStore::default();
        let device = b.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &fork, 1);
        let mut genesis_only = History::genesis(&a);
        genesis_only.links.clear();
        import(&device, &genesis_only, &members, true);
        for v in [2, 3] {
            give(&device, &fork, v);
        }
        assert_eq!(state_of_version(&import(&device, &fork, &members, true), 3).0, Accepted);
        assert_eq!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&3].kept, Some(KeptTag::of(&fork.records[&3].0)));
        // Restarted, A (who signed v1 and v2) no longer confirmed: the real chain
        // settles the fork. v1-v2 still vouch by their kept tags; v3's step never
        // keeps the fork's tag.
        let restarted = restarted(&store);
        let report = import(&restarted, &real, &unconfirmed(&members, &a), true);
        assert!(!report.forked);
        let chains = restarted.refresh.read().unwrap();
        let chain = &chains[&CircleKey::of(CIRCLE)];
        for v in [1, 2] {
            assert_eq!(chain.history[&v].kept, Some(KeptTag::of(&real.records[&v].0)), "v{v}");
            assert!(chain.seen[&v].vouches_for_its_tag(), "v{v}");
        }
        assert_ne!(chain.history.get(&3).and_then(|step| step.kept), Some(KeptTag::of(&fork.records[&3].0)));
    }

    #[test]
    fn kept_the_held_copy_check_waits_while_the_chain_is_forked() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let same_rows = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let mut one = h.clone();
        one.rotate(RecordKind::Rotation, &a, same_rows(&h), None);
        let mut two = h.clone();
        two.keys.insert(3, [0x3c; 32]);
        two.rotate(RecordKind::Rotation, &c, same_rows(&h), None);
        // v3 (one's) taken as the reference, verified: its tag is kept.
        let (device, report) = device_at(&a, &a, &one, &members, &[2]);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        // Two records for v3 now: forked. The other side's v3 key, held while
        // forked, fails this side's kept tag, and stays.
        let mut both = one.signed();
        both.extend(two.signed());
        assert!(device.import_refresh_records_at(CIRCLE, &both, &one.links, &members, true, None, &[], NOW).unwrap().forked);
        assert!(device.add_verified_key(CIRCLE, 3, &two.keys[&3]));
        let report = device.import_refresh_records_at(CIRCLE, &one.signed(), &one.links, &members, true, None, &[], NOW).unwrap();
        assert!(report.forked);
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 3 && k.as_slice() == two.keys[&3]), "kept while forked");
    }

    #[test]
    fn kept_a_step_never_keeps_another_branchs_tag() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let same_rows = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        let (mut one, mut two) = (h.clone(), h.clone());
        one.rotate(RecordKind::Rotation, &a, same_rows(&h), None);
        two.rotate(RecordKind::Rotation, &c, same_rows(&h), None);
        let (ours, theirs) = (&one.records[&3].0, &two.records[&3].0);
        let mut chain = CircleChain::default();
        chain.note_step(ours, ours.chain(), true, None);
        assert_eq!(chain.history[&3].kept, Some(KeptTag::of(ours)));
        chain.note_step(ours, ours.chain(), false, None);
        assert_eq!(chain.history[&3].kept, Some(KeptTag::of(ours)), "the same record keeps its tag");
        chain.note_step(theirs, theirs.chain(), false, None);
        assert_eq!(chain.history[&3].kept, None, "another branch's step never keeps it");
        chain.note_step(theirs, theirs.chain(), true, None);
        assert_eq!(chain.history[&3].kept, Some(KeptTag::of(theirs)));
    }

    // ------------------------------------------------------------------
    // On the account's own head's word, a version opens only with a copy
    // that verifies its record's tag
    // ------------------------------------------------------------------

    /// `h`'s record for `version` again, the same body (its signer `signer`)
    /// with a tag made for `key`: signed again by `signer`, or with a junk
    /// signature.
    fn same_body_with_tag(h: &History, version: u32, key: [u8; 32], signer: &Acct, junk_signature: bool) -> History {
        let (wire, _) = &h.records[&version];
        let mut other = h.clone();
        other.records.retain(|v, _| *v < version);
        other.keys.insert(version, key);
        other.push(wire.body.kind, version, wire.body.prev_version, wire.body.prev_chain, wire.body.link_to, signer, wire.body.entries.clone());
        if junk_signature {
            other.records.get_mut(&version).unwrap().1 = [0x11; 64];
        }
        assert_eq!(other.records[&version].0.chain(), wire.chain(), "the same body");
        other
    }

    #[test]
    fn by_account_a_made_up_same_body_head_is_never_sealed_under() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        // A fresh install of A's account: the account's own head vouches for
        // v3's body; the server serves that body with a tag made for K' and a
        // junk signature, and a wrap of K' for v3 came first.
        let k_prime = [0x77u8; 32];
        let made_up = same_body_with_tag(&h, 3, k_prime, &a, true);
        let fresh = a.device();
        give(&fresh, &h, 1);
        give(&fresh, &h, 2);
        assert!(fresh.add_verified_key(CIRCLE, 3, &k_prime));
        let report = fresh.import_refresh_records_at(CIRCLE, &made_up.signed(), &h.links, &members, true, Some(&head_by(&a, &h, 3)), &[], NOW).unwrap();
        assert!(report.versions.iter().all(|r| r.state != Rejected), "{:?}", report.versions);
        assert_eq!(fresh.get_active_version(CIRCLE.into()).unwrap(), 2, "never sealed under K'");
    }

    #[test]
    fn by_account_a_head_whose_signer_is_confirmed_later_opens_at_the_next_import() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        // A fresh install of D's account, D's own head at v2 (by A). A isn't
        // confirmed here yet, so nothing vouches, and nothing is sealed.
        let fresh = d.device();
        give(&fresh, &h, 1);
        give(&fresh, &h, 2);
        let report = fresh.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &unconfirmed(&members, &a), true, Some(&head_by(&d, &h, 2)), &[], NOW).unwrap();
        assert!(!report.forked);
        assert!(fresh.get_active_version(CIRCLE.into()).is_err(), "nothing vouches yet");
        // A confirmed now; the next import serves nothing new: v1-v2 vouch by
        // their signatures, and v2 opens, with no restart and no new record.
        fresh.import_refresh_records_at(CIRCLE, &[], &[], &members, true, None, &[], NOW).unwrap();
        assert_eq!(fresh.get_active_version(CIRCLE.into()).unwrap(), 2);
        assert!(fresh.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&2].kept.is_some(), "its tag kept from now on");
    }

    #[test]
    fn kept_a_signed_copy_with_another_tag_never_outranks_the_kept_tag() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = kept_reference(&a, &d, &h, &members);
        // A signs v2's body again with a tag for K'' (equivocating); served, it
        // replaces the held record, yet the kept tag still decides v2's key.
        let k2 = [0x2au8; 32];
        let other = same_body_with_tag(&h, 2, k2, &a, false);
        device.import_refresh_records_at(CIRCLE, &other.signed(), &h.links, &members, true, None, &[], NOW).unwrap();
        assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].seen[&2].wire.key_tag_matches(&k2));
        assert!(device.copy_contradicts_record(CIRCLE, 2, &k2));
        assert!(!device.copy_contradicts_record(CIRCLE, 2, &h.keys[&2]));
    }

    // ------------------------------------------------------------------
    // finalize never installs over a known circle id
    // ------------------------------------------------------------------

    fn held_sorted(device: &CryptoManager, circle: &str) -> Vec<(u32, Vec<u8>)> {
        let mut held: Vec<(u32, Vec<u8>)> = device.held_keys(circle).into_iter().map(|(v, k)| (v, k.to_vec())).collect();
        held.sort();
        held
    }

    #[test]
    fn finalize_never_installs_over_a_circle_this_device_knows() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        let legacy = "c0c0c0c0-1111-4222-8333-444444444444";
        assert!(device.add_verified_key(legacy, 1, &[0x42; 32]));
        // A circle a head latched, with no key held yet.
        let latched = "d0d0d0d0-1111-4222-8333-444444444444";
        device.note_circle_has_records(latched.into());
        let before = (held_sorted(&device, CIRCLE), held_sorted(&device, legacy));
        // A creation finalized under the id of a recorded circle, of a legacy one
        // this device holds keys for, or of a latched one: refused, and nothing
        // changes.
        let creation = device.prepare_circle_creation().unwrap();
        for known in [CIRCLE, legacy, latched] {
            match device.finalize_circle_creation(creation.temp_circle_id.clone(), known.into()) {
                Err(MobileError::InvalidInput(why)) => assert!(why.contains("already knows"), "{why}"),
                other => panic!("refused, got {other:?}"),
            }
        }
        assert_eq!((held_sorted(&device, CIRCLE), held_sorted(&device, legacy)), before);
        assert!(held_sorted(&device, latched).is_empty());
        assert_eq!(device.get_active_version(CIRCLE.into()).unwrap(), 2);
        // Under a new id, the same creation is finalized.
        let new_id = uuid::Uuid::new_v4().to_string();
        device.finalize_circle_creation(creation.temp_circle_id, new_id.clone()).unwrap();
        assert_eq!(device.get_active_version(new_id).unwrap(), 1);
    }

    #[test]
    fn by_account_a_record_waiting_on_its_signer_vouches_for_nothing() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let x = Acct::new(0xe1);
        let members = four_members(&a, &b, &c, &d);
        // v3 by X, whom this device doesn't confirm: it waits here,
        // never passed over. v4, the owner's repair that removes X,
        // waits behind it.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &x, v3, None);
        let mut v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        v4.push(h.entry(&x, Removed, Member));
        h.rotate(RecordKind::Repair, &a, v4, None);
        let (device, report) = device_at(&a, &a, &h, &members, &[2, 4]);
        assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::SignerUnknown));
        assert!(report.versions.iter().all(|r| r.version <= 3), "{:?}", report.versions);
        // A copy of v3 that fails its tag is held. Nothing of v3 is kept to
        // vouch for a tag, or to drop a copy.
        assert!(device.add_verified_key(CIRCLE, 3, &[0x33; 32]));
        {
            let chains = device.refresh.read().unwrap();
            assert!(!chains[&CircleKey::of(CIRCLE)].seen.contains_key(&3));
            assert_eq!(chains[&CircleKey::of(CIRCLE)].history.get(&3).and_then(|step| step.kept), None);
        }
        // X confirmed now, and the chain served again: v3 is judged like any
        // record (a newcomer no owner or admin invited: rejected), the owner's
        // repair is taken, and the copy stays (a rejected record vouches for no tag).
        let with_x = [&members[..], &[x.member()]].concat();
        let report = import(&device, &h, &with_x, true);
        assert_eq!(state_of_version(&report, 3).0, Rejected, "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        assert!(!device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].seen[&3].vouches_for_its_tag());
        assert!(device.held_keys(CIRCLE).iter().any(|(v, k)| *v == 3 && k.as_slice() == [0x33; 32]), "kept");
    }

    // ------------------------------------------------------------------
    // The latched mark across this account's own leave
    // ------------------------------------------------------------------

    #[test]
    fn latch_a_left_circle_rejoined_with_its_records_withheld_waits_for_them() {
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = stored_device(&a, &h, &members);
        assert!(device.forget_circle(CIRCLE.into()));
        // Re-joined: a copy of the current key arrives; the server withholds
        // the circle's records.
        own_copy(&device, &a, 2, &h.keys[&2]).unwrap();
        let report = device.import_refresh_records_at(CIRCLE, &[], &[], &members, true, None, &[], NOW).unwrap();
        assert_eq!(report.sealing_version, None);
        let waits = |device: &CryptoManager| {
            assert!(device.circle_has_refresh_records(CIRCLE.into()), "never legacy");
            assert!(device.get_active_version(CIRCLE.into()).is_err(), "nothing sealed");
            assert!(device.refresh_eligibility_at(CIRCLE, &members, EligibilityPurpose::Deliver, NOW).is_err(), "nothing delivered");
            let transition = plan(&[(&a, S::Included, Some(CircleRole::Owner)), (&b, S::Included, Some(CircleRole::Member)), (&c, S::Included, Some(CircleRole::Admin)), (&d, S::Included, Some(CircleRole::Member))]);
            assert!(device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Transition, &transition, &members, true, "n", NOW).is_err(), "no transition");
            assert!(device.prepare_key_rotation(CIRCLE.into(), a.uid.clone(), vec![], vec![], vec![], "n".into()).is_err(), "no record-less rotation");
            let creation = device.prepare_circle_creation().unwrap();
            assert!(device.finalize_circle_creation(creation.temp_circle_id, CIRCLE.into()).is_err(), "never a new circle");
        };
        waits(&device);
        // The same after a restart: the mark is kept like any latch.
        let restarted = restarted(&store);
        restarted.import_refresh_records_at(CIRCLE, &[], &[], &members, true, None, &[], NOW).unwrap();
        waits(&restarted);
        // The records, served at last, are taken as a first device's prefix.
        let report = import(&restarted, &h, &members, true);
        assert_eq!(state_of_version(&report, 2).0, Accepted);
        assert_eq!(restarted.get_active_version(CIRCLE.into()).unwrap(), 2);
    }

    #[test]
    fn latch_only_clear_all_keys_removes_the_mark() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = stored_device(&a, &h, &members);
        assert!(device.forget_circle(CIRCLE.into()));
        assert!(device.circle_has_refresh_records(CIRCLE.into()));
        device.clear_all_keys();
        assert!(!device.circle_has_refresh_records(CIRCLE.into()));
        assert!(store.0.lock().unwrap().is_none(), "the store is wiped with it");
    }

    #[test]
    fn latch_a_circle_that_never_had_records_leaves_no_mark() {
        let (a, b, c, d, _) = four();
        let members = four_members(&a, &b, &c, &d);
        let device = a.device();
        let legacy = "c0c0c0c0-1111-4222-8333-444444444444";
        assert!(device.add_verified_key(legacy, 1, &[0x42; 32]));
        // An import that finds no records for it leaves it legacy.
        device.import_refresh_records_at(legacy, &[], &[], &members, true, None, &[], NOW).unwrap();
        assert!(!device.circle_has_refresh_records(legacy.into()));
        assert!(device.forget_circle(legacy.into()));
        assert!(!device.circle_has_refresh_records(legacy.into()));
        assert!(device.refresh.read().unwrap().get(&CircleKey::of(&legacy)).is_none());
        // Re-joined, it is legacy again until an import finds records.
        assert!(device.add_verified_key(legacy, 2, &[0x43; 32]));
        assert_eq!(device.get_active_version(legacy.into()).unwrap(), 2);
    }

    // ------------------------------------------------------------------
    // Roles through a record rejected for R2
    // ------------------------------------------------------------------

    /// four()'s v2, then v3 by the owner A: D promoted to admin, and newcomer N
    /// included (A holds N's invitation; B's device doesn't list N).
    fn promoted_with_a_newcomer() -> (Acct, Acct, Acct, Acct, Acct, History) {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let n = Acct::new(0xe7);
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Admin), (&n, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        (a, b, c, d, n, h)
    }

    #[test]
    fn roles_a_departed_admin_promoted_in_a_rejected_record_is_carried_pending_as_admin() {
        use RecordMemberState as S;
        let (a, b, c, d, n, h) = promoted_with_a_newcomer();
        let all = four_members(&a, &b, &c, &d);
        // Plain member B's device rejects v3 for R2: N matches nobody here.
        let (member, report) = device_at(&b, &a, &h, &all, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(member.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Admin), "v3 moved D's role");
        // D leaves; B repairs, naming who it can.
        let without_d = all[..3].to_vec();
        let plan_abc = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]);
        let bundle = member.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Repair, &plan_abc, &without_d, true, "n", NOW).unwrap();
        let record = parsed(&bundle);
        let d_entry = record.body.entry(&h.code(&d)).unwrap();
        assert_eq!((d_entry.state, d_entry.role), (Pending, ChainRole::Admin), "carried pending, with the role v3 gave D");
        // Both sides accept it: B's device, served it back, and the owner's, which accepted v3.
        let (records, links) = served_with(&h, &bundle);
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &without_d, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        let owner_list = [&without_d[..], &[with(n.member(), |m| m.statements = vec![a.invite(&n, 2)])]].concat();
        let (owner, report) = device_at(&a, &a, &h, &[&all[..], &owner_list[3..]].concat(), &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        assert!(owner.add_verified_key(CIRCLE, 4, &open_wrap(&a, &bundle.rotation)));
        let report = owner.import_refresh_records_at(CIRCLE, &records, &links, &owner_list, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
    }

    #[test]
    fn roles_a_record_rejected_for_a_role_moves_none() {
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let all = four_members(&a, &b, &c, &d);
        // Plain member B promotes D: refused for ROLE everywhere.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Admin)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let (owner, report) = device_at(&a, &a, &h, &all, &[2, 3]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Role));
        // The owner's repair carries the last accepted roles: D a member.
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let bundle = owner.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Repair, &everyone, &all, true, "n", NOW).unwrap();
        assert_eq!(parsed(&bundle).body.entry(&h.code(&d)).unwrap().role, Member);
        assert_eq!(owner.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member));
    }

    #[test]
    fn roles_an_admin_promoted_in_a_record_rejected_for_r2_removes_with_the_right() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, n, mut h) = promoted_with_a_newcomer();
        let all = four_members(&a, &b, &c, &d);
        // v4 by D, admin since v3: removes C (and N).
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Removed, Admin), (&d, Included, Admin), (&n, Removed, Member)]);
        h.rotate(RecordKind::Repair, &d, v4, None);
        // B's device rejected v3 for R2; D's removal of C counts there.
        let (member, report) = device_at(&b, &a, &h, &all, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
        assert_eq!(member.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Admin));
        assert_eq!(member.chain_role(CIRCLE.into(), c.uid.clone()), None, "removed");
        let e = eligible(&member, &all, &c, EligibilityPurpose::Include);
        assert!(e.removed_by_owner_or_admin && !e.eligible, "{e:?}");
    }

    #[test]
    fn roles_an_admin_promoted_in_a_record_rejected_for_r2_invites_with_the_right() {
        let (a, b, c, d, _, h) = promoted_with_a_newcomer();
        let all = four_members(&a, &b, &c, &d);
        let (member, report) = device_at(&b, &a, &h, &all, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Rejected);
        // D, admin since v3 here too, invites M: that invitation counts (E (c)).
        let m = Acct::new(0xe8);
        let listed = [&all[..], &[with(m.member(), |row| row.statements = vec![d.invite(&m, 3)])]].concat();
        let e = eligible(&member, &listed, &m, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis, e.invitation_signer_not_chain_admin), (true, Some(EligibilityBasis::Invitation), false), "{e:?}");
    }

    #[test]
    fn roles_a_plain_members_departure_of_an_admin_promoted_in_a_rejected_record_never_counts() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, n, mut h) = promoted_with_a_newcomer();
        let all = four_members(&a, &b, &c, &d);
        // v4 by plain member B, after the rejected v3: D written departed,
        // N departed.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Departed, Admin), (&n, Departed, Member)]);
        h.rotate(RecordKind::Repair, &b, v4, None);
        let without_d = all[..3].to_vec();
        let (member, report) = device_at(&b, &a, &h, &all, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3).0, Rejected);
        assert_eq!(state_of_version(&report, 4).0, Accepted);
        // D was an admin when B wrote it (v3's role): a plain member's
        // departure of an admin doesn't count, even off the list.
        let e = eligible(&member, &[&without_d[..], &[with(all[3].clone(), |m| m.listed = false)]].concat(), &d, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (true, Some(EligibilityBasis::CountedByChain)), "{e:?}");
    }

    #[test]
    fn roles_a_planned_entry_with_no_role_carries_the_role_a_rejected_record_gave() {
        use RecordMemberState as S;
        let (a, b, c, d, _, h) = promoted_with_a_newcomer();
        let all = four_members(&a, &b, &c, &d);
        let (member, _) = device_at(&b, &a, &h, &all, &[2, 3]);
        // B repairs with D still here, named with no role: D's role is v3's.
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let bundle = member.prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Repair, &everyone, &all, true, "n", NOW).unwrap();
        assert_eq!(parsed(&bundle).body.entry(&h.code(&d)).unwrap().role, ChainRole::Admin);
    }


    #[test]
    fn roles_an_admin_cannot_remove_the_owner_a_record_rejected_for_r2_named() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let n = Acct::new(0xe7);
        // v3 by owner A: hands over to D, and includes newcomer N (B's device
        // can't match N: rejected for R2 only, so its roles move there).
        let v3 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Owner), (&n, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        // v4 by admin C: removes D, the owner since v3.
        let v4 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Owner), (&n, Removed, Member)]);
        h.rotate(RecordKind::Repair, &c, v4, None);
        let all = four_members(&a, &b, &c, &d);
        let (_member, report) = device_at(&b, &a, &h, &all, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::Removal));
    }

    #[test]
    fn roles_the_new_owner_a_record_rejected_for_r2_named_removes_the_old_one() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let n = Acct::new(0xe7);
        let v3 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Owner), (&n, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        // v4 by D, the owner since v3: removes A, an admin since v3.
        let v4 = rows(&h, &[(&a, Removed, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Owner), (&n, Removed, Member)]);
        h.rotate(RecordKind::Repair, &d, v4, None);
        let all = four_members(&a, &b, &c, &d);
        let (_member, report) = device_at(&b, &a, &h, &all, &[2, 3, 4]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None));
    }

    #[test]
    fn roles_a_first_devices_prefix_moves_no_role_through_a_role_refusal() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        // v3 by plain member B: promotes D, refused for ROLE everywhere.
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Admin)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        // v4 by D, an admin only by v3's word: removes C.
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Removed, Admin), (&d, Included, Admin)]);
        h.rotate(RecordKind::Repair, &d, v4, None);
        let all = four_members(&a, &b, &c, &d);
        // A first device: the served chain is judged as a prefix.
        let device = a.device();
        for version in 2..=4 {
            give(&device, &h, version);
        }
        let report = import(&device, &h, &all, true);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::Role));
        assert_ne!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        assert_eq!(device.chain_role(CIRCLE.into(), c.uid.clone()), Some(CircleRole::Admin));
        assert_eq!(device.chain_role(CIRCLE.into(), d.uid.clone()), Some(CircleRole::Member));
    }

    #[test]
    fn roles_an_owner_named_only_by_a_record_rejected_for_r2_is_not_gone() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let x = Acct::new(0xe9);
        // v3 by owner A: includes newcomer X and hands ownership to X (A admin).
        let v3 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Included, Owner)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let listed = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Admin)),
            with(b.member(), |m| m.statements = vec![a.invite(&b, 1)]),
            with(c.member(), |m| {
                m.statements = vec![a.invite(&c, 1)];
                m.listed_role = Some(CircleRole::Owner);
            }),
            with(d.member(), |m| m.statements = vec![a.invite(&d, 1)]),
        ];
        let owner_list = [&listed[..], &[with(x.member(), |m| m.statements = vec![a.invite(&x, 2)])]].concat();
        // v4 by admin C, whom the server lists as owner: names itself owner.
        for (x_state, b_side, a_side) in [
            // Removing nobody: X, the owner by v3, isn't gone. Both sides refuse (the owner
            // claim needs X's removal).
            (Departed, (Rejected, RecordProblem::Role), (Rejected, RecordProblem::Role)),
            // Removing X: the owner claim's record. Both sides accept it.
            (Removed, (Accepted, RecordProblem::None), (Accepted, RecordProblem::None)),
        ] {
            let mut claim = h.clone();
            let v4 = rows(&claim, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Owner), (&d, Included, Member), (&x, x_state, Member)]);
            claim.rotate(RecordKind::Repair, &c, v4, None);
            // B's device: X matches nobody here, so v3 is rejected for R2 only.
            let (_member, report) = device_at(&b, &a, &claim, &listed, &[2, 3, 4]);
            assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
            assert_eq!(state_of_version(&report, 4), b_side, "B's device, X {x_state:?}");
            // The owner's device, which lists X with A's invitation: v3 accepted.
            let (_owner, report) = device_at(&a, &a, &claim, &owner_list, &[2, 3, 4]);
            assert_eq!(state_of_version(&report, 3).0, Accepted);
            assert_eq!(state_of_version(&report, 4), a_side, "A's device, X {x_state:?}");
        }
    }

    #[test]
    fn roles_an_owner_a_counting_removal_took_out_is_gone() {
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let x = Acct::new(0xe9);
        let y = Acct::new(0xea);
        // v3 by owner A: includes newcomer X (B's device can't match X: R2 only).
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        // v4 by owner A: removes X while naming X the owner (A admin), and
        // includes newcomer Y (B's device can't match Y: R2 only again).
        let v4 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member), (&x, Removed, Owner), (&y, Included, Member)]);
        h.rotate(RecordKind::Rotation, &a, v4, None);
        // v5 by admin C, whom the server lists as owner: names itself owner, removes nobody.
        let v5 = rows(&h, &[(&a, Included, Admin), (&b, Included, Member), (&c, Included, Owner), (&d, Included, Member), (&y, Departed, Member)]);
        h.rotate(RecordKind::Repair, &c, v5, None);
        let listed = vec![
            with(a.member(), |m| m.listed_role = Some(CircleRole::Admin)),
            with(b.member(), |m| m.statements = vec![a.invite(&b, 1)]),
            with(c.member(), |m| {
                m.statements = vec![a.invite(&c, 1)];
                m.listed_role = Some(CircleRole::Owner);
            }),
            with(d.member(), |m| m.statements = vec![a.invite(&d, 1)]),
        ];
        // B's device: v3 and v4 rejected for R2 only. X, the owner by v4's roles,
        // is in the removed overlay too: gone, so C's claim stands.
        let (_member, report) = device_at(&b, &a, &h, &listed, &[2, 3, 4, 5]);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 4), (Rejected, RecordProblem::R2UnmatchedEntry));
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None), "B's device");
        // A's device, which lists X and Y: the same outcome.
        let owner_list = [&listed[..], &[with(x.member(), |m| m.statements = vec![a.invite(&x, 2)]), with(y.member(), |m| m.statements = vec![a.invite(&y, 3)])]].concat();
        let (_owner, report) = device_at(&a, &a, &h, &owner_list, &[2, 3, 4, 5]);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted));
        assert_eq!(state_of_version(&report, 5), (Accepted, RecordProblem::None), "A's device");
    }

    // ------------------------------------------------------------------
    // Format 2: the locked v2 files through the importer, at each file's
    // own `now`.
    // ------------------------------------------------------------------

    use crate::refresh_record::v2_vectors;

    /// An admission of `subject` by `signer` at `at_version` in a v2 file, its
    /// statement id its own (`id`), a minute before the file's `now`.
    fn v2_admission(f: &WebBuilt, signer: &str, subject: &str, at_version: i32, id: u8) -> HeldStatement {
        let (bytes, _) = encode_statement(&MembershipStatement {
            kind: MembershipStatementKind::Admission,
            circle_id: f.circle(),
            statement_id: format!("3b0000ad-0000-4000-8000-0000000000{id:02x}"),
            signer_user_id: f.uid(signer),
            issued_at: f.now() - 60,
            expires_at: 0,
            at_version,
            subject_user_id: Some(f.uid(subject)),
            subject_sharing_public_key_hex: Some(f.0[&format!("{subject}_sharing_pk")].clone()),
            subject_signing_public_key_hex: Some(f.0[&format!("{subject}_signing_pk")].clone()),
            subject_email: None,
        })
        .unwrap();
        HeldStatement {
            statement_hex: hex::encode(&bytes),
            signature_hex: hex::encode(v2_signer(f, signer).sign(&statement_digest(&bytes)).to_bytes()),
        }
    }

    fn v2_signer(f: &WebBuilt, who: &str) -> SigningKey {
        SigningKey::from_bytes(&hex::decode(&f.0[&format!("{who}_signing_seed")]).unwrap().try_into().unwrap())
    }

    /// A device's list for a v2 file: A the owner, C an admin, B and D
    /// members, each admitted by the owner at `at`.
    fn v2_list(f: &WebBuilt, at: i32) -> Vec<RecordMember> {
        let admitted = |n: &str, role: CircleRole, id: u8| with(f.listed(n, role), |m| m.statements = vec![v2_admission(f, "A", n, at, id)]);
        vec![f.listed("A", CircleRole::Owner), admitted("B", CircleRole::Member, 0xb1), admitted("C", CircleRole::Admin, 0xc1), admitted("D", CircleRole::Member, 0xd1)]
    }

    /// Record `name` of a v2 file (a copy included), as served.
    fn v2_record(f: &WebBuilt, name: &str) -> SignedRefreshRecord {
        SignedRefreshRecord { record_hex: f.0[&format!("{name}_record_wire")].clone(), signature_hex: f.0[&format!("{name}_signature")].clone() }
    }

    /// Head `name` of a v2 file, as a member's.
    fn v2_head(f: &WebBuilt, name: &str, who: &str) -> MemberHead {
        MemberHead { user_id: f.uid(who), head: SignedCircleHead { head_hex: f.0[name].clone(), signature_hex: f.0[&format!("{name}_signature")].clone() } }
    }

    /// A head of `who` at `version` naming `chain` in `format`, signed with
    /// their seed in the file.
    fn v2_forged_head(f: &WebBuilt, who: &str, format: RecordFormat, version: u32, chain: [u8; 32]) -> MemberHead {
        let circle = *uuid::Uuid::parse_str(&f.circle()).unwrap().as_bytes();
        let user = *uuid::Uuid::parse_str(&f.uid(who)).unwrap().as_bytes();
        let bytes = Head { format, circle_id: circle, user_id: user, version, chain }.encode().unwrap();
        let signature = v2_signer(f, who).sign(&Head::digest(&bytes)).to_bytes();
        MemberHead { user_id: f.uid(who), head: SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(signature) } }
    }

    fn step_of(device: &CryptoManager, f: &WebBuilt, version: u32) -> ChainStep {
        device.refresh.read().unwrap()[&CircleKey::of(&f.circle())].history[&version]
    }

    fn rows_of(report: &RefreshRecordsReport) -> Vec<(i32, RecordVersionState, RecordProblem)> {
        report.versions.iter().map(|r| (r.version, r.state, r.problem)).collect()
    }

    fn b32_of(f: &WebBuilt, name: &str) -> [u8; 32] {
        hex::decode(&f.0[name]).unwrap().try_into().unwrap()
    }

    #[test]
    fn v2_the_switch_mid_chain_is_taken_and_heads_read_in_their_own_format() {
        let f = WebBuilt::new(v2_vectors::SWITCH);
        let list = v2_list(&f, 1);
        // B's device, step by step: format 1 up to v2, format 2 from v3 on.
        let (b, reports) = f.step_by_step(&vec![list.clone(); 4]);
        for (report, v) in reports.iter().zip(1u32..) {
            assert_eq!(state_of_version(report, v), (Accepted, RecordProblem::None), "v{v}: {:?}", report.versions);
        }
        // C's eject of D, in the circle's first format-2 record, counts.
        let e = f.eligibility(&b, &list, "D", EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{e:?}");
        // Each step keeps the wire of the copy it took, and its format.
        for (v, format) in [(1, RecordFormat::V1), (2, RecordFormat::V1), (3, RecordFormat::V2), (4, RecordFormat::V2)] {
            let step = step_of(&b, &f, v);
            assert_eq!((step.wire, step.format), (Some(b32_of(&f, &format!("r{v}_wire_chain"))), format), "v{v}");
        }
        // The heads in both formats name B's chain: no fork.
        let heads = [v2_head(&f, "head_B_v2_format1", "B"), v2_head(&f, "head_B_v2_format2", "B"), v2_head(&f, "head_A_v4_format2", "A")];
        let report = b.import_refresh_records_at(&f.circle(), &f.records(1..=4), &f.links(4), &list, true, None, &heads, f.now()).unwrap();
        assert!(!report.forked && report.versions.is_empty(), "{:?}", report.versions);
        // A format-2 head naming another copy's wire at v4: a fork.
        let wrong = v2_forged_head(&f, "A", RecordFormat::V2, 4, b32_of(&f, "r3_wire_chain"));
        let report = b.import_refresh_records_at(&f.circle(), &f.records(1..=4), &f.links(4), &list, true, None, &[wrong], f.now()).unwrap();
        assert!(report.forked, "{:?}", report.versions);
        // B's own head is published in format 2, over the wire of r4.
        let (b, _) = f.step_by_step(&vec![list.clone(); 4]);
        {
            use base64::Engine as _;
            b.import_signing_private_key(base64::engine::general_purpose::STANDARD.encode(v2_signer(&f, "B").to_bytes())).unwrap();
        }
        let signed = b.sign_circle_head_of(&f.circle(), &f.uid("B")).unwrap();
        let head = Head::decode(&hex::decode(&signed.head_hex).unwrap()).unwrap();
        assert_eq!((head.format, head.version, head.chain), (RecordFormat::V2, 4, b32_of(&f, "r4_wire_chain")));
    }

    #[test]
    fn v2_a_copy_of_the_eject_that_must_not_link_never_passes_it_over() {
        // The file's copies of r3, the owner's eject of D; r4
        // (the admin C) links r3's wire.
        let f = WebBuilt::new(v2_vectors::GENESIS);
        let list = v2_list(&f, 1);
        let with_copy = |copy: &str| vec![v2_record(&f, "r1"), v2_record(&f, "r2"), v2_record(&f, copy), v2_record(&f, "r4")];
        let b_at_v2 = || {
            let (b, _) = f.step_by_step(&vec![list.clone(); 2]);
            for v in 3..=4 {
                assert!(b.add_verified_key(&f.circle(), v, &f.key(v)));
            }
            b
        };
        // A spoiled signature, or a spoiled key tag: the eject waits, r4 is
        // never taken, and the good records then decide it.
        for copy in ["r3_copy_flipped_signature", "r3_copy_flipped_key_tag"] {
            let b = b_at_v2();
            let report = f.import(&b, &with_copy(copy), 4, &list, None);
            assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::Signature)], "{copy}");
            assert_eq!(b.refresh.read().unwrap()[&CircleKey::of(&f.circle())].head.as_ref().map(|h| h.version), Some(2), "{copy}");
            let report = f.import(&b, &f.records(1..=4), 4, &list, None);
            assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted), "{copy}: {:?}", report.versions);
            assert_eq!(f.eligibility(&b, &list, "D", EligibilityPurpose::Include).removed_at_version, Some(3), "{copy}");
        }
        // The same body and tag re-signed by the admin C, served
        // alone: in format 2 it is misattributed, so rejected and
        // passed over, with D's removal counting (its signer code is
        // the owner's). That step keeps that copy: the honest r3
        // served afterwards doesn't take its place, and r4 (which
        // links the honest wire) doesn't link: a fork, waiting.
        let b = b_at_v2();
        let resigned = with_copy("r3_copy_resigned_by_C");
        let report = f.import(&b, &resigned[..3], 4, &list, None);
        assert_eq!(rows_of(&report), vec![(3, Rejected, RecordProblem::Misattributed)]);
        let e = f.eligibility(&b, &list, "D", EligibilityPurpose::Deliver);
        assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{e:?}");
        let report = f.import(&b, &f.records(1..=4), 4, &list, None);
        assert_eq!(rows_of(&report), vec![(3, Rejected, RecordProblem::Misattributed), (4, Rejected, RecordProblem::Fork)]);
        assert!(report.forked);
        assert!(!f.eligibility(&b, &list, "D", EligibilityPurpose::Deliver).eligible);
        // Served together with r4, which links another copy's wire:
        // this copy isn't the chain's record, so it waits, as a
        // spoiled copy does, and the honest r3 decides that wait; r4
        // links it.
        let b = b_at_v2();
        let report = f.import(&b, &resigned, 4, &list, None);
        assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::Signature)]);
        let report = f.import(&b, &f.records(1..=4), 4, &list, None);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted), "{:?}", report.versions);
        // Without C confirmed here, its key verifies no confirmed member: the
        // copy waits, as any signature that fails, and is never rejected.
        let unconfirmed = list.iter().map(|m| if m.user_id == f.uid("C") { with(m.clone(), |m| m.confirmed = false) } else { m.clone() }).collect::<Vec<_>>();
        let b = b_at_v2();
        let report = f.import(&b, &with_copy("r3_copy_resigned_by_C")[..3], 4, &unconfirmed, None);
        assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::Signature)]);
        // The good copy served first beside a copy with the same wire: the
        // first one served is the one read.
        let b = b_at_v2();
        let served = vec![v2_record(&f, "r1"), v2_record(&f, "r2"), v2_record(&f, "r3"), v2_record(&f, "r3_copy_resigned_by_C"), v2_record(&f, "r4")];
        let report = f.import(&b, &served, 4, &list, None);
        assert_eq!((state_of_version(&report, 3).0, state_of_version(&report, 4).0), (Accepted, Accepted), "{:?}", report.versions);
    }

    #[test]
    fn v2_a_transition_in_format_2_is_taken_and_its_spoiled_copies_wait() {
        let f = WebBuilt::new(v2_vectors::TRANSITION);
        // Everyone admitted by the owner at the transition's version.
        let list = v2_list(&f, 5);
        let links = |from_to: &[(u32, u32)]| -> Vec<KeyChainLinkData> {
            from_to
                .iter()
                .map(|(from, to)| KeyChainLinkData {
                    from_version: *from as i32,
                    to_version: *to as i32,
                    encrypted_key: f.0[&format!("link_{from}_{to}_encrypted_key")].clone(),
                    nonce: f.0[&format!("link_{from}_{to}_nonce")].clone(),
                })
                .collect()
        };
        let all = links(&[(2, 1), (3, 2), (4, 3), (5, 4), (6, 4)]);
        // B's device, legacy up to v4, then given key 6 (never 5: pending at v5).
        let b = f.device([1, 2, 3, 4, 6].into_iter());
        let report = b.import_refresh_records_at(&f.circle(), &f.records(5..=6), &all, &list, true, None, &[], f.now()).unwrap();
        assert_eq!(state_of_version(&report, 6), (Accepted, RecordProblem::None), "{:?}", report.versions);
        assert_eq!((step_of(&b, &f, 5).wire, step_of(&b, &f, 6).format), (Some(b32_of(&f, "r5_wire_chain")), RecordFormat::V2));
        // Its anchor tag spoiled: this device's own key 4 doesn't verify it.
        // Its key tag spoiled: its signature fails. Neither is taken, nor r6.
        for (copy, problem) in [("r5_copy_flipped_anchor_tag", RecordProblem::AnchorMismatch), ("r5_copy_flipped_key_tag", RecordProblem::Signature)] {
            let b = f.device([1, 2, 3, 4, 6].into_iter());
            let served = vec![v2_record(&f, copy), v2_record(&f, "r6")];
            let report = b.import_refresh_records_at(&f.circle(), &served, &all, &list, true, None, &[], f.now()).unwrap();
            assert!(report.versions.iter().all(|r| r.state == Waiting) && report.versions.iter().any(|r| r.problem == problem), "{copy}: {:?}", report.versions);
            assert!(b.refresh.read().unwrap().get(&CircleKey::of(&f.circle())).map_or(true, |chain| chain.head.is_none()), "{copy}");
        }
    }

    #[test]
    fn v2_a_misattributed_version_passed_over_waits_after_a_restart() {
        // B takes C's re-signed copy of the owner's eject of D, which
        // is passed over (MISATTRIBUTED) with D's removal counting.
        // The app restarts, and the server withholds v3.
        let f = WebBuilt::new(v2_vectors::GENESIS);
        let list = v2_list(&f, 1);
        let chain3 = WireRecord::parse(&hex::decode(&f.0["r3_record_wire"]).unwrap()).unwrap().chain();
        let store = MemStore::default();
        let b = CryptoManager::new();
        {
            // B's identity, so that the key store is written (its sharing key isn't in the file).
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD;
            b.import_private_key(b64.encode([0x4b; 32])).unwrap();
            b.import_signing_private_key(b64.encode(hex::decode(&f.0["B_signing_seed"]).unwrap())).unwrap();
        }
        b.register_secure_storage(Box::new(store.clone()));
        for v in 1..=3 {
            assert!(b.add_verified_key(&f.circle(), v, &f.key(v)));
        }
        f.import(&b, &f.records(1..=2), 2, &list, None);
        let resigned = [v2_record(&f, "r1"), v2_record(&f, "r2"), v2_record(&f, "r3_copy_resigned_by_C")];
        assert_eq!(rows_of(&f.import(&b, &resigned, 3, &list, None)), vec![(3, Rejected, RecordProblem::Misattributed)]);
        assert!(b.is_behind(f.circle()), "passed over: behind until a repair");
        let d_out = |device: &CryptoManager| {
            for purpose in [EligibilityPurpose::Include, EligibilityPurpose::Deliver] {
                let e = f.eligibility(device, &list, "D", purpose);
                assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{purpose:?}: {e:?}");
            }
        };
        d_out(&b);
        let everyone: Vec<PlannedEntry> =
            list.iter().map(|m| PlannedEntry { user_id: m.user_id.clone(), state: RecordMemberState::Included, role: None }).collect();
        let restart_withheld = || {
            let device = restarted(&store);
            let report = f.import(&device, &f.records(1..=2), 2, &list, None);
            assert!(report.versions.is_empty() && !report.forked, "{:?}", report.versions);
            assert_eq!(device.refresh.read().unwrap()[&CircleKey::of(&f.circle())].waiting.get(&3), Some(&chain3), "v3 waits for its own record");
            assert!(device.is_behind(f.circle()));
            d_out(&device);
            let built = device.prepare_recorded_rotation_at(&f.circle(), &f.uid("B"), RefreshRecordKind::Rotation, &everyone, &list, true, "n", f.now());
            assert!(matches!(&built, Err(MobileError::InvalidInput(m)) if m.contains("v3 of this circle waits here")), "{built:?}");
            device
        };
        // Served again, v3 is judged afresh: the same copy is passed over again,
        // and the honest r3 is taken (r4 then links it).
        let again = restart_withheld();
        assert_eq!(rows_of(&f.import(&again, &resigned, 3, &list, None)), vec![(3, Rejected, RecordProblem::Misattributed)]);
        assert!(again.refresh.read().unwrap()[&CircleKey::of(&f.circle())].waiting.is_empty());
        d_out(&again);
        let again = restart_withheld();
        let report = f.import(&again, &f.records(1..=4), 4, &list, None);
        // (B never got v4's key: r4 is its reference.)
        assert_eq!(rows_of(&report), vec![(3, Accepted, RecordProblem::None), (4, Reference, RecordProblem::None)]);
        assert!(again.refresh.read().unwrap()[&CircleKey::of(&f.circle())].carried.is_empty());
        // v4, a reference above the version sealed under, keeps B
        // behind, though it seals under v3.
        assert!(again.is_behind(f.circle()));
        assert_eq!(again.get_active_version(f.circle()).ok(), Some(3));
        assert_eq!(f.eligibility(&again, &list, "D", EligibilityPurpose::Include).removed_at_version, Some(3));
    }

    #[test]
    fn v2_a_misattributed_record_is_rejected_and_passed_over_with_its_removals() {
        // A misattributed record: r3 names the owner A as its
        // signer, but the admin C's key signed it; r4, A's repair,
        // links its whole wire.
        let f = WebBuilt::new(v2_vectors::MISATTRIBUTED);
        let list = v2_list(&f, 1);
        let (b, reports) = f.step_by_step(&vec![list.clone(); 4]);
        // In format 2 its successor will fix its bytes: rejected at once, as
        // MISATTRIBUTED (a repair is due).
        assert_eq!(rows_of(&reports[2]), vec![(3, Rejected, RecordProblem::Misattributed)]);
        assert_eq!(rows_of(&reports[3]), vec![(3, Rejected, RecordProblem::Misattributed), (4, Accepted, RecordProblem::None)]);
        let e = f.eligibility(&b, &list, "D", EligibilityPurpose::Include);
        assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{e:?}");
        assert_eq!((f.role(&b, "C"), f.role(&b, "A")), (Some(CircleRole::Admin), Some(CircleRole::Owner)), "nothing else in r3 moved");
        // The account's first device, over the whole chain (R1 only): the same.
        let first = f.device(1..=4);
        let report = f.import(&first, &f.records(1..=4), 4, &list, None);
        assert_eq!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        assert!(rows_of(&report).contains(&(3, Rejected, RecordProblem::Misattributed)), "{:?}", report.versions);
        assert_eq!(f.eligibility(&first, &list, "D", EligibilityPurpose::Include).removed_at_version, Some(3));
    }

    #[test]
    fn v2_a_format_going_down_beside_a_format_2_record_is_refused_and_the_other_taken() {
        // Two records for v4 above the head (v3, format 2): C's format-1 record
        // linking v3's chain value is refused on every device for the format
        // rule, so it's dropped as a body-refused candidate is, and A's
        // format-2 record stands alone: taken, either way round.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let everyone = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.format = RecordFormat::V2;
        let v3 = everyone(&h);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let mut down = h.clone();
        down.format = RecordFormat::V1;
        down.keys.insert(4, [0x4d; 32]);
        let v4 = everyone(&down);
        down.rotate(RecordKind::Rotation, &c, v4, None);
        let mut up = h.clone();
        let v4 = everyone(&up);
        up.rotate(RecordKind::Rotation, &a, v4, None);
        for served in [[down.signed(), up.signed()].concat(), [up.signed(), down.signed()].concat()] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2, 3]);
            give(&device, &up, 4);
            let report = device.import_refresh_records_at(CIRCLE, &served, &up.links, &members, true, None, &[], NOW).unwrap();
            assert!(!report.forked, "{:?}", report.versions);
            assert_eq!(rows_of(&report), vec![(4, Rejected, RecordProblem::Structure), (4, Accepted, RecordProblem::None)]);
        }
    }

    #[test]
    fn v2_a_first_devices_prefix_passes_a_misattributed_record_over() {
        // The account's first device takes the served chain by R1
        // alone: a misattributed format-2 record in it is rejected
        // and passed over there too, so what comes after it is still
        // taken by R1: v4, A's repair, includes N, a newcomer this
        // device doesn't confirm.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let n = Acct::new(0x7e);
        let members = four_members(&a, &b, &c, &d);
        h.format = RecordFormat::V2;
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let mut h = resigned(&h, 3, &c);
        let v4 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member), (&n, Included, Member)]);
        h.rotate(RecordKind::Repair, &a, v4, None);
        let device = b.device();
        for v in 1..=4 {
            give(&device, &h, v);
        }
        let report = import(&device, &h, &members, true);
        assert!(rows_of(&report).contains(&(3, Rejected, RecordProblem::Misattributed)), "{:?}", report.versions);
        assert_eq!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
        assert_eq!(eligible(&device, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
    }

    #[test]
    fn v2_a_misattributed_version_whose_key_reached_nobody_is_repaired_from_below() {
        // C made key 3 and wrapped it for nobody, signing the owner's
        // eject of D under A's name (format 2). Its inclusions move
        // nothing, so they set no floor: A, who never got key 3,
        // repairs from below (link_to 2); B's device (keys 1, 2 and
        // 4) accepts that repair, D's removal kept, nothing sealed
        // under 3. A device where v3 still waits (C not confirmed
        // there) takes the repair only once v3 is judged.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        h.format = RecordFormat::V2;
        let v3 = rows(&h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let h = resigned(&h, 3, &c);
        let (owner, report) = device_at(&a, &a, &h, &members, &[2]);
        assert_eq!(rows_of(&report).last(), Some(&(3, Rejected, RecordProblem::Misattributed)), "{:?}", report.versions);
        let bundle = owner
            .prepare_recorded_rotation_at(
                CIRCLE, &a.uid, RefreshRecordKind::Repair,
                &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None)]),
                &members, true, "n", NOW,
            )
            .unwrap();
        let record = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        let (v3_wire, v3_signature) = &h.records[&3];
        assert_eq!((record.body.version, record.body.link_to, record.body.prev_chain), (4, 2, v3_wire.wire_chain(v3_signature)));
        let key4 = open_wrap(&b, &bundle.rotation);
        let (records, links) = served_with(&h, &bundle);
        let (member, _) = device_at(&b, &a, &h, &members, &[2]);
        assert!(member.add_verified_key(CIRCLE, 4, &key4));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Rejected, RecordProblem::Misattributed), (4, Accepted, RecordProblem::None)]);
        assert_eq!(eligible(&member, &members, &d, EligibilityPurpose::Include).removed_at_version, Some(3));
        assert_eq!(member.get_active_version(CIRCLE.into()).unwrap(), 4);
        assert!(member.held_keys(CIRCLE).iter().all(|(v, _)| *v != 3), "nothing under 3 here");
        // C not confirmed on this device: v3 waits there, and the repair is
        // not judged; with C confirmed, v3 is judged and the repair taken.
        let unconfirmed: Vec<RecordMember> = members.iter().map(|m| if m.user_id == c.uid { with(m.clone(), |m| m.confirmed = false) } else { m.clone() }).collect();
        let (late, _) = device_at(&b, &a, &h, &members, &[2]);
        assert!(late.add_verified_key(CIRCLE, 4, &key4));
        let report = late.import_refresh_records_at(CIRCLE, &records, &links, &unconfirmed, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::Signature)]);
        let report = late.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Rejected, RecordProblem::Misattributed), (4, Accepted, RecordProblem::None)]);
    }

    #[test]
    fn v2_a_misattributed_candidate_beside_another_leaves_no_winner() {
        // A candidate whose signature fails under the signer its
        // entry names is never dropped, misattributed or not. The
        // admin C's re-signed copy of the owner's eject (format 2),
        // served beside C's own v3 that keeps D: no winner, the fork
        // above the head latched, and D never kept by it.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        h.format = RecordFormat::V2;
        let mut eject = h.clone();
        let v3 = rows(&eject, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        eject.rotate(RecordKind::Rotation, &a, v3, None);
        let copy = resigned(&eject, 3, &c);
        let insider = an_insiders_v3(&h, &a, &b, &c, &d);
        for served in [[copy.signed(), insider.signed()].concat(), [insider.signed(), copy.signed()].concat()] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            let report = device.import_refresh_records_at(CIRCLE, &served, &eject.links, &members, true, None, &[], NOW).unwrap();
            assert!(report.forked && rows_of(&report) == vec![(3, Waiting, RecordProblem::Fork)], "{:?}", report.versions);
            assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].fork_latched);
        }
    }

    #[test]
    fn v2_a_format_2_steps_kept_tag_binds_after_a_restart() {
        // A kept tag binds to its step by the chain value its record
        // gives, from what that record linked: for a format-2 record
        // the wire of the step before it.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = stored_device(&a, &h, &members);
        let mut next = h.clone();
        next.format = RecordFormat::V2;
        let v3 = rows(&next, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        next.rotate(RecordKind::Rotation, &c, v3, None);
        give(&device, &next, 3);
        assert_eq!(state_of_version(&import(&device, &next, &members, true), 3).0, Accepted);
        assert!(step_of_circle(&device, 3).kept.is_some());
        device.persist_keys().unwrap();
        let again = restarted(&store);
        let step = step_of_circle(&again, 3);
        assert!(step.kept.is_some() && step.format == RecordFormat::V2 && step.wire.is_some());
    }

    #[test]
    fn v2_a_format_going_down_is_never_the_record_at_its_version() {
        // A format going down is refused: it is no step, no wait and
        // nothing links it; the version stays open. v3 is format 2;
        // v4, the admin C's format-1 record linking v3's chain
        // value, is refused. A format-2 v4 is taken after it, and
        // this device's own rotation goes at v4, on v3.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, mut h) = four();
        let members = four_members(&a, &b, &c, &d);
        let everyone = |h: &History| rows(h, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        h.format = RecordFormat::V2;
        let v3 = everyone(&h);
        h.rotate(RecordKind::Rotation, &a, v3, None);
        let mut down = h.clone();
        down.format = RecordFormat::V1;
        let v4 = everyone(&down);
        down.rotate(RecordKind::Rotation, &c, v4, None);
        let mut up = h.clone();
        up.keys.insert(4, [0x4d; 32]);
        let v4 = everyone(&up);
        up.rotate(RecordKind::Rotation, &c, v4, None);
        let (device, report) = device_at(&b, &a, &h, &members, &[2, 3]);
        assert_eq!(state_of_version(&report, 3).0, Accepted);
        let report = import(&device, &down, &members, true);
        assert_eq!(rows_of(&report), vec![(4, Rejected, RecordProblem::Structure)]);
        {
            let chains = device.refresh.read().unwrap();
            let chain = &chains[&CircleKey::of(CIRCLE)];
            assert!(!chain.seen.contains_key(&4) && !chain.waiting.contains_key(&4) && !chain.history.contains_key(&4));
        }
        assert!(!device.is_behind(CIRCLE.into()), "nothing waits: v4 stays open");
        let bundle = device
            .prepare_recorded_rotation_at(CIRCLE, &b.uid, RefreshRecordKind::Rotation, &plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]), &members, true, "n", NOW)
            .unwrap();
        let own = WireRecord::parse(&hex::decode(&bundle.refresh_record.record_hex).unwrap()).unwrap();
        let (v3_wire, v3_signature) = &h.records[&3];
        assert_eq!((own.body.version, own.body.format, own.body.prev_chain), (4, RecordFormat::V2, v3_wire.wire_chain(v3_signature)));
        let (other, _) = device_at(&b, &a, &h, &members, &[2, 3]);
        import(&other, &down, &members, true);
        give(&other, &up, 4);
        assert_eq!(state_of_version(&import(&other, &up, &members, true), 4), (Accepted, RecordProblem::None));
    }

    #[test]
    fn v2_a_format_1_record_after_a_format_2_one_is_refused() {
        // The fifth file: r3 is validly signed and linked as a
        // format-1 record links; only the format rule refuses it.
        let f = WebBuilt::new(v2_vectors::FORMAT_DOWN);
        let list = v2_list(&f, 1);
        let (_, reports) = f.step_by_step(&vec![list.clone(); 3]);
        assert_eq!(rows_of(&reports[2]), vec![(3, Rejected, RecordProblem::Structure)]);
        // As the account's first device, over the whole chain.
        let first = f.device(1..=3);
        let report = f.import(&first, &f.records(1..=3), 3, &list, None);
        assert!(rows_of(&report).contains(&(3, Rejected, RecordProblem::Structure)), "{:?}", report.versions);
    }

    /// `h` with record `version` signed by `by` instead, its signer entry
    /// unchanged (a misattribution, or a re-signed copy).
    fn resigned(h: &History, version: u32, by: &Acct) -> History {
        let mut out = h.clone();
        let (wire, _) = out.records[&version].clone();
        let signature = by.signing.sign(&wire.signed_digest()).to_bytes();
        out.records.insert(version, (wire, signature));
        out
    }

    #[test]
    fn v2_a_misattributed_format_1_record_is_passed_over_only_before_a_format_2_one() {
        // A misattributed record is passed over only when it is in
        // format 2, or the record after it is. v3 (format 1) names
        // the owner A as its signer and ejects D; the admin C's key
        // signed it. Alone, or with a format-1 v4 after it, it waits;
        // with a format-2 v4 after it (A's repair, linking its whole
        // wire), it is rejected and passed over, D's removal
        // counting.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let mut eject = h.clone();
        let v3 = rows(&eject, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
        eject.rotate(RecordKind::Rotation, &a, v3, None);
        let misattributed = resigned(&eject, 3, &c);
        let repair_on = |format: RecordFormat| {
            let mut next = misattributed.clone();
            next.format = format;
            let v4 = rows(&next, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Removed, Member)]);
            next.rotate(RecordKind::Repair, &a, v4, None);
            next
        };
        for (served, want) in [
            (up_to(&misattributed, 3), vec![(3, Waiting, RecordProblem::Signature)]),
            (repair_on(RecordFormat::V1), vec![(3, Waiting, RecordProblem::Signature)]),
            (repair_on(RecordFormat::V2), vec![(3, Rejected, RecordProblem::Misattributed), (4, Accepted, RecordProblem::None)]),
        ] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            for v in 3..=4 {
                if served.keys.contains_key(&v) {
                    give(&device, &served, v);
                }
            }
            let report = import(&device, &served, &members, true);
            assert_eq!(rows_of(&report), want);
            if want.len() == 2 {
                let e = eligible(&device, &members, &d, EligibilityPurpose::Include);
                assert!(!e.eligible && e.removed_by_owner_or_admin && e.removed_at_version == Some(3), "{e:?}");
            }
        }
    }

    #[test]
    fn v2_a_store_without_its_heads_wire_learns_it_from_the_head_served_again() {
        // A device whose stored state predates `~rrx:`: it knows its head's
        // chain value, not its wire. It asks for its head record again (the
        // server serves `version > since`), learns the wire from it once its
        // signature verifies, and only then links a format-2 record; it builds
        // nothing on the head before.
        use ChainRole::{Admin, Member, Owner};
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, store) = stored_device(&a, &h, &members);
        let mut pins = stored_pins(&store);
        assert!(pins.contains_key(&format!("{WIRE_PREFIX}{CIRCLE}:2")), "a step's wire is kept");
        pins.retain(|key, _| !key.starts_with(WIRE_PREFIX));
        set_stored_pins(&store, &pins);
        drop(device);
        let mut next = h.clone();
        next.format = RecordFormat::V2;
        let v3 = rows(&next, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        next.rotate(RecordKind::Rotation, &c, v3, None);
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let again = restarted(&store);
        assert_eq!((step_of_circle(&again, 2).wire, again.refresh_head_versions().get(CIRCLE)), (None, Some(&0)), "not imported in this process yet");
        give(&again, &next, 3);
        // Served only what's above its head: v3 can't be linked yet, it waits;
        // the head is asked for again, and nothing is built on it.
        let only_v3 = |hist: &History| hist.signed().into_iter().skip(2).collect::<Vec<_>>();
        let report = again.import_refresh_records_at(CIRCLE, &only_v3(&next), &next.links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::RecordMissing)]);
        assert_eq!(again.refresh_head_versions().get(CIRCLE), Some(&1));
        let built = again.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW);
        assert!(built.is_err(), "nothing is built on a head whose wire isn't known");
        // Its head record served again: the wire is learned, v3 linked.
        let from_v2 = next.signed().into_iter().skip(1).collect::<Vec<_>>();
        let report = again.import_refresh_records_at(CIRCLE, &from_v2, &next.links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None), "{:?}", report.versions);
        let (wire2, signature2) = &h.records[&2];
        assert_eq!(step_of_circle(&again, 2).wire, Some(wire2.wire_chain(signature2)));
        assert_eq!(again.refresh_head_versions().get(CIRCLE), Some(&3));
        // Its copy of v2 spoiled, or signed with another member's
        // key (C's) than the owner its entry names: nothing is
        // learned, and v3 waits; the honest copy then teaches it.
        let copies: [fn(&History) -> History; 2] = [
            |h: &History| {
                let mut spoiled = h.clone();
                spoiled.records.get_mut(&2).unwrap().1[0] ^= 1;
                spoiled
            },
            |h: &History| resigned(h, 2, &Acct::new(0xc1)),
        ];
        for copy in copies {
            set_stored_pins(&store, &pins);
            let again = restarted(&store);
            give(&again, &next, 3);
            let offered = copy(&next);
            let report = again.import_refresh_records_at(CIRCLE, &offered.signed().into_iter().skip(1).collect::<Vec<_>>(), &next.links, &members, true, None, &[], NOW).unwrap();
            assert!(rows_of(&report).contains(&(3, Waiting, RecordProblem::RecordMissing)), "{:?}", report.versions);
            assert_eq!(step_of_circle(&again, 2).wire, None);
            let report = again.import_refresh_records_at(CIRCLE, &from_v2, &next.links, &members, true, None, &[], NOW).unwrap();
            assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None), "{:?}", report.versions);
        }
    }

    fn step_of_circle(device: &CryptoManager, version: u32) -> ChainStep {
        device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].history[&version]
    }

    #[test]
    fn v2_a_steps_wire_is_kept_bound_and_read_fail_closed() {
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (_device, store) = stored_device(&a, &h, &members);
        let key = format!("{WIRE_PREFIX}{CIRCLE}:2");
        let (wire2, signature2) = &h.records[&2];
        // Kept, and read back bound to its step, with its format.
        let again = restarted(&store);
        assert_eq!((step_of_circle(&again, 2).wire, step_of_circle(&again, 2).format), (Some(wire2.wire_chain(signature2)), RecordFormat::V1));
        // One written for another chain value at that version: dropped.
        let mut pins = stored_pins(&store);
        pins.get_mut(&key).unwrap().signing_pubkey_hex = hex::encode([0x5a; 32]);
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        assert_eq!(step_of_circle(&again, 2).wire, None);
        assert!(!again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].forked);
        // One that doesn't read: the circle waits, latched, as for any part of
        // its stored state that doesn't read.
        for garble in [|p: &mut PinRecord| p.sharing_pubkey_hex = "zz".into(), |p: &mut PinRecord| p.last_verified_at = 3, |p: &mut PinRecord| p.first_pinned_at = 7] {
            let (_device, store) = stored_device(&a, &h, &members);
            let mut pins = stored_pins(&store);
            garble(pins.get_mut(&key).unwrap());
            set_stored_pins(&store, &pins);
            let again = restarted(&store);
            let chains = again.refresh.read().unwrap();
            assert!(chains[&CircleKey::of(CIRCLE)].forked && !chains[&CircleKey::of(CIRCLE)].as_stored.is_empty());
        }
    }

    #[test]
    fn v2_a_head_is_compared_in_its_own_format_and_only_with_what_is_known_here() {
        // A format-1 head against the record's chain value, a
        // format-2 head against the wire of the copy this device
        // took; after a restart from a store written by an older
        // SDK (no `~rrx:`), with no record held yet, nothing is
        // compared: never a fork on that alone.
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let signed_head = |format: RecordFormat, chain: [u8; 32]| {
            let bytes = Head { format, circle_id: circle16(), user_id: a.uid16(), version: 2, chain }.encode().unwrap();
            MemberHead { user_id: a.uid.clone(), head: SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(a.signing.sign(&Head::digest(&bytes)).to_bytes()) } }
        };
        let (wire2, signature2) = &h.records[&2];
        for (head, forks) in [
            (signed_head(RecordFormat::V2, wire2.wire_chain(signature2)), false),
            (signed_head(RecordFormat::V2, [0x77; 32]), true),
            (signed_head(RecordFormat::V2, wire2.chain()), true),
            (signed_head(RecordFormat::V1, wire2.chain()), false),
            (signed_head(RecordFormat::V1, [0x77; 32]), true),
        ] {
            let (device, _) = device_at(&b, &a, &h, &members, &[2]);
            let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &[head], NOW).unwrap();
            assert_eq!(report.forked, forks, "{:?}", report.versions);
        }
        let (device, store) = stored_device(&a, &h, &members);
        drop(device);
        let mut pins = stored_pins(&store);
        pins.retain(|key, _| !key.starts_with(WIRE_PREFIX));
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        let report = again.import_refresh_records_at(CIRCLE, &[], &h.links, &members, true, None, &[signed_head(RecordFormat::V2, [0x77; 32])], NOW).unwrap();
        assert!(!report.forked);
        // The head record served again: its wire is known, and the head a fork.
        let report = again.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &members, true, None, &[signed_head(RecordFormat::V2, [0x77; 32])], NOW).unwrap();
        assert!(report.forked);
    }

    // ------------------------------------------------------------------
    // A step's format is kept apart from its wire: formats only
    // go up, after a restart too
    // ------------------------------------------------------------------

    /// four()'s accounts, with v2 in `v2_format`; A's device at v2, stored.
    fn a_head_in(v2_format: RecordFormat) -> (Acct, Acct, Acct, Acct, History, Vec<RecordMember>, MemStore) {
        let (a, b, c, d, _) = four();
        let members = four_members(&a, &b, &c, &d);
        let mut h = History::genesis(&a);
        h.format = v2_format;
        let everyone = rows(&h, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&d, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &a, everyone, None);
        let (_, store) = stored_device(&a, &h, &members);
        (a, b, c, d, h, members, store)
    }

    /// The admin C's format-1 v3 on v2's chain value (an insider's), and a
    /// server that serves it with v2 withheld.
    fn a_format_1_v3(a: &Acct, b: &Acct, c: &Acct, d: &Acct, h: &History) -> (History, Vec<SignedRefreshRecord>) {
        let mut down = h.clone();
        down.format = RecordFormat::V1;
        let everyone = rows(&down, &[(a, Included, ChainRole::Owner), (b, Included, ChainRole::Member), (c, Included, ChainRole::Admin), (d, Included, ChainRole::Member)]);
        down.rotate(RecordKind::Rotation, c, everyone, None);
        let v3_alone = down.signed().into_iter().skip(2).collect();
        (down, v3_alone)
    }

    #[test]
    fn a_format_2_step_without_its_wire_stays_format_2_after_a_restart() {
        // v2 is format 2, and no wire of it is kept here (its `~rrx:` gone).
        // Reloaded, it's still format 2: C's format-1 v3 on its chain value,
        // served with v2 withheld, is refused for the format rule alone.
        let (a, b, c, d, h, members, store) = a_head_in(RecordFormat::V2);
        let mut pins = stored_pins(&store);
        assert_eq!(pins[&format!("{HISTORY_PREFIX}{CIRCLE}:2")].last_verified_at, 2, "the step's own entry keeps its format");
        pins.retain(|key, _| !key.starts_with(WIRE_PREFIX));
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        let step = step_of_circle(&again, 2);
        assert_eq!((step.wire, step.format, step.format_known), (None, RecordFormat::V2, true));
        let (down, v3_alone) = a_format_1_v3(&a, &b, &c, &d, &h);
        give(&again, &down, 3);
        let report = again.import_refresh_records_at(CIRCLE, &v3_alone, &down.links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Rejected, RecordProblem::Structure)]);
        assert_eq!(again.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].head.as_ref().map(|h| h.version), Some(2));
    }

    #[test]
    fn a_store_with_no_steps_format_links_nothing_until_its_record_comes_again() {
        // A store written by an older SDK: its `~rrv:` holds no format (0) and
        // no wire is kept. A format-1 v3 on the head's chain value waits (the
        // head record is asked for again); served with it, v3 is taken after a
        // format-1 v2 and refused after a format-2 one.
        for v2_format in [RecordFormat::V1, RecordFormat::V2] {
            let (a, b, c, d, h, members, store) = a_head_in(v2_format);
            let mut pins = stored_pins(&store);
            pins.retain(|key, _| !key.starts_with(WIRE_PREFIX));
            for (key, record) in pins.iter_mut() {
                if key.starts_with(HISTORY_PREFIX) && !key.ends_with(KEPT_TAG_SUFFIX) {
                    record.last_verified_at = 0;
                }
            }
            set_stored_pins(&store, &pins);
            let again = restarted(&store);
            assert!(!step_of_circle(&again, 2).format_known, "{v2_format:?}");
            let (down, v3_alone) = a_format_1_v3(&a, &b, &c, &d, &h);
            give(&again, &down, 3);
            let report = again.import_refresh_records_at(CIRCLE, &v3_alone, &down.links, &members, true, None, &[], NOW).unwrap();
            assert_eq!(rows_of(&report), vec![(3, Waiting, RecordProblem::RecordMissing)], "{v2_format:?}");
            assert_eq!(again.refresh_head_versions().get(CIRCLE), Some(&1), "{v2_format:?}: the head record is asked for again");
            // Its head record served again (any copy of that body teaches its
            // format): v3 is judged.
            let report = again.import_refresh_records_at(CIRCLE, &down.signed(), &down.links, &members, true, None, &[], NOW).unwrap();
            let want = match v2_format {
                RecordFormat::V1 => (Accepted, RecordProblem::None),
                RecordFormat::V2 => (Rejected, RecordProblem::Structure),
            };
            assert_eq!(state_of_version(&report, 3), want, "{v2_format:?}");
            assert!(step_of_circle(&again, 2).format_known, "{v2_format:?}");
        }
    }

    #[test]
    fn a_store_whose_wire_entry_tells_the_format_links_at_once() {
        // A store written by an older SDK: its `~rrv:` holds no format, its
        // `~rrx:` does. The format is known from the wire's entry, and a
        // format-2 v3 on the head's wire is taken with nothing served again.
        use ChainRole::{Admin, Member, Owner};
        let (a, b, c, d, h, members, store) = a_head_in(RecordFormat::V2);
        let mut pins = stored_pins(&store);
        for (key, record) in pins.iter_mut() {
            if key.starts_with(HISTORY_PREFIX) && !key.ends_with(KEPT_TAG_SUFFIX) {
                record.last_verified_at = 0;
            }
        }
        set_stored_pins(&store, &pins);
        let again = restarted(&store);
        let step = step_of_circle(&again, 2);
        assert!(step.wire.is_some() && step.format == RecordFormat::V2 && step.format_known);
        let mut next = h.clone();
        let everyone = rows(&next, &[(&a, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)]);
        next.rotate(RecordKind::Rotation, &c, everyone, None);
        give(&again, &next, 3);
        let v3_alone: Vec<SignedRefreshRecord> = next.signed().into_iter().skip(2).collect();
        let report = again.import_refresh_records_at(CIRCLE, &v3_alone, &next.links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(rows_of(&report), vec![(3, Accepted, RecordProblem::None)]);
    }

    #[test]
    fn a_steps_format_that_does_not_read_leaves_the_circle_waiting() {
        let (_a, _b, _c, _d, _h, _members, store) = a_head_in(RecordFormat::V2);
        for code in [3, -1, 258] {
            let mut pins = stored_pins(&store);
            pins.get_mut(&format!("{HISTORY_PREFIX}{CIRCLE}:2")).unwrap().last_verified_at = code;
            set_stored_pins(&store, &pins);
            let again = restarted(&store);
            let chains = again.refresh.read().unwrap();
            assert!(chains[&CircleKey::of(CIRCLE)].forked && !chains[&CircleKey::of(CIRCLE)].as_stored.is_empty(), "{code}");
        }
    }

    #[test]
    fn every_step_keeps_its_format() {
        let (_a, _b, _c, _d, _h, _members, store) = a_head_in(RecordFormat::V2);
        let pins = stored_pins(&store);
        let format_of = |v: u32| pins[&format!("{HISTORY_PREFIX}{CIRCLE}:{v}")].last_verified_at;
        assert_eq!((format_of(1), format_of(2)), (1, 2), "the genesis in format 1, v2 in format 2");
    }

    // ------------------------------------------------------------------
    // The web's own format-2 records: the two web-built v2 files,
    // checked value by value and through the importer
    // ------------------------------------------------------------------

    mod web_built_v2 {
        //! Files the web client's builder wrote, copied byte for byte
        //! and pinned by sha256. r1, r2 and r4 of the first file and r3
        //! of the switch were made by the web's builder; every value is
        //! rebuilt here with this SDK's code, and each importer the
        //! files' headers name gets what they say. The web's repair r4
        //! leaves D out (a repairer may leave a removed member out),
        //! and the importer keeps r3's counted removal.
        use super::*;
        use crate::membership::{decode_statement, statement_digest, MembershipStatementKind};
        use crate::refresh_record::{circle_secret, key_commitment, member_code};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};
        use sha2::{Digest, Sha256};
        use std::cell::RefCell;
        use std::collections::HashSet;

        const WEB_BUILT: &str = include_str!("../tests/data/refresh_record_v2_web_built.txt");
        const WEB_BUILT_SWITCH: &str = include_str!("../tests/data/refresh_record_v2_web_built_switch.txt");

        #[test]
        fn the_two_web_built_v2_files_are_the_pinned_bytes() {
            let sha = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
            assert_eq!(sha(WEB_BUILT), "39596b840795250e399694390222f918a322e093742fc0f7d26ab01967d147a2");
            assert_eq!(sha(WEB_BUILT_SWITCH), "12d0e532f78a357b20261ac4c62da4aab414eca2d57c21492e0021bb845b7a3d");
        }

        /// A file, every name read from it, and the name of every check that
        /// failed (never a value: the files hold seeds and keys).
        struct Web {
            values: HashMap<String, String>,
            read: RefCell<HashSet<String>>,
            failed: RefCell<Vec<String>>,
        }

        impl Web {
            fn new(text: &str) -> Self {
                let values = text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).map(|l| l.split_once('=').unwrap()).map(|(k, v)| (k.to_string(), v.to_string())).collect();
                Web { values, read: RefCell::new(HashSet::new()), failed: RefCell::new(Vec::new()) }
            }
            fn s(&self, k: &str) -> String {
                self.read.borrow_mut().insert(k.to_string());
                self.values.get(k).unwrap_or_else(|| panic!("{k} is in the file")).clone()
            }
            fn b(&self, k: &str) -> Vec<u8> {
                hex::decode(self.s(k)).unwrap_or_else(|_| panic!("{k} is hex"))
            }
            fn b32(&self, k: &str) -> [u8; 32] {
                self.b(k).try_into().unwrap_or_else(|_| panic!("{k} is 32 bytes"))
            }
            fn b64(&self, k: &str) -> [u8; 64] {
                self.b(k).try_into().unwrap_or_else(|_| panic!("{k} is 64 bytes"))
            }
            fn u16(&self, k: &str) -> [u8; 16] {
                *uuid::Uuid::parse_str(&self.s(k)).unwrap_or_else(|_| panic!("{k} is a UUID")).as_bytes()
            }
            fn check(&self, what: &str, holds: bool) {
                if !holds {
                    self.failed.borrow_mut().push(what.to_string());
                }
            }
            /// Every check held, and every value in the file was read.
            fn done(&self) {
                let read = self.read.borrow();
                let mut unread: Vec<&String> = self.values.keys().filter(|k| !read.contains(*k)).collect();
                unread.sort();
                assert!(self.failed.borrow().is_empty() && unread.is_empty(), "failed {:?}, unread {unread:?}", self.failed.borrow());
            }
            fn wire(&self, r: &str) -> (WireRecord, [u8; 64]) {
                (WireRecord::parse(&self.b(&format!("{r}_record_wire"))).unwrap_or_else(|e| panic!("{r}: {e:?}")), self.b64(&format!("{r}_signature")))
            }
        }

        struct Who {
            uid: [u8; 16],
            signing: [u8; 32],
            sharing: [u8; 32],
            code: [u8; 32],
            commitment: [u8; 32],
        }

        /// S, each member's keys, code and commitment, and each invitation (by A, at v1).
        fn members(f: &Web, names: &[&str], invited: &[&str]) -> HashMap<String, Who> {
            let secret = circle_secret(&f.b("key_v1")).unwrap();
            f.check("S = circle_secret(key_v1)", *secret == f.b32("S"));
            let circle = f.s("circle_id");
            let now: i64 = f.s("now").parse().unwrap();
            let mut who = HashMap::new();
            for n in names {
                let uid = f.u16(&format!("{n}_user_id"));
                let signing = SigningKey::from_bytes(&f.b32(&format!("{n}_signing_seed"))).verifying_key().to_bytes();
                f.check(&format!("{n}_signing_pk from its seed"), signing == f.b32(&format!("{n}_signing_pk")));
                let sharing = f.b32(&format!("{n}_sharing_pk"));
                let code = member_code(&secret, &uid);
                let commitment = key_commitment(&secret, &code, &sharing, &signing);
                who.insert(n.to_string(), Who { uid, signing, sharing, code, commitment });
            }
            for n in invited {
                let bytes = f.b(&format!("{n}_invitation"));
                let signature = f.b64(&format!("{n}_invitation_signature"));
                let Ok(st) = decode_statement(&bytes) else {
                    f.check(&format!("{n}_invitation decodes"), false);
                    continue;
                };
                let (a, w) = (&who["A"], &who[*n]);
                let id = |uid: &[u8; 16]| uuid::Uuid::from_bytes(*uid).hyphenated().to_string();
                f.check(
                    &format!("{n}_invitation_signature under A's key"),
                    VerifyingKey::from_bytes(&a.signing).unwrap().verify_strict(&statement_digest(&bytes), &Signature::from_bytes(&signature)).is_ok(),
                );
                f.check(
                    &format!("{n}_invitation: A invites {n}'s account, with {n}'s keys, into this circle"),
                    st.kind == MembershipStatementKind::InvitationToAccount
                        && st.circle_id == circle
                        && st.signer_user_id == id(&a.uid)
                        && st.subject_user_id.as_deref() == Some(id(&w.uid).as_str())
                        && st.subject_sharing_public_key_hex.as_deref() == Some(hex::encode(w.sharing).as_str())
                        && st.subject_signing_public_key_hex.as_deref() == Some(hex::encode(w.signing).as_str()),
                );
                f.check(&format!("{n}_invitation: at v1, fresh at now"), st.at_version == 1 && st.issued_at <= now && now < st.expires_at);
            }
            who
        }

        /// One record against what the file says of it: its bytes, kind,
        /// format, version, signer entry, the one key its signature verifies
        /// under, its key tag, wire_chain (and chain_V in format 1), and every
        /// entry's code, commitment, state and role.
        #[allow(clippy::too_many_arguments)]
        fn record(f: &Web, who: &HashMap<String, Who>, r: &str, version: u32, kind: RecordKind, format: RecordFormat, signed_by: &str, entries: &[(&str, EntryState, ChainRole)]) -> (WireRecord, [u8; 64]) {
            let (wire, signature) = f.wire(r);
            f.s(&format!("{r}_made_by"));
            f.check(&format!("{r}: travels as the same bytes"), wire.to_bytes() == f.b(&format!("{r}_record_wire")) && wire.body.encode().unwrap() == wire.body_bytes);
            f.check(&format!("{r}: circle and version"), wire.body.circle_id == f.u16("circle_id") && wire.body.version == version);
            f.check(&format!("{r}: kind"), wire.body.kind == kind && format!("{kind:?}").to_lowercase() == f.s(&format!("{r}_kind")));
            f.check(&format!("{r}: format"), wire.body.format == format && f.s(&format!("{r}_format")) == if format == RecordFormat::V2 { "2" } else { "1" });
            f.check(&format!("{r}: its signer entry names A"), wire.body.signer_code == who["A"].code);
            for (n, w) in who {
                f.check(&format!("{r}: verifies under {n}'s key only if {n} signed it"), wire.signature_verifies(&signature, &w.signing) == (n == signed_by));
            }
            f.check(&format!("{r}: key tag over key_v{version}"), wire.key_tag_matches(&f.b(&format!("key_v{version}"))));
            f.check(&format!("{r}_wire_chain"), wire.wire_chain(&signature) == f.b32(&format!("{r}_wire_chain")));
            if format == RecordFormat::V1 {
                f.check(&format!("{r}_chain"), wire.chain() == f.b32(&format!("{r}_chain")));
            }
            let mut got = Vec::new();
            for e in &wire.body.entries {
                match who.iter().find(|(_, w)| w.code == e.code) {
                    Some((n, w)) => {
                        f.check(&format!("{r}: {n}'s entry commits to {n}'s keys"), e.commitment == w.commitment);
                        got.push((n.clone(), e.state, e.role));
                    }
                    None => f.check(&format!("{r}: an entry matches no member"), false),
                }
            }
            got.sort_by(|a, b| a.0.cmp(&b.0));
            let want: Vec<(String, EntryState, ChainRole)> = entries.iter().map(|(n, s, role)| (n.to_string(), *s, *role)).collect();
            f.check(&format!("{r}: its entries"), got == want);
            (wire, signature)
        }

        fn link(f: &Web, from: u32, to: u32) {
            let opened = XChaCha20Poly1305::new_from_slice(&f.b(&format!("key_v{from}")))
                .unwrap()
                .decrypt(XNonce::from_slice(&f.b(&format!("link_{from}_{to}_nonce"))), f.b(&format!("link_{from}_{to}_encrypted_key")).as_slice());
            f.check(&format!("link {from} -> {to}"), opened.map_or(false, |key| key == f.b(&format!("key_v{to}"))));
        }

        /// A's format-2 head over `of`'s whole wire, under A's key.
        fn head(f: &Web, who: &HashMap<String, Who>, name: &str, of: &(WireRecord, [u8; 64])) {
            let bytes = f.b(name);
            let signature = f.b64(&format!("{name}_signature"));
            let Ok(h) = Head::decode(&bytes) else { return f.check(&format!("{name}: decodes"), false) };
            f.check(
                &format!("{name}: format 2, this circle, A, over its record's wire"),
                h.format == RecordFormat::V2 && h.circle_id == f.u16("circle_id") && h.user_id == who["A"].uid && h.version == of.0.body.version && h.chain == of.0.wire_chain(&of.1),
            );
            f.check(&format!("{name}: encodes again to the same bytes"), h.encode().unwrap().to_vec() == bytes);
            let array: [u8; 69] = bytes.as_slice().try_into().unwrap();
            f.check(&format!("{name}_signature under A's key"), VerifyingKey::from_bytes(&who["A"].signing).unwrap().verify_strict(&Head::digest(&array), &Signature::from_bytes(&signature)).is_ok());
        }

        fn listed(f: &Web, n: &str, role: CircleRole, invited: bool) -> RecordMember {
            RecordMember {
                user_id: f.s(&format!("{n}_user_id")),
                sharing_public_key_hex: Some(f.s(&format!("{n}_sharing_pk"))),
                signing_public_key_hex: Some(f.s(&format!("{n}_signing_pk"))),
                confirmed: true,
                listed: true,
                listed_role: Some(role),
                statements: if invited {
                    vec![HeldStatement { statement_hex: f.s(&format!("{n}_invitation")), signature_hex: f.s(&format!("{n}_invitation_signature")) }]
                } else {
                    Vec::new()
                },
                person_confirmed_keys: false,
                server_says_keyless: false,
            }
        }

        fn device(f: &Web, versions: &[u32]) -> Arc<CryptoManager> {
            let device = CryptoManager::new();
            for v in versions {
                assert!(device.add_verified_key(&f.s("circle_id"), *v, &f.b(&format!("key_v{v}"))));
            }
            device
        }

        fn import(f: &Web, device: &CryptoManager, rs: &[&str], links: &[(u32, u32)], list: &[RecordMember], heads: &[MemberHead]) -> RefreshRecordsReport {
            let records: Vec<SignedRefreshRecord> =
                rs.iter().map(|r| SignedRefreshRecord { record_hex: f.s(&format!("{r}_record_wire")), signature_hex: f.s(&format!("{r}_signature")) }).collect();
            let links: Vec<KeyChainLinkData> = links
                .iter()
                .map(|(from, to)| KeyChainLinkData {
                    from_version: *from as i32,
                    to_version: *to as i32,
                    encrypted_key: f.s(&format!("link_{from}_{to}_encrypted_key")),
                    nonce: f.s(&format!("link_{from}_{to}_nonce")),
                })
                .collect();
            device.import_refresh_records_at(&f.s("circle_id"), &records, &links, list, true, None, heads, f.s("now").parse().unwrap()).unwrap()
        }

        fn a_head(f: &Web, name: &str) -> MemberHead {
            MemberHead { user_id: f.s("A_user_id"), head: SignedCircleHead { head_hex: f.s(name), signature_hex: f.s(&format!("{name}_signature")) } }
        }

        #[test]
        fn the_webs_genesis_rotation_misattribution_and_repair_from_below() {
            use ChainRole::{Admin, Member, Owner};
            use EntryState::{Included, Removed};
            let f = Web::new(WEB_BUILT);
            let who = members(&f, &["A", "B", "C", "D"], &["B", "C", "D"]);
            let everyone = [("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("D", Included, Member)];
            let r1 = record(&f, &who, "r1", 1, RecordKind::Genesis, RecordFormat::V2, "A", &[("A", Included, Owner)]);
            let r2 = record(&f, &who, "r2", 2, RecordKind::Rotation, RecordFormat::V2, "A", &everyone);
            // Misattributed: its signer entry names A, C's key signed it; it ejects D.
            let r3 = record(&f, &who, "r3", 3, RecordKind::Rotation, RecordFormat::V2, "C", &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("D", Removed, Member)]);
            let r4 = record(&f, &who, "r4", 4, RecordKind::Repair, RecordFormat::V2, "A", &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin)]);
            f.check("r1 links nothing", r1.0.body.prev_version == 0 && r1.0.body.prev_chain == [0u8; 32]);
            f.check("r2 links r1's whole wire", r2.0.body.prev_version == 1 && r2.0.body.prev_chain == r1.0.wire_chain(&r1.1));
            f.check("r3 links r2's whole wire", r3.0.body.prev_version == 2 && r3.0.body.prev_chain == r2.0.wire_chain(&r2.1));
            f.check("r4 links r3's whole wire, from below", r4.0.body.prev_version == 3 && r4.0.body.prev_chain == r3.0.wire_chain(&r3.1) && r4.0.body.link_to == 2);
            for (from, to) in [(2, 1), (3, 2), (4, 2)] {
                link(&f, from, to);
            }
            head(&f, &who, "head_A_v4", &r4);
            // B's device: key_v1, then key_v2, never key_v3, then key_v4.
            let list = [listed(&f, "A", CircleRole::Owner, false), listed(&f, "B", CircleRole::Member, true), listed(&f, "C", CircleRole::Admin, true), listed(&f, "D", CircleRole::Member, true)];
            let circle = f.s("circle_id");
            let now: i64 = f.s("now").parse().unwrap();
            let role = |device: &CryptoManager, n: &str| device.chain_role(circle.clone(), f.s(&format!("{n}_user_id")));
            let b = device(&f, &[1]);
            f.check("B takes r1", rows_of(&import(&f, &b, &["r1"], &[], &list, &[])) == vec![(1, Accepted, RecordProblem::None)]);
            assert!(b.add_verified_key(&circle, 2, &f.b("key_v2")));
            f.check("B takes r2", rows_of(&import(&f, &b, &["r1", "r2"], &[(2, 1)], &list, &[])) == vec![(2, Accepted, RecordProblem::None)]);
            let report = import(&f, &b, &["r1", "r2", "r3"], &[(2, 1), (3, 2)], &list, &[]);
            f.check("B rejects r3 as MISATTRIBUTED", rows_of(&report) == vec![(3, Rejected, RecordProblem::Misattributed)]);
            f.check("B is behind, sealing v2", b.is_behind(circle.clone()) && b.get_active_version(circle.clone()).ok() == Some(2));
            assert!(b.add_verified_key(&circle, 4, &f.b("key_v4")));
            let report = import(&f, &b, &["r1", "r2", "r3", "r4"], &[(2, 1), (3, 2), (4, 2)], &list, &[a_head(&f, "head_A_v4")]);
            f.check("B takes the repair r4", rows_of(&report).contains(&(4, Accepted, RecordProblem::None)));
            f.check("A's head is no fork", !report.forked);
            f.check("B seals v4 and isn't behind", b.get_active_version(circle.clone()).ok() == Some(4) && !b.is_behind(circle.clone()));
            f.check("A owner, C admin, D gone", role(&b, "A") == Some(CircleRole::Owner) && role(&b, "C") == Some(CircleRole::Admin) && role(&b, "D").is_none());
            let d = b.refresh_eligibility_at(&circle, &list, EligibilityPurpose::Include, now).unwrap().into_iter().find(|e| e.user_id == f.s("D_user_id")).unwrap();
            f.check("D removed at 3, by the owner", !d.eligible && d.removed_by_owner_or_admin && d.removed_at_version == Some(3));
            // C's first device, holding key_v4 only (links 4 -> 2, 2 -> 1).
            let c = device(&f, &[4]);
            let report = import(&f, &c, &["r1", "r2", "r3", "r4"], &[(2, 1), (4, 2)], &list, &[]);
            f.check("C's prefix rejects r3 as MISATTRIBUTED", rows_of(&report).contains(&(3, Rejected, RecordProblem::Misattributed)));
            f.check("C takes r4", rows_of(&report).contains(&(4, Accepted, RecordProblem::None)));
            f.check("D gone on C", role(&c, "D").is_none());
            f.done();
        }

        #[test]
        fn the_webs_first_format_2_record_on_a_format_1_chain() {
            use ChainRole::{Admin, Member, Owner};
            use EntryState::{Included, Removed};
            let f = Web::new(WEB_BUILT_SWITCH);
            let who = members(&f, &["A", "B", "C"], &["B", "C"]);
            let r1 = record(&f, &who, "r1", 1, RecordKind::Genesis, RecordFormat::V1, "A", &[("A", Included, Owner)]);
            let r2 = record(&f, &who, "r2", 2, RecordKind::Rotation, RecordFormat::V1, "A", &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin)]);
            let r3 = record(&f, &who, "r3", 3, RecordKind::Rotation, RecordFormat::V2, "A", &[("A", Included, Owner), ("B", Removed, Member), ("C", Included, Admin)]);
            f.check("r1 links nothing", r1.0.body.prev_version == 0 && r1.0.body.prev_chain == [0u8; 32]);
            f.check("r2 links r1's chain_V", r2.0.body.prev_version == 1 && r2.0.body.prev_chain == r1.0.chain());
            f.check("r3 links r2's whole wire", r3.0.body.prev_version == 2 && r3.0.body.prev_chain == r2.0.wire_chain(&r2.1));
            for (from, to) in [(2, 1), (3, 2)] {
                link(&f, from, to);
            }
            head(&f, &who, "head_A_v3", &r3);
            // C's device, holding key_vN at step N: A, B, C listed (with their
            // invitations) at steps 1 and 2, A and C at step 3.
            let before = [listed(&f, "A", CircleRole::Owner, false), listed(&f, "B", CircleRole::Member, true), listed(&f, "C", CircleRole::Admin, true)];
            let after = [listed(&f, "A", CircleRole::Owner, false), listed(&f, "C", CircleRole::Admin, true)];
            let circle = f.s("circle_id");
            let c = device(&f, &[1]);
            f.check("C takes r1", rows_of(&import(&f, &c, &["r1"], &[], &before, &[])) == vec![(1, Accepted, RecordProblem::None)]);
            assert!(c.add_verified_key(&circle, 2, &f.b("key_v2")));
            f.check("C takes r2", rows_of(&import(&f, &c, &["r1", "r2"], &[(2, 1)], &before, &[])) == vec![(2, Accepted, RecordProblem::None)]);
            assert!(c.add_verified_key(&circle, 3, &f.b("key_v3")));
            let report = import(&f, &c, &["r1", "r2", "r3"], &[(2, 1), (3, 2)], &after, &[a_head(&f, "head_A_v3")]);
            f.check("C takes r3", rows_of(&report) == vec![(3, Accepted, RecordProblem::None)]);
            f.check("A's head is no fork", !report.forked);
            let role = |n: &str| c.chain_role(circle.clone(), f.s(&format!("{n}_user_id")));
            f.check("A owner, B gone, C admin", role("A") == Some(CircleRole::Owner) && role("B").is_none() && role("C") == Some(CircleRole::Admin));
            f.check("C seals v3 and isn't behind", c.get_active_version(circle.clone()).ok() == Some(3) && !c.is_behind(circle.clone()));
            f.done();
        }
    }

    // ========================================================================
    // After a password reset and the portal's restore, the account's OWN
    // entry is also matched through its recovered pre-reset pairs, by the
    // commitment alone. And a reference head above the version sealed
    // under is behind.
    // ========================================================================

    /// `a` after a password reset: the same account, new keys.
    fn reset(a: &Acct, n: u8) -> Acct {
        Acct { uid: a.uid.clone(), signing: SigningKey::from_bytes(&[n; 32]), sharing: StaticSecret::from([n ^ 0x5a; 32]) }
    }

    /// The portal's restore of `old` on `new`'s device: the v2 blob (its
    /// signing key bound), or with `v1_only` the private key alone.
    fn restore_on(device: &CryptoManager, old: &Acct, new: &Acct, v1_only: bool) {
        let signing = old.signing_pk();
        let blob = crate::crypto::seal_previous_identity_for_tests(&old.sharing, (!v1_only).then_some(&signing), &new.sharing);
        assert_eq!(device.import_previous_identities_v2(vec![blob]).unwrap(), 1);
    }

    /// `a`'s own row as its device lists it: confirmed, listed, owner, with the device's keys.
    fn own_row(a: &Acct) -> RecordMember {
        with(a.member(), |m| m.listed_role = Some(CircleRole::Owner))
    }

    /// A record under `as_code`'s user id signed with `key`'s signing key:
    /// `as_code`'s code, `key`'s key (for the "under another code" checks).
    fn signing_as(as_code: &Acct, key: &Acct) -> Acct {
        Acct { uid: as_code.uid.clone(), signing: key.signing.clone(), sharing: key.sharing.clone() }
    }

    fn active(device: &CryptoManager) -> Option<i32> {
        device.get_active_version(CIRCLE.into()).ok()
    }

    #[test]
    fn a_lone_own_genesis_signed_before_a_reset_is_taken_after_the_restore() {
        // Before the restore it waits (no first sight for the own code);
        // after it, ACCEPTED, and it is the version sealed under.
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::genesis(&old);
        let device = new.device();
        give(&device, &h, 1);
        let list = [own_row(&new)];
        let before = import(&device, &h, &list, true);
        assert_eq!(state_of_version(&before, 1), (Waiting, RecordProblem::SignerUnknown));
        assert!(device.is_behind(CIRCLE.into()) && active(&device).is_none());
        restore_on(&device, &old, &new, false);
        let after = import(&device, &h, &list, true);
        assert_eq!(state_of_version(&after, 1), (Accepted, RecordProblem::None));
        assert_eq!(after.sealing_version, Some(1));
        assert_eq!(active(&device), Some(1));
        assert!(!device.is_behind(CIRCLE.into()));
        assert!(device.encrypt_data_v2(CIRCLE.into(), "x".into(), "name".into()).is_ok());
        assert_eq!(device.chain_role(CIRCLE.into(), new.uid.clone()), Some(CircleRole::Owner));
        // Nothing is vouched with the recovered pair, for anyone.
        let old_pair = (old.sharing_pk(), old.signing_pk());
        assert!(device.refresh.read().unwrap()[&CircleKey::of(CIRCLE)].facts.values().all(|f| f.vouched_keys != Some(old_pair)));
    }

    #[test]
    fn without_the_restore_or_with_a_v1_blob_a_lone_own_genesis_still_waits() {
        // No blob, or a v1 blob (no signing key bound): it waits, SignerUnknown.
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::genesis(&old);
        for v1_blob in [false, true] {
            let device = new.device();
            give(&device, &h, 1);
            if v1_blob {
                restore_on(&device, &old, &new, true);
            }
            let report = import(&device, &h, &[own_row(&new)], true);
            assert_eq!(state_of_version(&report, 1), (Waiting, RecordProblem::SignerUnknown), "v1 blob: {v1_blob}");
            assert!(device.is_behind(CIRCLE.into()) && active(&device).is_none());
        }
    }

    #[test]
    fn a_lone_own_transition_signed_before_a_reset_is_taken_after_the_restore() {
        // The same for a legacy circle's first record: the owner's transition at
        // v3 (anchor v2).
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::transition(&old, 3, &[(&old, Included, ChainRole::Owner)]);
        let device = legacy_device(&new, 3);
        let list = [own_row(&new)];
        assert_eq!(state_of_version(&import(&device, &h, &list, true), 3), (Waiting, RecordProblem::SignerUnknown));
        restore_on(&device, &old, &new, false);
        let after = import(&device, &h, &list, true);
        assert_eq!(state_of_version(&after, 3), (Accepted, RecordProblem::None));
        assert_eq!(active(&device), Some(3));
        assert!(!device.is_behind(CIRCLE.into()));
    }

    #[test]
    fn r2_takes_the_own_entry_under_a_recovered_pair() {
        // A first record signed by ANOTHER member (B, current keys) that
        // includes A with A's OLD commitment: R2's own entry.
        let b = Acct::new(0xb1);
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::transition(&b, 3, &[(&b, Included, ChainRole::Owner), (&old, Included, ChainRole::Member)]);
        let list = [with(b.member(), |m| m.listed_role = Some(CircleRole::Owner)), with(new.member(), |m| m.listed_role = Some(CircleRole::Member))];
        let without = legacy_device(&new, 3);
        assert_eq!(state_of_version(&import(&without, &h, &list, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
        let with_restore = legacy_device(&new, 3);
        restore_on(&with_restore, &old, &new, false);
        assert_eq!(state_of_version(&import(&with_restore, &h, &list, true), 3), (Accepted, RecordProblem::None));
        assert_eq!(active(&with_restore), Some(3));
    }

    #[test]
    fn with_a_recovered_pair_e_takes_a_later_record_continuing_the_old_commitment() {
        // Records served one by one. The owner's transition (v2, old
        // key) names A, B and the admin C; v3 (the owner's, old key)
        // and v4 (the admin's, current key) continue A's OLD
        // commitment. E judges the own row with the pair's keys, so the
        // chain's count holds for it.
        use ChainRole::{Admin, Member, Owner};
        let (b, c) = (Acct::new(0xb1), Acct::new(0xc1));
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let everyone = |h: &History| rows(h, &[(&old, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        let mut h = History::transition(&old, 2, &[(&old, Included, Owner), (&b, Included, Member), (&c, Included, Admin)]);
        h.rotate(RecordKind::Rotation, &old, everyone(&h), None);
        h.rotate(RecordKind::Rotation, &c, everyone(&h), None);
        let list = [own_row(&new), b.member(), with(c.member(), |m| m.listed_role = Some(CircleRole::Admin))];
        let device = legacy_device(&new, 4);
        restore_on(&device, &old, &new, false);
        for version in 2..=4 {
            let mut upto = h.clone();
            upto.records.retain(|v, _| *v <= version);
            upto.links.retain(|l| l.from_version <= version as i32);
            let report = import(&device, &upto, &list, true);
            assert_eq!(state_of_version(&report, version), (Accepted, RecordProblem::None), "v{version}: {:?}", report.versions);
        }
        assert_eq!(active(&device), Some(4));
        assert!(!device.is_behind(CIRCLE.into()));
    }

    #[test]
    fn with_a_recovered_pair_e_takes_an_admission_binding_the_old_keys() {
        // O's circle, served one by one; v2 first includes A (old keys) on O's
        // admission of A's OLD keys. With the pair, E's admission binds and v2 is
        // taken; without it, the entry matches nobody.
        let o = Acct::new(0xc1);
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&o);
        let mut first = h.clone();
        first.links.clear();
        let v2 = rows(&h, &[(&o, Included, ChainRole::Owner), (&old, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &o, v2, None);
        let list = [
            with(o.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(new.member(), |m| m.statements = vec![o.admit(&old, 1)]),
        ];
        for restored in [false, true] {
            let device = new.device();
            give(&device, &h, 1);
            give(&device, &h, 2);
            if restored {
                restore_on(&device, &old, &new, false);
            }
            assert_eq!(state_of_version(&import(&device, &first, &list, true), 1), (Accepted, RecordProblem::None));
            let report = import(&device, &h, &list, true);
            let expected = if restored { (Accepted, RecordProblem::None) } else { (Rejected, RecordProblem::R2UnmatchedEntry) };
            assert_eq!(state_of_version(&report, 2), expected, "restored: {restored}");
        }
    }

    #[test]
    fn reinclusions_eligible_reincludes_the_own_entry_under_a_recovered_pair() {
        // A, removed at v3 by the owner O, is included again at v4 on
        // O's admission of A's OLD keys (at v3). `reinclusions_eligible`
        // checks that admission against the pair; the statement still
        // verifies only under O's confirmed key.
        use ChainRole::{Admin, Member, Owner};
        let o = Acct::new(0xc1);
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&o);
        let v2 = rows(&h, &[(&o, Included, Owner), (&old, Included, Member)]);
        h.rotate(RecordKind::Rotation, &o, v2, None);
        let v3 = rows(&h, &[(&o, Included, Owner), (&old, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &o, v3, None);
        let v4 = rows(&h, &[(&o, Included, Owner), (&old, Included, Member)]);
        h.rotate(RecordKind::Rotation, &o, v4, None);
        let _ = Admin;
        // A prefix judged at once (a fresh device's first import of 2+ records).
        let list = [
            with(o.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(new.member(), |m| m.statements = vec![o.admit(&old, 3)]),
        ];
        let device = new.device();
        for version in 1..=4 {
            give(&device, &h, version);
        }
        restore_on(&device, &old, &new, false);
        let report = import(&device, &h, &list, true);
        assert_eq!(state_of_version(&report, 4), (Accepted, RecordProblem::None), "{:?}", report.versions);
        let without = new.device();
        for version in 1..=4 {
            give(&without, &h, version);
        }
        let report = import(&without, &h, &list, true);
        assert_ne!(state_of_version(&report, 4).0, Accepted, "{:?}", report.versions);
    }

    #[test]
    fn reinclusions_eligible_decides_in_a_prefix_that_goes_on_past_the_reinclusion() {
        // The same where only `reinclusions_eligible` decides: A,
        // removed at v3, is included again at v4 on O's admission of A's
        // OLD keys, and O removes A again at v5. A fresh device with the
        // pair takes the five as one prefix. v5 names A only as removed,
        // so the prefix goes on past v4 whatever it made of it, and v4,
        // below the head it takes, is judged nowhere else: through the
        // pair it is taken, A's last inclusion is v4, and its key (held)
        // is sealed under. (When the record after v4 carries or includes
        // A, a prefix that refused v4 refuses that record too, and
        // `judge` takes both with R2, E judging the own row by the
        // pair's keys.)
        use ChainRole::{Member, Owner};
        let o = Acct::new(0xc1);
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&o);
        let v2 = rows(&h, &[(&o, Included, Owner), (&old, Included, Member)]);
        h.rotate(RecordKind::Rotation, &o, v2, None);
        let v3 = rows(&h, &[(&o, Included, Owner), (&old, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &o, v3, None);
        let v4 = rows(&h, &[(&o, Included, Owner), (&old, Included, Member)]);
        h.rotate(RecordKind::Rotation, &o, v4, None);
        let v5 = rows(&h, &[(&o, Included, Owner), (&old, Removed, Member)]);
        h.rotate(RecordKind::Rotation, &o, v5, None);
        let list = [
            with(o.member(), |m| m.listed_role = Some(CircleRole::Owner)),
            with(new.member(), |m| m.statements = vec![o.admit(&old, 3)]),
        ];
        let device = new.device();
        for version in [1, 2, 4] {
            give(&device, &h, version);
        }
        restore_on(&device, &old, &new, false);
        let report = import(&device, &h, &list, true);
        assert!(report.versions.iter().all(|r| r.state != Rejected), "{:?}", report.versions);
        assert_eq!(active(&device), Some(4));
        let chains = device.refresh.read().unwrap();
        let chain = &chains[&CircleKey::of(CIRCLE)];
        assert_eq!(chain.head.as_ref().map(|h| h.version), Some(5));
        assert_eq!((chain.facts[&h.code(&old)].state, chain.facts[&h.code(&old)].last_included), (Removed, 4));
    }

    #[test]
    fn a_recovered_pair_never_confirms_another_member() {
        // The pairs answer for the own code only.
        let b = Acct::new(0xb1);
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let list = [with(b.member(), |m| m.listed_role = Some(CircleRole::Owner)), own_row(&new)];
        // (i) B's code as signer, its entry committing to A's OLD keys, signed with A's old key.
        let forged_b = signing_as(&b, &old);
        let mut h = History::transition(&forged_b, 3, &[(&forged_b, Included, ChainRole::Owner)]);
        let device = legacy_device(&new, 3);
        restore_on(&device, &old, &new, false);
        assert_eq!(state_of_version(&import(&device, &h, &list, true), 3), (Waiting, RecordProblem::SignerUnknown));
        // (ii) an own record (old key) including B with a commitment over A's OLD keys: R2 matches nobody.
        h = History::transition(&old, 3, &[(&old, Included, ChainRole::Owner), (&forged_b, Included, ChainRole::Member)]);
        let device = legacy_device(&new, 3);
        restore_on(&device, &old, &new, false);
        assert_eq!(state_of_version(&import(&device, &h, &list, true), 3), (Rejected, RecordProblem::R2UnmatchedEntry));
    }

    #[test]
    fn a_record_signed_with_the_old_key_under_another_code_waits() {
        // B's code and B's own commitment, signed with A's OLD key.
        // misattributed_to reads rows only, so it WAITS (Signature), never
        // MISATTRIBUTED: a stolen pre-reset key must count no removal under
        // another code. In format 1, and in format 2 (where a misattribution
        // would otherwise be judged).
        use ChainRole::{Admin, Member, Owner};
        let (b, c, d) = (Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let table = [(&old, Included, Owner), (&b, Included, Member), (&c, Included, Admin), (&d, Included, Member)];
        let base = History::transition(&old, 2, &table);
        let list = [own_row(&new), b.member(), with(c.member(), |m| m.listed_role = Some(CircleRole::Admin)), d.member()];
        let as_b_with_a_old = Acct { uid: b.uid.clone(), signing: old.signing.clone(), sharing: b.sharing.clone() };
        for format in [RecordFormat::V1, RecordFormat::V2] {
            let mut h = base.clone();
            h.format = format;
            let v3 = rows(&h, &table);
            h.rotate(RecordKind::Rotation, &as_b_with_a_old, v3, None);
            let device = legacy_device(&new, 3);
            restore_on(&device, &old, &new, false);
            let mut first = h.clone();
            first.records.retain(|v, _| *v == 2);
            first.links.retain(|l| l.from_version <= 2);
            assert_eq!(state_of_version(&import(&device, &first, &list, true), 2), (Accepted, RecordProblem::None));
            let report = import(&device, &h, &list, true);
            assert_eq!(state_of_version(&report, 3), (Waiting, RecordProblem::Signature), "{format:?}: {:?}", report.versions);
        }
    }

    #[test]
    fn a_recovered_pair_never_verifies_a_head() {
        // Heads are untouched: an own head signed with the OLD key
        // gives nothing, restore or not; a member head for A signed
        // with it forks nothing.
        let (a, b, c, d, h) = four();
        let new = reset(&a, 0xa7);
        let mut list = four_members(&a, &b, &c, &d);
        list[0] = own_row(&new);
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version: 2, chain: h.records[&2].0.chain() };
        let bytes = head.encode().unwrap();
        let old_head = SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(a.signing.sign(&Head::digest(&bytes)).to_bytes()) };
        let device = new.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        restore_on(&device, &a, &new, false);
        let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &list, true, Some(&old_head), &[contradicting_head(&a)], NOW).unwrap();
        assert!(report.head_confirmed_members.is_empty(), "an old-key own head vouches for nobody");
        assert!(!report.forked, "an old-key head is never compared");
        // A contradicting own head under the OLD key: no fork either.
        let other = new.device();
        give(&other, &h, 1);
        give(&other, &h, 2);
        restore_on(&other, &a, &new, false);
        let bogus = Head { chain: [0x2d; 32], ..Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version: 2, chain: [0; 32] } };
        let bogus_bytes = bogus.encode().unwrap();
        let bogus_old = SignedCircleHead { head_hex: hex::encode(bogus_bytes), signature_hex: hex::encode(a.signing.sign(&Head::digest(&bogus_bytes)).to_bytes()) };
        let report = other.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &list, true, Some(&bogus_old), &[], NOW).unwrap();
        assert!(!report.forked);
        assert_eq!(state_of_version(&report, 2), (Accepted, RecordProblem::None));
    }

    #[test]
    fn with_a_recovered_pair_the_own_row_is_the_one_with_the_current_keys() {
        // No row with the device's keys (unlisted, unconfirmed, or other keys),
        // or two of them: nothing is matched through old keys.
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let third = reset(&old, 0xa9);
        let h = History::genesis(&old);
        let impostor = Acct { uid: Acct::new(0xee).uid, signing: new.signing.clone(), sharing: new.sharing.clone() };
        let lists: Vec<(&str, Vec<RecordMember>)> = vec![
            ("none", vec![]),
            ("unlisted", vec![with(own_row(&new), |m| m.listed = false)]),
            ("unconfirmed", vec![with(own_row(&new), |m| m.confirmed = false)]),
            ("other keys", vec![own_row(&third)]),
            ("two rows", vec![own_row(&new), with(impostor.member(), |m| m.listed_role = Some(CircleRole::Member))]),
        ];
        for (what, list) in lists {
            let device = new.device();
            give(&device, &h, 1);
            restore_on(&device, &old, &new, false);
            let report = import(&device, &h, &list, true);
            assert_ne!(state_of_version(&report, 1).0, Accepted, "{what}: {:?}", report.versions);
            assert!(active(&device).is_none(), "{what}");
        }
    }

    #[test]
    fn on_the_accounts_own_head_the_old_key_record_opens() {
        // A fresh device takes the prefix on the account's own head, re-signed
        // under the NEW key, over its lone pre-reset genesis. With the restore
        // the record verifies and opens; without, it is a reference and the
        // device is BEHIND.
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&old);
        h.rotate(RecordKind::Rotation, &old, vec![h.entry(&old, Included, ChainRole::Owner)], None);
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: new.uid16(), version: 2, chain: h.records[&2].0.chain() };
        let bytes = head.encode().unwrap();
        let y3 = SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(new.signing.sign(&Head::digest(&bytes)).to_bytes()) };
        let list = [own_row(&new)];
        for restored in [false, true] {
            let device = new.device();
            give(&device, &h, 1);
            give(&device, &h, 2);
            if restored {
                restore_on(&device, &old, &new, false);
            }
            let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &list, true, Some(&y3), &[], NOW).unwrap();
            if restored {
                assert_eq!(state_of_version(&report, 2), (Accepted, RecordProblem::None));
                assert_eq!(active(&device), Some(2));
                assert!(!device.is_behind(CIRCLE.into()));
            } else {
                assert_eq!(state_of_version(&report, 2), (Reference, RecordProblem::None));
                assert!(device.is_behind(CIRCLE.into()), "a reference head above the version sealed under is behind");
            }
        }
    }

    #[test]
    fn a_record_taken_on_the_accounts_head_before_the_restore_opens_after_it() {
        // A fresh device takes the prefix on the account's own head (new key)
        // BEFORE the restore: its pre-reset records are references it can't
        // verify, nothing is sealed under. Once the identities are imported, the
        // next import verifies them under the pair and they open with their held
        // keys, whether the records are served again or not, in this process
        // or after a restart (the app asks from 0 then).
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&old);
        h.rotate(RecordKind::Rotation, &old, vec![h.entry(&old, Included, ChainRole::Owner)], None);
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: new.uid16(), version: 2, chain: h.records[&2].0.chain() };
        let bytes = head.encode().unwrap();
        let y3 = SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(new.signing.sign(&Head::digest(&bytes)).to_bytes()) };
        let list = [own_row(&new)];
        for (served_again, restart) in [(false, false), (true, false), (true, true)] {
            let store = MemStore::default();
            let device = new.device();
            device.register_secure_storage(Box::new(store.clone()));
            give(&device, &h, 1);
            give(&device, &h, 2);
            let report = device.import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &list, true, Some(&y3), &[], NOW).unwrap();
            assert_eq!(state_of_version(&report, 2), (Reference, RecordProblem::None));
            assert!(device.is_behind(CIRCLE.into()) && active(&device).is_none());
            let device = if restart {
                device.persist_keys().unwrap();
                restarted(&store)
            } else {
                device
            };
            restore_on(&device, &old, &new, false);
            let served = if served_again { h.signed() } else { Vec::new() };
            device.import_refresh_records_at(CIRCLE, &served, &h.links, &list, true, Some(&y3), &[], NOW).unwrap();
            assert_eq!(active(&device), Some(2), "served again: {served_again}, restart: {restart}");
            assert!(!device.is_behind(CIRCLE.into()), "served again: {served_again}, restart: {restart}");
        }
    }

    #[test]
    fn a_reference_whose_signer_is_confirmed_later_opens_when_served_again() {
        // Not the recovered pairs alone: A's fresh device takes v1-v3 on A's own
        // head; v3 is admin B's, whom the app doesn't confirm yet, so v3 is a
        // reference and the device seals under v2, behind. B confirmed, v3 opens
        // with its held key at the next import, whether it is served again
        // (after a restart the app asks from 0) or not.
        let (a, b) = (Acct::new(0xa1), Acct::new(0xb1));
        let mut h = History::genesis(&a);
        let v2 = rows(&h, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Admin)]);
        h.rotate(RecordKind::Rotation, &a, v2, None);
        let v3 = rows(&h, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Admin)]);
        h.rotate(RecordKind::Rotation, &b, v3, None);
        let head = Head { format: RecordFormat::V1, circle_id: circle16(), user_id: a.uid16(), version: 3, chain: h.records[&3].0.chain() };
        let bytes = head.encode().unwrap();
        let own_head = SignedCircleHead { head_hex: hex::encode(bytes), signature_hex: hex::encode(a.signing.sign(&Head::digest(&bytes)).to_bytes()) };
        let owner = with(a.member(), |m| m.listed_role = Some(CircleRole::Owner));
        let admin = with(b.member(), |m| m.listed_role = Some(CircleRole::Admin));
        for served_again in [false, true] {
            let device = a.device();
            for version in 1..=3 {
                give(&device, &h, version);
            }
            let first = device
                .import_refresh_records_at(CIRCLE, &h.signed(), &h.links, &[owner.clone(), with(admin.clone(), |m| m.confirmed = false)], true, Some(&own_head), &[], NOW)
                .unwrap();
            assert_eq!(state_of_version(&first, 3), (Reference, RecordProblem::None));
            assert_eq!(active(&device), Some(2));
            assert!(device.is_behind(CIRCLE.into()));
            let served = if served_again { h.signed() } else { Vec::new() };
            device.import_refresh_records_at(CIRCLE, &served, &h.links, &[owner.clone(), admin.clone()], true, Some(&own_head), &[], NOW).unwrap();
            assert_eq!(active(&device), Some(3), "served again: {served_again}");
            assert!(!device.is_behind(CIRCLE.into()), "served again: {served_again}");
        }
    }

    #[test]
    fn a_restore_end_to_end_with_the_own_pre_reset_wrap() {
        // The key reaches the fresh device as it does: the account's own
        // wrap of v1 made before the reset (signed with the OLD key, to
        // the OLD identity), stored through the restored identity; then
        // the record.
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::genesis(&old);
        let old_device = old.device();
        let ephemeral = StaticSecret::from([0x31; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(old.sharing_pk()));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = [0x44u8; 24];
        let ciphertext = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap().encrypt(&XNonce::from(nonce), h.keys[&1].as_ref()).unwrap();
        let eph_hex = hex::encode(PublicKey::from(&ephemeral).as_bytes());
        let signature = old_device
            .sign_wrap(crate::types::SignWrapParams {
                domain: "pingolin.sig.v1.circle_member_wrap".into(),
                sender_user_id: old.uid.clone(),
                recipient_user_id: old.uid.clone(),
                circle_id: CIRCLE.into(),
                place_id: String::new(),
                key_version: 1,
                ephemeral_pubkey_hex: eph_hex.clone(),
                wrap_nonce_hex: hex::encode(nonce),
                wrap_ciphertext_hex: hex::encode(&ciphertext),
            })
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        let device = new.device();
        restore_on(&device, &old, &new, false);
        device
            .store_circle_key(CIRCLE.into(), hex::encode(blob), eph_hex, 1, old.uid.clone(), old.uid.clone(), Some(signature), None)
            .unwrap();
        let report = import(&device, &h, &[own_row(&new)], true);
        assert_eq!(state_of_version(&report, 1), (Accepted, RecordProblem::None));
        assert_eq!(active(&device), Some(1));
        assert!(device.encrypt_data_v2(CIRCLE.into(), "sos".into(), "location".into()).is_ok(), "the SOS path seals again");
    }

    /// `a`'s own row carrying its admission of its own current keys (kind 3,
    /// signer = subject, signed with the current key), as the server serves it.
    fn self_admitted(a: &Acct, at_version: i32) -> RecordMember {
        with(own_row(a), |m| m.statements = vec![a.admit(a, at_version)])
    }

    /// The app pins `a`'s keys at its first contact with them.
    fn pin(device: &CryptoManager, a: &Acct) {
        device.pin_member_keys(CIRCLE.into(), a.uid.clone(), hex::encode(a.sharing_pk()), hex::encode(a.signing_pk())).unwrap();
    }

    /// The person approves `a`'s changed keys in `circle` (the safety-number check).
    fn approve_in(device: &CryptoManager, circle: &str, a: &Acct) {
        device.approve_member_key_change(circle.into(), a.uid.clone(), hex::encode(a.sharing_pk()), hex::encode(a.signing_pk())).unwrap();
    }

    fn approve(device: &CryptoManager, a: &Acct) {
        approve_in(device, CIRCLE, a);
    }

    /// four() with A's post-reset v3: signed with A's NEW key, its own entry over
    /// the new keys. Returns (a, b, c, d, a_new, history).
    fn four_with_a_post_reset_v3() -> (Acct, Acct, Acct, Acct, Acct, History) {
        let (a, b, c, d, mut h) = four();
        let a_new = reset(&a, 0xa7);
        let v3 = rows(&h, &[(&a_new, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&d, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &a_new, v3, None);
        (a, b, c, d, a_new, h)
    }

    /// B (head v2, its app having pinned A's old keys at the first contact), with
    /// `pins` applied, judges `h` with A's row `a_row`.
    fn on_b(h: &History, a_row: RecordMember, pins: impl FnOnce(&CryptoManager)) -> ((RecordVersionState, RecordProblem), bool, Option<i32>) {
        let (a, b, c, d) = (Acct::new(0xa1), Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
        let mut members = four_members(&a, &b, &c, &d);
        members[0] = a_row;
        let (device, _) = device_at(&b, &a, h, &four_members(&a, &b, &c, &d), &[2]);
        pin(&device, &a);
        pins(&device);
        give(&device, h, 3);
        let report = import(&device, h, &members, true);
        (state_of_version(&report, 3), device.is_behind(CIRCLE.into()), active(&device))
    }

    #[test]
    fn a_post_reset_key_change_waits_on_another_members_device_until_its_self_admission() {
        // On B (head v2):
        let (a, _, _, _, a_new, h) = four_with_a_post_reset_v3();
        // A's OLD keys on B (what B's pin gives): it waits, behind,
        // sealing v2.
        assert_eq!(on_b(&h, own_row(&a), |_| {}), ((Waiting, RecordProblem::SignerUnknown), true, Some(2)));
        // A's NEW keys, approved, no admission: E counts v1/v2's OLD
        // commitment, and the only entry not allowed is its signer's:
        // it WAITS.
        assert_eq!(on_b(&h, own_row(&a_new), |b| approve(b, &a_new)), ((Waiting, RecordProblem::R2NotAllowed), true, Some(2)));
        // With A's own admission of them (new key): taken.
        assert_eq!(on_b(&h, self_admitted(&a_new, 2), |b| approve(b, &a_new)), ((Accepted, RecordProblem::None), false, Some(3)));
    }

    // ---- A reset signer's own entry, and its self-admission ----

    #[test]
    fn a_record_whose_only_failure_is_its_signers_own_entry_waits_then_is_taken() {
        // A's post-reset v3 waits on B, import after import, while A's
        // admission of its new keys isn't served; served, the SAME record is taken.
        let (a, b, c, d, a_new, h) = four_with_a_post_reset_v3();
        let (device, _) = device_at(&b, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
        pin(&device, &a);
        approve(&device, &a_new);
        give(&device, &h, 3);
        let mut members = four_members(&a, &b, &c, &d);
        members[0] = own_row(&a_new);
        for _ in 0..2 {
            let report = import(&device, &h, &members, true);
            let row = report.versions.iter().find(|r| r.version == 3).unwrap();
            assert_eq!((row.state, row.problem, row.not_allowed.clone()), (Waiting, RecordProblem::R2NotAllowed, vec![a.uid.clone()]));
            assert!(device.is_behind(CIRCLE.into()));
            assert_eq!(active(&device), Some(2));
        }
        members[0] = self_admitted(&a_new, 2);
        let report = import(&device, &h, &members, true);
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        assert_eq!(active(&device), Some(3));
        assert!(!device.is_behind(CIRCLE.into()));
    }

    #[test]
    fn an_admins_own_key_change_waits_too() {
        // The wait holds an ADMIN's own entry as an owner's: admin C
        // resets and rotates v3 over its new keys. On B, which
        // approved them: waits without C's admission of them, taken
        // with it.
        let (a, b, c, d, mut h) = four();
        let c_new = reset(&c, 0xc7);
        let v3 = rows(&h, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c_new, Included, ChainRole::Admin), (&d, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &c_new, v3, None);
        let judged_on_b = |statements: Vec<HeldStatement>| {
            let mut members = four_members(&a, &b, &c, &d);
            members[2] = with(c_new.member(), |m| {
                m.listed_role = Some(CircleRole::Admin);
                m.statements = statements;
            });
            let (device, _) = device_at(&b, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
            pin(&device, &c);
            approve(&device, &c_new);
            give(&device, &h, 3);
            state_of_version(&import(&device, &h, &members, true), 3)
        };
        assert_eq!(judged_on_b(vec![]), (Waiting, RecordProblem::R2NotAllowed));
        assert_eq!(judged_on_b(vec![c_new.admit(&c_new, 2)]), (Accepted, RecordProblem::None));
    }

    #[test]
    fn another_entry_not_allowed_or_unmatched_still_rejects() {
        // A's v3 also includes N, whom nobody admitted. Only N not allowed
        // (A's admission served), A and N, or N on no list (unmatched) with A not
        // allowed: REJECTED on a complete list.
        let (a, b, c, d, mut h) = four();
        let a_new = reset(&a, 0xa7);
        let n = Acct::new(0x70);
        let v3 = rows(&h, &[(&a_new, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&d, Included, ChainRole::Member), (&n, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &a_new, v3, None);
        let cases = [
            (self_admitted(&a_new, 2), true, RecordProblem::R2NotAllowed, vec![n.uid.clone()]),
            (own_row(&a_new), true, RecordProblem::R2NotAllowed, vec![a.uid.clone(), n.uid.clone()]),
            (own_row(&a_new), false, RecordProblem::R2UnmatchedEntry, vec![a.uid.clone()]),
        ];
        for (a_row, n_listed, problem, mut want) in cases {
            let (device, _) = device_at(&b, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
            pin(&device, &a);
            approve(&device, &a_new);
            give(&device, &h, 3);
            let mut members = four_members(&a, &b, &c, &d);
            members[0] = a_row;
            if n_listed {
                members.push(n.member());
            }
            let report = import(&device, &h, &members, true);
            let row = report.versions.iter().find(|r| r.version == 3).unwrap();
            let mut got = row.not_allowed.clone();
            got.sort();
            want.sort();
            assert_eq!((row.state, row.problem, got), (Rejected, problem, want), "N listed: {n_listed}");
        }
    }

    /// The portal's restore of each of `olds` on `new`'s device, at once (the
    /// import replaces the set it holds).
    fn restore_all(device: &CryptoManager, olds: &[&Acct], new: &Acct) {
        let blobs = olds
            .iter()
            .map(|old| crate::crypto::seal_previous_identity_for_tests(&old.sharing, Some(&old.signing_pk()), &new.sharing))
            .collect();
        assert_eq!(device.import_previous_identities_v2(blobs).unwrap(), olds.len() as u32);
    }

    #[test]
    fn a_signer_found_through_a_recovered_pair_is_rejected_not_held() {
        // Only a signer matched among the CONFIRMED ROWS makes it wait.
        // A's own key change K0 → K1 (signed with K1), made before the reset
        // that gave it K2, judged on A's K2 device with K0 and K1 restored: its
        // entry over K1 is not allowed, its signer is found through the pair,
        // and no admission of an old key will ever come: rejected.
        let o = Acct::new(0xc1);
        let a0 = Acct::new(0xa1);
        let a1 = reset(&a0, 0xa4);
        let a2 = reset(&a0, 0xa7);
        let mut h = History::transition(&o, 2, &[(&o, Included, ChainRole::Owner), (&a0, Included, ChainRole::Admin)]);
        let v3 = rows(&h, &[(&o, Included, ChainRole::Owner), (&a1, Included, ChainRole::Admin)]);
        h.rotate(RecordKind::Rotation, &a1, v3, None);
        let list = [with(o.member(), |m| m.listed_role = Some(CircleRole::Owner)), with(a2.member(), |m| m.listed_role = Some(CircleRole::Admin))];
        let device = legacy_device(&a2, 3);
        restore_all(&device, &[&a0, &a1], &a2);
        let mut first = h.clone();
        first.records.retain(|v, _| *v == 2);
        first.links.retain(|l| l.from_version <= 2);
        assert_eq!(state_of_version(&import(&device, &first, &list, true), 2), (Accepted, RecordProblem::None));
        let report = import(&device, &h, &list, true);
        assert_eq!(state_of_version(&report, 3), (Rejected, RecordProblem::R2NotAllowed), "{:?}", report.versions);
    }

    #[test]
    fn a_self_admission_that_must_not_count_on_another_device() {
        // Negative cases, on B, which approved A's new keys; the positive
        // control first.
        let (a, _, _, _, a_new, h) = four_with_a_post_reset_v3();
        let approved = |b: &CryptoManager| approve(b, &a_new);
        assert_eq!(on_b(&h, self_admitted(&a_new, 2), approved).0, (Accepted, RecordProblem::None));
        // A's new keys UNCONFIRMED (B's pin of them alone confirms
        // nobody): no signer.
        assert_eq!(on_b(&h, with(self_admitted(&a_new, 2), |m| m.confirmed = false), approved).0, (Waiting, RecordProblem::SignerUnknown));
        // Signed with A's OLD key: it verifies only under the key
        // confirmed for A.
        assert_eq!(on_b(&h, with(own_row(&a_new), |m| m.statements = vec![a.admit(&a_new, 2)]), approved).0, (Waiting, RecordProblem::R2NotAllowed));
        // Made before the last record naming A (v2):
        // stale.
        assert_eq!(on_b(&h, self_admitted(&a_new, 1), approved).0, (Waiting, RecordProblem::R2NotAllowed));
    }

    #[test]
    fn a_plain_members_self_admission_never_counts() {
        // D, a plain member, resets and rotates v3 over its new keys. On
        // B, which approved them, D's own admission never counts (its
        // signer is no owner or admin), and no wait holds a plain
        // member's own entry: v3 is rejected. The owner's admission of
        // them counts.
        let (a, b, c, d, mut h) = four();
        let d_new = reset(&d, 0xd7);
        let v3 = rows(&h, &[(&a, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&d_new, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &d_new, v3, None);
        let judged_on_b = |statements: Vec<HeldStatement>| {
            let mut members = four_members(&a, &b, &c, &d);
            members[3] = with(d_new.member(), |m| m.statements = statements);
            let (device, _) = device_at(&b, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
            pin(&device, &d);
            approve(&device, &d_new);
            give(&device, &h, 3);
            let report = import(&device, &h, &members, true);
            (state_of_version(&report, 3), eligible(&device, &members, &d_new, EligibilityPurpose::Include).eligible)
        };
        assert_eq!(judged_on_b(vec![d_new.admit(&d_new, 2)]), ((Rejected, RecordProblem::R2NotAllowed), false));
        assert_eq!(judged_on_b(vec![a.admit(&d_new, 2)]), ((Accepted, RecordProblem::None), true));
    }

    #[test]
    fn a_self_admission_counts_only_on_keys_this_device_pinned() {
        // iOS and the web pass a confirmed member with no pin with the
        // server's listed keys. A's self-admission counts on B only for keys B
        // pinned for A: in this circle, or (no pin here) the identity pin.
        const ELSEWHERE: &str = "e1e1e1e1-2222-4333-8444-555555555555";
        let (a, _, _, _, a_new, h) = four_with_a_post_reset_v3();
        let admitted = || self_admitted(&a_new, 2);
        let waits = ((Waiting, RecordProblem::R2NotAllowed), true, Some(2));
        let taken = ((Accepted, RecordProblem::None), false, Some(3));
        // B's pin is A's OLD keys (the change not approved): it waits.
        assert_eq!(on_b(&h, admitted(), |_| {}), waits);
        // B never pinned A (B's own first-contact pin of A forgotten): it waits.
        let no_pin = |h: &History, a_row: RecordMember, pins: &dyn Fn(&CryptoManager)| {
            let (b, c, d) = (Acct::new(0xb1), Acct::new(0xc1), Acct::new(0xd1));
            let mut members = four_members(&a, &b, &c, &d);
            members[0] = a_row;
            let (device, _) = device_at(&b, &a, h, &four_members(&a, &b, &c, &d), &[2]);
            pins(&device);
            give(&device, h, 3);
            let report = import(&device, h, &members, true);
            (state_of_version(&report, 3), device.is_behind(CIRCLE.into()), active(&device))
        };
        assert_eq!(no_pin(&h, admitted(), &|_| {}), waits);
        // The new keys approved here: taken.
        assert_eq!(on_b(&h, admitted(), |b| approve(b, &a_new)), taken);
        // No pin here, the new keys approved in another circle: the identity pin.
        assert_eq!(no_pin(&h, admitted(), &|b| approve_in(b, ELSEWHERE, &a_new)), taken);
        // A pin here wins over the identity pin.
        assert_eq!(on_b(&h, admitted(), |b| approve_in(b, ELSEWHERE, &a_new)), waits);
        // A self-made INVITATION never counts ((b) only), approved keys or not.
        let invited = with(own_row(&a_new), |m| m.statements = vec![a_new.invite(&a_new, 2)]);
        assert_eq!(on_b(&h, invited, |b| approve(b, &a_new)), waits);
    }

    #[test]
    fn a_self_admission_in_the_own_row_counts_by_the_current_keys() {
        // Nobody holds a pin for themselves. On A's device after the
        // reset and the restore of its pre-reset pairs: the own row is
        // not eligible (the apps' "due" signal), and the post-reset
        // rotation is refused; with A's admission served in its own
        // row, eligible by (b), and it builds. One signed with the OLD
        // (recovered) key never counts.
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let a_new = reset(&a, 0xa7);
        let device = a_new.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        restore_on(&device, &a, &a_new, false);
        let mut members = four_members(&a, &b, &c, &d);
        members[0] = own_row(&a_new);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 2), (Accepted, RecordProblem::None));
        let e = eligible(&device, &members, &a_new, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (false, None), "due");
        let everyone = plan(&[(&a_new, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        let build = |members: &[RecordMember]| device.prepare_recorded_rotation_at(CIRCLE, &a_new.uid, RefreshRecordKind::Rotation, &everyone, members, true, "n", NOW);
        assert!(matches!(build(&members), Err(MobileError::InvalidInput(m)) if m.contains("not eligible")));
        members[0] = with(own_row(&a_new), |m| m.statements = vec![a.admit(&a_new, 2)]);
        assert!(!eligible(&device, &members, &a_new, EligibilityPurpose::Include).eligible, "old key");
        assert!(build(&members).is_err(), "old key");
        members[0] = self_admitted(&a_new, 2);
        let e = eligible(&device, &members, &a_new, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (true, Some(EligibilityBasis::Admission)));
        assert!(build(&members).is_ok());
    }

    #[test]
    fn an_old_key_self_admission_never_counts_on_the_own_device_either() {
        // With the recovered pair held: admin C's v3 includes A over its NEW
        // keys; on A's own device, an admission of them signed with A's OLD key
        // verifies under no key confirmed for A, and a recovered key never
        // verifies a statement. With the current key: taken.
        let (a, b, c, d, mut h) = four();
        let a_new = reset(&a, 0xa7);
        let v3 = rows(&h, &[(&a_new, Included, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&d, Included, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let on_a = |admission: HeldStatement| {
            let device = a_new.device();
            for version in 1..=3 {
                give(&device, &h, version);
            }
            restore_on(&device, &a, &a_new, false);
            let mut members = four_members(&a, &b, &c, &d);
            members[0] = own_row(&a_new);
            let mut first = h.clone();
            first.records.retain(|v, _| *v <= 2);
            first.links.retain(|l| l.from_version <= 2);
            assert_eq!(state_of_version(&import(&device, &first, &members, true), 2), (Accepted, RecordProblem::None));
            members[0] = with(own_row(&a_new), |m| m.statements = vec![admission]);
            state_of_version(&import(&device, &h, &members, true), 3)
        };
        assert_eq!(on_a(a.admit(&a_new, 2)), (Rejected, RecordProblem::R2NotAllowed));
        assert_eq!(on_a(a_new.admit(&a_new, 2)), (Accepted, RecordProblem::None));
    }

    #[test]
    fn the_reset_owners_rotation_with_its_served_self_admission_is_taken_on_another_device() {
        // A's device after the reset and the restore of its pre-reset
        // pairs builds its post-reset rotation only with its
        // self-admission SERVED in its own row (the app signs it with
        // sign_membership_admission: the current key, at the active
        // version); B, which approved A's new keys and is served the same
        // statement, takes the bundle's record, its key through its wrap;
        // served back, A takes it.
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let a_new = reset(&a, 0xa7);
        let device = a_new.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        restore_on(&device, &a, &a_new, false);
        let mut members = four_members(&a, &b, &c, &d);
        members[0] = own_row(&a_new);
        assert_eq!(state_of_version(&import(&device, &h, &members, true), 2), (Accepted, RecordProblem::None));
        let everyone = plan(&[(&a_new, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        assert!(device.prepare_recorded_rotation_at(CIRCLE, &a_new.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).is_err());
        let signed = device
            .sign_membership_admission(CIRCLE.into(), a_new.uid.clone(), a_new.uid.clone(), hex::encode(a_new.sharing_pk()), hex::encode(a_new.signing_pk()))
            .unwrap();
        assert_eq!((signed.statement.at_version, signed.statement.signer_user_id.as_str()), (2, a_new.uid.as_str()));
        let served = HeldStatement { statement_hex: signed.statement_hex, signature_hex: signed.signature_hex };
        members[0] = with(own_row(&a_new), |m| m.statements = vec![served]);
        let bundle = device.prepare_recorded_rotation_at(CIRCLE, &a_new.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).unwrap();
        assert_eq!(bundle.rotation.new_key_version, 3);
        let (records, links) = served_with(&h, &bundle);
        let (member, _) = device_at(&b, &a, &h, &four_members(&a, &b, &c, &d), &[2]);
        pin(&member, &a);
        approve(&member, &a_new);
        assert!(member.add_verified_key(CIRCLE, 3, &open_wrap(&b, &bundle.rotation)));
        let report = member.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        assert_eq!(active(&member), Some(3));
        assert!(!member.is_behind(CIRCLE.into()));
        let report = device.import_refresh_records_at(CIRCLE, &records, &links, &members, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 3), (Accepted, RecordProblem::None));
        assert_eq!(active(&device), Some(3));
        assert!(!device.is_behind(CIRCLE.into()));
        let e = eligible(&device, &members, &a_new, EligibilityPurpose::Include);
        assert_eq!((e.eligible, e.basis), (true, Some(EligibilityBasis::CountedByChain)), "nothing due any more");
    }

    #[test]
    fn a_lone_owner_resets_restores_admits_itself_and_rotates() {
        // End to end: the owner's lone pre-reset genesis; after the
        // reset the restore takes it (through the recovered pair); the
        // app reads "due", signs its self-admission, the server serves
        // it back in the own row; the post-reset rotation builds; served
        // back, v2 is taken and sealed under, and nothing is due any
        // more.
        use RecordMemberState as S;
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::genesis(&old);
        let device = new.device();
        give(&device, &h, 1);
        restore_on(&device, &old, &new, false);
        let mut list = vec![own_row(&new)];
        assert_eq!(state_of_version(&import(&device, &h, &list, true), 1), (Accepted, RecordProblem::None));
        assert!(!eligible(&device, &list, &new, EligibilityPurpose::Include).eligible, "due");
        let signed = device
            .sign_membership_admission(CIRCLE.into(), new.uid.clone(), new.uid.clone(), hex::encode(new.sharing_pk()), hex::encode(new.signing_pk()))
            .unwrap();
        list[0] = with(own_row(&new), |m| m.statements = vec![HeldStatement { statement_hex: signed.statement_hex, signature_hex: signed.signature_hex }]);
        assert_eq!(eligible(&device, &list, &new, EligibilityPurpose::Include).basis, Some(EligibilityBasis::Admission));
        let bundle = device
            .prepare_recorded_rotation_at(CIRCLE, &new.uid, RefreshRecordKind::Rotation, &plan(&[(&new, S::Included, None)]), &list, true, "n", NOW)
            .unwrap();
        let (records, links) = served_with(&h, &bundle);
        let report = device.import_refresh_records_at(CIRCLE, &records, &links, &list, true, None, &[], NOW).unwrap();
        assert_eq!(state_of_version(&report, 2), (Accepted, RecordProblem::None));
        assert_eq!(active(&device), Some(2));
        assert!(!device.is_behind(CIRCLE.into()));
        assert_eq!(eligible(&device, &list, &new, EligibilityPurpose::Include).basis, Some(EligibilityBasis::CountedByChain), "nothing due");
        assert!(device.encrypt_data_v2(CIRCLE.into(), "sos".into(), "location".into()).is_ok());
    }

    #[test]
    fn recovered_pairs_are_not_persisted() {
        // A record taken before a restart stays taken; one served
        // after it waits until the identities are imported again (the
        // app's loader).
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let mut h = History::genesis(&old);
        let store = MemStore::default();
        let device = new.device();
        device.register_secure_storage(Box::new(store.clone()));
        give(&device, &h, 1);
        restore_on(&device, &old, &new, false);
        let list = [own_row(&new)];
        assert_eq!(state_of_version(&import(&device, &h, &list, true), 1), (Accepted, RecordProblem::None));
        device.persist_keys().unwrap();
        let again = restarted(&store);
        assert!(again.previous_key_pairs().is_empty(), "never persisted");
        assert_eq!(active(&again), Some(1));
        assert!(!again.is_behind(CIRCLE.into()));
        assert!(import(&again, &h, &list, true).versions.is_empty(), "nothing at or below the head is judged again");
        // v2, made with the old key before the reset, served only now.
        h.rotate(RecordKind::Rotation, &old, vec![h.entry(&old, Included, ChainRole::Owner)], None);
        give(&again, &h, 2);
        assert_eq!(state_of_version(&import(&again, &h, &list, true), 2), (Waiting, RecordProblem::SignerUnknown));
        restore_on(&again, &old, &new, false);
        assert_eq!(state_of_version(&import(&again, &h, &list, true), 2), (Accepted, RecordProblem::None));
        assert_eq!(active(&again), Some(2));
    }

    #[test]
    fn after_a_restore_the_builder_needs_the_own_new_keys_counted() {
        // After the recovered pair takes A's pre-reset genesis, A's next
        // key change includes A with its NEW keys, and the builder's own
        // R2 check (E) refuses it until something counts those keys: here
        // A's self-admission of them, signed with the new key (kind 3,
        // signer = subject; A is the owner).
        use RecordMemberState as S;
        let old = Acct::new(0xa1);
        let new = reset(&old, 0xa7);
        let h = History::genesis(&old);
        let device = new.device();
        give(&device, &h, 1);
        restore_on(&device, &old, &new, false);
        assert_eq!(state_of_version(&import(&device, &h, &[own_row(&new)], true), 1), (Accepted, RecordProblem::None));
        let me = plan(&[(&new, S::Included, None)]);
        let refused = device.prepare_recorded_rotation_at(CIRCLE, &new.uid, RefreshRecordKind::Rotation, &me, &[own_row(&new)], true, "n", NOW);
        assert!(matches!(&refused, Err(MobileError::InvalidInput(m)) if m.contains("not eligible")), "{refused:?}");
        let admitted = [with(own_row(&new), |m| m.statements = vec![new.admit(&new, 1)])];
        let built = device.prepare_recorded_rotation_at(CIRCLE, &new.uid, RefreshRecordKind::Rotation, &me, &admitted, true, "n", NOW);
        assert!(built.is_ok(), "{built:?}");
    }

    // ---- A reference head above the sealing version ----

    #[test]
    fn ref_head_above_the_sealing_version_is_behind_and_its_key_by_the_apps_path_accepts_it() {
        // The real eject of D (v3) served intact, v3's key withheld from
        // B: v3 is B's reference head above v2 (sealed under). B is
        // behind, and still seals under v2 (what an SOS alert seals
        // under); the head is still reported (the Android app's
        // from-below eject reads it). Then v3's key arrives by the app's
        // path.
        let (a, b, _c, _d, h, real, _spoiled, members) = an_eject_and_its_spoiled_copy();
        let device = b.device();
        give(&device, &h, 1);
        give(&device, &h, 2);
        import(&device, &h, &members, true);
        assert!(!device.is_behind(CIRCLE.into()));
        let report = import(&device, &real, &members, true);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        assert!(device.is_behind(CIRCLE.into()), "a reference head above the version sealed under");
        assert_eq!(active(&device), Some(2));
        assert!(device.encrypt_data_v2(CIRCLE.into(), "sos".into(), "location".into()).is_ok(), "the SOS still seals under v2");
        assert_eq!(device.refresh_head_versions().get(CIRCLE).copied(), Some(3));
        // v3's key by the APP's path, A's signed rotation wrap to B
        // (store_circle_key → accept_reference_with_key).
        let ephemeral = StaticSecret::from([0x53; 32]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(b.sharing_pk()));
        let wrapping = blake3::derive_key("pingolin.circle_key_wrap", shared.as_bytes());
        let nonce = [0x46u8; 24];
        let ciphertext = XChaCha20Poly1305::new_from_slice(&wrapping).unwrap().encrypt(&XNonce::from(nonce), real.keys[&3].as_ref()).unwrap();
        let eph_hex = hex::encode(PublicKey::from(&ephemeral).as_bytes());
        let signature = a
            .device()
            .sign_wrap(crate::types::SignWrapParams {
                domain: "pingolin.sig.v1.circle_member_wrap".into(),
                sender_user_id: a.uid.clone(),
                recipient_user_id: b.uid.clone(),
                circle_id: CIRCLE.into(),
                place_id: String::new(),
                key_version: 3,
                ephemeral_pubkey_hex: eph_hex.clone(),
                wrap_nonce_hex: hex::encode(nonce),
                wrap_ciphertext_hex: hex::encode(&ciphertext),
            })
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        // B's pin for A, as B's app made it at the first contact.
        device.pin_member_keys(CIRCLE.into(), a.uid.clone(), hex::encode(a.sharing_pk()), hex::encode(a.signing_pk())).unwrap();
        device
            .store_circle_key(CIRCLE.into(), hex::encode(blob), eph_hex, 3, a.uid.clone(), b.uid.clone(), Some(signature), Some(hex::encode(a.signing_pk())))
            .unwrap();
        assert_eq!(active(&device), Some(3));
        assert!(!device.is_behind(CIRCLE.into()));
    }

    #[test]
    fn ref_head_own_unconfirmed_rotation_above_the_head_is_not_behind() {
        // This device's own rotation above its head, not served back
        // yet, is what it seals under.
        use RecordMemberState as S;
        let (a, b, c, d, h) = four();
        let members = four_members(&a, &b, &c, &d);
        let (device, _) = device_at(&a, &a, &h, &members, &[2]);
        assert!(!device.is_behind(CIRCLE.into()));
        let everyone = plan(&[(&a, S::Included, None), (&b, S::Included, None), (&c, S::Included, None), (&d, S::Included, None)]);
        device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &everyone, &members, true, "n", NOW).unwrap();
        assert!(!device.is_behind(CIRCLE.into()));
        assert_eq!(active(&device), Some(3));
    }

    #[test]
    fn ref_head_the_from_below_eject_still_builds() {
        // Admin C's v3 ejects X and leaves the owner A pending, so A
        // never gets key 3: v3 is A's reference head, A is behind, and
        // A's eject from below (down to v2, the last it was included
        // in) still builds. The builder never reads is_behind.
        use RecordMemberState as S;
        let (a, b, c, x, mut h) = four();
        let v3 = rows(&h, &[(&a, Pending, ChainRole::Owner), (&b, Included, ChainRole::Member), (&c, Included, ChainRole::Admin), (&x, Removed, ChainRole::Member)]);
        h.rotate(RecordKind::Rotation, &c, v3, None);
        let listed: Vec<RecordMember> = four_members(&a, &b, &c, &x).into_iter().filter(|m| m.user_id != x.uid).collect();
        let (device, report) = device_at(&a, &a, &h, &four_members(&a, &b, &c, &x), &[2]);
        assert_eq!(state_of_version(&report, 3), (Reference, RecordProblem::None));
        assert!(device.is_behind(CIRCLE.into()));
        let eject_b = plan(&[(&a, S::Included, None), (&b, S::Removed, None), (&c, S::Included, None)]);
        let built = device.prepare_recorded_rotation_at(CIRCLE, &a.uid, RefreshRecordKind::Rotation, &eject_b, &listed, true, "n", NOW).unwrap();
        let record = WireRecord::parse(&hex::decode(&built.refresh_record.record_hex).unwrap()).unwrap();
        assert_eq!((record.body.version, record.body.link_to), (4, 2));
        // Its own rotation above the reference head is what it seals under now:
        // not behind (the clause holds only with nothing of its own above).
        assert!(!device.is_behind(CIRCLE.into()));
        assert_eq!(active(&device), Some(4));
    }
}
