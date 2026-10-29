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

//! Refresh records: the byte format.
//!
//! Every change of a circle's key writes a refresh record: who got the new key
//! ("included"), who is still a member without it ("pending"), and who is gone
//! ("removed" by the signer's own act, or "departed" as the signer saw it). The
//! device that makes the change signs it; it carries a tag only a holder of the
//! new key can compute, and the chain value of the previous record, so each
//! circle has one hash-chained history the server can store and withhold, but
//! neither forge nor change.
//!
//! Members appear only as per-circle codes and keyed commitments to their keys,
//! which only holders of the circle's secret S can compute.
//!
//! CANONICAL ENCODING (format 1). Fixed-width fields; a UUID is its 16 RFC 4122
//! bytes (as in membership statements); integers are little-endian.
//!
//! ```text
//!   BODY (103 + 66 * count bytes)
//!   [0]        u8      format = 1
//!   [1]        u8      kind: 1 genesis | 2 transition | 3 rotation | 4 repair
//!   [2..18]    16      circle_id
//!   [18..22]   u32 LE  version, 1..=1_000_000
//!   [22..26]   u32 LE  prev_version: 0 for a genesis or a transition, else version - 1
//!   [26..58]   32      prev_chain: zero for a genesis or a transition, else the
//!                      chain value after the record for prev_version
//!   [58..62]   u32 LE  link_to: the version this change's key-chain link goes
//!                      down to. 0 for a genesis; version - 1 for a transition
//!                      (the circle's anchor); 1..=prev_version for a rotation
//!                      or a repair
//!   [62..94]   32      signer_code
//!   [94..102]  u64 LE  issued_at (unix seconds, > 0)
//!   [102]      u8      count, 1..=200
//!   [103 + 66i ..]     entry i, strictly ascending by code bytes:
//!              32      member code
//!              u8      state: 1 included | 2 pending | 3 removed | 4 departed
//!              u8      role: 1 owner | 2 admin | 3 member
//!              32      key commitment
//!
//!   WIRE: the record is BODY || key_tag (32 bytes), and for a transition
//!   BODY || key_tag || anchor_tag (32 + 32 bytes); the 64-byte Ed25519
//!   signature travels beside it, as a statement's does.
//! ```
//!
//! Derivations (BLAKE3 `derive_key(context, material)` and
//! `keyed_hash(key, message)`):
//!
//! ```text
//!   S             = derive_key("pingolin.refresh_record.v1.circle_secret", key_A)
//!                   A, the circle's anchor: 1 for a genesis circle; for a
//!                   transition at V0, V0 - 1
//!   code(x)       = keyed_hash(derive_key("pingolin.refresh_record.v1.member", S), uuid16(user_id))
//!   commitment    = keyed_hash(derive_key("pingolin.refresh_record.v1.keys", S),
//!                              code || sharing_pk || signing_pk)
//!   record_digest = keyed_hash(derive_key("pingolin.sig.v1.context_key", DOMAIN), BODY)
//!   key_tag       = keyed_hash(derive_key("pingolin.refresh_record.v1.key_tag", key_V), record_digest)
//!   anchor_tag    = keyed_hash(derive_key("pingolin.refresh_record.v1.anchor_tag", key_A), record_digest)
//!                   (a transition only)
//!   signature     = Ed25519 over keyed_hash(derive_key("pingolin.sig.v1.context_key", DOMAIN),
//!                                           BODY || key_tag [|| anchor_tag])
//!   chain_V       = keyed_hash(derive_key("pingolin.refresh_record.v1.chain", uuid16(circle_id)),
//!                              prev_chain || record_digest)
//! ```
//!
//! Only the signature covers the tags; chain_V covers the body alone. So a
//! device keeps the key tag (and the digest) of each record whose signature it
//! verified: after a restart, a copy served again vouches only with that tag,
//! and a copy of the version's key is checked against it, served again or not.
//!
//! FORMAT 2: the BODY as above with `[0]` = 2, and a record links the record
//! before it by its whole signed wire:
//!
//! ```text
//!   signed_digest = keyed_hash(derive_key("pingolin.sig.v1.context_key", DOMAIN),
//!                              BODY || key_tag [|| anchor_tag])   (what the signer signs)
//!   wire_chain    = keyed_hash(derive_key("pingolin.refresh_record.v2.chain", uuid16(circle_id)),
//!                              signed_digest || signature)
//! ```
//!
//! A format-2 record's `prev_chain` is the `wire_chain` of the record before
//! it, of either format; a format-1 record's is that record's chain_V. Formats
//! only go up within a circle. chain_V (over the body) still names a record, in
//! both formats: the same body with another signature is a copy of it, which
//! a format-2 successor links only if it is the copy that successor fixed.
//!
//! DOMAIN is `pingolin.sig.v1.circle_refresh_record`: the statements'
//! construction with a domain of its own, so a record signature can never be
//! taken for a statement or a wrap signature, or the other way round.
//!
//! An account HEAD is 69 bytes: `[0]` u8 format, `[1..17]` circle_id,
//! `[17..33]` user_id, `[33..37]` u32 LE version, `[37..69]` the chain value
//! after that version's record (format 1: chain_V; format 2: that record's
//! wire_chain); signed the same way under `pingolin.sig.v1.circle_refresh_head`.
//!
//! Parsing is strict: a wrong format, kind, state or role, a count or length
//! that does not match, codes out of order or repeated, a second owner, a
//! signer who is not an included entry, or a field that breaks its kind's shape
//! is an error, never a best-effort read. What needs the circle's secret or a
//! key (who an entry is, the tag) is checked elsewhere.


use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::crypto::ct_eq;
use crate::types::MobileError;

/// Domain separator of refresh-record signatures (distinct from the
/// statements' and every wrap domain).
pub(crate) const RECORD_DOMAIN: &str = "pingolin.sig.v1.circle_refresh_record";
/// Domain separator of account heads.
pub(crate) const HEAD_DOMAIN: &str = "pingolin.sig.v1.circle_refresh_head";
/// Context of the keyed-hash key derivation shared with the wrap and statement
/// signatures.
const SIG_CONTEXT: &str = "pingolin.sig.v1.context_key";
const CTX_CIRCLE_SECRET: &str = "pingolin.refresh_record.v1.circle_secret";
const CTX_MEMBER: &str = "pingolin.refresh_record.v1.member";
const CTX_KEYS: &str = "pingolin.refresh_record.v1.keys";
const CTX_KEY_TAG: &str = "pingolin.refresh_record.v1.key_tag";
const CTX_ANCHOR_TAG: &str = "pingolin.refresh_record.v1.anchor_tag";
const CTX_CHAIN: &str = "pingolin.refresh_record.v1.chain";
const CTX_WIRE_CHAIN: &str = "pingolin.refresh_record.v2.chain";

const HEADER_LEN: usize = 103;
const ENTRY_LEN: usize = 66;
const TAG_LEN: usize = 32;
/// At most this many entries: far above any real circle's size, and
/// within the u8 `count`.
pub(crate) const MAX_ENTRIES: usize = 200;
/// The bound `store_circle_key` puts on a circle-key version.
const MAX_VERSION: u32 = 1_000_000;
const HEAD_LEN: usize = 69;

/// A record's (or a head's) format, its byte `[0]`. Formats only go up
/// within a circle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordFormat {
    /// Wire code 1: linked by the chain value over the body (chain_V).
    V1,
    /// Wire code 2: linked by the record before's whole signed wire
    /// (`wire_chain`).
    V2,
}

impl RecordFormat {
    fn code(self) -> u8 {
        match self {
            RecordFormat::V1 => 1,
            RecordFormat::V2 => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(RecordFormat::V1),
            2 => Some(RecordFormat::V2),
            _ => None,
        }
    }
}

/// What kind of key change a record is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    /// Wire code 1: written with the circle, version 1.
    Genesis,
    /// Wire code 2: the first record of a legacy circle, one made
    /// without records.
    Transition,
    /// Wire code 3: every rotate-keys and eject-and-rotate.
    Rotation,
    /// Wire code 4: a rotation made because this device refused the record
    /// before it.
    Repair,
}

impl RecordKind {
    fn code(self) -> u8 {
        match self {
            RecordKind::Genesis => 1,
            RecordKind::Transition => 2,
            RecordKind::Rotation => 3,
            RecordKind::Repair => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(RecordKind::Genesis),
            2 => Some(RecordKind::Transition),
            3 => Some(RecordKind::Rotation),
            4 => Some(RecordKind::Repair),
            _ => None,
        }
    }
}

/// What a record says about one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryState {
    /// Wire code 1: given the new key (the signer among them).
    Included,
    /// Wire code 2: still a member, without the new key.
    Pending,
    /// Wire code 3: removed by the signer's OWN act (its eject, or its own
    /// revoke-access).
    Removed,
    /// Wire code 4: seen gone from the signer's complete member list.
    Departed,
}

impl EntryState {
    fn code(self) -> u8 {
        match self {
            EntryState::Included => 1,
            EntryState::Pending => 2,
            EntryState::Removed => 3,
            EntryState::Departed => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(EntryState::Included),
            2 => Some(EntryState::Pending),
            3 => Some(EntryState::Removed),
            4 => Some(EntryState::Departed),
            _ => None,
        }
    }
}

/// A member's role in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainRole {
    /// Wire code 1.
    Owner,
    /// Wire code 2.
    Admin,
    /// Wire code 3.
    Member,
}

impl ChainRole {
    fn code(self) -> u8 {
        match self {
            ChainRole::Owner => 1,
            ChainRole::Admin => 2,
            ChainRole::Member => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(ChainRole::Owner),
            2 => Some(ChainRole::Admin),
            3 => Some(ChainRole::Member),
            _ => None,
        }
    }
}

/// One member entry of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordEntry {
    pub code: [u8; 32],
    pub state: EntryState,
    pub role: ChainRole,
    pub commitment: [u8; 32],
}

/// The fields of a record's BODY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordBody {
    pub format: RecordFormat,
    pub kind: RecordKind,
    pub circle_id: [u8; 16],
    pub version: u32,
    pub prev_version: u32,
    pub prev_chain: [u8; 32],
    pub link_to: u32,
    pub signer_code: [u8; 32],
    pub issued_at: u64,
    /// Strictly ascending by code.
    pub entries: Vec<RecordEntry>,
}

fn invalid(what: impl Into<String>) -> MobileError {
    MobileError::InvalidInput(what.into())
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    let mut le = [0u8; 4];
    le.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(le)
}

fn read_32(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[at..at + 32]);
    out
}

impl RecordBody {
    /// The entry for `code`, if the record names it.
    pub(crate) fn entry(&self, code: &[u8; 32]) -> Option<&RecordEntry> {
        self.entries
            .binary_search_by(|e| e.code.cmp(code))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// The structural rules every record meets, whatever its content means
    /// (as far as they need neither S nor a key).
    fn check(&self) -> Result<(), MobileError> {
        if !(1..=MAX_VERSION).contains(&self.version) {
            return Err(invalid(format!("version must be 1..={MAX_VERSION}")));
        }
        if self.issued_at == 0 || i64::try_from(self.issued_at).is_err() {
            return Err(invalid("issued_at must be positive"));
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ENTRIES {
            return Err(invalid(format!("a record names 1..={MAX_ENTRIES} members")));
        }
        if self.entries.windows(2).any(|pair| pair[0].code >= pair[1].code) {
            return Err(invalid("entries must be in strictly ascending code order"));
        }
        if self.entries.iter().filter(|e| e.role == ChainRole::Owner).count() > 1 {
            return Err(invalid("a record names at most one owner"));
        }
        let signer = self
            .entry(&self.signer_code)
            .filter(|e| e.state == EntryState::Included)
            .ok_or_else(|| invalid("the signer must be an included entry"))?;
        let no_previous = self.prev_version == 0 && self.prev_chain == [0u8; 32];
        match self.kind {
            RecordKind::Genesis => {
                if self.version != 1 || !no_previous || self.link_to != 0 {
                    return Err(invalid("a genesis is version 1, with no previous record and no link"));
                }
                if self.entries.len() != 1 || signer.role != ChainRole::Owner {
                    return Err(invalid("a genesis names only its creator, as the owner"));
                }
            }
            RecordKind::Transition => {
                if self.version < 2 || !no_previous || self.link_to != self.version - 1 {
                    return Err(invalid(
                        "a transition has no previous record, and its link steps one version down",
                    ));
                }
                if self
                    .entries
                    .iter()
                    .any(|e| !matches!(e.state, EntryState::Included | EntryState::Pending))
                {
                    return Err(invalid("a transition names members only as included or pending"));
                }
                if !self.entries.iter().any(|e| e.role == ChainRole::Owner) {
                    return Err(invalid("a transition names exactly one owner"));
                }
                if signer.role == ChainRole::Member {
                    return Err(invalid("a transition is signed by an owner or admin"));
                }
            }
            RecordKind::Rotation | RecordKind::Repair => {
                if self.version < 2 || self.prev_version != self.version - 1 {
                    return Err(invalid("a rotation moves from the version just below it"));
                }
                if self.prev_chain == [0u8; 32] {
                    return Err(invalid("a rotation links the previous record"));
                }
                if self.link_to == 0 || self.link_to > self.prev_version {
                    return Err(invalid("a rotation's link goes down to 1..=prev_version"));
                }
            }
        }
        Ok(())
    }

    /// Validate the body and produce its canonical bytes.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, MobileError> {
        self.check()?;
        let mut out = Vec::with_capacity(HEADER_LEN + ENTRY_LEN * self.entries.len());
        out.push(self.format.code());
        out.push(self.kind.code());
        out.extend_from_slice(&self.circle_id);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.prev_version.to_le_bytes());
        out.extend_from_slice(&self.prev_chain);
        out.extend_from_slice(&self.link_to.to_le_bytes());
        out.extend_from_slice(&self.signer_code);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.push(self.entries.len() as u8);
        for entry in &self.entries {
            out.extend_from_slice(&entry.code);
            out.push(entry.state.code());
            out.push(entry.role.code());
            out.extend_from_slice(&entry.commitment);
        }
        if Self::decode(&out)? != *self {
            return Err(invalid("record does not read back as written"));
        }
        Ok(out)
    }

    /// Strictly read canonical BODY bytes back into their fields.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, MobileError> {
        if bytes.len() < HEADER_LEN {
            return Err(invalid("refresh record too short"));
        }
        let format = RecordFormat::from_code(bytes[0])
            .ok_or_else(|| invalid(format!("unknown refresh record format {}", bytes[0])))?;
        let kind = RecordKind::from_code(bytes[1])
            .ok_or_else(|| invalid(format!("unknown refresh record kind {}", bytes[1])))?;
        let count = bytes[HEADER_LEN - 1] as usize;
        if bytes.len() != HEADER_LEN + ENTRY_LEN * count {
            return Err(invalid("refresh record length does not match its count"));
        }
        let mut circle_id = [0u8; 16];
        circle_id.copy_from_slice(&bytes[2..18]);
        let mut issued = [0u8; 8];
        issued.copy_from_slice(&bytes[94..102]);
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let at = HEADER_LEN + ENTRY_LEN * i;
            entries.push(RecordEntry {
                code: read_32(bytes, at),
                state: EntryState::from_code(bytes[at + 32])
                    .ok_or_else(|| invalid(format!("unknown entry state {}", bytes[at + 32])))?,
                role: ChainRole::from_code(bytes[at + 33])
                    .ok_or_else(|| invalid(format!("unknown entry role {}", bytes[at + 33])))?,
                commitment: read_32(bytes, at + 34),
            });
        }
        let body = RecordBody {
            format,
            kind,
            circle_id,
            version: read_u32(bytes, 18),
            prev_version: read_u32(bytes, 22),
            prev_chain: read_32(bytes, 26),
            link_to: read_u32(bytes, 58),
            signer_code: read_32(bytes, 62),
            issued_at: u64::from_le_bytes(issued),
            entries,
        };
        body.check()?;
        Ok(body)
    }
}

/// A record as it travels, read and hashed.
#[derive(Debug, Clone)]
pub(crate) struct WireRecord {
    pub body: RecordBody,
    pub body_bytes: Vec<u8>,
    pub key_tag: [u8; 32],
    /// A transition's tag over the circle's anchor key; None for every
    /// other kind.
    pub anchor_tag: Option<[u8; 32]>,
    pub digest: [u8; 32],
}

impl WireRecord {
    /// Read `BODY || key_tag`, or `BODY || key_tag || anchor_tag` for a
    /// transition: exactly those lengths.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, MobileError> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(invalid("refresh record too short"));
        }
        let body_len = HEADER_LEN + ENTRY_LEN * bytes[HEADER_LEN - 1] as usize;
        let trailer = if bytes[1] == RecordKind::Transition.code() { 2 * TAG_LEN } else { TAG_LEN };
        if bytes.len() != body_len + trailer {
            return Err(invalid("refresh record length does not match its count and kind"));
        }
        let (body_bytes, tags) = bytes.split_at(body_len);
        let body = RecordBody::decode(body_bytes)?;
        Ok(WireRecord {
            digest: record_digest(body_bytes),
            body,
            body_bytes: body_bytes.to_vec(),
            key_tag: read_32(tags, 0),
            anchor_tag: (trailer == 2 * TAG_LEN).then(|| read_32(tags, TAG_LEN)),
        })
    }

    /// The bytes as they travel.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes.clone();
        out.extend_from_slice(&self.key_tag);
        if let Some(anchor_tag) = &self.anchor_tag {
            out.extend_from_slice(anchor_tag);
        }
        out
    }

    /// The chain value after this record, over its body (chain_V): what names
    /// it, in both formats, and what a format-1 record after it links.
    pub(crate) fn chain(&self) -> [u8; 32] {
        chain_value(&self.body.circle_id, &self.body.prev_chain, &self.digest)
    }

    /// The 32 bytes its signer signs: the body and its tags.
    pub(crate) fn signed_digest(&self) -> [u8; 32] {
        signed_digest(&self.body_bytes, &self.key_tag, self.anchor_tag.as_ref())
    }

    /// What a format-2 record after this one links: this copy's whole signed
    /// wire, `signature` included.
    pub(crate) fn wire_chain(&self, signature: &[u8; 64]) -> [u8; 32] {
        wire_chain(&self.body.circle_id, &self.signed_digest(), signature)
    }

    /// Whether `key_v` is the key this record was made for, in constant time.
    pub(crate) fn key_tag_matches(&self, key_v: &[u8]) -> bool {
        key_tag_verifies(key_v, &self.digest, &self.key_tag)
    }

    /// Whether `key_a` is the circle's anchor key this transition was made
    /// over, in constant time. False for every other kind. (The verification
    /// checks it through `AnchorCheck`; the vectors through this.)
    #[cfg(test)]
    pub(crate) fn anchor_tag_matches(&self, key_a: &[u8]) -> bool {
        match &self.anchor_tag {
            Some(expected) => anchor_tag(key_a, &self.digest).map_or(false, |tag| ct_eq(&tag, expected)),
            None => false,
        }
    }

    /// Whether `signature` is `signing_public_key`'s signature of this record.
    pub(crate) fn signature_verifies(&self, signature: &[u8; 64], signing_public_key: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(signing_public_key) else {
            return false;
        };
        key.verify_strict(&self.signed_digest(), &Signature::from_bytes(signature)).is_ok()
    }
}

fn domain_key(domain: &str) -> [u8; 32] {
    blake3::derive_key(SIG_CONTEXT, domain.as_bytes())
}

/// The circle's secret S, from the key of its anchor version.
pub(crate) fn circle_secret(anchor_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, MobileError> {
    if anchor_key.len() != 32 {
        return Err(MobileError::CryptoError("a circle key is 32 bytes".to_string()));
    }
    Ok(Zeroizing::new(blake3::derive_key(CTX_CIRCLE_SECRET, anchor_key)))
}

/// A member's code in the circle whose secret is `secret`.
pub(crate) fn member_code(secret: &[u8; 32], user_id: &[u8; 16]) -> [u8; 32] {
    let key = Zeroizing::new(blake3::derive_key(CTX_MEMBER, secret));
    *blake3::keyed_hash(&key, user_id).as_bytes()
}

/// The commitment to a member's keys: `code || sharing || signing`.
pub(crate) fn key_commitment(
    secret: &[u8; 32],
    code: &[u8; 32],
    sharing_public_key: &[u8; 32],
    signing_public_key: &[u8; 32],
) -> [u8; 32] {
    let key = Zeroizing::new(blake3::derive_key(CTX_KEYS, secret));
    let mut message = [0u8; 96];
    message[..32].copy_from_slice(code);
    message[32..64].copy_from_slice(sharing_public_key);
    message[64..].copy_from_slice(signing_public_key);
    *blake3::keyed_hash(&key, &message).as_bytes()
}

/// The digest of a record's BODY.
pub(crate) fn record_digest(body: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(&domain_key(RECORD_DOMAIN), body).as_bytes()
}

/// Whether `key_v` is the key a record with `digest` and key tag `tag` was made
/// for, in constant time.
pub(crate) fn key_tag_verifies(key_v: &[u8], digest: &[u8; 32], tag: &[u8; 32]) -> bool {
    key_tag(key_v, digest).map_or(false, |computed| ct_eq(&computed, tag))
}

/// The tag only a holder of `key_v` can compute for the record `digest`.
pub(crate) fn key_tag(key_v: &[u8], digest: &[u8; 32]) -> Result<[u8; 32], MobileError> {
    if key_v.len() != 32 {
        return Err(MobileError::CryptoError("a circle key is 32 bytes".to_string()));
    }
    let key = Zeroizing::new(blake3::derive_key(CTX_KEY_TAG, key_v));
    Ok(*blake3::keyed_hash(&key, digest).as_bytes())
}

/// The tag only a holder of the circle's anchor key `key_a` can compute for a
/// transition's `digest`.
pub(crate) fn anchor_tag(key_a: &[u8], digest: &[u8; 32]) -> Result<[u8; 32], MobileError> {
    if key_a.len() != 32 {
        return Err(MobileError::CryptoError("a circle key is 32 bytes".to_string()));
    }
    let key = Zeroizing::new(blake3::derive_key(CTX_ANCHOR_TAG, key_a));
    Ok(*blake3::keyed_hash(&key, digest).as_bytes())
}

/// The 32 bytes a record's signer signs: the body plus its tags.
pub(crate) fn signed_digest(body: &[u8], key_tag: &[u8; 32], anchor_tag: Option<&[u8; 32]>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&domain_key(RECORD_DOMAIN));
    hasher.update(body);
    hasher.update(key_tag);
    if let Some(anchor_tag) = anchor_tag {
        hasher.update(anchor_tag);
    }
    *hasher.finalize().as_bytes()
}

/// The chain value after a record.
pub(crate) fn chain_value(circle_id: &[u8; 16], prev_chain: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let key = blake3::derive_key(CTX_CHAIN, circle_id);
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(prev_chain);
    message[32..].copy_from_slice(digest);
    *blake3::keyed_hash(&key, &message).as_bytes()
}

/// The wire_chain of a record whose signed digest is `signed_digest`, signed
/// with `signature` (format 2).
pub(crate) fn wire_chain(circle_id: &[u8; 16], signed_digest: &[u8; 32], signature: &[u8; 64]) -> [u8; 32] {
    let key = blake3::derive_key(CTX_WIRE_CHAIN, circle_id);
    let mut message = [0u8; 96];
    message[..32].copy_from_slice(signed_digest);
    message[32..].copy_from_slice(signature);
    *blake3::keyed_hash(&key, &message).as_bytes()
}

/// An account head: the chain value this account accepted at a version of a
/// circle, in the head's format (format 1: chain_V; format 2: the record's
/// wire_chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub format: RecordFormat,
    pub circle_id: [u8; 16],
    pub user_id: [u8; 16],
    pub version: u32,
    pub chain: [u8; 32],
}

impl Head {
    pub(crate) fn encode(&self) -> Result<[u8; HEAD_LEN], MobileError> {
        if !(1..=MAX_VERSION).contains(&self.version) {
            return Err(invalid(format!("version must be 1..={MAX_VERSION}")));
        }
        let mut out = [0u8; HEAD_LEN];
        out[0] = self.format.code();
        out[1..17].copy_from_slice(&self.circle_id);
        out[17..33].copy_from_slice(&self.user_id);
        out[33..37].copy_from_slice(&self.version.to_le_bytes());
        out[37..].copy_from_slice(&self.chain);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, MobileError> {
        if bytes.len() != HEAD_LEN {
            return Err(invalid("a head is 69 bytes"));
        }
        let format = RecordFormat::from_code(bytes[0]).ok_or_else(|| invalid(format!("unknown head format {}", bytes[0])))?;
        let mut circle_id = [0u8; 16];
        circle_id.copy_from_slice(&bytes[1..17]);
        let mut user_id = [0u8; 16];
        user_id.copy_from_slice(&bytes[17..33]);
        let head = Head { format, circle_id, user_id, version: read_u32(bytes, 33), chain: read_32(bytes, 37) };
        if !(1..=MAX_VERSION).contains(&head.version) {
            return Err(invalid(format!("version must be 1..={MAX_VERSION}")));
        }
        Ok(head)
    }

    /// The 32 bytes the account signs.
    pub(crate) fn digest(bytes: &[u8; HEAD_LEN]) -> [u8; 32] {
        *blake3::keyed_hash(&domain_key(HEAD_DOMAIN), bytes).as_bytes()
    }
}

#[cfg(test)]
mod vectors {
    //! The shared cross-implementation vectors: the file below
    //! (`refresh_record_v1.txt`) was written by an independent generator from
    //! the documented layout, and the web client pins the same file.

    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use x25519_dalek::{PublicKey, StaticSecret};

    const VECTORS: &str = include_str!("../tests/data/refresh_record_v1.txt");

    fn vectors() -> HashMap<&'static str, &'static str> {
        VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').expect("name=value"))
            .collect()
    }

    fn bytes(v: &HashMap<&str, &str>, name: &str) -> Vec<u8> {
        hex::decode(v[name]).unwrap_or_else(|_| panic!("{name} is hex"))
    }

    fn b32(v: &HashMap<&str, &str>, name: &str) -> [u8; 32] {
        bytes(v, name).try_into().unwrap_or_else(|_| panic!("{name} is 32 bytes"))
    }

    fn uuid16(s: &str) -> [u8; 16] {
        *uuid::Uuid::parse_str(s).unwrap().as_bytes()
    }

    const NAMES: [&str; 5] = ["A", "B", "C", "D", "E"];

    #[test]
    fn codes_and_commitments_match_the_vectors() {
        let v = vectors();
        let secret = circle_secret(&b32(&v, "key_v1")).unwrap();
        assert_eq!(hex::encode(*secret), v["S"]);
        for (n, (sign_byte, share_byte)) in NAMES.iter().zip([(0xa1u8, 0xa2u8), (0xb1, 0xb2), (0xc1, 0xc2), (0xd1, 0xd2), (0xe1, 0xe2)]) {
            let signing = SigningKey::from_bytes(&[sign_byte; 32]).verifying_key().to_bytes();
            let sharing = PublicKey::from(&StaticSecret::from([share_byte; 32])).to_bytes();
            assert_eq!(hex::encode(signing), v[format!("{n}_signing_pk").as_str()]);
            assert_eq!(hex::encode(sharing), v[format!("{n}_sharing_pk").as_str()]);
            let code = member_code(&secret, &uuid16(v[format!("{n}_user_id").as_str()]));
            assert_eq!(hex::encode(code), v[format!("{n}_code").as_str()], "{n}'s code");
            let commitment = key_commitment(&secret, &code, &sharing, &signing);
            assert_eq!(hex::encode(commitment), v[format!("{n}_commitment").as_str()], "{n}'s commitment");
        }
    }

    #[test]
    fn every_record_reads_verifies_and_rebuilds_byte_for_byte() {
        let v = vectors();
        let signer_of = [("r1", "a1"), ("r2", "a1"), ("r3", "c1"), ("r4", "a1")];
        let mut prev_chain = [0u8; 32];
        for (i, (r, seed)) in signer_of.iter().enumerate() {
            let version = (i + 1) as u32;
            let wire = WireRecord::parse(&bytes(&v, &format!("{r}_record_wire"))).unwrap();
            assert_eq!(wire.body_bytes, bytes(&v, &format!("{r}_body")));
            assert_eq!(wire.body.encode().unwrap(), wire.body_bytes, "{r} re-encodes to the same bytes");
            assert_eq!(wire.to_bytes(), bytes(&v, &format!("{r}_record_wire")));
            assert_eq!(wire.body.version, version);
            assert_eq!(wire.body.prev_chain, prev_chain, "{r} links the record before it");
            assert_eq!(hex::encode(wire.digest), v[format!("{r}_record_digest").as_str()]);
            assert_eq!(hex::encode(wire.key_tag), v[format!("{r}_key_tag").as_str()]);
            let key_v = b32(&v, &format!("key_v{version}"));
            assert_eq!(key_tag(&key_v, &wire.digest).unwrap(), wire.key_tag);
            assert!(wire.key_tag_matches(&key_v));
            assert_eq!(
                hex::encode(signed_digest(&wire.body_bytes, &wire.key_tag, None)),
                v[format!("{r}_sig_digest").as_str()]
            );
            let signing = SigningKey::from_bytes(&<[u8; 32]>::try_from(hex::decode(seed.repeat(32)).unwrap()).unwrap());
            let signature: [u8; 64] = bytes(&v, &format!("{r}_signature")).try_into().unwrap();
            assert_eq!(signing.sign(&signed_digest(&wire.body_bytes, &wire.key_tag, None)).to_bytes(), signature);
            assert!(wire.signature_verifies(&signature, &signing.verifying_key().to_bytes()));
            assert_eq!(hex::encode(wire.chain()), v[format!("{r}_chain").as_str()]);
            prev_chain = wire.chain();

            // Negative controls: another version's key fails the tag, and the
            // signature holds only for its signer, this body and this tag.
            let other_key = b32(&v, &format!("key_v{}", version % 4 + 1));
            assert!(!wire.key_tag_matches(&other_key), "{r}: another version's key");
            let mut flipped_tag = wire.clone();
            flipped_tag.key_tag[0] ^= 1;
            assert!(!flipped_tag.key_tag_matches(&key_v), "{r}: a flipped tag");
            assert!(!flipped_tag.signature_verifies(&signature, &signing.verifying_key().to_bytes()), "{r}: the tag is signed");
            let mut flipped_body = wire.clone();
            flipped_body.body_bytes[100] ^= 1;
            assert!(!flipped_body.signature_verifies(&signature, &signing.verifying_key().to_bytes()), "{r}: the body is signed");
            let mut flipped_signature = signature;
            flipped_signature[10] ^= 1;
            assert!(!wire.signature_verifies(&flipped_signature, &signing.verifying_key().to_bytes()), "{r}: a flipped signature");
            let stranger = SigningKey::from_bytes(&[0x5e; 32]).verifying_key().to_bytes();
            assert!(!wire.signature_verifies(&signature, &stranger), "{r}: someone else's key");
        }
    }

    #[test]
    fn the_records_say_what_the_vectors_describe() {
        let v = vectors();
        let code = |n: &str| b32(&v, &format!("{n}_code"));
        let commitment = |n: &str| b32(&v, &format!("{n}_commitment"));
        let read = |r: &str| WireRecord::parse(&bytes(&v, &format!("{r}_record_wire"))).unwrap().body;
        let check = |body: &RecordBody, n: &str, state: EntryState, role: ChainRole| {
            let entry = body.entry(&code(n)).unwrap_or_else(|| panic!("{n} is named"));
            assert_eq!((entry.state, entry.role), (state, role), "{n}");
            assert_eq!(entry.commitment, commitment(n));
        };
        let r1 = read("r1");
        assert_eq!((r1.kind, r1.prev_version, r1.link_to, r1.entries.len()), (RecordKind::Genesis, 0, 0, 1));
        assert_eq!(r1.circle_id, uuid16(v["circle_id"]));
        assert_eq!(r1.signer_code, code("A"));
        assert_eq!(r1.issued_at, 1_790_208_000 + 3600);
        check(&r1, "A", EntryState::Included, ChainRole::Owner);
        let r2 = read("r2");
        assert_eq!((r2.kind, r2.prev_version, r2.link_to, r2.entries.len()), (RecordKind::Rotation, 1, 1, 4));
        check(&r2, "B", EntryState::Included, ChainRole::Member);
        check(&r2, "C", EntryState::Included, ChainRole::Admin);
        let r3 = read("r3");
        assert_eq!((r3.prev_version, r3.link_to, r3.signer_code), (2, 2, code("C")));
        check(&r3, "A", EntryState::Pending, ChainRole::Owner);
        check(&r3, "B", EntryState::Removed, ChainRole::Member);
        check(&r3, "D", EntryState::Included, ChainRole::Member);
        check(&r3, "E", EntryState::Departed, ChainRole::Member);
        let r4 = read("r4");
        assert_eq!((r4.prev_version, r4.link_to, r4.signer_code, r4.entries.len()), (3, 2, code("A"), 3));
        assert!(r4.entry(&code("B")).is_none() && r4.entry(&code("E")).is_none());
    }

    #[test]
    fn the_links_carry_the_keys_they_name() {
        let v = vectors();
        for (from, to) in [(2, 1), (3, 2), (4, 2)] {
            let cipher = XChaCha20Poly1305::new_from_slice(&b32(&v, &format!("key_v{from}"))).unwrap();
            let nonce: [u8; 24] = bytes(&v, &format!("link_{from}_{to}_nonce")).try_into().unwrap();
            let opened = cipher
                .decrypt(&XNonce::from(nonce), bytes(&v, &format!("link_{from}_{to}_encrypted_key")).as_ref())
                .unwrap();
            assert_eq!(opened, b32(&v, &format!("key_v{to}")));
        }
    }

    #[test]
    fn the_head_matches_the_vector() {
        let v = vectors();
        let head = Head {
            format: RecordFormat::V1,
            circle_id: uuid16(v["circle_id"]),
            user_id: uuid16(v["A_user_id"]),
            version: 4,
            chain: b32(&v, "r4_chain"),
        };
        let encoded = head.encode().unwrap();
        assert_eq!(hex::encode(encoded), v["head_A_v4"]);
        assert_eq!(Head::decode(&encoded).unwrap(), head);
        assert_eq!(hex::encode(Head::digest(&encoded)), v["head_A_v4_digest"]);
        let a = SigningKey::from_bytes(&[0xa1; 32]);
        assert_eq!(hex::encode(a.sign(&Head::digest(&encoded)).to_bytes()), v["head_A_v4_signature"]);
    }
}

#[cfg(test)]
mod transition_vectors {
    //! The shared TRANSITION vectors (`refresh_record_v1_transition.txt`), which
    //! an independent checker reproduces from the documented layout. A legacy
    //! circle at key version 4; A's transition at V0 = 5 links to the anchor 4
    //! and carries the anchor tag; C's rotation at 6 moves off 5 and links down
    //! to 4.

    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use x25519_dalek::{PublicKey, StaticSecret};

    const VECTORS: &str = include_str!("../tests/data/refresh_record_v1_transition.txt");

    fn vectors() -> HashMap<&'static str, &'static str> {
        VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| l.split_once('=').expect("name=value"))
            .collect()
    }

    fn bytes(v: &HashMap<&str, &str>, name: &str) -> Vec<u8> {
        hex::decode(v[name]).unwrap_or_else(|_| panic!("{name} is hex"))
    }

    fn b32(v: &HashMap<&str, &str>, name: &str) -> [u8; 32] {
        bytes(v, name).try_into().unwrap_or_else(|_| panic!("{name} is 32 bytes"))
    }

    fn uuid16(s: &str) -> [u8; 16] {
        *uuid::Uuid::parse_str(s).unwrap().as_bytes()
    }

    fn signer(v: &HashMap<&str, &str>, name: &str) -> SigningKey {
        SigningKey::from_bytes(&b32(v, &format!("{name}_signing_seed")))
    }

    #[test]
    fn the_secret_comes_from_the_anchor_key() {
        let v = vectors();
        assert_eq!(v["anchor"], "4");
        let secret = circle_secret(&b32(&v, "key_v4")).unwrap();
        assert_eq!(hex::encode(*secret), v["S"]);
        // Break: S from V0's own key is not the circle's secret.
        assert_ne!(hex::encode(*circle_secret(&b32(&v, "key_v5")).unwrap()), v["S"]);
        for (n, (sign_byte, share_byte)) in ["A", "B", "C", "D"].iter().zip([(0xa1u8, 0xa2u8), (0xb1, 0xb2), (0xc1, 0xc2), (0xd1, 0xd2)]) {
            let signing = SigningKey::from_bytes(&[sign_byte; 32]).verifying_key().to_bytes();
            let sharing = PublicKey::from(&StaticSecret::from([share_byte; 32])).to_bytes();
            assert_eq!(hex::encode(signing), v[format!("{n}_signing_pk").as_str()]);
            assert_eq!(hex::encode(sharing), v[format!("{n}_sharing_pk").as_str()]);
            let code = member_code(&secret, &uuid16(v[format!("{n}_user_id").as_str()]));
            assert_eq!(hex::encode(code), v[format!("{n}_code").as_str()], "{n}'s code");
            let commitment = key_commitment(&secret, &code, &sharing, &signing);
            assert_eq!(hex::encode(commitment), v[format!("{n}_commitment").as_str()], "{n}'s commitment");
        }
    }

    #[test]
    fn the_transition_carries_and_signs_its_anchor_tag() {
        let v = vectors();
        let wire = WireRecord::parse(&bytes(&v, "r5_record_wire")).unwrap();
        assert_eq!(wire.body_bytes, bytes(&v, "r5_body"));
        assert_eq!(wire.body.encode().unwrap(), wire.body_bytes);
        assert_eq!(wire.to_bytes(), bytes(&v, "r5_record_wire"));
        assert_eq!(hex::encode(wire.digest), v["r5_record_digest"]);
        let (key_4, key_5) = (b32(&v, "key_v4"), b32(&v, "key_v5"));
        assert_eq!(hex::encode(wire.key_tag), v["r5_key_tag"]);
        assert!(wire.key_tag_matches(&key_5));
        let anchor = wire.anchor_tag.expect("a transition carries the anchor tag");
        assert_eq!(hex::encode(anchor), v["r5_anchor_tag"]);
        assert_eq!(anchor_tag(&key_4, &wire.digest).unwrap(), anchor);
        assert!(wire.anchor_tag_matches(&key_4));
        assert!(!wire.anchor_tag_matches(&key_5), "V0's own key is not the anchor");
        assert!(!wire.anchor_tag_matches(&b32(&v, "key_v3")), "nor the key below it");
        // The two tags are keyed apart: the anchor key's key tag is not its anchor tag.
        assert_ne!(key_tag(&key_4, &wire.digest).unwrap(), anchor);

        let digest = signed_digest(&wire.body_bytes, &wire.key_tag, Some(&anchor));
        assert_eq!(hex::encode(digest), v["r5_sig_digest"]);
        let a = signer(&v, "A");
        let signature: [u8; 64] = bytes(&v, "r5_signature").try_into().unwrap();
        assert_eq!(a.sign(&digest).to_bytes(), signature);
        assert!(wire.signature_verifies(&signature, &a.verifying_key().to_bytes()));
        // The anchor tag is signed: flipped, or dropped from the digest, the
        // signature no longer holds.
        let mut flipped = wire.clone();
        flipped.anchor_tag.as_mut().unwrap()[0] ^= 1;
        assert!(!flipped.signature_verifies(&signature, &a.verifying_key().to_bytes()));
        assert!(!flipped.anchor_tag_matches(&key_4));
        let mut dropped = wire.clone();
        dropped.anchor_tag = None;
        assert!(!dropped.signature_verifies(&signature, &a.verifying_key().to_bytes()));
        assert!(!dropped.anchor_tag_matches(&key_4));
        assert_ne!(signed_digest(&wire.body_bytes, &wire.key_tag, None), digest);

        assert_eq!(wire.body.prev_chain, [0; 32]);
        assert_eq!(hex::encode(wire.chain()), v["r5_chain"]);
    }

    #[test]
    fn the_rotation_from_below_chains_on_the_transition() {
        let v = vectors();
        let r5 = WireRecord::parse(&bytes(&v, "r5_record_wire")).unwrap();
        let wire = WireRecord::parse(&bytes(&v, "r6_record_wire")).unwrap();
        assert_eq!(wire.to_bytes(), bytes(&v, "r6_record_wire"));
        assert_eq!(wire.anchor_tag, None, "only a transition carries an anchor tag");
        assert_eq!(wire.body.prev_chain, r5.chain());
        assert_eq!(hex::encode(wire.digest), v["r6_record_digest"]);
        assert_eq!(hex::encode(wire.key_tag), v["r6_key_tag"]);
        assert!(wire.key_tag_matches(&b32(&v, "key_v6")));
        let digest = signed_digest(&wire.body_bytes, &wire.key_tag, None);
        assert_eq!(hex::encode(digest), v["r6_sig_digest"]);
        let c = signer(&v, "C");
        let signature: [u8; 64] = bytes(&v, "r6_signature").try_into().unwrap();
        assert_eq!(c.sign(&digest).to_bytes(), signature);
        assert!(wire.signature_verifies(&signature, &c.verifying_key().to_bytes()));
        assert!(!wire.signature_verifies(&signature, &signer(&v, "A").verifying_key().to_bytes()));
        assert_eq!(hex::encode(wire.chain()), v["r6_chain"]);
    }

    #[test]
    fn the_records_say_what_the_vectors_describe() {
        let v = vectors();
        let code = |n: &str| b32(&v, &format!("{n}_code"));
        let read = |r: &str| WireRecord::parse(&bytes(&v, &format!("{r}_record_wire"))).unwrap().body;
        let state = |body: &RecordBody, n: &str| {
            let entry = body.entry(&code(n)).unwrap_or_else(|| panic!("{n} is named"));
            assert_eq!(entry.commitment, b32(&v, &format!("{n}_commitment")));
            (entry.state, entry.role)
        };
        let r5 = read("r5");
        assert_eq!(
            (r5.kind, r5.version, r5.prev_version, r5.link_to, r5.signer_code, r5.entries.len()),
            (RecordKind::Transition, 5, 0, 4, code("A"), 4)
        );
        assert_eq!(r5.circle_id, uuid16(v["circle_id"]));
        assert_eq!(r5.issued_at, 1_790_208_000 + 5 * 3600);
        assert_eq!(state(&r5, "A"), (EntryState::Included, ChainRole::Owner));
        assert_eq!(state(&r5, "B"), (EntryState::Pending, ChainRole::Member));
        assert_eq!(state(&r5, "C"), (EntryState::Pending, ChainRole::Admin));
        assert_eq!(state(&r5, "D"), (EntryState::Pending, ChainRole::Member));
        let r6 = read("r6");
        assert_eq!(
            (r6.kind, r6.version, r6.prev_version, r6.link_to, r6.signer_code, r6.entries.len()),
            (RecordKind::Rotation, 6, 5, 4, code("C"), 4)
        );
        assert_eq!(state(&r6, "A"), (EntryState::Pending, ChainRole::Owner));
        assert_eq!(state(&r6, "B"), (EntryState::Included, ChainRole::Member));
        assert_eq!(state(&r6, "C"), (EntryState::Included, ChainRole::Admin));
        assert_eq!(state(&r6, "D"), (EntryState::Included, ChainRole::Member));
    }

    #[test]
    fn the_links_carry_the_keys_they_name() {
        let v = vectors();
        for (from, to) in [(2, 1), (3, 2), (4, 3), (5, 4), (6, 4)] {
            let cipher = XChaCha20Poly1305::new_from_slice(&b32(&v, &format!("key_v{from}"))).unwrap();
            let nonce: [u8; 24] = bytes(&v, &format!("link_{from}_{to}_nonce")).try_into().unwrap();
            let opened = cipher
                .decrypt(&XNonce::from(nonce), bytes(&v, &format!("link_{from}_{to}_encrypted_key")).as_ref())
                .unwrap();
            assert_eq!(opened, b32(&v, &format!("key_v{to}")), "link {from} -> {to}");
        }
    }

    #[test]
    fn the_head_matches_the_vector() {
        let v = vectors();
        let head = Head {
            format: RecordFormat::V1,
            circle_id: uuid16(v["circle_id"]),
            user_id: uuid16(v["C_user_id"]),
            version: 6,
            chain: b32(&v, "r6_chain"),
        };
        let encoded = head.encode().unwrap();
        assert_eq!(hex::encode(encoded), v["head_C_v6"]);
        assert_eq!(Head::decode(&encoded).unwrap(), head);
        assert_eq!(hex::encode(Head::digest(&encoded)), v["head_C_v6_digest"]);
        assert_eq!(hex::encode(signer(&v, "C").sign(&Head::digest(&encoded)).to_bytes()), v["head_C_v6_signature"]);
    }

    #[test]
    fn each_kind_has_exactly_its_trailer() {
        let v = vectors();
        let r5 = bytes(&v, "r5_record_wire");
        let r6 = bytes(&v, "r6_record_wire");
        let refused = |bytes: &[u8], why: &str| assert!(WireRecord::parse(bytes).is_err(), "must be refused: {why}");
        refused(&r5[..r5.len() - 32], "a transition without its anchor tag");
        refused(&r5[..r5.len() - 1], "a transition's anchor tag cut short");
        let mut long = r5.clone();
        long.push(0);
        refused(&long, "a transition with a trailing byte");
        let mut three_tags = r5.clone();
        three_tags.extend_from_slice(&[0; 32]);
        refused(&three_tags, "a transition with a third tag");
        let mut rotation_with_two = r6.clone();
        rotation_with_two.extend_from_slice(&r5[r5.len() - 32..]);
        refused(&rotation_with_two, "a rotation with an anchor tag");
        // Relabelled: the kind byte decides the trailer, so a transition read as
        // a rotation (or the reverse) has the wrong length.
        let mut as_rotation = r5.clone();
        as_rotation[1] = RecordKind::Rotation.code();
        refused(&as_rotation, "a transition relabelled a rotation");
        let mut as_transition = r6.clone();
        as_transition[1] = RecordKind::Transition.code();
        refused(&as_transition, "a rotation relabelled a transition");
        let mut as_genesis = r5.clone();
        as_genesis[1] = RecordKind::Genesis.code();
        refused(&as_genesis, "a transition relabelled a genesis");
        let mut as_repair = r5;
        as_repair[1] = RecordKind::Repair.code();
        refused(&as_repair, "a transition relabelled a repair");
    }
}

#[cfg(test)]
mod web_vectors {
    //! The vectors the web client wrote with its own implementation, copied
    //! byte for byte and pinned by sha256: the SDK rebuilds and checks every
    //! value in them, so each implementation is checked against the other's
    //! output. The two chains are valid under the structural rules; chains
    //! that break them are kept as the `_negative` files.
    //!
    //! The `_web_built` files hold records the web client's BUILDER made,
    //! beside some made by hand: every value in them is checked here, and each
    //! record against what the file's header says of it; refresh.rs runs them
    //! through the importer as the header says.

    use super::*;
    use crate::membership::{decode_statement, statement_digest, MembershipStatementKind};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    const WEB: &str = include_str!("../tests/data/refresh_record_v1_web.txt");
    const WEB_TRANSITION: &str = include_str!("../tests/data/refresh_record_v1_web_transition.txt");
    const WEB_NEGATIVE: &str = include_str!("../tests/data/refresh_record_v1_web_negative.txt");
    const WEB_TRANSITION_NEGATIVE: &str = include_str!("../tests/data/refresh_record_v1_web_transition_negative.txt");
    const WEB_BUILT: &str = include_str!("../tests/data/refresh_record_v1_web_built.txt");
    const WEB_BUILT_TRANSITION: &str = include_str!("../tests/data/refresh_record_v1_web_built_transition.txt");
    const WEB_BUILT_EJECTS: &str = include_str!("../tests/data/refresh_record_v1_web_built_ejects.txt");

    type Checked = Result<(), String>;

    /// Fail the check with `what` unless `ok`.
    fn ensure(ok: bool, what: impl FnOnce() -> String) -> Checked {
        if ok {
            Ok(())
        } else {
            Err(what())
        }
    }

    /// A vector file, and every name read from it.
    struct Vectors {
        values: HashMap<String, String>,
        read: RefCell<HashSet<String>>,
    }

    impl Vectors {
        fn new(text: &str) -> Self {
            let values = text
                .lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .map(|l| l.split_once('=').expect("name=value"))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Vectors { values, read: RefCell::new(HashSet::new()) }
        }
        fn str(&self, name: &str) -> Result<String, String> {
            let value = self.values.get(name).ok_or_else(|| format!("{name} is missing"))?;
            self.read.borrow_mut().insert(name.to_string());
            Ok(value.clone())
        }
        fn has(&self, name: &str) -> bool {
            self.values.contains_key(name)
        }
        fn bytes(&self, name: &str) -> Result<Vec<u8>, String> {
            hex::decode(self.str(name)?).map_err(|_| format!("{name} is not hex"))
        }
        fn b32(&self, name: &str) -> Result<[u8; 32], String> {
            self.bytes(name)?.try_into().map_err(|_| format!("{name} is not 32 bytes"))
        }
        fn uuid16(&self, name: &str) -> Result<[u8; 16], String> {
            uuid::Uuid::parse_str(&self.str(name)?).map(|u| *u.as_bytes()).map_err(|_| format!("{name} is not a UUID"))
        }
        /// Every value in the file was read and checked.
        fn all_read(&self) -> Checked {
            let read = self.read.borrow();
            let mut unread: Vec<&String> = self.values.keys().filter(|k| !read.contains(*k)).collect();
            unread.sort();
            ensure(unread.is_empty(), || format!("values nobody checked: {unread:?}"))
        }
    }

    /// Check every value of a web vector file with the SDK's own code.
    fn check(v: &Vectors, anchor: u32, records: &[u32], links: &[(u32, u32)], head: (&str, &str)) -> Checked {
        let key = |n: u32| v.b32(&format!("key_v{n}"));
        let secret = circle_secret(&key(anchor)?).map_err(|e| format!("{e:?}"))?;
        ensure(hex::encode(*secret) == v.str("S")?, || "S from the anchor key".into())?;
        if v.has("anchor") {
            ensure(v.str("anchor")? == anchor.to_string(), || "the anchor".into())?;
        }
        let circle = v.uuid16("circle_id")?;
        let mut signers: HashMap<[u8; 32], SigningKey> = HashMap::new();
        for n in ["A", "B", "C"] {
            let signing = SigningKey::from_bytes(&v.b32(&format!("{n}_signing_seed"))?);
            let signing_pk = signing.verifying_key().to_bytes();
            ensure(hex::encode(signing_pk) == v.str(&format!("{n}_signing_pk"))?, || format!("{n}'s signing key"))?;
            let sharing = v.b32(&format!("{n}_sharing_pk"))?;
            let code = member_code(&secret, &v.uuid16(&format!("{n}_user_id"))?);
            ensure(hex::encode(code) == v.str(&format!("{n}_code"))?, || format!("{n}'s code"))?;
            let commitment = key_commitment(&secret, &code, &sharing, &signing_pk);
            ensure(hex::encode(commitment) == v.str(&format!("{n}_commitment"))?, || format!("{n}'s commitment"))?;
            signers.insert(code, signing);
        }
        let mut previous: Option<[u8; 32]> = None;
        for r in records {
            let name = |what: &str| format!("r{r}_{what}");
            let wire_bytes = v.bytes(&name("record_wire"))?;
            let wire = WireRecord::parse(&wire_bytes).map_err(|e| format!("r{r} parses: {e:?}"))?;
            ensure(wire.body_bytes == v.bytes(&name("body"))?, || format!("r{r}'s body"))?;
            ensure(wire.body.encode().map_err(|e| format!("{e:?}"))? == wire.body_bytes, || format!("r{r} re-encodes"))?;
            ensure(wire.to_bytes() == wire_bytes, || format!("r{r}'s wire"))?;
            ensure((wire.body.version, wire.body.circle_id) == (*r, circle), || format!("r{r}'s version and circle"))?;
            if let Some(previous) = previous {
                ensure(wire.body.prev_chain == previous, || format!("r{r} links the record before it"))?;
            }
            ensure(hex::encode(wire.digest) == v.str(&name("record_digest"))?, || format!("r{r}'s digest"))?;
            ensure(hex::encode(wire.key_tag) == v.str(&name("key_tag"))?, || format!("r{r}'s key tag"))?;
            let key_r = key(*r)?;
            ensure(key_tag(&key_r, &wire.digest).map_err(|e| format!("{e:?}"))? == wire.key_tag, || format!("r{r}'s key tag from key_v{r}"))?;
            if v.has(&name("anchor_tag")) {
                ensure(wire.body.kind == RecordKind::Transition, || format!("r{r} is a transition"))?;
                ensure(wire.anchor_tag.map(hex::encode) == Some(v.str(&name("anchor_tag"))?), || format!("r{r}'s anchor tag"))?;
                ensure(wire.anchor_tag_matches(&key(anchor)?), || format!("r{r}'s anchor tag from the anchor key"))?;
            } else {
                ensure(wire.anchor_tag.is_none(), || format!("r{r} carries no anchor tag"))?;
            }
            let digest = signed_digest(&wire.body_bytes, &wire.key_tag, wire.anchor_tag.as_ref());
            ensure(hex::encode(digest) == v.str(&name("sig_digest"))?, || format!("r{r}'s signed digest"))?;
            let signer = signers.get(&wire.body.signer_code).ok_or_else(|| format!("r{r}'s signer is not A, B or C"))?;
            let signature: [u8; 64] = v.bytes(&name("signature"))?.try_into().map_err(|_| format!("r{r}'s signature length"))?;
            ensure(signer.sign(&digest).to_bytes() == signature, || format!("r{r}'s signature"))?;
            ensure(wire.signature_verifies(&signature, &signer.verifying_key().to_bytes()), || format!("r{r}'s signature verifies"))?;
            ensure(hex::encode(wire.chain()) == v.str(&name("chain"))?, || format!("r{r}'s chain value"))?;
            previous = Some(wire.chain());
        }
        for (from, to) in links {
            let cipher = XChaCha20Poly1305::new_from_slice(&key(*from)?).map_err(|e| format!("{e:?}"))?;
            let nonce: [u8; 24] = v.bytes(&format!("link_{from}_{to}_nonce"))?.try_into().map_err(|_| "a nonce length".to_string())?;
            let opened = cipher
                .decrypt(&XNonce::from(nonce), v.bytes(&format!("link_{from}_{to}_encrypted_key"))?.as_ref())
                .map_err(|_| format!("link {from} -> {to} opens"))?;
            ensure(opened == key(*to)?, || format!("link {from} -> {to} carries key_v{to}"))?;
        }
        let (head_name, head_signer) = head;
        let encoded = v.bytes(head_name)?;
        let decoded = Head::decode(&encoded).map_err(|e| format!("{e:?}"))?;
        let last = *records.last().expect("a record");
        ensure(
            (decoded.circle_id, decoded.user_id, decoded.version, hex::encode(decoded.chain))
                == (circle, v.uuid16(&format!("{head_signer}_user_id"))?, last, v.str(&format!("r{last}_chain"))?),
            || "the head's fields".into(),
        )?;
        let encoded: [u8; 69] = encoded.try_into().map_err(|_| "the head's length".to_string())?;
        ensure(decoded.encode().map_err(|e| format!("{e:?}"))? == encoded, || "the head re-encodes".into())?;
        ensure(hex::encode(Head::digest(&encoded)) == v.str(&format!("{head_name}_digest"))?, || "the head's digest".into())?;
        let signer = SigningKey::from_bytes(&v.b32(&format!("{head_signer}_signing_seed"))?);
        ensure(
            hex::encode(signer.sign(&Head::digest(&encoded)).to_bytes()) == v.str(&format!("{head_name}_signature"))?,
            || "the head's signature".into(),
        )?;
        v.all_read()
    }

    fn check_web(text: &str) -> Checked {
        check(&Vectors::new(text), 1, &[1, 2, 3], &[(2, 1), (3, 2)], ("head_B_v3", "B"))
    }

    fn check_web_transition(text: &str) -> Checked {
        check(&Vectors::new(text), 2, &[3, 4], &[(2, 1), (3, 2), (4, 2)], ("head_C_v4", "C"))
    }

    #[test]
    fn the_nine_vector_files_are_the_pinned_bytes() {
        let sha = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
        assert_eq!(sha(WEB), "1b174af8667072947786d6ced4710ac40a9a1e11e4b659fbd74e2c3c7e9a4206");
        assert_eq!(sha(WEB_TRANSITION), "bbf14ccd45a2b215b47d75c79de1a6c9a6c8f170ba88fefb94426f25759c8ed5");
        assert_eq!(sha(WEB_NEGATIVE), "b7756aeb47f5279f52d7185c24b1609a17b49be8675590f6d3f4a54f17b32df3");
        assert_eq!(sha(WEB_TRANSITION_NEGATIVE), "29f448ffcd6d474860f2a4fd1a19b17c41f74eeddca46cac350ca2221a4a2b8e");
        // The web client's builder's records, as the web client pins them.
        assert_eq!(sha(WEB_BUILT), "1dd3d15fe2f82d8d47e0c779b10a5d866544568d2fa57130265aa374da213ca5");
        assert_eq!(sha(WEB_BUILT_TRANSITION), "03adb4768f1c554c75a7b0cc821e58f8956c3f6ea40621f4405575174d32fdd9");
        assert_eq!(sha(WEB_BUILT_EJECTS), "ad551c43f328417a41197e60ded1aad9a25977a06be1ed3b93557db77f51d1d3");
        assert_eq!(
            sha(include_str!("../tests/data/refresh_record_v1.txt")),
            "09f62ac3bff5371d1f5b3c57dc8ec29c3ad43c3947a7aa6d852966c1a420350b"
        );
        assert_eq!(
            sha(include_str!("../tests/data/refresh_record_v1_transition.txt")),
            "a8caeb5ed9be6469f9025dac085dfa951662a4854bd411eedf0ba1a523fd8209"
        );
    }

    #[test]
    fn every_value_of_the_webs_genesis_vectors_checks_out() {
        for text in [WEB, WEB_NEGATIVE] {
            check_web(text).unwrap();
            let v = Vectors::new(text);
            let read = |r: &str| WireRecord::parse(&hex::decode(&v.values[r]).unwrap()).unwrap().body;
            assert_eq!(read("r1_record_wire").kind, RecordKind::Genesis);
            assert_eq!(read("r3_record_wire").kind, RecordKind::Rotation);
        }
    }

    #[test]
    fn every_value_of_the_webs_transition_vectors_checks_out() {
        for text in [WEB_TRANSITION, WEB_TRANSITION_NEGATIVE] {
            check_web_transition(text).unwrap();
            let v = Vectors::new(text);
            let r3 = WireRecord::parse(&hex::decode(&v.values["r3_record_wire"]).unwrap()).unwrap().body;
            assert_eq!((r3.kind, r3.prev_version, r3.link_to), (RecordKind::Transition, 0, 2));
            let r4 = WireRecord::parse(&hex::decode(&v.values["r4_record_wire"]).unwrap()).unwrap().body;
            assert_eq!((r4.kind, r4.prev_version, r4.link_to), (RecordKind::Rotation, 3, 2));
        }
    }

    /// `text` with the value of `name` changed: its first hex digit flipped.
    fn with_changed(text: &str, name: &str) -> String {
        text.lines()
            .map(|l| match l.split_once('=') {
                Some((n, value)) if n == name => {
                    let mut chars: Vec<char> = value.chars().collect();
                    let at = chars.iter().position(|c| c.is_ascii_hexdigit()).expect("a hex digit");
                    chars[at] = if chars[at] == '0' { '1' } else { '0' };
                    format!("{n}={}", chars.into_iter().collect::<String>())
                }
                _ => l.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn changing_any_value_fails_the_check() {
        // Each value of each file, changed on its own, fails the recomputation
        // (not only the pin): the check is blind to none of them.
        for (text, check) in [
            (WEB, check_web as fn(&str) -> Checked),
            (WEB_NEGATIVE, check_web),
            (WEB_TRANSITION, check_web_transition),
            (WEB_TRANSITION_NEGATIVE, check_web_transition),
        ] {
            let names: Vec<String> = Vectors::new(text).values.keys().cloned().collect();
            assert!(names.len() >= 49, "{} values", names.len());
            for name in names {
                let changed = with_changed(text, &name);
                assert!(check(&changed).is_err(), "{name} changed must fail the check");
            }
        }
    }

    /// One record as a web-built file's header describes it.
    struct Said {
        version: u32,
        kind: RecordKind,
        made_by: &'static str,
        signer: &'static str,
        link_to: u32,
        /// Every entry, by member name.
        entries: &'static [(&'static str, EntryState, ChainRole)],
    }

    fn kind_name(kind: RecordKind) -> &'static str {
        match kind {
            RecordKind::Genesis => "genesis",
            RecordKind::Transition => "transition",
            RecordKind::Rotation => "rotation",
            RecordKind::Repair => "repair",
        }
    }

    /// Check every value of a web-BUILT vector file with the SDK's own code,
    /// and each record against what the header says of it (`said`), the
    /// invitations as `invited` says (subject, signer, at_version). These files
    /// carry no codes, commitments or digests: they are recomputed here.
    fn check_built(
        v: &Vectors,
        anchor: u32,
        said: &[Said],
        invited: &[(&str, &str, i32)],
        links: &[(u32, u32)],
        head: Option<(&str, &str, u32)>,
    ) -> Checked {
        struct Member {
            uid: [u8; 16],
            code: [u8; 32],
            sharing: [u8; 32],
            signing: SigningKey,
        }
        let key = |n: u32| v.b32(&format!("key_v{n}"));
        let secret = circle_secret(&key(anchor)?).map_err(|e| format!("{e:?}"))?;
        ensure(hex::encode(*secret) == v.str("S")?, || "S from the anchor key".into())?;
        if v.has("anchor") {
            ensure(v.str("anchor")? == anchor.to_string(), || "the anchor".into())?;
        }
        let circle = v.uuid16("circle_id")?;
        let now: u64 = v.str("now")?.parse().map_err(|_| "now is not a number".to_string())?;
        let mut members: HashMap<&str, Member> = HashMap::new();
        for n in ["A", "B", "C", "D", "E", "F", "N", "M"].into_iter().filter(|n| v.has(&format!("{n}_user_id"))) {
            let signing = SigningKey::from_bytes(&v.b32(&format!("{n}_signing_seed"))?);
            ensure(hex::encode(signing.verifying_key().to_bytes()) == v.str(&format!("{n}_signing_pk"))?, || format!("{n}'s signing key"))?;
            let uid = v.uuid16(&format!("{n}_user_id"))?;
            members.insert(n, Member { uid, code: member_code(&secret, &uid), sharing: v.b32(&format!("{n}_sharing_pk"))?, signing });
        }
        // E's keys after a password reset, which only the lists show: no
        // record commits to them.
        if v.has("E_new_signing_seed") {
            let signing = SigningKey::from_bytes(&v.b32("E_new_signing_seed")?);
            ensure(hex::encode(signing.verifying_key().to_bytes()) == v.str("E_new_signing_pk")?, || "E's new signing key".into())?;
            v.b32("E_new_sharing_pk")?;
        }
        let member = |n: &str| members.get(n).ok_or_else(|| format!("{n} is not in the file"));
        for (subject, signer, at_version) in invited {
            let bytes = v.bytes(&format!("{subject}_invitation"))?;
            let s = decode_statement(&bytes).map_err(|e| format!("{subject}'s invitation: {e:?}"))?;
            let (who, by) = (member(subject)?, member(signer)?);
            ensure(
                s.kind == MembershipStatementKind::InvitationToAccount
                    && s.circle_id == v.str("circle_id")?
                    && s.signer_user_id == v.str(&format!("{signer}_user_id"))?
                    && s.at_version == *at_version
                    && s.subject_user_id == Some(v.str(&format!("{subject}_user_id"))?)
                    && s.subject_sharing_public_key_hex == Some(hex::encode(who.sharing))
                    && s.subject_signing_public_key_hex == Some(hex::encode(who.signing.verifying_key().to_bytes())),
                || format!("{subject}'s invitation, by {signer} at v{at_version}"),
            )?;
            let signature: [u8; 64] =
                v.bytes(&format!("{subject}_invitation_signature"))?.try_into().map_err(|_| format!("{subject}'s invitation signature length"))?;
            ensure(
                by.signing.verifying_key().verify_strict(&statement_digest(&bytes), &Signature::from_bytes(&signature)).is_ok(),
                || format!("{subject}'s invitation verifies under {signer}'s key"),
            )?;
        }
        let mut previous: Option<[u8; 32]> = None;
        for s in said {
            let r = s.version;
            let name = |what: &str| format!("r{r}_{what}");
            let wire_bytes = v.bytes(&name("record_wire"))?;
            let wire = WireRecord::parse(&wire_bytes).map_err(|e| format!("r{r} parses: {e:?}"))?;
            ensure(wire.to_bytes() == wire_bytes, || format!("r{r}'s wire"))?;
            ensure(wire.body.encode().map_err(|e| format!("{e:?}"))? == wire.body_bytes, || format!("r{r} re-encodes"))?;
            ensure((wire.body.version, wire.body.circle_id) == (r, circle), || format!("r{r}'s version and circle"))?;
            ensure(wire.body.kind == s.kind && v.str(&name("kind"))? == kind_name(s.kind), || format!("r{r} is a {}", kind_name(s.kind)))?;
            ensure(v.str(&name("made_by"))? == s.made_by, || format!("r{r} was made by {}", s.made_by))?;
            if s.made_by == "web builder" {
                ensure(wire.body.issued_at == now, || format!("r{r}, built, is issued at now"))?;
            }
            ensure(wire.body.link_to == s.link_to, || format!("r{r} links to v{}", s.link_to))?;
            if let Some(previous) = previous {
                ensure(wire.body.prev_version == r - 1 && wire.body.prev_chain == previous, || format!("r{r} links the record before it"))?;
            }
            ensure(key_tag(&key(r)?, &wire.digest).map_err(|e| format!("{e:?}"))? == wire.key_tag, || format!("r{r}'s key tag from key_v{r}"))?;
            if s.kind == RecordKind::Transition {
                ensure(s.link_to == anchor && wire.anchor_tag_matches(&key(anchor)?), || format!("r{r}'s anchor tag from the anchor key"))?;
            } else {
                ensure(wire.anchor_tag.is_none(), || format!("r{r} carries no anchor tag"))?;
            }
            let signer = member(s.signer)?;
            ensure(wire.body.signer_code == signer.code, || format!("r{r} is signed as {}", s.signer))?;
            let signature: [u8; 64] = v.bytes(&name("signature"))?.try_into().map_err(|_| format!("r{r}'s signature length"))?;
            let digest = signed_digest(&wire.body_bytes, &wire.key_tag, wire.anchor_tag.as_ref());
            ensure(signer.signing.sign(&digest).to_bytes() == signature, || format!("r{r}'s signature"))?;
            ensure(wire.signature_verifies(&signature, &signer.signing.verifying_key().to_bytes()), || format!("r{r}'s signature verifies"))?;
            let mut entries = Vec::new();
            for e in &wire.body.entries {
                let (n, m) = members.iter().find(|(_, m)| m.code == e.code).ok_or_else(|| format!("r{r} names someone not in the file"))?;
                let commitment = key_commitment(&secret, &e.code, &m.sharing, &m.signing.verifying_key().to_bytes());
                ensure(e.commitment == commitment, || format!("r{r}'s entry for {n} commits to {n}'s keys"))?;
                entries.push((*n, e.state, e.role));
            }
            entries.sort_by_key(|(n, _, _)| *n);
            let mut want = s.entries.to_vec();
            want.sort_by_key(|(n, _, _)| *n);
            ensure(entries == want, || format!("r{r}'s entries: {entries:?}"))?;
            ensure(hex::encode(wire.chain()) == v.str(&name("chain"))?, || format!("r{r}'s chain value"))?;
            previous = Some(wire.chain());
        }
        for (from, to) in links {
            let cipher = XChaCha20Poly1305::new_from_slice(&key(*from)?).map_err(|e| format!("{e:?}"))?;
            let nonce: [u8; 24] = v.bytes(&format!("link_{from}_{to}_nonce"))?.try_into().map_err(|_| "a nonce length".to_string())?;
            let opened = cipher
                .decrypt(&XNonce::from(nonce), v.bytes(&format!("link_{from}_{to}_encrypted_key"))?.as_ref())
                .map_err(|_| format!("link {from} -> {to} opens"))?;
            ensure(opened == key(*to)?, || format!("link {from} -> {to} carries key_v{to}"))?;
        }
        if let Some((head_name, signer, version)) = head {
            let encoded = v.bytes(head_name)?;
            let decoded = Head::decode(&encoded).map_err(|e| format!("{e:?}"))?;
            ensure(
                (decoded.circle_id, decoded.user_id, decoded.version, hex::encode(decoded.chain))
                    == (circle, member(signer)?.uid, version, v.str(&format!("r{version}_chain"))?),
                || "the head's fields".into(),
            )?;
            let encoded: [u8; 69] = encoded.try_into().map_err(|_| "the head's length".to_string())?;
            ensure(decoded.encode().map_err(|e| format!("{e:?}"))? == encoded, || "the head re-encodes".into())?;
            ensure(
                hex::encode(member(signer)?.signing.sign(&Head::digest(&encoded)).to_bytes()) == v.str(&format!("{head_name}_signature"))?,
                || "the head's signature".into(),
            )?;
        }
        v.all_read()
    }

    fn check_web_built(text: &str) -> Checked {
        use ChainRole::{Admin, Member, Owner};
        use EntryState::{Departed, Included, Pending};
        use RecordKind::{Genesis, Repair, Rotation};
        let said = [
            Said { version: 1, kind: Genesis, made_by: "hand", signer: "A", link_to: 0, entries: &[("A", Included, Owner)] },
            // Owner A's rotation: B, C and D in by A's invitations, C made admin.
            Said {
                version: 2,
                kind: Rotation,
                made_by: "web builder",
                signer: "A",
                link_to: 1,
                entries: &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("D", Included, Member)],
            },
            // A's fresh install, D off its list: D filled in departed.
            Said {
                version: 3,
                kind: Rotation,
                made_by: "web builder",
                signer: "A",
                link_to: 2,
                entries: &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("D", Departed, Member)],
            },
            // Admin C: newcomer N in.
            Said {
                version: 4,
                kind: Rotation,
                made_by: "hand",
                signer: "C",
                link_to: 3,
                entries: &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("N", Included, Member)],
            },
            // A's repair where r4 is rejected: N pending, link 5 -> 4.
            Said {
                version: 5,
                kind: Repair,
                made_by: "web builder",
                signer: "A",
                link_to: 4,
                entries: &[("A", Included, Owner), ("B", Included, Member), ("C", Included, Admin), ("N", Pending, Member)],
            },
        ];
        let invited = [("B", "A", 1), ("C", "A", 1), ("D", "A", 1), ("N", "C", 3)];
        check_built(&Vectors::new(text), 1, &said, &invited, &[(2, 1), (3, 2), (4, 3), (5, 4)], Some(("head_A_v2", "A", 2)))
    }

    fn check_web_built_transition(text: &str) -> Checked {
        use ChainRole::{Admin, Member, Owner};
        use EntryState::{Included, Pending};
        // Owner A's transition over a circle at v4: B admin, C a member pending.
        let said = [Said {
            version: 5,
            kind: RecordKind::Transition,
            made_by: "web builder",
            signer: "A",
            link_to: 4,
            entries: &[("A", Included, Owner), ("B", Included, Admin), ("C", Pending, Member)],
        }];
        check_built(&Vectors::new(text), 4, &said, &[], &[(2, 1), (3, 2), (4, 3), (5, 4)], None)
    }

    fn check_web_built_ejects(text: &str) -> Checked {
        use ChainRole::{Admin, Member, Owner};
        use EntryState::{Departed, Included, Pending, Removed};
        use RecordKind::{Genesis, Repair, Rotation};
        let said = [
            Said { version: 1, kind: Genesis, made_by: "hand", signer: "A", link_to: 0, entries: &[("A", Included, Owner)] },
            Said {
                version: 2,
                kind: Rotation,
                made_by: "hand",
                signer: "A",
                link_to: 1,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("D", Included, Member),
                    ("E", Included, Member),
                    ("F", Included, Member),
                ],
            },
            // A's eject of D, counted: D removed.
            Said {
                version: 3,
                kind: Rotation,
                made_by: "web builder",
                signer: "A",
                link_to: 2,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("D", Removed, Member),
                    ("E", Included, Member),
                    ("F", Included, Member),
                ],
            },
            // Admin C: E and F pending only, newcomer N in.
            Said {
                version: 4,
                kind: Rotation,
                made_by: "hand",
                signer: "C",
                link_to: 3,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("E", Pending, Member),
                    ("F", Pending, Member),
                    ("N", Included, Member),
                ],
            },
            // A's repair where r4 is rejected: E pending, F filled departed, N pending.
            Said {
                version: 5,
                kind: Repair,
                made_by: "web builder",
                signer: "A",
                link_to: 4,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("E", Pending, Member),
                    ("F", Departed, Member),
                    ("N", Pending, Member),
                ],
            },
            // Admin C: N included again, newcomer M in.
            Said {
                version: 6,
                kind: Rotation,
                made_by: "hand",
                signer: "C",
                link_to: 5,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("E", Pending, Member),
                    ("M", Included, Member),
                    ("N", Included, Member),
                ],
            },
            // A's eject of M where r6 is rejected: M, named by r6 only, removed.
            Said {
                version: 7,
                kind: Rotation,
                made_by: "web builder",
                signer: "A",
                link_to: 6,
                entries: &[
                    ("A", Included, Owner),
                    ("B", Included, Member),
                    ("C", Included, Admin),
                    ("E", Pending, Member),
                    ("M", Removed, Member),
                    ("N", Pending, Member),
                ],
            },
        ];
        let invited = [("B", "A", 1), ("C", "A", 1), ("D", "A", 1), ("E", "A", 1), ("F", "A", 1), ("N", "C", 3), ("M", "C", 5)];
        let links = [(2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 6)];
        check_built(&Vectors::new(text), 1, &said, &invited, &links, None)
    }

    #[test]
    fn every_value_of_the_webs_built_vectors_checks_out() {
        check_web_built(WEB_BUILT).unwrap();
        check_web_built_transition(WEB_BUILT_TRANSITION).unwrap();
        check_web_built_ejects(WEB_BUILT_EJECTS).unwrap();
    }

    #[test]
    fn changing_any_value_of_a_built_file_fails_the_check() {
        for (text, check) in [
            (WEB_BUILT, check_web_built as fn(&str) -> Checked),
            (WEB_BUILT_TRANSITION, check_web_built_transition),
            (WEB_BUILT_EJECTS, check_web_built_ejects),
        ] {
            let names: Vec<String> = Vectors::new(text).values.keys().cloned().collect();
            assert!(names.len() >= 34, "{} values", names.len());
            for name in names {
                // What the lists show for E after the reset: no record commits
                // to it, so nothing in the file checks it.
                if name == "E_new_sharing_pk" {
                    continue;
                }
                let changed = with_changed(text, &name);
                assert!(check(&changed).is_err(), "{name} changed must fail the check");
            }
        }
    }
}

#[cfg(test)]
mod refusals {
    //! Every structural rule, broken on its own, is refused.

    use super::*;

    const R2_WIRE: &str = include_str!("../tests/data/refresh_record_v1.txt");

    fn body_of(name: &str) -> Vec<u8> {
        let line = R2_WIRE
            .lines()
            .find(|l| l.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} in the vectors"));
        hex::decode(&line[name.len() + 1..]).unwrap()
    }

    fn refused(bytes: &[u8], why: &str) {
        assert!(RecordBody::decode(bytes).is_err(), "must be refused: {why}");
    }

    /// Rewrite a field of a vector body, keeping everything else.
    fn with(name: &str, edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut bytes = body_of(name);
        edit(&mut bytes);
        bytes
    }

    #[test]
    fn the_vectors_themselves_are_accepted() {
        for name in ["r1_body", "r2_body", "r3_body", "r4_body"] {
            RecordBody::decode(&body_of(name)).unwrap();
        }
    }

    #[test]
    fn a_wrong_format_kind_or_length_is_refused() {
        // Formats 1 and 2 read; no other.
        let format2 = RecordBody::decode(&with("r2_body", |b| b[0] = 2)).unwrap();
        assert_eq!(format2, RecordBody { format: RecordFormat::V2, ..RecordBody::decode(&body_of("r2_body")).unwrap() });
        refused(&with("r2_body", |b| b[0] = 3), "format 3");
        refused(&with("r2_body", |b| b[0] = 0xff), "format 255");
        refused(&with("r2_body", |b| b[0] = 0), "format 0");
        refused(&with("r2_body", |b| b[1] = 0), "kind 0");
        refused(&with("r2_body", |b| b[1] = 5), "kind 5");
        refused(&with("r2_body", |b| b.push(0)), "a trailing byte");
        refused(&with("r2_body", |b| {
            b.pop();
        }), "a missing byte");
        refused(&with("r2_body", |b| b[102] += 1), "count one more than the entries");
        refused(&with("r2_body", |b| b[102] -= 1), "count one fewer than the entries");
        refused(&body_of("r2_body")[..102], "no count");
        refused(&[], "empty");
    }

    /// r2's header and signer entry, plus `extra` plain pending members, as
    /// raw bytes (no encoder check), with the count byte set to match.
    fn r2_with_extra_members(extra: u32) -> Vec<u8> {
        let r2 = RecordBody::decode(&body_of("r2_body")).unwrap();
        let signer = r2.entry(&r2.signer_code).unwrap().clone();
        let mut entries: Vec<RecordEntry> = (0..extra)
            .map(|i| {
                let mut code = [0u8; 32];
                code[..4].copy_from_slice(&i.to_be_bytes());
                RecordEntry { code, state: EntryState::Pending, role: ChainRole::Member, commitment: [7; 32] }
            })
            .collect();
        entries.push(signer);
        entries.sort_by(|a, b| a.code.cmp(&b.code));
        let mut bytes = body_of("r2_body")[..103].to_vec();
        bytes[102] = entries.len() as u8;
        for e in &entries {
            bytes.extend_from_slice(&e.code);
            bytes.push(e.state.code());
            bytes.push(e.role.code());
            bytes.extend_from_slice(&e.commitment);
        }
        bytes
    }

    #[test]
    fn a_count_outside_1_to_200_is_refused() {
        let count_error = |bytes: &[u8]| match RecordBody::decode(bytes) {
            Err(MobileError::InvalidInput(why)) => why,
            other => panic!("must be refused, got {other:?}"),
        };
        let mut empty = body_of("r1_body")[..103].to_vec();
        empty[102] = 0;
        assert_eq!(count_error(&empty), "a record names 1..=200 members", "count 0, for that reason");
        assert_eq!(count_error(&r2_with_extra_members(200)), "a record names 1..=200 members", "count 201");
        // The bound is exactly 200.
        let two_hundred = RecordBody::decode(&r2_with_extra_members(199)).unwrap();
        assert_eq!(two_hundred.entries.len(), MAX_ENTRIES);
        assert_eq!(two_hundred.encode().unwrap().len(), 103 + 66 * 200);
    }

    #[test]
    fn entries_out_of_order_repeated_or_malformed_are_refused() {
        // r2 has four entries; swap the first two.
        refused(&with("r2_body", |b| {
            let first: Vec<u8> = b[103..169].to_vec();
            let second: Vec<u8> = b[169..235].to_vec();
            b[103..169].copy_from_slice(&second);
            b[169..235].copy_from_slice(&first);
        }), "entries out of order");
        refused(&with("r2_body", |b| {
            let first: Vec<u8> = b[103..169].to_vec();
            b[169..235].copy_from_slice(&first);
        }), "a repeated entry");
        for (at, bad) in [(135usize, 0u8), (135, 5), (136, 0), (136, 4)] {
            refused(&with("r2_body", |b| b[at] = bad), "a bad state or role");
        }
    }

    #[test]
    fn a_second_owner_or_a_signer_not_included_is_refused() {
        // r2: make B (a member) an owner too.
        let r2 = RecordBody::decode(&body_of("r2_body")).unwrap();
        let b_index = r2.entries.iter().position(|e| e.role == ChainRole::Member).unwrap();
        refused(&with("r2_body", |b| b[103 + 66 * b_index + 33] = 1), "two owners");
        // r3: the signer C marked pending instead of included.
        let r3 = RecordBody::decode(&body_of("r3_body")).unwrap();
        let c_index = r3.entries.iter().position(|e| e.code == r3.signer_code).unwrap();
        refused(&with("r3_body", |b| b[103 + 66 * c_index + 32] = 2), "the signer pending");
        // r3: a signer code that names nobody.
        refused(&with("r3_body", |b| b[62] ^= 1), "a signer who is not named");
    }

    #[test]
    fn each_kind_keeps_its_shape() {
        // Genesis (r1).
        refused(&with("r1_body", |b| b[18] = 2), "a genesis at version 2");
        refused(&with("r1_body", |b| b[22] = 1), "a genesis with a previous version");
        refused(&with("r1_body", |b| b[26] = 1), "a genesis with a previous chain");
        refused(&with("r1_body", |b| b[58] = 1), "a genesis with a link");
        refused(&with("r1_body", |b| b[136] = 2), "a genesis whose creator is not the owner");
        // Rotation (r2, version 2 from 1).
        refused(&with("r2_body", |b| b[22] = 0), "a rotation from version 0");
        refused(&with("r2_body", |b| b[22] = 2), "a rotation from its own version");
        refused(&with("r2_body", |b| b[26..58].fill(0)), "a rotation with no previous chain");
        refused(&with("r2_body", |b| b[58] = 0), "a rotation with no link");
        refused(&with("r2_body", |b| b[58] = 2), "a rotation linking above the version it moved off");
        refused(&with("r2_body", |b| b[1] = 1), "a rotation relabelled a genesis");
        refused(&with("r2_body", |b| b[1] = 2), "a rotation relabelled a transition");
        // A repair has a rotation's shape.
        RecordBody::decode(&with("r2_body", |b| b[1] = 4)).unwrap();
        // Versions and times.
        refused(&with("r2_body", |b| b[18..22].copy_from_slice(&0u32.to_le_bytes())), "version 0");
        refused(&with("r4_body", |b| {
            b[18..22].copy_from_slice(&1_000_001u32.to_le_bytes());
            b[22..26].copy_from_slice(&1_000_000u32.to_le_bytes());
        }), "a version above 1,000,000");
        refused(&with("r2_body", |b| b[94..102].fill(0)), "issued_at 0");
        refused(&with("r2_body", |b| b[94..102].copy_from_slice(&u64::MAX.to_le_bytes())), "issued_at above i64");
    }

    #[test]
    fn a_transition_keeps_its_shape() {
        // A transition built from r2's entries: version 2, no previous record,
        // link_to 1, only included and pending, one owner, signed by the owner.
        let r2 = RecordBody::decode(&body_of("r2_body")).unwrap();
        let transition = RecordBody { kind: RecordKind::Transition, prev_version: 0, prev_chain: [0; 32], ..r2.clone() };
        let bytes = transition.encode().unwrap();
        assert_eq!(RecordBody::decode(&bytes).unwrap(), transition);
        let refused_body = |edit: fn(&mut RecordBody), why: &str| {
            let mut body = transition.clone();
            edit(&mut body);
            assert!(body.encode().is_err(), "must be refused: {why}");
        };
        refused_body(|b| b.link_to = 0, "a transition with no link");
        refused_body(|b| b.link_to = b.version, "a transition linking to itself");
        refused_body(|b| b.version = 1, "a transition at version 1");
        refused_body(|b| b.prev_version = 1, "a transition with a previous version");
        refused_body(|b| b.prev_chain = [1; 32], "a transition with a previous chain");
        refused_body(|b| b.entries.iter_mut().for_each(|e| if e.role == ChainRole::Owner { e.role = ChainRole::Admin }), "a transition with no owner");
        refused_body(|b| b.entries[0].state = EntryState::Removed, "a transition naming a removal");
        refused_body(|b| b.entries[0].state = EntryState::Departed, "a transition naming a departure");
        refused_body(
            |b| {
                let signer = b.signer_code;
                b.entries.iter_mut().filter(|e| e.code == signer).for_each(|e| e.role = ChainRole::Member);
                // Keep exactly one owner: give it to someone else.
                if let Some(e) = b.entries.iter_mut().find(|e| e.code != signer) {
                    e.role = ChainRole::Owner;
                }
            },
            "a transition signed by a plain member",
        );
    }

    #[test]
    fn wire_records_need_their_tag_and_nothing_more() {
        let r1 = body_of("r1_record_wire");
        WireRecord::parse(&r1).unwrap();
        assert!(WireRecord::parse(&r1[..r1.len() - 1]).is_err(), "a short tag");
        let mut long = r1.clone();
        long.push(0);
        assert!(WireRecord::parse(&long).is_err(), "a trailing byte");
        assert!(WireRecord::parse(&r1[..r1.len() - 32]).is_err(), "no tag");
    }

    #[test]
    fn heads_are_strict() {
        let head = body_of("head_A_v4");
        Head::decode(&head).unwrap();
        assert!(Head::decode(&head[..68]).is_err());
        let mut long = head.clone();
        long.push(0);
        assert!(Head::decode(&long).is_err());
        let mut format = head.clone();
        format[0] = 2;
        assert_eq!(Head::decode(&format).unwrap().format, RecordFormat::V2);
        format[0] = 3;
        assert!(Head::decode(&format).is_err());
        format[0] = 0;
        assert!(Head::decode(&format).is_err());
        let mut zero = head.clone();
        zero[33..37].fill(0);
        assert!(Head::decode(&zero).is_err());
    }
}

#[cfg(test)]
pub(crate) mod v2_vectors {
    //! The format-2 vectors: an independent generator made them, and they
    //! are locked byte for byte (the fifth, a format going down, among them).
    //! The SDK pins each file by sha256 and rebuilds every value in it with
    //! its own code, every one read; refresh.rs runs them through the
    //! importer.

    use super::*;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    pub(crate) const SWITCH: &str = include_str!("../tests/data/refresh_record_v2_switch.txt");
    pub(crate) const GENESIS: &str = include_str!("../tests/data/refresh_record_v2_genesis.txt");
    pub(crate) const TRANSITION: &str = include_str!("../tests/data/refresh_record_v2_transition.txt");
    pub(crate) const MISATTRIBUTED: &str = include_str!("../tests/data/refresh_record_v2_misattributed.txt");
    pub(crate) const FORMAT_DOWN: &str = include_str!("../tests/data/refresh_record_v2_format_down.txt");

    #[test]
    fn the_five_v2_files_are_the_locked_bytes() {
        let sha = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
        assert_eq!(sha(SWITCH), "8e4029feeff6740a4f8cbefeb32f588041b4449444bbcc81ff9de51708f043b4");
        assert_eq!(sha(GENESIS), "8bb6e64cff778fd5b2d87a58f1c1acdcd05e6951ad310536bd08683db0029f83");
        assert_eq!(sha(TRANSITION), "116bcf72636ddba6612a62136563641a6cecbfab78a73b28245a4f02d7c66449");
        assert_eq!(sha(MISATTRIBUTED), "1a1df096102a7278f11c943890aba1bfb893707d2c770a5fe75813d2c8148d11");
        assert_eq!(sha(FORMAT_DOWN), "641c63d79bf17e0a3a6b5093b94445ec6192893931058f0bdae027c54190343a");
    }

    /// A vector file, and every name read from it.
    pub(crate) struct File {
        values: HashMap<String, String>,
        read: RefCell<HashSet<String>>,
    }

    impl File {
        pub(crate) fn new(text: &str) -> Self {
            let values = text
                .lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .map(|l| l.split_once('=').expect("name=value"))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            File { values, read: RefCell::new(HashSet::new()) }
        }
        pub(crate) fn str(&self, name: &str) -> String {
            let value = self.values.get(name).unwrap_or_else(|| panic!("{name} is missing"));
            self.read.borrow_mut().insert(name.to_string());
            value.clone()
        }
        pub(crate) fn has(&self, name: &str) -> bool {
            self.values.contains_key(name)
        }
        pub(crate) fn bytes(&self, name: &str) -> Vec<u8> {
            hex::decode(self.str(name)).unwrap_or_else(|_| panic!("{name} is not hex"))
        }
        pub(crate) fn b32(&self, name: &str) -> [u8; 32] {
            self.bytes(name).try_into().unwrap_or_else(|_| panic!("{name} is not 32 bytes"))
        }
        pub(crate) fn b64(&self, name: &str) -> [u8; 64] {
            self.bytes(name).try_into().unwrap_or_else(|_| panic!("{name} is not 64 bytes"))
        }
        pub(crate) fn uuid16(&self, name: &str) -> [u8; 16] {
            *uuid::Uuid::parse_str(&self.str(name)).unwrap_or_else(|_| panic!("{name} is not a UUID")).as_bytes()
        }
        pub(crate) fn wire(&self, name: &str) -> (WireRecord, [u8; 64]) {
            (WireRecord::parse(&self.bytes(&format!("{name}_record_wire"))).unwrap_or_else(|e| panic!("{name}: {e:?}")), self.b64(&format!("{name}_signature")))
        }
        fn all_read(&self) {
            let read = self.read.borrow();
            let mut unread: Vec<&String> = self.values.keys().filter(|k| !read.contains(*k)).collect();
            unread.sort();
            assert!(unread.is_empty(), "values nobody checked: {unread:?}");
        }
    }

    /// What a file holds: its records in chain order (name, the one before it,
    /// who signed it: the named signer unless it says otherwise), its copies
    /// (name, of, how it differs, the record after the original), its links
    /// and its heads (name, whose, the record at its version).
    struct Plan<'a> {
        records: &'a [(&'a str, Option<&'a str>, Option<&'a str>)],
        copies: &'a [(&'a str, &'a str, &'a str, &'a str)],
        links: &'a [(u32, u32)],
        heads: &'a [(&'a str, &'a str, &'a str)],
        /// A format-1 record after a format-2 one: the file's format going down.
        format_down: Option<&'a str>,
    }

    fn signing_key(f: &File, who: &str) -> SigningKey {
        SigningKey::from_bytes(&f.b32(&format!("{who}_signing_seed")))
    }

    /// Every value of `f`, rebuilt with the SDK's own code.
    fn check(f: &File, plan: &Plan) {
        let circle = f.uuid16("circle_id");
        let _now: i64 = f.str("now").parse().expect("now");
        let anchor: u32 = f.str("anchor").parse().expect("anchor");
        let key = |v: u32| f.b32(&format!("key_v{v}"));
        let secret = circle_secret(&key(anchor)).unwrap();
        assert!(*secret == f.b32("S"), "S from the anchor key");
        let mut members: HashMap<[u8; 32], (String, [u8; 32])> = HashMap::new();
        for who in ["A", "B", "C", "D"] {
            let uid = f.uuid16(&format!("{who}_user_id"));
            let signing = signing_key(f, who).verifying_key().to_bytes();
            assert_eq!(signing, f.b32(&format!("{who}_signing_pk")), "{who}'s signing key");
            let code = member_code(&secret, &uid);
            assert_eq!(code, f.b32(&format!("{who}_code")), "{who}'s code");
            let commitment = key_commitment(&secret, &code, &f.b32(&format!("{who}_sharing_pk")), &signing);
            assert_eq!(commitment, f.b32(&format!("{who}_commitment")), "{who}'s commitment");
            members.insert(code, (who.to_string(), signing));
        }
        let signer_key = |who: &str| signing_key(f, who).verifying_key().to_bytes();
        // The record a format going down links: its chain value is printed.
        let down_links = plan.format_down.and_then(|down| plan.records.iter().find(|(n, ..)| *n == down)).and_then(|(_, before, _)| *before);
        let mut read: HashMap<&str, (WireRecord, [u8; 64])> = HashMap::new();
        let each = |name: &str, signed_by: Option<&str>, key_tag_holds: bool| -> (WireRecord, [u8; 64]) {
            let (wire, signature) = f.wire(name);
            assert_eq!(wire.to_bytes(), f.bytes(&format!("{name}_record_wire")), "{name} as it travels");
            let body = f.bytes(&format!("{name}_body"));
            assert_eq!(wire.body_bytes, body, "{name}'s body");
            assert_eq!(wire.body.encode().unwrap(), body, "{name}'s body, encoded again");
            assert_eq!(wire.body.circle_id, circle, "{name}'s circle");
            let format = RecordFormat::from_code(f.str(&format!("{name}_format")).parse().expect("format")).expect("a format");
            assert_eq!(wire.body.format, format, "{name}'s format");
            assert_eq!(wire.digest, f.b32(&format!("{name}_record_digest")), "{name}'s digest");
            assert_eq!(wire.key_tag, f.b32(&format!("{name}_key_tag")), "{name}'s key tag");
            assert_eq!(wire.key_tag_matches(&key(wire.body.version)), key_tag_holds, "{name}'s key tag under its key");
            let anchor_name = format!("{name}_anchor_tag");
            assert_eq!(wire.anchor_tag, f.has(&anchor_name).then(|| f.b32(&anchor_name)), "{name}'s anchor tag");
            assert_eq!(wire.signed_digest(), f.b32(&format!("{name}_signed_digest")), "{name}'s signed digest");
            let chain_name = format!("{name}_chain");
            if format == RecordFormat::V1 || down_links == Some(name) {
                assert_eq!(wire.chain(), f.b32(&chain_name), "{name}'s chain value");
            } else {
                assert!(!f.has(&chain_name), "only a format-1 record prints its chain value");
            }
            assert_eq!(wire.wire_chain(&signature), f.b32(&format!("{name}_wire_chain")), "{name}'s wire_chain");
            // Who its signature verifies under: whoever signed it, and the
            // member its signer entry names only when that is the same one.
            let (named, _) = &members[&wire.body.signer_code];
            for (who, _) in members.values() {
                let verifies = wire.signature_verifies(&signature, &signer_key(who));
                assert_eq!(verifies, signed_by == Some(who.as_str()), "{name} under {who}'s key (named: {named})");
            }
            (wire, signature)
        };
        for (name, _, signed_by) in plan.records {
            let named = members[&f.wire(name).0.body.signer_code].0.clone();
            let (wire, signature) = each(name, Some(signed_by.unwrap_or(named.as_str())), true);
            read.insert(name, (wire, signature));
        }
        // Each links the one before by its own format; a genesis or a
        // transition none; formats only go up but where the file says.
        for (name, before, _) in plan.records {
            let (wire, _) = &read[name];
            match before {
                None => {
                    assert!(matches!(wire.body.kind, RecordKind::Genesis | RecordKind::Transition), "{name} starts the chain");
                    assert_eq!(wire.body.prev_chain, [0u8; 32], "{name} links nothing");
                }
                Some(before) => {
                    let (prev, prev_signature) = &read[before];
                    assert_eq!(wire.body.prev_version, prev.body.version, "{name} moves off {before}");
                    let linked = match wire.body.format {
                        RecordFormat::V2 => prev.wire_chain(prev_signature),
                        RecordFormat::V1 => prev.chain(),
                    };
                    assert_eq!(wire.body.prev_chain, linked, "{name} links {before} by its format");
                    assert_eq!(wire.body.format < prev.body.format, plan.format_down == Some(*name), "{name}'s format against {before}'s");
                }
            }
        }
        for (name, of, how, successor) in plan.copies {
            let (original, original_signature) = &read[of];
            let signed_by = how.strip_prefix("resigned by ");
            let (copy, signature) = each(name, signed_by, *how != "key tag" );
            assert_eq!(copy.body_bytes, original.body_bytes, "{name} is a copy of {of}'s body");
            match *how {
                "signature" => assert!(copy.key_tag == original.key_tag && signature != *original_signature, "{name}: only its signature differs"),
                "key tag" | "anchor tag" => assert_eq!(signature, *original_signature, "{name}: its signature is {of}'s"),
                _ => assert!(signed_by.is_some() && signature != *original_signature, "{name}: signed again"),
            }
            assert_eq!(copy.chain(), original.chain(), "{name} has {of}'s body chain");
            assert_ne!(copy.wire_chain(&signature), original.wire_chain(original_signature), "{name}'s wire differs");
            let (next, _) = &read[successor];
            assert_eq!(next.body.prev_chain, original.wire_chain(original_signature), "{successor} links {of}");
            assert_ne!(next.body.prev_chain, copy.wire_chain(&signature), "{successor} never links {name}");
        }
        for (from, to) in plan.links {
            let nonce = f.bytes(&format!("link_{from}_{to}_nonce"));
            let sealed = f.bytes(&format!("link_{from}_{to}_encrypted_key"));
            let opened = XChaCha20Poly1305::new_from_slice(&key(*from)).unwrap().decrypt(XNonce::from_slice(&nonce), sealed.as_slice()).unwrap();
            assert!(opened == key(*to), "link {from} → {to} carries key {to}");
        }
        for (name, who, record) in plan.heads {
            let bytes = f.bytes(name);
            let head = Head::decode(&bytes).unwrap();
            let (wire, signature) = &read[record];
            let value = match head.format {
                RecordFormat::V2 => wire.wire_chain(signature),
                RecordFormat::V1 => wire.chain(),
            };
            assert_eq!(
                (head.circle_id, head.user_id, head.version, head.chain),
                (circle, f.uuid16(&format!("{who}_user_id")), wire.body.version, value),
                "{name} names {record} in its own format"
            );
            assert_eq!(head.encode().unwrap().to_vec(), bytes, "{name}, encoded again");
            let array: [u8; 69] = bytes.as_slice().try_into().unwrap();
            let digest = Head::digest(&array);
            assert_eq!(digest, f.b32(&format!("{name}_digest")), "{name}'s digest");
            let head_signature = f.b64(&format!("{name}_signature"));
            let key = VerifyingKey::from_bytes(&signer_key(who)).unwrap();
            assert!(key.verify_strict(&digest, &Signature::from_bytes(&head_signature)).is_ok(), "{name} under {who}'s key");
        }
        f.all_read();
    }

    #[test]
    fn the_switch_links_format_1_history_and_then_whole_wires() {
        let f = File::new(SWITCH);
        let heads = [("head_B_v2_format1", "B", "r2"), ("head_B_v2_format2", "B", "r2"), ("head_A_v4_format2", "A", "r4")];
        let records = [("r1", None, None), ("r2", Some("r1"), None), ("r3", Some("r2"), None), ("r4", Some("r3"), None)];
        check(&f, &Plan { records: &records, copies: &[], links: &[(2, 1), (3, 2), (4, 3)], heads: &heads, format_down: None });
    }

    #[test]
    fn a_format_2_genesis_and_the_copies_of_its_eject_that_must_not_link() {
        let f = File::new(GENESIS);
        let records = [("r1", None, None), ("r2", Some("r1"), None), ("r3", Some("r2"), None), ("r4", Some("r3"), None)];
        let copies = [
            ("r3_copy_flipped_signature", "r3", "signature", "r4"),
            ("r3_copy_flipped_key_tag", "r3", "key tag", "r4"),
            ("r3_copy_resigned_by_C", "r3", "resigned by C", "r4"),
        ];
        check(&f, &Plan { records: &records, copies: &copies, links: &[(2, 1), (3, 2), (4, 3)], heads: &[("head_C_v4_format2", "C", "r4")], format_down: None });
    }

    #[test]
    fn a_format_2_transition_and_the_copies_that_must_not_link() {
        let f = File::new(TRANSITION);
        let records = [("r5", None, None), ("r6", Some("r5"), None)];
        let copies = [("r5_copy_flipped_anchor_tag", "r5", "anchor tag", "r6"), ("r5_copy_flipped_key_tag", "r5", "key tag", "r6")];
        let (r5, _) = f.wire("r5");
        assert!(r5.anchor_tag_matches(&f.b32("key_v4")), "the anchor tag, over the anchor key");
        check(&f, &Plan { records: &records, copies: &copies, links: &[(2, 1), (3, 2), (4, 3), (5, 4), (6, 4)], heads: &[("head_C_v6_format2", "C", "r6")], format_down: None });
    }

    #[test]
    fn a_misattributed_record_is_linked_by_the_record_after_it() {
        let f = File::new(MISATTRIBUTED);
        // r3's signer entry names the owner A; C's key signed it.
        let records = [("r1", None, None), ("r2", Some("r1"), None), ("r3", Some("r2"), Some("C")), ("r4", Some("r3"), None)];
        check(&f, &Plan { records: &records, copies: &[], links: &[(2, 1), (3, 2), (4, 3)], heads: &[("head_A_v4_format2", "A", "r4")], format_down: None });
        let (r3, _) = f.wire("r3");
        let (r4, _) = f.wire("r4");
        assert_eq!((r3.body.entries.iter().filter(|e| e.state == EntryState::Removed).count(), r4.body.kind), (1, RecordKind::Repair));
    }

    #[test]
    fn a_format_1_record_after_a_format_2_one_breaks_only_the_format_rule() {
        let f = File::new(FORMAT_DOWN);
        let records = [("r1", None, None), ("r2", Some("r1"), None), ("r3", Some("r2"), None)];
        check(&f, &Plan { records: &records, copies: &[], links: &[(2, 1), (3, 2)], heads: &[], format_down: Some("r3") });
        let (r2, _) = f.wire("r2");
        let (r3, _) = f.wire("r3");
        let same = |r: &WireRecord| r.body.entries.iter().map(|e| (e.code, e.state, e.role, e.commitment)).collect::<Vec<_>>();
        assert_eq!(same(&r2), same(&r3), "it names everyone r2 names, as r2 names them");
    }
}
