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

//! Classifying server-side location rejections, and the bounded queue that
//! re-sends the ones worth re-sending.
//!
//! # The failure this exists to stop
//!
//! `LocationIngest::SendLocation` answers a *refused* update with a perfectly
//! healthy gRPC response carrying `LocationAck { success: false, error }`.
//! Nothing about the transport failed, so a loop that only logs the `error`,
//! hands it to `StreamErrorCallback::on_location_rejected` and moves on loses
//! the fix. The apps act on that callback only when the string names a device
//! ownership problem, so every other refusal — rate limiting, storage
//! backpressure, a storage insert error, the server's ordering check failing
//! CLOSED while its store is briefly unavailable — would throw the fix away
//! for good, while the device kept saying "Location sharing active" and peers
//! watched a marker that had stopped moving.
//!
//! # Why the classifier defaults to "permanent"
//!
//! Retrying a refusal the server will never accept is worse than dropping it:
//! it is a busy-loop against a settled decision, on a battery. So the mapping
//! below is an allow-list of the strings the ingest service emits for reasons
//! that have nothing to do with the contents of the update, and *everything
//! else* — including any rejection a future server version invents — is
//! permanent: an unrecognised rejection is dropped and reported, which is the
//! safe direction to be wrong in.
//!
//! # Why a retry has a short shelf life
//!
//! The server reads the latest location newest-**inserted** first, not
//! newest-timestamp first. A fix that finally lands ten minutes late therefore
//! becomes the peer's *current* position, moving their marker backwards to a
//! place they have already left. For a product whose first question is "where
//! are they right now", a late fix is not a partial win, it is a wrong answer.
//! Two rules keep that from happening:
//!
//! * a queued fix is abandoned once a NEWER fix from the same
//!   (circle, device) has been accepted — its only remaining value was history
//!   density, and it would cost a backwards jump on the live map to buy it;
//! * a fix older than [`MAX_RETRY_AGE_MS`] is abandoned outright. The number
//!   is the server's own freshness rule: its HTTP path refuses a location
//!   whose timestamp is more than 5 minutes in the past, calling it
//!   "expired".
//!
//! A late HISTORY point (`LocationUpdate.history_only`: a point the device
//! kept while it could not open a circle, sent once it can) is exempt from
//! both. It is stored in history only and is never anyone's latest location,
//! so it cannot move a marker: it is never superseded, never raises the live
//! high-water mark, and keeps its place until [`MAX_HISTORY_AGE_MS`], the
//! window the server accepts such points in.
//!
//! Note what these two rules do NOT cost. While every update is refused for a
//! few minutes, nothing is accepted, so nothing supersedes anything, and the
//! queue flushes in insertion order once the server recovers: chronological
//! order is preserved and the last row inserted is genuinely the newest fix.
//!
//! # Across a process restart
//!
//! The queue lives in the upload task and dies with it: `stop_streaming`, a
//! settled RPC failure that ends the loop (an expired token, say), app death.
//! A TRANSPORT failure does not end it: the fix goes back on this queue
//! behind [`TransportBackoff`] and tonic re-dials on the next send.
//!
//! It is deliberately not persisted. Anything that survives a restart would
//! come back older than [`MAX_RETRY_AGE_MS`] by the time the SDK had a stream
//! again, so a durable queue would only ever hand back fixes the rules above
//! then discard.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// How many refused fixes may be waiting at once. The cap is what keeps a long
/// outage from turning into unbounded memory growth on a phone; when it is
/// reached the OLDEST waiting fix is evicted, because freshness is the whole
/// value here.
pub(crate) const RETRY_QUEUE_CAPACITY: usize = 32;

/// Re-sends allowed per fix, on top of the original attempt. With the backoff
/// below, six covers roughly two minutes of server trouble — long enough for a
/// brief outage of the server's store, short enough to stay inside
/// [`MAX_RETRY_AGE_MS`].
pub(crate) const MAX_RETRY_ATTEMPTS: u32 = 6;

/// First backoff step; each further attempt doubles it.
const RETRY_BASE_DELAY_MS: u64 = 2_000;

/// Ceiling for one backoff step, and for any server-supplied `Retry in {n}s`
/// hint. A hint is a suggestion from a service that is by definition unwell;
/// it does not get to park a fix past its shelf life.
const RETRY_MAX_DELAY_MS: u64 = 60_000;

/// Beyond this age a fix is abandoned rather than sent. See the module docs:
/// the number is the server's own freshness limit, 5 minutes.
pub(crate) const MAX_RETRY_AGE_MS: i64 = 300_000;

/// Shelf life of a late HISTORY point: the server accepts `history_only`
/// points up to 48 h after the fix.
pub(crate) const MAX_HISTORY_AGE_MS: i64 = 48 * 60 * 60 * 1000;

/// Floor on the gap between two re-sends. Without it, a queue that all comes
/// due inside the same jitter window fires a burst straight into the
/// server's per-user message limit (2 per second), which answers with
/// rate-limit rejections that spend the retry budget on nothing.
const RETRY_MIN_SPACING_MS: u64 = 250;

/// Bound on the accepted-high-water map. The key is (circle, device) for the
/// single device this SDK instance streams from, so the real size is "circles
/// this user is in" — far below the cap, which exists only so a pathological
/// caller cannot grow the map without limit.
const MAX_HIGH_WATER_ENTRIES: usize = 32;

/// What the queue needs to know about the thing it is holding, so the queue
/// itself can be tested without building a whole `LocationUpdateMessage`.
pub(crate) trait RetryItem {
    /// `(circle_id, device_id)` — the emitter whose "latest location" this
    /// update competes to be.
    fn emitter(&self) -> (&str, &str);

    /// Wall-clock milliseconds of the fix itself (not of the send attempt).
    fn fix_timestamp_ms(&self) -> i64;

    /// True for a late HISTORY point, which is never anyone's latest location
    /// (see the module docs). A live fix by default.
    fn history_only(&self) -> bool {
        false
    }
}

/// How old a fix may get before it is not worth sending.
fn shelf_life<T: RetryItem>(item: &T) -> i64 {
    if item.history_only() {
        MAX_HISTORY_AGE_MS
    } else {
        MAX_RETRY_AGE_MS
    }
}

/// How a `success: false` ack should be treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RejectionClass {
    /// The server refused for a reason unrelated to the contents of this
    /// update: the identical bytes can succeed later. `server_retry_after` is
    /// the server's own hint when it gave one.
    Retryable { server_retry_after: Option<Duration> },
    /// The server will refuse these bytes however many times they are sent.
    /// Dropping the fix and telling the app is the only correct action.
    Permanent,
}

/// What the upload loop does about one ack. Extracted as a pure function so
/// the "a permanent rejection is never re-queued" property is asserted against
/// the code the loop actually runs, not against a re-statement of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AckAction {
    /// Stored. Record it as the emitter's high-water mark.
    Accepted,
    /// Put it back on the queue.
    Retry { server_retry_after: Option<Duration> },
    /// Give up on this fix and report it to the app.
    Drop,
}

pub(crate) fn action_for_ack(success: bool, error: &str) -> AckAction {
    if success {
        return AckAction::Accepted;
    }
    match classify_rejection(error) {
        RejectionClass::Retryable { server_retry_after } => {
            AckAction::Retry { server_retry_after }
        }
        RejectionClass::Permanent => AckAction::Drop,
    }
}

/// Map an ack's `error` string onto [`RejectionClass`].
///
/// Every arm below is a literal the ingest service emits; the comment on each
/// says what it means. Matching on prose is unlovely, but the ack carries no code —
/// `LocationAck` is `{ device_id, timestamp_ms, success, error, queue_depth_percent }`
/// — and inventing one would be a wire change on both ends. The strings are
/// pinned by tests so a server-side reword fails loudly here instead of
/// quietly reclassifying a whole failure mode.
pub(crate) fn classify_rejection(error: &str) -> RejectionClass {
    let e = error.trim().to_ascii_lowercase();

    // "Rate limited: {reason}. Retry in {n}s".
    // The one rejection that tells us when to come back, so we listen.
    if e.starts_with("rate limited:") {
        return RejectionClass::Retryable {
            server_retry_after: parse_retry_after(&e),
        };
    }

    // The limiter's own Redis is unreachable — nothing to do
    // with this update.
    if e.starts_with("rate limiting service unavailable") {
        return RejectionClass::Retryable { server_retry_after: None };
    }

    // The server's ordering check fails CLOSED when its store errors,
    // refusing everything from every device for the length of the outage.
    // Treated as permanent, a brief outage would become a fleet-wide hole in
    // history.
    if e.starts_with("location service temporarily unavailable") {
        return RejectionClass::Retryable { server_retry_after: None };
    }

    // Storage backpressure. gRPC says "Server overloaded. Please reduce
    // update frequency."; the HTTP fallback appends "and retry in 5
    // seconds.". Prefix match covers both.
    if e.starts_with("server overloaded") {
        return RejectionClass::Retryable { server_retry_after: None };
    }

    // The ClickHouse insert itself errored. Transient.
    if e.starts_with("failed to store location") {
        return RejectionClass::Retryable { server_retry_after: None };
    }

    // Postgres was unreachable during the ownership / membership lookups.
    // NOT the same as being refused by them: those say "Device not found or
    // not owned by user" and "Not a member of this circle", both handled as
    // permanent below.
    if e.starts_with("device validation failed") || e.starts_with("circle validation failed") {
        return RejectionClass::Retryable { server_retry_after: None };
    }

    // Everything else is permanent — see the module docs. Named here purely so
    // the tests can pin them and a reader can see they were considered:
    //
    //   "Device not found or not owned by user"  — re-register
    //   "Not a member of this circle"
    //   "Circle not found"
    //   "Session revoked"                        — needs a new login
    //   "Plaintext coordinates are not accepted"
    //   "Out-of-order location…"
    //   "Missing day_bucket"
    //   "day_bucket too old: {n} days"
    //   "Missing encrypted payload"
    //   "Encryption validation failed: …"
    //   "Invalid device_id/user_id/circle_id format"
    //
    // Two deserve a note. A monotonicity refusal ("Out-of-order location") is
    // permanent even though it reads transient: the per-device high-water mark
    // only ever moves forward, so a fix it has already passed can never be
    // accepted later. And "Session revoked" is permanent to the *queue* — the
    // fix is unsendable until the app logs in again, which is a different
    // recovery on a different clock, not something a backoff can wait out.
    RejectionClass::Permanent
}

/// Pull `n` out of a lowercased "rate limited: …. retry in {n}s".
fn parse_retry_after(lowercased: &str) -> Option<Duration> {
    let tail = lowercased.rsplit_once("retry in ")?.1;
    let secs: u64 = tail
        .trim_end_matches('.')
        .trim_end_matches('s')
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_millis(
        secs.saturating_mul(1_000).min(RETRY_MAX_DELAY_MS),
    ))
}

/// Backoff for the `attempt`-th re-send (1 = the first re-send).
///
/// The jitter is derived from the fix's own timestamp rather than an RNG:
/// deterministic for tests, and still decorrelated across devices — two phones
/// never hold fixes with the same millisecond — which is all the jitter is for.
pub(crate) fn retry_delay(
    attempt: u32,
    server_retry_after: Option<Duration>,
    fix_timestamp_ms: i64,
) -> Duration {
    let step = RETRY_BASE_DELAY_MS
        .saturating_mul(1u64 << attempt.saturating_sub(1).min(6))
        .min(RETRY_MAX_DELAY_MS);
    let jitter = fix_timestamp_ms.unsigned_abs() % (step / 2 + 1);
    let with_jitter = step.saturating_add(jitter).min(RETRY_MAX_DELAY_MS);

    let hinted = server_retry_after
        .map(|d| (d.as_millis() as u64).min(RETRY_MAX_DELAY_MS))
        .unwrap_or(0);

    Duration::from_millis(with_jitter.max(hinted))
}

/// First step of the connection-level backoff; each further failure doubles it.
const TRANSPORT_BACKOFF_BASE_MS: u64 = 1_000;

/// Ceiling for one connection-level backoff step. Same ceiling as a fix's own
/// backoff, for the same reason: past a minute the wait costs more freshness
/// than the retry saves battery.
const TRANSPORT_BACKOFF_MAX_MS: u64 = 60_000;

/// Wait before the next send after `consecutive_failures` failed RPCs in a row
/// (1 = the first failure).
pub(crate) fn transport_backoff_delay(consecutive_failures: u32) -> Duration {
    let step = TRANSPORT_BACKOFF_BASE_MS
        .saturating_mul(1u64 << consecutive_failures.saturating_sub(1).min(6))
        .min(TRANSPORT_BACKOFF_MAX_MS);
    Duration::from_millis(step)
}

/// Holds ALL sends back while the upload connection is failing.
///
/// A fix's own backoff (see [`RetryQueue`]) is per fix. That is the right shape
/// for a server that refuses one update, and the wrong one for a connection
/// that is down: every new fix would still open with an immediate attempt, and
/// on a phone every attempt is a radio wake — an offline phone in a tunnel
/// would dial out on each fix. So a transport failure closes a gate that new
/// fixes queue behind, and only one send probes the connection when it opens.
/// One success opens it again.
#[derive(Debug, Default)]
pub(crate) struct TransportBackoff {
    consecutive_failures: u32,
    blocked_until: Option<Instant>,
    last_error: String,
}

impl TransportBackoff {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// True while sends must wait for the connection to be probed again.
    pub(crate) fn is_blocked(&self, now: Instant) -> bool {
        matches!(self.blocked_until, Some(until) if now < until)
    }

    /// When the gate opens, if it is closed at all.
    pub(crate) fn blocked_until(&self) -> Option<Instant> {
        self.blocked_until
    }

    /// The failure that closed the gate, so a fix that ages out while waiting
    /// behind it is reported with the real cause.
    pub(crate) fn last_error(&self) -> &str {
        &self.last_error
    }

    /// Record a failed RPC; returns how long sends are now held back.
    pub(crate) fn record_failure(&mut self, now: Instant, error: &str) -> Duration {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let delay = transport_backoff_delay(self.consecutive_failures);
        self.blocked_until = Some(now + delay);
        self.last_error = error.to_string();
        delay
    }

    /// Any answer from the server — accepted or refused — proves the
    /// connection works.
    pub(crate) fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.blocked_until = None;
        self.last_error.clear();
    }
}

/// When the upload loop should next wake to retry: the earliest queued fix,
/// but never before the connection gate opens. `None` when nothing is queued —
/// the gate alone is no reason to wake, because there is nothing to send.
pub(crate) fn retry_wakeup(next_due: Option<Instant>, gate: Option<Instant>) -> Option<Instant> {
    let due = next_due?;
    Some(match gate {
        Some(open_at) if open_at > due => open_at,
        _ => due,
    })
}

/// Why a fix left the queue without ever being stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropReason {
    /// Spent its [`MAX_RETRY_ATTEMPTS`] budget.
    AttemptsExhausted,
    /// Older than [`MAX_RETRY_AGE_MS`] (a history point: [`MAX_HISTORY_AGE_MS`]);
    /// sending it now would misreport where the person is, or the server would
    /// refuse it.
    TooStale,
    /// A newer fix from the same (circle, device) has already been accepted.
    Superseded,
    /// Evicted to keep the queue inside [`RETRY_QUEUE_CAPACITY`].
    QueueFull,
    /// The upload task ended (stop_streaming, a settled RPC failure, app
    /// death) while this fix was still waiting — or was still in flight, or
    /// still buffered in the channel. The queue does not outlive the task.
    StreamEnded,
}

impl DropReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DropReason::AttemptsExhausted => "attempts exhausted",
            DropReason::TooStale => "too stale to send",
            DropReason::Superseded => "superseded by a newer fix",
            DropReason::QueueFull => "evicted, retry queue full",
            DropReason::StreamEnded => "upload stream ended before it could be re-sent",
        }
    }
}

/// A fix that will never be sent, and everything needed to report it.
#[derive(Debug, PartialEq)]
pub(crate) struct Abandoned<T> {
    pub(crate) item: T,
    pub(crate) reason: DropReason,
    /// The last rejection the server gave for this fix. Reported to the app
    /// verbatim, so a terminal drop names the real server-side cause instead
    /// of the client-side bookkeeping that finally ended it.
    pub(crate) last_error: String,
}

/// Result of offering a rejected fix back to the queue.
#[derive(Debug)]
pub(crate) struct RequeueOutcome<T> {
    /// `Some(delay)` when the fix went back on the queue.
    pub(crate) queued: Option<Duration>,
    /// Fixes this call gave up on for good — the offered one when it was not
    /// worth queueing, plus anything evicted to make room for it.
    pub(crate) abandoned: Vec<Abandoned<T>>,
}

struct Entry<T> {
    item: T,
    /// Sends already made for this fix, original included.
    attempts: u32,
    next_attempt_at: Instant,
    /// The most recent rejection string, so a terminal drop can tell the app
    /// what actually went wrong rather than inventing a reason.
    last_error: String,
}

/// A bounded, self-pruning hold of fixes the server refused for transient
/// reasons.
///
/// Time is passed in rather than read: `Instant` for the backoff (monotonic,
/// immune to a clock step) and wall-clock milliseconds for the staleness rule
/// (it is compared against the fix's own timestamp, which is wall-clock). The
/// split is deliberate, and the parameters make every rule here testable
/// without sleeping.
pub(crate) struct RetryQueue<T> {
    entries: VecDeque<Entry<T>>,
    /// Newest accepted fix timestamp per (circle, device).
    accepted_high_water: HashMap<(String, String), i64>,
    last_send_at: Option<Instant>,
    capacity: usize,
    max_attempts: u32,
}

impl<T: RetryItem> RetryQueue<T> {
    pub(crate) fn new() -> Self {
        Self::with_limits(RETRY_QUEUE_CAPACITY, MAX_RETRY_ATTEMPTS)
    }

    pub(crate) fn with_limits(capacity: usize, max_attempts: u32) -> Self {
        Self {
            entries: VecDeque::new(),
            accepted_high_water: HashMap::new(),
            last_send_at: None,
            capacity: capacity.max(1),
            max_attempts,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a stored fix as its emitter's high-water mark, which is what
    /// lets [`Self::purge`] abandon the queued fixes it superseded.
    pub(crate) fn note_accepted(&mut self, item: &T) {
        // A late history point is nobody's latest location: it must not make
        // the live fixes still waiting look superseded.
        if item.history_only() {
            return;
        }
        let (circle, device) = item.emitter();
        let key = (circle.to_string(), device.to_string());
        let ts = item.fix_timestamp_ms();
        match self.accepted_high_water.get_mut(&key) {
            Some(existing) => {
                if ts > *existing {
                    *existing = ts;
                }
            }
            None => {
                if self.accepted_high_water.len() >= MAX_HIGH_WATER_ENTRIES {
                    if let Some(victim) = self.accepted_high_water.keys().next().cloned() {
                        self.accepted_high_water.remove(&victim);
                    }
                }
                self.accepted_high_water.insert(key, ts);
            }
        }
    }

    /// Offer a rejected fix back to the queue. `attempts_so_far` is the number
    /// of sends already made for it (1 after its first rejection); `error` is
    /// the rejection that sent it here, kept so a later terminal drop can name
    /// the server-side cause.
    pub(crate) fn requeue(
        &mut self,
        item: T,
        attempts_so_far: u32,
        server_retry_after: Option<Duration>,
        error: &str,
        now: Instant,
        now_ms: i64,
    ) -> RequeueOutcome<T> {
        let mut abandoned = Vec::new();

        if attempts_so_far > self.max_attempts {
            abandoned.push(Abandoned {
                item,
                reason: DropReason::AttemptsExhausted,
                last_error: error.to_string(),
            });
            return RequeueOutcome { queued: None, abandoned };
        }
        if let Some(reason) = self.expiry_reason(&item, now_ms) {
            abandoned.push(Abandoned { item, reason, last_error: error.to_string() });
            return RequeueOutcome { queued: None, abandoned };
        }

        let delay = retry_delay(attempts_so_far, server_retry_after, item.fix_timestamp_ms());

        // Look ahead before committing to the wait. A fix parked past its own
        // expiry can only ever come back to be dropped as stale, so scheduling
        // it spends an attempt — and a queue slot another fix could use — on a
        // send that cannot happen. This is also what keeps the attempt budget
        // honest: six attempts each parked for the maximum backoff would
        // otherwise stretch past the shelf life, making the tail of the budget
        // unreachable in exactly the case (a server begging for a long
        // `Retry in {n}s`) where it was supposed to help.
        let age_at_next_attempt = now_ms
            .saturating_sub(item.fix_timestamp_ms())
            .saturating_add(delay.as_millis() as i64);
        if age_at_next_attempt > shelf_life(&item) {
            abandoned.push(Abandoned {
                item,
                reason: DropReason::TooStale,
                last_error: error.to_string(),
            });
            return RequeueOutcome { queued: None, abandoned };
        }

        while self.entries.len() >= self.capacity {
            // Oldest first: the queue's whole purpose is to land fixes while
            // they still describe where someone is.
            match self.entries.pop_front() {
                Some(evicted) => abandoned.push(Abandoned {
                    item: evicted.item,
                    reason: DropReason::QueueFull,
                    last_error: evicted.last_error,
                }),
                None => break,
            }
        }

        self.entries.push_back(Entry {
            item,
            attempts: attempts_so_far,
            next_attempt_at: now + delay,
            last_error: error.to_string(),
        });

        RequeueOutcome { queued: Some(delay), abandoned }
    }

    /// Hold a fix while the upload CONNECTION is failing — as opposed to
    /// [`Self::requeue`], which is for a fix the server answered and refused.
    ///
    /// There is no per-fix backoff here: the fix is due at once, and
    /// [`TransportBackoff`] paces every send while the connection is down. A
    /// per-fix timer on top would only reorder the queue — a failed probe
    /// would come back later than fixes taken after it — and a backlog that
    /// flushes out of order loses its older fixes to the high-water rule.
    ///
    /// `ahead` puts the fix at the FRONT: use it for the fix that was in
    /// flight when the connection failed, which is older than anything that
    /// queued behind it. New fixes that arrive while the connection is down go
    /// to the back (`ahead = false`) with `attempts_so_far = 0`, since waiting
    /// is not an attempt.
    ///
    /// The shelf life and the attempt budget apply exactly as they do to a
    /// refused fix, so an outage cannot hold a fix past the point where
    /// sending it would misreport where the person is.
    pub(crate) fn hold_for_connection(
        &mut self,
        item: T,
        attempts_so_far: u32,
        error: &str,
        now: Instant,
        now_ms: i64,
        ahead: bool,
    ) -> RequeueOutcome<T> {
        let mut abandoned = Vec::new();

        if attempts_so_far > self.max_attempts {
            abandoned.push(Abandoned {
                item,
                reason: DropReason::AttemptsExhausted,
                last_error: error.to_string(),
            });
            return RequeueOutcome { queued: None, abandoned };
        }
        if let Some(reason) = self.expiry_reason(&item, now_ms) {
            abandoned.push(Abandoned { item, reason, last_error: error.to_string() });
            return RequeueOutcome { queued: None, abandoned };
        }

        while self.entries.len() >= self.capacity {
            match self.entries.pop_front() {
                Some(evicted) => abandoned.push(Abandoned {
                    item: evicted.item,
                    reason: DropReason::QueueFull,
                    last_error: evicted.last_error,
                }),
                None => break,
            }
        }

        let entry = Entry {
            item,
            attempts: attempts_so_far,
            next_attempt_at: now,
            last_error: error.to_string(),
        };
        if ahead {
            self.entries.push_front(entry);
        } else {
            self.entries.push_back(entry);
        }

        RequeueOutcome { queued: Some(Duration::ZERO), abandoned }
    }

    /// Drop everything that can no longer usefully be sent. Called on every
    /// wake-up of the upload loop, so a fix that goes stale while waiting is
    /// reported promptly rather than at whatever moment its backoff expires.
    pub(crate) fn purge(&mut self, now_ms: i64) -> Vec<Abandoned<T>> {
        let mut abandoned = Vec::new();
        let mut kept = VecDeque::with_capacity(self.entries.len());
        while let Some(entry) = self.entries.pop_front() {
            match self.expiry_reason(&entry.item, now_ms) {
                Some(reason) => abandoned.push(Abandoned {
                    item: entry.item,
                    reason,
                    last_error: entry.last_error,
                }),
                None => kept.push_back(entry),
            }
        }
        self.entries = kept;
        abandoned
    }

    /// The next fix whose backoff has expired, with the attempt count it has
    /// already used. Insertion order, so a queue that built up during an
    /// outage flushes oldest-first and the newest fix is the last one stored.
    pub(crate) fn take_due(&mut self, now: Instant) -> Option<(T, u32)> {
        if let Some(last) = self.last_send_at {
            if now < last + Duration::from_millis(RETRY_MIN_SPACING_MS) {
                return None;
            }
        }
        let idx = self
            .entries
            .iter()
            .position(|e| e.next_attempt_at <= now)?;
        let entry = self.entries.remove(idx)?;
        self.last_send_at = Some(now);
        Some((entry.item, entry.attempts))
    }

    /// When the loop should next wake for a retry, honouring the spacing floor.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        let earliest = self.entries.iter().map(|e| e.next_attempt_at).min()?;
        Some(match self.last_send_at {
            Some(last) => earliest.max(last + Duration::from_millis(RETRY_MIN_SPACING_MS)),
            None => earliest,
        })
    }

    /// Everything still waiting, abandoned. For the shutdown path, which has
    /// no further chance to send.
    pub(crate) fn drain_all(&mut self) -> Vec<Abandoned<T>> {
        self.entries
            .drain(..)
            .map(|e| Abandoned {
                item: e.item,
                reason: DropReason::StreamEnded,
                last_error: e.last_error,
            })
            .collect()
    }

    fn expiry_reason(&self, item: &T, now_ms: i64) -> Option<DropReason> {
        let ts = item.fix_timestamp_ms();
        if now_ms.saturating_sub(ts) > shelf_life(item) {
            return Some(DropReason::TooStale);
        }
        // A newer accepted fix takes nothing from a history point, which is
        // not competing to be the latest location.
        if item.history_only() {
            return None;
        }
        let (circle, device) = item.emitter();
        // Borrowing a (&str, &str) key out of a HashMap<(String, String), _>
        // needs an owned probe; the map is circle-sized, so this is noise.
        let key = (circle.to_string(), device.to_string());
        if let Some(&accepted) = self.accepted_high_water.get(&key) {
            if accepted > ts {
                return Some(DropReason::Superseded);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for `LocationUpdateMessage`, which is private to `location`.
    #[derive(Debug, Clone, PartialEq)]
    struct Fix {
        circle: String,
        device: String,
        ts: i64,
        history: bool,
    }

    impl Fix {
        fn at(ts: i64) -> Self {
            Fix { circle: "c1".into(), device: "d1".into(), ts, history: false }
        }
        fn in_circle(circle: &str, ts: i64) -> Self {
            Fix { circle: circle.into(), device: "d1".into(), ts, history: false }
        }
        /// A late history point (`history_only`) from the same emitter.
        fn history_at(ts: i64) -> Self {
            Fix { history: true, ..Fix::at(ts) }
        }
    }

    impl RetryItem for Fix {
        fn emitter(&self) -> (&str, &str) {
            (&self.circle, &self.device)
        }
        fn fix_timestamp_ms(&self) -> i64 {
            self.ts
        }
        fn history_only(&self) -> bool {
            self.history
        }
    }

    const NOW_MS: i64 = 1_755_000_000_000;
    /// A representative transient rejection, so the tests carry a real
    /// server string through the queue rather than an empty placeholder.
    const ERR: &str = "Location service temporarily unavailable";

    fn retryable(error: &str) -> bool {
        matches!(classify_rejection(error), RejectionClass::Retryable { .. })
    }

    // ===================== classification =====================

    /// Every string below is a literal the ingest service emits for a
    /// condition that has nothing to do with the update's contents: the
    /// fixes that must not be lost for good.
    #[test]
    fn transient_server_conditions_are_retryable() {
        for error in [
            "Rate limited: Per-user rate limit exceeded. Retry in 30s",
            "Rate limited: Per-stream rate limit exceeded. Retry in 5s",
            "Rate limited: Too fast. Retry in 1s",
            "Rate limiting service unavailable",
            "Location service temporarily unavailable",
            "Server overloaded. Please reduce update frequency.",
            "Server overloaded. Please reduce update frequency and retry in 5 seconds.",
            "Failed to store location",
            "Device validation failed",
            "Circle validation failed",
        ] {
            assert!(retryable(error), "should be retryable: {error:?}");
        }
    }

    /// The negative control. A classifier that answered "retry" to everything
    /// — the failure mode worth guarding, because it turns a settled refusal
    /// into a battery-burning loop — fails right here.
    #[test]
    fn settled_refusals_are_permanent() {
        for error in [
            // Handled by the apps' re-registration path, not by a retry.
            "Device not found or not owned by user",
            // The user is out of the circle. Sending again cannot re-admit them.
            "Not a member of this circle",
            "Circle not found",
            // Needs a new login, on a clock no backoff can wait out.
            "Session revoked",
            // A client defect or a hostile client. Never retry a refused payload.
            "Plaintext coordinates are not accepted",
            "Missing encrypted payload",
            "Missing day_bucket",
            "Encryption validation failed: nonce must be 24 bytes",
            "Encryption validation failed: ciphertext too small",
            "Invalid device_id format",
            "Invalid user_id format",
            "Invalid circle_id format",
            // The high-water mark only moves forward; this can never pass.
            "Out-of-order location: timestamp 100ms older than last seen 200ms",
            "Out-of-order location update: timestamp 100ms is not newer than last seen 200ms",
            // Outside the server's ±2 day window, and only more so later.
            "day_bucket too old: 4 days",
        ] {
            assert_eq!(
                classify_rejection(error),
                RejectionClass::Permanent,
                "must not be retried: {error:?}"
            );
        }
    }

    /// A rejection this SDK version has never seen is dropped and reported,
    /// not looped on.
    #[test]
    fn an_unrecognised_rejection_is_permanent() {
        for error in [
            "Quota exceeded for this subscription tier",
            "",
            "   ",
            "unavailable",
            "temporarily unavailable",
        ] {
            assert_eq!(
                classify_rejection(error),
                RejectionClass::Permanent,
                "unknown rejections must default to permanent: {error:?}"
            );
        }
    }

    /// "Device validation failed" (the server's database unreachable) and
    /// "Device not found or not owned by user" (the database answered: no) are
    /// one character apart in meaning and opposite in treatment. Pinned so a
    /// careless prefix change cannot merge them.
    #[test]
    fn a_database_outage_is_not_the_same_as_a_refusal() {
        assert!(retryable("Device validation failed"));
        assert_eq!(
            classify_rejection("Device not found or not owned by user"),
            RejectionClass::Permanent
        );
        assert!(retryable("Circle validation failed"));
        assert_eq!(
            classify_rejection("Not a member of this circle"),
            RejectionClass::Permanent
        );
    }

    #[test]
    fn classification_ignores_case_and_surrounding_space() {
        assert!(retryable("  SERVER OVERLOADED. Please reduce update frequency.  "));
        assert_eq!(
            classify_rejection("  SESSION REVOKED  "),
            RejectionClass::Permanent
        );
    }

    #[test]
    fn the_rate_limit_hint_is_read_and_capped() {
        assert_eq!(
            classify_rejection("Rate limited: Too fast. Retry in 5s"),
            RejectionClass::Retryable {
                server_retry_after: Some(Duration::from_secs(5))
            }
        );
        // A hint longer than the ceiling is clamped, not obeyed.
        assert_eq!(
            classify_rejection("Rate limited: Per-user rate limit exceeded. Retry in 9000s"),
            RejectionClass::Retryable {
                server_retry_after: Some(Duration::from_millis(RETRY_MAX_DELAY_MS))
            }
        );
        // A malformed hint downgrades to "no hint", it does not misclassify.
        assert_eq!(
            classify_rejection("Rate limited: Too fast."),
            RejectionClass::Retryable { server_retry_after: None }
        );
    }

    // ===================== the loop's decision =====================

    #[test]
    fn action_for_ack_never_retries_a_permanent_rejection() {
        assert_eq!(action_for_ack(true, ""), AckAction::Accepted);
        // Even a success carrying a stale error string is an acceptance.
        assert_eq!(action_for_ack(true, "Rate limited: x. Retry in 1s"), AckAction::Accepted);
        assert_eq!(
            action_for_ack(false, "Device not found or not owned by user"),
            AckAction::Drop
        );
        assert_eq!(action_for_ack(false, "Session revoked"), AckAction::Drop);
        assert_eq!(
            action_for_ack(false, "Server overloaded. Please reduce update frequency."),
            AckAction::Retry { server_retry_after: None }
        );
    }

    // ===================== boundedness =====================

    /// The retry budget must actually run out. Without this the queue is an
    /// infinite loop with extra steps.
    #[test]
    fn retries_stop_after_the_attempt_budget() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 3);
        let fix = Fix::at(NOW_MS);

        // Each take_due must be at a distinct instant: re-sends are spaced,
        // so two in the same instant is exactly what the spacing forbids.
        let mut at = now + Duration::from_secs(600);
        for attempt in 1..=3 {
            let out = q.requeue(fix.clone(), attempt, None, ERR, now, NOW_MS);
            assert!(out.queued.is_some(), "attempt {attempt} should be queued");
            assert!(out.abandoned.is_empty());
            q.take_due(at).expect("due");
            at += Duration::from_millis(RETRY_MIN_SPACING_MS);
        }

        let out = q.requeue(fix.clone(), 4, None, ERR, now, NOW_MS);
        assert!(out.queued.is_none(), "the budget must run out");
        assert_eq!(out.abandoned.len(), 1);
        assert_eq!(out.abandoned[0].reason, DropReason::AttemptsExhausted);
        assert_eq!(out.abandoned[0].item, fix);
        assert_eq!(out.abandoned[0].last_error, ERR);
        assert!(q.is_empty());
    }

    /// Memory on a phone during a long outage. Far more rejections than the
    /// cap must leave the queue at the cap, with every displaced fix reported
    /// rather than silently vanished.
    #[test]
    fn the_queue_never_grows_past_its_capacity() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(4, 6);
        let mut evicted = 0usize;

        for i in 0..200i64 {
            let out = q.requeue(Fix::at(NOW_MS + i), 1, None, ERR, now, NOW_MS + i);
            assert!(out.queued.is_some());
            evicted += out
                .abandoned
                .iter()
                .filter(|a| a.reason == DropReason::QueueFull)
                .count();
            assert!(q.len() <= 4, "queue grew to {} past its cap", q.len());
        }

        assert_eq!(q.len(), 4);
        assert_eq!(evicted, 196, "every displaced fix must be reported");
    }

    /// Eviction takes the OLDEST, so what survives an overrun is what still
    /// describes where the person is.
    #[test]
    fn a_full_queue_evicts_the_oldest_fix() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(2, 6);
        q.requeue(Fix::at(NOW_MS), 1, None, ERR, now, NOW_MS);
        q.requeue(Fix::at(NOW_MS + 1), 1, None, ERR, now, NOW_MS);

        let out = q.requeue(Fix::at(NOW_MS + 2), 1, None, ERR, now, NOW_MS);
        assert_eq!(out.abandoned.len(), 1);
        assert_eq!(
            out.abandoned[0].item.ts, NOW_MS,
            "the oldest must be the one evicted"
        );
        assert_eq!(out.abandoned[0].reason, DropReason::QueueFull);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        // Timestamp 0 => zero jitter, so the steps are exact.
        let d = |attempt| retry_delay(attempt, None, 0).as_millis() as u64;
        assert_eq!(d(1), 2_000);
        assert_eq!(d(2), 4_000);
        assert_eq!(d(3), 8_000);
        assert_eq!(d(4), 16_000);
        assert_eq!(d(5), 32_000);
        assert_eq!(d(6), RETRY_MAX_DELAY_MS);
        assert_eq!(d(99), RETRY_MAX_DELAY_MS, "no overflow, no runaway");
    }

    #[test]
    fn jitter_stays_inside_the_ceiling() {
        for ts in [0i64, 1, NOW_MS, i64::MAX, i64::MIN] {
            for attempt in 1..=8 {
                let d = retry_delay(attempt, None, ts).as_millis() as u64;
                assert!(
                    d >= RETRY_BASE_DELAY_MS && d <= RETRY_MAX_DELAY_MS,
                    "attempt {attempt} ts {ts} produced {d}ms"
                );
            }
        }
    }

    #[test]
    fn a_server_hint_raises_the_floor_but_cannot_exceed_the_ceiling() {
        let hinted = retry_delay(1, Some(Duration::from_secs(30)), 0);
        assert_eq!(hinted, Duration::from_secs(30), "the server knows better than step 1");
        let ignored = retry_delay(6, Some(Duration::from_secs(1)), 0);
        assert_eq!(
            ignored,
            Duration::from_millis(RETRY_MAX_DELAY_MS),
            "a shorter hint must not shorten a long backoff"
        );
        let clamped = retry_delay(1, Some(Duration::from_secs(3_600)), 0);
        assert_eq!(clamped, Duration::from_millis(RETRY_MAX_DELAY_MS));
    }

    /// A retry is never parked past the moment the fix expires. Without this,
    /// a server asking for a long `Retry in {n}s` could schedule a send whose
    /// only possible outcome is a stale drop — spending an attempt and a queue
    /// slot on nothing.
    #[test]
    fn a_retry_is_never_scheduled_past_the_shelf_life() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);

        // Ten seconds of life left, and a server hint asking for a minute.
        let nearly_expired = Fix::at(NOW_MS - MAX_RETRY_AGE_MS + 10_000);
        let out = q.requeue(
            nearly_expired,
            1,
            Some(Duration::from_secs(60)),
            ERR,
            now,
            NOW_MS,
        );
        assert!(out.queued.is_none(), "parked past its own expiry");
        assert_eq!(out.abandoned.len(), 1);
        assert_eq!(out.abandoned[0].reason, DropReason::TooStale);
        assert!(q.is_empty());
    }

    /// The same property across the whole attempt budget and every hint: if a
    /// fix is queued at all, it is still inside its shelf life when its own
    /// re-send comes due.
    #[test]
    fn anything_queued_is_still_fresh_when_its_re_send_falls_due() {
        let now = Instant::now();
        for age_ms in [0i64, 1_000, 60_000, 200_000, 290_000, 299_999] {
            for attempt in 1..=MAX_RETRY_ATTEMPTS {
                for hint in [None, Some(Duration::from_secs(1)), Some(Duration::from_secs(9_999))] {
                    let mut q: RetryQueue<Fix> = RetryQueue::with_limits(4, MAX_RETRY_ATTEMPTS);
                    let fix = Fix::at(NOW_MS - age_ms);
                    let out = q.requeue(fix, attempt, hint, ERR, now, NOW_MS);
                    if let Some(delay) = out.queued {
                        assert!(
                            age_ms + delay.as_millis() as i64 <= MAX_RETRY_AGE_MS,
                            "age {age_ms}ms + delay {delay:?} at attempt {attempt} outlives the shelf life"
                        );
                    }
                }
            }
        }
    }

    // ===================== shelf life =====================

    #[test]
    fn a_fix_older_than_the_age_bound_is_never_queued() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        let stale = Fix::at(NOW_MS - MAX_RETRY_AGE_MS - 1);

        let out = q.requeue(stale.clone(), 1, None, ERR, now, NOW_MS);
        assert!(out.queued.is_none());
        assert_eq!(out.abandoned.len(), 1);
        assert_eq!(out.abandoned[0].reason, DropReason::TooStale);
        assert_eq!(out.abandoned[0].item, stale);
        assert!(q.is_empty());
    }

    #[test]
    fn a_fix_that_goes_stale_while_waiting_is_purged() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        let fix = Fix::at(NOW_MS);
        assert!(q.requeue(fix.clone(), 1, None, ERR, now, NOW_MS).queued.is_some());

        assert!(q.purge(NOW_MS + MAX_RETRY_AGE_MS).is_empty(), "still inside the window");
        let dropped = q.purge(NOW_MS + MAX_RETRY_AGE_MS + 1);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, DropReason::TooStale);
        assert_eq!(dropped[0].item, fix);
        assert_eq!(dropped[0].last_error, ERR, "the drop must name the server-side cause");
        assert!(q.is_empty());
    }

    /// The rule that stops a late fix moving a peer's marker backwards.
    #[test]
    fn a_superseded_fix_is_abandoned_rather_than_sent_late() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        let old = Fix::at(NOW_MS);
        assert!(q.requeue(old.clone(), 1, None, ERR, now, NOW_MS).queued.is_some());

        q.note_accepted(&Fix::at(NOW_MS + 5_000));

        let dropped = q.purge(NOW_MS + 5_000);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, DropReason::Superseded);
        assert_eq!(dropped[0].item, old);
        assert!(q.is_empty(), "the live map must not be walked backwards");
    }

    /// An OLDER acceptance must not supersede a newer queued fix — the
    /// high-water mark only moves forward.
    #[test]
    fn an_older_acceptance_does_not_supersede_a_newer_queued_fix() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        q.requeue(Fix::at(NOW_MS + 10_000), 1, None, ERR, now, NOW_MS);

        q.note_accepted(&Fix::at(NOW_MS + 20_000));
        q.note_accepted(&Fix::at(NOW_MS)); // late ack for an older fix

        let dropped = q.purge(NOW_MS + 20_000);
        assert_eq!(dropped.len(), 1, "the NEWER acceptance still supersedes it");
        assert_eq!(dropped[0].reason, DropReason::Superseded);
    }

    /// Supersession is per emitter: another circle's acceptance says nothing
    /// about this circle's queued fix.
    #[test]
    fn supersession_does_not_cross_circles() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        let queued = Fix::in_circle("c1", NOW_MS);
        q.requeue(queued, 1, None, ERR, now, NOW_MS);

        q.note_accepted(&Fix::in_circle("c2", NOW_MS + 60_000));

        assert!(q.purge(NOW_MS).is_empty());
        assert_eq!(q.len(), 1);
    }

    /// The outage case the whole module is for: nothing is accepted, so
    /// nothing supersedes anything, and the backlog flushes oldest-first —
    /// which is what makes the last row inserted the newest fix.
    #[test]
    fn an_outage_backlog_flushes_in_chronological_order() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        for i in 0..5i64 {
            q.requeue(Fix::at(NOW_MS + i * 1_000), 1, None, ERR, now, NOW_MS);
        }
        assert!(q.purge(NOW_MS).is_empty(), "an outage supersedes nothing");

        let later = now + Duration::from_secs(600);
        let mut order = Vec::new();
        let mut at = later;
        while let Some((fix, _)) = q.take_due(at) {
            order.push(fix.ts);
            at += Duration::from_millis(RETRY_MIN_SPACING_MS);
        }
        assert_eq!(
            order,
            vec![NOW_MS, NOW_MS + 1_000, NOW_MS + 2_000, NOW_MS + 3_000, NOW_MS + 4_000]
        );
    }

    // ===================== scheduling =====================

    #[test]
    fn a_fix_is_not_taken_before_its_backoff_expires() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        // now_ms matches the fix, so nothing here is about staleness; a
        // timestamp of 0 also means zero jitter, making the delay exact.
        let delay = q
            .requeue(Fix::at(0), 1, None, ERR, now, 0)
            .queued
            .expect("queued");

        assert!(q.take_due(now).is_none(), "taken before its time");
        assert!(q.take_due(now + delay - Duration::from_millis(1)).is_none());
        assert!(q.take_due(now + delay).is_some());
    }

    #[test]
    fn re_sends_are_spaced_so_a_flush_cannot_become_a_burst() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        q.requeue(Fix::at(0), 1, None, ERR, now, 0);
        q.requeue(Fix::at(1), 1, None, ERR, now, 0);

        let due = now + Duration::from_secs(600);
        assert!(q.take_due(due).is_some());
        assert!(q.take_due(due).is_none(), "two re-sends in the same instant");
        assert!(
            q.take_due(due + Duration::from_millis(RETRY_MIN_SPACING_MS))
                .is_some()
        );
    }

    #[test]
    fn next_due_is_none_when_nothing_is_waiting() {
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        assert!(q.next_due().is_none());
        q.requeue(Fix::at(0), 1, None, ERR, Instant::now(), 0);
        assert!(q.next_due().is_some());
    }

    #[test]
    fn the_high_water_map_is_bounded() {
        let mut q: RetryQueue<Fix> = RetryQueue::new();
        for i in 0..(MAX_HIGH_WATER_ENTRIES * 4) {
            q.note_accepted(&Fix::in_circle(&format!("c{i}"), NOW_MS + i as i64));
        }
        assert!(q.accepted_high_water.len() <= MAX_HIGH_WATER_ENTRIES);
    }

    /// The queue does not outlive the upload task, and says so: every fix
    /// still waiting comes back with a reason the app can be told about.
    #[test]
    fn drain_all_hands_back_everything_still_waiting() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        q.requeue(Fix::at(NOW_MS), 1, None, ERR, now, NOW_MS);
        q.requeue(Fix::at(NOW_MS + 1), 1, None, ERR, now, NOW_MS);

        let abandoned = q.drain_all();
        assert_eq!(abandoned.len(), 2);
        assert!(abandoned.iter().all(|a| a.reason == DropReason::StreamEnded));
        assert!(q.is_empty());
    }

    /// End to end over the ack decision: a mixed stream of rejections must
    /// leave only the transient ones waiting.
    #[test]
    fn only_transient_rejections_reach_the_queue() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(16, 6);
        let acks = [
            (false, "Location service temporarily unavailable"),
            (false, "Device not found or not owned by user"),
            (false, "Rate limited: Too fast. Retry in 1s"),
            (false, "Not a member of this circle"),
            (false, "Server overloaded. Please reduce update frequency."),
            (false, "Plaintext coordinates are not accepted"),
            (false, "Out-of-order location: timestamp 1ms older than last seen 2ms"),
        ];

        let mut dropped = 0;
        for (i, (success, error)) in acks.iter().enumerate() {
            match action_for_ack(*success, error) {
                AckAction::Retry { server_retry_after } => {
                    q.requeue(
                        Fix::at(NOW_MS + i as i64),
                        1,
                        server_retry_after,
                        error,
                        now,
                        NOW_MS,
                    );
                }
                AckAction::Drop => dropped += 1,
                AckAction::Accepted => unreachable!("no successes in this table"),
            }
        }

        assert_eq!(q.len(), 3, "exactly the transient ones");
        assert_eq!(dropped, 4);
    }

    // ---- connection-level backoff ----

    #[test]
    fn transport_backoff_doubles_from_one_second_and_stops_at_a_minute() {
        let steps: Vec<u64> = (1..=9).map(|n| transport_backoff_delay(n).as_millis() as u64).collect();
        assert_eq!(
            steps,
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000]
        );
        // Zero failures never happens in the loop, but must not underflow.
        assert_eq!(transport_backoff_delay(0), Duration::from_millis(1_000));
    }

    #[test]
    fn a_failure_closes_the_gate_and_a_success_opens_it() {
        let now = Instant::now();
        let mut gate = TransportBackoff::new();
        assert!(!gate.is_blocked(now), "a fresh connection is not held back");
        assert_eq!(gate.blocked_until(), None);

        let d1 = gate.record_failure(now, "Unavailable: error trying to connect");
        assert_eq!(d1, Duration::from_secs(1));
        assert!(gate.is_blocked(now));
        assert!(gate.is_blocked(now + Duration::from_millis(999)));
        assert!(!gate.is_blocked(now + Duration::from_millis(1_000)), "open again at the deadline");
        assert_eq!(gate.last_error(), "Unavailable: error trying to connect");

        // Consecutive failures stretch the hold.
        let d2 = gate.record_failure(now, "Cancelled: Timeout expired");
        assert_eq!(d2, Duration::from_secs(2));
        assert_eq!(gate.last_error(), "Cancelled: Timeout expired");

        gate.record_success();
        assert!(!gate.is_blocked(now), "one answer from the server reopens the gate");
        assert_eq!(gate.blocked_until(), None);
        assert_eq!(gate.last_error(), "");
        // And the count starts over.
        assert_eq!(gate.record_failure(now, "x"), Duration::from_secs(1));
    }

    #[test]
    fn the_retry_wakeup_waits_for_the_gate_but_never_invents_work() {
        let now = Instant::now();
        let soon = now + Duration::from_secs(2);
        let later = now + Duration::from_secs(8);

        assert_eq!(retry_wakeup(None, None), None);
        assert_eq!(
            retry_wakeup(None, Some(later)),
            None,
            "a closed gate with nothing queued is no reason to wake"
        );
        assert_eq!(retry_wakeup(Some(soon), None), Some(soon));
        assert_eq!(retry_wakeup(Some(soon), Some(later)), Some(later), "held until the gate opens");
        assert_eq!(retry_wakeup(Some(later), Some(soon)), Some(later), "an open gate does not rush a fix");
    }

    /// A fix parked behind the gate has never been sent: it must enter the
    /// queue with its full attempt budget, not with one already spent, and be
    /// due at once — the gate, not a per-fix timer, decides when it goes.
    #[test]
    fn a_parked_fix_keeps_its_whole_attempt_budget_and_is_due_at_once() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        let outcome = q.hold_for_connection(Fix::at(NOW_MS), 0, ERR, now, NOW_MS, false);
        assert_eq!(outcome.queued, Some(Duration::ZERO));
        assert!(outcome.abandoned.is_empty());
        assert_eq!(q.next_due(), Some(now), "no per-fix backoff while the connection is down");

        let (fix, attempts) = q.take_due(now).expect("due");
        assert_eq!(fix, Fix::at(NOW_MS));
        assert_eq!(attempts, 0, "no attempt is charged for waiting");
    }

    /// THE ORDERING RULE. The fix that was in flight when the connection
    /// failed is older than anything that queued behind it, so it must go
    /// back to the FRONT; a backlog that flushes out of order loses its older
    /// fixes to the high-water rule the moment a newer one lands first.
    #[test]
    fn a_connection_backlog_drains_in_the_order_the_fixes_were_taken() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        // Two fixes queued behind a closed gate...
        q.hold_for_connection(Fix::at(NOW_MS + 20), 0, ERR, now, NOW_MS, false);
        q.hold_for_connection(Fix::at(NOW_MS + 40), 0, ERR, now, NOW_MS, false);
        // ...then the probe (the OLDEST fix) fails again and is held ahead.
        q.hold_for_connection(Fix::at(NOW_MS), 2, ERR, now, NOW_MS, true);

        let mut order = Vec::new();
        let mut t = now;
        while let Some((fix, _)) = q.take_due(t) {
            order.push(fix.ts - NOW_MS);
            t += Duration::from_millis(RETRY_MIN_SPACING_MS);
        }
        assert_eq!(order, vec![0, 20, 40], "chronological, oldest first");
    }

    /// An outage does not suspend the shelf life or the attempt budget.
    #[test]
    fn a_held_fix_still_ages_out_and_still_runs_out_of_attempts() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);

        let stale = q.hold_for_connection(Fix::at(NOW_MS - MAX_RETRY_AGE_MS - 1), 1, ERR, now, NOW_MS, true);
        assert_eq!(stale.queued, None);
        assert_eq!(stale.abandoned[0].reason, DropReason::TooStale);
        assert_eq!(stale.abandoned[0].last_error, ERR, "reported with the connection failure that held it");

        let spent = q.hold_for_connection(Fix::at(NOW_MS), 7, ERR, now, NOW_MS, true);
        assert_eq!(spent.queued, None);
        assert_eq!(spent.abandoned[0].reason, DropReason::AttemptsExhausted);
        assert!(q.is_empty());
    }

    /// A long outage fills the queue; the cap still holds and still evicts
    /// the oldest waiting fix, reported rather than silently lost.
    #[test]
    fn a_held_backlog_is_capped_and_evicts_the_oldest() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(2, 6);
        q.hold_for_connection(Fix::at(NOW_MS), 0, ERR, now, NOW_MS, false);
        q.hold_for_connection(Fix::at(NOW_MS + 1), 0, ERR, now, NOW_MS, false);
        let outcome = q.hold_for_connection(Fix::at(NOW_MS + 2), 0, ERR, now, NOW_MS, false);
        assert_eq!(q.len(), 2);
        assert_eq!(outcome.abandoned.len(), 1);
        assert_eq!(outcome.abandoned[0].reason, DropReason::QueueFull);
        assert_eq!(outcome.abandoned[0].item, Fix::at(NOW_MS));
    }

    // ===================== late history points =====================

    const HOUR_MS: i64 = 60 * 60 * 1000;

    /// A history point is hours old by design: the live 5-minute shelf life
    /// would drop every one on its first transient refusal. It keeps its place
    /// for the 48 h the server accepts it in, and not a millisecond longer.
    #[test]
    fn a_history_point_is_kept_for_48_hours_not_5_minutes() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);

        let live = q.requeue(Fix::at(NOW_MS - 2 * HOUR_MS), 1, None, ERR, now, NOW_MS);
        assert_eq!(live.abandoned[0].reason, DropReason::TooStale, "the live rule is unchanged");

        let history = q.requeue(Fix::history_at(NOW_MS - 2 * HOUR_MS), 1, None, ERR, now, NOW_MS);
        assert!(history.queued.is_some() && history.abandoned.is_empty());
        let held = q.hold_for_connection(Fix::history_at(NOW_MS - 47 * HOUR_MS), 0, ERR, now, NOW_MS, false);
        assert!(held.queued.is_some() && held.abandoned.is_empty());
        assert!(q.purge(NOW_MS).is_empty(), "both still inside 48 h");
        assert_eq!(q.len(), 2);

        let too_old = q.requeue(Fix::history_at(NOW_MS - MAX_HISTORY_AGE_MS - 1), 1, None, ERR, now, NOW_MS);
        assert_eq!(too_old.abandoned[0].reason, DropReason::TooStale);
        // An hour and a bit later the 47 h point is past 48 h: purged, reported.
        let dropped = q.purge(NOW_MS + HOUR_MS + 1);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, DropReason::TooStale);
        assert_eq!(dropped[0].item, Fix::history_at(NOW_MS - 47 * HOUR_MS));
    }

    /// A newer accepted live fix supersedes queued LIVE fixes (they would move
    /// the marker backwards) but takes nothing from a history point, which is
    /// never anyone's latest location.
    #[test]
    fn a_newer_accepted_fix_never_supersedes_a_history_point() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        q.note_accepted(&Fix::at(NOW_MS + 20_000));

        let live = q.requeue(Fix::at(NOW_MS), 1, None, ERR, now, NOW_MS);
        assert_eq!(live.abandoned[0].reason, DropReason::Superseded, "the live rule is unchanged");
        let history = q.requeue(Fix::history_at(NOW_MS - HOUR_MS), 1, None, ERR, now, NOW_MS);
        assert!(history.queued.is_some());
        assert!(q.purge(NOW_MS).is_empty());
    }

    /// An accepted history point must not raise the live high-water mark: a
    /// backlog newer than the last live fix would otherwise make the live
    /// fixes still waiting look superseded.
    #[test]
    fn an_accepted_history_point_leaves_the_live_high_water_alone() {
        let now = Instant::now();
        let mut q: RetryQueue<Fix> = RetryQueue::with_limits(8, 6);
        q.note_accepted(&Fix::history_at(NOW_MS + 60_000));
        let live = q.requeue(Fix::at(NOW_MS), 1, None, ERR, now, NOW_MS);
        assert!(live.queued.is_some(), "not superseded by a history point");
        assert!(q.purge(NOW_MS).is_empty());
    }
}
