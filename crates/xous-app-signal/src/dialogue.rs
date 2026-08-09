//! Conversation-list data model.
//!
//! [`ThreadMessage`] is one entry in xas's RAM-only message buffer.
//! Both inbound (received over WS) and outbound (composed in xas)
//! messages live in the same flat `Vec`, distinguished by the
//! [`ThreadMessage::outgoing`] field.
//!
//! [`DialogueSummary`] is the aggregated per-conversation view: one
//! row per UUID for the home screen, re-derived from the message
//! vec whenever messages change. Cheap because the in-RAM buffer is
//! bounded by `INBOX_CAPACITY` in `gam_app.rs`.
//!
//! No persistence here — the cache lives only in `App` state and
//! resets on app restart. Future PDDB-backed history will live
//! behind the same interface; the data shapes in this module are
//! the persistence-side schema as well.
//!
//! # Trust boundary
//!
//! Every [`ThreadMessage`] carries plaintext that already crossed
//! the libsignal decrypt boundary inside `xous-signal-worker`. The
//! `body` and `author_label` fields are PII or higher; do not log
//! them and avoid `Debug`-printing values of these types beyond the
//! existing structured trace lines.

use std::collections::HashMap;

use uuid::Uuid;

/// Status of a single message in xas's view.
///
/// Incoming messages are always `Sent` (the server delivered them to us;
/// the term carries no meaning for the receive direction). Outgoing
/// messages move through `Pending` (queued, awaiting the worker's
/// `Event::SendComplete`) → `Delivered` (worker reported success) or
/// `Failed` (worker reported `Event::SendError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStatus {
    Pending,
    Sent,
    Delivered,
    Failed,
}

/// One message in xas's view, either inbound or outbound. Fields are
/// kept narrow on purpose; the renderer derives display-formatted
/// strings (`"You" / contact-name / timestamp`) at draw time.
#[derive(Debug, Clone)]
pub struct ThreadMessage {
    /// The conversation this message belongs to (sender if `outgoing`
    /// is false; recipient if true).
    pub uuid: Uuid,
    /// Pre-resolved display label for the message's author. For
    /// incoming this is the sender's contact name (or e164/uuid
    /// fallback). For outgoing this is `"You"`.
    pub author_label: String,
    /// Message body as plain text.
    pub body: String,
    /// Unix milliseconds.
    pub timestamp: u64,
    /// True if xas sent this; false if it was received.
    pub outgoing: bool,
    /// Lifecycle state.
    pub status: SendStatus,
    /// Whether the user has seen this message. Auto-true for outgoing.
    /// Auto-false for incoming until the Thread is opened (reading
    /// the messages) or the user invokes "Mark all read". Drives the
    /// `unread_count` aggregation in `rebuild_summaries`.
    pub read: bool,
    /// True if this message carried GV2 group context — it belongs
    /// to a group conversation, not a private 1:1 with its author.
    /// Drives the `[group]` UI label and the group reply-block.
    pub group: bool,
}

/// Aggregated per-conversation view. One per UUID. Built by
/// [`rebuild_summaries`] from a slice of [`ThreadMessage`].
#[derive(Debug, Clone)]
pub struct DialogueSummary {
    pub uuid: Uuid,
    /// Best-effort name of the *other* party. Falls back to a short
    /// uuid prefix if no incoming messages have ever been received from
    /// this UUID (e.g. the user only sent outgoing).
    pub display_name: String,
    /// Latest message body, ellipsized for one-line preview.
    pub last_msg_snippet: String,
    /// Timestamp of the latest message in this conversation.
    pub last_msg_ts: u64,
    /// Whether the latest message was outgoing (drives the row's
    /// send-status glyph in the UI).
    pub last_msg_outgoing: bool,
    /// Status of the latest message — meaningful only when
    /// `last_msg_outgoing == true`.
    pub last_msg_status: SendStatus,
    /// Count of incoming messages whose status is `Sent` (the only
    /// state an unread incoming message can be in). Outgoing messages
    /// never increment this.
    pub unread_count: u32,
    /// True if any message in this conversation is group-tagged.
    /// Group messages file under a pseudo-thread UUID derived from
    /// the group's master key (see `gam_app`), so in practice the
    /// whole thread is either group or 1:1. Drives the `[group]`
    /// label and blocks the compose path (a "reply" would go out
    /// as a private 1:1 DM to one member).
    pub is_group: bool,
}

/// Group `messages` by UUID, sorted by `last_msg_ts` descending.
///
/// O(N) over the input; xas's in-RAM message buffer is bounded so this
/// is cheap to call on every message arrival.
///
/// Display-name resolution: prefers any incoming message's
/// `author_label`. If the conversation only contains outgoing messages
/// the fallback is a short UUID prefix (`"uuid:1234abcd"`).
pub fn rebuild_summaries(messages: &[ThreadMessage]) -> Vec<DialogueSummary> {
    let mut by_uuid: HashMap<Uuid, DialogueSummary> = HashMap::new();
    for m in messages {
        let entry = by_uuid.entry(m.uuid).or_insert_with(|| DialogueSummary {
            uuid: m.uuid,
            display_name: short_uuid_label(&m.uuid),
            last_msg_snippet: String::new(),
            last_msg_ts: 0,
            last_msg_outgoing: false,
            last_msg_status: SendStatus::Sent,
            unread_count: 0,
            is_group: false,
        });

        entry.is_group |= m.group;

        // Prefer the author label of any incoming message — that's the
        // contact's name. Outgoing messages have author_label == "You",
        // which is not the conversation's display name. If the author
        // label looks like a raw UUID (36 chars with dashes), the
        // worker couldn't find the contact in the store; surface a
        // shorter "uuid:1234abcd" instead of the full hex blob.
        if !m.outgoing {
            entry.display_name = if looks_like_raw_uuid(&m.author_label) {
                short_uuid_label(&m.uuid)
            } else {
                m.author_label.clone()
            };
        }

        if m.timestamp >= entry.last_msg_ts {
            entry.last_msg_ts = m.timestamp;
            entry.last_msg_snippet = ellipsize(&m.body, 32);
            entry.last_msg_outgoing = m.outgoing;
            entry.last_msg_status = m.status;
        }

        if !m.outgoing && m.status == SendStatus::Sent && !m.read {
            entry.unread_count = entry.unread_count.saturating_add(1);
        }
    }

    let mut v: Vec<DialogueSummary> = by_uuid.into_values().collect();
    v.sort_by(|a, b| b.last_msg_ts.cmp(&a.last_msg_ts));
    v
}

/// Truncate `s` to at most `max` *characters* (not bytes), appending
/// `'…'` if truncation happened. `max` must be ≥ 1; `max == 0` returns
/// an empty string.
pub fn ellipsize(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        // Reserve one slot for the ellipsis.
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Brief relative timestamp, like Signal Android's
/// `DateUtils.getBriefRelativeTimeSpanString` — but without the
/// dependency surface of `chrono` / `time`.
///
/// Buckets: `< 60s` → `"Ns"`; `< 1h` → `"Nm"`; `< 24h` → `"Nh"`;
/// `24h..48h` → `"Yest"`; older → `"Nd"`.
///
/// `now_ms` is supplied by the caller (rather than read here) for
/// testability and to keep this function pure.
pub fn brief_relative(ts_ms: u64, now_ms: u64) -> String {
    let dt_s = now_ms.saturating_sub(ts_ms) / 1_000;
    if dt_s < 60 {
        format!("{}s", dt_s)
    } else if dt_s < 60 * 60 {
        format!("{}m", dt_s / 60)
    } else if dt_s < 24 * 60 * 60 {
        format!("{}h", dt_s / 3_600)
    } else if dt_s < 48 * 60 * 60 {
        "Yest".to_string()
    } else {
        format!("{}d", dt_s / (24 * 60 * 60))
    }
}

/// Display fallback for a UUID we have no contact record for.
/// E.g. `Uuid::from_u128(0x0123_4567_89ab_cdef_0011_2233_4455_6677)` →
/// `"uuid:01234567"`.
fn short_uuid_label(uuid: &Uuid) -> String {
    let s = uuid.simple().to_string();
    let prefix: String = s.chars().take(8).collect();
    format!("uuid:{}", prefix)
}

/// Heuristic: does this string look like a raw UUID? Used to detect
/// when the worker fell back to passing the canonical UUID string as
/// `author_label` because the contact lookup returned nothing. Matches
/// both dashed (36-char) and undashed (32-char) hex forms.
pub(crate) fn looks_like_raw_uuid(s: &str) -> bool {
    let len = s.len();
    if len == 36 {
        s.chars()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) == (c == '-') && (c == '-' || c.is_ascii_hexdigit()))
    } else if len == 32 {
        s.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid_a() -> Uuid { Uuid::from_u128(0x0123_4567_89ab_cdef_0011_2233_4455_6677) }
    fn uuid_b() -> Uuid { Uuid::from_u128(0xf0f0_f0f0_f0f0_f0f0_f0f0_f0f0_f0f0_f0f0) }

    fn incoming(uuid: Uuid, ts: u64, body: &str, label: &str) -> ThreadMessage {
        ThreadMessage {
            uuid,
            author_label: label.to_string(),
            body: body.to_string(),
            timestamp: ts,
            outgoing: false,
            status: SendStatus::Sent,
            read: false,
            group: false,
        }
    }

    fn outgoing(uuid: Uuid, ts: u64, body: &str, status: SendStatus) -> ThreadMessage {
        ThreadMessage {
            uuid,
            author_label: "You".to_string(),
            body: body.to_string(),
            timestamp: ts,
            outgoing: true,
            status,
            read: true,
            group: false,
        }
    }

    #[test]
    fn ellipsize_short_unchanged() {
        assert_eq!(ellipsize("hi", 5), "hi");
    }

    #[test]
    fn ellipsize_at_boundary_unchanged() {
        assert_eq!(ellipsize("hello", 5), "hello");
    }

    #[test]
    fn ellipsize_truncates_with_ellipsis() {
        let out = ellipsize("hello world", 5);
        assert_eq!(out.chars().count(), 5);
        assert!(out.ends_with('…'));
        assert_eq!(out, "hell…");
    }

    #[test]
    fn ellipsize_zero_max_yields_empty() {
        assert_eq!(ellipsize("anything", 0), "");
    }

    #[test]
    fn ellipsize_handles_multibyte() {
        // "hï" is 2 chars but 3 bytes; ensure we count chars not bytes.
        assert_eq!(ellipsize("hï", 2), "hï");
        assert_eq!(ellipsize("hïllo", 3), "hï…");
    }

    #[test]
    fn brief_relative_seconds() {
        assert_eq!(brief_relative(0, 30_000), "30s");
        assert_eq!(brief_relative(0, 59_999), "59s");
    }

    #[test]
    fn brief_relative_minutes() {
        assert_eq!(brief_relative(0, 60_000), "1m");
        assert_eq!(brief_relative(0, 12 * 60_000), "12m");
        assert_eq!(brief_relative(0, 59 * 60_000 + 999), "59m");
    }

    #[test]
    fn brief_relative_hours() {
        assert_eq!(brief_relative(0, 60 * 60_000), "1h");
        assert_eq!(brief_relative(0, 23 * 60 * 60_000), "23h");
    }

    #[test]
    fn brief_relative_yesterday() {
        assert_eq!(brief_relative(0, 24 * 60 * 60_000), "Yest");
        assert_eq!(brief_relative(0, 47 * 60 * 60_000), "Yest");
    }

    #[test]
    fn brief_relative_days() {
        assert_eq!(brief_relative(0, 48 * 60 * 60_000), "2d");
        assert_eq!(brief_relative(0, 7 * 24 * 60 * 60_000), "7d");
    }

    #[test]
    fn brief_relative_clock_skew_clamps_to_zero() {
        // ts_ms > now_ms (RTC drift, future-dated server message).
        assert_eq!(brief_relative(1_000_000, 0), "0s");
    }

    #[test]
    fn rebuild_empty_input_yields_empty() {
        assert!(rebuild_summaries(&[]).is_empty());
    }

    #[test]
    fn rebuild_single_incoming() {
        let msgs = vec![incoming(uuid_a(), 100, "hello", "Alice")];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].uuid, uuid_a());
        assert_eq!(v[0].display_name, "Alice");
        assert_eq!(v[0].last_msg_snippet, "hello");
        assert_eq!(v[0].last_msg_ts, 100);
        assert!(!v[0].last_msg_outgoing);
        assert_eq!(v[0].unread_count, 1);
    }

    #[test]
    fn rebuild_groups_by_uuid_takes_latest() {
        let msgs = vec![
            incoming(uuid_a(), 100, "first", "Alice"),
            incoming(uuid_a(), 200, "second", "Alice"),
            incoming(uuid_a(), 50, "earlier", "Alice"),
        ];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].last_msg_ts, 200);
        assert_eq!(v[0].last_msg_snippet, "second");
        assert_eq!(v[0].unread_count, 3); // all 3 are incoming + Sent
    }

    #[test]
    fn rebuild_outgoing_does_not_count_unread() {
        let msgs = vec![
            outgoing(uuid_a(), 100, "ping", SendStatus::Delivered),
            outgoing(uuid_a(), 200, "still ping", SendStatus::Pending),
        ];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].unread_count, 0);
        assert!(v[0].last_msg_outgoing);
        assert_eq!(v[0].last_msg_status, SendStatus::Pending);
        assert_eq!(v[0].last_msg_ts, 200);
    }

    #[test]
    fn rebuild_mixed_outgoing_uses_incoming_label_for_display_name() {
        // Outgoing message arrives first; display_name temporarily falls
        // back to a uuid prefix. Then an incoming message arrives; the
        // display_name updates to the contact's name.
        let msgs = vec![
            outgoing(uuid_a(), 50, "hi there", SendStatus::Delivered),
            incoming(uuid_a(), 100, "hello", "Alice"),
        ];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].display_name, "Alice");
    }

    #[test]
    fn rebuild_outgoing_only_uses_uuid_fallback_display_name() {
        let msgs = vec![outgoing(uuid_a(), 50, "anyone there?", SendStatus::Sent)];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert!(v[0].display_name.starts_with("uuid:"));
    }

    #[test]
    fn rebuild_multi_uuid_sorts_by_ts_desc() {
        let msgs = vec![
            incoming(uuid_a(), 100, "older", "Alice"),
            incoming(uuid_b(), 300, "newest", "Bob"),
            incoming(uuid_a(), 200, "middle", "Alice"),
        ];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 2);
        // Bob's 300 should come before Alice's 200 (latest of her two).
        assert_eq!(v[0].uuid, uuid_b());
        assert_eq!(v[1].uuid, uuid_a());
        assert_eq!(v[0].last_msg_ts, 300);
        assert_eq!(v[1].last_msg_ts, 200);
    }

    #[test]
    fn rebuild_long_body_is_ellipsized_in_snippet() {
        let body = "a".repeat(80);
        let msgs = vec![incoming(uuid_a(), 100, &body, "Alice")];
        let v = rebuild_summaries(&msgs);
        // Snippet capped at 32 chars per the implementation.
        assert!(v[0].last_msg_snippet.chars().count() <= 32);
        assert!(v[0].last_msg_snippet.ends_with('…'));
    }

    #[test]
    fn rebuild_unread_excludes_read_messages() {
        // Three incoming messages from one sender; the first two are
        // marked read (e.g. user opened the thread before the third
        // arrived). Unread count should reflect only the unread one.
        let mut msgs = vec![
            incoming(uuid_a(), 100, "first", "Alice"),
            incoming(uuid_a(), 200, "second", "Alice"),
            incoming(uuid_a(), 300, "third", "Alice"),
        ];
        msgs[0].read = true;
        msgs[1].read = true;
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].unread_count, 1);
    }

    #[test]
    fn rebuild_all_read_yields_zero_unread() {
        let mut msgs = vec![incoming(uuid_a(), 100, "hi", "Alice"), incoming(uuid_b(), 200, "hello", "Bob")];
        for m in &mut msgs {
            m.read = true;
        }
        let v = rebuild_summaries(&msgs);
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|d| d.unread_count == 0));
    }

    #[test]
    fn rebuild_group_tag_propagates_to_summary() {
        let mut m = incoming(uuid_a(), 100, "party is off", "Bob");
        m.group = true;
        let v = rebuild_summaries(&[m]);
        assert!(v[0].is_group);
    }

    #[test]
    fn rebuild_plain_thread_is_not_group() {
        let msgs = vec![incoming(uuid_a(), 100, "hello", "Alice")];
        assert!(!rebuild_summaries(&msgs)[0].is_group);
    }

    #[test]
    fn rebuild_group_tag_is_sticky_across_messages() {
        let mut first = incoming(uuid_a(), 100, "one", "Bob");
        first.group = true;
        let second = incoming(uuid_a(), 200, "two", "Bob");
        let v = rebuild_summaries(&[first, second]);
        assert_eq!(v.len(), 1);
        assert!(v[0].is_group);
    }

    #[test]
    fn rebuild_status_reflects_latest_message() {
        let msgs = vec![
            outgoing(uuid_a(), 100, "first", SendStatus::Delivered),
            outgoing(uuid_a(), 200, "second", SendStatus::Failed),
        ];
        let v = rebuild_summaries(&msgs);
        assert_eq!(v[0].last_msg_status, SendStatus::Failed);
    }
}
