//! In-RAM message store: the single mutation funnel for xas's
//! message and conversation state.
//!
//! Every change to the message buffer or the derived dialogue
//! summaries goes through one [`MessageStore`] method — eviction,
//! summary rebuild, and read-state transitions live here and only
//! here. `gam_app.rs` holds a `MessageStore` and never touches the
//! underlying vectors directly. This is the seam the PDDB-backed
//! history (issue #2) will slot into: the future load path hydrates
//! through the same methods, and the write path mirrors mutations to
//! the worker without the UI growing new state-management sites.
//!
//! The data shapes ([`ThreadMessage`], [`DialogueSummary`]) stay in
//! [`crate::dialogue`], which module-documents itself as the
//! persistence-side schema.
//!
//! # Security
//!
//! Holds plaintext message bodies and sender labels (PII or higher —
//! they crossed the libsignal decrypt boundary in the worker). The
//! derived `Debug` on the element types is not redacting; do not log
//! store contents. SecretBox wrapping of bodies is tracked in issue
//! #37, item 3.

use uuid::Uuid;

use crate::dialogue::{DialogueSummary, SendStatus, ThreadMessage, looks_like_raw_uuid, rebuild_summaries};

/// Bounded in-RAM message buffer plus the per-conversation summary
/// cache derived from it.
///
/// Capacity semantics: [`Self::push_incoming`] and
/// [`Self::push_outgoing_pending`] evict the oldest message (index
/// 0, insertion order) when the buffer is at or above capacity —
/// one eviction per push, matching the pre-extraction behavior.
/// [`Self::seed`] deliberately bypasses the cap (hosted-mode mock
/// data seeds more rows than `INBOX_CAPACITY`; see its doc).
pub struct MessageStore {
    messages: Vec<ThreadMessage>,
    dialogues: Vec<DialogueSummary>,
    capacity: usize,
}

impl MessageStore {
    pub fn new(capacity: usize) -> Self {
        Self { messages: Vec::with_capacity(capacity), dialogues: Vec::new(), capacity }
    }

    // ---- read surface ----

    /// Per-conversation summaries, newest-activity first.
    pub fn dialogues(&self) -> &[DialogueSummary] { &self.dialogues }

    /// Messages belonging to one conversation, insertion order.
    /// Takes `Uuid` by value (it's `Copy`) so the returned iterator
    /// captures no borrow of the caller's uuid.
    pub fn thread_messages(&self, uuid: Uuid) -> impl Iterator<Item = &ThreadMessage> {
        self.messages.iter().filter(move |m| m.uuid == uuid)
    }

    /// Sum of unread counts across all conversations (Home header).
    pub fn total_unread(&self) -> u32 { self.dialogues.iter().map(|d| d.unread_count).sum() }

    /// Whether `uuid`'s conversation is group-tagged (any message in
    /// it carried GV2 group context). Gate for the compose/send
    /// path: sends can only address a single contact today.
    pub fn is_group_thread(&self, uuid: Uuid) -> bool {
        self.dialogues.iter().any(|d| d.uuid == uuid && d.is_group)
    }

    // ---- mutation funnel ----

    /// Append an inbound message (unread, `SendStatus::Sent`),
    /// evicting the oldest row first if the buffer is full. `group`
    /// tags a message that carried GV2 group context (see
    /// [`ThreadMessage::group`]).
    pub fn push_incoming(
        &mut self,
        uuid: Uuid,
        author_label: String,
        body: String,
        timestamp: u64,
        group: bool,
    ) {
        self.evict_if_full();
        self.messages.push(ThreadMessage {
            uuid,
            author_label,
            body,
            timestamp,
            outgoing: false,
            status: SendStatus::Sent,
            read: false,
            group,
        });
        self.rebuild();
    }

    /// Append an optimistic outbound message (`SendStatus::Pending`,
    /// author `"You"`, read), evicting the oldest row first if the
    /// buffer is full. The caller matches later worker events back to
    /// this row by `timestamp`.
    pub fn push_outgoing_pending(&mut self, uuid: Uuid, body: String, timestamp: u64) {
        self.evict_if_full();
        self.messages.push(ThreadMessage {
            uuid,
            author_label: "You".to_string(),
            body,
            timestamp,
            outgoing: true,
            status: SendStatus::Pending,
            read: true,
            // Compose into a group thread is blocked upstream
            // (`gam_app` reply-block); outgoing rows are 1:1 only.
            group: false,
        });
        self.rebuild();
    }

    /// Flip the newest outgoing row with `timestamp` to `Delivered`.
    /// Returns whether a row matched (callers log the no-match case:
    /// a worker event for a send we hold no optimistic row for).
    pub fn mark_send_delivered(&mut self, timestamp: u64) -> bool {
        self.set_outgoing_status(timestamp, SendStatus::Delivered)
    }

    /// Flip the newest outgoing row with `timestamp` to `Failed`.
    /// Returns whether a row matched.
    pub fn mark_send_failed(&mut self, timestamp: u64) -> bool {
        self.set_outgoing_status(timestamp, SendStatus::Failed)
    }

    /// Mark every message in `uuid`'s conversation read. Rebuilds
    /// summaries only when something actually changed (re-entering an
    /// already-read thread stays cheap).
    pub fn mark_thread_read(&mut self, uuid: Uuid) {
        let mut changed = false;
        for m in self.messages.iter_mut() {
            if m.uuid == uuid && !m.read {
                m.read = true;
                changed = true;
            }
        }
        if changed {
            self.rebuild();
        }
    }

    /// Replace UUID-shaped author labels for `uuid` with the resolved
    /// contact `name` (late `Event::ContactResolved`). Outgoing rows
    /// are untouched ("You" doesn't look like a raw UUID). Returns
    /// whether anything changed so the caller can re-render.
    pub fn resolve_author_labels(&mut self, uuid: Uuid, name: &str) -> bool {
        let mut touched = false;
        for m in self.messages.iter_mut() {
            if m.uuid == uuid && looks_like_raw_uuid(&m.author_label) {
                m.author_label = name.to_string();
                touched = true;
            }
        }
        if touched {
            self.rebuild();
        }
        touched
    }

    /// Drop all messages and summaries (logout / auth-expired /
    /// conflicting-device wipe).
    pub fn clear(&mut self) {
        self.messages.clear();
        self.dialogues.clear();
    }

    /// Bulk-load rows, then rebuild once. **Bypasses the capacity
    /// cap** — used by the hosted-mode mock seeder, which populates
    /// more rows than `INBOX_CAPACITY` so Home/Thread rendering can
    /// be exercised with a realistic conversation list. (The cap
    /// applies to live pushes; a future PDDB hydration path will
    /// come with its own pagination story per issue #2.)
    pub fn seed(&mut self, rows: impl IntoIterator<Item = ThreadMessage>) {
        self.messages.extend(rows);
        self.rebuild();
    }

    // ---- internals ----

    fn evict_if_full(&mut self) {
        if self.messages.len() >= self.capacity {
            self.messages.remove(0);
        }
    }

    fn set_outgoing_status(&mut self, timestamp: u64, status: SendStatus) -> bool {
        let matched = self.messages.iter_mut().rev().find(|m| m.outgoing && m.timestamp == timestamp);
        match matched {
            Some(m) => {
                m.status = status;
                self.rebuild();
                true
            }
            None => false,
        }
    }

    fn rebuild(&mut self) { self.dialogues = rebuild_summaries(&self.messages); }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 5;

    fn uuid_a() -> Uuid { Uuid::from_u128(0x0123_4567_89ab_cdef_0011_2233_4455_6677) }
    fn uuid_b() -> Uuid { Uuid::from_u128(0xf0f0_f0f0_f0f0_f0f0_f0f0_f0f0_f0f0_f0f0) }

    fn store() -> MessageStore { MessageStore::new(CAP) }

    #[test]
    fn starts_empty() {
        let s = store();
        assert!(s.dialogues().is_empty());
        assert_eq!(s.total_unread(), 0);
        assert_eq!(s.thread_messages(uuid_a()).count(), 0);
    }

    #[test]
    fn push_incoming_creates_unread_dialogue() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "hello".into(), 100, false);
        assert_eq!(s.dialogues().len(), 1);
        assert_eq!(s.dialogues()[0].display_name, "Alice");
        assert_eq!(s.dialogues()[0].unread_count, 1);
        assert_eq!(s.total_unread(), 1);
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].outgoing);
        assert_eq!(msgs[0].status, SendStatus::Sent);
        assert!(!msgs[0].read);
    }

    #[test]
    fn push_outgoing_is_pending_read_and_labeled_you() {
        let mut s = store();
        s.push_outgoing_pending(uuid_a(), "ping".into(), 200);
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].outgoing);
        assert_eq!(msgs[0].author_label, "You");
        assert_eq!(msgs[0].status, SendStatus::Pending);
        assert!(msgs[0].read);
        assert_eq!(s.total_unread(), 0);
        assert_eq!(s.dialogues()[0].last_msg_status, SendStatus::Pending);
    }

    #[test]
    fn eviction_drops_oldest_at_capacity() {
        let mut s = store();
        for i in 0..CAP as u64 {
            s.push_incoming(uuid_a(), "Alice".into(), format!("m{}", i), 100 + i, false);
        }
        assert_eq!(s.thread_messages(uuid_a()).count(), CAP);
        // One more evicts exactly the oldest (m0), not more.
        s.push_incoming(uuid_a(), "Alice".into(), "overflow".into(), 999, false);
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs.len(), CAP);
        assert_eq!(msgs[0].body, "m1");
        assert_eq!(msgs.last().unwrap().body, "overflow");
    }

    #[test]
    fn eviction_applies_to_outgoing_pushes_too() {
        let mut s = store();
        for i in 0..CAP as u64 {
            s.push_incoming(uuid_a(), "Alice".into(), format!("m{}", i), 100 + i, false);
        }
        s.push_outgoing_pending(uuid_b(), "reply".into(), 999);
        assert_eq!(s.thread_messages(uuid_a()).count() + s.thread_messages(uuid_b()).count(), CAP);
    }

    #[test]
    fn mark_send_delivered_matches_newest_row_with_timestamp() {
        let mut s = store();
        s.push_outgoing_pending(uuid_a(), "one".into(), 500);
        assert!(s.mark_send_delivered(500));
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs[0].status, SendStatus::Delivered);
        assert_eq!(s.dialogues()[0].last_msg_status, SendStatus::Delivered);
    }

    #[test]
    fn mark_send_delivered_returns_false_without_match() {
        let mut s = store();
        s.push_outgoing_pending(uuid_a(), "one".into(), 500);
        assert!(!s.mark_send_delivered(501));
        // No-match must not touch existing rows.
        assert_eq!(s.thread_messages(uuid_a()).next().unwrap().status, SendStatus::Pending);
    }

    #[test]
    fn mark_send_failed_flips_status_and_summary() {
        let mut s = store();
        s.push_outgoing_pending(uuid_a(), "one".into(), 500);
        assert!(s.mark_send_failed(500));
        assert_eq!(s.dialogues()[0].last_msg_status, SendStatus::Failed);
    }

    #[test]
    fn send_status_match_ignores_incoming_rows_with_same_timestamp() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "in".into(), 500, false);
        assert!(!s.mark_send_delivered(500));
        assert_eq!(s.thread_messages(uuid_a()).next().unwrap().status, SendStatus::Sent);
    }

    #[test]
    fn send_status_match_picks_newest_of_duplicate_timestamps() {
        // Two optimistic sends stamped in the same millisecond: the
        // rev-scan must update the newest row, matching the
        // pre-extraction `iter_mut().rev().find(...)` behavior.
        let mut s = store();
        s.push_outgoing_pending(uuid_a(), "first".into(), 500);
        s.push_outgoing_pending(uuid_a(), "second".into(), 500);
        assert!(s.mark_send_delivered(500));
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs[0].status, SendStatus::Pending, "older row untouched");
        assert_eq!(msgs[1].status, SendStatus::Delivered, "newest row updated");
    }

    #[test]
    fn mark_thread_read_clears_unread_for_that_thread_only() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "a1".into(), 100, false);
        s.push_incoming(uuid_a(), "Alice".into(), "a2".into(), 200, false);
        s.push_incoming(uuid_b(), "Bob".into(), "b1".into(), 300, false);
        assert_eq!(s.total_unread(), 3);
        s.mark_thread_read(uuid_a());
        assert_eq!(s.total_unread(), 1);
        let bob = s.dialogues().iter().find(|d| d.uuid == uuid_b()).unwrap();
        assert_eq!(bob.unread_count, 1);
    }

    #[test]
    fn mark_thread_read_idempotent() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "a1".into(), 100, false);
        s.mark_thread_read(uuid_a());
        s.mark_thread_read(uuid_a());
        assert_eq!(s.total_unread(), 0);
    }

    #[test]
    fn resolve_author_labels_rewrites_uuid_shaped_labels_only() {
        let mut s = store();
        let raw = uuid_a().to_string(); // dashed 36-char form
        s.push_incoming(uuid_a(), raw, "hi".into(), 100, false);
        s.push_outgoing_pending(uuid_a(), "yo".into(), 200);
        assert!(s.resolve_author_labels(uuid_a(), "Alice"));
        let msgs: Vec<_> = s.thread_messages(uuid_a()).collect();
        assert_eq!(msgs[0].author_label, "Alice");
        assert_eq!(msgs[1].author_label, "You", "outgoing label untouched");
        assert_eq!(s.dialogues()[0].display_name, "Alice");
    }

    #[test]
    fn resolve_author_labels_no_op_on_named_labels() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "hi".into(), 100, false);
        assert!(!s.resolve_author_labels(uuid_a(), "Alicia"));
        assert_eq!(s.thread_messages(uuid_a()).next().unwrap().author_label, "Alice");
    }

    #[test]
    fn clear_wipes_messages_and_dialogues() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "hi".into(), 100, false);
        s.clear();
        assert!(s.dialogues().is_empty());
        assert_eq!(s.thread_messages(uuid_a()).count(), 0);
        assert_eq!(s.total_unread(), 0);
    }

    #[test]
    fn push_incoming_group_tags_summary() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Bob".into(), "party is off".into(), 100, true);
        s.push_incoming(uuid_b(), "Alice".into(), "hi".into(), 200, false);
        let group = s.dialogues().iter().find(|d| d.uuid == uuid_a()).unwrap();
        let dm = s.dialogues().iter().find(|d| d.uuid == uuid_b()).unwrap();
        assert!(group.is_group);
        assert!(!dm.is_group);
    }

    #[test]
    fn seed_bypasses_capacity_and_rebuilds_once() {
        let mut s = store();
        let rows: Vec<ThreadMessage> = (0..(CAP as u64 + 5))
            .map(|i| ThreadMessage {
                uuid: uuid_a(),
                author_label: "Alice".into(),
                body: format!("m{}", i),
                timestamp: 100 + i,
                outgoing: false,
                status: SendStatus::Sent,
                read: false,
                group: false,
            })
            .collect();
        s.seed(rows);
        assert_eq!(s.thread_messages(uuid_a()).count(), CAP + 5);
        assert_eq!(s.dialogues().len(), 1);
        assert_eq!(s.total_unread(), (CAP + 5) as u32);
    }

    #[test]
    fn dialogues_sorted_newest_first_across_threads() {
        let mut s = store();
        s.push_incoming(uuid_a(), "Alice".into(), "old".into(), 100, false);
        s.push_incoming(uuid_b(), "Bob".into(), "new".into(), 900, false);
        assert_eq!(s.dialogues()[0].uuid, uuid_b());
        assert_eq!(s.dialogues()[1].uuid, uuid_a());
    }
}
