//! GAM-rendered xas UI: hardware-side link / receive / send.
//!
//! Owns the on-device UI loop. The binary in `xous-app-signal`
//! calls [`run`], which registers a GAM context under
//! [`gam::APP_NAME_XAS`], constructs the [`App`] state, and drives
//! the main IPC loop until the GAM tears the context down.
//!
//! # State machine
//!
//! Pre-link screens:
//!
//! - **Menu** — landing for an unlinked device. Items: Link / About / Help. Up/Down navigates; Enter (or
//!   `'∴'`) selects.
//! - **About** — version string, author handle, what xas protects.
//! - **Linking** — transient; shown while the worker is waiting on the provisioning WebSocket. The QR modal
//!   opens on top of this screen when the worker emits `Event::LinkUrl`.
//! - **Linked { Success }** — brief banner; auto-fires `Cmd::StartReceive` and transitions to **Home**.
//! - **Linked { Failure }** — error string; Enter returns to Menu.
//!
//! Post-link screens:
//!
//! - **Home** — the conversation list. F1 opens a new chat, F2 syncs contacts, F3 opens Help, F4 opens
//!   Settings.
//! - **Thread { uuid }** — single conversation history plus an in-screen compose box. Enter sends; Esc/Menu
//!   opens Settings.
//! - **Settings** — Profile / Help / About / Logout.
//! - **Profile** — account display name, phone, ACI.
//! - **Help** — FAQ pointer and Wi-Fi recipe.
//! - **NoInternet** — preflight failure; transitions back to the intended next screen on retry success.
//!
//! # Trust boundary
//!
//! Everything rendered after the link completes is plaintext that
//! crossed the libsignal decrypt boundary inside
//! `xous-signal-worker`. Inbound message bodies, sender ACIs, and
//! the registration tuple (`device_name`, `aci`, `phone`) all
//! arrive here as bare strings. Treat all of them as PII or higher
//! when adding consumers; the existing `log::info!` lines emit a
//! deliberately limited subset (sender label, byte length) and new
//! log lines should follow the same discipline.
//!
//! # Worker integration
//!
//! `event_rx` cannot be polled inside the GAM main loop (which
//! blocks on `xous::receive_message`). A dedicated forwarder thread
//! bridges the two: it blocks on `event_rx.recv_blocking`, pushes
//! each event onto a shared `Mutex<VecDeque<Event>>`, and pokes the
//! main SID with a `XasOp::WorkerEvent` scalar. The main loop wakes
//! and drains the deque under [`handle_worker_event`]. **The
//! forwarder is the sole consumer of `event_rx`** — no other site
//! may call `recv*` on the receiver.

use core::fmt::Write;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_channel::{Receiver, Sender};
use blitstr2::GlyphStyle;
use num_traits::*;
use uuid::Uuid;
use ux_api::minigfx::*;
use ux_api::service::api::Gid;
use xous::{CID, Message};
use xous_signal_worker::{Cmd, Event};

use crate::dialogue::{SendStatus, ThreadMessage};
use crate::store::MessageStore;

/// IPC server name xas registers under [`xous_names::XousNames`].
///
/// # Trust boundary
///
/// This is xas's only outward-facing IPC surface on the system.
/// `gam` looks it up when delivering `Redraw` / `Rawkeys` /
/// `FocusChange` notifications; the binary's own forwarder thread
/// uses it to wake the main loop with `WorkerEvent`. No other
/// caller has reason to send to this SID; the GAM enforces this on
/// the redraw / rawkeys side, but a malicious local process with
/// `xous-names` access could in principle connect and send
/// arbitrary scalars. The receive loop is defensive (unknown opcode
/// → log + drop, see `_ => log::debug!("…unknown msg id…")`).
const SERVER_NAME_XAS: &str = "_xas_";

/// Maximum recent messages held in RAM by the [`App`].
///
/// Keeps the render cheap and avoids any thread / sync work for
/// scrolling. Oldest message is evicted when a new arrival or send
/// would overflow this bound.
///
/// # rv32 / 16 MiB constraint
///
/// Each [`ThreadMessage`] owns the body `String` and label
/// `String`. The cap is deliberately small while xas runs without
/// PDDB-backed history; widening this without also adding a
/// pagination story would push real RAM use up on the rv32 device.
const INBOX_CAPACITY: usize = 5;

/// Opcodes the GAM (and the worker-event forwarder) send to xas's
/// own SID via `xous::send_message`. Each variant maps to one arm
/// of the receive loop in [`run`].
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
enum XasOp {
    /// GAM asks us to repaint the canvas.
    Redraw = 0,
    /// GAM forwards a key event from the keyboard service.
    Rawkeys = 1,
    /// GAM signals focus gained/lost — used to repaint on
    /// re-foreground.
    FocusChange = 2,
    /// The worker-event forwarder thread woke us; drain the
    /// pending-events deque.
    WorkerEvent = 3,
}

/// One screen state in the UI's stack-of-one model. See the
/// module-level "State machine" section for the transition graph.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Screen {
    /// Pre-link app menu (Link / About / Help). Post-link the menu
    /// is reduced to About / Help; the post-link landing screen is
    /// [`Self::Home`] and the per-link control surface is
    /// [`Self::Settings`].
    Menu,
    About,
    /// Transient screen shown while waiting for the worker's
    /// `Event::LinkUrl`. The QR-code modal opens on top of this
    /// screen when the URL arrives.
    Linking,
    /// Wipe in progress. Exits only on `Event::LoggedOut`, which the
    /// worker emits whether or not the clear succeeded. Deliberately
    /// keyless: a half-done wipe is worse than waiting.
    Wiping,
    /// Terminal link banner. Auto-transitions to [`Self::Home`] on
    /// `Success` after the user presses Enter; Enter on `Failure`
    /// returns to the pre-link Menu.
    Linked {
        kind: LinkedKind,
    },
    /// Post-link landing: conversation list. Default screen after
    /// `Event::LinkComplete`.
    Home,
    /// Per-conversation history view plus the in-screen compose
    /// box.
    Thread {
        uuid: Uuid,
    },
    /// Post-link settings sub-menu (Profile / Help / About /
    /// Logout). Reachable via F4 (or Esc) from [`Self::Home`].
    Settings,
    /// Account info display (Name / Number / ACI).
    Profile,
    /// FAQ + issue-tracker pointer.
    Help,
    /// Preflight failed: no Wi-Fi link or no DHCP lease. Shown
    /// instead of attempting any network operation. Enter re-runs
    /// the check; on success, transitions to the screen the user
    /// was trying to reach (encoded in `next`).
    NoInternet {
        next: NextScreenAfterInternet,
        reason: String,
    },
}

/// What to do when the no-internet preflight clears. Embedded in
/// `Screen::NoInternet` so the retry-on-Enter path knows where to
/// transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NextScreenAfterInternet {
    /// Pre-link path: the user was trying to Link.
    Link,
    /// Post-link path: the user was on Home (the post-link landing).
    Home,
}

/// Outcome of the link flow. Carried in `Screen::Linked` so the
/// renderer knows whether to show the success or failure banner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkedKind {
    Success,
    Failure,
}

/// Cursor position on the top-level [`Screen::Menu`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MenuItem {
    Link,
    About,
    Help,
    /// Pre-link escape hatch for a stale store. Same `Cmd::Logout`
    /// wipe as Settings -> Logout post-link. Also where
    /// `Event::StaleStoreDetected` parks the cursor after the
    /// worker refuses a link over leftover account state.
    WipeSettings,
}

/// Items shown on `Screen::Settings`. Reachable via F4 (or Esc) from
/// `Home` once the device is linked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SettingsItem {
    Profile,
    Help,
    About,
    Logout,
}

/// The full UI state machine.
///
/// Owns the GAM context (`gam`, `content`, `bounds`), the current
/// [`Screen`], the in-RAM message buffer, and several pieces of
/// flow state. Driven entirely by the IPC loop in [`run`]; there
/// is exactly one `App` per UI session and it lives until the
/// process exits.
///
/// # Security
///
/// Holds plaintext message bodies (inside `store`), sender labels,
/// the account-identifying tuple (`account_*`), and the in-flight
/// compose buffer. The derived `Debug` impl is **not** redacting;
/// adding `tracing::debug!(?app)` anywhere will dump everything.
struct App {
    gam: gam::Gam,
    content: Gid,
    bounds: Point,
    screen: Screen,
    selected: MenuItem,
    /// Pre-link is `false`; flipped to `true` once
    /// `Event::LinkComplete` arrives. Drives which menu items are
    /// visible and which screens are reachable.
    linked: bool,
    /// All inbound and outbound messages held in RAM for the
    /// lifetime of this UI session, plus the derived per-conversation
    /// summaries. Every mutation (append, eviction at
    /// `INBOX_CAPACITY`, status/read transitions, wipe) funnels
    /// through [`MessageStore`]'s methods — this struct never touches
    /// the underlying vectors directly.
    ///
    /// # Security
    ///
    /// Plaintext bodies for every received message live here until
    /// the cap evicts them. SecretBox wrapping of the `body` field is
    /// tracked in issue #37, item 3.
    store: MessageStore,
    /// Low-level I/O client used solely to pulse the vibe motor on
    /// inbound messages — a physical cue that works regardless of
    /// which app holds GAM focus. Hosted mode routes to llio's
    /// emulated backend (no-op).
    llio: llio::Llio,
    /// Index of the focused row when [`Screen::Home`] is active.
    home_focus: usize,
    /// Active compose buffer when [`Screen::Thread`] is on top.
    /// Cleared when the user sends or backs out. The filter
    /// [`is_compose_char`] gates which keystrokes append; non-ASCII
    /// (emoji, accented chars, CJK) is silently dropped today.
    ///
    /// # Security
    ///
    /// Holds plaintext the user has typed but not yet sent. Cleared
    /// on send via `mem::take`, but the captured `String` is then
    /// passed to `Cmd::SendMessage` (also plaintext) before the
    /// worker encrypts it. Do not log this field; do not surface it
    /// in error paths.
    compose_buffer: String,
    /// One-line text rendered on transient screens (Linked banner,
    /// SendError surface, SignalAuthExpired banner). Cleared on
    /// transition back to a normal screen.
    last_status: String,
    /// `true` between `Cmd::LinkDevice` send and the terminal
    /// `Event::Link{Complete,Error}`. While set,
    /// [`handle_worker_event`] opens the QR modal on `LinkUrl` and
    /// transitions on `LinkComplete`/`LinkError`; once cleared,
    /// late-arriving link events are dropped on the floor (the user
    /// has navigated away).
    linking_in_progress: bool,
    /// Cursor on [`Screen::Settings`].
    settings_selected: SettingsItem,
    /// Device name confirmed by the linked phone (from
    /// `Event::LinkComplete` or `Event::AccountInfo`). `None` on a
    /// cold start until either event arrives.
    ///
    /// # Security
    ///
    /// PII. Display-only; never log this beyond the existing
    /// structured trace line.
    account_device_name: Option<String>,
    /// ACI (Signal account UUID) for the linked account.
    ///
    /// # Security
    ///
    /// PII. Same logging discipline as `account_device_name`.
    account_aci: Option<String>,
    /// E.164 phone number for the linked account.
    ///
    /// # Security
    ///
    /// PII. Same logging discipline as `account_device_name`.
    account_phone: Option<String>,
    /// A `Cmd::GetAccountInfo` is in flight. Distinguishes "not linked"
    /// from "do not know yet", which the header must not conflate.
    account_query_pending: bool,
    /// `true` between `Cmd::ResolveUsername` send and the
    /// corresponding `Event::UsernameResolveResult`. Suppresses
    /// concurrent lookups and gates
    /// [`handle_username_resolve_result`] so a stale response after
    /// the user navigated away is dropped silently.
    username_lookup_in_progress: bool,
    /// Username being resolved, kept so the thread can be labelled with
    /// what the user typed instead of a UUID prefix.
    username_lookup_pending: Option<String>,
}

impl App {
    /// Wipe link-derived state back to the pre-link Menu: linked
    /// flag, message store, focus/compose/link-progress state, and
    /// the cached account tuple. Shared by the `Event::LoggedOut`,
    /// `Event::SignalAuthExpired`, and
    /// `Event::SignalConflictingDevice` arms — the caller sets (or
    /// clears) `last_status` for its specific banner and triggers
    /// the re-render.
    fn reset_to_unlinked(&mut self) {
        self.linked = false;
        self.store.clear();
        self.home_focus = 0;
        self.compose_buffer.clear();
        self.linking_in_progress = false;
        // Also drop any in-flight username lookup: a stale
        // Event::UsernameResolveResult arriving after the wipe would
        // otherwise pass handle_username_resolve_result's staleness
        // guard and open a Thread screen (or clobber the re-link
        // banner) on an unlinked app.
        self.username_lookup_in_progress = false;
        self.username_lookup_pending = None;
        self.account_device_name = None;
        self.account_aci = None;
        self.account_phone = None;
        self.screen = Screen::Menu;
        self.selected = MenuItem::Link;
    }

    fn menu_items(&self) -> [Option<MenuItem>; 4] {
        if self.linked {
            // Post-link Menu is reachable from Home (via the Menu key)
            // for the few utility actions that don't have a dedicated
            // F-key. Settings (F4) is the main post-link surface, and
            // carries Logout — the post-link name for a store wipe.
            [Some(MenuItem::About), Some(MenuItem::Help), None, None]
        } else {
            // Pre-link Menu IS the landing screen. The typed-'yes'
            // modal, not the cursor position, guards the wipe.
            [Some(MenuItem::Link), Some(MenuItem::About), Some(MenuItem::Help), Some(MenuItem::WipeSettings)]
        }
    }

    /// Move the cursor by `delta` (+1 = down, -1 = up) wrapping
    /// around the visible items.
    fn move_cursor(&mut self, delta: isize) {
        let items = self.menu_items();
        let visible: Vec<MenuItem> = items.iter().flatten().copied().collect();
        if visible.is_empty() {
            return;
        }
        let idx = visible.iter().position(|m| *m == self.selected).unwrap_or(0);
        let len = visible.len() as isize;
        let new = (idx as isize + delta).rem_euclid(len);
        self.selected = visible[new as usize];
    }

    fn render(&self) -> Result<(), String> {
        self.gam
            .draw_rectangle(
                self.content,
                Rectangle::new_with_style(
                    Point::new(0, 0),
                    self.bounds,
                    DrawStyle { fill_color: Some(PixelColor::Light), stroke_color: None, stroke_width: 0 },
                ),
            )
            .map_err(|e| format!("draw_rectangle: {:?}", e))?;

        let mut tv = TextView::new(
            self.content,
            TextBounds::BoundingBox(Rectangle::new(
                Point::new(8, 8),
                Point::new(self.bounds.x - 8, self.bounds.y - 8),
            )),
        );
        tv.border_width = 1;
        tv.draw_border = true;
        tv.clear_area = true;
        tv.rounded_border = Some(3);
        // Bold on the conversation-list and thread screens for
        // legibility — those are the primary surfaces. Other transient
        // screens (About, Linked banner, Linking) keep Regular.
        tv.style = match self.screen {
            Screen::Home | Screen::Thread { .. } => GlyphStyle::Bold,
            _ => GlyphStyle::Regular,
        };

        match &self.screen {
            Screen::Menu => self.write_menu(&mut tv.text)?,
            Screen::About => write!(
                tv.text,
                "About xas\n\n\
                 Unofficial Signal client\n\
                 for Xous on Precursor.\n\n\
                 Version: {}\n\
                 Author:  @tunnell\n\n\
                 github.com/tunnell/\n\
                  xous-app-signal\n\n\
                 What xas protects:\n\
                  - Messages are end-to-end\n\
                    encrypted via the Signal\n\
                    Protocol (the same Double\n\
                    Ratchet and post-quantum\n\
                    key agreement the official\n\
                    Signal app uses).\n\
                  - The connection to\n\
                    chat.signal.org is\n\
                    verified against Signal's\n\
                    own pinned Certificate\n\
                    Authority. The public\n\
                    web certificate bundle\n\
                    on your device is not\n\
                    trusted.\n\
                  - On Precursor every layer\n\
                    of hardware and software\n\
                    is inspectable. Keys are\n\
                    generated on the device\n\
                    and sealed there; they\n\
                    do not leave.\n\n\
                 What xas does NOT protect:\n\
                  - The phone you linked\n\
                    from. If your phone is\n\
                    compromised, the attacker\n\
                    can read messages out of\n\
                    Signal's plaintext buffer\n\
                    after they're decrypted.\n\
                  - Physical seizure plus\n\
                    knowledge of your PDDB\n\
                    passphrase.\n\
                  - Traffic-analysis: the\n\
                    fact that you're talking\n\
                    to chat.signal.org is\n\
                    visible to your network\n\
                    operator, even though\n\
                    contents aren't.\n\
                  - Disappearing-message\n\
                    timers (not yet shown).\n\n\
                 Built on:\n\
                  - presage v0.8.0-dev\n\
                  - libsignal-service-rs\n\
                  - libsignal v0.91.0\n\n\
                 Limitations (alpha):\n\
                  - No group chats\n\
                  - No attachments\n\
                  - Send takes 1-4 minutes\n\
                    (transport refactor\n\
                    pending)\n\
                  - 2.4 GHz Wi-Fi only\n\n\
                 Press Enter to return.",
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|e| format!("write About: {}", e))?,
            Screen::Linking => write!(
                tv.text,
                "Linking device...\n\n\
                 Connecting to Signal's servers and requesting a \
                 provisioning URL.\n\n\
                 The Signal server's certificate is verified against \
                 Signal's own pinned Certificate Authority. The public \
                 web certificate bundle on your device is not trusted \
                 for this.\n\n\
                 Linking takes a few minutes after you scan the QR. \
                 Don't power-cycle.\n\n\
                 Press Backspace to cancel.\n\n\
                 (Please wait.)"
            )
            .map_err(|e| format!("write Linking: {}", e))?,
            Screen::Wiping => write!(
                tv.text,
                "Wiping stored Signal data...\n\nThis can take a minute.\nDo not power off the device.",
            )
            .map_err(|e| format!("write Wiping: {}", e))?,
            Screen::Linked { kind } => {
                let title = match kind {
                    LinkedKind::Success => "Link succeeded",
                    LinkedKind::Failure => "Link failed",
                };
                let first_use_note = match kind {
                    // Key provisioning continues in the background; the
                    // first send queues behind it. Receive settles first.
                    LinkedKind::Success => {
                        "\n\nNote: first receive/send can take\nseveral minutes while key\nprovisioning finishes. Try\nreceiving first; later sends\nare fast."
                    }
                    LinkedKind::Failure => "",
                };
                write!(
                    tv.text,
                    "{}\n\n{}{}\n\nPress Enter to continue.",
                    title, self.last_status, first_use_note
                )
                .map_err(|e| format!("write Linked: {}", e))?
            }
            Screen::Home => self.write_home(&mut tv.text)?,
            Screen::Thread { uuid } => self.write_thread(&mut tv.text, uuid)?,
            Screen::Settings => self.write_settings(&mut tv.text)?,
            Screen::Profile => self.write_profile(&mut tv.text)?,
            Screen::Help => self.write_help(&mut tv.text)?,
            Screen::NoInternet { reason, .. } => self.write_no_internet(&mut tv.text, reason)?,
        }

        self.gam.post_textview(&mut tv).map_err(|e| format!("post_textview: {:?}", e))?;
        self.gam.redraw().map_err(|e| format!("redraw: {:?}", e))?;
        Ok(())
    }

    /// Which account this device is acting as, for the screen headers.
    /// `(unlinked)` is a claim, not a default: it is shown only once a
    /// lookup has actually come back saying so. While one is in flight,
    /// or we are linked but the fields have not arrived, say so.
    fn identity_line(&self) -> String {
        if self.account_query_pending {
            return "(loading linked account…)".to_string();
        }
        match (self.linked, self.account_phone.as_deref(), self.account_device_name.as_deref()) {
            (true, Some(phone), Some(name)) => format!("{}  ({})", phone, name),
            (true, Some(phone), None) => phone.to_string(),
            (true, None, _) => "(loading linked account…)".to_string(),
            (false, _, _) => "(unlinked)".to_string(),
        }
    }

    fn write_menu(&self, out: &mut String) -> Result<(), String> {
        let header = if self.linked { "Signal — linked" } else { "xas — Signal client" };
        write!(out, "{}\n{}\n\n", header, self.identity_line()).map_err(|e| format!("hdr: {}", e))?;
        for maybe in self.menu_items() {
            if let Some(item) = maybe {
                let mark = if item == self.selected { ">" } else { " " };
                let label = match item {
                    MenuItem::Link => "Link device",
                    MenuItem::About => "About",
                    MenuItem::Help => "Help",
                    MenuItem::WipeSettings => "Wipe settings",
                };
                write!(out, "{} {}\n", mark, label).map_err(|e| format!("item: {}", e))?;
            }
        }
        write!(out, "\nUp/Down: navigate\nEnter: select").map_err(|e| format!("foot: {}", e))
    }

    /// Render the conversation-list screen.
    ///
    /// Layout per row (single-TextView text mode):
    /// ```text
    ///   Bob                    12m
    /// * did you get the file?           (1)
    /// ───────────────────────────────────────
    /// > Carol                            1h
    ///   Thanks!
    /// ```
    /// `>` marks the focused row, `*` marks unread. The right-aligned
    /// timestamp comes from [`crate::dialogue::brief_relative`]; the
    /// trailing unread count is shown in `(N)` form; the second
    /// line previews the latest message with an optional outgoing
    /// status glyph.
    ///
    /// # Security
    ///
    /// Renders plaintext message snippets. Do not extend this method
    /// to emit log lines containing the snippet body or sender label.
    fn write_home(&self, out: &mut String) -> Result<(), String> {
        let total_unread: u32 = self.store.total_unread();
        if total_unread > 0 {
            writeln!(out, "xas                       {} unread", total_unread)
                .map_err(|e| format!("home hdr: {}", e))?;
        } else {
            writeln!(out, "xas").map_err(|e| format!("home hdr: {}", e))?;
        }
        writeln!(out, "{}", self.identity_line()).map_err(|e| format!("home ident: {}", e))?;
        writeln!(out, "{}", "-".repeat(45)).map_err(|e| format!("home rule: {}", e))?;

        if self.store.dialogues().is_empty() {
            writeln!(out).map_err(|e| format!("home empty: {}", e))?;
            writeln!(out, "      No conversations yet.").map_err(|e| format!("home empty: {}", e))?;
            writeln!(out).map_err(|e| format!("home empty: {}", e))?;
            writeln!(out, "  Wait for someone to message,").map_err(|e| format!("home empty: {}", e))?;
            writeln!(out, "  or press F1 to start one.").map_err(|e| format!("home empty: {}", e))?;
            writeln!(out).map_err(|e| format!("home empty: {}", e))?;
            writeln!(out, "  F1 New  F2 Sync  F3 Help  F4 Settings")
                .map_err(|e| format!("home empty: {}", e))?;
            return Ok(());
        }

        let now_ms = unix_now_ms();
        // Clamp focus index in case the list shrank.
        let focus = self.home_focus.min(self.store.dialogues().len().saturating_sub(1));

        for (i, d) in self.store.dialogues().iter().enumerate() {
            let focus_marker = if i == focus { '>' } else { ' ' };
            let unread_marker = if d.unread_count > 0 { '*' } else { ' ' };
            let timestamp = crate::dialogue::brief_relative(d.last_msg_ts, now_ms);

            // Group threads are labeled so a room never masquerades
            // as a 1:1 (display_name is the last speaker's name).
            let name =
                if d.is_group { format!("[group] {}", d.display_name) } else { d.display_name.clone() };
            let name_short = crate::dialogue::ellipsize(&name, 24);
            // First line: focus, name, right-padded timestamp.
            writeln!(out, "{} {:<24} {:>6}", focus_marker, name_short, timestamp)
                .map_err(|e| format!("home row name: {}", e))?;

            // Second line: unread marker, status glyph, snippet, count.
            let status_glyph = match (d.last_msg_outgoing, d.last_msg_status) {
                (true, SendStatus::Pending) => "..",
                (true, SendStatus::Sent) => "v ",
                (true, SendStatus::Delivered) => "vv",
                (true, SendStatus::Failed) => "! ",
                _ => "  ",
            };
            let snippet_short = crate::dialogue::ellipsize(&d.last_msg_snippet, 26);
            let badge = if d.unread_count > 0 {
                let n = d.unread_count.min(99);
                format!("({})", n)
            } else {
                String::new()
            };
            writeln!(out, "{} {} {:<26} {:>4}", unread_marker, status_glyph, snippet_short, badge)
                .map_err(|e| format!("home row body: {}", e))?;

            writeln!(out, "{}", "-".repeat(45)).map_err(|e| format!("home sep: {}", e))?;
        }
        writeln!(out).map_err(|e| format!("home foot: {}", e))?;
        write!(out, "  ↑↓ Sel  Enter Open\n  F1 New  F2 Sync  F3 Help  F4 Settings")
            .map_err(|e| format!("home hint: {}", e))
    }

    /// Render the per-conversation history view plus the in-screen
    /// compose box.
    ///
    /// Layout:
    /// ```text
    /// Bob
    /// -------------------------------------
    /// Bob 12m
    ///   did you get the file?
    ///
    /// You 11m  vv
    ///   yes, on my way
    ///
    /// Bob 5m
    ///   thanks!
    /// -------------------------------------
    ///   Enter: back to Home
    /// ```
    /// Messages oldest at top, newest just above the footer (mirrors
    /// every chat UI). Outgoing messages carry a send-status glyph;
    /// incoming messages have no prefix.
    ///
    /// # Security
    ///
    /// Renders decrypted message bodies and sender labels. The
    /// caller (`render`) writes the output into a GAM `TextView`
    /// that is rendered to the framebuffer; no body or label leaves
    /// the screen surface.
    fn write_thread(&self, out: &mut String, uuid: &Uuid) -> Result<(), String> {
        let summary = self.store.dialogues().iter().find(|d| d.uuid == *uuid);
        let is_group = summary.is_some_and(|d| d.is_group);
        let name = summary
            .map(|d| d.display_name.clone())
            .unwrap_or_else(|| format!("uuid:{:.8}", uuid.simple().to_string()));
        let header = if is_group { format!("[group] {}", name) } else { name };
        writeln!(out, "{}", header).map_err(|e| format!("thread hdr: {}", e))?;
        writeln!(out, "{}", "-".repeat(45)).map_err(|e| format!("thread rule: {}", e))?;

        let now_ms = unix_now_ms();
        let thread_msgs: Vec<&ThreadMessage> = self.store.thread_messages(*uuid).collect();

        if thread_msgs.is_empty() {
            writeln!(out).map_err(|e| format!("thread empty: {}", e))?;
            writeln!(out, "  (no messages in this thread)").map_err(|e| format!("thread empty: {}", e))?;
        } else {
            for m in &thread_msgs {
                let ts = crate::dialogue::brief_relative(m.timestamp, now_ms);
                let header_line = if m.outgoing {
                    let glyph = match m.status {
                        SendStatus::Pending => "..",
                        SendStatus::Sent => "v ",
                        SendStatus::Delivered => "vv",
                        SendStatus::Failed => "! ",
                    };
                    format!("You {}  {}", ts, glyph)
                } else {
                    format!("{} {}", crate::dialogue::ellipsize(&m.author_label, 22), ts)
                };
                writeln!(out, "{}", header_line).map_err(|e| format!("thread row hdr: {}", e))?;
                writeln!(out, "  {}", crate::dialogue::ellipsize(&m.body, 70))
                    .map_err(|e| format!("thread row body: {}", e))?;
                writeln!(out).map_err(|e| format!("thread row sep: {}", e))?;
            }
        }
        writeln!(out, "{}", "-".repeat(45)).map_err(|e| format!("thread foot rule: {}", e))?;
        if is_group {
            // Reply-block: xas's send path can only address a single
            // contact, so a "reply" here would go out as a private
            // 1:1 DM to whichever member last spoke. Refuse loudly
            // rather than mis-deliver (send_compose enforces this;
            // the line here explains it).
            writeln!(out, "Group chat: reply not supported yet")
                .map_err(|e| format!("thread group note: {}", e))?;
            write!(out, "Enter/Esc Back  F4 Settings").map_err(|e| format!("thread hint: {}", e))?;
            return Ok(());
        }
        // Compose input. Cursor glyph is the trailing `_`; if the
        // buffer is wider than the visible width the ellipsizer
        // shows only the leading slice — there is no horizontal
        // scroll today.
        writeln!(out, "> {}_", crate::dialogue::ellipsize(&self.compose_buffer, 30))
            .map_err(|e| format!("thread compose: {}", e))?;
        write!(out, "Enter Send  Esc Back  F4 Settings").map_err(|e| format!("thread hint: {}", e))?;
        Ok(())
    }

    fn settings_items(&self) -> [SettingsItem; 4] {
        [SettingsItem::Profile, SettingsItem::Help, SettingsItem::About, SettingsItem::Logout]
    }

    fn settings_move(&mut self, delta: isize) {
        let items = self.settings_items();
        let idx = items.iter().position(|s| *s == self.settings_selected).unwrap_or(0);
        let len = items.len() as isize;
        let new = (idx as isize + delta).rem_euclid(len);
        self.settings_selected = items[new as usize];
    }

    fn write_settings(&self, out: &mut String) -> Result<(), String> {
        write!(out, "Settings\n\n").map_err(|e| format!("set hdr: {}", e))?;
        for item in self.settings_items() {
            let mark = if item == self.settings_selected { ">" } else { " " };
            let label = match item {
                SettingsItem::Profile => "Profile",
                SettingsItem::Help => "Help",
                SettingsItem::About => "About",
                SettingsItem::Logout => "Logout",
            };
            writeln!(out, "{} {}", mark, label).map_err(|e| format!("set item: {}", e))?;
        }
        write!(out, "\n↑↓ Sel  Enter Open  Esc Back").map_err(|e| format!("set foot: {}", e))
    }

    fn write_profile(&self, out: &mut String) -> Result<(), String> {
        let none = "(not loaded)";
        let device = self.account_device_name.as_deref().unwrap_or(none);
        let phone = self.account_phone.as_deref().unwrap_or(none);
        let aci = self.account_aci.as_deref().unwrap_or(none);
        write!(
            out,
            "Profile\n\n\
             Name:     {}\n\
             Number:   {}\n\
             Username: (not available)\n\n\
             ACI:      {}\n\n\
             (Username read isn't exposed\n\
              by libsignal; the primary\n\
              phone holds that state.)\n\n\
             Press Enter to return.",
            device, phone, aci,
        )
        .map_err(|e| format!("profile: {}", e))
    }

    fn write_help(&self, out: &mut String) -> Result<(), String> {
        write!(
            out,
            "Help\n\n\
             xas — Signal client for Precursor (Xous OS). \
             Status: alpha.\n\n\
             Wi-Fi (do this first, in shellchat, before opening xas):\n\
               wlan off\n\
               wlan on\n\
               ssid scan\n\
               wlan status   (until 'Connected')\n\
               net ping 1.1.1.1\n\
             Use one SSID only — no roaming support yet.\n\n\
             Known limits:\n\
              - Send may fail (WS keepalive)\n\
              - No group chats\n\
              - No images / attachments\n\
              - No history scroll / search\n\n\
             File a bug: github.com/tunnell/xous-app-signal/issues\n\n\
             Full FAQ: see FAQ.md in repo.\n\n\
             Press Enter to return."
        )
        .map_err(|e| format!("help: {}", e))
    }

    fn write_no_internet(&self, out: &mut String, reason: &str) -> Result<(), String> {
        write!(
            out,
            "No internet\n\n\
             {}\n\n\
             Connect Wi-Fi from shellchat (run there, not here):\n\n\
               wlan off\n\
               wlan on\n\
               ssid scan\n\
               wlan status   (until 'Connected')\n\
               net ping 1.1.1.1\n\n\
             2.4 GHz networks only — 5 GHz isn't supported. \
             Use a saved SSID, or set one with `wlan setssid` and \
             `wlan setpass`.\n\n\
             Press Enter to retry.",
            reason
        )
        .map_err(|e| format!("no-internet: {}", e))
    }
}

/// Whether a character is acceptable in the Thread compose buffer.
///
/// Accepts alphanumeric, space, and ASCII punctuation. Non-ASCII
/// (emoji, accented chars, CJK) is silently dropped to match the
/// font set the GAM renderer currently exposes; widening this
/// filter is straightforward once the font has the glyphs.
fn is_compose_char(c: char) -> bool { c.is_alphanumeric() || c == ' ' || c.is_ascii_punctuation() }

/// If `XAS_MOCK_MESSAGES=1` is set in the environment, seed `App`
/// with a small fake conversation history so hosted-mode UI work
/// can iterate on a populated Home + Thread without needing real
/// signal-cli traffic. Linked state is set to `true` and the
/// initial screen becomes [`Screen::Home`].
///
/// The variable is harmless on rv32 (no env, so the path simply
/// returns without seeding) — kept here without `cfg`-gating so
/// hosted and on-device builds share one source-of-truth helper.
fn seed_mock_messages_if_requested(app: &mut App) {
    if std::env::var("XAS_MOCK_MESSAGES").ok().as_deref() != Some("1") {
        return;
    }
    log::info!("xas/gam_app: XAS_MOCK_MESSAGES=1 — seeding mock history");

    let now_ms = unix_now_ms();
    let alice = Uuid::from_u128(0x0a11ce_aaaaaa_bbbbbb_cccccc_dddddd_001);
    let bob = Uuid::from_u128(0x0b0b_bbbbbb_cccccc_dddddd_eeeeee_002);
    let dad = Uuid::from_u128(0xdad0_cccccc_dddddd_eeeeee_ffffff_003);
    let unknown = Uuid::from_u128(0x9999_dddddd_eeeeee_ffffff_111111_004);
    // Pseudo-thread uuid a GV2 group would file under (derived from
    // a mock master key the same way handle_worker_event does it).
    let party = Uuid::new_v5(&Uuid::NAMESPACE_OID, &[0x42u8; 32]);

    let mocks: &[(Uuid, &str, &str, u64, bool, SendStatus, bool)] = &[
        (alice, "Alice", "sure, meet at 6", 2 * 60_000, false, SendStatus::Sent, false),
        (alice, "Alice", "I'll bring drinks", 1 * 60_000, false, SendStatus::Sent, false),
        (alice, "Alice", "actually make it 6:30", 30_000, false, SendStatus::Sent, false),
        (bob, "Bob", "did you get the file?", 12 * 60_000, false, SendStatus::Sent, false),
        (bob, "You", "yes, on my way", 11 * 60_000, true, SendStatus::Delivered, false),
        (bob, "Bob", "thanks!", 5 * 60_000, false, SendStatus::Sent, false),
        (dad, "Dad", "lunch sunday?", 25 * 60 * 60_000, false, SendStatus::Sent, false),
        (dad, "You", "On my way", 24 * 60 * 60_000, true, SendStatus::Delivered, false),
        (unknown, "+14155550199", "Your Uber has arrived", 3 * 60 * 60_000, false, SendStatus::Sent, false),
        (unknown, "+14155550199", "Your driver is waiting", 2 * 60 * 60_000, false, SendStatus::Sent, false),
        (party, "Bob", "the party is off", 8 * 60_000, false, SendStatus::Sent, true),
        (party, "Carol", "aw, next week then?", 7 * 60_000, false, SendStatus::Sent, true),
    ];

    app.store.seed(mocks.iter().map(|(uuid, label, body, age_ms, outgoing, status, group)| {
        ThreadMessage {
            uuid: *uuid,
            author_label: label.to_string(),
            body: body.to_string(),
            timestamp: now_ms.saturating_sub(*age_ms),
            outgoing: *outgoing,
            status: *status,
            read: *outgoing, // outgoing always read; incoming starts unread
            group: *group,
        }
    }));
    // Mark linked + jump straight into Home so the demo lands on the
    // populated conversation list rather than the pre-link Welcome.
    app.linked = true;
    app.screen = Screen::Home;
    app.home_focus = 0;
}

/// Unix milliseconds, or 0 if the system clock is before the epoch.
///
/// Used by the conversation-list renderer to compute relative
/// timestamps, and by `Cmd::SendMessage` to stamp outbound messages.
/// The 0 fallback is benign: a 0 timestamp simply renders as `0s` /
/// `(very long ago)`.
fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Fire the optimistic send flow for the compose buffer: take the
/// buffer, stamp a send timestamp, append a `Pending` row to the
/// store (so the Thread render shows it immediately), and dispatch
/// `Cmd::SendMessage`. If the command channel is closed, the
/// optimistic row is flipped to `Failed` in place.
///
/// Shared by the Enter and F1 send arms of `handle_keys`; `trigger`
/// only varies the UART log line ("send" vs "F1 send"). Caller
/// guarantees the compose buffer is non-empty.
fn send_compose(app: &mut App, cmd_tx: &Sender<Cmd>, recipient_uuid: Uuid, trigger: &str) {
    // Group reply-block. The send path addresses exactly one
    // contact (`Thread::Contact` in the worker); "replying" to a
    // group thread would deliver a private 1:1 DM to a single
    // member while the user believes they addressed the room.
    // Refuse and say so — never silently drop, never mis-deliver.
    if app.store.is_group_thread(recipient_uuid) {
        log::info!("xas/gam_app: {} blocked — group thread, 1:1 send would misdeliver", trigger);
        app.last_status = "Group reply not supported yet".to_string();
        return;
    }
    let body = std::mem::take(&mut app.compose_buffer);
    let send_ts = unix_now_ms();
    let recipient_str = recipient_uuid.to_string();
    log::info!("xas/gam_app: {} to={} ({} body bytes) ts={}", trigger, recipient_str, body.len(), send_ts,);
    app.store.push_outgoing_pending(recipient_uuid, body.clone(), send_ts);
    if let Err(e) =
        cmd_tx.send_blocking(Cmd::SendMessage { recipient: recipient_str, body, timestamp: send_ts })
    {
        log::warn!("xas/gam_app: Cmd::SendMessage send err: {:?}", e);
        app.store.mark_send_failed(send_ts);
    }
}

/// `true` if `s` matches the Signal "username" shape: a non-empty
/// nickname (3-32 chars, ASCII alphanumeric or `_`) followed by
/// `.` and 2-9 digits, e.g. `alice.42`.
///
/// Used only for classifying user input in the New Chat modal so
/// the rejection message can be specific; the server validates the
/// real format on resolution.
fn looks_like_signal_username(s: &str) -> bool {
    let (nick, rest) = match s.split_once('.') {
        Some(parts) => parts,
        None => return false,
    };
    if !(3..=32).contains(&nick.len()) {
        return false;
    }
    if !nick.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    if !(2..=9).contains(&rest.len()) {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_digit())
}

/// Pre-link "Wipe settings" — see [`drive_wipe_settings`]; this is
/// the post-link entry point to the same `Cmd::Logout` wipe.
///
/// Settings → Logout. Confirms with the user, then sends
/// `Cmd::Logout` and lets the forwarder + [`handle_worker_event`]
/// pick up the resulting `Event::LoggedOut` (or, on partial
/// failure, a warning log line from the worker followed by
/// `Event::LoggedOut` anyway; surfacing partial wipes more).
///
/// # Security
///
/// Logout wipes Signal-Protocol state in the PDDB. Failure paths
/// here are limited to "Modals init failed" or "Cmd channel
/// closed" — neither of which leaks state — but the worker-side
/// wipe surface is not yet enforced as all-or-nothing.
/// Pre-link "Wipe settings": `Cmd::Logout` from the main menu, for a
/// store left stale by an earlier session.
///
/// PDDB frees a page at a time and, with `mbbb`, rewrites the page
/// table around every entry — roughly 25 flash sector operations per
/// 17 KiB record. A store holding a few hundred such records grinds
/// for ten minutes or more, most of it below `log::info`, so both the
/// UART and the screen look idle. Hence [`Screen::Wiping`] and a modal
/// that promises minutes, not a minute.
///
/// # Security
///
/// As `Cmd::Logout`: not atomic across dictionaries, and the PDDB does
/// not zero freed pages. Logical wipe, not secure erase.
fn drive_wipe_settings(app: &mut App, cmd_tx: &Sender<Cmd>, modals_xns: &xous_names::XousNames) {
    let modals = match modals::Modals::new(modals_xns) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("xas/gam_app: drive_wipe_settings - Modals init err: {:?}", e);
            return;
        }
    };
    let confirm = modals
        .alert_builder(
            "Wipe settings?\n\nErases link state, keys,\ncontacts and profiles.\nStored message history\nis NOT erased.\n\nRuns for minutes and\nthe device stays busy.\nDo not power off.\n\nYou will need to scan\nthe QR code again.",
        )
        .field(Some("type 'yes' to confirm".to_string()), None)
        .build();
    let confirmed = match confirm {
        Ok(payloads) => payloads.first().as_str().trim().eq_ignore_ascii_case("yes"),
        Err(_) => false,
    };
    if !confirmed {
        log::info!("xas/gam_app: Wipe settings cancelled");
        return;
    }
    log::info!("xas/gam_app: Wipe settings confirmed; sending Cmd::Logout");
    // Draw before the worker starts: a grinding PDDB starves the rest
    // of the device, and a frame that never lands reads as a freeze.
    // render() touches GAM only.
    app.screen = Screen::Wiping;
    app.render().ok();
    if let Err(e) = cmd_tx.send_blocking(Cmd::Logout) {
        log::warn!("xas/gam_app: Cmd::Logout (wipe) send err: {:?}", e);
        app.screen = Screen::Menu;
        app.render().ok();
        let _ = modals.show_notification(
            "Wipe failed:\n\
             worker not reachable.\n\
             The app may need a restart.",
            None,
        );
    }
}

fn drive_logout(cmd_tx: &Sender<Cmd>, modals_xns: &xous_names::XousNames) {
    let modals = match modals::Modals::new(modals_xns) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("xas/gam_app: drive_logout — Modals init err: {:?}", e);
            return;
        }
    };
    // Confirm modal first — Logout is irreversible without re-linking
    // (which means another QR-scan ceremony with the phone).
    let confirm = modals
        .alert_builder("Logout?\nThis wipes link state.\nYou will need to scan\nthe QR code again.")
        .field(Some("type 'yes' to confirm".to_string()), None)
        .build();
    let confirmed = match confirm {
        Ok(payloads) => payloads.first().as_str().trim().eq_ignore_ascii_case("yes"),
        Err(_) => false,
    };
    if !confirmed {
        log::info!("xas/gam_app: Logout cancelled");
        return;
    }
    log::info!("xas/gam_app: Logout confirmed; sending Cmd::Logout");
    if let Err(e) = cmd_tx.send_blocking(Cmd::Logout) {
        log::warn!("xas/gam_app: Cmd::Logout send err: {:?}", e);
        let _ = modals.show_notification(
            "Logout failed:\n\
             worker not reachable.\n\
             The app may need a restart.",
            None,
        );
    }
    // Don't transition here; wait for Event::LoggedOut to arrive via
    // the forwarder, where handle_worker_event will reset App state.
}

/// F1 on Home: prompt for a UUID or username and open an empty
/// thread for it. The compose box becomes the entry point; the
/// thread becomes a real conversation as soon as a message goes
/// out or comes back.
///
/// Three input shapes are accepted:
///
/// - UUID (immediate, no server round-trip).
/// - Username (`name.000` form; resolved via `Cmd::ResolveUsername` and the matching `Event` reply).
/// - E.164 phone (rejected — CDSI is not available in this build; see the inline comment on the `+`-prefixed
///   branch).
///
/// # Trust boundary
///
/// The username path crosses the network: it routes through the
/// worker, then through libsignal-service's username-resolution
/// endpoint over the TLS-pinned Signal connection. The other two
/// paths are local-only.
fn drive_new_chat(app: &mut App, cmd_tx: &Sender<Cmd>, modals_xns: &xous_names::XousNames) {
    let modals = match modals::Modals::new(modals_xns) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("xas/gam_app: F1 new chat — Modals::new err {:?}", e);
            return;
        }
    };
    let raw = match modals.alert_builder("New chat — username (name.000)").field(None, None).build() {
        Ok(payloads) => payloads.first().as_str().trim().to_string(),
        Err(e) => {
            log::info!("xas/gam_app: F1 new chat cancelled / err: {:?}", e);
            return;
        }
    };
    if raw.is_empty() {
        return;
    }
    // Three input shapes: UUID (immediate, no server round-trip);
    // username "name.000" (server round-trip via Cmd::ResolveUsername
    // → Event::UsernameResolveResult); +E.164 (would need CDSI which
    // is disabled in this build because boring-sys can't target rv32).
    if let Ok(uuid) = Uuid::parse_str(&raw) {
        app.screen = Screen::Thread { uuid };
        app.compose_buffer.clear();
        return;
    }
    if looks_like_signal_username(&raw) {
        if app.username_lookup_in_progress {
            let _ = modals.show_notification("Already looking up a\nusername; please wait.", None);
            return;
        }
        log::info!("xas/gam_app: F1 username lookup {:?}", raw);
        if let Err(e) = cmd_tx.send_blocking(Cmd::ResolveUsername(raw.clone())) {
            log::warn!("xas/gam_app: Cmd::ResolveUsername send err: {:?}", e);
            let _ = modals.show_notification("Lookup failed:\nworker not reachable.", None);
            return;
        }
        app.username_lookup_in_progress = true;
        app.username_lookup_pending = Some(raw.clone());
        // Brief visual feedback. The Event::UsernameResolveResult
        // arrives via the forwarder and is handled by
        // handle_username_resolve_result, which transitions to
        // Screen::Thread on success or sets app.last_status on failure.
        let _ = modals.show_notification(&format!("Looking up\n{}\non the server...", raw), None);
        return;
    }
    if raw.starts_with('+') && raw.len() > 1 && raw[1..].chars().all(|c| c.is_ascii_digit()) {
        // Phone-number lookup needs CDSI (Signal's contact-discovery
        // service over SGX/Intel-attested enclaves). The libsignal-
        // service-rs cdsi feature pulls boring-sys (BoringSSL) which
        // doesn't target rv32-xous, so the feature is disabled in
        // this build: every consumer sets default-features = false
        // on libsignal-service (see docs/FORKS.md, CDSI rule).
        log::info!("xas/gam_app: F1 phone lookup not supported (CDSI disabled)");
        let _ = modals.show_notification(
            "Phone numbers are not\n\
             supported. Ask for their\n\
             username instead\n\
             (looks like name.000).",
            None,
        );
        return;
    }
    log::info!("xas/gam_app: F1 unrecognized input {:?}", raw);
    let _ = modals.show_notification("Not a username.\nFormat: name.000", None);
}

/// Run the GAM-rendered UI loop.
///
/// Registers the xas SID under [`SERVER_NAME_XAS`], constructs the
/// GAM `UxRegistration`, spawns the event-forwarder thread that
/// bridges `event_rx` into the GAM IPC loop, builds the [`App`],
/// and dispatches incoming GAM messages until the binary exits.
///
/// # Trust boundary
///
/// Called from `main.rs` after the worker is spawned. From this
/// point on the UI owns the `cmd_tx` / `event_rx` channels and is
/// the sole consumer of `event_rx` (the forwarder thread that
/// `run` spawns is the one consumer).
///
/// # Errors
///
/// Returns `Err(String)` describing the failing call when initial
/// GAM setup (`XousNames::new`, `register_name`, `register_ux`,
/// canvas request) fails. The receive loop itself only returns on
/// fatal IPC error; the typical exit path is the binary process
/// being torn down by the Xous shell.
pub fn run(cmd_tx: Sender<Cmd>, event_rx: Receiver<Event>) -> Result<(), String> {
    log::info!("xas/gam_app: starting GAM-rendered loop");

    let xns = xous_names::XousNames::new().map_err(|e| format!("XousNames::new: {:?}", e))?;
    let sid = xns.register_name(SERVER_NAME_XAS, None).map_err(|e| format!("register_name: {:?}", e))?;

    let gam = gam::Gam::new(&xns).map_err(|e| format!("Gam::new: {:?}", e))?;
    let token = gam
        .register_ux(gam::UxRegistration {
            app_name: String::from(gam::APP_NAME_XAS),
            ux_type: gam::UxType::Chat,
            predictor: None,
            listener: sid.to_array(),
            redraw_id: XasOp::Redraw.to_u32().unwrap(),
            gotinput_id: None,
            audioframe_id: None,
            rawkeys_id: Some(XasOp::Rawkeys.to_u32().unwrap()),
            focuschange_id: Some(XasOp::FocusChange.to_u32().unwrap()),
        })
        .map_err(|e| format!("register_ux: {:?}", e))?
        .ok_or_else(|| "register_ux returned None token".to_string())?;
    log::info!("xas/gam_app: GAM token = {:x?}", token);

    let content = gam.request_content_canvas(token).map_err(|e| format!("canvas: {:?}", e))?;
    let bounds = gam.get_canvas_bounds(content).map_err(|e| format!("bounds: {:?}", e))?;
    log::info!("xas/gam_app: canvas {:?}, bounds {:?}", content, bounds);

    let _ = gam.allow_mainmenu();

    // === Worker-event forwarder ===
    //
    // gam_app's main loop blocks on `xous::receive_message(sid)`,
    // but worker events arrive on `event_rx`. A dedicated thread
    // bridges the two: it blocks on `event_rx.recv_blocking`,
    // pushes each event onto a shared deque, and pokes our SID via
    // a `XasOp::WorkerEvent` scalar so our main loop wakes and
    // drains the deque.
    let pending_events: Arc<Mutex<VecDeque<Event>>> = Arc::new(Mutex::new(VecDeque::new()));
    let self_cid: CID = xous::connect(sid).map_err(|e| format!("self-connect: {:?}", e))?;
    {
        let pending = pending_events.clone();
        let event_rx = event_rx.clone();
        std::thread::Builder::new()
            .name("xas-event-forwarder".into())
            .spawn(move || {
                while let Ok(event) = event_rx.recv_blocking() {
                    pending.lock().unwrap().push_back(event);
                    let _ = xous::send_message(
                        self_cid,
                        Message::new_scalar(XasOp::WorkerEvent.to_usize().unwrap(), 0, 0, 0, 0),
                    );
                }
                log::warn!("xas/gam_app: event forwarder exited (event_rx closed)");
            })
            .map_err(|e| format!("spawn forwarder: {}", e))?;
    }

    let modals_xns = xous_names::XousNames::new().map_err(|e| format!("XousNames for modals: {:?}", e))?;

    let mut app = App {
        gam,
        content,
        bounds,
        screen: Screen::Menu,
        selected: MenuItem::Link,
        linked: false,
        store: MessageStore::new(INBOX_CAPACITY),
        llio: llio::Llio::new(&xns),
        home_focus: 0,
        compose_buffer: String::new(),
        last_status: String::new(),
        linking_in_progress: false,
        settings_selected: SettingsItem::Profile,
        account_device_name: None,
        account_aci: None,
        account_phone: None,
        account_query_pending: false,
        username_lookup_in_progress: false,
        username_lookup_pending: None,
    };
    seed_mock_messages_if_requested(&mut app);
    app.render().ok();

    loop {
        let msg = xous::receive_message(sid).map_err(|e| format!("receive: {:?}", e))?;
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(XasOp::Redraw) => {
                app.render().ok();
            }
            Some(XasOp::Rawkeys) => {
                xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                    let keys = [
                        char::from_u32(k1 as u32).unwrap_or('\u{0}'),
                        char::from_u32(k2 as u32).unwrap_or('\u{0}'),
                        char::from_u32(k3 as u32).unwrap_or('\u{0}'),
                        char::from_u32(k4 as u32).unwrap_or('\u{0}'),
                    ];
                    log::info!("xas/gam_app: keys {:?}", keys);
                    handle_keys(&mut app, keys, &cmd_tx, &event_rx, &modals_xns);
                });
                // Quit was removed from the menus (it didn't actually
                // exit anything — just hid the app and reset state);
                // the app stays foregrounded for its lifetime.
            }
            Some(XasOp::FocusChange) => {
                xous::msg_scalar_unpack!(msg, new_state_code, _, _, _, {
                    let new_state = gam::FocusState::convert_focus_change(new_state_code);
                    log::info!("xas/gam_app: focus change -> {:?}", new_state);
                    if matches!(new_state, gam::FocusState::Foreground) {
                        // Startup `load_registered` expires before the PDDB is
                        // unlocked; foreground is the first point it is not.
                        if !app.linked && app.account_aci.is_none() {
                            log::info!("xas/gam_app: foreground while unlinked — querying account state");
                            match cmd_tx.send_blocking(Cmd::GetAccountInfo) {
                                Ok(()) => app.account_query_pending = true,
                                Err(e) => log::warn!("xas/gam_app: Cmd::GetAccountInfo send err: {:?}", e),
                            }
                        }
                        if let Err(e) = app.render() {
                            log::warn!("xas/gam_app: render after focus: {}", e);
                        }
                    }
                });
            }
            Some(XasOp::WorkerEvent) => {
                let drained: Vec<Event> = {
                    let mut q = pending_events.lock().unwrap();
                    q.drain(..).collect()
                };
                for ev in drained {
                    handle_worker_event(&mut app, ev, &cmd_tx, &modals_xns);
                }
                if let Err(e) = app.render() {
                    log::warn!("xas/gam_app: render after WorkerEvent: {}", e);
                }
            }
            _ => {
                log::debug!("xas/gam_app: unknown msg id={}", msg.body.id());
            }
        }
    }
}

/// Dispatch a Precursor keypress batch.
///
/// The GAM packs up to four `char`s per `Rawkeys` IPC; `'\u{0}'`
/// fills unused slots. Each non-null char is matched against the
/// `(Screen, char)` tuple and may mutate `app.screen`, advance the
/// compose buffer, send a `Cmd`, or open a modal.
///
/// # Threading model
///
/// Called from the GAM main thread. Does not call any
/// `event_rx.recv*` — the `_event_rx` parameter exists only to be
/// passed through to [`drive_link`] which itself does not consume
/// from it. The event forwarder spawned by [`run`] is the sole
/// receiver.
fn handle_keys(
    app: &mut App,
    keys: [char; 4],
    cmd_tx: &Sender<Cmd>,
    event_rx: &Receiver<Event>,
    modals_xns: &xous_names::XousNames,
) {
    for &k in keys.iter() {
        if k == '\u{0}' {
            continue;
        }
        match (&app.screen, k) {
            (Screen::Menu, '↑') => app.move_cursor(-1),
            (Screen::Menu, '↓') => app.move_cursor(1),
            (Screen::Menu, '∴') | (Screen::Menu, '\u{d}') => match app.selected {
                MenuItem::Link => match check_internet(modals_xns) {
                    Ok(()) => drive_link(app, cmd_tx, event_rx, modals_xns),
                    Err(reason) => {
                        log::info!("xas/gam_app: preflight failed before Link: {}", reason);
                        app.screen = Screen::NoInternet { next: NextScreenAfterInternet::Link, reason };
                    }
                },
                MenuItem::About => app.screen = Screen::About,
                MenuItem::Help => app.screen = Screen::Help,
                MenuItem::WipeSettings => drive_wipe_settings(app, cmd_tx, modals_xns),
            },
            // Esc on the post-link Menu returns to Home (the landing).
            // Pre-link, Menu IS the landing — Esc is a no-op.
            (Screen::Menu, '\u{1b}') if app.linked => {
                app.screen = Screen::Home;
                app.selected = MenuItem::About;
            }
            (Screen::About, '∴') | (Screen::About, '\u{d}') => {
                app.screen = if app.linked { Screen::Home } else { Screen::Menu };
            }
            (Screen::Linked { .. }, '∴') | (Screen::Linked { .. }, '\u{d}') => {
                if app.linked {
                    // Preflight before landing on Home so an offline
                    // user gets the recipe instead of opaque receive
                    // failures from libsignal.
                    match check_internet(modals_xns) {
                        Ok(()) => {
                            app.screen = Screen::Home;
                            app.home_focus = 0;
                        }
                        Err(reason) => {
                            log::info!("xas/gam_app: preflight failed before Home: {}", reason);
                            app.screen = Screen::NoInternet { next: NextScreenAfterInternet::Home, reason };
                        }
                    }
                } else {
                    app.screen = Screen::Menu;
                    app.selected = MenuItem::Link;
                }
                app.last_status.clear();
            }
            // Enter on Screen::NoInternet re-runs the preflight.
            // On success, transition to the screen the user was
            // trying to reach (Home for post-link, Link flow for
            // pre-link). On failure, stay on NoInternet with a
            // refreshed reason.
            (Screen::NoInternet { next, .. }, '∴') | (Screen::NoInternet { next, .. }, '\u{d}') => {
                let next = *next;
                match check_internet(modals_xns) {
                    Ok(()) => match next {
                        NextScreenAfterInternet::Link => drive_link(app, cmd_tx, event_rx, modals_xns),
                        NextScreenAfterInternet::Home => {
                            app.screen = Screen::Home;
                            app.home_focus = 0;
                        }
                    },
                    Err(reason) => {
                        log::info!("xas/gam_app: preflight retry still failing: {}", reason);
                        app.screen = Screen::NoInternet { next, reason };
                    }
                }
            }
            // Esc / Backspace on Screen::NoInternet returns to the
            // pre/post-link Menu so the user isn't stuck.
            (Screen::NoInternet { .. }, '\u{1b}') | (Screen::NoInternet { .. }, '\u{8}') => {
                app.screen = if app.linked { Screen::Home } else { Screen::Menu };
                app.selected = MenuItem::Link;
            }
            // Esc / Backspace on Screen::Linking — cancel the
            // in-flight link. Worker drops the link future + emits
            // a LinkError("Cancelled") which we ignore (because
            // linking_in_progress is now false).
            (Screen::Linking, '\u{1b}') | (Screen::Linking, '\u{8}') => {
                log::info!("xas/gam_app: cancel link via Esc/backspace");
                if let Err(e) = cmd_tx.send_blocking(Cmd::LinkCancel) {
                    log::warn!("xas/gam_app: Cmd::LinkCancel send err: {:?}", e);
                }
                app.linking_in_progress = false;
                app.screen = Screen::Menu;
                app.selected = MenuItem::Link;
                app.last_status.clear();
            }
            (Screen::Home, '↑') => {
                app.home_focus = app.home_focus.saturating_sub(1);
            }
            (Screen::Home, '↓') => {
                let max = app.store.dialogues().len().saturating_sub(1);
                if app.home_focus < max {
                    app.home_focus += 1;
                }
            }
            (Screen::Home, '∴') | (Screen::Home, '\u{d}') => {
                // Open the focused thread. If the list is empty,
                // do nothing — user can still press the Menu key
                // to access About / Quit.
                if let Some(d) = app.store.dialogues().get(app.home_focus) {
                    let opened = d.uuid;
                    app.store.mark_thread_read(opened);
                    app.screen = Screen::Thread { uuid: opened };
                }
            }
            // Menu / Esc on Home opens Settings.
            (Screen::Home, '☰') | (Screen::Home, '\u{1b}') => {
                app.screen = Screen::Settings;
                app.settings_selected = SettingsItem::Profile;
            }
            // F1 (Precursor sends 0x11): "New chat" — prompt for UUID
            // or +e164, then open the empty Thread.
            (Screen::Home, '\u{11}') => {
                drive_new_chat(app, cmd_tx, modals_xns);
            }
            // F2 (0x12): Sync — request contacts from the linked
            // phone. Worker calls manager.request_contacts(); presage
            // saves the response into ContentsStore; Event::SyncComplete
            // fires when done (or Event::SyncError on failure). Future
            // inbound messages from synced contacts will pick up the
            // names via contact_by_id (the existing path).
            (Screen::Home, '\u{12}') => {
                log::info!("xas/gam_app: F2 sync requested");
                if let Err(e) = cmd_tx.send_blocking(Cmd::SyncContacts) {
                    log::warn!("xas/gam_app: Cmd::SyncContacts send err: {:?}", e);
                    if let Ok(modals) = modals::Modals::new(modals_xns) {
                        let _ = modals.show_notification("Sync send failed:\nworker not reachable.", None);
                    }
                } else if let Ok(modals) = modals::Modals::new(modals_xns) {
                    // Brief feedback so the user knows the tap registered.
                    // Real completion arrives as Event::SyncComplete.
                    let _ = modals.show_notification(
                        "Syncing contacts from\nthe linked phone...\n\
                         (this can take a minute)",
                        None,
                    );
                }
            }
            // F3 (0x13): Help / FAQ.
            (Screen::Home, '\u{13}') => {
                app.screen = Screen::Help;
            }
            // F4 (0x14): Settings.
            (Screen::Home, '\u{14}') => {
                app.screen = Screen::Settings;
                app.settings_selected = SettingsItem::Profile;
            }
            (Screen::Thread { uuid }, '∴') | (Screen::Thread { uuid }, '\u{d}') => {
                // Enter behavior depends on compose buffer state:
                // - empty → back to Home (BlackBerry/Nokia convention)
                // - non-empty → send the message
                if app.compose_buffer.is_empty() {
                    app.screen = Screen::Home;
                } else {
                    send_compose(app, cmd_tx, *uuid, "send");
                }
            }
            (Screen::Thread { .. }, '\u{8}') => {
                // Backspace: pop a char from the compose buffer.
                app.compose_buffer.pop();
            }
            (Screen::Thread { .. }, c) if is_compose_char(c) => {
                app.compose_buffer.push(c);
            }
            // F1 on Thread: same as Enter when buffer non-empty (send).
            // No-op on empty buffer (don't surprise-back-out via F1).
            (Screen::Thread { uuid }, '\u{11}') => {
                if !app.compose_buffer.is_empty() {
                    send_compose(app, cmd_tx, *uuid, "F1 send");
                }
            }
            // F4 on Thread: open Settings.
            (Screen::Thread { .. }, '\u{14}') => {
                app.screen = Screen::Settings;
                app.settings_selected = SettingsItem::Profile;
            }
            // F3 on Thread: Help.
            (Screen::Thread { .. }, '\u{13}') => {
                app.screen = Screen::Help;
            }
            // Settings sub-menu navigation + selection.
            (Screen::Settings, '↑') => app.settings_move(-1),
            (Screen::Settings, '↓') => app.settings_move(1),
            (Screen::Settings, '∴') | (Screen::Settings, '\u{d}') => {
                match app.settings_selected {
                    SettingsItem::Profile => {
                        // If Profile fields aren't loaded yet (cold
                        // start with linked-from-PDDB but no fresh
                        // LinkComplete), fire Cmd::GetAccountInfo
                        // so the worker can read registration_data
                        // and emit Event::AccountInfo. UI updates
                        // when Event arrives.
                        if app.account_aci.is_none() {
                            log::info!(
                                "xas/gam_app: Profile entry, account info not loaded — sending Cmd::GetAccountInfo"
                            );
                            match cmd_tx.send_blocking(Cmd::GetAccountInfo) {
                                Ok(()) => app.account_query_pending = true,
                                Err(e) => log::warn!("xas/gam_app: Cmd::GetAccountInfo send err: {:?}", e),
                            }
                        }
                        app.screen = Screen::Profile;
                    }
                    SettingsItem::Help => app.screen = Screen::Help,
                    SettingsItem::About => app.screen = Screen::About,
                    SettingsItem::Logout => drive_logout(cmd_tx, modals_xns),
                }
            }
            (Screen::Settings, '\u{1b}') | (Screen::Settings, '☰') | (Screen::Settings, '\u{11}') => {
                app.screen = Screen::Home;
            }
            // Profile / Help / About: Enter, Esc, or F1 returns to
            // the screen we came from. For Help we always go to
            // Home (F3 is the global Help shortcut from Home).
            // F1 acts as a "back" affordance because Esc isn't
            // present on the Precursor key set.
            (Screen::Profile, '∴')
            | (Screen::Profile, '\u{d}')
            | (Screen::Profile, '\u{1b}')
            | (Screen::Profile, '\u{11}') => {
                app.screen = Screen::Settings;
            }
            (Screen::Help, '∴')
            | (Screen::Help, '\u{d}')
            | (Screen::Help, '\u{1b}')
            | (Screen::Help, '\u{11}') => {
                // Help is reachable from Home (F3), pre-link Menu,
                // and Settings. Always return to Home for
                // simplicity — user can re-open Settings via F4.
                app.screen = Screen::Home;
            }
            // F1 on About also returns to the previous surface
            // (Home if linked, Menu otherwise).
            (Screen::About, '\u{11}') | (Screen::About, '\u{1b}') => {
                app.screen = if app.linked { Screen::Home } else { Screen::Menu };
            }
            // Linking is transient (waiting on worker); rawkeys are
            // ignored.
            _ => {}
        }
    }
    if let Err(e) = app.render() {
        log::warn!("render: {}", e);
    }
}

/// Process a worker [`Event`] delivered via the forwarder thread.
/// Mutates `app` state in place; the caller renders once after
/// draining the entire deque, so multiple events batch into one
/// redraw.
///
/// All `Event` variants land here — including the link-flow
/// (`LinkUrl`, `LinkComplete`, `LinkError`), the receive loop
/// (`ReceiveStarted`, `Message`, `ReceiveError`), the send loop
/// (`SendComplete`, `SendError`), and the terminal-state banners
/// (`LoggedOut`, `SignalAuthExpired`, `SignalConflictingDevice`).
///
/// # Trust boundary
///
/// This is the **post-decrypt boundary**: every event payload
/// originated inside the worker after libsignal completed its
/// ratchet and authentication checks. The body / sender / ACI /
/// phone fields are all plaintext PII or higher.
///
/// # Security
///
/// Existing `log::info!` lines record only structured metadata
/// (sender label, byte length, ACI for the audit trail). When
/// extending this function, mirror that discipline — never log
/// `body`, never `Debug`-print the whole `Event`.
fn handle_worker_event(
    app: &mut App,
    event: Event,
    cmd_tx: &Sender<Cmd>,
    modals_xns: &xous_names::XousNames,
) {
    match event {
        Event::LinkUrl(url) => {
            // LOGGING / SECURITY: the URL is the link credential
            // during its window — anyone with UART access can replay
            // it to pair their own device against the pending request.
            // Full URL only under the default-off `link-uri-uart`
            // feature; the exact "link URL = " text is grepped by
            // tests/hosted/test_link_qr.sh.
            #[cfg(feature = "link-uri-uart")]
            log::info!("xas/gam_app: link URL = {}", url);
            #[cfg(not(feature = "link-uri-uart"))]
            log::info!("xas/gam_app: link URL received ({} bytes)", url.len());
            // Open the QR modal. show_notification blocks until the
            // user dismisses it — meanwhile the worker keeps the
            // provisioning WS alive waiting for the encrypted
            // envelope. After the user scans + dismisses, we keep
            // looping; LinkComplete or LinkError will arrive next.
            if app.linking_in_progress {
                if let Ok(modals) = modals::Modals::new(modals_xns) {
                    let _ = modals.show_notification(
                        "Signal on phone.\n\
                         Scan QR, then press any key.\n\
                         Don't transfer old messages.",
                        Some(&url),
                    );
                }
            }
        }
        Event::LinkComplete { device_name, aci, phone } => {
            log::info!(
                "xas/gam_app: LinkComplete device={} aci={} phone={}",
                device_name,
                presage_store_pddb::log_id(&aci),
                presage_store_pddb::log_id(&phone)
            );
            app.linked = true;
            app.linking_in_progress = false;
            app.screen = Screen::Linked { kind: LinkedKind::Success };
            app.last_status = format!("device: {}\naci:    {}\nphone:  {}", device_name, aci, phone);
            app.account_device_name = Some(device_name);
            app.account_aci = Some(aci);
            app.account_phone = Some(phone);
            // Auto-fire StartReceive so the inbox begins
            // accumulating. Bridge dedupes; calling again later is
            // harmless.
            log::info!("xas/gam_app: sending Cmd::StartReceive");
            match cmd_tx.send_blocking(Cmd::StartReceive) {
                Ok(()) => log::info!("xas/gam_app: Cmd::StartReceive sent ok"),
                Err(e) => log::warn!("xas/gam_app: Cmd::StartReceive send err: {:?}", e),
            }
        }
        Event::LinkError(msg) => {
            log::warn!("xas/gam_app: LinkError: {}", msg);
            // If the user already navigated away (e.g., cancelled via
            // Esc on Screen::Linking), linking_in_progress is already
            // false. Don't bounce them onto the failure screen — the
            // late-arriving error is a confirmation that the cancel
            // took effect, not a user-facing problem.
            if !app.linking_in_progress {
                log::info!("xas/gam_app: ignoring late LinkError (link not in progress; user cancelled)");
                return;
            }
            app.linking_in_progress = false;
            app.screen = Screen::Linked { kind: LinkedKind::Failure };
            app.last_status = msg;
        }
        Event::StaleStoreDetected => {
            // The worker refused Cmd::LinkDevice: the store still holds
            // account state from a previous link. The modal names the
            // remedy; the cursor is deliberately left where it was, so
            // reaching a destructive wipe still takes navigation.
            log::warn!("xas/gam_app: StaleStoreDetected — link refused");
            app.linking_in_progress = false;
            app.screen = Screen::Menu;
            if let Ok(modals) = modals::Modals::new(modals_xns) {
                let _ = modals.show_notification(
                    "Settings from a previous\n\
                     link are still stored.\n\
                     Linking over them causes\n\
                     session errors.\n\n\
                     Run 'Wipe settings',\n\
                     then Link again.",
                    None,
                );
            }
        }
        Event::Message { sender, sender_phone, sender_name, body, timestamp, group_master_key } => {
            // Pretty label preference: name → phone → UUID. The
            // contacts store typically has both name and phone for
            // peers who've been synced from the linked phone; only
            // first-sight peers fall through to UUID.
            let author_label =
                sender_name.clone().or_else(|| sender_phone.clone()).unwrap_or_else(|| sender.clone());
            log::info!(
                "xas/gam_app: inbound message from {} ({} bytes) group={}",
                presage_store_pddb::log_id(&author_label),
                body.len(),
                group_master_key.is_some(),
            );
            // ACI from the worker is a canonical UUID string.
            // Fall back to the nil UUID if parse fails (defensive
            // — practically shouldn't happen since the worker only
            // surfaces senders it recognized).
            let sender_uuid = Uuid::parse_str(&sender).unwrap_or_else(|_| {
                log::warn!("xas/gam_app: sender {:?} doesn't parse as UUID; using nil", sender);
                Uuid::nil()
            });
            // Misfile guard: a group message must NOT land in the
            // sender's private 1:1 thread. File it under a
            // pseudo-thread UUID derived deterministically from the
            // GV2 master key (v5/SHA-1; no collision risk with real
            // contact ACIs in practice), keeping the Uuid thread-key
            // shape until real ThreadKey typing lands with the
            // gam_app split. The message row is group-tagged so the
            // UI labels the thread and blocks compose into it.
            let (uuid, group) = match &group_master_key {
                Some(key) => (Uuid::new_v5(&Uuid::NAMESPACE_OID, key), true),
                None => (sender_uuid, false),
            };
            app.store.push_incoming(uuid, author_label, body, timestamp, group);
            // Physical cue; a missed vibe must not affect delivery.
            app.llio.vibe(llio::VibePattern::Double).ok();
        }
        Event::ReceiveStarted => {
            log::info!("xas/gam_app: receive loop established");
        }
        Event::ReceiveError(msg) => {
            log::warn!("xas/gam_app: receive error: {}", msg);
            app.last_status = format!("Receive: {}", msg);
        }
        Event::SendComplete { timestamp } => {
            // If the send originated from a Thread compose, there's a
            // pending optimistic-rendered row in the store with this
            // timestamp. Update its status in place (the store
            // rebuilds the dialogue summaries so any cached
            // snippet/status reflects the new state). No screen
            // change — the Thread is already showing the message.
            //
            // Otherwise (no match), the worker emitted an event for
            // a send we don't have an optimistic row for. Log + ignore.
            if !app.store.mark_send_delivered(timestamp) {
                log::info!("xas/gam_app: SendComplete ts={} with no matching pending row", timestamp);
            }
        }
        Event::SendError { reason, timestamp } => {
            let matched = timestamp.is_some_and(|ts| app.store.mark_send_failed(ts));
            if !matched {
                log::warn!(
                    "xas/gam_app: SendError reason={} ts={:?} with no matching row",
                    reason,
                    timestamp
                );
            }
            app.last_status = format!("Send: {}", reason);
        }
        Event::ShuttingDown => {
            log::info!("xas/gam_app: worker is shutting down");
            app.last_status = "worker shutdown".to_string();
        }
        Event::AccountInfo(Ok(info)) => {
            app.account_query_pending = false;
            log::info!(
                "xas/gam_app: AccountInfo OK device={} aci={} phone={}",
                info.device_name,
                presage_store_pddb::log_id(&info.aci),
                presage_store_pddb::log_id(&info.phone),
            );
            app.account_device_name = Some(info.device_name);
            app.account_aci = Some(info.aci);
            app.account_phone = Some(info.phone);
            if !app.linked {
                // A registered account in the store means linked, even if this
                // boot never saw LinkComplete. Without this the UI stays on the
                // pre-link Menu, whose only actions are a link the worker will
                // refuse and a destructive wipe.
                log::info!("xas/gam_app: account found on an unlinked UI — resuming linked state");
                app.linked = true;
                app.screen = Screen::Home;
                app.home_focus = 0;
                if let Err(e) = cmd_tx.send_blocking(Cmd::StartReceive) {
                    log::warn!("xas/gam_app: Cmd::StartReceive send err: {:?}", e);
                }
                let _ = app.render();
            } else if matches!(app.screen, Screen::Profile) {
                let _ = app.render();
            }
        }
        Event::AccountInfo(Err(reason)) => {
            app.account_query_pending = false;
            log::warn!("xas/gam_app: AccountInfo Err: {}", reason);
            // Leave account_* fields as-is. Profile screen will
            // continue to show "(not loaded)" placeholders. Not
            // worth showing a popup since this is a passive lookup.
        }
        Event::ContactResolved { aci_uuid, name } => {
            log::info!("xas/gam_app: ContactResolved {} → {:?}", aci_uuid, name);
            // Replace any UUID-shaped author_label whose uuid matches
            // with the resolved name. Outgoing messages (author_label
            // == "You") are untouched by virtue of "You" not looking
            // like a raw UUID.
            if app.store.resolve_author_labels(aci_uuid, &name)
                && matches!(app.screen, Screen::Home | Screen::Thread { .. })
            {
                let _ = app.render();
            }
        }
        Event::SyncComplete => {
            log::info!("xas/gam_app: SyncComplete");
            if matches!(app.screen, Screen::Home | Screen::Thread { .. } | Screen::Settings) {
                let _ = app.render();
            }
        }
        Event::SyncError(reason) => {
            log::warn!("xas/gam_app: SyncError: {}", reason);
            // Surface as a notification so the user knows the Sync
            // they tapped didn't actually run.
            // (Modals from inside handle_worker_event would need an
            //  XousNames handle we don't have here — log only for now.)
        }
        Event::LoggedOut => {
            log::info!("xas/gam_app: LoggedOut — resetting App state");
            // Wipe link-derived state so the app behaves like a
            // fresh boot: pre-link Menu, no messages, no dialogues,
            // no cached account info.
            app.reset_to_unlinked();
            app.last_status.clear();
            let _ = app.render();
        }
        Event::SignalAuthExpired(reason) => {
            log::warn!("xas/gam_app: SignalAuthExpired: {}", reason);
            // Mirrors LoggedOut, but the reset is involuntary:
            // server-forced WS 4401 + failed reauth (see #13). The
            // banner tells the user why their app suddenly looks
            // unlinked, so they know to re-link rather than thinking
            // the device is generally broken.
            app.reset_to_unlinked();
            app.last_status = format!("Signal authentication expired:\n{}\n\nPlease re-link.", reason);
            let _ = app.render();
        }
        Event::SignalConflictingDevice(reason) => {
            log::warn!("xas/gam_app: SignalConflictingDevice: {}", reason);
            // Mirrors LoggedOut + SignalAuthExpired, but the trigger
            // is server-forced WS 4409 "Connected elsewhere" — another
            // authenticated WS for the same (account, deviceId) pair
            // displaced ours. Auto-reconnect would self-displace, so
            // the worker treats this as terminal. The banner tells
            // the user a different app instance is active and they
            // need to re-link this device to use it.
            app.reset_to_unlinked();
            app.last_status = format!("Another device took over:\n{}\n\nPlease re-link.", reason);
            let _ = app.render();
        }
        Event::UsernameResolveResult(result) => {
            log::info!("xas/gam_app: UsernameResolveResult: {:?}", result);
            // The Cmd::ResolveUsername caller stores its pending state
            // on app (see drive_new_chat). Apply the result here.
            handle_username_resolve_result(app, result);
        }
        Event::Pong | Event::Whoami(_) => {}
    }
}

/// Apply an `Event::UsernameResolveResult` to the in-flight New
/// Chat flow. On success, transitions to [`Screen::Thread`]. On
/// error or not-found, clears `username_lookup_in_progress` and
/// surfaces the reason in `app.last_status` for the next render.
///
/// Stale responses (those arriving after the user navigated away
/// from the New Chat modal) are silently dropped via the
/// `username_lookup_in_progress` guard.
fn handle_username_resolve_result(app: &mut App, result: Result<Option<Uuid>, String>) {
    if !app.username_lookup_in_progress {
        // No-op: probably a stale response after the user navigated
        // away. Just clear the in-flight indicator if any.
        return;
    }
    app.username_lookup_in_progress = false;
    match result {
        Ok(Some(uuid)) => {
            log::info!("xas/gam_app: username resolved to {}", presage_store_pddb::log_id(&uuid.to_string()));
            // Label the thread with the username the user typed. Without
            // this the row falls back to a UUID prefix — the one
            // identifier they never entered and cannot recognise.
            if let Some(name) = app.username_lookup_pending.take() {
                app.store.resolve_author_labels(uuid, &name);
            }
            app.screen = Screen::Thread { uuid };
            let _ = app.render();
        }
        Ok(None) => {
            log::info!("xas/gam_app: username not found");
            // Surface as last_status banner for the next render cycle.
            app.last_status = "Username not found.".to_string();
            let _ = app.render();
        }
        Err(reason) => {
            log::warn!("xas/gam_app: username lookup err: {}", reason);
            app.last_status = format!("Lookup failed:\n{}", reason);
            let _ = app.render();
        }
    }
}

/// Hosted-mode helper: read `$HOME/.xas-link-attempts`, increment
/// it, and return the device name to default to. Each link attempt
/// gets a fresh `xasN` so the user can correlate this run's QR with
/// the entry that lands in their phone's Linked Devices list.
///
/// File semantics: missing → create with `0`, use `0`, write `1`.
/// Existing → read N, use N, write N+1. If `$HOME` is not set or
/// the read/write fails, fall back to the bare `"xas"` name.
#[cfg(not(target_os = "xous"))]
fn next_attempt_device_name() -> String {
    let Ok(home) = std::env::var("HOME") else {
        return "xas".to_string();
    };
    let path = std::path::PathBuf::from(home).join(".xas-link-attempts");
    let n: u32 = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let _ = std::fs::write(&path, format!("{}", n + 1));
    format!("xas{}", n)
}

/// rv32 stub: there is no general filesystem to track attempt
/// counts on, so every link attempt defaults to the bare `"xas"`
/// name. The user can still override via the device-name modal.
#[cfg(target_os = "xous")]
fn next_attempt_device_name() -> String { "xas".to_string() }

/// No-internet preflight.
///
/// `Ok(())` means xas has an IPv4 lease and the link is up;
/// `Err(reason)` is a short user-facing string explaining what is
/// missing. Used to short-circuit link / receive attempts that
/// would otherwise spend tens of seconds inside libsignal failing
/// to resolve `chat.signal.org`.
///
/// # Errors
///
/// - `"COM didn't respond: …"` — the COM service did not answer the `wlan_status` request.
/// - `"Wi-Fi link is …"` — the EC reports the link is not in the `Connected` state.
/// - `"Joined a network but no DHCP lease yet."` — link up but `ipv4.addr` is `0.0.0.0`.
///
/// Outside Xous (bare `cargo run` on Linux) or when
/// `XAS_BYPASS_PREFLIGHT` is set, this returns `Ok(())`
/// unconditionally — the host kernel's networking is assumed
/// usable.
fn check_internet(xns: &xous_names::XousNames) -> Result<(), String> {
    // Hosted-mode escape hatch: tests/hosted/test_link_qr.sh sets
    // XAS_BYPASS_PREFLIGHT=1 because hosted has no real WF200 radio
    // and wlan_status() always returns Unknown. Without this, the
    // smoke test can never reach the link-URL emit.
    if std::env::var("XAS_BYPASS_PREFLIGHT").is_ok() {
        return Ok(());
    }
    // com::Com::new only succeeds when the COM service is up — i.e.,
    // we're inside a Xous environment with the EC ready. Outside Xous
    // (bare cargo run on Linux) this returns Err and we treat the
    // host kernel's networking as already-OK.
    let com = match com::Com::new(xns) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let status = match com.wlan_status() {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("COM didn't respond: {:?}", e));
        }
    };
    if status.link_state != com_rs::LinkState::Connected {
        return Err(format!("Wi-Fi link is {:?}.", status.link_state));
    }
    if status.ipv4.addr == [0, 0, 0, 0] {
        return Err("Joined a network but no\nDHCP lease yet.".to_string());
    }
    Ok(())
}

/// Kick off the link flow. Synchronous part only: prompts for a
/// device name, sends `Cmd::LinkDevice`, sets [`Screen::Linking`],
/// and returns. All async results (`LinkUrl`, `LinkComplete`,
/// `LinkError`, `StaleStoreDetected`) flow through the forwarder
/// thread and land in [`handle_worker_event`].
///
/// # Threading model
///
/// `drive_link` is called on the GAM main thread. It must not call
/// `event_rx.recv*` — the forwarder thread is the sole consumer of
/// `event_rx`. The `_event_rx` parameter is held only so a caller
/// can prove ownership; it is intentionally not used.
fn drive_link(
    app: &mut App,
    cmd_tx: &Sender<Cmd>,
    _event_rx: &Receiver<Event>,
    modals_xns: &xous_names::XousNames,
) {
    let modals = match modals::Modals::new(modals_xns) {
        Ok(m) => m,
        Err(e) => {
            app.screen = Screen::Linked { kind: LinkedKind::Failure };
            app.last_status = format!("Modals init failed:\n{:?}", e);
            return;
        }
    };

    let default_name = next_attempt_device_name();
    let device_name =
        match modals.alert_builder("Device name?").field(Some(default_name.clone()), None).build() {
            Ok(payloads) => {
                let trimmed = payloads.first().as_str().trim().to_string();
                if trimmed.is_empty() { default_name } else { trimmed }
            }
            Err(e) => {
                app.screen = Screen::Linked { kind: LinkedKind::Failure };
                app.last_status = format!("device name modal:\n{:?}", e);
                return;
            }
        };

    app.screen = Screen::Linking;
    app.linking_in_progress = true;
    app.render().ok();

    if let Err(e) = cmd_tx.send_blocking(Cmd::LinkDevice { device_name }) {
        app.screen = Screen::Linked { kind: LinkedKind::Failure };
        app.last_status = format!("Cmd::LinkDevice send:\n{:?}", e);
        app.linking_in_progress = false;
        return;
    }
    // Return now; events arrive via the forwarder.
}
