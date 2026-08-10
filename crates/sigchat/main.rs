#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

mod api;
use api::*;
use chat::{Chat, Event, POST_TEXT_MAX};
use gam::{MenuItem, MenuPayload};
use locales::t;
use num_traits::*;
use sigchat::SigChat;
use xous_ipc::Buffer;
use xous_signal_worker::{Cmd, Event, run_signal_worker};


/// Capacity of the [`Cmd`] and [`Event`] async channels between
/// the UI and the worker.
///
/// Sized for the UI's typical command pattern: a small handful of
/// commands in flight at any time (link, send, sync, account
/// info). The worker drains commands eagerly so back-pressure on
/// the UI side is unlikely on real workloads.
///
/// Capacity tradeoff: the `event_tx` cap bounds how many
/// back-pressured `Event::Message` emissions
/// `xous_signal_worker::manager_task` can buffer before its
/// `event_tx.send(...).await` blocks the worker's receive stream.
/// Too small → an idle or slow UI stalls inbound receive; too large
/// → unbounded memory on a poorly-behaved peer with high message
/// flux. 16 is the negotiated middle: enough for a bursty receive
/// from a chat the user just opened, small enough to keep the
/// post-Drop bare-`String` body exposure window bounded (SecretBox
/// wrapping of message bodies is tracked in issue #37, item 3).
const CHAN_CAP: usize = 16;


/// This is a Migration Stub
/// see tunnell/xous-app-signal/crates/xous-app-signal/main.rs
use crate::dialogue::{SendStatus, ThreadMessage};
use crate::store::MessageStore;

/// This is a Migration Stub
/// see tunnell/xous-app-signal/crates/xous-app-signal/main.rs
struct AppStub {
    gam: gam::Gam,
    content: Gid,
    bounds: Point,
    screen: Screen,
    selected: MenuItem,
    linked: bool,
    store: MessageStore,
    llio: llio::Llio,
    home_focus: usize,
    compose_buffer: String,
    last_status: String,
    linking_in_progress: bool,
    settings_selected: SettingsItem,
    account_device_name: Option<String>,
    account_aci: Option<String>,
    account_phone: Option<String>,
    account_query_pending: bool,
    username_lookup_in_progress: bool,
    username_lookup_pending: Option<String>,
}

/// This is a Migration Stub
/// see tunnell/xous-app-signal/crates/xous-app-signal/main.rs
impl Default for AppStub {
    fn default() -> Self {
        AppStub {
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
    }
}

/// This is a Migration Stub
/// see tunnell/xous-app-signal/crates/xous-app-signal/main.rs
impl AppStub {
    fn reset_to_unlinked(&mut self) {todo!();}
    fn menu_items(&self) -> [Option<MenuItem>; 4] {todo!();}
    fn move_cursor(&mut self, delta: isize) {todo!();}
    fn render(&self) -> Result<(), String> {todo!();}
    fn identity_line(&self) -> String {todo!();}
    fn write_menu(&self, out: &mut String) -> Result<(), String> {todo!();}
    fn write_home(&self, out: &mut String) -> Result<(), String> {todo!();}
    fn write_thread(&self, out: &mut String, uuid: &Uuid) -> Result<(), String> {todo!();}
    fn settings_items(&self) -> [SettingsItem; 4] {todo!();}
    fn settings_move(&mut self, delta: isize) {todo!();}
    fn write_settings(&self, out: &mut String) -> Result<(), String> {todo!();}
    fn write_profile(&self, out: &mut String) -> Result<(), String> {todo!();}
    fn write_help(&self, out: &mut String) -> Result<(), String> {todo!();}
    fn write_no_internet(&self, out: &mut String, reason: &str) -> Result<(), String> {todo!();}
}


fn main() -> ! {
    let stack_size = 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(stack_size)
        .spawn(wrapped_main)
        .unwrap()
        .join()
        .unwrap()
}

fn wrapped_main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("my PID is {}", xous::process::id());

    const HEAP_LARGER_LIMIT: usize = 2048 * 1024;
    let new_limit = HEAP_LARGER_LIMIT;
    let result = xous::rsyscall(xous::SysCall::AdjustProcessLimit(
        xous::Limits::HeapMaximum as usize,
        0,
        new_limit,
    ));

    if let Ok(xous::Result::Scalar2(1, current_limit)) = result {
        xous::rsyscall(xous::SysCall::AdjustProcessLimit(
            xous::Limits::HeapMaximum as usize,
            current_limit,
            new_limit,
        ))
        .unwrap();
        log::info!("Heap limit increased to: {}", new_limit);
    } else {
        panic!("Unsupported syscall!");
    }

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns
        .register_name(SERVER_NAME_SIGCHAT, None)
        .expect("can't register server");
    log::trace!("registered with NS -- {:?}", sid);

    let chat = Chat::new(
        gam::APP_NAME_SIGCHAT,
        gam::APP_MENU_0_SIGCHAT,
        Some(xous::connect(sid).unwrap()),
        Some(SigchatOp::Post as usize),
        Some(SigchatOp::Event as usize),
        Some(SigchatOp::Rawkeys as usize),
    );

    let cid = xous::connect(sid).unwrap();
    chat.menu_add(MenuItem {
        name: xous_ipc::String::from_str(t!("sigchat.menu.close", locales::LANG)),
        action_conn: Some(cid),
        action_opcode: SigchatOp::Menu as u32,
        action_payload: MenuPayload::Scalar([MenuOp::Noop as u32, 0, 0, 0]),
        close_on_select: true,
    })
    .expect("failed add menu");

    let (cmd_tx, cmd_rx) = bounded::<Cmd>(CHAN_CAP);
    let (event_tx, event_rx) = bounded::<Event>(CHAN_CAP);
    let worker = run_signal_worker(store, cmd_rx, event_tx);
    log::info!("xas: worker started");

    // === Worker-event forwarder ===
    //
    // gam_app's main loop blocks on `xous::receive_message(sid)`,
    // but worker events arrive on `event_rx`. A dedicated thread
    // bridges the two: it blocks on `event_rx.recv_blocking`,
    // pushes each event onto a shared deque, and pokes our SID via
    // a `SigchatOp::WorkerEvent` scalar so our main loop wakes and
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
                        Message::new_scalar(SigchatOp::WorkerEvent.to_usize().unwrap(), 0, 0, 0, 0),
                    );
                }
                log::warn!("xas/gam_app: event forwarder exited (event_rx closed)");
            })
            .map_err(|e| format!("spawn forwarder: {}", e))?;
    }

    // app is initialised as a Migration App Stub
    let mut app = AppStub::default();

    let mut sigchat = SigChat::new(&chat);
    let mut first_focus = true;
    let mut user_post: Option<String> = None;
    loop {
        let msg = xous::receive_message(sid).unwrap();
        log::debug!("got message {:?}", msg);
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(SigchatOp::Event) => {
                log::info!("got Chat UI Event");
                xous::msg_scalar_unpack!(msg, event_code, _, _, _, {
                    match FromPrimitive::from_usize(event_code) {
                        Some(Event::Focus) => {
                            if first_focus {
                                first_focus = false;
                                match sigchat.connect() {
                                    Ok(true) => log::info!("connected to Signal Account"),
                                    Ok(false) => log::info!("not connected to Signal Account"),
                                    Err(e) => {
                                        log::warn!("error while connecting to Signal Account: {e}")
                                    }
                                }
                            }
                            sigchat.redraw();
                        }
                        _ => (),
                    }
                });
            }
            Some(SigchatOp::Menu) => {
                log::info!("got Chat Menu Click");
                xous::msg_scalar_unpack!(msg, menu_code, _, _, _, {
                    match FromPrimitive::from_usize(menu_code) {
                        Some(MenuOp::Noop) => {}
                        _ => (),
                    }
                });
            }
            Some(SigchatOp::Post) => {
                let buffer =
                    unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                let s = buffer
                    .to_original::<xous_ipc::String<{ POST_TEXT_MAX }>, _>()
                    .unwrap();
                if s.len() > 0 {
                    // capture input instead of calling here, so message can drop and calling server is released
                    user_post = Some(s.to_string());
                }
            }
            Some(SigchatOp::WorkerEvent) => {
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
            Some(SigchatOp::Rawkeys) => log::info!("got sigchat rawkeys"),
            Some(SigchatOp::Quit) => {
                log::error!("got Quit");
                break;
            }
            _ => (),
        }
        if let Some(_post) = user_post {
            //sigchat.post(&post);
            user_post = None;
        }
    }

    // Worker has been told to shut down; join it. If the join hangs
    // it's a worker-side bug — surface as a nonzero exit, not a
    // silent hang.
    let _ = worker.join();

    // clean up our program
    log::error!("main loop exit, destroying servers");
    xns.unregister_server(sid).unwrap();
    xous::destroy_server(sid).unwrap();
    log::trace!("quitting");
    xous::terminate_process(0)
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
