//! Worker-thread harness for the `presage::Manager` state machine.
//!
//! Owns a single Xous OS thread (named `signal-worker`) that runs a
//! `smol-rs::LocalExecutor`. The worker accepts a [`PddbStore`] and a
//! pair of `async-channel`s, dispatches [`Cmd`] values from the UI,
//! and emits [`Event`] replies. All `libsignal-service-rs`
//! thread-locals (`HttpClient`, `TaskSpawner`) are installed inside
//! the worker, so `Manager` operations stay confined to this thread.
//!
//! # Crate boundaries
//!
//! - Upstream of this crate: the binary in `xous-app-signal` (sends [`Cmd`], receives [`Event`]).
//! - Below this crate:
//!   - [`presage_store_pddb`] for storage (passed in as [`PddbStore`]).
//!   - [`xous_net_bridge`] for transport (installed as a `thread_local!` `HttpClient` here).
//!   - `presage::Manager` and `libsignal-service-rs` consumed via the rev-pinned forks (docs/FORKS.md).
//!
//! # Why a `LocalExecutor`
//!
//! `presage`'s storage traits use `#[async_trait(?Send)]` (see
//! `libsignal/protocol/src/storage/traits.rs`), and the PDDB-backed
//! `PddbStore` holds non-`Send` cache handles. A `LocalExecutor`
//! pins all spawned tasks to this single OS thread and side-steps
//! the `Send` requirement; the same pattern is used by
//! Whisperfish-Qt on Linux.
//!
//! The `thread_local!` installations below
//! ([`presage::libsignal_service::transport::set_http_client`] and
//! [`presage::set_executor`]) are per-thread; any future contributor
//! that spawns a second thread which calls libsignal/presage APIs
//! must repeat these installations at the new thread's startup or
//! libsignal-service-rs panics on first WS construction. WS frame I/O
//! itself runs on [`xous_net_bridge`]'s `ws_pump` thread pair (setup
//! + reader + writer), not on this thread; the worker only sees
//! `WebSocketChannels` ends.
//!
//! # Trust boundary
//!
//! This crate sees libsignal-decrypted plaintext on the inbound
//! path (after `Manager::receive_messages` has run a frame through
//! `ServiceCipher::open_envelope`) and sender-supplied plaintext on
//! the outbound path (before `Manager::send_message` encrypts it
//! under Double Ratchet). Sensitive material that transits this
//! crate includes the registration record (ACI, PNI, master key) and
//! plaintext message bodies. None of these are logged in cleartext —
//! see the trace-line conventions in this module's source.

mod cmd;

use std::sync::Arc;
use std::thread::{self, JoinHandle};

use async_channel::{Receiver, Sender};
use async_executor::LocalExecutor;
pub use cmd::{Cmd, Event};
use futures_lite::future::block_on;
use presage::Manager;
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::transport;
use presage::manager::Registered;
use presage_store_pddb::PddbStore;
use xous_net_bridge::{SyncHttpClient, signal_production_roots};

/// Worker-thread stack size.
///
/// 2 MiB is the empirical floor for the deepest path in the link
/// flow: a `PUT /v1/accounts/attributes` post-link call runs zkgroup
/// credential batch construction + serde JSON build + rustls TLS
/// write + tungstenite WS framing, deep enough to blow a 1 MiB stack.
/// Xous commits stack pages eagerly via `map_memory`, so this is the
/// RAM the worker thread permanently reserves from the 16 MiB SRAM
/// budget — every increase here costs SRAM that cannot be reclaimed
/// while the worker is alive.
///
/// # rv32 / 16 MiB constraint
///
/// If a future flow stage overflows again, the next step is 4 MiB.
/// Profile the failing call to confirm before adjusting; cheaper
/// fixes (boxing large futures, shrinking serde build state) may
/// land within the existing budget.
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

/// Spawn the `presage::Manager` worker thread.
///
/// Returns a [`JoinHandle`] for the worker thread itself. The worker
/// terminates when either:
///
/// - `cmd_rx` returns `Err(RecvError)` (the main thread dropped its sender — implicit shutdown), or
/// - it processes a [`Cmd::Shutdown`] and emits [`Event::ShuttingDown`].
///
/// `event_tx` is held across `await` points so the executor parks on
/// I/O rather than busy-waiting; cloning is cheap (the channel
/// handle is `Arc`-shaped).
///
/// On any `event_tx.send` failure, the worker exits cleanly rather
/// than panicking — if the main thread has dropped its receiver, the
/// right thing is to teardown, not to abort the executor.
///
/// # Trust boundary
///
/// Spawn-time only. The caller passes in a `PddbStore` that already
/// owns access to the protocol-store dictionaries; the worker
/// thread becomes the sole owner of that store handle for life. The
/// channel pair (`cmd_rx`, `event_tx`) is the *only* surface through
/// which the rest of xas exchanges work with the Signal-Protocol
/// state machine — see [`crate::Cmd`] and [`crate::Event`].
///
/// # Panics
///
/// Panics if the OS refuses to spawn the worker thread (`thread::
/// Builder::spawn` returning `Err`). The Xous kernel may run out of
/// thread slots; on a healthy boot this is unreachable.
///
/// # rv32 / 16 MiB constraint
///
/// The worker permanently reserves 2 MiB of SRAM for its stack
/// (`WORKER_STACK_BYTES`). Calling this twice produces two threads
/// and two stack reservations — there is no intent for multiple
/// workers to coexist; the binary spawns exactly one.
pub fn run_signal_worker(store: PddbStore, cmd_rx: Receiver<Cmd>, event_tx: Sender<Event>) -> JoinHandle<()> {
    thread::Builder::new()
        .name("signal-worker".into())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || worker_main(store, cmd_rx, event_tx))
        .expect("spawn signal-worker thread")
}

/// Worker-thread entry point invoked from inside the spawned thread.
///
/// Wires up the libsignal/presage thread-locals (HTTP client, task
/// spawner, presage executor), then `block_on`s the [`LocalExecutor`]
/// running the async dispatch loop. Returns when the dispatch loop
/// breaks (shutdown path).
///
/// The [`LocalExecutor`] is allocated via `Box::leak` so async tasks
/// spawned onto it can borrow it for `'static`. The executor is
/// `!Send` and stays pinned to this thread for the process lifetime;
/// because the worker thread itself never exits during normal
/// operation, the leak is intentional and bounded — there is at most
/// one executor allocation per process.
///
/// # rv32 / 16 MiB constraint
///
/// Single-threaded async on a single hart. Every spawned task runs
/// on this same thread; there is no work-stealing and no
/// `Send`-required future. presage's `#[async_trait(?Send)]` markers
/// (per `libsignal/protocol/src/storage/traits.rs`) and the many
/// `!Send` store-cache pointers depend on this.
fn worker_main(store: PddbStore, cmd_rx: Receiver<Cmd>, event_tx: Sender<Event>) {
    // `Box::leak` is intentional: spawned tasks borrow the executor
    // for `'static`. The leak is bounded (one allocation per process).
    let executor: &'static LocalExecutor<'static> = Box::leak(Box::new(LocalExecutor::new()));

    // Install the per-thread state that libsignal-service-rs and
    // presage require on every thread that calls their async APIs.
    // The worker is the only such thread.
    //
    // 1. `HttpClient` — the sync HTTP/1.1 + WebSocket transport (`SyncHttpClient` from `xous-net-bridge`).
    //    Cloning is cheap (Arc-shaped).
    // 2. `TaskSpawner` — closure used by libsignal-service-rs's internals (`provisioning::link_device`, WS
    //    handlers) to fire-and-forget detached tasks onto our local executor.
    //
    // Without either, `Manager::link_secondary_device` panics on its
    // first internal `PushService` construction or `ws()` call.
    transport::set_http_client(Arc::new(SyncHttpClient::new(
        signal_production_roots(),
        format!("xas/{}", env!("CARGO_PKG_VERSION")),
    )));
    transport::set_task_spawner(Box::new(|task| {
        executor.spawn(task).detach();
    }));
    // presage's `receive_messages` and other long-running Manager
    // ops spawn their own background tasks via
    // `presage::runtime::spawn_detached`, which uses a separate
    // thread-local from libsignal-service's `task_spawner` and panics
    // if not configured. Wire to the same LocalExecutor.
    presage::set_executor(executor);

    block_on(executor.run(async move {
        tracing::debug!("signal-worker: ready");

        // Op-channel handle to the manager task. `Some(tx)` once a
        // `Manager<S, Registered>` exists (startup `load_registered`
        // or a completed link) — the task owns the Manager for its
        // lifetime and every manager-touching command is forwarded to
        // it as a [`WorkerOp`]. `None` means not linked (or the task
        // died). Dropping the sender tears the task down (Logout,
        // shutdown).
        let mut manager_ops: Option<Sender<WorkerOp>> = None;

        // Cached identity fields. Populated whenever the worker sees
        // a successful Manager (`load_registered` or
        // `link_secondary_device`); served back via
        // `Cmd::GetAccountInfo` for the UI Profile screen on
        // cold-start where `Event::LinkComplete` may have fired
        // before the user navigated to Profile (or never fired
        // because PDDB wasn't unlocked within the `load_registered`
        // retry budget).
        let mut cached_account_info: Option<crate::cmd::AccountInfoData> = None;

        // Auto-load existing registration so the user doesn't re-link
        // on every boot. PDDB may not be mounted at worker spawn time
        // (mount fires lazily on first IPC, racing with us); retry on
        // transient errors until the store either returns a Manager
        // or a definitive `NotYetRegistered`.
        //
        // LOGGING: the success arm below emits `device_name`, `aci`,
        // and `phone` to the log pipeline at info level. All three
        // are Signal account identifiers (PII) — a known
        // log-discipline audit item.
        log::info!("worker: attempting load_registered from PDDB");
        let mut linked_attempts = 0;
        loop {
            match Manager::load_registered(store.clone()).await {
                Ok(manager) => {
                    let info = crate::cmd::AccountInfoData::from_manager(&manager);
                    log::info!(
                        "worker: load_registered OK — device={} aci={} phone={}",
                        info.device_name, info.aci, info.phone
                    );
                    cached_account_info = Some(info.clone());
                    let _ = event_tx
                        .send(Event::LinkComplete {
                            device_name: info.device_name,
                            aci: info.aci,
                            phone: info.phone,
                        })
                        .await;
                    manager_ops = Some(spawn_manager_task(
                        executor,
                        manager,
                        store.clone(),
                        event_tx.clone(),
                    ));
                    break;
                }
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("not yet registered") || msg.contains("NotYetRegistered") {
                        log::info!("worker: load_registered: not registered yet (first boot)");
                        break;
                    }
                    linked_attempts += 1;
                    if linked_attempts >= 10 {
                        log::warn!("worker: load_registered gave up after 10 retries: {}", e);
                        break;
                    }
                    log::info!(
                        "worker: load_registered transient err (attempt {}/10): {}",
                        linked_attempts, e
                    );
                    futures_lite::future::yield_now().await;
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }

        loop {
            match cmd_rx.recv().await {
                Ok(Cmd::Hello) => {
                    if event_tx.send(Event::Pong).await.is_err() {
                        tracing::warn!("event channel dropped while sending Pong; shutting down");
                        break;
                    }
                }
                Ok(Cmd::GetWhoami) => {
                    let outcome = handle_whoami(store.clone()).await;
                    if event_tx.send(Event::Whoami(outcome)).await.is_err() {
                        tracing::warn!("event channel dropped while sending Whoami; shutting down");
                        break;
                    }
                }
                Ok(Cmd::LinkDevice { device_name }) => {
                    log::info!("worker: Cmd::LinkDevice received");
                    // Pre-link stale-store guard. Linking on top of
                    // leftover account state re-inherits stale
                    // sessions and orphaned kyber records (the
                    // prekey-storm seed). Do NOT wipe here — the
                    // implicit link-time wipe (3680fe2) hung a
                    // device and was reverted (fa1c37b). Detect,
                    // refuse, and let the UI route the user to the
                    // explicit Wipe settings flow. Probe errors
                    // fail open inside `has_account_state`, so a
                    // flaky PDDB cannot block a genuine first link.
                    if store.has_account_state() {
                        log::warn!("worker: link refused — store holds prior account state; wipe first");
                        if event_tx.send(Event::StaleStoreDetected).await.is_err() {
                            tracing::warn!(
                                "event channel dropped while sending StaleStoreDetected; shutting down"
                            );
                            break;
                        }
                        continue;
                    }
                    use futures::FutureExt;
                    use futures::future::{self, Either};
                    use futures::pin_mut;

                    // Cancel primitive: a 1-slot async-channel. The
                    // outer "race" loop below sends `()` on
                    // `cancel_tx` when `Cmd::LinkCancel` arrives;
                    // the link future is wrapped to race against
                    // `cancel_rx.recv()`. Dropping `cancel_tx` (the
                    // shutdown path) also closes the channel — the
                    // `recv()` sees `RecvError`, and the race
                    // interprets either signal as "cancel."
                    let (cancel_tx, cancel_rx) = async_channel::bounded::<()>(1);

                    let store_for_link = store.clone();
                    let event_tx_for_link = event_tx.clone();
                    let link_with_cancel = async move {
                        let h = handle_link_device(
                            store_for_link,
                            event_tx_for_link.clone(),
                            device_name,
                        );
                        pin_mut!(h);
                        let cancel = cancel_rx.recv();
                        pin_mut!(cancel);
                        match future::select(h, cancel).await {
                            Either::Left((result, _)) => result,
                            Either::Right((_, _)) => {
                                log::info!("worker/link: cancelled by user");
                                let _ = event_tx_for_link
                                    .send(Event::LinkError("Cancelled".to_string()))
                                    .await;
                                Err(())
                            }
                        }
                    }
                    .fuse();
                    pin_mut!(link_with_cancel);

                    // While link runs, also poll cmd_rx so a
                    // Cmd::LinkCancel sent from the UI can reach us.
                    // Other Cmds during in-flight link are silently
                    // dropped — the UI is on Screen::Linking and only
                    // LinkCancel makes sense there. Cmd::Shutdown
                    // during link cancels link first, then exits.
                    let outcome: Result<Manager<PddbStore, Registered>, ()> = 'race: loop {
                        futures::select_biased! {
                            result = link_with_cancel => break 'race result,
                            cmd = cmd_rx.recv().fuse() => match cmd {
                                Ok(Cmd::LinkCancel) => {
                                    log::info!("worker: LinkCancel during in-flight link");
                                    let _ = cancel_tx.try_send(());
                                    // link_with_cancel resolves to
                                    // Err(()) on its next poll; loop
                                    // back to receive that and exit.
                                }
                                Ok(Cmd::Shutdown) => {
                                    log::info!("worker: Shutdown during in-flight link");
                                    let _ = cancel_tx.try_send(());
                                    let _ = event_tx.send(Event::ShuttingDown).await;
                                    return;
                                }
                                Ok(_other) => {
                                    log::warn!(
                                        "worker: cmd dropped during in-flight link (UI shouldn't send anything but LinkCancel here)"
                                    );
                                }
                                Err(_) => {
                                    log::info!("worker: cmd channel closed during in-flight link");
                                    let _ = cancel_tx.try_send(());
                                    return;
                                }
                            }
                        }
                    };
                    drop(cancel_tx);

                    match outcome {
                        Ok(manager) => {
                            // `Event::LinkComplete` was already sent
                            // from inside `handle_link_device`. Cache
                            // the account info for `Cmd::GetAccountInfo`
                            // and hand the Manager to a fresh manager
                            // task, which owns it from here on.
                            cached_account_info =
                                Some(crate::cmd::AccountInfoData::from_manager(&manager));
                            manager_ops = Some(spawn_manager_task(
                                executor,
                                manager,
                                store.clone(),
                                event_tx.clone(),
                            ));
                        }
                        Err(()) => {
                            // `handle_link_device` (or the cancel
                            // branch above) already sent the
                            // appropriate `Event::LinkError`. Drop
                            // any half-linked state on the floor;
                            // retry by sending another
                            // `Cmd::LinkDevice`.
                        }
                    }
                }
                Ok(Cmd::LinkCancel) => {
                    // Outside an in-flight link this is a no-op —
                    // the UI shouldn't send it from non-Linking
                    // screens. Log and ignore defensively.
                    log::info!("worker: LinkCancel received outside in-flight link; no-op");
                }
                Ok(Cmd::GetAccountInfo) => {
                    log::info!("worker: Cmd::GetAccountInfo received");
                    // Try the cache first (fastest path: this is
                    // populated after any successful load_registered
                    // or link_secondary_device).
                    let outcome = if let Some(info) = cached_account_info.as_ref() {
                        log::info!("worker: GetAccountInfo — serving from cache");
                        Ok(info.clone())
                    } else {
                        // No cache. Try a fresh load_registered —
                        // PDDB may have unlocked since the worker's
                        // startup retry budget expired.
                        log::info!("worker: GetAccountInfo — cache miss, retrying load_registered");
                        match Manager::load_registered(store.clone()).await {
                            Ok(manager) => {
                                let info = crate::cmd::AccountInfoData::from_manager(&manager);
                                cached_account_info = Some(info.clone());
                                // If no manager task is running (e.g.
                                // the startup load failed), keep this
                                // Manager — saves a re-load when
                                // StartReceive arrives.
                                if manager_ops.is_none() {
                                    manager_ops = Some(spawn_manager_task(
                                        executor,
                                        manager,
                                        store.clone(),
                                        event_tx.clone(),
                                    ));
                                }
                                Ok(info)
                            }
                            Err(e) => {
                                let msg = format!("{}", e);
                                log::warn!("worker: GetAccountInfo — load_registered err: {}", msg);
                                Err(msg)
                            }
                        }
                    };
                    if event_tx.send(Event::AccountInfo(outcome)).await.is_err() {
                        tracing::warn!("event channel dropped while sending AccountInfo");
                        break;
                    }
                }
                Ok(Cmd::StartReceive) => {
                    log::info!("worker: Cmd::StartReceive received");
                    let Some(ops) = manager_ops.as_ref() else {
                        log::warn!("worker: StartReceive — not linked");
                        let _ = event_tx
                            .send(Event::ReceiveError(
                                "not linked yet — send Cmd::LinkDevice first".to_string(),
                            ))
                            .await;
                        continue;
                    };
                    if ops.send(WorkerOp::StartReceive).await.is_err() {
                        manager_ops = None;
                        let _ = event_tx
                            .send(Event::ReceiveError("manager task died".to_string()))
                            .await;
                    }
                }
                Ok(Cmd::SendMessage { recipient, body, timestamp }) => {
                    let Some(ops) = manager_ops.as_ref() else {
                        let _ = event_tx
                            .send(Event::SendError {
                                reason: "not linked yet — send Cmd::LinkDevice first"
                                    .to_string(),
                                timestamp: Some(timestamp),
                            })
                            .await;
                        continue;
                    };
                    // Forward to the manager task. If the channel is
                    // closed (manager task exited) we drop the
                    // manager_ops handle and surface the error.
                    if ops
                        .send(WorkerOp::Send(InnerSend { recipient, body, timestamp }))
                        .await
                        .is_err()
                    {
                        manager_ops = None;
                        let _ = event_tx
                            .send(Event::SendError {
                                reason: "manager task died".to_string(),
                                timestamp: Some(timestamp),
                            })
                            .await;
                    }
                }
                Ok(Cmd::Logout) => {
                    log::info!("worker: Cmd::Logout received");
                    // SECURITY: best-effort key destruction. See the
                    // `Cmd::Logout` `# Security` block for the wipe's
                    // failure-mode discussion.
                    //
                    // 1. Drop the op-channel sender. The manager task
                    //    sees its channel close and exits, releasing
                    //    the Manager (and its WS pump).
                    manager_ops = None;
                    // 2. Wipe the PDDB-backed Store. `Store::clear`
                    //    chains `clear_registration` +
                    //    `clear_contents` + `delete_dict` for both
                    //    protocol stores. Errors are non-fatal —
                    //    `LoggedOut` is still emitted so the UI
                    //    returns to the pre-link menu, but a warning
                    //    is logged so a re-link doesn't silently mix
                    //    new state with stale leftovers.
                    {
                        use presage::store::{Store, StateStore};
                        let mut store_clone = store.clone();
                        if let Err(e) = StateStore::clear_registration(&mut store_clone).await {
                            log::warn!("worker/logout: clear_registration err: {:?}", e);
                        }
                        if let Err(e) = Store::clear(&mut store_clone).await {
                            log::warn!("worker/logout: Store::clear err: {:?}", e);
                        }
                    }
                    // 3. Reset cached identity so Cmd::GetAccountInfo
                    //    after relink doesn't return stale data.
                    cached_account_info = None;
                    log::info!("worker: Logout complete; emitting LoggedOut");
                    let _ = event_tx.send(Event::LoggedOut).await;
                }
                Ok(Cmd::SyncContacts) => {
                    log::info!("worker: Cmd::SyncContacts received");
                    let Some(ops) = manager_ops.as_ref() else {
                        log::warn!("worker/sync: not linked");
                        let _ = event_tx
                            .send(Event::SyncError(
                                "not linked yet — send Cmd::LinkDevice first".to_string(),
                            ))
                            .await;
                        continue;
                    };
                    if ops.send(WorkerOp::SyncContacts).await.is_err() {
                        manager_ops = None;
                        let _ = event_tx
                            .send(Event::SyncError("manager task died".to_string()))
                            .await;
                    }
                }
                Ok(Cmd::ResolveUsername(input)) => {
                    log::info!("worker: Cmd::ResolveUsername({:?})", input);
                    let Some(ops) = manager_ops.as_ref() else {
                        let _ = event_tx
                            .send(Event::UsernameResolveResult(Err(
                                "not linked yet — send Cmd::LinkDevice first".to_string(),
                            )))
                            .await;
                        continue;
                    };
                    if ops.send(WorkerOp::ResolveUsername(input)).await.is_err() {
                        manager_ops = None;
                        let _ = event_tx
                            .send(Event::UsernameResolveResult(Err(
                                "manager task died".to_string(),
                            )))
                            .await;
                    }
                }
                Ok(Cmd::Shutdown) => {
                    let _ = event_tx.send(Event::ShuttingDown).await;
                    break;
                }
                Err(_) => {
                    // Sender dropped. Treat as implicit shutdown — no
                    // farewell event since nobody's listening anyway.
                    tracing::debug!("signal-worker: cmd channel closed, exiting");
                    break;
                }
            }
        }

        // Dropping the op sender ends the manager task, which drops
        // the Manager. A graceful teardown (close WS, flush sessions)
        // would be nicer; `Drop` semantics are sufficient for the
        // current shutdown path.
        drop(manager_ops);
    }));
}

/// Run [`presage::Manager::link_secondary_device`] and forward the
/// resulting provisioning URL to the UI as [`Event::LinkUrl`] as soon
/// as it arrives, then await the user-confirmation step.
///
/// Returns the linked `Manager` on success (the dispatcher hands it
/// to a fresh [`manager_task`]) or `Err(())` after sending
/// [`Event::LinkError`].
///
/// Uses `futures::channel::oneshot` for the URL handoff (the type
/// presage's API requires) and `futures::future::join` to drive the
/// link future and the URL forwarder concurrently. The store is
/// cloned for the call — `link_secondary_device` consumes its `S`
/// argument: it clears the registration on entry and writes fresh
/// keys. Cloning means the worker's outer `store` (still owned, used
/// for `whoami` and similar paths) stays usable if linking fails.
///
/// # Trust boundary
///
/// This is the only path that originates a new Signal-Protocol
/// identity for the worker. On success, freshly-generated identity
/// keys and a registered `ServiceIds` triple have been written to
/// the cloned store; the returned `Manager<PddbStore, Registered>`
/// is the trust witness that those keys exist and the server
/// accepted them.
///
/// # Security
///
/// The provisioning URL forwarded through `Event::LinkUrl` is
/// short-lived but high-value — see that variant's `# Security`
/// section.
///
/// # Logging
///
/// Emits the provisioning URL to the log pipeline only under the
/// default-off `link-uri-uart` feature (the URL is the link
/// credential for its window); default builds log its length. The
/// user-chosen `device_name` is still logged.
async fn handle_link_device(
    store: PddbStore,
    event_tx: Sender<Event>,
    device_name: String,
) -> Result<Manager<PddbStore, Registered>, ()> {
    use futures::channel::oneshot;
    use futures::future;

    log::info!("worker/link: begin (device_name={:?})", device_name);

    let (url_tx, url_rx) = oneshot::channel::<url::Url>();
    let event_tx_for_url = event_tx.clone();

    let forwarder = async move {
        match url_rx.await {
            Ok(url) => {
                // The exact "URL received from libsignal:" text is
                // grepped by tests/hosted/test_link_qr.sh — keep it
                // stable under the feature.
                #[cfg(feature = "link-uri-uart")]
                log::info!("worker/link: URL received from libsignal: {}", url);
                #[cfg(not(feature = "link-uri-uart"))]
                log::info!("worker/link: link URL received ({} bytes)", url.as_str().len());
                if let Err(e) = event_tx_for_url.send(Event::LinkUrl(url.to_string())).await {
                    log::warn!("worker/link: event_tx send LinkUrl failed: {:?}", e);
                }
            }
            Err(e) => {
                log::warn!("worker/link: url_rx closed before URL: {:?}", e);
            }
        }
    };

    log::info!("worker/link: calling Manager::link_secondary_device");
    let (link_result, _) = future::join(
        Manager::link_secondary_device(store, SignalServers::Production, device_name, url_tx),
        forwarder,
    )
    .await;
    log::info!("worker/link: link_secondary_device returned");

    match link_result {
        Ok(manager) => {
            let data = manager.registration_data();
            let device_name = data.device_name.clone().unwrap_or_default();
            let aci = data.service_ids.aci.to_string();
            let phone = data.phone_number.to_string();
            let _ = event_tx.send(Event::LinkComplete { device_name, aci, phone }).await;
            // NOTE: load-bearing — do NOT auto-fetch contacts on link.
            //
            // `manager.request_contacts()` does multiple WS round-trips
            // (establish self-session, fetch own prekey bundle, send
            // self-targeted contact-sync request) and BLOCKS the
            // worker for 30-90s on rv32. During that window
            // `Cmd::StartReceive` cannot be processed, and the
            // self-targeted send races the Signal-server WS-rotation
            // problem that intermittently kills user sends.
            //
            // xas can already send to UUIDs (the working path).
            // Phone-number recipient resolution stays broken until
            // the user runs the explicit `Cmd::SyncContacts` flow;
            // see that variant's docs.
            log::info!("worker/link: skipping request_contacts (deferred to user-triggered Sync)");
            Ok(manager)
        }
        Err(e) => {
            let _ = event_tx.send(Event::LinkError(format!("{e}"))).await;
            Err(())
        }
    }
}

/// Send payload carried inside [`WorkerOp::Send`].
///
/// [`Cmd::SendMessage`] decomposes into this struct before being
/// forwarded to the long-running manager task; the dispatcher cannot
/// call `send_message` directly because the `&mut Manager` borrow is
/// owned by the receive-stream loop inside `manager_task`.
///
/// # Security
///
/// `body` is plaintext at this point — see [`Cmd::SendMessage`]'s
/// `# Trust boundary`. Logging discipline applies (length only,
/// never the body itself).
struct InnerSend {
    /// Recipient string (`ACI UUID` or `+e164`); parsed by
    /// [`handle_send`] before invoking `Manager::send_message`.
    recipient: String,
    /// Plaintext message body. MUST NOT be logged.
    body: String,
    /// Client-generated unix-ms timestamp; carried through to
    /// `manager.send_message` and echoed back in
    /// [`Event::SendComplete`] / [`Event::SendError`] so the UI can
    /// correlate the optimistic-render row with the eventual
    /// outcome event.
    timestamp: u64,
}

/// Operations forwarded from the worker dispatcher to the
/// [`manager_task`] that owns the linked `Manager`.
///
/// Every command that needs `&mut Manager` crosses this channel —
/// the dispatcher never holds the Manager itself. `StartReceive`
/// gates the receive stream; the other ops run while the stream is
/// dropped (between iterations, or before the stream has ever been
/// opened), when the `&mut` borrow is free.
enum WorkerOp {
    /// Open the receive stream. Idempotent once receiving.
    StartReceive,
    /// Send a 1:1 text; see [`InnerSend`].
    Send(InnerSend),
    /// `manager.request_contacts()` round-trip; replies with
    /// [`Event::SyncComplete`] / [`Event::SyncError`].
    SyncContacts,
    /// `manager.lookup_username` lookup; replies with
    /// [`Event::UsernameResolveResult`].
    ResolveUsername(String),
}

/// Spawn the [`manager_task`] for a freshly linked or loaded
/// `Manager` and return the op-channel sender.
///
/// Dropping the returned sender ends the task: it sees the channel
/// close and exits, dropping the Manager (and with it the WS pump).
fn spawn_manager_task(
    executor: &'static LocalExecutor<'static>,
    manager: Manager<PddbStore, Registered>,
    store: PddbStore,
    event_tx: Sender<Event>,
) -> Sender<WorkerOp> {
    let (op_tx, op_rx) = async_channel::bounded::<WorkerOp>(8);
    executor.spawn(manager_task(manager, store, event_tx, op_rx)).detach();
    op_tx
}

/// Long-running task that owns the linked `Manager` for its lifetime
/// and multiplexes the receive stream with inbound [`WorkerOp`]s
/// (send, contact-sync, username-resolve).
///
/// Spawned via [`spawn_manager_task`] as soon as a Manager exists
/// (startup `load_registered` or a completed link). The receive
/// stream opens on [`WorkerOp::StartReceive`]; until then the task
/// parks on the op channel, so sync / username-resolve / send ops
/// work on a linked-but-not-yet-receiving Manager. The task runs
/// until either (a) the worker dispatcher drops the op sender
/// (`Cmd::Logout`, `Cmd::Shutdown`, or implicit teardown), or
/// (b) the receive loop hits a terminal error
/// (`MAX_CONSECUTIVE_FAILURES` reached, a fatal `4409` close code,
/// or the `MAX_REAUTH_403S` budget exhausted).
///
/// # Manager ownership and Drop
///
/// The `manager` parameter is moved into this task at spawn time
/// and is dropped only when the task exits. On Drop the
/// [`presage_store_pddb::PddbStore`] handle held inside `Manager`
/// is dropped too; the `PddbStore` is `Clone + Send + Sync` but
/// `Clone` is shallow (clones share one
/// `Arc<Mutex<HashMap<SessionKey, SessionRecord>>>` session cache
/// and one `Arc<dyn KvBackend>`). The `session_cache` therefore
/// stays alive as long as *any* clone exists — see
/// `presage_store_pddb::PddbStore` Clone semantics in the docstring
/// of that type. libsignal's `SessionRecord` does **not** derive
/// `Zeroize` upstream, so an
/// extended `Manager` / `PddbStore` lifetime extends the post-Drop
/// memory-disclosure window for ratchet state. The receive loop
/// flushes sessions on `Received::QueueEmpty`; future code paths
/// that hold long-lived Store clones should consider an explicit
/// `flush_sessions` + drop before the receive cycle ends.
///
/// `presage_store_pddb::PddbBackend` does **not** retry internally
/// on `NotMounted` — that retry loop lives here in the worker
/// (`worker_main`'s `load_registered` loop). New paths that read
/// the store must do their own readiness handling.
///
/// # Why the multiplexer exists
///
/// presage's API forces a difficult shape: `receive_messages`,
/// `send_message`, `request_contacts`, and `lookup_username` all
/// take `&mut self`, and `receive_messages` returns a stream that
/// holds the `&mut self` borrow for its lifetime. The stream and any
/// other Manager op cannot be in flight at the same time. The
/// workaround: open the stream, `futures::select` between stream
/// items and the op channel; when an op arrives, drop the stream
/// (release the borrow), run the op, then re-open the stream and
/// loop. Re-opening the stream causes presage to re-establish the WS
/// read and replay pending server-side messages from the next batch
/// — no data loss, just a brief reconnect cost.
///
/// # Trust boundary
///
/// All inbound traffic flows through [`process_received`], which
/// receives presage's already-decrypted-and-authenticated
/// [`presage::model::messages::Received::Content`]; emission of
/// [`Event::Message`] thus carries the libsignal trust witness
/// (see that event's `# Trust boundary`). Outbound traffic flows
/// through [`handle_send`], which receives plaintext that has not
/// yet been encrypted (encryption happens inside libsignal's
/// `send_message`).
///
/// # WS close-code semantics
///
/// The receive loop reads `manager.last_identified_close_code()` to
/// distinguish three failure modes on a failed reconnect:
///
/// - `4409 "Connected elsewhere"` — another authenticated WS for the same `(account, deviceId)` displaced
///   this one. Treated as terminal (auto-reconnect would self-displace again); emits
///   [`Event::SignalConflictingDevice`] and exits.
/// - `4401 "Reauthentication required"` followed by repeated `HTTP 403 Forbidden` handshakes — credential
///   rotation has failed permanently. After `MAX_REAUTH_403S` attempts emits [`Event::SignalAuthExpired`] and
///   exits.
/// - `1001 "Connection Idle Timeout"` and other transient closes — exponential backoff (base 1s × 1.5^n,
///   capped at 30s) plus a close-code-specific settling delay (10 s after `4401`, 1 s after `1001`/`4409`) to
///   let the server-side `(account, deviceId)` listener-slot eviction complete before reconnecting.
///
/// # Pending-send grace window
///
/// When `handle_send` exhausts its retry budget against
/// `WebSocket closing`-shaped errors, the cipher may have landed on
/// the server even though the local future returned `Err`. Rather
/// than emit `Event::SendError` immediately, the timestamp is
/// recorded in `pending_unconfirmed_sends` with a 30-second
/// deadline. If a Signal `DELIVERY` receipt for that timestamp
/// arrives within the window, [`process_received`] surfaces
/// `Event::SendComplete` instead. Stale entries are swept by
/// [`sweep_expired_pending_sends`] on every 1-second select tick.
///
/// # Logging
///
/// Emits message kinds and per-stream-item progress markers at
/// `log::info!` (`worker:`, `worker/send:`, `worker/profile:`
/// prefixes). Does not log message bodies. ACI UUIDs and contact
/// names are logged at info level — a known log-discipline
/// audit item.
async fn manager_task(
    mut manager: Manager<PddbStore, Registered>,
    store: PddbStore,
    event_tx: Sender<Event>,
    op_rx: Receiver<WorkerOp>,
) {
    use futures::FutureExt;
    use futures::StreamExt;
    use futures::select;

    // Reason why the inner `select!` pump exits. The pump runs inside
    // a single `loop { select! { ... } }`; surfacing both "an op
    // arrived, drop the stream and run it" and "stream died, drop
    // everything and re-open with backoff" cases up to the outer loop
    // is cleaner than `continue 'outer` from inside the macro.
    enum PumpExit {
        Op(WorkerOp),
        Reopen { reason: String },
        Shutdown,
    }

    // Tell the UI we're listening (only on the first stream open).
    let mut announced = false;

    // The receive stream opens only after `WorkerOp::StartReceive`
    // arrives; until then the task parks on the op channel (the
    // `!receiving` branch at the top of the outer loop).
    let mut receiving = false;

    // Consecutive failures since the last real progress. Used to
    // (a) decide backoff before re-opening the stream and
    // (b) deduplicate the "receive error" event so the UI sees one
    // banner per outage, not one per retry. Reset to 0 after a
    // successful `manager.receive_messages()` AND after observing
    // an actual stream item — opening `Ok` then immediately seeing
    // `None` counts as a failure (no real progress).
    let mut consecutive_failures: u32 = 0;

    // Count of consecutive `4401`-then-`403` reauth failures. After
    // `MAX_REAUTH_403S` in a row the worker treats the auth path as
    // terminally rotten and emits `Event::SignalAuthExpired`. Reset
    // on a successful reconnect or real stream progress (same
    // semantics as `consecutive_failures`).
    let mut consecutive_reauth_403s: u32 = 0;

    // First-touch profile-fetch queue. `process_received` pushes
    // `(aci_uuid, profile_key_bytes)` for any inbound message whose
    // sender wasn't in the contacts store but whose DataMessage
    // carried a profile_key. The queue is drained between
    // receive-stream iterations (when the `&mut manager` borrow is
    // released) and emits `Event::ContactResolved` on success.
    // `fetched_or_failed` tracks ACIs already attempted in this
    // worker run so a 404 doesn't get retried on every cycle.
    //
    // SECURITY: the profile_key bytes (32 bytes per entry) are
    // secret-derived material from the sender. Treated as opaque
    // here and passed to `ProfileKey::create` without copying; never
    // logged. Not wrapped in `Zeroizing`.
    let mut pending_profile_fetches: Vec<(presage::libsignal_service::prelude::Uuid, [u8; 32])> = Vec::new();
    let mut fetched_or_failed: std::collections::HashSet<presage::libsignal_service::prelude::Uuid> =
        std::collections::HashSet::new();

    // Deferred-send map: sends that exhausted the retry loop with a
    // "websocket closing"-shaped error are deferred here instead of
    // immediately surfacing as `Event::SendError`. Key is the message
    // timestamp; value is the deadline. If a DELIVERY receipt arrives
    // for that timestamp before the deadline, the entry is removed
    // and `Event::SendComplete` is emitted instead — the recipient
    // confirms the cipher landed despite the local error.
    //
    // The 30 s grace window is well above the worst-case observed
    // per-send pipeline (~4 minutes total wallclock dominated by the
    // 62-second retry-loop budget; the per-attempt `pipeline_ms` is
    // sub-second).
    let mut pending_unconfirmed_sends: std::collections::HashMap<u64, std::time::Instant> =
        std::collections::HashMap::new();
    const PENDING_RECEIPT_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

    // Cap on how many consecutive failures we tolerate before giving
    // up entirely. With backoff capped at 30 s, this is roughly an
    // 8-minute window of constant retries before a fatal
    // `ReceiveError` is surfaced and the task exits. Empirically the
    // rv32 net stack recovers from idle-WS death in well under a
    // minute, so any failure that persists past this is something
    // that cannot be papered over.
    const MAX_CONSECUTIVE_FAILURES: u32 = 20;

    // Cap on `4401`-then-`403` sequences before `SignalAuthExpired`
    // is surfaced. 3 is intentionally low — hosted evidence shows
    // that once this storm starts it doesn't recover within the
    // user's patience window. Prompting re-link early beats spinning
    // silently for minutes.
    const MAX_REAUTH_403S: u32 = 3;

    // Extra settling delay applied on top of the normal exponential
    // backoff after a `4401` close. The 4401-then-403 storm is
    // hypothesized to share a root cause with the `4409` displacement
    // race: server-side `(account, deviceId)` listener-slot eviction.
    // Giving the eviction time to complete before reopening is the
    // cheapest mitigation. 10 s is a starting heuristic; bump if
    // packet capture shows 403s still firing inside this window.
    const REAUTH_SETTLING_DELAY_MS: u64 = 10_000;

    // Throttle applied after non-zero close codes other than 4401.
    // Server-side `(account, deviceId)` listener-slot eviction is
    // asynchronous. When the WS closes (e.g. 1001 idle) and a
    // reconnect races the eviction, the new auth handshake can
    // displace its own previous WS (4409). 1 s is the starting
    // heuristic.
    const RECONNECT_THROTTLE_MS: u64 = 1_000;

    log::info!("worker: manager_task entered");

    'outer: loop {
        // Not yet receiving: park on the op channel. Ops run directly
        // (the `&mut manager` borrow is free — no stream exists), and
        // `StartReceive` flips into the streaming half below.
        if !receiving {
            sweep_expired_pending_sends(&mut pending_unconfirmed_sends, &event_tx).await;
            let op = if pending_unconfirmed_sends.is_empty() {
                op_rx.recv().await
            } else {
                // A deferred send is awaiting its grace deadline;
                // wake every second so the sweep above can expire it.
                select! {
                    op = op_rx.recv().fuse() => op,
                    _ = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse() => {
                        continue 'outer;
                    }
                }
            };
            match op {
                Ok(WorkerOp::StartReceive) => {
                    log::info!("worker: manager_task — StartReceive, opening stream");
                    receiving = true;
                }
                Ok(op) => {
                    run_manager_op(
                        &mut manager,
                        op,
                        &event_tx,
                        &mut pending_unconfirmed_sends,
                        PENDING_RECEIPT_GRACE,
                    )
                    .await;
                }
                Err(_) => break 'outer,
            }
            continue 'outer;
        }

        // Backoff before reopening if this isn't the first attempt.
        // 1s * 1.5^n capped at 30s. Sleep happens BEFORE the open
        // attempt so a failed open also gets the delay without
        // double-sleeping.
        if consecutive_failures > 0 {
            // 1500 = 1s in ms with 1.5^0; the f64 path is fine in a
            // backoff context — we don't need millisecond accuracy.
            let base_backoff_ms =
                (1000.0 * 1.5_f64.powi(consecutive_failures as i32 - 1)).min(30_000.0) as u64;

            // Close-code-aware extra delay. Read once per iteration so
            // the value can't shift mid-`select!`. The slot retains the
            // last-closed WS until a successful reconnect replaces it
            // (see `Manager::last_identified_close_code` docstring), so
            // a streak of failed reconnects all see the same prior
            // close code.
            let prev_close = manager.last_identified_close_code().await;
            let extra_delay_ms: u64 = match prev_close {
                // 4401 "Reauthentication required": settling delay so
                // server-side (account, deviceId) listener-slot
                // eviction completes before reconnect.
                Some(4401) => REAUTH_SETTLING_DELAY_MS,
                // 4409 "Connected elsewhere" should not normally
                // reach this backoff path — the err-arm below treats
                // it as terminal and emits SignalConflictingDevice.
                // Defensive throttle in case that policy is ever
                // loosened.
                Some(4409) => RECONNECT_THROTTLE_MS,
                // 1001 idle close: small throttle to let the server's
                // listener-slot eviction complete before reconnect
                // can race it.
                Some(1001) => RECONNECT_THROTTLE_MS,
                // Any other close code or no prior close: exponential
                // backoff only, no extra delay.
                _ => 0,
            };
            let backoff_ms = base_backoff_ms + extra_delay_ms;

            log::info!(
                "worker: manager_task — backoff {}ms before re-open (consecutive_failures={}, prev_close={:?}, extra_delay_ms={})",
                backoff_ms,
                consecutive_failures,
                prev_close,
                extra_delay_ms,
            );
            futures_timer::Delay::new(std::time::Duration::from_millis(backoff_ms)).await;
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                log::error!(
                    "worker: manager_task — gave up after {} consecutive failures",
                    consecutive_failures,
                );
                let _ = event_tx
                    .send(Event::ReceiveError(format!(
                        "receive failed {} times; restart xas to retry",
                        consecutive_failures,
                    )))
                    .await;
                return;
            }
        }

        // Open the stream for this iteration.
        log::info!("worker: manager_task — opening receive_messages stream");
        let mut stream = match manager.receive_messages().await {
            Ok(s) => {
                log::info!("worker: manager_task — receive_messages OK");
                Box::pin(s)
            }
            Err(e) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                let err_str = e.to_string();
                log::warn!(
                    "worker: manager_task — receive_messages err (failure #{}): {}",
                    consecutive_failures,
                    err_str,
                );

                // Fetch the previous WS's close code once; reused by
                // both the 4409 and 4401-403 checks below. Reads the
                // slot of the most recently closed identified WS —
                // see `Manager::last_identified_close_code` for why
                // this returns the *previous* WS's code after a
                // failed reconnect.
                let prev_close = manager.last_identified_close_code().await;

                // 4409 "Connected elsewhere": another authenticated
                // WS for the same (account, deviceId) displaced ours.
                // Auto-reconnecting would self-displace again
                // (RECONNECT_THROTTLE_MS gives the eviction time to
                // complete, but if 4409 still surfaces here that
                // means a *different* device — or our own race-prone
                // reconnect — is genuinely interfering). Treat as
                // terminal; emit `SignalConflictingDevice` and exit.
                if matches!(prev_close, Some(4409)) {
                    log::warn!(
                        "worker: manager_task — previous WS closed with 4409 \
                         (Connected elsewhere); treating as terminal and emitting \
                         Event::SignalConflictingDevice (issue #1 Bug A)",
                    );
                    let _ = event_tx
                        .send(Event::SignalConflictingDevice(format!(
                            "Server reported 4409 'Connected elsewhere' — another \
                             device or app instance with this Signal account is \
                             active. Receive-stream error: {}",
                            err_str,
                        )))
                        .await;
                    return;
                }

                // 4401 + 403 storm detection: if the previous
                // identified WS was closed by the server with code
                // 4401 ("Reauth required") AND this fresh handshake
                // came back as HTTP 403 Forbidden, count it. After
                // `MAX_REAUTH_403S` in a row, treat as terminal and
                // surface `SignalAuthExpired`.
                //
                // The "403 Forbidden" substring is a deliberate
                // stringly-typed check: the error path is
                // `xous-net-bridge` -> tungstenite -> libsignal-service
                // `HttpTransport` wrapping; "403 Forbidden" is the
                // stable terminator (RFC 7231) in the formatter. A
                // typed approach would require cross-crate enums
                // plumbed through `ServiceError`.
                if matches!(prev_close, Some(4401)) && err_str.contains("403 Forbidden") {
                    consecutive_reauth_403s = consecutive_reauth_403s.saturating_add(1);
                    log::warn!(
                        "worker: manager_task — 4401-then-403 #{}/{} (issue #13 Bug B)",
                        consecutive_reauth_403s,
                        MAX_REAUTH_403S,
                    );
                    if consecutive_reauth_403s >= MAX_REAUTH_403S {
                        log::error!(
                            "worker: manager_task — Signal auth permanently expired \
                             (close code 4401 followed by {} consecutive 403s); \
                             emitting Event::SignalAuthExpired",
                            consecutive_reauth_403s,
                        );
                        let _ = event_tx
                            .send(Event::SignalAuthExpired(format!(
                                "Server requested reauthentication (code 4401); \
                                 refreshed handshake rejected with HTTP 403 after \
                                 {} retries.",
                                consecutive_reauth_403s,
                            )))
                            .await;
                        return;
                    }
                }

                // Surface only the first error in a streak so the UI
                // shows one banner per outage, not N. (SignalAuthExpired
                // above is the exception — that's a terminal event, not
                // a transient error banner.)
                if consecutive_failures == 1 {
                    let _ = event_tx.send(Event::ReceiveError(format!("receive_messages: {e}"))).await;
                }
                continue 'outer;
            }
        };

        if !announced {
            log::info!("worker: manager_task — sending ReceiveStarted");
            if event_tx.send(Event::ReceiveStarted).await.is_err() {
                return;
            }
            announced = true;
        }

        // Pump items + ops + pending-send timeout sweep.
        let exit: PumpExit = loop {
            // Scan `pending_unconfirmed_sends` each iteration; emit
            // `SendError` for any whose grace window expired. The
            // 1-second `select!` timeout below bounds how late these
            // can fire.
            sweep_expired_pending_sends(&mut pending_unconfirmed_sends, &event_tx).await;

            select! {
                item = stream.next().fuse() => {
                    match item {
                        Some(item) => {
                            log::info!("worker: stream item received");
                            // Real progress on this stream — clear
                            // the failure counter so the next reopen
                            // (when `handle_send` forces one) doesn't
                            // sleep at all. Also clear the
                            // 4401-then-403 counter, since real
                            // progress proves the auth path recovered.
                            consecutive_failures = 0;
                            consecutive_reauth_403s = 0;
                            if !process_received(
                                item,
                                &store,
                                &event_tx,
                                &mut pending_profile_fetches,
                                &mut pending_unconfirmed_sends,
                            ).await {
                                // event_tx closed — bail.
                                return;
                            }
                        }
                        None => {
                            // Stream ended — typically because the
                            // identified WS died (rv32: keepalive
                            // responses not coming back, libsignal
                            // closes after 2 outstanding). Don't
                            // exit the task — re-open after backoff.
                            break PumpExit::Reopen {
                                reason: "stream ended".to_string(),
                            };
                        }
                    }
                }
                op = op_rx.recv().fuse() => {
                    match op {
                        Ok(WorkerOp::StartReceive) => {
                            // Already receiving; keep pumping.
                            log::info!("worker: StartReceive — already running, idempotent drop");
                        }
                        Ok(op) => break PumpExit::Op(op),
                        Err(_) => {
                            // Sender side dropped — worker dispatcher
                            // ended or logged out; shutting down.
                            break PumpExit::Shutdown;
                        }
                    }
                }
                _ = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse() => {
                    // Wake-up to re-run the pending-send sweep above.
                    // No other state to touch here.
                }
            }
        };

        // Drop the stream so the &mut borrow on `manager` is
        // released before we call anything else on `manager`.
        log::info!("worker: manager_task — dropping receive stream to free &mut manager borrow");
        drop(stream);

        // Drain pending first-touch profile fetches now that the
        // manager borrow is released. Each fetch is one HTTP round-
        // trip via the identified websocket; on success we cache the
        // ACI in `fetched_or_failed` (so a churn of messages from the
        // same sender doesn't re-fetch) and emit ContactResolved so
        // the UI can swap the UUID for the name in any rendered rows.
        // On failure we still mark the ACI as attempted — a 404 means
        // the sender opted out of profile lookups and won't change.
        if !pending_profile_fetches.is_empty() {
            use presage::libsignal_service::protocol::Aci;
            use presage::libsignal_service::zkgroup::profiles::ProfileKey;
            let drained: Vec<_> = pending_profile_fetches.drain(..).collect();
            for (aci_uuid, key_bytes) in drained {
                if !fetched_or_failed.insert(aci_uuid) {
                    continue; // already tried this run
                }
                let key = ProfileKey::create(key_bytes);
                let aci = Aci::from(aci_uuid);
                log::info!("worker/profile: fetching profile for {}", aci_uuid);
                match manager.retrieve_profile_by_uuid(aci, key).await {
                    Ok(profile) => {
                        let name_str = profile
                            .name
                            .as_ref()
                            .map(|n| {
                                let g = n.given_name.trim();
                                let f = n.family_name.as_deref().unwrap_or("").trim();
                                if f.is_empty() { g.to_string() } else { format!("{} {}", g, f) }
                            })
                            .unwrap_or_default();
                        if name_str.is_empty() {
                            log::info!(
                                "worker/profile: {} resolved with empty name; skipping event",
                                aci_uuid
                            );
                            continue;
                        }
                        log::info!("worker/profile: {} resolved → {:?}", aci_uuid, name_str);
                        let _ = event_tx.send(Event::ContactResolved { aci_uuid, name: name_str }).await;
                    }
                    Err(e) => {
                        log::info!(
                            "worker/profile: {} fetch failed (will not retry this run): {}",
                            aci_uuid,
                            e
                        );
                    }
                }
            }
        }

        match exit {
            PumpExit::Op(op) => {
                log::info!("worker: manager_task — running op between stream iterations");
                run_manager_op(
                    &mut manager,
                    op,
                    &event_tx,
                    &mut pending_unconfirmed_sends,
                    PENDING_RECEIPT_GRACE,
                )
                .await;
                log::info!("worker: manager_task — op done, re-opening stream");
                // Keep consecutive_failures as is. If the op failed
                // because the WS was already dying, the upcoming
                // receive_messages() call may also fail — and we
                // want backoff to kick in then.
            }
            PumpExit::Reopen { reason } => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                log::warn!(
                    "worker: manager_task — stream closed (failure #{}, reason={}), re-opening with backoff",
                    consecutive_failures,
                    reason,
                );
                if consecutive_failures == 1 {
                    let _ = event_tx
                        .send(Event::ReceiveError(format!("receive {} (auto-retrying)", reason)))
                        .await;
                }
            }
            PumpExit::Shutdown => break 'outer,
        }
        // Loop back: re-open the stream and continue.
    }
    log::info!("worker: manager_task exiting (outer break)");
}

/// Process one item from [`presage::Manager::receive_messages`].
///
/// Returns `false` if the event channel is closed (the caller exits
/// the receive task); `true` to keep going.
///
/// Three variants are handled:
///
/// - `Received::Content(content)` — a decrypted-and-authenticated inbound message. `DataMessage`-style text
///   bodies surface as [`Event::Message`]; `ReceiptMessage`s of type `DELIVERY` are peeled off to confirm
///   pending deferred sends (see `pending_unconfirmed_sends` in [`manager_task`]); other body kinds are
///   silently dropped because presage's internal handlers have already absorbed their effects into the store.
/// - `Received::QueueEmpty` — server signals the message queue is drained. Triggers `store.flush_sessions()`
///   to persist the batch of double-ratchet steps accumulated since the previous quiescence. Errors are
///   logged but non-fatal — the next `QueueEmpty` retries.
/// - `Received::Contacts` — contact-sync batch absorbed by the store internally; no user-visible event.
///
/// # Trust boundary
///
/// `content.metadata.sender` is the libsignal-authenticated origin
/// of the message; the double-ratchet MAC and sealed-sender
/// certificate were verified by presage before this item entered
/// the stream. Emission of `Event::Message` therefore carries the
/// authentication witness — see [`Event::Message`]'s `# Trust
/// boundary`.
///
/// # Security
///
/// `body` is decrypted plaintext from a remote peer. It is forwarded
/// as a `String` into `Event::Message`; no body content is logged.
/// `profile_key` bytes ([`u8; 32`]) are extracted unredacted into
/// `pending_profile_fetches` for later use — those bytes are
/// secret-derived material; see [`manager_task`]'s `SECURITY` note
/// on that field.
///
/// # Logging
///
/// Emits the body-kind enum-variant name (`NullMessage`,
/// `DataMessage`, `SynchronizeMessage`, ...) at `log::info!`. Does
/// not emit the body text. Sender ACI is *not* logged here, but the
/// upstream contact resolution and profile-fetch code does.
async fn process_received(
    item: presage::model::messages::Received,
    store: &PddbStore,
    event_tx: &Sender<Event>,
    pending_profile_fetches: &mut Vec<(presage::libsignal_service::prelude::Uuid, [u8; 32])>,
    pending_unconfirmed_sends: &mut std::collections::HashMap<u64, std::time::Instant>,
) -> bool {
    use presage::libsignal_service::content::ContentBody;
    use presage::model::messages::Received;

    log::info!(
        "worker: process_received variant={}",
        match &item {
            Received::Content(_) => "Content",
            Received::QueueEmpty => "QueueEmpty",
            Received::Contacts => "Contacts",
        }
    );
    match item {
        Received::Content(content) => {
            log::info!(
                "worker: process_received Content body_kind={}",
                match &content.body {
                    presage::libsignal_service::content::ContentBody::NullMessage(_) => "NullMessage",
                    presage::libsignal_service::content::ContentBody::DataMessage(_) => "DataMessage",
                    presage::libsignal_service::content::ContentBody::SynchronizeMessage(_) =>
                        "SynchronizeMessage",
                    presage::libsignal_service::content::ContentBody::CallMessage(_) => "CallMessage",
                    presage::libsignal_service::content::ContentBody::ReceiptMessage(_) => "ReceiptMessage",
                    presage::libsignal_service::content::ContentBody::TypingMessage(_) => "TypingMessage",
                    presage::libsignal_service::content::ContentBody::DecryptionErrorMessage(_) =>
                        "DecryptionErrorMessage",
                    presage::libsignal_service::content::ContentBody::StoryMessage(_) => "StoryMessage",
                    presage::libsignal_service::content::ContentBody::PniSignatureMessage(_) =>
                        "PniSignatureMessage",
                    presage::libsignal_service::content::ContentBody::EditMessage(_) => "EditMessage",
                }
            );
            // Peel off DELIVERY receipts here so they can confirm
            // pending deferred sends (see `pending_unconfirmed_sends`
            // in `manager_task`). Other receipt types (READ, VIEWED)
            // are not yet acted on; xas's UI doesn't surface
            // read-state, so they fall through to the catch-all
            // skip below.
            if let ContentBody::ReceiptMessage(rm) = &content.body {
                use presage::libsignal_service::proto::receipt_message::Type as RType;
                let rtype = RType::try_from(rm.r#type.unwrap_or_default()).unwrap_or(RType::Delivery);
                if rtype == RType::Delivery {
                    for ts in &rm.timestamp {
                        if pending_unconfirmed_sends.remove(ts).is_some() {
                            log::info!(
                                "worker/send: ts={} confirmed by DELIVERY receipt; emitting SendComplete",
                                ts,
                            );
                            if event_tx.send(Event::SendComplete { timestamp: *ts }).await.is_err() {
                                return false;
                            }
                        }
                    }
                }
                return true;
            }
            // Only surface text-bearing DataMessages for MVP.
            // Sync/receipt/typing messages have already been
            // absorbed by the store machinery presage runs
            // internally; they don't need UI display.
            // `group_master_key`: group-context detection (misfile
            // guard). A DataMessage with `group_v2` belongs to a GV2
            // group thread, not to `sender`'s 1:1 thread; the same
            // check runs on the sync-sent transcript's inner
            // DataMessage so a group message sent from the linked
            // phone tags identically — and a 1:1 transcript (no
            // `group_v2`) stays untagged. Presence of the context
            // is the group signal even if `master_key` is absent
            // (defensive default to an empty key).
            let group_of = |dm: &presage::libsignal_service::content::DataMessage| {
                dm.group_v2.as_ref().map(|g| g.master_key.clone().unwrap_or_default())
            };
            let (body, group_master_key) = match &content.body {
                ContentBody::DataMessage(dm) => (dm.body.clone().unwrap_or_default(), group_of(dm)),
                ContentBody::SynchronizeMessage(sm) => {
                    match sm.sent.as_ref().and_then(|s| s.message.as_ref()) {
                        Some(dm) => (dm.body.clone().unwrap_or_default(), group_of(dm)),
                        None => (String::new(), None),
                    }
                }
                _ => return true, // EditMessage / Typing / Call — skip
            };
            if body.is_empty() {
                return true; // attachment- or reaction-only
            }
            let sender_sid = content.metadata.sender.clone();
            let sender = sender_sid.service_id_string();
            let timestamp = content.metadata.timestamp;

            // Resolve display info from the contacts store. Empty if the
            // sender isn't yet known (peer hasn't been synced from the
            // linked phone). UI falls back to the UUID.
            use presage::libsignal_service::prelude::phonenumber::Mode;
            use presage::store::ContentsStore;
            let (sender_phone, sender_name) = match store.contact_by_id(&sender_sid).await {
                Ok(Some(c)) => {
                    let phone = c.phone_number.as_ref().map(|pn| pn.format().mode(Mode::E164).to_string());
                    let name = if c.name.is_empty() { None } else { Some(c.name) };
                    (phone, name)
                }
                _ => (None, None),
            };

            // First-touch profile fetch: if the contact is unknown
            // and the DataMessage carried a profile_key, queue a
            // profile lookup for `manager_task` to drain between
            // stream iterations. Mobile clients do this on every
            // unsealed envelope; batching here avoids fighting the
            // `&mut manager` borrow held by the receive stream.
            //
            // SECURITY: `profile_key` is secret-derived material
            // shared by the peer; copied verbatim into the pending
            // queue and consumed by `ProfileKey::create` in the
            // drain loop. Never logged.
            if sender_name.is_none() {
                if let ContentBody::DataMessage(dm) = &content.body {
                    if let Some(key_bytes) = dm.profile_key.as_ref() {
                        if key_bytes.len() == 32 {
                            if let presage::libsignal_service::protocol::ServiceId::Aci(aci) = sender_sid {
                                let aci_uuid: presage::libsignal_service::prelude::Uuid = aci.into();
                                let mut bytes = [0u8; 32];
                                bytes.copy_from_slice(key_bytes);
                                pending_profile_fetches.push((aci_uuid, bytes));
                            }
                        }
                    }
                }
            }

            event_tx
                .send(Event::Message { sender, sender_phone, sender_name, body, timestamp, group_master_key })
                .await
                .is_ok()
        }
        Received::QueueEmpty => {
            // Flush dirty sessions in batched chunks at
            // quiescence. Errors are non-fatal — next QueueEmpty
            // retries.
            if let Err(e) = store.flush_sessions() {
                tracing::warn!("flush_sessions on QueueEmpty failed: {e}");
            }
            true
        }
        Received::Contacts => {
            tracing::debug!("contact-sync batch absorbed by store");
            true
        }
    }
}

/// Scan the deferred-send map for entries whose grace window expired
/// without a delivery receipt; emit [`Event::SendError`] for each
/// and remove from the map.
///
/// Cheap (`HashMap` iteration); called every ~1 s from
/// [`manager_task`]'s `select!` loop. The 1-second timeout in that
/// loop bounds how late expired entries can fire.
///
/// # Trust boundary
///
/// Operates on local in-memory state only. The `pending` map holds
/// only timestamps and `Instant`s — no Signal-Protocol material
/// crosses this function.
async fn sweep_expired_pending_sends(
    pending: &mut std::collections::HashMap<u64, std::time::Instant>,
    event_tx: &Sender<Event>,
) {
    if pending.is_empty() {
        return;
    }
    let now = std::time::Instant::now();
    let expired: Vec<u64> =
        pending.iter().filter_map(|(ts, deadline)| if now >= *deadline { Some(*ts) } else { None }).collect();
    for ts in expired {
        pending.remove(&ts);
        log::info!(
            "worker/send: pending ts={} grace expired with no delivery receipt; emitting SendError",
            ts,
        );
        let _ = event_tx
            .send(Event::SendError {
                reason: "WebSocket closed during send and no delivery receipt arrived within \
                         the grace window — recipient probably did not receive this message"
                    .to_string(),
                timestamp: Some(ts),
            })
            .await;
    }
}

/// Dispatch one [`WorkerOp`] against the task-owned `Manager`.
///
/// Called by [`manager_task`] while the receive stream is dropped
/// (between iterations, or before it has ever been opened), so the
/// `&mut Manager` borrow is free.
async fn run_manager_op(
    manager: &mut Manager<PddbStore, Registered>,
    op: WorkerOp,
    event_tx: &Sender<Event>,
    pending_unconfirmed_sends: &mut std::collections::HashMap<u64, std::time::Instant>,
    pending_grace: std::time::Duration,
) {
    match op {
        // Handled at manager_task's two op-intake sites; nothing to
        // run against the Manager itself.
        WorkerOp::StartReceive => {}
        WorkerOp::Send(send) => {
            handle_send(manager, send, event_tx, pending_unconfirmed_sends, pending_grace).await
        }
        WorkerOp::SyncContacts => handle_sync_contacts(manager, event_tx).await,
        WorkerOp::ResolveUsername(input) => handle_resolve_username(manager, input, event_tx).await,
    }
}

/// `manager.request_contacts()` round-trip; emits
/// [`Event::SyncComplete`] / [`Event::SyncError`].
///
/// The contacts blob arrives as an inbound `SynchronizeMessage` on
/// the receive stream; presage's handler writes each entry into
/// `ContentsStore`. Display names for already-rendered rows are then
/// picked up by the `contact_by_id` resolution in
/// [`process_received`] as further messages arrive.
async fn handle_sync_contacts(manager: &mut Manager<PddbStore, Registered>, event_tx: &Sender<Event>) {
    match manager.request_contacts().await {
        Ok(()) => {
            log::info!("worker/sync: request_contacts OK");
            let _ = event_tx.send(Event::SyncComplete).await;
        }
        Err(e) => {
            log::warn!("worker/sync: request_contacts err: {}", e);
            let _ = event_tx.send(Event::SyncError(format!("{}", e))).await;
        }
    }
}

/// `manager.lookup_username` round-trip; emits
/// [`Event::UsernameResolveResult`].
async fn handle_resolve_username(
    manager: &mut Manager<PddbStore, Registered>,
    input: String,
    event_tx: &Sender<Event>,
) {
    let result = match manager.lookup_username(&input).await {
        Ok(Some(aci)) => {
            let uuid: presage::libsignal_service::prelude::Uuid = aci.into();
            log::info!("worker/username: {:?} → {}", input, uuid);
            Ok(Some(uuid))
        }
        Ok(None) => {
            log::info!("worker/username: {:?} not found", input);
            Ok(None)
        }
        Err(e) => {
            log::warn!("worker/username: {:?} err: {}", input, e);
            Err(format!("{}", e))
        }
    };
    let _ = event_tx.send(Event::UsernameResolveResult(result)).await;
}

/// Parse the recipient, build a text-only `DataMessage` with the
/// caller-supplied timestamp, and call
/// [`presage::Manager::send_message`] under a write-batch scope.
///
/// Always emits exactly one event for the caller's timestamp:
///
/// - [`Event::SendComplete`] on a successful send.
/// - [`Event::SendError`] on a non-retryable failure (panic, bad recipient, batch begin failure, etc.).
/// - Nothing immediately: on a `WebSocket closing`-shaped failure after the retry budget is exhausted, the
///   timestamp is deferred into `pending_unconfirmed_sends` with deadline `now + pending_grace`. Either
///   [`process_received`] surfaces a `SendComplete` when the DELIVERY receipt arrives, or
///   [`sweep_expired_pending_sends`] emits the final `SendError` after the deadline.
///
/// # Recipient parsing
///
/// `recipient` may be:
///
/// - A UUID/ACI in dashed form (36 chars): converted directly to `ServiceId::Aci`.
/// - A phone number in e164 form (`+<digits>`): resolved against the contacts store. Fails with
///   `Event::SendError` if no contact matches (the user must either receive a message from that peer first,
///   run `Cmd::SyncContacts`, or send by UUID).
/// - Anything else: fails with `Event::SendError`.
///
/// # Retry policy
///
/// `WebSocket closing`-shaped errors are retried up to
/// `SEND_MAX_ATTEMPTS` (6) times with exponential backoff
/// (2 s, 4 s, 8 s, 16 s, 32 s — total ~62 s worst case). On rv32
/// the auth WS dies after ~60-90 s when keepalive responses don't
/// make it back from the server, and libsignal-service spawns a
/// fresh WS automatically; the retry lets the next attempt land on
/// the new WS instead of bubbling the transient close up.
///
/// Detection is by substring match on the error display because the
/// error type passes through several wrapping layers
/// (`presage::Error` -> `ServiceError` -> `SignalProtocolError`)
/// before reaching us. The substring "websocket closing" appears in
/// both surfaced shapes.
///
/// # Trust boundary
///
/// `send.body` is plaintext at entry. Encryption (X3DH/PQXDH +
/// double-ratchet seal) happens inside `manager.send_message`. The
/// resulting ciphertext and ratchet steps are persisted to PDDB
/// via the write-batch scope opened around the send.
///
/// # Security
///
/// The `catch_unwind` wrapper around `manager.send_message` uses
/// `AssertUnwindSafe` on `&mut manager` because `Manager` is not
/// `UnwindSafe` by default. A panic mid-send may leave the
/// `Manager`'s session state inconsistent. The alternative — let
/// the panic propagate and kill `manager_task` — would force every
/// subsequent send to surface "manager task died." Both outcomes
/// are bad; this path picks the recoverable one.
///
/// # Logging
///
/// Emits `body_len` only (never `body`). Emits the recipient string
/// verbatim (UUID or e164) and the parsed `Uuid` of the resolved
/// recipient — both are PII-relevant — a known log-discipline
/// audit item.
///
/// # rv32 / 16 MiB constraint
///
/// The "first send" path runs prekey-bundle fetch + PQXDH + initial
/// double-ratchet setup + a large PDDB write of the session record.
/// The write-batch scope around the send packs that into a single
/// `Opcode::WriteKeyBatch` IPC so the trailing basis sync runs once
/// per send rather than once per Store-trait call.
async fn handle_send(
    manager: &mut Manager<PddbStore, Registered>,
    send: InnerSend,
    event_tx: &Sender<Event>,
    pending_unconfirmed_sends: &mut std::collections::HashMap<u64, std::time::Instant>,
    pending_grace: std::time::Duration,
) {
    use futures::FutureExt;
    use presage::libsignal_service::content::ContentBody;
    use presage::libsignal_service::prelude::Uuid;
    use presage::libsignal_service::proto::DataMessage;
    use presage::libsignal_service::protocol::{Aci, ServiceId};
    use presage::store::ContentsStore;

    let timestamp = send.timestamp;
    let _perf_handle_send_start = std::time::Instant::now();
    log::info!("perf/cold-send: START ts={} body_len={}", timestamp, send.body.len());
    log::info!("perf/send: handle_send entry ts={} body_len={}", timestamp, send.body.len());
    log::info!(
        "worker/send: handle_send entered; recipient_raw={:?} body_len={} ts={}",
        send.recipient,
        send.body.len(),
        timestamp,
    );

    // Recipient may be either a UUID/ACI (36 chars, dashed) or a
    // phone number in e164 form (`+<digits>`). UUIDs go straight through;
    // phone numbers are looked up against the contacts store, which is
    // populated by phone-sourced sync messages (and `presage` auto-
    // saves contacts on first received message).
    let recipient = if let Ok(uuid) = Uuid::parse_str(send.recipient.trim()) {
        log::info!("worker/send: recipient parsed as UUID={}", uuid);
        ServiceId::Aci(Aci::from_uuid_bytes(uuid.into_bytes()))
    } else if send.recipient.trim().starts_with('+') {
        log::info!("worker/send: recipient is e164; consulting contacts");
        let target = send.recipient.trim();
        let Ok(contacts_iter) = manager.store().contacts().await else {
            log::warn!("worker/send: contacts() returned Err");
            let _ = event_tx
                .send(Event::SendError {
                    reason: "couldn't read contacts store".to_string(),
                    timestamp: Some(timestamp),
                })
                .await;
            return;
        };
        use presage::libsignal_service::prelude::phonenumber::Mode;
        let mut matched: Option<Uuid> = None;
        for contact_res in contacts_iter {
            let Ok(contact) = contact_res else { continue };
            let Some(pn) = contact.phone_number.as_ref() else { continue };
            let pn_str = pn.format().mode(Mode::E164).to_string();
            if pn_str == target {
                matched = Some(contact.uuid);
                break;
            }
        }
        let Some(uuid) = matched else {
            log::warn!("worker/send: no contact matched e164={}", presage_store_pddb::log_id(target));
            let _ = event_tx
                .send(Event::SendError {
                    reason: format!(
                        "phone {} not in contacts (receive a message from them first, or use their ACI UUID)",
                        target
                    ),
                    timestamp: Some(timestamp),
                })
                .await;
            return;
        };
        log::info!("worker/send: e164 resolved -> uuid={}", uuid);
        ServiceId::Aci(Aci::from_uuid_bytes(uuid.into_bytes()))
    } else {
        log::warn!("worker/send: recipient parse failed: {:?}", send.recipient);
        let _ = event_tx
            .send(Event::SendError {
                reason: format!("recipient must be ACI UUID or +e164 phone number; got {:?}", send.recipient),
                timestamp: Some(timestamp),
            })
            .await;
        return;
    };

    let content_body = ContentBody::DataMessage(DataMessage {
        body: Some(send.body),
        timestamp: Some(timestamp),
        ..Default::default()
    });

    log::info!(
        "worker/send: calling manager.send_message ts={} (heavy path on first-send: prekey bundle fetch + PQXDH + double-ratchet init + PDDB write)",
        timestamp
    );

    // See the function-level docstring for the retry rationale.
    // 6 retries with exponential gaps span ~62 s total, covering
    // roughly 10 server WS-rotation cycles on rv32.
    const SEND_MAX_ATTEMPTS: u32 = 6;

    /// Sleep before attempt N (one-indexed): 2 s, 4 s, 8 s, 16 s, 32 s.
    /// Total worst-case wait between user-press and giving up: 62 s.
    fn backoff_for(next_attempt: u32) -> std::time::Duration {
        let secs = 1_u64 << (next_attempt as u64).min(5);
        std::time::Duration::from_secs(secs)
    }

    // Clone the store handle so a send-time batch can be opened
    // alongside the `&mut manager` borrow that `send_message`
    // requires. The clone is shallow (Arc-based) — it shares the
    // same `BufferingBackend`, so `begin_send_batch` on this clone
    // toggles the same buffer state that the Store-trait impls
    // reach through `manager.store().backend`.
    let store_for_batch = manager.store().clone();

    let mut last_err: Option<String> = None;
    for attempt in 1..=SEND_MAX_ATTEMPTS {
        log::info!("worker/send: attempt {}/{} ts={}", attempt, SEND_MAX_ATTEMPTS, timestamp,);

        // Open a send-time write batch. Each attempt gets its own
        // batch scope; on retry the previous attempt's guard has
        // already dropped (abort = no replay).
        //
        // `begin_send_batch` returns `Ok(None)` for stores built
        // without buffering (e.g. the MockBackend used in some
        // hosted tests); in that case writes pass through as
        // before. Treat begin errors as a hard failure — they only
        // happen if a nested batch is requested, which is a logic
        // bug worth surfacing.
        let batch_guard = match store_for_batch.begin_send_batch() {
            Ok(g) => g,
            Err(e) => {
                log::error!("worker/send: begin_send_batch failed: {}", e);
                let _ = event_tx
                    .send(Event::SendError {
                        reason: format!("internal: begin_send_batch: {e}"),
                        timestamp: Some(timestamp),
                    })
                    .await;
                return;
            }
        };

        // `catch_unwind` so a panic inside libsignal/presage's send
        // path doesn't kill `manager_task`. See the function-level
        // `# Security` block for the rationale on `AssertUnwindSafe`.
        let pipeline_start = std::time::Instant::now();
        log::info!(
            "perf/send: batch_scope_enter ts={} attempt={} buffered={}",
            timestamp,
            attempt,
            batch_guard.as_ref().map(|g| g.buffered_len()).unwrap_or(0)
        );
        let send_fut = std::panic::AssertUnwindSafe(manager.send_message(
            recipient.clone(),
            content_body.clone(),
            timestamp,
        ));
        let outcome = send_fut.catch_unwind().await;
        let pipeline_ms = pipeline_start.elapsed().as_millis() as u64;
        log::info!(
            "perf/send: manager.send_message returned ts={} attempt={} pipeline_ms={} result={:?}",
            timestamp,
            attempt,
            pipeline_ms,
            match &outcome {
                Ok(Ok(())) => "ok",
                Ok(Err(_)) => "err",
                Err(_) => "panic",
            }
        );
        let result_kind = match &outcome {
            Ok(Ok(())) => "ok",
            Ok(Err(_)) => "err",
            Err(_) => "panic",
        };
        log::info!(
            "worker/send: attempt {} returned pipeline_ms={} result={}",
            attempt,
            pipeline_ms,
            result_kind,
        );

        match outcome {
            Ok(Ok(())) => {
                // Order: flush sessions FIRST, then commit the batch.
                // The `BufferingBackend` that sits in front of
                // `PddbBackend` (for `pddb-real` builds) intercepts
                // `put` while a batch is open, so `flush_sessions`
                // here routes its read-modify-write through the same
                // buffer as the other in-flight writes. Commit then
                // replays everything via a single `inner.put_batch`,
                // which the upstream PDDB packs into one
                // `Opcode::WriteKeyBatch` IPC with one trailing
                // basis sync.
                //
                // NOTE: load-bearing. Reversing the order routes
                // `flush_sessions` writes directly through
                // `PddbBackend::put` and chunks them into N
                // `Opcode::WriteKey` IPCs (one per ≤4072-byte
                // `KeyHandle::write` chunk). The ratchet bundle is
                // the largest single write per send, so this order
                // is what makes per-send PDDB cost a single
                // round-trip.
                //
                // The durability barrier still precedes the
                // `SendComplete` emission: the ratchet step paired
                // with the just-sent message is durable before the
                // UI is told the send succeeded.
                let _perf_pre_flush = std::time::Instant::now();
                if let Err(e) = store_for_batch.flush_sessions() {
                    log::warn!("worker/send: flush_sessions inside batch failed: {}", e);
                }
                let _perf_flush_ms = _perf_pre_flush.elapsed().as_millis();

                let _perf_pre_commit = std::time::Instant::now();
                let _perf_buffered_at_commit = batch_guard.as_ref().map(|g| g.buffered_len()).unwrap_or(0);
                if let Some(g) = batch_guard {
                    match g.commit() {
                        Ok(n) => log::info!(
                            "worker/send: batch committed (sessions inside) ts={} (n={})",
                            timestamp,
                            n
                        ),
                        Err(e) => log::warn!("worker/send: batch commit failed ts={}: {}", timestamp, e),
                    }
                }
                let _perf_commit_ms = _perf_pre_commit.elapsed().as_millis();
                log::info!(
                    "perf/send: batch_scope_commit ts={} attempt={} buffered_at_commit={} flush_sessions_ms={} commit_ms={}",
                    timestamp,
                    attempt,
                    _perf_buffered_at_commit,
                    _perf_flush_ms,
                    _perf_commit_ms
                );
                log::info!("worker/send: SendComplete ts={} (attempt {})", timestamp, attempt);
                log::info!(
                    "perf/cold-send: END ts={} attempt={} handle_send_total_ms={}",
                    timestamp,
                    attempt,
                    _perf_handle_send_start.elapsed().as_millis()
                );
                let _ = event_tx.send(Event::SendComplete { timestamp }).await;
                return;
            }
            Ok(Err(e)) => {
                let msg = format!("{e}");
                log::warn!("worker/send: attempt {} Err: {}", attempt, msg);
                let retryable = msg.to_lowercase().contains("websocket closing");
                if retryable && attempt < SEND_MAX_ATTEMPTS {
                    let delay = backoff_for(attempt);
                    log::info!(
                        "worker/send: WsClosing-shaped error; sleeping {:?} then retrying (attempt {}->{} of {})",
                        delay,
                        attempt,
                        attempt + 1,
                        SEND_MAX_ATTEMPTS,
                    );
                    futures_timer::Delay::new(delay).await;
                    last_err = Some(msg);
                    continue;
                }
                // WS-closing-shaped errors after retry exhaustion
                // go into the pending-receipt grace window. The
                // cipher may have landed even though the local future
                // returned `Err`; wait `pending_grace` for a DELIVERY
                // receipt to confirm before emitting `SendError`.
                // Other error shapes (panic, identity mismatch, etc.)
                // bypass the grace and surface immediately.
                if retryable {
                    let deadline = std::time::Instant::now() + pending_grace;
                    pending_unconfirmed_sends.insert(timestamp, deadline);
                    log::info!(
                        "worker/send: ts={} retries exhausted with WsClosing-shaped error; \
                         deferring SendError for {:?} pending delivery receipt",
                        timestamp,
                        pending_grace,
                    );
                    let _ = last_err.replace(msg);
                    return;
                }
                let _ = event_tx.send(Event::SendError { reason: msg, timestamp: Some(timestamp) }).await;
                return;
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic payload".to_string()
                };
                log::error!("worker/send: PANIC inside manager.send_message attempt {}: {}", attempt, msg,);
                let _ = event_tx
                    .send(Event::SendError {
                        reason: format!("panic in send: {msg}"),
                        timestamp: Some(timestamp),
                    })
                    .await;
                return;
            }
        }
    }

    // Loop ran out of attempts without an early return.
    let reason = last_err.unwrap_or_else(|| "send retry loop exhausted".to_string());
    log::warn!("worker/send: all {} attempts failed; last={}", SEND_MAX_ATTEMPTS, reason);
    let _ = event_tx
        .send(Event::SendError {
            reason: format!("retried {} times: {}", SEND_MAX_ATTEMPTS, reason),
            timestamp: Some(timestamp),
        })
        .await;
}

/// Run [`presage::Manager::load_registered`] and stringify the
/// result.
///
/// On a fresh install (or before PDDB unlock) this returns
/// `Err(Error::NotYetRegisteredError)` because the store starts
/// empty — exactly the path the [`Cmd::GetWhoami`] integration test
/// exercises (channel round-trip, error type stringification, no
/// executor deadlock when a future returns `Err`).
///
/// # Trust boundary
///
/// Reads the cached `RegistrationData` if available. No network
/// I/O. The returned string carries ACI/PNI/phone identifiers when
/// `Ok`; see the comment in [`Cmd::GetWhoami`] about the future
/// "real" whoami path.
///
/// # Logging
///
/// Does not log directly; the caller's `Event::Whoami` payload
/// containing the ACI/PNI/phone string is logged by the IPC layer.
async fn handle_whoami(store: PddbStore) -> Result<String, String> {
    match Manager::load_registered(store).await {
        Ok(manager) => {
            // The "real" whoami would issue a `GET /v1/accounts/whoami`
            // over the identified WS. Reaching into the cached
            // registration data here is enough to prove the store
            // round-trips through `Manager`.
            let data = manager.registration_data();
            Ok(format!(
                "phone={} aci={} pni={}",
                data.phone_number, data.service_ids.aci, data.service_ids.pni
            ))
        }
        Err(e) => Err(format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    //! Integration-style tests: spawn the worker and exercise the
    //! channel round-trip end-to-end.
    //!
    //! Uses [`PddbStore::with_mock_backend`] so no Xous services are
    //! required. The tests cover lifecycle (ping/pong, error-on-
    //! empty-store, implicit shutdown via channel drop) and the
    //! pure data-manipulation portion of [`sweep_expired_pending_sends`].
    //! Full receive/send paths require an executor + mocked manager
    //! and are exercised by the workspace-level hosted run.

    use super::*;

    /// Channel capacity. 16 is plenty for these tests; the
    /// production binary sizes this against the IPC fan-in/fan-out.
    const CHAN_CAP: usize = 16;

    fn spawn() -> (Sender<Cmd>, Receiver<Event>, JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = async_channel::bounded(CHAN_CAP);
        let (event_tx, event_rx) = async_channel::bounded(CHAN_CAP);
        let store = PddbStore::with_mock_backend();
        let handle = run_signal_worker(store, cmd_rx, event_tx);
        (cmd_tx, event_rx, handle)
    }

    #[test]
    fn hello_pong_round_trip() {
        let (cmd_tx, event_rx, handle) = spawn();
        cmd_tx.send_blocking(Cmd::Hello).unwrap();
        let evt = event_rx.recv_blocking().unwrap();
        assert!(matches!(evt, Event::Pong));

        cmd_tx.send_blocking(Cmd::Shutdown).unwrap();
        let evt = event_rx.recv_blocking().unwrap();
        assert!(matches!(evt, Event::ShuttingDown));
        handle.join().unwrap();
    }

    #[test]
    fn whoami_returns_error_on_empty_store() {
        let (cmd_tx, event_rx, handle) = spawn();
        cmd_tx.send_blocking(Cmd::GetWhoami).unwrap();
        let evt = event_rx.recv_blocking().unwrap();
        match evt {
            Event::Whoami(Err(_)) => { /* expected: not registered */ }
            other => panic!("unexpected event: {other:?}"),
        }
        cmd_tx.send_blocking(Cmd::Shutdown).unwrap();
        let _ = event_rx.recv_blocking();
        handle.join().unwrap();
    }

    /// Pure data-manipulation half of the deferred-send path:
    /// expired entries become `SendError`; non-expired entries stay
    /// in the map. The full DELIVERY-receipt round-trip needs an
    /// executor + mocked manager and is not exercised here.
    #[test]
    fn sweep_expired_pending_sends_emits_send_error_for_expired_entries_only() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let (event_tx, event_rx) = async_channel::bounded::<Event>(8);
        let mut pending: HashMap<u64, Instant> = HashMap::new();
        let now = Instant::now();
        pending.insert(100, now - Duration::from_secs(1)); // expired
        pending.insert(200, now + Duration::from_secs(60)); // not yet
        pending.insert(300, now - Duration::from_millis(1)); // expired

        futures::executor::block_on(super::sweep_expired_pending_sends(&mut pending, &event_tx));

        // Two SendError events expected, for ts=100 and ts=300, in
        // any order (HashMap iteration is unordered).
        let mut got_ts: Vec<u64> = Vec::new();
        while let Ok(e) = event_rx.try_recv() {
            match e {
                Event::SendError { timestamp: Some(ts), .. } => got_ts.push(ts),
                other => panic!("unexpected event: {other:?}"),
            }
        }
        got_ts.sort();
        assert_eq!(got_ts, vec![100, 300]);
        // ts=200 is still pending.
        assert!(pending.contains_key(&200));
        assert!(!pending.contains_key(&100));
        assert!(!pending.contains_key(&300));
    }

    /// Manager-touching commands sent before any link exists must
    /// fail fast with their respective error events (the mock store
    /// has no registration, so no manager task is running).
    #[test]
    fn manager_ops_before_link_error_cleanly() {
        let (cmd_tx, event_rx, handle) = spawn();

        cmd_tx
            .send_blocking(Cmd::SendMessage {
                recipient: "nobody".to_string(),
                body: "hi".to_string(),
                timestamp: 42,
            })
            .unwrap();
        match event_rx.recv_blocking().unwrap() {
            Event::SendError { reason, timestamp } => {
                assert!(reason.contains("not linked"), "reason: {reason}");
                assert_eq!(timestamp, Some(42));
            }
            other => panic!("unexpected event: {other:?}"),
        }

        cmd_tx.send_blocking(Cmd::StartReceive).unwrap();
        match event_rx.recv_blocking().unwrap() {
            Event::ReceiveError(reason) => {
                assert!(reason.contains("not linked"), "reason: {reason}")
            }
            other => panic!("unexpected event: {other:?}"),
        }

        cmd_tx.send_blocking(Cmd::SyncContacts).unwrap();
        match event_rx.recv_blocking().unwrap() {
            Event::SyncError(reason) => {
                assert!(reason.contains("not linked"), "reason: {reason}")
            }
            other => panic!("unexpected event: {other:?}"),
        }

        cmd_tx.send_blocking(Cmd::ResolveUsername("alice.42".to_string())).unwrap();
        match event_rx.recv_blocking().unwrap() {
            Event::UsernameResolveResult(Err(reason)) => {
                assert!(reason.contains("not linked"), "reason: {reason}")
            }
            other => panic!("unexpected event: {other:?}"),
        }

        cmd_tx.send_blocking(Cmd::Shutdown).unwrap();
        let _ = event_rx.recv_blocking();
        handle.join().unwrap();
    }

    /// A store that still holds account state from a previous link
    /// refuses `Cmd::LinkDevice` with `Event::StaleStoreDetected`
    /// and starts no link — and never wipes (fa1c37b). The empty-
    /// store negative (a genuine first link must not trip the
    /// guard) is covered by presage-store-pddb's
    /// `empty_store_has_no_account_state`; exercising it here would
    /// start a real link attempt against the network.
    #[test]
    fn link_device_refused_on_stale_store() {
        use std::sync::Arc;

        use presage_store_pddb::{KvBackend, MockBackend};

        let backend = Arc::new(MockBackend::new());
        // Leftover kyber record with no registration data — the
        // exact post-fa1c37b hazard shape (presage clears the
        // registration on link entry; protocol dicts survive).
        backend.put("signal.protocol.aci.kyber_prekey", "17", &[0u8; 4]).unwrap();

        let (cmd_tx, cmd_rx) = async_channel::bounded(CHAN_CAP);
        let (event_tx, event_rx) = async_channel::bounded(CHAN_CAP);
        let handle = run_signal_worker(PddbStore::new(backend), cmd_rx, event_tx);

        cmd_tx.send_blocking(Cmd::LinkDevice { device_name: "test".to_string() }).unwrap();
        match event_rx.recv_blocking().unwrap() {
            Event::StaleStoreDetected => {}
            other => panic!("unexpected event: {other:?}"),
        }

        // The refusal leaves the worker alive and the store intact.
        cmd_tx.send_blocking(Cmd::Hello).unwrap();
        assert!(matches!(event_rx.recv_blocking().unwrap(), Event::Pong));

        cmd_tx.send_blocking(Cmd::Shutdown).unwrap();
        let _ = event_rx.recv_blocking();
        handle.join().unwrap();
    }

    /// Dropping the cmd-channel sender (without sending Shutdown) is
    /// the implicit teardown path. The worker exits when its `recv`
    /// returns `Err(RecvError)`.
    #[test]
    fn dropping_cmd_channel_shuts_down_cleanly() {
        let (cmd_tx, event_rx, handle) = spawn();
        cmd_tx.send_blocking(Cmd::Hello).unwrap();
        assert!(matches!(event_rx.recv_blocking().unwrap(), Event::Pong));
        drop(cmd_tx);
        // event_rx will return Err once the worker exits and event_tx
        // drops. Don't assert on the value — just confirm the join.
        let _ = event_rx.recv_blocking();
        handle.join().unwrap();
    }

    // ---- group misfile guard: process_received tagging ----
    //
    // These drive the real `process_received` path with constructed
    // `Received::Content` values (mock store, no Manager needed) and
    // assert the `group_master_key` tag on the emitted
    // `Event::Message` — including the sync-sent transcript cases,
    // where a 1:1 transcript must NOT be group-tagged.

    use presage::libsignal_service::content::{
        Content, ContentBody, DataMessage, GroupContextV2, Metadata, SyncMessage, sync_message,
    };
    use presage::libsignal_service::protocol::{Aci, ServiceId};

    const MASTER_KEY: [u8; 32] = [7u8; 32];

    fn test_metadata() -> Metadata {
        use presage::libsignal_service::prelude::Uuid;
        let sender = ServiceId::Aci(Aci::from(Uuid::from_u128(0x1111_2222_3333_4444_5555_0001)));
        let destination = ServiceId::Aci(Aci::from(Uuid::from_u128(0xaaaa_bbbb_cccc_dddd_eeee_0002)));
        Metadata {
            sender,
            destination,
            sender_device: 1u32.try_into().unwrap(),
            timestamp: 1_700_000_000_000,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            server_guid: None,
        }
    }

    fn data_message(body: &str, group: bool) -> DataMessage {
        DataMessage {
            body: Some(body.to_string()),
            group_v2: group.then(|| GroupContextV2 {
                master_key: Some(MASTER_KEY.to_vec()),
                revision: Some(1),
                group_change: None,
            }),
            ..Default::default()
        }
    }

    /// Run one `Received::Content` through `process_received` and
    /// return the events it emitted.
    fn process_one(body: ContentBody) -> Vec<Event> {
        let store = PddbStore::with_mock_backend();
        let (event_tx, event_rx) = async_channel::bounded::<Event>(8);
        let content = Content::from_body(body, test_metadata());
        let mut fetches = Vec::new();
        let mut pending = std::collections::HashMap::new();
        let keep_going = futures::executor::block_on(super::process_received(
            presage::model::messages::Received::Content(Box::new(content)),
            &store,
            &event_tx,
            &mut fetches,
            &mut pending,
        ));
        assert!(keep_going);
        let mut events = Vec::new();
        while let Ok(e) = event_rx.try_recv() {
            events.push(e);
        }
        events
    }

    #[test]
    fn inbound_group_data_message_is_group_tagged() {
        let events = process_one(ContentBody::DataMessage(data_message("the party is off", true)));
        match events.as_slice() {
            [Event::Message { body, group_master_key, .. }] => {
                assert_eq!(body, "the party is off");
                assert_eq!(group_master_key.as_deref(), Some(&MASTER_KEY[..]));
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }

    #[test]
    fn inbound_one_to_one_data_message_is_not_group_tagged() {
        let events = process_one(ContentBody::DataMessage(data_message("hi", false)));
        match events.as_slice() {
            [Event::Message { group_master_key: None, .. }] => {}
            other => panic!("unexpected events: {other:?}"),
        }
    }

    #[test]
    fn sync_sent_group_transcript_is_group_tagged() {
        // A group message sent from the linked phone arrives as a
        // sync-sent transcript; it must tag with the same master key
        // so it files into the group thread, not a 1:1.
        let sm = SyncMessage {
            sent: Some(sync_message::Sent {
                message: Some(data_message("sent to the room", true)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let events = process_one(ContentBody::SynchronizeMessage(sm));
        match events.as_slice() {
            [Event::Message { group_master_key, .. }] => {
                assert_eq!(group_master_key.as_deref(), Some(&MASTER_KEY[..]));
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }

    #[test]
    fn sync_sent_one_to_one_transcript_is_not_mistagged() {
        // The other direction of the same guard: a 1:1 transcript
        // must NOT come out group-tagged.
        let sm = SyncMessage {
            sent: Some(sync_message::Sent {
                message: Some(data_message("just for you", false)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let events = process_one(ContentBody::SynchronizeMessage(sm));
        match events.as_slice() {
            [Event::Message { group_master_key: None, body, .. }] => {
                assert_eq!(body, "just for you");
            }
            other => panic!("unexpected events: {other:?}"),
        }
    }
}
