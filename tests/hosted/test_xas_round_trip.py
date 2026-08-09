#!/usr/bin/env python3
"""xas round-trip test against signal-cli.

Boots hosted xas, drives the launcher to xas, links via
`signal-cli addDevice`, then runs Round 1 (peer→xas + xas reply ×2)
and Round 2 (xas→peer + peer reply ×2). xas-side sends use a
maintainer-prompt — the script waits for the kernel log to record
`worker/send: handle_send entered`.

Exit codes:
  0 — all phases PASS
  1 — setup / prerequisite failure
  3 — Phase 1 (link) failed
  4 — Round 1 (recv-reply) failed
  5 — Round 2 (send-recv) failed

Env: tests/hosted/test_env supplies TEST_PEER_NUMBER (NL peer) and
TEST_XAS_NUMBER (US primary that signal-cli runs against; xas
links here as a secondary). KEEP_LOGS=1 preserves $LOG_DIR.
"""

from __future__ import annotations

import argparse
import atexit
import ctypes
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- config

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_XOUS_CORE = REPO_ROOT / "xous-core"
DEFAULT_XAS_BIN = REPO_ROOT / "target/release/xas"

BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", 180))
LINK_TIMEOUT = int(os.environ.get("LINK_TIMEOUT", 90))
RECV_TIMEOUT = int(os.environ.get("RECV_TIMEOUT", 60))
SEND_PROMPT_TIMEOUT = int(os.environ.get("XAS_SEND_PROMPT_TIMEOUT", 300))
WIPE_PDDB = os.environ.get("WIPE_PDDB", "1") == "1"
KEEP_LOGS = os.environ.get("KEEP_LOGS", "0") == "1"

# Kernel log patterns we anchor on.
RE_BOOT = re.compile(r"starting main loop")
RE_LINK_DEVICE_RECEIVED = re.compile(r"worker: Cmd::LinkDevice received")
RE_LINK_URL = re.compile(r"sgnl://linkdevice\?[^\s\"]+")
RE_LINK_DONE_WORKER = re.compile(r"worker/link: link_secondary_device returned")
RE_LINK_COMPLETE = re.compile(r"xas/gam_app: LinkComplete")
RE_INBOUND = re.compile(r"xas/gam_app: inbound message from")
RE_HANDLE_SEND = re.compile(r"worker/send: handle_send entered")
RE_SEND_COMPLETE = re.compile(r"worker/send: SendComplete")
RE_PIPELINE_MS = re.compile(r"pipeline_ms=(\d+)")

# Close-code patterns (for the summary census).
RE_CLOSE = re.compile(r"websocket closed code=(\d+)")

# ---------------------------------------------------------------- state

@dataclass
class Config:
    xous_core: Path
    xas_bin: Path
    display: str
    peer_number: str
    xas_number: str
    log_dir: Path
    kernel_log: Path
    signal_cli_log: Path
    summary_path: Path

@dataclass
class StepResult:
    name: str
    status: str
    detail: str

@dataclass
class State:
    cfg: Config
    summary: list[StepResult] = field(default_factory=list)
    kernel_proc: subprocess.Popen | None = None
    win_id: int | None = None

# ---------------------------------------------------------------- helpers

def die(code: int, msg: str) -> "_NoReturn":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(code)

def load_env() -> dict[str, str]:
    env_path = REPO_ROOT / "tests/hosted/test_env"
    if not env_path.exists():
        die(1, f"tests/hosted/test_env not found (copy from test_env.example)")
    out: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out

def require_cmd(cmd: str) -> None:
    if not shutil.which(cmd):
        die(1, f"missing required command: {cmd}")

def run(args: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run with check=False by default; returns CompletedProcess."""
    kw.setdefault("text", True)
    kw.setdefault("capture_output", True)
    return subprocess.run(args, **kw)

def append_log(path: Path, content: str) -> None:
    with path.open("a") as f:
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")

def now_ms() -> int:
    return int(time.time() * 1000)

# ---------------------------------------------------------------- X11

# XSendEvent path — same shape as tests/hosted/drive_link.py. xdotool
# is unreliable under SSH X11 forwarding; ctypes works.

class _XKeyEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong),
        ("root", ctypes.c_ulong),
        ("subwindow", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("x", ctypes.c_int),
        ("y", ctypes.c_int),
        ("x_root", ctypes.c_int),
        ("y_root", ctypes.c_int),
        ("state", ctypes.c_uint),
        ("keycode", ctypes.c_uint),
        ("same_screen", ctypes.c_int),
    ]

_X11 = None
_DPY = None

def _x11() -> tuple[ctypes.CDLL, int]:
    global _X11, _DPY
    if _X11 is None:
        _X11 = ctypes.cdll.LoadLibrary("libX11.so.6")
        _X11.XOpenDisplay.restype = ctypes.c_void_p
        _X11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        _X11.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _X11.XDefaultRootWindow.restype = ctypes.c_ulong
        _X11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        _X11.XKeysymToKeycode.restype = ctypes.c_uint
        _X11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        _X11.XFlush.argtypes = [ctypes.c_void_p]
        _X11.XSendEvent.restype = ctypes.c_int
    if _DPY is None:
        d = _X11.XOpenDisplay(os.environ.get("DISPLAY", ":0").encode())
        if not d:
            die(1, f"cannot open DISPLAY={os.environ.get('DISPLAY')}")
        _DPY = d
    return _X11, _DPY

# KeySym constants.
_KS_HOME = 0xFF50
_KS_DOWN = 0xFF54
_KS_RETURN = 0xFF0D

def send_key(win: int, keysym: int, settle: float = 0.3) -> None:
    """Send a press+release pair for one keysym to one window. Same
    XSendEvent pattern as drive_link.py."""
    x11, dpy = _x11()
    root = x11.XDefaultRootWindow(dpy)
    kc = x11.XKeysymToKeycode(dpy, ctypes.c_ulong(keysym))
    for evtype in (2, 3):  # KeyPress, KeyRelease
        ev = _XKeyEvent()
        ev.type = evtype
        ev.display = dpy
        ev.window = win
        ev.root = root
        ev.keycode = kc
        ev.same_screen = 1
        ev.send_event = 0  # look non-synthetic
        x11.XSendEvent(dpy, win, 1, 1, ctypes.byref(ev))
        x11.XFlush(dpy)
        time.sleep(0.05)
    x11.XSync(dpy, 0)
    time.sleep(settle)

def find_precursor_window(timeout_s: int = 30) -> int | None:
    """xdotool's only reliable role: window search (it works because
    that's a query, not an event-injection). The minifb window can
    appear several seconds after the kernel logs `starting main
    loop` — under load that gap has been observed at >4 s — so we
    poll up to timeout_s for the window to register on the X server."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        cp = run(["xdotool", "search", "--name", "Precursor"])
        if cp.returncode == 0:
            ids = [int(s) for s in cp.stdout.split() if s.strip().isdigit()]
            if ids:
                return ids[0]
        time.sleep(0.5)
    return None

# ---------------------------------------------------------------- log polling

def wait_for_pattern(
    log: Path,
    pattern: re.Pattern,
    budget_s: int,
    poll_s: float = 1.0,
) -> tuple[int, str] | None:
    """Wait up to budget_s for any line in `log` to match `pattern`.
    Returns (wall-clock ms when first matched, matching line) or None."""
    deadline = time.time() + budget_s
    while time.time() < deadline:
        if log.exists() and pattern.search(log.read_text(errors="replace")):
            return now_ms(), pattern.search(log.read_text(errors="replace")).group(0)
        time.sleep(poll_s)
    return None

def count_pattern(log: Path, pattern: re.Pattern, start_line: int = 0) -> int:
    if not log.exists():
        return 0
    lines = log.read_text(errors="replace").splitlines()[start_line:]
    return sum(1 for line in lines if pattern.search(line))

def wait_for_count(
    log: Path,
    pattern: re.Pattern,
    target_count: int,
    start_line: int,
    budget_s: int,
    poll_s: float = 1.0,
) -> int | None:
    """Returns ms when the count first reaches target_count, or None."""
    deadline = time.time() + budget_s
    while time.time() < deadline:
        if count_pattern(log, pattern, start_line) >= target_count:
            return now_ms()
        time.sleep(poll_s)
    return None

def line_count(log: Path) -> int:
    if not log.exists():
        return 0
    return len(log.read_text(errors="replace").splitlines())

def grep_n(log: Path, pattern: re.Pattern, start_line: int = 0) -> list[str]:
    if not log.exists():
        return []
    lines = log.read_text(errors="replace").splitlines()[start_line:]
    return [line for line in lines if pattern.search(line)]

# ---------------------------------------------------------------- signal-cli

def signal_cli(account: str, *args: str, log: Path | None = None) -> subprocess.CompletedProcess:
    """signal-cli subprocess wrapper. Logs to $log if given. Account
    is passed via -a; never echo to stdout to avoid leaking numbers."""
    cp = run(["signal-cli", "-a", account, *args])
    if log is not None:
        append_log(log, f"$ signal-cli -a <REDACTED> {' '.join(args)}\n")
        append_log(log, f"  rc={cp.returncode}\n")
        if cp.stdout:
            append_log(log, cp.stdout)
        if cp.stderr:
            append_log(log, cp.stderr)
    return cp

def remove_all_linked_devices(account: str, log: Path) -> int:
    """Per maintainer: at launch, clear ANY pre-existing linked devices
    on the xas primary so device IDs don't pile up across runs. Returns
    the number of devices removed."""
    cp = signal_cli(account, "listDevices", log=log)
    if cp.returncode != 0:
        # Caller treats this as setup failure.
        return -1
    # Parse "Device N:" / "Device N (this device):" lines. Skip the
    # one tagged "(this device)" — that's signal-cli's own primary
    # slot; removing it would unregister the account.
    removed = 0
    for m in re.finditer(r"^- Device (\d+)(.*)$", cp.stdout, re.M):
        dev_id, tail = int(m.group(1)), m.group(2)
        if "(this device)" in tail:
            continue
        rc = signal_cli(account, "removeDevice", "-d", str(dev_id), log=log)
        if rc.returncode == 0:
            removed += 1
        else:
            print(f"  warning: removeDevice -d {dev_id} returned {rc.returncode}",
                  file=sys.stderr)
    return removed

def clear_peer_session_db(peer_account: str, target_account: str, log: Path) -> None:
    """A fresh xas link gets new identity keys; without clearing the
    peer's cached recipient row + sessions, the peer would still
    encrypt to the old session (often PNI-only because xas wasn't
    fully CDSI-discoverable on the previous link), and xas would
    reject inbound with 'mismatch destination service id'.

    `signal-cli removeContact --forget` is documented to "Delete all
    data associated with this contact, including identity keys and
    sessions" — verified to drop the recipient row + every session
    row tied to its number/ACI/PNI. That forces the next send to
    re-run CDSI and populate a fresh identity."""
    cp = signal_cli(peer_account, "removeContact", "--forget", target_account, log=log)
    if cp.returncode != 0:
        # Non-fatal: an "unknown contact" error here is fine (means
        # nothing to clear). Anything else, just warn — the test
        # still has a chance of passing if no stale state existed.
        print(f"  warning: removeContact --forget returned {cp.returncode}",
              file=sys.stderr)

# ---------------------------------------------------------------- kernel

def start_kernel(cfg: Config, env_overrides: dict[str, str] | None = None) -> subprocess.Popen:
    """Launch `cargo xtask run xas:...` writing combined stdout+stderr
    to cfg.kernel_log. Returns the Popen so the caller can wait/kill."""
    env = os.environ.copy()
    env["XAS_BYPASS_PREFLIGHT"] = "1"
    env["DISPLAY"] = cfg.display
    if env_overrides:
        env.update(env_overrides)
    f = cfg.kernel_log.open("w")
    proc = subprocess.Popen(
        ["cargo", "xtask", "run", f"xas:{cfg.xas_bin}"],
        cwd=str(cfg.xous_core),
        stdout=f,
        stderr=subprocess.STDOUT,
        env=env,
        preexec_fn=os.setsid,
    )
    return proc

def kill_kernel(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    # Belt + suspenders: pkill anything the cargo invocation forked.
    for pat in ("xous-core/target/release/xous-kernel",
                "target/debug/xtask run"):
        subprocess.run(["pkill", "-f", pat], capture_output=True)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass

# ---------------------------------------------------------------- nav driver

# Driver scripts shell out as subprocesses — each invocation opens a
# fresh X11 connection. Long-running scripts reusing one connection
# wedge after the first burst of keystrokes (observed today). The
# drive_link.py / drive_compose.py pair handles all keystroke I/O.

_SCRIPT_DIR = Path(__file__).resolve().parent
_DRIVE_LINK = _SCRIPT_DIR / "drive_link.py"
_DRIVE_COMPOSE = _SCRIPT_DIR / "drive_compose.py"


def drive_launcher_to_link(win: int) -> None:
    """Shell out to drive_link.py — its keystroke sequence lands xas
    at the QR modal."""
    subprocess.run([sys.executable, str(_DRIVE_LINK), str(win)], check=True)


def drive_press_enter(win: int) -> None:
    """Single Enter — dismiss QR modal, or open Thread for the focused
    contact row."""
    subprocess.run([sys.executable, str(_DRIVE_COMPOSE), str(win)], check=True)


def drive_compose_send(win: int, body: str) -> None:
    """Open Thread (if not already there), type body, Enter to send."""
    subprocess.run([sys.executable, str(_DRIVE_COMPOSE), str(win), body], check=True)

# ---------------------------------------------------------------- phases

def _dbg(msg: str) -> None:
    print(f"  [dbg] {msg}", flush=True)


def phase1_link(state: State) -> int:
    """Returns 0 on PASS, exit-code on FAIL."""
    cfg = state.cfg
    print("\n==> Phase 1: boot + auto-link", flush=True)

    # Fresh PDDB.
    pddb = cfg.xous_core / "tools/pddb-images/hosted.bin"
    backup = cfg.xous_core / "tools/pddb-images/hosted_backup.bin"
    if WIPE_PDDB:
        if backup.exists():
            shutil.copy2(backup, pddb)
        elif pddb.exists():
            pddb.unlink()
    _dbg(f"PDDB prepared (wipe={WIPE_PDDB})")

    state.kernel_proc = start_kernel(cfg)
    _dbg(f"kernel PID={state.kernel_proc.pid}")

    # Wait for boot.
    boot_match = wait_for_pattern(cfg.kernel_log, RE_BOOT, BOOT_TIMEOUT)
    if not boot_match:
        _dbg("boot pattern not matched")
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", f"no boot in {BOOT_TIMEOUT}s"))
        return 3
    _dbg(f"boot detected at {boot_match[0]}ms")
    time.sleep(4)  # let shellchat register launcher manifest + gam settle

    win = find_precursor_window()
    _dbg(f"find_precursor_window → {win}")
    if win is None:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", "no X11 window"))
        return 3
    state.win_id = win

    # Drive launcher to link.
    _dbg(f"driving keystrokes to win={win}")
    drive_launcher_to_link(win)
    _dbg("nav done")

    # The drive_link script stops after pressing Enter to select
    # "Link" on the xas Menu — that opens the device-name TextEntry
    # modal. We retry-Enter until the worker logs the
    # `Cmd::LinkDevice received` marker, which only fires once the
    # modal's default text was accepted and gam_app forwarded it.
    # Anchoring on the marker avoids the race where Enter arrives
    # while modals is still rendering and falls on a stale Menu
    # screen (re-selects Link → stacks a second modal).
    _dbg("retry-Enter loop until Cmd::LinkDevice received")
    accept_deadline = time.time() + LINK_TIMEOUT
    last_retry = 0.0
    accepted = False
    while time.time() < accept_deadline:
        if cfg.kernel_log.exists() and RE_LINK_DEVICE_RECEIVED.search(
            cfg.kernel_log.read_text(errors="replace")
        ):
            accepted = True
            break
        if time.time() - last_retry > 3:
            drive_press_enter(win)
            last_retry = time.time()
        time.sleep(0.5)
    if not accepted:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL",
                                        "device-name modal never accepted"))
        return 3
    _dbg("device-name modal accepted; polling for URL emission")

    # Wait for link URL emission.
    url_match = wait_for_pattern(cfg.kernel_log, RE_LINK_URL, LINK_TIMEOUT)
    if not url_match:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", "no URL"))
        return 3
    qr_emit_ms = url_match[0]
    link_url = url_match[1].replace("&amp;", "&")

    # Approve via signal-cli addDevice on the US primary.
    cp = signal_cli(cfg.xas_number, "addDevice", "--uri", link_url, log=cfg.signal_cli_log)
    if cp.returncode != 0:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", "addDevice rejected"))
        return 3

    # Wait for worker-side success first. Then dismiss the QR modal
    # so gam_app drains Event::LinkComplete.
    worker_done = wait_for_pattern(cfg.kernel_log, RE_LINK_DONE_WORKER, LINK_TIMEOUT)
    if not worker_done:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", "no link_secondary_device returned"))
        return 3
    # Dismiss the QR modal so gam_app drains Event::LinkComplete.
    drive_press_enter(win)

    # Wait for gam_app's LinkComplete.
    done = wait_for_pattern(cfg.kernel_log, RE_LINK_COMPLETE, LINK_TIMEOUT)
    if not done:
        state.summary.append(StepResult("Phase 1 (link)", "FAIL", "no LinkComplete"))
        return 3
    link_done_ms = done[0]

    # gam_app.rs:1069 — Screen::Linked dismisses on Enter and only then
    # transitions to Screen::Home. The receive worker is already
    # running (Cmd::StartReceive fires inside the LinkComplete handler
    # regardless of UI state), but Home is what xas displays when an
    # Event::Message lands. Dismiss the info screen so subsequent
    # rounds run from a clean UI state.
    drive_press_enter(win)
    time.sleep(0.8)

    elapsed = link_done_ms - qr_emit_ms
    print(f"  PASS Phase 1: QR-to-LinkComplete = {elapsed}ms (auto)")
    state.summary.append(StepResult("Phase 1 (link)", "PASS", f"qr→link={elapsed}ms"))
    return 0

def drive_xas_send_and_wait(
    win: int,
    body: str,
    start_line: int,
    kernel_log: Path,
    open_thread_first: bool,
) -> int | None:
    """Autonomous compose driver. drive_compose.py without a body
    arg presses Enter once; with a body it opens Thread + types +
    sends. Returns wall-clock ms when worker logs handle_send."""
    handle_before = count_pattern(kernel_log, RE_HANDLE_SEND, start_line)
    if open_thread_first:
        drive_press_enter(win)
        time.sleep(0.5)
    drive_compose_send(win, body)
    deadline = time.time() + SEND_PROMPT_TIMEOUT
    while time.time() < deadline:
        if count_pattern(kernel_log, RE_HANDLE_SEND, start_line) > handle_before:
            return now_ms()
        time.sleep(1)
    return None

def round1_recv_then_reply(state: State, start_line: int) -> int:
    cfg = state.cfg
    print("\n==> Round 1: peer→xas, xas reply ×2")
    for i in (1, 2):
        # peer → xas
        inbound_before = count_pattern(cfg.kernel_log, RE_INBOUND, start_line)
        marker = f"round1-msg{i}-{time.time_ns()}"
        t_send = now_ms()
        cp = signal_cli(cfg.peer_number, "send", "-m", marker, cfg.xas_number,
                        log=cfg.signal_cli_log)
        if cp.returncode != 0:
            state.summary.append(StepResult(f"Round 1 msg {i} recv", "FAIL", "peer send"))
            return 4
        t_recv = wait_for_count(cfg.kernel_log, RE_INBOUND,
                                inbound_before + 1, start_line, RECV_TIMEOUT)
        if t_recv is None:
            state.summary.append(StepResult(f"Round 1 msg {i} recv", "FAIL", "xas recv timeout"))
            return 4
        recv_lat = t_recv - t_send
        print(f"  msg{i} recv:  peer→xas {recv_lat}ms")
        state.summary.append(StepResult(f"Round 1 msg {i} recv", "PASS", f"{recv_lat}ms"))

        # xas reply — autonomous compose via XSendEvent.
        send_before = count_pattern(cfg.kernel_log, RE_SEND_COMPLETE, start_line)
        body = f"r1r{i}-{int(time.time())}"
        # Open Thread only on the first reply; subsequent replies
        # stay on the Thread view from the prior compose.
        open_first = (i == 1)
        t_handle = drive_xas_send_and_wait(state.win_id, body, start_line,
                                           cfg.kernel_log, open_first)
        if t_handle is None:
            state.summary.append(StepResult(f"Round 1 msg {i} reply", "FAIL", "no handle_send"))
            return 4
        t_sc = wait_for_count(cfg.kernel_log, RE_SEND_COMPLETE,
                              send_before + 1, start_line, RECV_TIMEOUT)
        if t_sc is None:
            state.summary.append(StepResult(f"Round 1 msg {i} reply", "FAIL", "no SendComplete"))
            return 4
        pipeline_lines = grep_n(cfg.kernel_log, RE_PIPELINE_MS, start_line)
        pipeline_ms = "?"
        if len(pipeline_lines) > send_before:
            m = RE_PIPELINE_MS.search(pipeline_lines[send_before])
            if m:
                pipeline_ms = m.group(1)
        send_lat = t_sc - t_handle
        print(f"  msg{i} reply: xas→peer {send_lat}ms pipeline_ms={pipeline_ms}")
        state.summary.append(StepResult(f"Round 1 msg {i} reply", "PASS",
                                        f"xas→peer={send_lat}ms pipeline_ms={pipeline_ms}"))
    return 0

def round2_send_then_recv(state: State, start_line: int) -> int:
    cfg = state.cfg
    print("\n==> Round 2: xas→peer, peer reply ×2")
    for i in (1, 2):
        # xas send — already on Thread from Round 1; just type.
        send_before = count_pattern(cfg.kernel_log, RE_SEND_COMPLETE, start_line)
        body = f"r2s{i}-{int(time.time())}"
        t_handle = drive_xas_send_and_wait(state.win_id, body, start_line,
                                           cfg.kernel_log, open_thread_first=False)
        if t_handle is None:
            state.summary.append(StepResult(f"Round 2 msg {i} send", "FAIL", "no handle_send"))
            return 5
        t_sc = wait_for_count(cfg.kernel_log, RE_SEND_COMPLETE,
                              send_before + 1, start_line, RECV_TIMEOUT)
        if t_sc is None:
            state.summary.append(StepResult(f"Round 2 msg {i} send", "FAIL", "no SendComplete"))
            return 5
        pipeline_lines = grep_n(cfg.kernel_log, RE_PIPELINE_MS, start_line)
        pipeline_ms = "?"
        if len(pipeline_lines) > send_before:
            m = RE_PIPELINE_MS.search(pipeline_lines[send_before])
            if m:
                pipeline_ms = m.group(1)
        send_lat = t_sc - t_handle
        print(f"  msg{i} send:  xas→peer {send_lat}ms pipeline_ms={pipeline_ms}")
        state.summary.append(StepResult(f"Round 2 msg {i} send", "PASS",
                                        f"xas→peer={send_lat}ms pipeline_ms={pipeline_ms}"))

        # peer reply → xas
        inbound_before = count_pattern(cfg.kernel_log, RE_INBOUND, start_line)
        marker = f"round2-reply{i}-{time.time_ns()}"
        t_send = now_ms()
        cp = signal_cli(cfg.peer_number, "send", "-m", marker, cfg.xas_number,
                        log=cfg.signal_cli_log)
        if cp.returncode != 0:
            state.summary.append(StepResult(f"Round 2 msg {i} reply", "FAIL", "peer send"))
            return 5
        t_recv = wait_for_count(cfg.kernel_log, RE_INBOUND,
                                inbound_before + 1, start_line, RECV_TIMEOUT)
        if t_recv is None:
            state.summary.append(StepResult(f"Round 2 msg {i} reply", "FAIL", "xas recv timeout"))
            return 5
        recv_lat = t_recv - t_send
        print(f"  msg{i} reply: peer→xas {recv_lat}ms")
        state.summary.append(StepResult(f"Round 2 msg {i} reply", "PASS", f"{recv_lat}ms"))
    return 0

def render_summary(state: State) -> None:
    cfg = state.cfg
    # Close-code census across the whole run.
    closes: dict[str, int] = {}
    for m in RE_CLOSE.finditer(cfg.kernel_log.read_text(errors="replace")
                               if cfg.kernel_log.exists() else ""):
        closes[m.group(1)] = closes.get(m.group(1), 0) + 1

    name_w = max((len(r.name) for r in state.summary), default=0)
    status_w = max((len(r.status) for r in state.summary), default=0)
    print()
    print("==> SUMMARY")
    for r in state.summary:
        print(f"  {r.name:<{name_w}}  {r.status:<{status_w}}  {r.detail}")
    print()
    print(f"  Close codes: " +
          (" ".join(f"{k}={v}" for k, v in sorted(closes.items())) or "(none)"))

    cfg.summary_path.write_text(
        "\n".join(f"{r.name}\t{r.status}\t{r.detail}" for r in state.summary) + "\n"
    )

# ---------------------------------------------------------------- main

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--xous-core",
                   default=os.environ.get("XOUS_CORE_DIR", str(DEFAULT_XOUS_CORE)))
    p.add_argument("--xas-bin",
                   default=os.environ.get("XAS_BIN_PATH", str(DEFAULT_XAS_BIN)))
    p.add_argument("--display",
                   default=os.environ.get("DISPLAY", "localhost:10.0"))
    return p.parse_args()

def setup(args) -> State:
    env = load_env()
    peer = env.get("TEST_PEER_NUMBER", "").strip()
    xas = env.get("TEST_XAS_NUMBER", "").strip()
    if not peer or not xas:
        die(1, "TEST_PEER_NUMBER / TEST_XAS_NUMBER missing from test_env")

    for cmd in ("signal-cli", "cargo", "xdotool", "python3"):
        require_cmd(cmd)

    xas_bin = Path(args.xas_bin)
    if not (xas_bin.exists() and os.access(xas_bin, os.X_OK)):
        die(1, f"xas binary not at {xas_bin}")

    log_dir = Path(tempfile.mkdtemp(prefix="xas-round-trip."))
    cfg = Config(
        xous_core=Path(args.xous_core),
        xas_bin=xas_bin,
        display=args.display,
        peer_number=peer,
        xas_number=xas,
        log_dir=log_dir,
        kernel_log=log_dir / "xous-kernel.log",
        signal_cli_log=log_dir / "signal-cli.log",
        summary_path=log_dir / "summary.txt",
    )
    return State(cfg=cfg)

def cleanup_factory(state: State):
    def _cleanup():
        # Server-side device cleanup first (while the network state is
        # still whatever it was at the end of the test). Each test
        # iteration links a fresh xas secondary; without an explicit
        # post-run removeDevice the secondary stays on the Signal
        # server until the *next* run's pre-launch sweep — which is
        # fine when runs are back-to-back, but accumulates if a run
        # crashes hard and there's a long gap before the next launch.
        # Calling it here makes "no stale devices on Signal" the
        # invariant at exit, not just at entry.
        #
        # Wrapped in try/except so an atexit-time signal-cli failure
        # (network down, daemon unreachable) doesn't mask the rest of
        # cleanup. Worst case: a stale device persists until the next
        # run's pre-launch sweep — same outcome as before this change.
        try:
            removed = remove_all_linked_devices(
                state.cfg.xas_number, state.cfg.signal_cli_log
            )
            if removed > 0:
                print(f"\nAtexit: removed {removed} linked device(s) "
                      f"from xas primary", file=sys.stderr)
        except Exception as e:
            print(f"\nAtexit: removeDevice sweep failed (non-fatal): {e}",
                  file=sys.stderr)

        kill_kernel(state.kernel_proc)
        # Aggressive: anything cargo xtask spawned.
        for pat in ("test_xas_round_trip", "xous-core/target/release/xous-kernel",
                    "target/debug/xtask run"):
            subprocess.run(["pkill", "-KILL", "-f", pat], capture_output=True)
        if KEEP_LOGS:
            print(f"\nLogs preserved: {state.cfg.log_dir}", file=sys.stderr)
        else:
            shutil.rmtree(state.cfg.log_dir, ignore_errors=True)
    return _cleanup

def kill_stale_xas_processes() -> None:
    """Pre-test cleanup: orphan xous-kernels from prior failed runs
    hold UDP ports (DNS bind conflicts), IPC sockets, and X11 windows.
    Also closes leftover Precursor windows — minifb sometimes orphans
    them when the kernel is hard-killed, and xdotool will then return
    a dead window-ID, sending the test's keystrokes into the void."""
    for pat in (
        "xous-core/target/release/xous-kernel",
        "target/debug/xtask run",
        "target/release/xas$",
    ):
        subprocess.run(["pkill", "-KILL", "-f", pat], capture_output=True)
    time.sleep(2)
    cp = subprocess.run(["xdotool", "search", "--name", "Precursor"],
                        capture_output=True, text=True)
    for w in cp.stdout.split():
        if w.strip().isdigit():
            subprocess.run(["xdotool", "windowkill", w], capture_output=True)
    time.sleep(0.5)


def main() -> int:
    args = parse_args()
    state = setup(args)
    cfg = state.cfg
    # Push DISPLAY into the process env so xdotool subprocess and the
    # X11 ctypes path resolve the right server (our ambient bash may
    # not have DISPLAY set when invoked from claude / a script).
    os.environ["DISPLAY"] = cfg.display
    kill_stale_xas_processes()
    atexit.register(cleanup_factory(state))

    print("==> tests/hosted/test_xas_round_trip.py")
    print(f"    XOUS_CORE_DIR={cfg.xous_core}")
    print(f"    XAS_BIN_PATH={cfg.xas_bin}")
    print(f"    DISPLAY={cfg.display}")
    print(f"    LOG_DIR={cfg.log_dir}")

    # Maintainer ask: at launch, remove any leftover linked devices
    # on the xas primary so device IDs don't pile up across runs.
    print("\n==> removing leftover linked devices on xas primary")
    removed = remove_all_linked_devices(cfg.xas_number, cfg.signal_cli_log)
    if removed < 0:
        die(1, "could not list devices on xas primary")
    print(f"    removed {removed} stale device(s)")

    # Drain pending receive on both accounts so leftover traffic
    # doesn't false-match a fresh marker.
    signal_cli(cfg.xas_number, "receive", "--timeout", "2", log=cfg.signal_cli_log)
    signal_cli(cfg.peer_number, "receive", "--timeout", "2", log=cfg.signal_cli_log)

    rc = phase1_link(state)
    if rc != 0:
        render_summary(state)
        return rc

    # Fresh xas keys → clear the peer's session db so the next send
    # encrypts with a fresh PreKey bundle (matches the new xas state).
    print("  clearing peer session for xas account")
    clear_peer_session_db(cfg.peer_number, cfg.xas_number, cfg.signal_cli_log)

    round1_start = line_count(cfg.kernel_log)
    rc = round1_recv_then_reply(state, round1_start)
    if rc != 0:
        render_summary(state)
        return rc

    round2_start = line_count(cfg.kernel_log)
    rc = round2_send_then_recv(state, round2_start)
    if rc != 0:
        render_summary(state)
        return rc

    render_summary(state)
    print("\nPASS: all phases completed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
