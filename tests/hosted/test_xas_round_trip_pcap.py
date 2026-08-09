#!/usr/bin/env python3
"""Pcap variant of tests/hosted/test_xas_round_trip.py. Starts a
tcpdump filtered to chat/storage/cdsi `.signal.org` IPs on :443
before invoking the inner round-trip script, then archives the
pcap and reports a TCP-level census at exit.

Same exit codes as test_xas_round_trip.py, plus 64 for tcpdump
setup failures.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
INNER = HERE / "test_xas_round_trip.py"


def resolve_signal_ips() -> list[str]:
    out: set[str] = set()
    for host in ("chat.signal.org", "storage.signal.org", "cdsi.signal.org"):
        try:
            for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
                out.add(info[4][0])
        except socket.gaierror:
            continue
    return sorted(out)


def detect_outbound_iface() -> str | None:
    """`ip route get 1.1.1.1` returns a line whose `dev` token is the
    outbound interface. tcpdump needs this — anycast traffic to
    chat.signal.org goes out via the host's default route."""
    cp = subprocess.run(["ip", "route", "get", "1.1.1.1"],
                        capture_output=True, text=True)
    if cp.returncode != 0:
        return None
    toks = cp.stdout.split()
    if "dev" in toks:
        return toks[toks.index("dev") + 1]
    return None


def main() -> int:
    if not INNER.exists():
        print(f"ERROR: inner script missing at {INNER}", file=sys.stderr)
        return 64
    if not shutil.which("tcpdump"):
        print("ERROR: tcpdump not installed", file=sys.stderr)
        return 64

    wrapper_dir = Path(tempfile.mkdtemp(prefix="xas-round-trip-pcap."))
    pcap = wrapper_dir / "capture.pcap"
    tcpdump_log = wrapper_dir / "tcpdump.log"

    print(f"==> tests/hosted/test_xas_round_trip_pcap.py")
    print(f"    WRAPPER_DIR={wrapper_dir}")
    print(f"    pcap={pcap}")

    ips = resolve_signal_ips()
    if not ips:
        print("ERROR: could not resolve any Signal IPs", file=sys.stderr)
        return 64
    bpf = " or ".join(f"host {ip}" for ip in ips) + " and port 443"

    iface = os.environ.get("IFACE") or detect_outbound_iface()
    if not iface:
        print("ERROR: outbound interface unknown (set IFACE=ethN)", file=sys.stderr)
        return 64
    print(f"    iface={iface}")

    # Drop privileges to $USER after capture starts; that lets us
    # SIGINT later without sudo. Same pattern as the morning's
    # tcpdump runs.
    user = os.environ.get("USER", "")
    tcpdump_args = [
        "sudo", "-n", "tcpdump", "-Z", user, "-i", iface, "-U",
        "-w", str(pcap), bpf,
    ]
    log_f = tcpdump_log.open("w")
    tcpdump_proc = subprocess.Popen(
        tcpdump_args,
        stdout=log_f, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    time.sleep(2)

    tcpdump_alive = subprocess.run(["pgrep", "-x", "tcpdump"],
                                   capture_output=True).returncode == 0
    if not tcpdump_alive:
        print(f"ERROR: tcpdump did not start; see {tcpdump_log}", file=sys.stderr)
        print(tcpdump_log.read_text()[:500], file=sys.stderr)
        return 64
    print(f"    tcpdump up: PID {tcpdump_proc.pid}")

    # Force the inner script to keep its logs (we archive both pcap +
    # inner logs together for forensics).
    env = os.environ.copy()
    env["KEEP_LOGS"] = "1"

    inner_rc = subprocess.run([sys.executable, str(INNER)], env=env).returncode

    # Stop tcpdump. -Z drop means kill-as-$USER is fine.
    subprocess.run(["pkill", "-INT", "-x", "tcpdump"], capture_output=True)
    time.sleep(1)

    print()
    print(f"==> pcap archive")
    pcap_size = pcap.stat().st_size if pcap.exists() else 0
    print(f"    {pcap} ({pcap_size} bytes)")
    print(f"    inner exit={inner_rc}")
    print()
    print("==> close-code census on captured pcap (TCP-level, indicative)")
    try:
        total = int(subprocess.check_output(
            f"tcpdump -r {pcap} -nn 2>/dev/null | wc -l", shell=True).decode().strip())
        syns = int(subprocess.check_output(
            f"tcpdump -r {pcap} -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' 2>/dev/null | wc -l",
            shell=True).decode().strip())
        fins = int(subprocess.check_output(
            f"tcpdump -r {pcap} -nn 'tcp[tcpflags] & tcp-fin != 0' 2>/dev/null | wc -l",
            shell=True).decode().strip())
        rsts = int(subprocess.check_output(
            f"tcpdump -r {pcap} -nn 'tcp[tcpflags] & tcp-rst != 0' 2>/dev/null | wc -l",
            shell=True).decode().strip())
        print(f"    packets={total} SYN={syns} FIN={fins} RST={rsts}")
    except subprocess.CalledProcessError as e:
        print(f"    (census failed: {e})")

    return inner_rc


if __name__ == "__main__":
    sys.exit(main())
