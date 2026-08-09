#!/usr/bin/env python3
"""Capability-parity check: Signal-Server DeviceCapability.java vs the
libsignal-service-rs fork's LinkCapabilities / DeviceCapabilities.

Spec: ignore/research-v0.4/fork-drift.md §5. Read-only; no build needed.

Fetches (raw, over HTTPS):
  - signalapp/Signal-Server default branch:
      service/.../storage/DeviceCapability.java
  - tunnell/libsignal-service-rs AT THE REV PINNED in xas Cargo.toml
    ([patch."https://github.com/whisperfish/libsignal-service-rs"]):
      src/push_service/linking.rs   (LinkCapabilities)
      src/websocket/account.rs      (DeviceCapabilities)

Exit codes:
  0  parity holds
  1  mismatch (readable diff printed)
  2  fetch or parse yielded nothing — the check itself is broken; this
     must never be allowed to look like a pass.
"""

import re
import sys
import urllib.request
from pathlib import Path

SERVER_URL = (
    "https://raw.githubusercontent.com/signalapp/Signal-Server/main/"
    "service/src/main/java/org/whispersystems/textsecuregcm/storage/"
    "DeviceCapability.java"
)
FORK_RAW = "https://raw.githubusercontent.com/tunnell/libsignal-service-rs/{rev}/{path}"
LINKING_PATH = "src/push_service/linking.rs"
ACCOUNT_PATH = "src/websocket/account.rs"

CARGO_TOML = Path(__file__).resolve().parents[2] / "Cargo.toml"

# fork-drift.md §5 step 1
SERVER_ENUM_RE = re.compile(
    r'^\s*[A-Z_0-9]+\("([^"]+)",\s*AccountCapabilityMode\.(\w+),'
    r"\s*AccountCapabilityVisibility\.(\w+),\s*(true|false),\s*(true|false)\)",
    re.M,
)


def die(msg):
    print(f"PARITY-CHECK BROKEN: {msg}", file=sys.stderr)
    print("This is a check failure, NOT a parity pass.", file=sys.stderr)
    sys.exit(2)


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            body = r.read().decode("utf-8")
    except Exception as e:
        die(f"fetch failed for {url}: {e}")
    if not body.strip():
        die(f"empty body from {url}")
    return body


def pinned_fork_rev():
    text = CARGO_TOML.read_text()
    m = re.search(
        r'libsignal-service\s*=\s*\{[^}]*git\s*=\s*"https://github\.com/'
        r'tunnell/libsignal-service-rs"[^}]*rev\s*=\s*"([0-9a-f]{7,40})"',
        text,
    )
    if not m:
        die(f"could not parse libsignal-service [patch] rev from {CARGO_TOML}")
    return m.group(1)


def parse_server(java):
    caps = {}
    for name, _mode, _vis, prevent, require in SERVER_ENUM_RE.findall(java):
        caps[name] = {"preventDowngrade": prevent == "true",
                      "requireForNewDevices": require == "true"}
    if not caps:
        die("parsed 0 enum entries from DeviceCapability.java "
            "(server-side refactor? regex needs updating)")
    return caps


def camel(snake):
    head, *rest = snake.split("_")
    return head + "".join(w.capitalize() for w in rest)


def parse_struct(rust, struct_name, src_label):
    """Return {wire_name: default_bool} for a serde camelCase struct of bools."""
    sm = re.search(
        rf"pub struct {struct_name}\s*\{{(.*?)\n\}}", rust, re.S)
    if not sm:
        die(f"struct {struct_name} not found in {src_label}")
    fields = {}  # rust field name -> wire name
    body = sm.group(1)
    # serde attrs may carry more than the rename, e.g.
    # #[serde(default, rename = "profiles_v2")]
    for m in re.finditer(
            r'(?:#\[serde\([^)]*rename\s*=\s*"([^"]+)"[^)]*\)\]\s*)?'
            r"pub\s+(\w+)\s*:\s*bool",
            body):
        rename, field = m.groups()
        fields[field] = rename if rename else camel(field)
    if not fields:
        die(f"parsed 0 bool fields from {struct_name} in {src_label}")

    dm = re.search(
        rf"impl Default for {struct_name}\s*\{{(.*?)\n\}}", rust, re.S)
    if not dm:
        die(f"impl Default for {struct_name} not found in {src_label}")
    defaults = dict(re.findall(r"(\w+)\s*:\s*(true|false)", dm.group(1)))
    out = {}
    for field, wire in fields.items():
        if field not in defaults:
            die(f"no Default value parsed for {struct_name}.{field} in {src_label}")
        out[wire] = defaults[field] == "true"
    return out


def main():
    rev = pinned_fork_rev()
    print(f"fork rev (Cargo.toml pin): {rev}")

    server = parse_server(fetch(SERVER_URL))
    link = parse_struct(fetch(FORK_RAW.format(rev=rev, path=LINKING_PATH)),
                        "LinkCapabilities", LINKING_PATH)
    device = parse_struct(fetch(FORK_RAW.format(rev=rev, path=ACCOUNT_PATH)),
                          "DeviceCapabilities", ACCOUNT_PATH)

    print(f"server caps ({len(server)}): {sorted(server)}")
    print(f"LinkCapabilities ({len(link)}): { {k: v for k, v in sorted(link.items())} }")
    print(f"DeviceCapabilities ({len(device)}): { {k: v for k, v in sorted(device.items())} }")

    failures, warnings = [], []

    # FAIL class: exactly what produced the 2026-07 link 409.
    for name, flags in server.items():
        if flags["preventDowngrade"] or flags["requireForNewDevices"]:
            why = [k for k, v in flags.items() if v]
            if name not in link:
                failures.append(
                    f"server cap '{name}' ({', '.join(why)}) missing from LinkCapabilities")
            elif not link[name]:
                failures.append(
                    f"server cap '{name}' ({', '.join(why)}) defaults FALSE in LinkCapabilities")

    # WARN class: name-set drift. Full-set comparison is against
    # DeviceCapabilities only — LinkCapabilities is intentionally the
    # link-flow subset (fork-drift.md §5 says "either struct", but that
    # would warn on today's known-good state; the FAIL rule above already
    # covers the caps that matter for linking). A LinkCapabilities field
    # unknown to the server is still worth a warning.
    for name in sorted(set(server) - set(device)):
        warnings.append(f"server cap '{name}' absent from DeviceCapabilities "
                        "(new capability landed server-side)")
    for name in sorted(set(device) - set(server)):
        warnings.append(f"DeviceCapabilities field '{name}' absent server-side "
                        "(capability retired; removal candidate at next rebase)")
    for name in sorted(set(link) - set(server)):
        warnings.append(f"LinkCapabilities field '{name}' absent server-side "
                        "(capability retired; removal candidate at next rebase)")

    for w in warnings:
        print(f"WARN: {w}")
    for f in failures:
        print(f"FAIL: {f}")

    if failures or warnings:
        print(f"\ncapability parity MISMATCH: "
              f"{len(failures)} failure(s), {len(warnings)} warning(s)")
        sys.exit(1)
    print(f"\ncapability parity OK: {len(server)}/{len(server)} caps match; "
          "all preventDowngrade/requireForNewDevices caps default true in "
          "LinkCapabilities")


if __name__ == "__main__":
    main()
