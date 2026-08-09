# xous-app-signal (`xas`)

Unofficial Signal client for [Xous](https://github.com/betrusted-io/xous-core)
on [Precursor](https://www.crowdsupply.com/sutajio-kosagi/precursor).

**Prototype. Not for production use.**

Built on the Whisperfish Rust stack —
[`presage`](https://github.com/whisperfish/presage),
[`libsignal-service-rs`](https://github.com/whisperfish/libsignal-service-rs),
and [`signalapp/libsignal`](https://github.com/signalapp/libsignal) — rather
than reimplementing the Signal protocol from primitives. The on-device binary
is named **`xas`** ("**X**ous **a**pp **s**ignal").

The driving project value is end-user verifiability: a user who buys a
Precursor should be able to read every line of Rust that ends up on their
device. The design therefore leans on upstream community-maintained code
(reused as-is or with small reviewable patches) and minimizes bespoke
Xous-specific glue.

---

## Why a Signal client on Precursor

Smartphones are the primary target for surveillance of journalists and human-rights workers. The [Pegasus Project](https://forbiddenstories.org/about-the-pegasus-project/) — coordinated by Forbidden Stories with forensic support from [Amnesty International's Security Lab](https://securitylab.amnesty.org/case-study-the-pegasus-project/) — documented commercial spyware on devices belonging to journalists, activists, and dissidents in [over 50 countries](https://www.eff.org/deeplinks/2026/04/digital-hopes-real-power-how-arab-spring-fueled-global-surveillance-boom). Zero-click exploits like [BLASTPASS](https://securitylab.amnesty.org/latest/2023/12/india-damning-new-forensic-investigation-reveals-repeated-use-of-pegasus-spyware-to-target-high-profile-journalists/) install spyware without the target tapping anything. End-to-end encryption in apps like Signal is necessary but insufficient when the host operating system itself is compromised — once Pegasus is on the phone, [it can read messages and turn on the microphone and camera regardless of which app you used](https://forbiddenstories.org/about-the-pegasus-project/).

[Precursor](https://www.crowdsupply.com/sutajio-kosagi/precursor) is an open-hardware mobile device built around the principle of [evidence-based trust](https://www.bunniestudios.com/blog/2022/precursor-from-boot-to-root/): every layer from the FPGA bitstream up through the [Xous microkernel](https://betrusted.io/) is inspectable and reproducible, and Precursor [generates and seals its own keys](https://www.bunniestudios.com/blog/?p=5979) without relying on factory secrets. Until now most Precursor applications have focused on credential storage (password managers, FIDO/U2F, cryptocurrency wallets). This project fills the missing piece — **communications** — by porting Signal's secondary-device protocol to Xous so that messages a journalist or activist sends from their pocket are protected by hardware they can audit themselves.

**Short-term goal**: a communications device journalists and activists who already have a Precursor can audit end to end.

**Long-term goal**: a cheaper successor (the [Betrusted](https://betrusted.io/) ASIC currently in development) that puts this same threat model in reach of users in the Global South, where surveillance pressure is highest and where activists and journalists [most often lack resources to recover from compromise](https://www.amnesty.org/en/latest/news/2024/12/serbia-authorities-using-spyware-and-cellebrite-forensic-extraction-tools-to-hack-journalists-and-activists/).

**Scope tradeoff**: Precursor's hardware constraints (16 MiB
total RAM, no GPU, single-screen monochrome 336×536 display, no
audio/video hardware) mean this client implements a deliberately
minimal Signal feature set. The goal is "your most sensitive
conversations on hardware you can audit," not "feature parity
with the mobile app." The feature support matrix below makes the
tradeoffs explicit.

---

## Feature support

Verified working on Precursor PVT2 hardware unless noted. Each
capability that maps to a Signal app feature is listed; the third
column says whether the gap is fundamental (hardware can't do it)
or a roadmap item (planned but not yet built).

### Messaging

| Feature | Status | Note |
|---|---|---|
| Link as a secondary device (QR scan) | ✅ | Boot, PDDB unlock, QR scan, decrypt ProvisionEnvelope, register, persist |
| Receive 1:1 text messages | ✅ | Near-instant once linked. Verified on hardware (2026-05-11) receiving DMs from multiple distinct senders. |
| Send 1:1 text messages | ✅ | Latency 1–4 min — Signal edge-server WS rotation race; transport refactor on roadmap |
| Conversation list (Home) | ✅ | Per-thread last-message + relative timestamp + unread indicator |
| Per-thread message view | ✅ | Optimistic-render compose; auto-mark-read on thread open |
| Group chats (read or write) | ❌ | Roadmap. Adds ~1 MiB of state per group + UI surface |
| Disappearing messages | ❌ | Body still displays but no timer indicator; xas doesn't honor the expire_timer (no auto-delete). Roadmap |
| Typing indicators | ❌ | Roadmap. Low priority |
| Read receipts (sending) | ❌ | Auto-mark-read on thread open updates UI state only; xas doesn't call any send-receipt API. Roadmap |
| Stories | ❌ | Out of scope. Built around media |

### Media + attachments

| Feature | Status | Note |
|---|---|---|
| Image / video / file attachments (send or receive) | ❌ | Out of scope. Display + storage budget too small for media-first UX |
| Voice notes | ❌ | Hardware: no microphone codec wired through Xous |
| Stickers | ❌ | Out of scope. Display is monochrome |
| Emoji reactions | ❌ | Inbound reactions arrive as DataMessages with empty body and are silently dropped at process_received. No outbound UI either. Roadmap |

### Calling

| Feature | Status | Note |
|---|---|---|
| Voice calls | ❌ | Hardware: no audio path on Precursor |
| Video calls | ❌ | Hardware: no camera, no codec |

### Account + profile

| Feature | Status | Note |
|---|---|---|
| Display name + phone number on Profile | ✅ | Read from registration data |
| Profile editing (name / picture / about) | ❌ | Roadmap. Read-only today |
| Username (`@alice.42`) on Profile | ❌ | No API to read one's own Signal username in our build (RegistrationData has no username field; Profile struct has no username field). The primary phone holds that state |
| Username lookup in "New chat" | ✅ | F1 → enter `name.42` → presage's `lookup_username` resolves to ACI; UI opens a Thread |
| Phone-number lookup in "New chat" | ❌ | Needs CDSI which requires boring-sys (BoringSSL) — disabled in this build because it can't target rv32-xous |
| Logout | ✅ | Settings → Logout: confirmation modal, then the worker wipes link state from the PDDB (`Cmd::Logout`) and the UI returns to the pre-link menu |
| Multiple linked accounts | ❌ | Single-account device by design |
| Primary registration (this device IS the primary) | ❌ | Out of scope. Secondary-device only — your phone stays primary |

### Hardware integration

| Feature | Status | Note |
|---|---|---|
| Wi-Fi (2.4 GHz only — Precursor is single-band) | ✅ | Configured via shellchat (`wlan off; wlan on; ssid scan; wlan status`); no in-app onboarding |
| Hardware-rooted key sealing (PDDB) | ✅ | Inherited from Xous; xas writes registration + sessions through `presage-store-pddb` |
| Sealed sender (Signal Protocol) | ✅ | Handled transparently by libsignal-service-rs |
| PQXDH (post-quantum key agreement) | ✅ | libsignal default; verified working on rv32 |

### Things handled by upstream code (not xas's own logic)

xas uses the Signal Protocol implementation in
[`signalapp/libsignal`](https://github.com/signalapp/libsignal)
(via [`libsignal-service-rs`](https://github.com/whisperfish/libsignal-service-rs)
and [`presage`](https://github.com/whisperfish/presage)). Cryptographic
primitives — Double Ratchet, X3DH/PQXDH, sealed sender, prekeys,
identity keys — are **not reimplemented** here. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for what xas adds
on top of those libraries (mostly: Xous IPC plumbing, a
sync-blocking-on-async transport bridge, and the GAM-rendered
UI).

---

## Where to learn more

- [`BUILDING.md`](BUILDING.md) — clone-to-running instructions
  for both hosted-mode emulator and Precursor hardware paths
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how xas
  works, written for a Rust developer with passing crypto
  knowledge
- [`tests/README.md`](tests/README.md) — overview of the four
  testing approaches (unit / hosted / Renode / Precursor),
  pros and cons, and the dev/main branch convention
- [`tests/precursor/README.md`](tests/precursor/README.md) —
  hardware-test workflow: build, flash, watch UART (read this
  BEFORE running any flash command — its "Brick prevention"
  section is non-negotiable)

---

## Upstream patches

**Nothing xas needs is waiting on an upstream merge.** The two
encoding bugs that originally forced a kernel fork are both fixed
upstream: the net-service error-encoding mismatch
([betrusted-io/xous-core#877](https://github.com/betrusted-io/xous-core/pull/877),
merged 2026-06-02 as `2005a801c`) and its std-side twin
([rust-lang/rust#156414](https://github.com/rust-lang/rust/pull/156414),
merged; the kernel-side mirror covers the gap until it reaches a
stable toolchain). The keepalive-tolerance PR
([whisperfish/libsignal-service-rs#431](https://github.com/whisperfish/libsignal-service-rs/pull/431))
was closed unmerged by its author in 2026-07; its fix is a
deliberate fork delta now, not a pending patch.

What xas deliberately carries that upstream doesn't have — pins
and compare URLs in [docs/FORKS.md](docs/FORKS.md):

- **Kernel fork** (`tunnell/xous-core`, branch `xas-integration` =
  upstream `dev` + a small cherry-pick set; releases freeze it
  into `xas-vN` tags — v0.2 builds use the frozen `xas-v0.2`
  tag): the `apps/manifest.json` xas registration, the DNS
  CNAME-chain fix, the quiet-socket reaper fixes (filed once as
  [#880](https://github.com/betrusted-io/xous-core/pull/880),
  closed pending the upstream Renode-CI net refactor), and a few
  hosted-test conveniences.
- **Crate forks**: keepalive tolerance + a sync transport layer
  (`libsignal-service-rs`); tokio removal + a PNI-cipher fix
  (`presage`); the lizard module port from signalapp's tree
  (`curve25519-dalek`).

Separately, a batch of maintainer PRs is open at
`betrusted-io/xous-core` — the Renode net-CI suite
[#918](https://github.com/betrusted-io/xous-core/pull/918) and
eight pddb `std::fs` fixes #910–#917 — which came out of xas
testing but stand on their own.

---

## Layout

```
xous-app-signal/
├── crates/
│   ├── presage-store-pddb/     storage trait impls over PDDB
│   ├── xous-net-bridge/        sync TLS + WS pump + channel bridge
│   ├── xous-pddb-ipc/          hand-rolled PDDB IPC client
│   ├── xous-signal-worker/     presage::Manager on worker thread + Cmd/Event channels
│   ├── xous-app-signal/        binary entry point (binary name: `xas`)
├── docs/                       ARCHITECTURE.md (reader's-eye-view), FORKS.md (dependency fork pins)
└── tests/                      hosted-mode + Renode + precursor (hardware) test harnesses
```

The patched Signal-stack forks (presage, libsignal-service-rs,
curve25519-dalek) are consumed as rev-pinned git dependencies,
not in-tree copies — see [docs/FORKS.md](docs/FORKS.md).

---

## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This project is dual-licensed under the terms of the AGPL 3.0 license, as
a derivative work; and under the terms of the Apache 2.0 license.
`SPDX-License-Identifier: AGPL-3.0 OR Apache-2.0`

You can choose between one of them if you use this work.
* [AGPLv3.0](https://www.gnu.org/licenses/license-list.html#AGPLv3.0)
* [Apachev2.0](https://www.apache.org/licenses/GPL-compatibility.html)

We have a **desire** to license xas under Apache-2.0 so that elements may
be readily incorporated into other future
[Xous](https://github.com/betrusted-io/xous-core) related projects.
We are **required** to license any derivative works of
[libsignal](https://github.com/signalapp/libsignal) under the AGPL-3.0 license.

---

## Contributing — including AI-assisted contributions

Contributions are welcome via pull request against the `dev`
branch. See [CONTRIBUTING.md](CONTRIBUTING.md) for how issues,
PRs, and commit messages should read, and
[`tests/README.md`](tests/README.md) for the branch convention
and what release-cycle gates a PR has to pass before it can land
in `main`.

AI-assisted contributions are welcome if you disclose them: the
`Assisted-by: coding agent` trailer, why it isn't a model name,
and what you're still vouching for are in
[CONTRIBUTING.md](CONTRIBUTING.md). Users of this client need to
be able to audit it, and knowing where a tool was involved tells
a reviewer where to look harder.
