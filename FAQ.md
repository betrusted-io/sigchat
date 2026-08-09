# xas FAQ

xas is an unofficial Signal client for Precursor running Xous OS.
Status: prototype — not for production use (see the README's
feature-support matrix). Built on `presage` and
`libsignal-service-rs`.

If something here is wrong or out of date, file an issue or open a
PR at <https://github.com/tunnell/xous-app-signal>.

---

## Linking

### "I scanned the QR but nothing happened."
- The QR window stays up until you press a key on Precursor; it
  doesn't auto-close. After scanning, press any key on the device
  to dismiss the modal — only then will the worker continue.
- If `LinkComplete` doesn't arrive within ~30s, the WebSocket may
  have idled out. Cancel from the menu, run `wlan status` from
  shellchat to confirm Wi-Fi is still associated, and try again.

### "Linking ran out of memory."
- Older builds hit a per-process heap cap of 512 KiB. The current
  build uses `--kernel-feature big-heap` (12 MiB) plus an XIP image
  that runs apps from flash. If you build your own image, make
  sure both apply: `cargo xtask app-image-xip ... --kernel-feature
  big-heap`.

### "Signal said 'too many linked devices'."
- Signal allows ~5 linked secondary devices per primary. Remove an
  old one from your phone (Settings → Linked Devices) before
  re-linking.

---

## Sending

### "Send fails with 'WebSocket closing'."
- Hard failures of this shape are addressed in the current build:
  the vendored `libsignal-service-rs` tolerates in-flight
  keepalives (`MAX_OUTSTANDING_KEEPALIVES = 3`) and the pinned
  `xas-integration` xous-core carries the recv-encoding fix (upstream
  betrusted-io/xous-core#877, since merged). If you still see it,
  you're probably on an older xous-core — see BUILDING.md's
  troubleshooting table.
- The residual known issue is **latency, not failure**: a send
  can take 1–4 minutes while the Signal edge server rotates the
  WebSocket. The transport refactor on the roadmap addresses it.
  Give a pending send a few minutes before declaring it dead.

### "Send fails with 'panic in send: …'."
- `catch_unwind` around the libsignal-service send path surfaces
  any panic as a regular UI error. If you see one, capture the
  message and the message text (or shape) and file an issue.

---

## Receiving

### "I don't see a name, just a UUID."
- Until you reply to that contact, xas only knows the UUID. Once
  you send a message back — or pull the contact list from your
  linked phone with F2 (Sync) on Home — the human-readable
  short-name kicks in.

### "Messages from groups don't appear."
- Group messages aren't supported yet. Only 1:1 conversations
  render. Group support is a roadmap item (see the README's
  feature-support matrix) — file an issue if you need it sooner.

### "Attachments don't appear."
- Attachments aren't supported (out of scope — see the README's
  feature-support matrix). The text body of an attachment-only
  message renders as the body the sender attached (if any).

---

## Wi-Fi

### "I need to connect to Wi-Fi before xas works."
- xas doesn't include Wi-Fi onboarding (a prior attempt caused a
  downstream crash; reverted while we set up UART debugging).
  Before opening xas, switch to shellchat (use the launcher menu)
  and run **in this exact order**:
  ```
  wlan off
  wlan on
  ssid scan
  wlan status      # poll until it shows 'Connected'
  ```
  The first time you bring up Wi-Fi after a cold boot, the cycle
  matters: `wlan off` makes sure no stale connection state lingers,
  `wlan on` powers up the radio, `ssid scan` triggers an active
  scan, and `wlan status` is the only way to know when association
  finished. (Connection completion is async; there's no event we
  surface.) Once `wlan status` reports `Connected`, sanity-check
  the link with `net ping 1.1.1.1` — that confirms the IP path is
  alive without involving DNS.

  After both succeed, `net ping chat.signal.org` is a good last
  step before launching xas: it exercises the DNS resolver
  (including the CNAME-chain fix) on the actual Signal hostname.

### "Should I configure multiple Wi-Fi networks?"
- **Stick to one SSID.** xas has no code today for handling a
  network transition (e.g. roaming from home Wi-Fi to a coffee-shop
  AP, or even reconnecting after the AP reboots). If you change
  networks, repeat the `wlan off / wlan on / ssid scan / wlan
  status` dance and restart xas.

### "My SSID doesn't show up in the scan."
- **Precursor only supports 2.4 GHz.** The on-board WF200 radio
  is 802.11 b/g/n single-band — 5 GHz networks (and most modern
  mesh systems' "fast" SSID) won't appear in `ssid scan` output
  no matter what you do. If your home AP only broadcasts on
  5 GHz, or splits SSIDs by band and you're trying to join the
  5 GHz one, the scan will return nothing useful.
- Two practical workarounds:
  - **Phone hotspot in 2.4 GHz mode.** Most modern phones
    default to 5 GHz now; you usually have to dig into the
    hotspot settings to force 2.4 GHz (or "compatibility mode").
    Easiest portable fix.
  - **A small router that emits 2.4 GHz reliably.** The
    [Nitrokey NW750 NitroWall](https://shop.nitrokey.com/shop/nw750-nitrowall-nw750-590)
    is a known-good option with sane defaults; it's a hardened
    OpenWrt box that gives you a 2.4 GHz SSID Precursor can
    join. (Not a paid promotion — just one device that's been
    verified to work.)
- After joining, sanity-check with `wlan status` (must show
  `Connected`) and `net ping 1.1.1.1` (must round-trip) before
  opening xas.

### "DNS fails for chat.signal.org."
- The pinned xous-core carries a CNAME-chain fix for the Xous DNS
  parser (`xous-core/services/dns/src/main.rs`, commit
  `43dcb4a59`). If you're on an older xous-core, switch to the
  `xas-integration` branch from BUILDING.md step 1.
- If `net ping 1.1.1.1` succeeds but `net ping chat.signal.org`
  fails, your DNS resolver is misconfigured (or you're on an
  xous-core build that predates the CNAME fix). Check
  `wlan status` for the resolver IPs.

---

## Keyboard

### "What do F1–F4 do?"
- **F1**: New chat — prompts for a UUID or a Signal username
  (`name.000` form, resolved over the network). Phone-number
  lookup is not supported (CDSI is disabled in this build).
- **F2**: Sync — pulls the contact list from your linked phone;
  a notification confirms when it completes.
- **F3**: Help — opens this FAQ summary in-app.
- **F4**: Settings — Profile / Help / About / Logout.
- On Thread: F1 also sends (alias for Enter), F4 opens Settings.

### "Esc?"
- Esc on Home opens Settings. Esc on a Thread returns to Home.
  Esc on Settings returns to Home.

### "Hosted mode doesn't have F-keys."
- Hosted (minifb on Linux) doesn't deliver F1–F4 like the device
  does. Use the in-app Settings menu (Esc on Home) and the on-screen
  hints to navigate. F-keys only work on Precursor hardware.

---

## State / persistence

### "I want to test the UI without re-linking."
- After a successful link, run `pddb dump` from shellchat. That
  writes `xous-core/tools/pddb-images/full.bin`. Copy that file
  somewhere safe, and copy it back into place before launching
  hosted to restore the linked state.

### "How do I log out / re-link as a different account?"
- Settings (F4) → Logout. It asks for confirmation, then wipes
  the link state from the PDDB and returns to the pre-link menu;
  re-linking means another QR scan. Manual fallback if the app
  is wedged: `pddb wipe` from shellchat (or wipe the snapshot
  file in hosted mode).

---

## Filing issues

- Repo: <https://github.com/tunnell/xous-app-signal>
- When filing a bug, include:
  - xas version (shown in the About screen).
  - Whether you're on hardware or hosted.
  - The exact error string from the UI (or the panic, if any).
  - What you were doing when it happened (link / send / receive /
    idle).

The best-known active issue is send latency (first send can take
1–4 minutes — Signal edge-server WebSocket rotation; transport
refactor on the roadmap). Anything else is probably a fresh bug —
please report it.
