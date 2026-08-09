# Forked dependencies

xas consumes its patched Signal-stack dependencies as GitHub forks,
each a rebase-managed branch = **upstream pin + a small stack of
reviewable commits**. The workspace root `Cargo.toml` redirects the
canonical upstream URLs / crates.io names to these forks via
`[patch]` entries with explicit `rev` pins; member crates keep
declaring the upstream URLs. This replaces the old `vendor/`
directory model (removed 2026-07; the delta used to live in
hand-regenerated `diff -ruN` blobs, now it is plain git history).

## Pin matrix

| Crate | Upstream base | Fork repo + branch | Pinned rev | Delta |
|---|---|---|---|---|
| `presage` | [whisperfish/presage](https://github.com/whisperfish/presage) `600c4ed` | [tunnell/presage](https://github.com/tunnell/presage) `xous-600c4ed` | `7b63a451f4089011830302538c854d6860f74ecc` | [compare](https://github.com/whisperfish/presage/compare/600c4ed...tunnell:presage:xous-600c4ed) — 3 commits: `presage::runtime` LocalExecutor module + tokio removal; ws-task adaptation + `last_identified_close_code()`; PNI `service_id_string()` cipher fix |
| `libsignal-service` | [whisperfish/libsignal-service-rs](https://github.com/whisperfish/libsignal-service-rs) `782c0d6` | [tunnell/libsignal-service-rs](https://github.com/tunnell/libsignal-service-rs) `xous-782c0d6` | `96bcdf8eb69bd25d3f9770295535222540b6f491` | [compare](https://github.com/whisperfish/libsignal-service-rs/compare/782c0d6...tunnell:libsignal-service-rs:xous-782c0d6) — 7 commits: `HttpClient`/`WebSocketChannels` transport trait; `ws()` -> `(ws, task)` + keepalive tolerance (`MAX_OUTSTANDING_KEEPALIVES = 3`); `last_close_code()` accessor; manifest; backup5 in the provisioning QR URL; link/device capability sync (`usernameChangeSyncMessage` — clears the 2026-07 HTTP 409 on `PUT /v1/devices/link`); slow-flash prekey replenish mitigation (batch 25 + per-key yield — stops the regeneration storm; idempotent re-upload deferred, upstream #462) |
| `curve25519-dalek` (+ `-derive`) | [betrusted-io/curve25519-dalek](https://github.com/betrusted-io/curve25519-dalek) main `16e087ab9` (4.1.2) | [tunnell/curve25519-dalek](https://github.com/tunnell/curve25519-dalek) `xous-signal-4.1.3` | `0cac8fc8239e73ea740ff720c7f93b486618b77d` | [compare](https://github.com/betrusted-io/curve25519-dalek/compare/16e087ab9...tunnell:curve25519-dalek:xous-signal-4.1.3) — version bump 4.1.2 -> 4.1.3 (matches zkgroup's `curve25519-dalek = "4.1.3"`); `src/lizard/` port from [signalapp/curve25519-dalek](https://github.com/signalapp/curve25519-dalek) tag `signal-curve25519-4.1.3` |
| `getrandom` | n/a (in-repo package, no fork) | [betrusted-io/xous-core](https://github.com/betrusted-io/xous-core) in-repo path `imports/getrandom` (not a branch) | `2005a801c917753175d3826446ce1352c119e020` | none — consumed as-is at a fixed rev (the betrusted-io/sigchat / dabao-base-app pattern) |

`Cargo.lock` records the same revs; cargo verifies every checkout
against them. To audit a delta, open the compare URL or run
`git log <upstream-pin>..<pinned-rev>` in a fork clone.

## Rules

- **presage and libsignal-service revs are coupled.** The forked
  `ws()` returns `(ws, task)` (the caller spawns the task; there is
  no ambient tokio runtime), and the presage fork is written against
  exactly that API. Never bump one pin without the other — bump them
  as a pair and re-run the full verification gate.
- **CDSI stays off via consumers, not the fork.** The
  libsignal-service fork keeps upstream's `default = ["cdsi"]`
  (zero manifest divergence); CDSI pulls boring-sys (BoringSSL),
  which has no rv32-xous target. Every consumer MUST declare
  `default-features = false` — today that is `xous-net-bridge` and
  the presage fork's own `libsignal-service` dep. A new consumer
  that forgets this breaks the rv32 build at boring-sys.
- **The dalek `digest` feature is required.** The `src/lizard/`
  module uses `digest::Digest` unconditionally; zkgroup/libsignal
  already enable the feature, so nothing extra is needed today —
  but a hypothetical consumer of the patched crate with
  `default-features = false` and no `digest` would fail to compile.
- **The two dalek patch entries move in lockstep.**
  `[patch.crates-io]` and
  `[patch."https://github.com/signalapp/curve25519-dalek"]` must
  point at the same fork rev, or two `RistrettoPoint` types
  reappear and the build fails with duplicate-type errors.

## Maintenance cadence

1. `git fetch upstream` in the fork; review what moved
   (`git log <current-base>..upstream/main`).
2. To adopt a new base: rebase the commit stack onto the new
   upstream pin and push it as a **new branch**
   `xous-<newbase-short-sha>` (dalek keeps its
   `xous-signal-<version>` naming). **Never force-push** an
   existing `xous-*` branch — pinned revs in released xas
   Cargo.locks must stay fetchable forever.
3. Update the `[patch]` revs in the workspace `Cargo.toml` (presage
   + libsignal-service as a pair), regenerate `Cargo.lock`, update
   the matrix above, and run the full verification gate (hosted
   tests, net-bridge + store suites, rv32 build; transport-affecting
   bumps need Renode/hardware evidence per the verification norms
   in tests/README.md).
4. At each xas release, tag the consumed rev in every fork as
   `xas-vX.Y` (same convention as the frozen `xous-core@xas-vX.Y`
   kernel branches) so release provenance survives branch churn.
5. When a fork commit merges upstream, drop it from the stack on
   the next rebase; the goal state for each fork is an empty delta.

## Offline source snapshot (release artifacts)

The in-tree copy is gone, but a full source snapshot for offline
audit or archival is one command away:

```sh
cargo vendor --locked vendor-snapshot
```

This materializes every dependency — including the git-pinned forks
at exactly the locked revs — under `vendor-snapshot/`. Attach the
tarball to release artifacts if a self-contained source archive is
wanted; do not check it in.
