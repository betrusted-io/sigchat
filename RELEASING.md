# Releasing xas

xas releases are pinned to specific snapshots of `tunnell/xous-core` so a
given xas version always builds against the same kernel + services state.
Each release gets its own `xas-vX.Y` tag on xous-core. A tag does not
move, so the pin cannot drift after the release ships. Later releases
add `xas-vX.Y+1`; old tags are never deleted or repointed.

## Pre-flight

- No open `WIP` / `[do not merge]` commits on `dev`.
- The BUILDING.md workflow has been walked cold (blank agent or a
  fresh checkout) recently — BUILDING.md drift is the most common
  silent regression.
- Hardware validation done end-to-end for the release scope:
  link → send → receive on a real Precursor PVT2 (see step 4).

## Procedure for cutting `vX.Y`

1. **Decide what's in the release.** The xous-core changes needed by xas
   for this release should already be on the floating
   `tunnell/xous-core@xas-integration` branch (or tracked in open
   PRs against it).

2. **Create the pinned xous-core tag.**

   ```sh
   cd path/to/xous-core
   git fetch origin xas-integration
   # If any in-flight PRs against xous-core need to be in this
   # release, cherry-pick them onto a temporary branch first and
   # tag that instead.
   git tag -a xas-vX.Y origin/xas-integration -m "xas vX.Y kernel-side pin"
   git push origin xas-vX.Y
   ```

   Tags are immutable pins — never move or delete a published
   `xas-vX.Y` tag. (Before the 2026-07 branch cleanup releases
   pinned via frozen *branches*; the v0.2 pin survives as the
   lightweight `xas-v0.2` tag at the deleted branch's head.)

3. **Bump xas's version.** Semver: patch for doc/bug fixes, minor for
   user-visible features, major reserved for "we consider this
   production". In the xas repo:

   ```sh
   cd path/to/xous-app-signal
   # Edit Cargo.toml: bump [workspace.package] version to "X.Y.0"
   # Edit BUILDING.md step 1 and the "Branch selection" note at
   # the top of the hardware path if
   # the release-pin tag they mention needs bumping (dev builds keep
   # pointing at the xas-integration branch).
   cargo metadata --format-version 1 >/dev/null   # regen Cargo.lock
   git add Cargo.toml Cargo.lock BUILDING.md
   git commit -m "release: bump workspace version to X.Y.0"
   ```

4. **Hardware verify.** Build, flash to Precursor PVT2, drive a send to
   a single-device peer. The send should complete in <60 s end-to-end
   (target was set during v0.2 design). If the send regresses vs the
   prior release, **stop** and investigate before tagging.

5. **Open the release PR.** Branch named `vX.Y-candidate`, base `dev`.
   PR body includes:
   - Hardware verification UART excerpts.
   - Companion `tunnell/xous-core` PR(s) that landed in `xas-vX.Y`.
   - Issues closed.
   - Known issues that ship anyway.

6. **Merge the PR.** Squash-merge is acceptable for a release branch.
   Merge-commit also works if the PR's history is already clean.

7. **Tag the release.**

   ```sh
   cd path/to/xous-app-signal
   git checkout dev
   git pull --ff-only
   git tag -a vX.Y -m "xas vX.Y"
   git push origin vX.Y
   ```

8. **Move `main` to the release.** `main` carries merge commits from
   past releases, so it is not a fast-forward of `dev` — open a PR
   from `dev` to `main` and merge it:

   ```sh
   gh pr create --base main --head dev --title "release: xas vX.Y"
   gh pr merge --merge
   ```
9. **Create the GitHub Release.** The git tag alone is not enough; GitHub
   surfaces releases as a separate first-class concept on the Releases
   tab. Without an explicit Release entry, the tag exists but doesn't
   appear in the "Latest" badge or get picked up by release-feed
   integrations.

   Draft the release notes first (in the maintainer's workspace, not
   in-tree). Mirror the prior release's structure so the Releases page
   reads consistently — typically:

   - One-line headline (the user-visible win this release ships).
   - "What changed vs `vX.{Y-1}`" bullets.
   - "Required upstream patches" status (in-flight PRs that this
     release depends on or that ship downstream-vendored until they
     merge).
   - Until-those-merge build pointer (the pinned `xas-vX.Y` branch
     from step 2).
   - "Known limitations" with GitHub issue references.
   - Build / release-procedure pointers (BUILDING.md, this file).

   Then publish via `gh`:

   ```sh
   gh release create vX.Y \
       --title "xas vX.Y" \
       --notes-file path/to/release-notes.md \
       --latest
   ```

   Verify with `gh release view vX.Y --repo tunnell/xous-app-signal` —
   should show the "Latest" badge and the notes rendered.

10. **Don't delete `xas-vX.Y` tags on xous-core.** Past release pins
    stay accessible forever — anyone re-building an old xas version
    from source needs them.

## Why this pin model

Decoupling the release pin (a tag) from the floating
xas-integration branch means:

- Reproducible builds: `xas vX.Y` always builds against the same kernel.
- No coordination dance: in-flight xous-core PRs can land on
  `tunnell/xous-core@xas-integration` (and eventually upstream `betrusted-io/xous-core@dev`)
  on their own timeline. They get rolled into xas releases when the next
  xas release decides to pin them in.
- Clean fallback: if a maintainer reports a bug on `xas vX.Y`, that
  bug-fix path is well-defined — clone `xous-app-signal@vX.Y`, clone
  `xous-core@xas-vX.Y`, reproduce, fix on a hot-fix branch off `vX.Y`.
