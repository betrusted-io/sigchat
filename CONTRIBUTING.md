# Contributing

The merged pull requests are this project's history. The code says
what it does now; only the PR log says why it got that way, what was
tried and abandoned, and what was measured on real hardware. Someone
reading it in a year — or an agent opening its first PR here — should
be able to reconstruct the reasoning without asking anyone.

That is the whole reason for this file. Everything below serves it.

## What a pull request says

Write it for a person. The reader might be you in a year, or someone
who just unboxed a Precursor and wants to know why sending was slow.
They do not have your last three weeks in their head, and they do not
know what a `BufferingBackend` is. Say enough that they don't have to
open the diff to follow you.

Four beats, in prose. Most PRs here fit in one to three paragraphs.

1. **What someone would notice** — the symptom, in plain words.
2. **Why it happened** — the mechanism, and the number that proves it.
3. **What you changed.**
4. **What is still broken**, what you did not test, and `Closes #N`.

Start where the reader is. "Wiping settings looks like the device has
crashed" lands before any sentence about flash sector counts does.
Then earn it — the mechanism is what turns the first sentence from a
complaint into a finding.

The dense material belongs in the commit messages, and there you can
go as deep as you like. A PR body is the human-facing summary of a
branch; `git log` is where the reasoning lives in full.

A whole PR body, for a one-line fix to the build instructions:

> Follow our USB setup instructions on Arch and the flashing tool
> still can't open the device. The rule file was named
> `99-precursor.rules`, and systemd hands out the permission from
> `73-seat-late.rules` — so by the time our rule ran, the thing that
> reads it had already finished. Renamed to `70-precursor.rules`,
> with a line saying why the number matters.
>
> The troubleshooting table further down had the same problem twice
> over: it still carried the old pre-`uaccess` recipe, which fails on
> Arch and Fedora for a different reason, so anyone who skipped to it
> got advice contradicting the setup section. It now points back at
> that section instead of repeating a second recipe.
>
> Not tested on Fedora or Debian — only Arch, where it was reported.
>
> Closes #77 — reported by @nworbnhoj, who found the systemd issue
> that explains the ordering.

Symptom, cause, fix, what wasn't checked, credit. No headings, no
summary of its own diff, nothing a reader takes on faith. Someone who
has never heard of udev still learns what broke and why.

**Titles** carry a conventional-commit prefix (`fix(ui):`, `docs:`,
`perf(pddb):`), matching the commit subjects underneath them. We merge
with merge commits rather than squashing, so the title is not itself
recorded in git — it is what people scan the PR list by, which is
reason enough to make it say something. Imperative mood, no trailing
period, under about 72 characters. A title should name the effect, not
the file touched: "a wipe takes minutes, not a minute" beats "update
modal string". This
is a local convention — 35 of the first 41 PRs here follow it, while
xous-core upstream uses bare lowercase subjects. Keep it inside xas;
drop it when sending a patch upstream.

**One concern per PR.** Bug fixes, refactors, and doc updates go in
separate PRs even when they touch the same file. If a change needs
headings to stay navigable, it needs splitting instead.

**Claims need their evidence inline.** Don't write "much faster" —
write the number and where it came from. `#73` earns its conclusion
in one sentence: "~25 flash sector operations per 17 KiB record, at
~100 ms each on PVT2." A reader can check that. "Significantly
improves wipe performance" is not checkable and is not worth typing.

If a claim rests on something you did not run, say so. The honest
form is "hardware-verified 2026-07-31, send round-trip 10.7 s"; the
dishonest form is a ticked checkbox next to a test nobody ran.

**Say what you don't know.** Name the residual risk, the hang you
couldn't reproduce, the part you didn't test. Upstream this is the
house habit — bunnie merges a TOCTOU fix saying "This should finally
thoroughly eliminate the TOCTOU risk on swap, I hope", and elsewhere
records that a fix he shipped was not the bug he was chasing. Write
that way here. Unqualified confidence in a security-relevant change
is a defect, not a style choice.

**Every link must resolve for a stranger.** Several older PRs cite
paths under a maintainer-private `notes/` workspace. To any other
reader those are dead ends that look like evidence. Quote the three
relevant lines of UART instead, or leave it out.

**Name sections, don't number them.** Write "the USB access step in
BUILDING.md", not "BUILDING.md §0". The `§` reads like a statute, and
section numbers rot the moment anyone inserts a heading — a name
still finds the right place after the document moves around. Link to
the heading where you can.

## What an issue says

Issues take plain descriptive titles — they name a symptom, not a
change type, so the commit prefixes don't apply. Lead with where the
problem came from and what is concretely broken, with file cites.
Then the shape of a fix as a short list, then sequencing. `#40` is
the model: provenance, the defect with `lib.rs` cites, four bullets
of intended shape, then "Sequencing: before any retry-loop rework."

State effort if you know it. Don't design the fix in the issue; that
is what the PR is for.

## Commit messages

Same prefix convention as PR titles, imperative, no trailing period.
Body only when the subject can't carry it — and then explain why,
not what. `git blame` and the diff already cover what.

Wrap bodies at 72 columns so `git log` stays readable indented.

`Closes #N` goes in the PR description, not the commit message. On a
rebase, an issue number in a commit re-notifies the issue every time
— rust-lang/rust avoids it for exactly this reason.

One logical change per commit. A PR whose commits each need a
paragraph of explanation is usually several PRs.

## Release notes

Written for someone deciding whether to flash the thing. Lead with
what now works and what it was verified against, then fixes as cause
and consequence, then limits plainly stated. The v0.3 notes are the
template — including the closing line that says "1:1 text only — no
group chats, no attachments," which is the most useful sentence in
them.

## Security-relevant changes

This is a messaging client on a device people are asked to trust, so
the language around security carries weight. Four rules, each lifted
from a project that does this well.

**Say what an attacker gained before and does not gain now.** If you
can't write that sentence, you have a bug fix, not a security fix —
call it a bug fix. "Fixed a security issue" tells a reader nothing
they can act on.

**Name who is not affected.** rustls does this in nearly every
advisory: "Callers which do not call `complete_io()` are not
affected." Here that usually means which pins, which firmware
revision, or whether the device has to be unlocked already.

**Bound the compromise in the same sentence that admits it.** From
WireGuard's known-limitations page: a traffic log plus a key
compromise "would enable an attacker to figure out who has sent
handshakes, but not what data is inside of them." Admitting the
weakness and scoping it are one act, not two.

**Severity comes from specificity, not adjectives.** OpenSSH writes
"requires on average 6-8 hours of continuous connections" rather than
"hard to exploit." Sequoia writes "low-severity as Rust correctly
detects the out of bounds access and panics" rather than "minor."

And when a change is security-shaped but fixes nothing exploitable,
say so plainly. rustls merged one whose entire body was: "It is a
logic error to verify a signature with an unidentified key. This is a
structural robustness improvement, with no runtime effect."

Vulnerabilities do not go in a PR. Use GitHub's private
vulnerability reporting on this repository (Security → Report a
vulnerability); if that is unavailable, open an issue saying only
"security contact requested" and nothing else. Never put
reproduction details, captured traffic, or account identifiers in a
public issue — a PCAP of real Signal traffic carries phone numbers
and ACIs.

## AI-assisted work

AI-assisted contributions are welcome, on one condition: disclose
them. Users of this client need to audit it, and reviewers benefit
from knowing where to look harder.

Commits carry a trailer, exactly:

```
Assisted-by: coding agent
```

Never a model, product, or vendor name. The trailer records that a
tool was involved, which is the reviewable fact; which tool it was
dates badly and reads as advertising. You are the author either way
— agents are tools, not co-authors, so no `Co-Authored-By` for them.

You are vouching for every line you submit. "The agent wrote it" is
not a defence of a diff you did not read.

**Write the prose yourself.** Generating the diff with an agent is
fine; handing a reviewer generated prose is not. You should be able
to explain the change in your own words, in the PR body and in
replies to review. This rule is not ours — it is BurntSushi's
`AI_POLICY.md`, since copied into rustls, and he puts it best: "I'm
totally fine with coding via AI. I just don't want to be talking with
one when I expect to be speaking with a human."

If you want to quote an agent's output, put it in a `>` block, say
that's what it is, and add your own reading of it.

## What we don't do

Every item here appeared in this repo's own history and was dropped
for a reason. This is a guide for writing, not a detector for
rejecting people — surface style is a poor proxy for effort, and
penalising it hits non-native English speakers and anyone using a
translation tool hardest. Judge whether a contributor can explain
their change, not whether their prose pattern-matches.

- **Section scaffolding.** `## Summary` / `## Changes` / `## Test
  plan` / `## Notes` on a change that fits in a paragraph. Thirteen
  early PRs did this; the later ones don't, and they read better.
- **Checkbox test plans.** `#31` merged with three boxes unticked.
  Boxes invite that. Say what you ran, in past tense, in a sentence.
- **Emoji as status markers.** ✅ / ⏸️ / ⏭️ instead of a clause.
- **Restating the diff in prose.** GitHub renders the diff already.
- **Tables summarising other PRs.** Link them.
- **Copying BUILDING.md into a PR body.** Link the section.
- **Adjective inflation.** "Comprehensive", "robust", "seamless",
  "dramatically" standing in for a fact. If the number is good, give
  the number. Comparative and scoped uses are fine — bunnie's
  "slightly less hardened than your typical key" says something.
- **Length as evidence of effort.** Median PR body here was 4,292
  characters through `#34` and is 463 since `#49`, for changes of
  comparable weight. The short ones are the better ones. Upstream
  in xous-core, bunnie's median merged-PR body is 161 characters.

## Review and branches

PRs target `dev`. `main` moves only by release merge, so a `Closes
#N` on a `dev` PR won't shut the issue until that release lands —
that is expected, not a bug.

CI must be green before merge, `rustfmt` included; it runs under
nightly, matching `rustfmt.toml`. See [BUILDING.md](BUILDING.md) for
the build.
