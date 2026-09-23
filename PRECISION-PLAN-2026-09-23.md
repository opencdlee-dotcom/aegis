# Precision plan — why Aegis cannot tell the operator from an attacker, and the fix that ends the batches

Written 2026-09-23 against main at `49e38b3` and the live store in `~/.aegis`.
Roles: Fable plans, scores and verifies; an Opus builder executes one step per worktree.

## The numbers this plan is built on (live store, last 30 days)

| measure | value |
|---|---|
| incidents closed as noise (FALSE_POSITIVE) | 233 |
| incidents open, all noise | 5 |
| true positives, lifetime | 0 of 538 |
| closed-noise interrupts that were HIGH with **no provenance rung** | 190 of 200 |
| hand verdicts given by the operator | 72, across 45 classes |
| new incidents opened in a class the operator had **already judged** | 109 |
| HIGH interrupts caused by one codesign misread (Zoom + Zotero "broken") | 36 |
| events on Spotify labelled `unsigned` while codesign says Developer ID | 314 (09-20 to 09-23) |

Six false-alarm batches since 2026-08-20 each fixed four to eight mechanisms and each was followed by another batch. The
batches were correct and they did not converge, because every one of them worked *downstream* of three structural defects.

## The three core defects

**1. Provenance is asked last and can only whisper.** Every sensor fires on an attribute the operator's own work shares
with malware: ad-hoc signature in `$HOME` (every build product), a new listener port (Spotify picks one per launch), a
long-lived connection from a Developer ID binary under `$HOME` (the beacon rule is `suspicious_sig OR risky_location`,
the only sensor with an OR), `eval … $(` in argv (every command Claude Code runs). The custody ladder that could explain
the artifact runs *after* the finding exists, may only demote one step, and never suppresses. Measured result: 190 of
200 closed-noise interrupts carried no rung at all. The ladder exists; the interrupts never meet it.

**2. Teaching evaporates.** A benign-positive verdict is keyed on `process:<path>:<trust>`. The operator's artifacts are
reborn under a new sha (every build), a new path (`bin.2.337.0`, a new worktree, a new App Translocation id) and so the
verdict covers nothing the operator meant. 72 verdicts, 109 re-fires in the same class. The two widest classes are the
operator's own LaunchAgents (60 re-fires) and the Zotero fork he builds (27).

**3. There is no ground truth, so every fix is measured by silence.** The 1,900-test suite is synthetic and has never
found one of these defects; the live queue found all of them. The 233 labelled incidents and 3,747 recorded findings are
an unused corpus. "The queue got shorter" is also what broken detection looks like.

Beneath these, one parser defect is worth naming on its own because it explains four of the five open incidents:
`_classify_mac` (aegis.py ~2696) turns *any* non-zero `codesign --verify --strict` into `broken`. The message on Zoom and
Zotero today is "resource fork, Finder information, or similar detritus not allowed" — Finder xattrs inside the bundle,
a valid Developer ID chain, an intact seal. A real tamper reads "code or signature have been modified" or "a sealed
resource is missing or invalid". `broken` is in `suspicious_sig`, so a valid signature became HIGH 36 times.

## Done-condition and verification (fixed before any code)

**Done** when, on this Mac, all four hold at the tip that ships:

1. `aegis.py backtest replay --days 30` re-routes the recorded findings of every incident the operator closed as noise
   and opens **0** interrupts from them. (Residual must be listed by incident id with a one-line reason each.)
2. The same command runs the 21 assay lanes and every attack fixture through the identical path and **all still
   interrupt** — precision may never be bought with recall.
3. The full suite is green (`python3 -m pytest tests/ -q`, background, 10 min) and the simulated-Windows diff against the
   merge base adds no failures (`PYTHONPATH=tests SIM_BODY=win python3 -m pytest tests/ -q -p simbody`, background).
4. After `aegis.py install watch` and one live scan cycle, the five open incidents are closed by the mechanism that
   explains them (not by hand), and 48 hours of live operation open no new noise incident.

**Pass cap**: six build-verify passes on Phase 2/3 combined. If the cap is hit, the residual is reported, not hidden.

Fable runs every verification personally and reads the output; a builder's "tests pass" is a claim, not a result.

## Phase 0 — the ground-truth harness (S0)

`aegis.py backtest replay [--days N] [--reobserve]`: build an in-memory store, load the recorded findings (events with
`event_type='observation.finding'`, oldest first), run them through the live pipeline — `route_findings`,
`_apply_correlations`, `_accumulate_risk`, `_signal_decision` with the live tolerance memory — and print, per category:
would-interrupt count, and the ids of noise-labelled incidents that would re-open. With `--reobserve`, for every subject
still on disk, recompute `classify_signature` and the custody rung with the *current* code and patch them into the
finding before routing, so classifier and ladder fixes are scoreable, not only routing fixes. Then run the 21 assay lanes
and report recall. Rule 17: the command asserts its own counts against the store before printing them.

Baseline is recorded on main before Phase 1 lands. Every later step is a diff against that number.

## Phase 1 — the four defects that are wrong today (S1–S4, independent, parallel)

- **S1 codesign parser.** Distinguish the verify failure classes. Detritus/xattr complaints with a valid authority chain
  keep the chain's trust (developer-id / apple / app-store). "modified", "sealed resource missing or invalid", "invalid
  signature" stay `broken`. Test against the real tool on this body (gate on `sys.platform == "darwin"` and the app
  being present), plus a fixture for the CI legs. Memory: a fixture cannot test a parser.
- **S2 behavior wrapper.** The agent harness runs `bash -c "source <snapshot>; eval '<CMD>'"`. Strip the harness wrapper
  and judge `<CMD>`. A hostile `<CMD>` (curl piped to sh, base64 decode+exec, osascript phish) still fires at full
  severity; a `while … $(gh pr checks …)` loop does not. Not a blanket trust of agent hosts — a prompt-injected agent
  running `curl | bash` is exactly what the sensor is for.
- **S3 chain legs.** `_entities` says an interpreter never joins, but `/bin/bash` was the *primary* entity of the
  os-program-update finding, so an Apple OS update joined a harness eval into "persistence followed by execution". A
  finding whose custody is in the self or vouched tier cannot be a chain leg; an interpreter cannot be the shared entity
  from either side.
- **S4 listener identity.** A listener's identity is the program's content, not `(program, port)`; ports are evidence on
  one case. Spotify's per-launch port must not be a new signal each time. Ephemeral-range ports already fold to
  `#ephemeral`; the fixed port and the helper binary still minted separate signals that fed risk accumulation.

## Phase 2 — provenance becomes a gate (S5)

One decision, consulted before interrupt, for every sensor that names a binary:

- **Reach**: wire `publisher-stable` so a Developer ID or App Store signature with a valid chain earns it on *first*
  sight, not only on re-sign-in-place (the docstring at ~2742 already records it was structurally unreachable). Wire
  `_grade_binary` into the emitters that still pass nothing (behavior, agent-surface where the subject is a binary).
- **Gate**: in `route_findings`, a finding below CRITICAL that is not attack-defined and whose custody is in
  `_SELF_CUSTODY` or `_VOUCHED_CUSTODY` routes to digest, never interrupt. Weak rungs (`build-output`, `supervised`,
  `copy-of-graded`) still demote one step, as today. The risk tier already weights these 0 and 0.25.
- **Invariant kept**: attack-defined evidence keeps its severity under perfect custody. A vouched binary running an
  osascript password prompt is still CRITICAL. Origin is not innocence; this gate only removes *attribute-only*
  findings on binaries whose origin is proven.

## Phase 3 — verdicts teach at class width (S6, S7)

- **S6 class tolerance.** `_signal_decision` already tries three candidates per finding (identity, endpoint class,
  producer class). Add the classes the ladder can *verify*: signer team id (`8LAYR367YV` is Zotero wherever it runs),
  package receipt, build-output repo, supervisor (vouched parent). A benign-positive on a finding that carries a class
  records tolerance for the class. Threshold 1 for cryptographically anchored classes (team id, package receipt), 3 for
  content-derived ones (build-output, supervisor). `incident <id> benign-positive` prints what it learned:
  `Learned: anything signed by team 8LAYR367YV (Zotero) — wherever it runs`. `families` shows the class it will teach.
  Read PR #51 first (tolerance-follows-bytes); absorb or supersede, never duplicate.
- **S7 own LaunchAgents.** Use the harness to run `_custody_persistence` over the 60 re-fires and find why the
  self-committed rung never reached a `com.charlie.*` plist whose payload is in the operator's repo. Fix what the
  numbers show, not what the docstring says.

## Phase 4 — the loop stays closed (S8)

`aegis.py report` and the weekly digest print three lines from the harness: precision on the trailing 30 days, assay
recall, and teaching evaporation (incidents opened in an already-judged class). A rise in the third, or a drop in the
second, opens an incident against `self-protection`. The number the operator sees is the number the loop is judged on.

## Ownership and mechanics

- Each step: one builder, own worktree (`AIKIT_AGENT=precision-sN uv run ~/Ai/Universe/tools/aikit/worktree.py enter`),
  tests first where the I/O is testable, one PR. Builder reports actual command output, never "should work".
- Fable verifies each PR: harness diff against baseline, suite, simbody, then a live scan on this Mac after install.
- Parked for the human: PRs #49 and #50 (Codex, 2026-09-20) overlap Phase 2/3 in intent; they are not merged or
  rebased by this plan. Their fate is the operator's call after Phase 1 lands.

## Assumptions stated

- The `events` table holds enough of each finding (`path`, `trust`, `sha`, `custody`, `ancestry`, `argv preview`) to
  re-route it. Checked on the five open incidents; S0 asserts it over the corpus and reports any field it lacks.
- The Zoom and Zotero detritus complaint is Finder xattrs, not a modified bundle. Both binaries print a TeamIdentifier
  and a full Developer ID chain today. S1 verifies with `codesign --verify` (no `--strict`) as the discriminator.
- Spotify's `unsigned` run was the non-answer-as-verdict defect PR #52 fixed; no `unsigned` event since the 08:09
  restart today. S0's `--reobserve` will confirm rather than assume.
