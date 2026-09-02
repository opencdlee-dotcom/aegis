# Aegis → full-suite roadmap ("Norton parity")

Decided 2026-09-01 by the operator: expand Aegis from a detect-only monitor to a
full protection suite, with automatic response, plus companion tools for the
suite features that don't belong inside a monitor. This document is the map;
each phase is a separate build with its own tests, simbody diff, and PR.

## The one doctrine change, stated plainly

ARCHITECTURE.md's standing invariant is "nothing fires automatically from a
heuristic." This roadmap amends it — deliberately, by operator decision, not by
drift — to the tiered form Norton itself uses:

| Evidence class | Norton behavior | Aegis behavior after Phase 1 |
|---|---|---|
| Deterministic (known-bad hash, XProtect match, attack-defined trigger: cleared latch, decoy read) | auto-quarantine | **auto-quarantine** (transactional, restorable, witnessed) |
| Heuristic (behavioral, entropy, lineage, risk score) | SONAR: reputation + prompt | **auto-freeze** (reversible, fail-open) + alert; quarantine stays human-approved |

Rationale: Aegis's measured history is 314 detections, 0 true positives, 130
benign-positives. Auto-quarantine on heuristics would have destroyed 130
workflows; auto-quarantine on deterministic evidence would have fired zero
false times. Freeze is the reversible verb the architecture already built for
exactly this: being wrong costs one `thaw`.

Every automatic action leaves an `actions.jsonl` record and a notary anchor —
an automatic action with no witness is the violation, not the action itself.

## Phase 0 — menu bar restored (DONE 2026-09-01)

xbar relaunched, added to login items. Plugin `menubar/aegis-status.30s.py`
unchanged.

## Phase 1 — Auto-Protect tier

The heart of Norton parity. Three stages, strictly in order:

1. **Shadow mode (SHIPPED 2026-09-01).** New `autoprotect` state (off → shadow → live). In shadow,
   every detection that *would* auto-act writes a `would_quarantine` /
   `would_freeze` line to `actions.jsonl` with the evidence class that
   licensed it. Menu bar shows the shadow tally. Exit criterion: ≥7 days or
   ≥50 scans with the operator reviewing the would-have log — the same
   shadow-first rollout ARCHITECTURE.md's power-tier gate prescribes for ES.
2. **Live, deterministic tier.** Auto-quarantine fires only on the
   deterministic evidence class. Uses the existing transactional quarantine
   store (protected-path refusals intact), notifies via menu bar + report, and
   prints the one-line restore command in the alert itself.
3. **Live, heuristic tier.** Behavioral detections auto-`freeze` the process
   tree (existing machinery: root-first suspend, ancestor/other-user guards,
   auto-release fail-open) and open an incident for the human verdict.

Enablement is an operator action behind the existing one-time-code channel
(automation must not be able to switch Aegis to auto mode — the same reasoning
as `unlatch`). ARCHITECTURE.md gets the amended invariant in the same PR.

## Phase 2 — Signature engine ("LiveUpdate")

Largely pre-existed as the `intel` tier (found during the Phase 1 build):
abuse.ch MalwareBazaar + ThreatFox hash/C2 feeds via by-hand `intel update`,
graded offline every scan against hashes the scan already computes —
LiveUpdate without a phone-home — and the XProtect corpus harvested
separately. What was actually missing:

- **Operator-supplied IOCs (SHIPPED 2026-09-01):** `aegis.py intel import
  <file>` — one sha256 or ip:port per line, optional family name — merged
  into the same local store; no network; operator meta wins over feed meta.
  An `intel:hash:`/`intel:net:` match is deterministic evidence → Phase 1.
- Remaining: hash new/changed executables the watch surfaces beyond what
  scans already hash today.

## Phase 3 — Real-time feed (eslogger)

- Root helper wraps Apple's `eslogger` (entitled ES client, NOTIFY-only) and
  streams exec/file/persistence events into the event store — real-time
  detection latency instead of poll latency. Blocking stays impossible without
  a notarized system extension; that remains out of scope per the power-tier
  gate.
- Falls back cleanly to the current kqueue/poll watch when the helper isn't
  installed (Linux/Windows keep inotify / short-cycle poll).

## Phase 4 — Network watch ("Smart Firewall" analog)

- Monitor macOS ALF and pf state; alert on firewall disabled/rules changed.
- Outbound-connection inventory keyed on subject identity (already built),
  baseline + alert on new listeners and beacon-like patterns.
- No packet blocking (needs a Network Extension); a confirmed-bad endpoint
  alert includes the one-paste pf rule for the human to apply.

## Phase 5 — Privacy watch ("SafeCam" analog)

- Detect camera/microphone activation via the unified log and TCC state,
  correlated to process identity; alert on use by a process outside the
  operator's tolerated set. Detect-and-alert (blocking would need entitlement).

## Phase 6 — Companion suite (separate tools, NOT in aegis.py)

The cloud-service half of Norton 360, done the local-first way. Each is its own
small tool that Aegis's report/menu bar surfaces:

- **Backup** (Norton Cloud Backup): don't reinvent backup — monitor Time
  Machine: last-success age, destination reachability, verification; a stale
  backup is a MEDIUM incident. Optional restic wrapper later if off-machine
  copies are wanted.
- **VPN** (Norton Secure VPN): Tailscale is already fleet infrastructure.
  Watch its state; alert when on an unknown Wi-Fi network with the tunnel
  down.
- **Passwords** (Norton Password Manager): building a password manager is a
  liability, not a feature — instead a Keychain hygiene auditor: weak/reused
  password flags via `security` CLI where readable, plus an opt-in, manual,
  k-anonymity HIBP range check (explicit command, never automatic — same
  posture as `vt`).
- **Dark-web monitoring**: inherently a cloud subscription; the HIBP breach
  check above is the local-first stand-in. Anything more is explicitly out of
  scope.

## Phase 7 — Menu bar as control surface

Dropdown grows verbs: Scan now, Open latest report, Auto-Protect state (with
shadow tally), last auto-action + its restore command, thaw/restore shortcuts.
The plugin stays read-only; verbs shell out to `aegis.py` so every gate
(one-time codes, protected paths) still applies.

## Cross-cutting rules for every phase

- stdlib-only, single-file `aegis.py` for the monitor; companions are their
  own small files. Local-only: no telemetry, no automatic network.
- Full pytest suite + `SIM_BODY=win` simbody diff against merge base before
  any push; Windows legs (Defender harvest, Task Scheduler, deny-write ACE)
  ship in the same phase, not "later".
- Every new surface answers "what did you measure and when" (state-vs-events
  lesson, PR #17); every summary asserts against its source.

## Order and sizing

1 → 2 are the value core and unlock each other (signatures give tier-1 its
teeth). 3 is the biggest latency win. 4–5 widen coverage. 6 is parallelizable
any time. 7 lands last so the menu bar exposes finished verbs, not stubs.
