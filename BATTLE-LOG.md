# Aegis — Battle-Test Log (2026-07-16, pass 3 — residual-gap-detectors branch)

Inline adversarial probe of the surfaces added this session (event-driven kqueue
watch + live `log stream` tail, hot-dir `.app`/notarization, network listeners,
BTM/Login-Items, opt-in VirusTotal). Every oracle derived from README/docstring
intent; each finding proven fail-before/pass-after against the committed baseline
before it was trusted; no live notification, launchd load, VT network call, or
write outside a per-test tmp dir fired. Suite: `selftest` 3/3,
`tests/test_regression.py` **148/148**.

## Outcome (pass 3)

**4 genuine defects fixed** (1 HIGH detection-evasion, 1 MEDIUM staleness-evasion,
1 HIGH live alert-storm, 1 HIGH self-protection blind-spot — the last two found
only by an on-machine end-to-end run), each pinned; plus 1 real-state
test-pollution bug caught and fixed in-pass; plus a live-installation repair.

| # | Sev | Where | Defect (vs intent) | Evidence | Fix |
|---|-----|-------|--------------------|----------|-----|
| P3-1 | **HIGH** | `_bundle_executable` | `CFBundleExecutable` is attacker-authored plist data. A value with a path separator (`/bin/sh`, `../../x`) makes `os.path.join(app,'Contents/MacOS',name)` **escape the bundle** — `join` discards everything before an absolute component — so Aegis would classify a *clean Apple binary out-of-bundle* instead of the ad-hoc payload, silently downgrading a HIGH `.app` finding to nothing. | Probed the committed `5b95c2c` `_bundle_executable` with a `/bin/sh` name → resolved outside the bundle. | Reject any `CFBundleExecutable` containing `/`; a legit value is always a bare filename. Post-fix → `None` (no finding suppression). Pinned. |
| P3-2 | **MEDIUM** | `_check_hot_app` | Bundle freshness keyed on the `.app` **root** mtime only. Swapping a fresh payload into an *existing old* bundle's `Contents/MacOS` never touches the root mtime → a re-weaponized old app ages out of the hot window and is never scored. | A 60-day-old bundle root with a freshly-written exe → no finding pre-fix. | Freshness = `max(root_mtime, exe_mtime)`; a fresh exe in an old bundle still flags HIGH, a fully-old bundle still ages out. Both pinned. |
| P3-3 | **MEDIUM** | `TestVTReputation` (test) | A new VT test wrote a key to the **real** `~/.aegis/vt_key` (the sandbox overrode `STATE_DIR` but not `VT_KEY_FILE`), polluting real host state — the suite's own "never touch real `~/.aegis`" invariant. | Real `~/.aegis/vt_key` (11 bytes) appeared after a run. | Sandbox now overrides `VT_KEY_FILE`; the stray file was removed. Guards the invariant that would otherwise let any future key-path test leak. |
| P3-4 | **HIGH** | `snapshot_btm` / `snapshot_listeners` / `_scan_surfaces` | `sfltool dumpbtm` is SLOW (~12s; observed **wedged >60s** under load on this machine) and its 15s `run` timeout returned empty → `snapshot_btm` recorded `{}` = "no background items." A Mac always has ~90 (DisplayLink, auto-updaters…), so the **false-empty was adopted into the live baseline**, and the instant sfltool next succeeded the diff would fire **~95 bogus `New background item` findings — a real alert storm on the user's own installed monitor**, violating the storm-free invariant (same class as the pass-1 corrupt-baseline fix). | Live on-machine `aegis.py scan`: baseline recorded `btm: {}` while `snapshot_btm()` returned 95 real items; a `{}`→95 diff = 95 findings (reproduced in `test_none_snapshot_is_not_adopted_and_does_not_storm`). | A fallible snapshot now returns **`None` (non-answer)** on timeout/hard-failure vs `{}` (genuine empty); `_scan_surfaces`/`cmd_baseline` **skip** a `None` surface — never adopt it, never diff against it. sfltool timeout raised 15→30s; the live poisoned `btm` baseline key was healed. 3 tests pinned. |
| P3-5 | **HIGH** | `check_self_protection` | Self-protection detected the agent being *removed* but not present-but-**broken**. The live machine's own plist was invalid XML — a raw `&` from the `…/Work & Projects/…` install path (the pass-1 **F0** bug, in a plist generated *before* F0 was fixed). launchd keeps running a previously-loaded copy so the monitor *looks* alive, but on the next reboot/reload it silently refuses the bad plist and the monitor **dies with no signal** — a security tool rotting itself into non-execution. | `plutil -lint ~/Library/LaunchAgents/com.charlie.aegis.plist` → "unknown ampersand-escape sequence at line 9"; launchctl last-exit status was `2`. | Self-check now `plistlib.load`s its own plist when present → HIGH `self:agent:malformed` while it is still limping and fixable. **Live repair:** regenerated the plist via the F0-fixed `install.sh` → `plutil -lint: OK`, running PID, exit 0, baseline preserved. 2 tests pinned. |

## Saturated (survived attack, no fix needed)

- lsof listener parser fuzzed with 8 malformed inputs (empty ports, bare `:::`,
  truncated records, NUL/high bytes) → never raises; a `:`-in-path key still
  round-trips the port correctly.
- BTM parser on garbage / header-only / embedded-only input → never raises,
  never mis-emits an embedded sub-ref as a top-level item.
- `vt` with no key → refuses, **zero** network calls; with a stubbed transport
  the request carries only the sha256 + key header (file bytes never leave host).
- kqueue watch + `EVFILT_READ` stream fd: wakes within seconds on a real write /
  real pipe data, times out quietly otherwise, drains fully (no busy-spin), tail
  respawns if it dies.

---

# Aegis — Battle-Test Log (2026-07-15, pass 2 — residual-gap-detectors branch)

Second `/battle-test` pass (fable-mode gates) targeting **only the new surfaces**
added on `feat/residual-gap-detectors` (behavioral argv tier, XProtect harvest,
shell-history, staging, wallet, canary, IDE-ext, vendor-label impersonation) — the
older code was saturated in pass 1. **Tier: standard.** Subagent hunters were
gated (Opus classifier down), so hunting ran inline: sandboxed reproducers, every
oracle derived from README/docstring intent, each finding proven with captured
tool output before it was trusted. No live notification, launchd load, or write
outside a per-test tmp dir ever fired; real `~/.aegis` mtime unchanged across the
whole pass.

## Outcome (pass 2)

**3 genuine defects fixed** (1 HIGH detection-evasion, 1 MEDIUM alert-fatigue,
1 HIGH spec/code contradiction), each pinned by a permanent regression test. Test
state: `selftest.py` 3/3, `tests/test_regression.py` **89/89** (86 + 3 new).

| # | Sev | Where | Defect (vs stated intent) | Evidence | Fix |
|---|-----|-------|---------------------------|----------|-----|
| P2-1 | **HIGH** | `check_behavior` | Self-exclusion was a substring test (`"aegis" in argv` / `"aegis " in argv`). Aegis is open-source, so an attacker reading the check evades the **flagship CRITICAL password-phish detection** by putting the word "aegis" anywhere in argv (e.g. a dialog reading *"System aegis needs your password"*). | Repro: that exact phish argv → `check_behavior()` returned `[]` (no alert); the identical phish without "aegis" → CRITICAL. | Exclude self by the **unspoofable real PID** (`pid == os.getpid()`), not an argv substring. Post-fix the "aegis"-laden phish scores CRITICAL. |
| P2-2 | **MEDIUM** | `check_shell_history` | Every hostile-idiom match was hard-coded **HIGH**, so a lone everyday `curl https://…` (no pipe-to-shell) in history fired a HIGH desktop notification — an "alert rarely" violation the live-process tier explicitly avoids by gating lone fetch to a fetch+exec combo. | Repro: history with one benign `curl -fsSL https://…` → `[HIGH] shell-history`. | Score via the **same `_argv_signals` oracle** as the behavioral tier: lone fetch → MEDIUM (logged, below notify floor); `curl…\|sh`, `dscl -authonly`, reverse shell → still HIGH+. Post-fix the benign curl is MEDIUM. |
| P2-3 | **HIGH** | `emit` / `cmd_scan` | README (lines 41–44) promises shell-history is "adopted silently **per-surface**… so upgrading Aegis is storm-free." But suppression keyed on **global `first_run`** only; shell-history isn't a baseline surface, so on an **upgrade** (baseline already exists) months-old `curl\|sh` residue alerts as if live — the documented guarantee was false. | Code: `suppressed = first_run and category in (...)`; no per-surface adoption for the live history check. | Add a `shell_history_adopted` baseline marker; the first scan on an upgrade adopts existing residue silently (logged, not notified) and records the marker; new hostile lines thereafter alert. |

## Not fixed (residual)

- `check_behavior` ps parsing (`line.split(None, 3)`) garbles the reported
  `program`/`pid` fields when a process's exec path contains spaces
  (`/Users/Shared/My App/run`). Detection still **fires** (the fetch/exec idiom is
  matched in the argv tail regardless), so this is a cosmetic misattribution in the
  finding detail, not a missed threat — left un-fixed to avoid over-fitting `ps`
  column parsing. Interpreter binaries (bash/osascript/curl), which front every
  hostile chain, have space-free paths, so the common case is unaffected.
- Probed and **saturated** (survived attack): XProtect malformed-ndjson / non-JSON
  `eventMessage` parsing (no raise, still catches the real detection), vendor-label
  impersonation on an Apple-signed backing binary (HIGH), fish-format history,
  canary modify/delete, staging mtime-fingerprint stability (dedups, no re-alert).

---

# Aegis — Battle-Test Log (2026-07-13)

Adversarial hardening pass under `/battle-test` (fable-mode gates + delegated
hunters). **Tier: standard** (blast-radius × complexity × reversibility → a real
module with local state and no live irreversible effect during test). Framing
held throughout: *surface failures honestly; captured stdout + exit code is the
only evidence.* Every oracle was derived from the README/docstring intent (never
from the code under test) and mutation-validated before it was trusted.

## Outcome

**11 genuine defects fixed** (2 CRITICAL, 4 HIGH, 4 MEDIUM, 1 LOW) across
`aegis.py` + `install.sh`, each pinned by a permanent regression test.
**1 proposed change was rejected** because it removed a detection gate. Test
state after the pass: `selftest.py` 7/7, `tests/test_regression.py` 21/21, a
full sandboxed CLI drive scored a planted `bash -c "curl|sh"` launchd item HIGH
end-to-end. No live notification, launchd load, or write outside the sandbox ever
fired; real `~/.aegis` untouched (mtime predates the session).

## Side-effect safety (how the loop stayed inert)

- All aegis state paths + `PERSISTENCE_DIRS`/`HOT_DIRS` redirected to a per-test
  tmp dir; `notify` replaced by a recording spy (asserts both fire-and no-fire).
- `install.sh` exercised with `$HOME` redirected and `launchctl` **stubbed** — no
  real agent was ever loaded; the generated plist was validated with `plutil`.
- Guard self-test (playbook §5): a scan that *should* notify must hit the spy; an
  unchanged re-scan must not. Both asserted.

## Findings (fixed)

| # | Sev | Where | Defect (vs stated intent) | Evidence | Fix |
|---|-----|-------|---------------------------|----------|-----|
| F0 | **CRITICAL** | `install.sh` | Repo path interpolated into plist XML unescaped; a path with `&` (e.g. `…/Work & Projects/…`) makes the plist invalid XML → launchd silently refuses to load → **the whole tool never runs on schedule**. | `plutil -lint` FAILED ("unknown ampersand-escape sequence, line 9") on the generated plist. | XML-escape `&<>` in all interpolated paths; `plutil -lint` now `OK`, `&`→`&amp;`. |
| F1 | **CRITICAL** | `_persistence_severity` | A signed interpreter + hostile payload (`bash -c "curl\|sh"`, `osascript -e …`) scored **LOW** → below the HIGH notify floor → the #1 AMOS/Poseidon launchd pattern the README claims to catch never alerts. | `check_persistence` on synthetic snapshots returned LOW; end-to-end scan #2 now scores it **HIGH**. | New `_hostile_args` escalates interpreter-with-inline-script and network-fetch args to HIGH/CRITICAL, independent of the binary's own signature. |
| F2 | **CRITICAL** | `cmd_scan` | A **corrupt** `baseline.json` collapsed to the same `None` as *no baseline* → `first_run=True` → current state (incl. freshly-planted persistence) silently re-recorded as known-good, **erasing tamper evidence**. | Scan → plant adhoc LaunchAgent + truncate baseline → re-scan was silent. | `load_baseline()` distinguishes missing from corrupt; on corrupt it refuses to re-baseline, raises a HIGH `integrity:baseline:corrupt` finding, and re-evaluates all persistence as new. |
| F3 | **HIGH** | `emit` | First-run silence was applied to **all** categories, so a payload already in a hot dir / a suspicious process / a weak hardening setting present at install was added to `seen` and **never alerted, ever**. | Adhoc binary in a hot dir before first scan → never notified on any later scan. | Scope the first-run silence to `category=="persistence"` only (the KnockKnock "trust what's installed" rule); live threats notify on first sight. |
| F4 | **HIGH** | `check_hot_dirs` / `check_processes` | Fingerprint was `path+trust` with no content hash, so `allow <path>` for a benign binary silently covered **any different malicious binary** later reusing that path. | Allow a path → swap in a different adhoc binary (new sha256) at the same path → no alert. | Fold `sha256` into hot-dir/process fingerprints; a different binary at a reused path is a new finding. |
| F5 | **HIGH** | `TRUSTED_PREFIXES` / `is_risky_location` | Bare `/usr/` was trusted, so `/usr/local/*` (Homebrew, **not** SIP-protected, group-writable) processes were never signature-checked at all. | `is_risky_location('/usr/local/bin/evil')==False`; classifier never invoked on a `/usr/local` process. | Narrow `/usr/` to its SIP subpaths; add `/usr/local` to `RISKY_PREFIXES`. |
| F6 | **MEDIUM** | `RISKY_PREFIXES` | `/var/folders` was risky but `/private/var/folders` (its canonical form — `/var`→`/private/var` symlink) was not. | `is_risky_location('/private/var/folders/…')==False`. | Add `/private/var/folders` alongside `/var/folders` (and to the CRITICAL-escalation tuple). |
| F7 | **MEDIUM** | `classify_signature` cache | Key `(path, int(mtime), size)` is content-blind on same-second same-size replacement → serves a stale signature classification. | Same-second, same-size content swap returned the cached (wrong) result. | Cache per-path with `st_mtime_ns`+size stored as a field; content change invalidates. |
| F8 | **MEDIUM** | sigcache eviction | Eviction was insertion-order, and composite keys orphaned a stale entry on every binary rebuild → cache churn / an hourly-hit path could evict before a dead one-off. | 5200-entry cache trimmed the always-hit entry, kept a dead one; updated binary left an orphan. | Per-path keying (one entry/path, rebuild overwrites) + LRU touch on hit → the insertion-order trim becomes true LRU. |
| F9 | **MEDIUM** | `emit` / `seen.json` | `seen.json` had no cap (unlike `sigcache.json`) yet is fully read+rewritten every scan → unbounded growth for an hourly-forever tool. | 50 churning scans → linear growth, no compaction. | `_cap_seen` bounds it to the newest `SEEN_MAX` fingerprints; `findings.jsonl` remains the durable record. |
| F10 | **LOW** | `check_hardening` | `launchctl print-disabled system` result computed and never used — a wasted subprocess every scan forever. | Source: assigned `out`, only `lout` read. | Removed the dead call (-1 subprocess/scan). |
| F11 | **MEDIUM** | `install.sh` | Re-running to change the interval unconditionally re-baselined → blessed any persistence added since first install. | Script flow: unconditional `baseline` on every run. | Baseline only when none exists (after the agent plist is written); interval change preserves known-good. |

## Rejected (would remove a safety gate)

- **"Skip `codesign --verify --strict` for apple/developer-id trust"** (proposed as
  a ~7.8s cold-scan speedup). **Rejected — verified it creates a false negative.**
  Appending 4 bytes to a copy of `/bin/ls`: `codesign -dv` still reports
  `Authority=Software Signing` (classifies `apple`), but `codesign --verify
  --strict` → *"main executable failed strict validation"*. The verify pass is the
  **only** thing that catches a tampered Apple/dev-id binary (sets `trust=broken`).
  The cost is a bursty, cached, self-healing cold-scan artifact (steady state
  ~90 ms/scan; warm scans make **zero** codesign calls). A genuine improvement may
  never remove a detection gate.

## Stop-gate (why the loop ended)

Composite gate met: oracles mutation-validated · major surfaces saturated by both
hunters (persistence diff+severity, signature classify+cache, hot-dir, process,
location partitions, emit/seen/allowlist state machine, install) · a dry
re-verification round after fixes (scan #3 found nothing new; 21/21 regression +
7/7 selftest green) · well under the 4-round standard-tier cap.

## Residual risk / notes

- The `curl|wget http…` arg heuristic (F1) is high-precision but could in
  principle flag a legit auto-updater that shells out to `curl` from a *new*
  launchd agent; such items are baselined and allowlistable, and a raw fetch in
  `ProgramArguments` is itself unusual. The broader "script in a dotdir" signal
  was **deliberately dropped** to avoid false HIGHs on `~/.local`/`~/.cargo`/… —
  "alert rarely" wins; the trade-off is that a signed interpreter running a
  *hidden-dir script with no inline flag and no fetch* is not escalated.
- `check_cron` edge cases and the `os.listdir` >2000-entry slice were left
  un-hunted (noted low-yield by the hunter), not cleared.
- Not covered by battle-test: whether the ESF/blocking ceiling described in the
  README changes — out of scope (detection tool only).
