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
