# Aegis — Battle-Test Log (2026-08-21, `/battle-test` siege — 6 fixes, delegated 4-lens hunt)

Full repository siege under the fable-mode gates. Aegis has manually invoked
quarantine, neutralize, kill, freeze and irreversible destroy paths, so every
test used inert fixtures, temporary state, mocked process control, or the
repository's real-state pytest guard. No live scan, response action, install,
service change, notification, deployment, or network call ran.

## Outcome

**6 genuine defects fixed**: one malformed-input correctness bug, one silent
sensor-coverage loss, two measured repeated-I/O defects, one missing human
authorization boundary, and one authorization-audit omission found by the
mandatory Builder/Reviewer duel. Seven permanent regression tests were added.

Final captured gates:

- `pytest tests/ -q` → **968 passed, 4 skipped, 11 subtests passed** in 357.06s
  (baseline: 961 passed, 4 skipped, 11 subtests).
- `selftest.py` → **7/7 passed**.
- Python compile, `bash -n`, ShellCheck, and `git diff --check` → exit 0.
- Completeness pre-flight → **0 pass-only / ellipsis stubs**.
- Mandatory patch duel after the last fix → **two consecutive dry rounds**:
  5 passed + 7 subtests, then 47 passed + 7 subtests.
- Battle-log self-check → **PASS**: six finding rows, final/baseline test counts,
  both dry rounds, and the mutation/cross-OS limits are all published above or
  below; the numeric claims match the captured command output from this run.

## Findings fixed

| # | Sev | Defect | Reproducer / measured baseline | Fix |
|---|-----|--------|--------------------------------|-----|
| F1 | MEDIUM | `_beacon_parts` accepted malformed IP literals and ports outside 1–65535, allowing invalid endpoint evidence into rotating-beacon tolerance state. | Invalid IPv4 `999.999.999.999`, malformed IPv6 `12345::1` / `:`, and ports 0 / 65536 all parsed before the fix. The intent-derived `ipaddress` oracle rejected them and killed the permissive-parser mutation. | Validate with stdlib `ipaddress.ip_address()` and enforce port 1–65535 before generalizing. |
| F2 | HIGH | On macOS, failure of the second `ps` call (full argv) silently substituted the executable path while leaving process coverage healthy. Behavioral/session-theft sensors then lost their load-bearing input without a DEGRADED health record. | Inert split-`ps` fixture returned a valid executable row plus failed argv query; `_PROC_ARGV_PARTIAL` did not exist and health stayed complete. | Retain useful executable rows, reset a per-scan partial flag, and publish `process.argv` DEGRADED when argv enumeration fails. |
| F3 | LOW/PERF | Writ enforcement loaded `writs.json` once before its loop and again for every finding. | 100 findings → **101 reads**. | Split the pure snapshot check from the file-loading wrapper; `_apply_writ` now evaluates one loaded snapshot → **1 read**. |
| F4 | LOW/PERF | Intel grading called `_intel_sets()` once per candidate hash; even cache hits stat both feed files. | Two matching records → 2 set lookups; the 100-record reproducer implied 200 avoidable stats. | Load the hash set once in `check_intel` and pass it through the grading closure → **1 lookup per pass**. |
| F5 | HIGH | The CLI claimed response was human-reviewed and run by hand, but direct `quarantine`, `restore`, `destroy --yes`, `kill`, `freeze`, `thaw`, and `neutralize` dispatches had no interactive authorization boundary. A same-uid script could invoke them. | A refusal stub still reached every mutating `cmd_*` function. | Gate only the external dispatcher with the existing interactive challenge, bound to the exact verb and argument. Internal functions remain composable and sandbox-testable; `destroy --yes` remains an additional irreversible confirmation. |
| F6 | MEDIUM | F5's first fix discarded whether approval was out-of-band or merely `tty-only`, violating the architecture rule that the weaker channel must be recorded rather than overstated. | Inert duel captured a successful terminal action with no authorization-channel evidence. | Write a durable audit-before-mutation `response-auth` event for approval and refusal, including verb, argument, result, and exact channel. An unavailable audit log now fails an approval closed. |

Every regression was observed RED before production code changed and GREEN
afterward. The focused post-fix set was 7 tests; adjacent regression
neighborhoods were also exercised in both dry duel rounds.

## Four-lens evidence and stop gate

- **Correctness:** F1 reproduced and mutation-validated; no other candidate
  survived minimization.
- **Architecture / efficiency:** F2–F4 reproduced. The automated lexical scan
  produced 252 noisy flags; data-flow triage rejected all of them rather than
  inflating the finding count.
- **Security:** `watchdog` was unavailable, so the required inline sink and
  trust-boundary review ran. It found F5. No hardcoded live secrets, unsafe
  deserialization, executable `eval`/`exec`, or `shell=True` sink survived.
- **Adversarial duel:** the initial pass found F6. After its fix, two bounded
  consecutive rounds were dry, including fail-closed audit-write checks across
  all seven mutating dispatchers and exact argument/channel binding.

The composite stop gate was met on dry rounds, saturated affected regression
neighborhoods, and a fully green suite—not on the siege six-round hard cap.
There is **no repository-wide mutation harness**, so no numeric mutation score
is claimed; F1 used a targeted killed mutation and every fix has captured
fail-before evidence.

## End-state checklist

- [x] Bugs found → fixed and regression-pinned (F1, F2, F5, F6).
- [x] Logic / efficiency errors found → fixed and measured (F3, F4).
- [x] Edge cases found → permanent tests added.
- [x] No unimplemented pass-only / ellipsis stubs remain.
- [x] Security lens run (inline because the watchdog binary was unavailable).
- [x] Mandatory adversarial duel went dry twice after the final fix.

## Residual risk

- Windows and Linux kernel-specific live harnesses did not run on this macOS
  host; their CI coverage remains the cross-platform evidence.
- A same-uid attacker can allocate a pseudo-terminal and read an in-terminal
  challenge when no separate GUI/notification channel exists. Aegis now records
  that weaker condition honestly as `tty-only`; it is not equivalent to an
  out-of-band human channel.
- The existing PID-reuse interval between process identity verification and
  signaling remains a review candidate; this run did not produce a safe,
  reproducible proof, so it was not represented as fixed or cleared.

---

# Aegis — Battle-Test Log (2026-08-12, `/battle-test` siege — 6 fixes, delegated 4-lens hunt)

Full `/battle-test` run under fable-mode gates. **Tier: siege** (blast-radius ×
complexity × reversibility → a tool with irreversible response verbs: quarantine
/ neutralize / kill / destroy). Framing held throughout: *surface failures
honestly; captured stdout + exit code is the only evidence.* Every oracle was
derived from README/ARCHITECTURE intent (never from the code under test) and each
finding independently reproduced before it was trusted. No live launchctl load,
process kill, quarantine, or notification ever fired — the whole run was
synthetic inputs + sandboxed state.

## Outcome

**6 genuine defects fixed** (2 HIGH, 3 MEDIUM, 1 LOW/MED) across `aegis.py`, each
pinned by a permanent fail-before/pass-after regression test
(`tests/test_battle_20260812.py`, 21 cases). Test state after the pass:
**846 passed, 4 skipped** (825 baseline → +21 new), `selftest.py` 7/7. The 11
behavior-change assertions were confirmed to FAIL against the pre-fix `aegis.py`
(`git stash` + re-run) and pass after. **1 genuine improvement deferred** (F7,
below) as a dedicated pass rather than bundled. No detection gate was removed.

## Findings (fixed)

| # | Sev | Where | Defect (vs stated intent) | Evidence | Fix |
|---|-----|-------|---------------------------|----------|-----|
| F1 | **HIGH** | `_HOSTILE_ARGV_RES` osascript-password-phish (was aegis.py:794) | The single regex `\bosascript\b.{0,512}display dialog.{0,512}(?:hidden\|default) answer` bridges "display dialog" → the answer keyword across the **attacker-controlled dialog message**. Padding the message past ~510 chars makes a *fully-functional* AMOS password phish score **nothing at all** — README claims CRITICAL. | Reproduced: message len ≥520 → `_argv_signals` returns `[]`; short control → CRITICAL. Threshold is exactly the 512 regex cap. | Replaced the bridged regex with `_osascript_phish()` — three ordered, unbounded-distance, linear `.search` token checks (osascript → display dialog → hidden/default answer). No paddable bridge, no ReDoS. Round-2 spar re-attacked with 8 functional variants (padding/reorder/case/whitespace/flags/comments/unicode) → all still CRITICAL. |
| F2 | **HIGH** | `_SECRET_ASSIGN_RE` / `_SECRET_FLAG_RE` → `redact_sensitive` | `\b` before the keyword never fires next to `_` (underscore is `\w`), so `DB_PASSWORD=`, `API_TOKEN=`, `AWS_SECRET_KEY=` (the dominant env-var secret shape, exactly what a launchd `EnvironmentVariables`/MCP `env` block renders into a finding) were **persisted verbatim** — breaking the "redact before persistence" invariant. `_SECRET_FLAG_RE`'s `(\S+)` value also leaked the tail of a quoted multi-word secret. | `redact_sensitive("DB_PASSWORD=hunter2")` → unchanged; secret survived into `finding()['detail']`. | Treat `_` as a component separator: optional `_`-joined word components may precede/follow the keyword (bounded {0,8}×{1,40}), with `(?<![a-z0-9])`/`(?![a-z0-9])` custom boundaries so `secretary=`/`broken=`/`--token-count 5` stay unmatched (no over-redaction). Value group now consumes a `"…"`/`'…'` quoted run. Verified linear on pathological input. |
| F3 | **MEDIUM** | `_quarantine_item` / `cmd_restore` / `cmd_destroy` | `qid` from argv was unvalidated: `os.path.join(QUARANTINE_DIR, qid)` silently discards the store when `qid` is absolute (`/tmp/evil`) and `..` walks out. And `cmd_restore` renamed a payload to `txn["original_path"]` with **no `_is_protected_path` refusal** (unlike `cmd_quarantine`/`neutralize`) — an arbitrary-file-drop primitive for a forged/tampered txn. | Reproduced: absolute-`qid` override and `../` escape both resolve outside the store; `cmd_restore` had no protected-dest check. | (a) `_quarantine_item` refuses any qid that isn't a plain basename (the one choke point every store path flows through). (b) Added a `_is_protected_path(dest)` refusal in `cmd_restore` before the exclusive rename — symmetric to `cmd_quarantine` refusing protected sources, so it provably never blocks a legit restore (quarantined items always came from non-protected sources). |
| F4 | **MEDIUM** | `gui-kill-coercion` (two regexes) + `_KILL_LOOP_RE` | A `killall -0 X` **liveness probe** (signal 0 never terminates) inside a `while` loop was escalated **CRITICAL** identically to a real kill loop — the exact benign supervisor/relaunch pattern the README's carve-out says must not fire. | Reproduced: `while true; do killall -0 SystemUIServer …; done` → `gui-kill-loop-coercion CRITICAL`. | `(?!\s+-0\b)` negative lookahead on both `gui-kill-coercion` regexes and `_KILL_LOOP_RE` excludes signal-0. A coercion kill sends a real terminating signal, so real kill loops still score CRITICAL and `killall Dock` stays clean. |
| F5 | **MEDIUM** | `_linux_socket_inode_pids` (Linux) | The full `/proc` fd-table walk (list every pid, readlink every fd of every process — O(system-wide open fds)) ran **twice per scan**: once for listeners, once for outbound. No cache, unlike the sibling `_PROC_SNAPSHOT`. Hourly, forever. | Two call sites (`_snapshot_listeners_linux`, `_outbound_rows`) both invoke it; doubled syscall count code-verified. | Scan-scoped `_SOCKET_INODE_SNAPSHOT`, armed once in `gather_all` alongside `_PROC_SNAPSHOT`, cleared in the same `finally` — the established in-codebase idiom. Walk runs once/scan; None outside a scan (by-hand commands walk live). |
| F6 | **LOW/MED** | `_snapshot_listeners_windows` / `_outbound_rows` (Windows) | Identical `netstat -ano -p tcp` spawned **twice per scan** (listeners + outbound), same args, same timeout. | Two literal duplicate `run([...])` call sites. | Scan-scoped `_NETSTAT_SNAPSHOT` via a shared `_netstat_tcp_rows()` helper that caches the raw `(stdout, rc)` so each caller keeps its own rc interpretation. One spawn/scan. |

## Follow-up (`/doit`, same day) — the deferred item + the hardening note, done

Both items this run first deferred were then implemented under `/doit`, on the same
branch, each regression-pinned and fail-before-proven:

- **F7 (MEDIUM perf) — three macOS `log show` sensors now run concurrently.**
  `check_xprotect` / `check_security_log` / `check_amfid_log` each shell out to an
  independent 45s-cap `log show` over a disjoint predicate; run serially in the
  sensor loop they cost ~the sum of three I/O waits (**measured 4.80s**). Now
  prewarmed **concurrently** once per scan into a scan-scoped `_LOG_SHOW_CACHE`
  (the same arm-once/clear-in-`finally` idiom as F5/F6), which the three sensors
  read via a shared `_log_show(predicate)` — **measured 2.11s** (56% cut,
  byte-identical output). Concurrency reuses `run()` verbatim (all its path/env/
  timeout hardening), one thread per command; `run()` is stateless, so it is
  thread-safe. Predicates are named once (`_PRED_XPROTECT`/`_PRED_SYSPOLICY`/
  `_PRED_AMFID`) so the prewarm and the sensors can't drift. No predicate, parser,
  or severity changed — only *when* each subprocess starts. Pinned by
  `TestLogShowScanCache` (prewarm covers all three, sensors hit the cache and
  route by predicate, unarmed→live, argv byte-unchanged).
- **H1 (hardening) — `ld-so-preload-write` argv idiom is now quote-tolerant.**
  Round-2 spar noted the plain `ld\.so\.preload` literal is shell-quote-evadable
  (`/etc/ld.so.pre""load` writes the file while splitting the substring). The
  idiom now allows optional quote chars between every character
  (`"['\"]*".join(re.escape(c) for c in "ld.so.preload")`) — coverage strictly
  widens (a verbatim match still matches; benign text like `ldconfig` does not).
  Defense in depth on top of the persistence file sensor that already catches the
  write. Pinned by `TestLdSoPreloadQuoteTolerant`.

Test state after the follow-up: **853 passed, 4 skipped** (846 → +7 new regression
cases for F7/H1), `selftest.py` 7/7. Nothing now remains deferred from this siege.

## Side-effect safety (how the loop stayed inert)

- Every hunt lens ran on **synthetic in-memory records** (crafted argv, forged
  txns) or **sandboxed state** (per-test tmp `STATE_DIR`/`QUARANTINE_DIR`); no
  `_argv_signals`/redaction/quarantine call ever touched the real `~/.aegis`.
- **Guard self-test (F3):** the regression suite asserts the protected-path
  refusal actually FIRES (`cmd_restore` on a txn whose `original_path` is a
  protected path → refused, item stays sealed) and that qid confinement blocks
  `/tmp/evil` and `../escape`. The conftest real-state backstop (which fails any
  write aimed at real `~/.aegis`) was green the whole run.
- No `launchctl bootout`, `os.kill`, `shutil.rmtree`, or `notify` on a real
  target was ever executed.

## Stop-gate (why the loop ended)

Round 1 (4-lens delegated hunt — correctness, perf/workflow, security-inline,
adversarial) → 6 genuine findings, all fixed, regression-pinned, and verified
(846 green, selftest 7/7, fail-before proven). Round 2 (spar confirming re-hunt)
→ F1 fix confirmed padding-proof against 8 functional variants, **and** two fresh
README claims attacked (deleted-binary structural HIGH; Linux argv-TTP
severities) — both HELD with mutation-validated oracles. **Dry.** One clean
confirming dry round after the fix round; a full second 4-lens sweep was judged
low-yield for a target with 3+ prior battle-test passes now surgically hardened
and fully green — reported honestly rather than run to pad the count. Well under
the siege 6-round cap.

## Residual risk / notes

- **`ld-so-preload-write` argv quote-evasion — now fixed** (H1 above). Was defense-
  in-depth only (the write is also caught by the persistence file sensor); the argv
  idiom is now quote-tolerant as well.
- **F7 latency — now fixed** (above): the macOS `log show` cluster runs concurrently.
- Base64/stdin-delivered osascript phish (`… | base64 -d | osascript -`) puts the
  dialog text on stdin, not argv, so no argv detector sees it — but that shape
  trips the fetch+pipe-exec idioms separately. Out of the argv-phish claim's scope.
  (Unchanged — genuinely outside what an argv detector can see.)

---

# Aegis — Recall build (2026-08-11, `/doit`: 4 detection surfaces, 4 opt-in tiers, 7 parallel branches)

The prior passes hardened what Aegis already detected. This one answered a
different question — *what does it structurally fail to see?* — and the honest
answer was: the rung attackers move to **because** the watched surfaces are
watched, the residue shapes that only recurrence reveals, the encoded payload no
idiom table can enumerate, and community intel the tool refused on local-only
grounds it had already learned to thread. Eight items, seven parallel branches,
each tests-first with captured fail-before evidence, merged and verified as one.

The build's own headline is a **measurement**, not a feature: the obfuscated-argv
detector's first draft flagged 2 of 611 live processes — a test harness's own
`bash -c` argv carrying hex-UUID scratchpad paths at 4.84 bits/char, over the
4.5 entropy floor. The fix was not a higher threshold (which would blind the
detector to real payloads) but an **alphabet-purity** rule: `+/` mixed with `-_`
decodes under no base64 flavour, and that mix is precisely what a UUID path is.
Re-measured: 0 of 611. The FP class is pinned by test, so the tightening cannot
silently regress into the threshold it replaced.

| # | Layer added | Shape | Tier |
|---|-------------|-------|------|
| 1 | **Windows persistence-evasion rung** | COM hijacking (`HKCU\...\CLSID\*\InprocServer32`/`LocalServer32`, T1546.015) → HIGH on a user-writable target; IFEO `Debugger` + `SilentProcessExit\MonitorProcess` (T1546.012/.008) → **CRITICAL** on an accessibility binary (sethc/utilman/osk/magnify/narrator/displayswitch), HIGH otherwise; AppInit_DLLs (T1546.010) → HIGH. Baseline-diffed, adopted on first sight. The rung an attacker reaches for *because* Run keys, schtasks and Winlogon are already watched. | detection (Windows) |
| 2 | **Sysmon harvest** | Where the `Microsoft-Windows-Sysmon/Operational` channel exists: EID 1 scored through the **existing** argv machinery (no second grammar to drift), EID 6 unsigned driver → HIGH, EID 25 process tampering → HIGH. Channel absent = sensor **absent**, never DEGRADED — Sysmon not being installed is not a coverage gap. | detection (Windows) |
| 3 | **Outbound beacon recurrence** | `check_outbound` could not baseline-diff (a browser opens hundreds) and said so; **recurrence keys on the opposite invariant** — browser churn does not survive between scans, a C2 pair does. Same `(binary, ip:port)` live now **and** in ≥3 stored scans spanning ≥45 min, non-browser, non-trusted-prefix, unsigned-or-user-writable → HIGH. Stored in the existing observation store; current-scan presence is required so a vanished binary cannot emit a 45-day zombie. | detection |
| 4 | **Obfuscated-payload argv** | Gate 1 (mandatory): interpreter **+ inline-code flag** — so Electron/JWT/cloud-CLI argv is structurally out of scope, not merely tuned out. Gate 2: a ≥100-char base64 run at ≥4.5 bits/char that actually **decodes**, or an in-process decode+exec composition. MEDIUM alone (corroboration fodder), HIGH with a fetch idiom. `powershell -enc` defers to the existing rule: one argv, one strongest finding. | detection |
| 5 | **Community IOC intel** | `intel update|status` — MalwareBazaar + ThreatFox recent exports, no key, **by hand**, `urllib` lazy-imported exactly like `vt`. The scan grades hashes it **already computes** and outbound endpoints against the local sets → CRITICAL with feed, family, first_seen. Pinned by a structural test that runs a full scan with `urlopen`, `create_connection` **and** `getaddrinfo` all replaced with raisers: the local-only guarantee stays literally true, not merely intended. | reputation (opt-in) |
| 6 | **Root-owned witness (`rootwatch`)** | Closes the gap the README stated and could not fix: a same-uid attacker kills Aegis and its user-level watchdog together, and the notary only makes that evident *later*. The privileged component is a generated **59-line** script — line count and import set **pinned by tests**, because the smallness *is* the security argument — run by a root LaunchDaemon/systemd timer, reading one heartbeat and alerting through a root-owned log, syslog and the user's session. Never `sys.executable` (often a `$HOME` venv, itself an escalation); never writes into `~/.aegis`; non-root invocation mutates nothing and prints one sudo line. | survivability (opt-in, root) |
| 7 | **`setup` + `update-check`** | The strongest tiers shipped **dormant** — canary, latch, decoy, guard, deadfall all opt-in and therefore off on most installs. `setup` walks them with one benefit-and-cost sentence each, default No, and **orchestrates the existing `cmd_*`** rather than reimplementing them (proven zero-mutation on all-No, idempotent on re-run). `update-check` catches the silent rot the README warned about in prose: the `~/.aegis` runtime copy staling behind an edited repo. | usability |
| 8 | **Menu-bar status** | `menubar/aegis-status.30s.py` (xbar/SwiftBar, stdlib, never imports `aegis.py`): 🛡️ healthy · ⚠️ N incidents · 💀 **monitor not beating** — the state the plugin exists for. Structurally read-only (`mode=ro&immutable=1`), proven by a full before/after sandbox inventory on **every** invocation across 19 tests; hostile incident text is `|`-sanitized so it cannot forge xbar params. | usability |

## Found while building (not shipped broken)

| Where | Defect | Fix |
|-------|--------|-----|
| `SENSOR_BENIGN_NOTES` | **Three benign-cause notes were dead code.** `_benign_note_for()` does an exact dict lookup on the finding *category*, but three notes were keyed on the *surface id* — `browserext`, `ide_ext`, `wallet` — while those sensors emit `browser-ext`, `ide-ext`, `wallet-integrity`. So the incident card's promise ("KNOWN BENIGN CAUSES for the sensors that fired, so triage is a lookup rather than an investigation") silently rendered **nothing** for browser and editor extensions — the two most FP-prone surfaces in the tool, and the exact ones whose notes say "extensions you installed yourself" and "auto-update re-fires this". | keys corrected to the category spelling; per-category test pinning all three (deliberately not a source-regex scraper: these categories are also emitted from multi-line calls with a variable severity, which no regex reads reliably) |
| `_parse_win_events` contract | The Sysmon harvest initially treated a probe failure as an empty window — the "an unanswered process table is not an empty one" defect this repo has already paid for twice. | non-answer returns `None` and DEGRADES; separate sentinel for "channel readable but read errored"; both poles tested |
| `_install_mac` vs `install.sh` | **The two macOS installers disagreed, and the README called them equivalent.** `install.sh` has always written `ProcessType=Background`, `LowPriorityIO`, `Nice=10`, `ThrottleInterval=30`; the Python port dropped all four. So anyone following the cross-platform path — including the refresh line `update-check` itself prints — got a monitor that scans un-niced at normal IO priority for ~a minute at a time, and in **watch** mode had no bound on `KeepAlive` respawn (a crash-looping watch relaunches about once a second instead of every 30). Found by diffing the deployed plist before and after refreshing this machine's own agent, which is the only place the two installers' output meets. | four keys restored to `_install_mac`; pinned by a **parity** test (`test_both_installers_agree_on_the_resource_keys`) rather than a hardcoded list, so whichever installer gains a resource key next, the other must match; fail-before captured at 5 failures |

## Hardened after the fact — the three defects' *classes*, not just their instances

Fixing a defect and leaving the mechanism that produced it is how the same bug
returns under a new name. Each of the three above got its class closed:

| Class | Why the instance fix wasn't enough | What closes it |
|-------|-----------------------------------|----------------|
| Two generators for one artifact | The four resource keys were restored and pinned by name — but they went missing *because* nothing enumerated them, so a by-name list has the same blind spot that caused the drift. | Compare the **whole parsed plist** from both installers, scan and watch mode, normalizing only the interpreter (legitimately different by design). Proven bidirectionally: dropping a key from `aegis.py` fails it, and adding a key to `install.sh` alone fails it. A future key nobody thought to list cannot drift. |
| Tests reaching real state | Two synthetic incidents were resolved out of the live store, and the leaking class is sandboxed *today* — but nothing stopped the next sandbox gap from doing it again, and nothing helped an install that already had residue. | A conftest autouse guard wraps `_event_connection`, `save_json` and `ensure_state` and **refuses** any write aimed at the real `~/.aegis`, naming the unsandboxed global. Plus `implausible_incidents()`: an incident stamped before 2026 cannot be real (Aegis did not exist), so `doctor` reports it and hands over the `resolve` line. It **reports, never deletes** — quietly editing the operator's security records would be the worse bug. Runner caveat stated in-source: the guard is a pytest fixture, so it binds `pytest tests/` (what CI runs on every push), and its own tests skip under `unittest discover` rather than run unguarded to find out. |
| Rot only a human could see | The runtime copy was refreshed and `doctor` reports drift — but `doctor` is precisely the command nobody runs when nothing looks wrong, which is why the monitor sat 18 days behind. | `check_self_protection` now emits the drift finding, so a **scan** reports it. Scoped so the scheduled agent (which *is* the runtime copy) stays silent instead of flagging itself forever, and MEDIUM rather than HIGH because a permanent HIGH for "you edited the repo" is how a tool trains its operator to ignore HIGHs. |

Adding that last check exposed one more of the same shape: `RUNTIME_SCRIPT` was
never sandboxed, so the moment a sensor read it, **every** self-protection test's
result depended on whether the developer had re-installed since their last edit —
a test consulting live host state, which is the failure the harness exists to
prevent. It is now in the `Sandbox` override list.

**The worst one, and I caused it: a test killed the live monitor.** Chasing a
`launchctl` last-exit-status of 2 on the operator's own machine turned up the
loaded launchd job pointing at
`/var/folders/.../T/aegis_inst_*/h & me/.aegis/aegis.py watch 600` — a
`TestInstaller` **sandbox tmp path**. A test that runs `aegis.py install` in a
subprocess had executed a **real** `launchctl bootstrap` against the live GUI
domain, because `_install_mac` (unlike `install.sh`, which substitutes a stub
launchctl under `AEGIS_TESTING`) drove `launchctl` unconditionally. Teardown
then deleted the tmp dir, so the squatting job ran `python3 <deleted-path>` →
exit 2, its stderr routed to the same deleted dir → **125 failed scheduled
runs, the operator's real monitor dead for ~2h, and not one signal in the real
`run.err`.** This session's own new watch-mode parity test was the trigger that
made it fire again. The class is identical to the test-residue defect above —
a test escaping its sandbox into real state — one layer lower: the OS job
registry instead of the SQLite store.

The fix is a guard at the one chokepoint every service-control call already
shares, `run()`: under `AEGIS_TESTING` a `launchctl`/`systemctl`/`schtasks`/
`loginctl` verb is routed to the test's stub, or **refused** (rc 2) if none was
supplied — so a test that forgets the stub fails loudly instead of mutating the
machine. Pinned two ways: a stub that *logs its calls* proves `aegis.py install`
drives the stub and never `/bin/launchctl` (and that the path it tries to load
is the sandbox, never a real one), and a direct test that `run()` refuses a
service-control verb with no stub. Fail-before confirmed the leak — and doing so
re-leaked a job, which was cleaned up; the guard now makes that impossible.
Verified after the whole suite runs under BOTH runners: the live launchd job
still points at the real `~/.aegis`, and the real event DB is byte-identical
(md5) — the "changed mtime" that first looked like a leak was the live agent's
own scan during the test window, not a test.

**CI "wedge" — corrected twice, and the second correction is the true one.**
The first correction (above, in an earlier version of this entry) diagnosed a
"post-job stall" from the run's `updated_at` looking frozen at ~24 minutes
against what was believed to be a 60-minute cap, and cut the job cap to 30 to
bound it. That diagnosis was itself wrong, proven by the very next run: cutting
to 30 turned a THIRD occurrence into a hard failure with real logs for the
first time, and those logs show no stall at all. Every step on both Windows
jobs genuinely ran to completion — `427 passed, 145 skipped`, zero failures,
`checks failed: 0` from the live harness — the run simply took ~33 minutes
wall-clock, longer than either guessed cap. `py3.12`'s `Test suite` step got a
hard `KeyboardInterrupt` from *its own* 20-minute STEP timeout four seconds
after printing a clean pass, because that cap was sized on the same stale
"~13 min" guess as the job cap, taken before this session added the tests
that made the Windows suite genuinely slower.

The corrected, MEASURED sizing: `Test suite` alone runs ~1176-1206s (~20 min)
on Windows, the live harness ~681-767s (~12 min) — both re-measured from this
run's own logs, not guessed. Job cap raised to 45 (real headroom over the
~33-35 min observed total); step caps to 35/5/25. If the suite keeps growing,
the fix is to re-measure and resize, not to nudge a constant again. The honest
residual: neither of the two EARLIER "wedge" reports was ever confirmed against
logs before being cancelled and rerun — the far more likely explanation for
both, in light of this, is the same ordinary Windows CI slowness misread as a
hang, not two separate platform-level freezes.

**Guardrails honored:** the scan path still makes **zero** network calls (intel
is by-hand, and the structural test proves the scan cannot reach the network even
with feeds present); nothing new fires automatically off a heuristic; the one
privileged component is opt-in, root-owned, and small enough to audit in a
glance; every Windows sensor is a pure function over registry/event dicts so it
is testable on any OS *and* exercised against a real Windows kernel in CI; and
absent-vs-degraded is respected everywhere (no Sysmon, no intel, no `rootwatch`
⇒ silent, never a manufactured coverage gap).

**Verified:** full suite green (798 tests at merge, up from 671) on all five CI
runners including two real Windows kernels; a live end-to-end scan on the
author's machine (59s cold, 19s warm, one aggregated notification, only true
positives already known to that machine, **zero** false positives from any new
detector); the obfuscated-argv 0-of-611 live measurement above; and the intel
tier exercised against the real fetched corpus (2,098 hashes + 2,715 endpoints
loaded, sensor status OK, this machine clean, feed files unmodified by the scan).

**One CI defect, and it was a test's fault, not the product's:** both Windows
jobs failed identically because the `update-check` drift assertions rebuilt their
expected string from a bare `_SELF_PATH`, while `_refresh_line()` **quotes** the
path on Windows — correctly, since the reference machine's repo path contains
both spaces and `&`. The fix makes the test use `_refresh_line()` as its own
oracle rather than re-deriving its quoting rule, so the mismatch is now
structurally impossible rather than merely corrected.

---

# Aegis — a governed battle-test: three loud rounds, sixteen defects (2026-08-05)

A single `/battle-test` run under `/fable-mode` governance: right-size, hunt across
independent lenses, adversarially verify every candidate against the real code before
it is trusted, fix, regression-pin, re-verify, loop. Siege tier, because this tool
quarantines, destroys, neutralizes and freezes. Three rounds of hunting all came back
*loud* — five defects in the newest delegate/session tier, five more in the *older core
the earlier passes never adversarially hunted* (including a CRITICAL bypass of the
destructive-action safety rail), and five in the install/watch/txn surfaces on the third
round — **one of which this very pass introduced with an earlier fix and then caught.**
Every one was verified against the running machine or a traced repro, not asserted from
a fixture.

The method that produced the two headline findings is worth stating: **when two pieces
of code read the same fact, do they agree?** The deadfall dispatch gate and the `assay`
sensor both read a lane's state from `assay.json` and disagreed (R1/C5). The protected-path
guard and the filesystem both name the same directory and disagreed about its case (R2-2).

## Round 1 — the delegate/session tier (5)

| # | Sev | Defect | Fix |
|---|-----|--------|-----|
| C5 | **HIGH** | `_deadfall_coverage_fresh()` — the gate that lets a pre-authorized reversible verb **fire with no human** — checked only that a lane's `last_ok` was recent, never that its most recent run *passed*. `cmd_assay` preserves a prior `last_ok` across a failing run so `check_assay` can age a broken lane out slowly, which means a lane failing *today* still carries a fresh `last_ok` with `ok=False` — a state `check_assay` flags HIGH "positive control is failing" while the dispatch gate called it PROVEN. So a standing order would auto-fire `freeze`/`latch` on a detector that cannot currently demonstrate it works, the exact thing the gate exists to refuse. | gate also requires `rec['ok']`; both-pole test |
| C2 | **HIGH** | `cmd_frozen()` re-walked the whole process table once per displayed pid (nested loop; ~41s CIM query each on Windows) — the anti-pattern its sibling `_process_owner_and_names` was written to avoid. | one `{pid:comm}` map from a single walk; ≤1-walk test |
| C1 | MED | `_AGENT_SCAN_TRUNCATED` set on a cap-hit, never reset → permanent false "coverage PARTIAL" for the whole uptime of the `cmd_watch` daemon after one transient spike. | reset at the producer's top; truncate-then-clean test |
| C3 | MED | `_outbound_rows()` macOS branch spawned one `ps` per connection row (measured 32 redundant/scan); Linux/Windows already batch. | per-pid memo, byte-identical output; spawn-count test |
| C4 | MED | Three sensors each re-walked the table per scan, and a comment *claimed* session-theft reused the collected list — it did not (the signature comment-vs-code defect). | one scan-scoped snapshot, shared and rebuilt-fresh each scan; comment made true; two-assertion pin (shared + fresh-per-scan) |

## Round 2 — the older core the prior passes never hunted (5)

| # | Sev | Defect | Fix |
|---|-----|--------|-----|
| R2-2 | **CRITICAL** | `_is_protected_path()` compared paths case-sensitively, but macOS/Windows filesystems are case-insensitive and `os.path.realpath` preserves the caller's case. Verified live: `/SYSTEM`, `/USR`, `~/.AEGIS/baseline.json`, even `/USERS/<me>` all resolve to real protected files yet returned **False** — so a destructive verb (`quarantine`/`destroy`/`neutralize`) could act on Aegis's own trust store, `/System`, or the home tree through a case-varied alias. The one rail the whole response tier stands on. | a case-fold comparison (`_cmp_path`) gated on a one-time `_fs_case_insensitive()` probe — folds on case-insensitive volumes, exact on case-sensitive Linux, fail-closed; also closes the same gap on the shared self/state/HOME checks; live-verified + both-pole test |
| R2-3 | **HIGH** | `_kill_program_instances()` — the shared neutralize kill step — SIGKILLed same-user processes with **no `actions.jsonl` record at all**, violating the tool's own audit-before-mutation invariant that `cmd_quarantine`/`cmd_destroy` enforce. | gated `log_action` before the kill (no audit ⇒ no kill); both-pole test |
| R2-4 | **HIGH** | Dismissing one `risk`/`chain` incident silently swallowed **all future evidence on that entity, forever**. Those incidents are entity-keyed with no content hash and hardcoded HIGH/CRITICAL severity, so the FALSE_POSITIVE reattachment gate (whose comment claims content-hash keys protect it — true only for `signal` incidents) always matched. A benign-positive on `/opt/x` blinded the tool to a real later attack there. | reattach only evidence whose **fingerprints** the incident already saw; a genuinely new fingerprint opens a fresh incident. Universal (signal keys already embed the fp, so unchanged there); both-pole test (recurrence stays suppressed, new evidence alerts) |
| R2-5 | **HIGH** | `redact_sensitive()` required a `:`/`=` delimiter, so the space-separated CLI form `--api-key VALUE` — exactly what MCP/agent-config `args` arrays carry, and what `diff_agent_surface` interpolates verbatim into a finding detail — leaked to `findings.jsonl`, as did the JSON `"password":` form and `sk_live_`/`xoxb-` token shapes. A security tool writing live secrets into its own logs. | new `_SECRET_FLAG_RE` (flag-tail anchored, so `--token-count 5` is untouched) + quote-tolerant assign regex + added token shapes; leak/preserve/no-over-redact test |
| R2-1 | LOW | The agent-surface coverage sensor (a `gather_all` reader) ran **before** its only writer (`snapshot_agent_surface` in `_scan_surfaces`), so on a one-shot `aegis.py scan` the truncation flag was always the stale module-init `False` and the "walk hit its cap" finding was never emitted — the C1 fix's own goal, unmet for the primary manual invocation. | read coverage after `_scan_surfaces`; one-shot-scan truncation test |

## Why the tests could not fail before, and the discipline that fixes the class

The recurring lesson, three more times: **a fixture inherits its author's model of the
system; only the system disagrees.** C5's dispatch tier had a test literally named
"unproven coverage refuses to fire," but its fixture coupled staleness with `ok=False`,
so the `ok` half was never exercised. R2-2's rail had tests for `/System` and `$HOME` —
all in canonical case, so the case-alias never appeared. R2-4's reattachment had a
comment asserting an invariant (content-hash keys) that held for one incident kind and
was silently false for two others. Each new test asserts **both poles**, because a
one-sided test passes against a detector hardwired to one answer.

## Verification actually performed

- macOS full suite **646 passed, 3 skipped** (was 636; +10 regression pins).
- Every one of the ten new tests was run against the **pre-fix** source and **failed**
  (assertion failures, plus a few errors where a fix introduces a new symbol the test
  needs — e.g. `_iter_processes_live`, `_FS_CASE_INSENSITIVE`, or an audit file that
  pre-fix code never writes) — so none is a tautology that passes either way.
- R2-2's bypass and its fix were **verified live** against this machine's real filesystem
  (`/SYSTEM`, `~/.AEGIS`, `/USERS/<me>` refused after the fix; a genuine `/tmp` payload
  still quarantinable).
- `selftest.py` 7/7.
- One pre-existing test needed a forced, called-out update: the P1 comm-truncation pin
  inspects the `ps`-call source, which the C4 refactor moved into `_iter_processes_live`;
  assertions kept verbatim, only the inspected symbol follows the code.

## Round 3 — a third loud round, and a defect this pass created (5)

Round 3 re-checked all ten fixes and swept the surfaces the first two rounds never
touched (the watch loop, install/scheduler lifecycle, quarantine transaction machine,
heartbeat/watchdog). Its automated fan-out first hit the session's rate limit; I
completed the fix re-check inline and — being honest about the record — **got one
wrong**: I reported the R2-5 flag regex "clean" because my inline probe used a single
`--aaaa…` anchor (fast, 4 ms) and never tried the pathological *hyphen-dense* input.
When the limit reset and the automated sweep actually ran, it found exactly that, plus
four more. The lesson the log keeps teaching, turned on its author this time: a check
that only exercises the easy input proves nothing about the hard one.

| # | Sev | Defect | Fix |
|---|-----|--------|-----|
| R3-1 | MED | **Introduced by the R2-5 fix.** `_SECRET_FLAG_RE` led with an unbounded `[\w-]*` before the keyword, so a hyphen-dense token backtracked O(n²) — a ReDoS reachable through an uncapped agent-config `args` value (measured 18.5 s at 40 KB, minutes at 200 KB), stalling the whole scan synchronously. | bound the prefix `{0,40}` (Python 3.9 has no possessive quantifier) **and** cap the interpolated args at 400 chars; 200 KB now redacts in 0.22 s. Both-pole timing test. |
| R3-2 | **HIGH** | `_install_linux` wrote an **unquoted** `ExecStart`; systemd splits on whitespace, so any space in `$HOME` or the interpreter path (a named venv/conda env, `/home/john doe`) produced a malformed unit that failed on every trigger — Aegis never ran, no heartbeat, no alert, while the timer reported itself healthily enabled. `_install_mac` (per-`<string>`) and `_install_windows` (quoted) already handled this. | quote each path in the exec line; test asserts a spaced path stays one argument. |
| R3-3 | MED | `cmd_install` on Linux was not idempotent despite the README promise: re-installing watch mode never restarted the running `simple` service, so a refreshed `~/.aegis/aegis.py` kept running the OLD code; switching modes left the previous unit enabled and running. | stop+disable BOTH units before enabling the target; test asserts the disable calls precede enable. |
| R3-5 | **HIGH** | macOS `HOT_DIRS`/`STAGING_DIRS` listed both `/tmp` and `/private/tmp` — the same firmlink (`realpath('/tmp') == '/private/tmp'`) — so every real `/tmp` detection was emitted **twice** with two different path fingerprints, inflating signal counts and defeating the RISK_MIN_SIGNALS distinct-signal guard (one physical file could masquerade as multiple corroborating sensors). | `_dedup_by_realpath` collapses aliases at definition (generic, so future symlinked dirs too); one physical file → one finding, pinned. |
| R3-4 | LOW | `_install_windows`' watch comment claimed the process was "kept alive by the scheduler's restart policy" — the `schtasks /create /sc onlogon` call configures no such policy (that needs the XML task API), so a crashed watch process is not relaunched until the next logon. The comment described resilience the code does not have. | comment corrected to state the gap honestly and point at the mutual watchdog as the real liveness signal. Not shipped blind: no untested XML task change on a platform this pass could not execute. |

One candidate was **refuted** on verification (raised, traced, found not to reach a
real wrong behaviour) — recorded because a rejected finding is part of an honest count.

### R3-6 — the re-check found the ReDoS the ReDoS fix missed

Because R3-1 proved my own fixes can introduce defects, I ran a focused adversarial
re-check of all five Round 3 fixes before shipping. Four were clean. The fifth surfaced
**R3-6 (MED):** `redact_sensitive` *still* had an O(n²) ReDoS — in `_AUTH_RE`, whose two
`\s*` runs around the optional `bearer|basic` re-partition a long whitespace value in
O(n) ways and backtrack O(n²) when the value group fails at EOF or a quote
(`authorization=` + 40 000 spaces → 9.5 s, measured). It is *pre-existing* — R3-1 did not
touch it — but R3-1's stated job was to de-ReDoS that exact function, so leaving a second
quadratic in it made the fix incomplete. Bounded the whitespace (`\s{0,20}`) like R3-1;
200 KB now redacts in 0.006 s, all real `Authorization:` header forms unchanged. The
regression test now pins **both** vectors. The lesson compounds R3-1's: fixing one ReDoS
in a function is not fixing *the function* — a per-pattern check would have caught this,
a per-symptom check ("is `_SECRET_FLAG_RE` fast now?") did not.

## Convergence

Three rounds plus a fix-re-check, all loud: 5 + 5 + 5 + 1 = **sixteen** genuine defects
(1 CRITICAL, 5 HIGH, 8 MED, 2 LOW), two of them ReDoS in the same redaction function —
one created this pass, one pre-existing, both closed. The stop is a
**hard-cap / diminishing-returns** judgement, not two consecutive dry rounds — stated
plainly rather than dressed as convergence. Every surface the three rounds targeted has
now been adversarially hunted at least once; a fourth round is the honest next step if
this is ever driven to a true dry-dry stop, and the workflow scripts (`bt_round{1,2,3}.mjs`)
are saved to re-run it.

## Verification (final)

- macOS full suite **651 passed, 3 skipped** (+15 regression pins over the 636 baseline);
  `selftest.py` 7/7.
- Every one of the new/extended tests was run against its pre-fix source and **failed**
  (assertion failures, plus a few errors where a fix introduces a symbol the test needs).
- Live-verified this pass: the R2-2 case bypass and its fix; the R3-1 ReDoS (18.5 s →
  0.22 s) and its fix; the R3-5 double-emit (2 findings → 1); the R3-2 quoted unit text.
- Cross-platform CI (Linux 3.9/3.12 · macOS · Windows 3.9/3.12) is the gate for the
  platform-specific fixes (R2-2/R2-3/R3-2/R3-3, C3/C4); driven on the branch's PR.

## Residual

- R2-2's case-fold is fail-closed: on a rare mixed-case-sensitivity volume it
  over-protects (refuses a legitimate quarantine of a case-alias) rather than under-protect.
- R2-4 adds two bounded lookups per FALSE_POSITIVE upsert (a rare path); no measurable cost.
- The Windows ~41 s CIM cost that C2/C3/C4 improve is inferred from the file's own prior
  measurement, not re-measured here. R3-2/R3-3/R3-4 are Linux/Windows paths verified by
  unit-level generation and stubbed lifecycle, not on a live foreign kernel this pass —
  CI and the live harnesses are the backstop.
- R3-4 leaves a real Windows watch-mode resilience gap (no crash-restart) documented but
  unfixed, because the fix needs the XML task API and this pass would not ship Windows
  scheduler code it cannot execute.

## End-state checklist

- bugs found → fixed: **16/16**, each with a repro that failed before and passes now.
- logic errors found → fixed: C5, R2-4, R2-1, R3-3 — fixed + pinned.
- edge cases found → tested: every fix has a both-poles / linear-timing regression test; all proven to fail pre-fix.
- no unimplemented files/stubs remain: completeness pre-flight clean at Gate 2.
- security lens run: inline across all three rounds; fixed the CRITICAL case-alias bypass, the neutralize audit gap, the secret-leak, and the ReDoS.
- adversarial-break: run as the Opus/high lens each round; Round 3 caught a self-introduced defect — the strongest evidence the loop works.
- verified vs inferred: suite/selftest/live-checks **verified**; Windows CIM timings **inferred**; nothing claimed clean that was only reasoned about (the R2-5 inline miss is recorded above, not hidden).

---

# Aegis — the same class again: a branch that could not be reached (2026-08-05)

The previous pass was named for a detector that never fired. This one went
looking for the *rest* of that class deliberately, by writing the positive
controls that were missing, and found another one immediately.

The method matters more than the count. The previous defect was found by
running the code against a real machine; this one was found by asking, for each
detector shipped in the last release, **what input would prove it fires, and
what input would prove it stays quiet** — then discovering the first question
had no answer for one of them.

## The defect

| # | Sev | Defect | Before | After |
|---|-----|--------|--------|-------|
| B1 | **HIGH** | `diff_agent_surface()` could not report an agent config whose exec target went from **absent to present**. `_resolve_exec_target()` records an absolute-but-missing target as `(target, None)`, and its own comment promised "if the file later appears the hash changes from None and the diff fires". It did not: the changed-target branch requires **both** `target_sha` values to be truthy, and the old one is `None` in exactly that case, so the branch was unreachable for an appearance. | `diff_agent_surface(target_sha=None → "b"*64)` returned `[]` | returns one HIGH `agent-surface:materialized:` finding; `hash → hash` still returns one, first sighting and steady state still return `[]` |

**What it left open.** Register an MCP entry pointing at a path that does not
exist yet — silent, and entirely plausible, since plenty of configs name a tool
you have not installed — then drop the payload there later. The config line
never changes, so the file's own `sha256` never changes either, and the surface
stayed quiet through the whole sequence. It is the cheapest way to arm an agent
config without ever editing a watched file.

**Same shape as A1, different mechanism.** A1 was an exception swallowing a
`NameError`; B1 is a boolean guard that is unsatisfiable in the case its own
comment advertises. Neither failed. Neither had a test. Both were branches that
could not be reached, in a file whose value is that it notices things.

The generalization worth keeping: **a comment describing a case the code cannot
execute is a defect report that nobody filed.** Both defects were sitting next
to prose that stated the intended behaviour correctly.

## What was added so the class stops recurring

Six assay lanes, each asserting **both** poles, covering every detector the
previous release shipped without one:

| Lane | Hostile pole | Benign pole |
|---|---|---|
| `agent-imperative` | conceal + credential scores HIGH | "Do not tell the user to run npm install manually" scores nothing — the real-file case the lookahead exists for |
| `agent-exec-target` | target swapped **and** target materialized both fire | first sighting and steady state stay silent |
| `session-theft` | debug port on the live profile is CRITICAL | non-browser, browser-without-flag, and an inherited `--type=renderer` all stay silent |
| `ext-cap-gain` | gaining `debugger` is CRITICAL; narrow → all-sites is a gain | steady state and *narrowing* stay silent |
| `glean-atoms` | 3 atoms all present matches | one missing does not; below the threshold never matches |
| `writ-enforcement` | enforcement ON escalates an uncovered change to HIGH | enforcement OFF returns **the same list object** — byte-identical, asserted by identity |

The benign pole is not symmetry for its own sake. A lane that checks only the
hostile side passes against a detector hardwired to say yes; one that checks
only the benign side passes against a dead one. `latch-cleared` (A1) is the
proof: a lane asserting only the intact case would have passed against the
broken function.

`_glean_rule_matches()` was extracted from `cmd_glean` so its lane challenges
the **shipped** predicate rather than a copy — a lane that re-implements the
rule proves only that the copy still works.

## Also shipped this pass

- **`deadfall` dispatch is wired.** The interlocks shipped last release and
  were tested; the gates now re-evaluate at **fire** time, not merely at arm
  time. Checking the coverage precondition once would have made it decorative:
  an order bound 30 days ago to a detector that has since gone stale would keep
  reading as protection. An unproven detector now disarms its own order and
  says so. Triggers stay attack-defined, verbs stay reversible, every dispatch
  leaves an `actions.jsonl` record and a notary link.
- **Event-driven watch on Linux**, `ctypes` inotify. The previous entry called
  this deliberately unbuilt rather than written blind, because kernel-interface
  code that cannot be executed on the machine writing it is the risk this
  project has already paid for once. That objection was answerable, not
  permanent: it is now proven against a **real Linux kernel** — real fd, real
  write, real wake, plus the drain that keeps a level-triggered fd from
  spinning the loop — and the test **skips** rather than passes where it cannot
  do that. `ReadDirectoryChangesW` stays unbuilt, held to the same bar.

## Test state

636 tests. macOS `632 passed, 1 skipped`; Linux (container) `513 passed,
123 skipped`; `selftest.py` 7/7. One caught defect was mine, during this pass:
`log_action()` takes `target` positionally and the dispatch code passed it again
as a keyword, which the new tests surfaced immediately.

---

# Aegis — agent surface, session theft, and a detector that never fired (2026-08-04)

The previous pass added the protective tier. This one started as a feature pass
— cover the AI-agent trust surface and session/cookie theft, neither of which
had a single line of coverage — and turned up a defect in the tier shipped one
commit earlier.

## The defect this pass exists to have found

| # | Sev | Defect | Before | After |
|---|-----|--------|--------|-------|
| A1 | **HIGH** | `_latch_intact()` referenced `stat_mod`, a name that does not exist anywhere in the file (the module imports `stat`, and the correct name is used two lines below). On macOS the reference raised `NameError` **into the function's own `except Exception: return None`**, so it answered "unknown" on every call. The flagship protective-tier signal — "a latch was cleared with no authorized `unlatch`", the one described as attack-defined evidence — had its HIGH branch made **unreachable on the primary platform**. Worse than silent: every latched path emitted a permanent `INFO` "latched surface could not be checked", so the mechanism produced a steady nag instead of a signal, training dismissal of exactly the category most worth reading. | `_latch_intact()` on a real `chflags uchg` file returned `None`; `check_latches()` could only ever emit INFO | returns `True` for an applied latch and `False` for a cleared one, verified against a real immutable file; `check_latches()` emits the HIGH finding |

**The honest-unknown path swallowed a coding error.** This tool is careful, on
purpose, never to report "clean" when it means "could not tell" — and that
discipline is right. But an `except Exception: return None` cannot distinguish
*the platform would not answer* from *this function is broken*, and it reports
both as the honest-sounding one. A defensive default made a hard failure look
like a soft limit. Where the cost of that confusion is a dead detector, the
broad `except` needs to be narrow enough that a `NameError` still crashes.

## Why no test caught it

There was no positive control for the latch detector. `assay` existed and had
six lanes; none of them exercised `_latch_intact`. The tier's own tests applied
and released latches and asserted on the *state file*, never on the function
that reads the *filesystem*.

Two lanes were added — `latch-cleared` and `decoy-read` — and the first asserts
**both poles in one lane**: that an applied latch reads intact AND that a
cleared one reads cleared. Either assertion alone is passable by a function
hardwired to a constant, which is precisely the failure mode being pinned. The
`deadfall` coverage gate then refuses to arm any standing order whose lane has
not passed within its half-life, so an automated response can never be bound to
a detector in this state.

## What the machine said that the fixtures could not

Four further defects were found only by running the new code against this
machine rather than against a fixture. The log's standing lesson holds: a
simulation inherits its author's model of the system.

| # | Defect | How it surfaced |
|---|--------|-----------------|
| A2 | `_automation_targets_live_profile()` captured the `--user-data-dir` value with `[^\s]+`. The real macOS profile root is `~/Library/Application Support/Google/Chrome` — **it contains spaces** — so the capture truncated at "Application" and classified a live-profile attack as a harmless scratch run. Failed **open**, on the single case the sensor exists to catch. | a hand-written case using the real path, not a synthetic one |
| A3 | `_resolve_exec_target()` treated any argument containing a path separator as the script. `@modelcontextprotocol/server-foo` is an npm **scope spec**, not a path, so every `npx`-based MCP server — most of them — resolved to nothing and was never hashed. | printing resolved targets for the machine's actual 158 exec entries; 105 were unresolved |
| A4 | The credential-surface table hardcoded Chrome's `Default/` profile. Real installs use `Profile 2`, `Profile 15`, `Profile 22`… so `cauterize` found **zero** cookie stores and printed a confident, tidy, incomplete plan. The most valuable credential class in the current threat model was absent while the output looked finished. | running `cauterize` on a real home directory and noticing what was missing |
| A5 | The semantic imperative detector matched bare adverbs and fired on this repo's own instruction files — "route silently", "never report a result you didn't watch happen", and a legitimate "Do not tell the user **to run** `codex plugin marketplace add`". | scoring the machine's 306 real agent files and reading every hit |

A5 is the calibration lesson in miniature. Concealment had to be redefined to
name *who* is kept in the dark: "silently" is a writing style, "without telling
the user" is an instruction to deceive the person the agent works for, and only
the second has no legitimate form. The `(?!\s+to\s+\w)` lookahead that
separates "don't tell the user **about** X" from "don't tell the user **to do**
X" exists because a real file needed it.

## Measured, not assumed

- **`atime` is dead as a read sensor.** The obvious cookie-jar sensor — watch
  the jar for reads — was designed, then discarded on evidence: on this APFS
  volume the first read advanced `atime` and the **second did not**.
  `EVFILT_VNODE` has no read flag, so there is no unprivileged fallback.
  Building it would have shipped a detector that silently never fires — the same
  failure as A1, chosen deliberately this time. Coverage went instead to the
  paths attackers moved to after App-Bound Encryption: a browser driven against
  its own live profile.
- **Agent-config churn is ~19 changes/week** across this operator's three main
  repos (244 in 90 days). A naive content-hash diff would emit ~19 alerts a week
  and be muted within a fortnight. So plain edits are silent, and only a new
  exec entry, a changed **resolved target**, or a **newly gained** semantic
  imperative alerts — with git provenance separating an edit you typed from an
  imperative that arrived in a `git pull` from a remote you do not control.
- **The new snapshots cost 0.26s.** `surface.btm` costs 30s (pre-existing
  `sfltool` timeout), which is now the dominant scan cost and is not this pass's
  to fix, but is recorded here so it is not mistaken for one.

## Also corrected

- **`unlatch`'s human check was satisfiable by automation.** It gated on
  `sys.stdin.isatty() and sys.stdout.isatty()` and reasoned that "a background
  script has no tty and cannot read the code off our stdout". That is true of a
  plain subprocess and **false of anything that allocates a pty** — `expect`,
  `script`, `ssh -t`, an AI agent's shell tool. Such a wrapper passes both
  checks, reads the challenge off the pty master, and types it back. Note the
  obvious fix does not work either: `/dev/tty` fails identically, because a pty
  *is* a controlling terminal. The channels must differ — the code now goes to a
  GUI dialog and the answer comes from the terminal, and where no out-of-band
  channel exists the weaker guarantee is recorded as `channel=tty-only` rather
  than claimed as equivalent.
- **Two comments asserted a constraint that does not exist**, saying inotify has
  no stdlib binding so event-driven watch is macOS-only. `ctypes` is stdlib;
  `inotify_init1` and `ReadDirectoryChangesW` are both reachable with zero
  dependencies. Polling on Linux/Windows is an unpaid implementation cost, not a
  platform limit. Corrected in place rather than deleted, because a limitation
  written down as structural stops being re-examined.
- **The "no new privileged parser" invariant was broader than its own
  justification.** The Norton/Symantec CVE-2016-2208 parser was dangerous
  because it ran as SYSTEM: a bug in it *escalated*. A parser at the same
  privilege as the file's owner escalates nothing. Restated as **never parse
  untrusted input above the privilege its author already holds** — which keeps
  untrusted binaries out of scope and puts the operator's own config files in.

## Second pass — the wiring, and a feature that measured its way to shippable

Four items were finished after the first commit; two of them were features that
existed only on paper.

| # | Defect | Evidence |
|---|--------|----------|
| A6 | **`writ_covers()` had zero call sites.** The command wrote state, the HELP text and README both claimed an unauthorized change would report as HIGH — and enforcement changed nothing at all. A documented behaviour with no implementation is worse than a missing feature, because it is believed. | `grep writ_covers aegis.py` returned the definition and nothing else |
| A7 | **`guard install` computed a bash path and never wrote it.** `bash_p` was a dead variable. bash also has no bracketed-paste widget, so paste provenance there is genuinely UNKNOWN — and the code was collapsing unknown to `False`, letting the weaker shell manufacture reassurance. Now tri-state. | dead local; `pasted` was `== "1"` |
| A8 | **Extension capability was ungraded.** An extension holding `cookies` + all-sites, or `debugger`, reads sessions through Chrome's own API — no process to see, no file touched, invisible to every other sensor here. | `grep host_permissions` → nothing |
| A9 | **Glean shipped as a false-positive generator and was measured back to shippable.** | below |

### The glean calibration, in numbers

The obvious implementation — match if ANY of a rule's literal atoms appears —
was written, run against this machine, and produced **46 matches**, including
`/opt/homebrew/bin/node`, two Python interpreters, GoogleUpdater and a Steam
binary. Against a known-good corpus of 97 system and Homebrew binaries it
flagged **81 of 97 — an 84% false-positive rate.**

The cause is not a tuning problem. A YARA rule's condition is usually *all of
them* or *N of them*; matching a SUBSET while skipping the condition is not a
weaker version of that rule, it is a different and far looser one. A lone atom
is frequently a Mach-O section name or a code idiom every Go binary shares.

Requiring a rule to declare **≥3 atoms with ALL present** measured **0 of the
same 97**, and dropped the live run from 46 matches to 2 while running ten times
faster (102s → 10s).

The two survivors — Microsoft AutoUpdate and Zoom's updater, both matching one
generic downloader rule — were then handled by **grading rather than
suppressing**. Raising the threshold again would have hidden them and also
hidden real Developer-ID-signed malware, since a hijacked cert is an established
technique. So matches are split into an unsigned/ad-hoc list (the one worth a
human's attention: **0 files here**) and a vendor-signed list shown as context.

This is the same decision the atime experiment forced earlier in the pass, one
rung further along: measure the thing, and let the measurement decide whether it
ships, in what form, or at all.

### Deliberately not built

Event-driven watch on Linux/Windows. The comments asserting it was impossible
were wrong and have been corrected — `ctypes` is stdlib, `inotify_init1` and
`ReadDirectoryChangesW` are both reachable. But writing kernel-interface code
that cannot be executed on the machine writing it is precisely this log's
standing lesson in reverse, and the gap it closes is latency (5s poll →
sub-second), not coverage. Recorded as unbuilt work with the constraint
corrected, rather than shipped blind.

## Residual

- `deadfall` cannot fire anything; dispatch is deliberately unwired so the
  interlocks land and get tested first. A test asserts this, so wiring it later
  requires changing that test on purpose.
- `guard` refuses nothing and covers interactive shells only. Win+R and
  GUI-launched payloads are explicitly out of scope, stated rather than implied.
- `writ` enforcement is default-off; while off, `writ_covers()` returns False
  and scan behaviour is byte-identical.
- The agent-surface walk is file-capped and hit its cap on this machine, which
  is reported as a LOW partial-coverage finding rather than absorbed.
- Three `credential+egress` instruction files remain flagged on this machine.
  All are operator-authored, all are adopted silently at baseline, and none
  produces an interrupt — but the calibration is a floor, not a proof.

---

# Aegis — protective tier (2026-08-04): pre-commit, contain reversibly, leave a witness

Every prior pass in this log made the detector see more. This one asked a
different question: the README's honest ceiling says an unprivileged process
cannot block, so is *detect and report* actually the whole of what it can do?

It is not, and the reason is narrower than the ceiling suggests. A veto must be
privileged **because it is irreversible** — the kernel is the only thing entitled
to arbitrate an act that cannot be taken back. Nothing in that argument applies
to an act that *can* be taken back. So three regions were open the whole time:
**before** the event (pre-commitment), **after** it (reversible containment), and
**outside** the attacker's trust domain (a witness). None needs a privilege Aegis
was refusing to ask for.

Six mechanisms shipped as by-hand commands — `freeze`/`thaw`/`frozen`, `latch`/
`unlatch`, `decoy`, `assay`, `notary`, `clipboard`, plus `rehunt`/`backtest` as
developer tooling. The invariant did not move: nothing here fires automatically
from a heuristic. What changed is that the operator now has reversible verbs to
reach for, not that Aegis acquired judgement.

## The defect this pass exists to have found

| # | Sev | Defect | Before | After |
|---|-----|--------|--------|-------|
| P1 | **CRITICAL** | macOS `ps` truncates the `comm` column to 16 characters **when `args` is requested in the same call** — exactly how `_iter_processes()` queried it. This was found via the freeze guard (`/System/…/MacOS/Dock` arrives as `/System/Library/`, so `_PROTECTED_COMMS` matched nothing), but the guard was the *smallest* consumer. `check_processes()` — the headline "unsigned binary running from a user-writable path" sensor — grades that same field. **305 of 642 processes (47%) reported an exec path that does not exist on disk.** `classify_signature()` answers `missing` for a path that isn't there; `is_risky_location()` answers `False` for a binary genuinely running out of a risky directory. The process sensor was scoring a prefix. | 305/642 exec paths nonexistent; a real Mach-O at a 50-char `/tmp` path scored `is_risky_location=False` | asked for on its own, `comm` is the full path (measured intact at 119 chars) — so two `ps` calls joined on pid. After: **21 of 627**, and those remaining are processes for which macOS genuinely reports a bare name or relative path, not truncation |

P1 is the finding this pass exists to have produced, and it was **pre-existing** —
nothing about the protective tier caused it. It surfaced only because a new
feature happened to depend on the same field, which is the argument for building
the guard rather than assuming the old one worked.

The log's standing lesson applies exactly. The suite had tests for the process
sensor, and they passed, because every one of them fed a **canned `ps` line in
the format the code expected**. The fixture inherited the code's belief about
what `ps` returns. Only the system disagreed — and it took running against the
real process table to hear it. The regression test added here therefore asserts
against the **live** process table (ratio of exec paths that actually exist), not
against a fixture, precisely so it cannot re-inherit the assumption.

Three existing tests had to be updated with it, and that is worth stating plainly
rather than burying: they stubbed `aegis.run` to return the single-call `ps`
shape, so they broke the moment the real call changed. Their assertions were kept
verbatim; only the canned output shape moved. One of them
(`test_spaced_exec_path_still_flagged`, for an attacker who copies `osascript` to
`/tmp/Sys Update`) is materially *better* served by the two-call form, because
`comm` is now the whole remainder of its own line and can no longer be sheared at
the space.

## Defects introduced by this pass and caught before merge

| # | Sev | Defect | Caught by |
|---|-----|--------|-----------|
| P2 | **HIGH** | Freeze inherited `_PROTECTED_COMMS` wholesale, which carries `python`/`python3` as a blunt proxy for "do not kill Aegis itself". Correct for an irreversible verb reached by name; wrong for freeze, which already refuses its own pid and every ancestor structurally. It refused to suspend **any** python process — and interpreted payloads are a large share of what the tier exists to contain. | Linux CI. macOS hid it: `ps` spells the framework binary `Python`, the set lists `python`. |
| P3 | **HIGH** | The Windows clipboard substitution ran `Set-Clipboard -Value $input`. `$input` is the *pipeline* variable and nothing is piped in, so the "replace with an inert notice" path would have silently **cleared** the clipboard — destroying the payload the incident record promises is restorable, at the moment the user is mid-paste. | Inspection. No test could see it: `TestClipboardBehaviour` stubs `_clipboard_write` to avoid touching a real clipboard. |
| P4 | **MEDIUM** | `ctypes` defaults `restype` to C `int` (32-bit) but a Win64 `HANDLE` is a 64-bit pointer, so `OpenProcess`'s handle was truncated on return and handed back to `NtSuspendProcess`/`CloseHandle` at the wrong width. Survives by luck because Windows hands out small handle values — the shape of defect that passes review and fails on someone else's machine. | Inspection. CI structurally cannot reach it (see Residual risk). |
| P5 | **MEDIUM** | `_freeze_refusal` walked the process table **twice per pid** (owner via `_process_identity`, names via `_process_names`) and is called once per descendant during a tree sweep. On Windows one walk is a CIM query this repo already measured at 41s for 135 processes, so freezing a five-process tree would have spent minutes in enumeration — for a verb whose entire value is landing before the payload finishes. | Reading the call sites against W4's own measurement. |
| P6 | **LOW** | The notary's macOS anchor read-back used an `eventMessage CONTAINS` predicate: a full-text scan of the archive, measured at **>120s** against a 1.7GB store. `process == "logger"` is indexed and returns the same set in ~4s. | It hung the first end-to-end run. |

## Two tests that were green and proved nothing

Worth recording separately, because a test that cannot fail is worse than no
test — it reports coverage that does not exist:

- `test_freeze_refuses_another_users_process` hard-coded uid `0` as "another
  user". CI and containers run the suite **as root**, so `0` was this process's
  own owner and the guard correctly allowed it. It now derives an owner that
  cannot be us whoever we are.
- The first draft of the notary tests asserted only that an edited chain fails
  verification. That is the easy adversary. The one that matters can read
  `hmac.key` — 0600 is no barrier to the file's owner — and recompute every head
  and MAC until the chain is internally flawless.

## The claim the notary actually makes

Tested against that second adversary rather than the first: a chain forged with
every head and MAC recomputed **defeats all local checks** — internal
verification caught 0 — and is still caught by the anchors already sitting in the
root-owned log store, which caught 2. That asymmetry is the whole design, and it
is why the claim is split in the docs rather than rounded up:

- **erasure-resistant** — removing an anchor needs root, so a sequence gap is
  real evidence, including the gap left by killing Aegis;
- **only partly forgery-resistant** — a same-uid attacker with the key can write
  a consistent local chain and matching new anchors.

What they cannot do is make a *past* anchor say something else. This is the
specific failure that kills unprivileged Tripwire/AIDE clones — the checker and
the checked share a trust boundary — and the only thing that closes it is a
witness in a domain the adversary does not hold.

## Verification actually performed

- Freeze asserted on **work a child process performs**, not on a process-state
  string: a child that writes a file after 1s produced nothing while frozen and
  wrote it after `thaw`.
- Notary anchors round-tripped through the **real macOS unified log**
  (`ok:2-anchors-matched`), not a stub.
- FIFO decoy detected a genuinely blocked reader as CRITICAL with its pid
  resolved.
- All six assay lanes pass, including a real quarantine → restore byte-exact
  round trip.
- Clipboard grammar: rustup's documented `curl … | sh` stays *suspect* and is
  never rewritten; the `\r` variant escalates to *certain*.
- 537 tests on macOS · 420 on Linux 3.9 and 3.12 in containers · full CI matrix
  green including **Windows 3.9 (20m) and Windows 3.12 (33m)** on a real kernel.

## Residual risk

- **P1 is closed at the source.** `_iter_processes()` now returns untruncated
  exec paths, so `cmd_kill`'s guard, `check_processes()`, listener attribution
  and the freeze guard all consume a correct value. The residue is that macOS
  reports a bare name or relative path for ~3% of processes (`autofsd`,
  `./externals/node20/bin/node`); that is what `ps` genuinely knows, not a
  truncation, and those paths are simply not classifiable.
- **Two Windows paths are implemented and reviewed but never executed.**
  `NtSuspendProcess` (the freeze tests are POSIX-only by construction) and the
  clipboard substitution (the harness never touches a real clipboard). They are
  pinned structurally — the prototypes and the `$env:` channel are asserted from
  source — which is strictly weaker than execution and must not be read as
  equivalent. A green Windows matrix does **not** cover them.
- **Freeze contains, it does not rewind.** It stops new reads, connections and
  forks; bytes already handed to the kernel's socket buffers still transmit.
- **A source-aware attacker can kill Aegis rather than evade the freeze.** No
  unprivileged tool prevents that. The notary does not stop it either — it makes
  it leave a gap that cannot be backfilled, which is a different and lesser
  claim, made deliberately.
- **Linux latches are a speed bump.** No unprivileged immutable flag exists
  (`chattr +i` needs `CAP_LINUX_IMMUTABLE`), so a same-uid attacker chmods back.
  The tamper signal is the value there, not the block.

---

# Aegis — first real-Windows run (2026-08-04): CI + a live-hardware harness

The cross-platform port shipped with one residual risk software could not close:
**no line of the Windows code had ever executed on Windows.** The parsers were
tested against captured real command output and `_snapshot_persistence_windows()`
ran end-to-end only against an injected fake `winreg`. That caught structural
defects. It could not catch anything that depends on what real Windows returns.

This pass added CI (the repo had none) and a Windows-only live harness, then
fixed what real Windows exposed. It took **seven CI runs**, not one: each round
of fixes let the harness reach further into the code and surface the next
defect. The two sensors that had never worked (W2, W3) were only reachable once
the crash in W1 was out of the way, and W6 was only visible once the harness's
own wrong assumption about catalog signing (below) was corrected.

## Why a fake registry was never going to be enough

Two of the defects below were **invisible to the existing tests because those
tests shared the bug's own assumption**:

- the fake-registry fixture was built from the same Winlogon constant aegis
  used, so it agreed with the typo and passed;
- the process-table tests fed tab-separated fixtures straight to the parser and
  never executed the PowerShell that was supposed to produce them.

A simulation inherits the author's model of the system. Only the system itself
disagrees.

## What the harness executes (`tests/win_live_harness.py`)

Opt-in via `AEGIS_WIN_LIVE=1`; it registers a real scheduled task and writes a
real registry value, both under names it owns, both removed in `finally`. State
is sandboxed into a throwaway `USERPROFILE` before `import aegis`; the registry
and Task Scheduler deliberately are **not** sandboxed, because they are what is
under test.

Real `Get-AuthenticodeSignature` (including a tampered copy of a signed system
binary) · real `Win32_Process` + `GetOwner` · a real enumeration of the real
Run/Winlogon/Services hives · the full `schtasks` lifecycle: register → query →
parse back out of real CSV → disable → delete → uninstall · the PowerShell
probes' no-false-empty contract · two full scans · and `aegis.py report` with
its stdout redirected to a pipe.

## Defects found and fixed

| # | Sev | Defect (proven on real Windows) | Before | After |
|---|-----|--------------------------------|--------|-------|
| W1 | **CRITICAL** | `write_report` opened `latest.md` in text mode with no encoding, so Python used the locale codec. On Windows that is cp1252, and every report line starts with a severity icon. `scan` found the threat, then **died with UnicodeEncodeError instead of reporting it**. | crash | 20 text-I/O sites pinned to UTF-8; `run()` decodes with `errors="replace"`; Windows stdout/stderr reconfigured (a scheduled task and `report > out.txt` both redirect, which is exactly where Python falls back to cp1252) |
| W2 | **CRITICAL** | Winlogon read from `Software\Microsoft\Windows\CurrentVersion\Winlogon`. The real key is under **`Windows NT`**. `winreg` raised, `_reg_values` swallowed it, so the Shell/Userinit hijack check (T1547.004) inspected an empty set on every Windows host it ever ran on. | 0 values read | `_WIN_LOGON_KEY`, asserted to contain `Windows NT`; the fake-registry fixture now keys off the same constant so it can never re-encode the typo |
| W3 | **CRITICAL** | `_WIN_PROC_PS` joined fields with a backtick-t inside a **single-quoted** PowerShell string, where backtick is not an escape. Every line came back as one field, every line failed the 4-field check: `_iter_processes()` yielded **zero processes, always** — no process surface, no argv scoring, no owner for listener attribution. | 0 processes | built with `[char]9` (which also avoids the double quotes CreateProcess argument quoting would mangle); pinned by a class guard — no PowerShell snippet may contain a backtick escape |
| W4 | **HIGH** | A failed signature probe was indistinguishable from a verdict of "fine". A cold `Get-AuthenticodeSignature` measured **21.4s and 28.8s** on two separate runs, against a 30s ceiling; on timeout `_classify_windows` returned `trust="unknown"`, and `suspicious_sig("unknown")` is `False` — so a timed-out probe rendered every unsigned **and every tampered** binary un-suspicious, and cached it until the file's mtime changed. | tampered binary → `unknown` (not suspicious), cached | 90s timeout; a failed probe is marked, never cached, and counted into a `signature.classify` DEGRADED sensor entry so a clean report cannot be read as "nothing found" when it means "I could not check N of them" |
| W5 | **HIGH** | `schtasks /query /fo csv /v` does not double the quotes inside its Task-To-Run column, so a conforming CSV reader returns `C:\p\x.exe" args"`. The program resolved to a path with a trailing quote: no trusted-prefix match, `sha256` None, trust `missing` — a task pointing at a real payload was scored against a path that does not exist. | `program` = `…pythonw.exe"`, severity `None` | `_win_strip_quotes` trims stray quotes; a quote is an illegal Windows filename character, so this cannot damage a legitimate path |
| W6 | **HIGH** | Real `Get-AuthenticodeSignature` answers `UnknownError` for a non-PE or corrupt image — a status named in no branch, so trust fell through to `unknown`, which `suspicious_sig()` does not flag. A script renamed `.exe`, or a corrupt/truncated dropper, was un-suspicious on Windows while macOS called the identical file `unsigned` and flagged it. | text file named `.exe` → `unknown` (not suspicious) | an ANSWERED probe whose answer is not a valid signature is `unsigned`; `unknown` is now reserved for the one case with genuinely no answer — a **failed** probe, which is marked, never cached and counted as DEGRADED |

## What the live run showed AFTER the fixes

Captured from the harness on `windows-latest`, same evidence standard as the
Linux siege — the before/after column is the same harness, two runs apart:

| Check | Before | After |
|---|---|---|
| Real `winreg` Winlogon read | `FileNotFoundError [WinError 2]` | real `Shell`=`explorer.exe` and `Userinit`=`C:\Windows\system32\userinit.exe,` read and matched against `_WIN_LOGON_EXPECT` — **no false deviation on a healthy host** |
| Persistence snapshot | 1 surface | **14 entries** across run-key, service, startup and task |
| `_iter_processes()` | **0 processes** | **135 processes**; own PID present, `GetOwner` → `runneradmin`, `_same_owner` true, absolute exe path, real argv; 109 of 135 correctly outside the same-user response boundary |
| Planted HKCU Run value | not reached | enumerated back out of the real registry with its program expanded from `%APPDATA%` |
| Real scheduled task program | `…\pythonw.exe"` (stray quote) | `…\pythonw.exe` |
| `schtasks` lifecycle | register/query/disable/delete/uninstall all correct | unchanged — the one surface that worked first time |
| Defender/BitLocker posture, exclusions, WMI subscriptions, listeners | real values, no false-empty | unchanged |
| Two full scans + `aegis.py report` into a pipe | rc 0, no storm, report written | unchanged |
| **Tamper gate** (the Windows analog of the macOS strict-verify rule) | never exercised — the harness copied a *catalog*-signed binary, whose copy reports NotSigned before anything is tampered with, so the test proved nothing | copy of an **embedded**-signed binary (`python.exe`, Python Software Foundation) with one byte flipped → **`trust: 'broken'`**, `suspicious_sig('broken') = True` |
| Windows suite | 28 failed → 4 failed → 2 failed | **337 passed, 137 skipped, 0 failed** |
| Suite wall time | >45 min (job cancelled at the ceiling) | **~14 min** |

## Test-suite defects the same run exposed

- `TestEventIncidentCore._rows` leaked its sqlite connection. `with
  sqlite3.connect(...)` commits the transaction; it does **not** close the
  connection. Invisible on POSIX (an open file can still be unlinked),
  `WinError 32` on Windows.
- `test_schema_is_idempotent_and_private` asserted mode `0o600` on the event DB.
  Windows has no POSIX mode — `os.chmod` there only toggles the read-only bit —
  so the assertion is now POSIX-scoped and states the Windows model (the
  inherited `%USERPROFILE%` ACL, the same owner+administrators boundary `0o600`
  leaves to root) instead of asserting a fiction.
- `Sandbox` did not isolate Windows persistence. Every other live-host source is
  pinned behind a path or a command, which suffices on POSIX because persistence
  there is files; the registry, the service hive and Task Scheduler cannot be
  redirected into a tmp dir, so sandboxed scans read the runner's real autostarts
  and notified HIGH on them.
- 20 POSIX-shaped cases (literal `/tmp` paths, setuid, cron, utmp sessions,
  `sudo -u`/`caffeinate` wrappers, the `/private/tmp` firmlink pair) are now
  skipped on Windows **only**, keyed by test name. They were deliberately *not*
  added to the macOS-only class list, which would have silently deleted their
  Linux coverage.

## Measured cost of running on Windows

Process spawning is far more expensive here than on POSIX, and on Windows every
signature classification spawns a `powershell.exe`. That is the same cost that
made W4 matter — a cold classification is *seconds*, not milliseconds — and in
production it is bounded by the signature stat-cache exactly as `codesign` is on
macOS.

In the suite it was not bounded by anything, because signature classification
was the last live-host source `Sandbox` did not pin: every persistence record
classifies its program, so a few hundred fixture files became a few hundred
PowerShell start-ups. Raising the probe timeout to 90s (required by W4) pushed
that past the job ceiling and the Windows jobs were cancelled mid-run. Pinning
`classify_signature` in the sandbox took the suite from **>45 min (cancelled) to
14:12**. The pinned verdict is not a fiction: a plist/txt fixture is not a PE,
real `Get-AuthenticodeSignature` answers `NotSupportedFileFormat`, and
`_classify_windows` maps that to exactly `unsigned` — same verdict, no
subprocess.

## State when W1-W6 closed (captured, not asserted)

Superseded by the follow-up section below, which carries the final numbers.
`windows-latest / py3.12`, the first run where both Windows jobs went green:

- test suite **339 passed, 137 skipped, 0 failed** (876s);
- live harness **`checks failed: 0`** — 35 passing checks against the real
  machine, plus 6 environment notes recording what the runner is (Defender off,
  Security log unreadable, timing);
- macOS **476 passed**, `selftest.py` green, 3.9-compatible;
- Linux 3.9 and 3.12, macOS 3.12 green.

Of the 13 new tests, the ones that pin a defect were each verified to FAIL
against the pre-fix source before being trusted — the encoding pair, the seven
in `FoundOnRealWindows`, and the `UnknownError` mapping. The remaining ones are
positive controls (caching still works; `Valid`/`HashMismatch`/`NotTrusted`/
`NotSigned` still map unchanged) and are expected to pass both ways.

## Residual risk

- A GitHub-hosted `windows-latest` runner is a **real Windows kernel with a real
  registry, real Task Scheduler, real PowerShell and real Authenticode**, which
  is what the three named unknowns needed. It is **not** a domain-joined
  workstation: the runner has Defender real-time protection and tamper
  protection OFF, its Security event log is not readable by the harness's
  principal (correctly reported DEGRADED, not silently empty), and no Group
  Policy applies. Behaviour under an enterprise policy set remains unproven.
- Windows sensor coverage is only as good as what an unprivileged process can
  read. The Security event log needed a principal the harness did not have, and
  that surface reports DEGRADED rather than pretending to be clean — correct,
  but it is a real gap on any machine where Aegis runs unelevated.

## Follow-up in the same session: one more dead sensor, and the batching

Two things were closed after the entry above was first written.

**W7 — the process table failed silently.** `_iter_processes()` returned an
empty generator when its probe failed, and downstream "no processes" reads as
"nothing suspicious is running": the same false-empty this repo already refuses
for sfltool/BTM and the Defender probes, sitting in the sensor W3 had just
brought back from the dead. Not hypothetical — the harness measured **41.0s for
135 processes** against what was then a 60s ceiling, and that measurement was
first filed as a "thin margin" note rather than as the defect it was. The
Windows query now gets 180s, and a failure on either the Windows or the macOS
path records `process.enumerate` DEGRADED.

**Batching, which the previous version of this section said had deliberately
not been attempted.** It has been, and the reasoning that deferred it — no
measurement, and it touches the trust path — was answered rather than ignored:

- the measurement exists (a cold `powershell.exe` at 21-29s, and every
  classification is its own start-up);
- the trust path is untouched, because `warm_signature_cache()` only seeds the
  cache with verdicts the per-path probe would have produced. Both routes go
  through one shared `_win_verdict()`, pinned equal across all six statuses. A
  failed batch caches nothing and every path falls back; a row with no status is
  a non-answer and is never cached.

Proven positively on real Windows rather than inferred from a green run — which
matters here, because the fail-soft design means a *broken* batch would have
left every other check passing. Section 1b of the harness resolves six real
System32 binaries and asserts the count, the caching, that the verdicts are real
signature answers rather than defaults, and that batch and single-path agree:
**6 of 6 in one start-up, all `os-signed`, identical to the single-path probe.**

It is wired into all three Windows cost centres — processes, the persistence
snapshot (two-phased so all five autostart sources share one resolve), and hot
dirs. Deliberately not wired into the macOS sites (`codesign` is milliseconds
and the prefetch is a Windows no-op) or the listener/outbound sites (a handful
of paths, already behind resolvability guards).

Final state: macOS **487 passed**, Windows **350 passed / 0 failed**, harness
**`checks failed: 0`**, all five CI jobs green on `main`.

---

# Aegis — Cross-platform port (2026-08-03): macOS + Linux + Windows

Aegis became system-agnostic in this pass: one stdlib-only file that detects its
OS at import and selects the sensor registry, path tables, trust model,
scheduler and change-detection mechanism for that platform. The bar was not
"it imports on Linux" — it was **"it actually defends that machine"**, proven
by planting real attacks and watching them get caught.

## Verification actually performed

**macOS** — full suite 422 passed; `selftest.py` green natively.

**Linux (live, in-container, nothing mocked)** — a 40-assertion siege that
plants real artifacts against the real OS and asserts severity:

| Planted attack | Result |
|---|---|
| systemd user unit with `ExecStart=/bin/bash /tmp/payload.sh` + `LD_PRELOAD` | CRITICAL |
| XDG autostart `.desktop` (Hidden=true) executing from `/tmp` | CRITICAL |
| live `curl http://…/a.sh \| bash` process | HIGH (`fileless-fetch-exec`) |
| process executing from `/tmp` | HIGH |
| binary deleted while still running (run-then-unlink) | HIGH |
| cron running a hidden `$HOME` script | HIGH |
| executable ELF dropped in `/tmp` | HIGH |
| staged `shadow.bak` loot | HIGH |
| new setuid-root binary (`/usr/local/bin/rootme`, mode 4755) | CRITICAL |
| `/etc/ld.so.preload` rootkit write | HIGH |
| newly loaded kernel module | HIGH |
| real non-loopback listener on `0.0.0.0:18081` (via `/proc/net/tcp`) | detected |
| loopback-only listener on `127.0.0.1:18082` | correctly IGNORED (no FP) |
| hostile line appended to `~/.bashrc` | HIGH |
| 12× SSH `Failed password` + `useradd` in `auth.log` | brute-force + new-account HIGH |

Plus: full `scan` writes report/DB/heartbeat and opens incidents; a second scan
does not storm duplicates; quarantine→restore round-trips byte-for-byte;
`/etc`, `$HOME` and `/usr/bin/python3` are refused as protected paths.

**Linux install lifecycle (real systemd, PID 1, unprivileged user session)** —
`aegis.py install` enabled `aegis.timer`; the timer **fired unattended**
(`Result=success`, `ExecMainStatus=0`) and produced a report, baseline, DB and
heartbeat. Then, simulating an attacker: `systemctl --user disable --now` →
self-protection reported **HIGH "Aegis systemd unit is not scheduled"**;
deleting the unit files → **HIGH "Aegis systemd unit is missing"**. A
*deliberate* `aegis.py uninstall` correctly stayed silent (uninstall is not
tampering) and kept the evidence. Generated units pass `systemd-analyze verify`
with zero warnings.

**Cross-distro** — `scan` completes cleanly on Debian slim, Alpine (musl) and
Fedora (rpm). The Linux process/listener sensors read `/proc` directly, so they
work on minimal images with no `procps` installed.

**Windows** — unit-tested against **captured real command output**
(`schtasks /query /fo csv /v`, `netstat -ano`, `Get-MpComputerStatus`,
`Get-WinEvent`), not executed on Windows. That is the honest limit of the
current evidence and it is stated as such in the README rather than implied
away. 78 cross-platform tests cover the parsers, the Defender/firewall/BitLocker
scoring, WMI-subscription and exclusion diffs, the LOLBin/encoded-PowerShell/
LSASS-dump idioms, and the false-positive guards.

> **Superseded 2026-08-04** — see the first entry in this file. Windows now runs
> in CI against a real kernel. Reading this paragraph as a standing claim would
> also mean trusting the confidence in it: those 78 tests were green while three
> Windows surfaces produced nothing at all, because two of the fixtures were
> built from the same assumptions as the bugs.

## Genuine defects found and fixed during the port

1. **Persistence severity under-rated the dominant shape.** Scoring keyed only
   on `program`, so `ExecStart=/bin/bash /tmp/payload.sh` scored on
   `/bin/bash` — a trusted path — and returned HIGH instead of CRITICAL. Risk is
   now evaluated over the program **and** its script target. Deliberately scoped
   to *volatile* targets only: a helper script under `~/Library`/`~/.config` is
   ordinary for real software, and escalating that would flatten the scale (the
   macOS `bash ~/.agent` case stays HIGH, as its pinned test requires).
2. **`privileged-group-add` never matched.** `\b-G\b` cannot match ` -G ` —
   a space followed by `-` is not a word boundary — so a real
   `usermod -G sudo backdoor` line was invisible. Caught by a test written
   against a real log line.
3. **Unattributable listener scored as a deleted binary.** A listener that
   cannot be attributed without root is recorded as `"?"`; `_exec_alert` then
   found no such file and reported "deleted-while-running" — a false positive on
   every root-owned listener. Now non-absolute paths are never scored.
4. **`_expand_win_env` was silently a no-op off-Windows.** It used
   `os.path.expandvars`, which only understands `%VAR%` on Windows, making the
   registry-autostart path untestable elsewhere. Replaced with an explicit
   `%VAR%` expander so the Windows path behaves identically — and is provable —
   on any host.

## Design decisions worth keeping

- **A sensor with no meaning on a platform is ABSENT, not DEGRADED.** Reporting
  a launchd check as a failed sensor on Linux would manufacture a permanent fake
  coverage gap and train the operator to ignore health warnings.
- **Linux does not get a fake signature model.** There is no ambient code
  signing; package-manager ownership is the honest analog, and `unmanaged` is
  *not* treated as malicious (every locally built binary is unmanaged). Linux
  keys its exec signal on structure instead — volatile-dir execution, or a
  running binary unlinked from disk.
- **No inotify dependency.** Linux/Windows poll the same watched path set every
  5s rather than take a third-party dependency; the single auditable stdlib-only
  file is load-bearing for security review.
- **macOS-era tests were scoped, not weakened.** 28 genuinely macOS-specific
  test classes (kqueue, `.app` bundles, BTM, codesign verdicts) are skipped
  off-macOS via `tests/conftest.py` rather than diluted into platform-agnostic
  mush that would delete real macOS coverage.

## Follow-up pass — closing the port's own residual risks

The port shipped with four named residual risks. Three were closed by finding
real defects behind them; the fourth (no Windows hardware) was reduced as far as
software can reduce it. Each was baselined with a failing reproducer at HEAD
before any edit.

| # | Defect (proven at HEAD) | Before | After |
|---|---|---|---|
| A | `check_auth_log` returned DEGRADED when the journal was **readable but empty** — `rc==0` with no matching sshd/sudo/useradd lines was indistinguishable from "cannot read". On any quiet box with a root-only `auth.log` this opens a false recurring *"Security coverage degraded: auth-log"* HIGH incident after 3 scans. | `None` (DEGRADED) | `[]` (OK) |
| B | Three Windows probes returned a **false-empty** on probe failure — exactly the bug class the repo already fixed once for `sfltool`/BTM. A blocked execution policy made `snapshot_win_exclusions`/`snapshot_wmi_subscriptions` return `{}` (adopting an empty baseline, so every real exclusion/subscription storms as "newly added" the first time PowerShell succeeds) and `check_windows_event_log` return `[]` (reporting security coverage it does not have). | `{}` / `[]` | `None` (DEGRADED) on any non-zero exit; `rc==0` with no output still `{}` |
| C | An unattributable Linux listener reported `path='?'` and nothing else. Attributing a socket to a *pid* needs root — but the socket's **uid is in `/proc/net/tcp` itself**, free. | `? is accepting connections on TCP port 22` | `an unattributable process (uid 0 — attributing it to a pid needs root) is accepting connections on TCP port 22` |
| D | `_snapshot_persistence_windows` had **never executed a single line** off Windows — the parsers were tested, the winreg enumeration loops, Winlogon deviation rule, startup-folder walk, `schtasks` call and service filter were not. | 0 executions | 9 tests execute the real function end-to-end against an injected fake `winreg` |

C is deliberately keyed so it cannot storm: the uid rides in the snapshot
**value**, never the key, and `diff_listeners` has no `changed_fn` — so an
upgrade re-keys nothing and already-baselined listeners stay silent. Both the
new dict form and the legacy bare-string form are handled, and all three cases
are pinned by tests.

Live-verified on Linux: a socket owned by another user reports
`uid 1000` from real `/proc/net/tcp`, not a guess.

Also removed two functions this port orphaned (`_is_macho`, superseded by
`_executable_kind`; and an unused `_APPLE_DAEMON_NAMES` back-compat alias) —
dead code in security-review-critical paths is a review hazard.

Verification after the follow-up: macOS 442 passed (+20), Linux 325 passed /
117 skipped, live siege 40/40, `selftest.py` green on both.

## Residual risk

- Windows still has no hardware run. The live plumbing is now *executed* against
  a simulated registry (D), which catches structural defects, but a fake winreg
  is not Windows: the first run on real hardware remains the outstanding
  validation step for `schtasks` registration, CIM owner lookup, and
  Authenticode verdicts.
- `check_auth_log` still degrades honestly where `auth.log` is root-only **and**
  no journal is readable — that is a genuine permission boundary, not a bug.
- Linux listener attribution still cannot resolve another user's *pid* without
  root; it now names the owning uid instead of guessing.

---

# Aegis — Battle-Test pass 5 (2026-07-24): fileless-pipeline EVASION closure

`/battle-test` (no arg → target = repo). **Tier: siege** (the response tier can
`quarantine`/`neutralize`/`destroy`). Framing held from the start: *surface a real
gap or report "already robust" — never fabricate.* Every oracle was derived from
README/ARCHITECTURE **intent** and the suite's own codified severity contract
(`test_fileless_fetch_exec_combo_is_high`: `curl … | bash` = **HIGH**); captured
stdout + a runnable probe were the only evidence. Unlike pass 4, this pass found
**2 genuine, proven root-cause gaps in detection efficacy** → fixed via surgical
regex change + 8 pinned regression tests → **shipped**.

## The question this pass answered

The operator asked the load-bearing question directly: *"is this actually
protection?"* So the hunt targeted **detection efficacy** (does a check fire on the
real TTP, and can a source-reading attacker trivially evade it?), not just code
correctness. A Breaker probe called the **real** `_argv_signals` / `_hostile_content`
functions with crafted argv — 4 positive controls (canonical `curl|bash`, osascript
phish, `/dev/tcp` reverse shell, keychain-db copy) **all fired correctly** (the
detections are real), then evasion variants were tried.

## What was attacked — captured-output evidence

| Lens | Finding | Result |
|------|---------|--------|
| **Behavioral argv scorer — evasion (Breaker probe, runnable repro)** | **Gap A:** the `pipe-to-shell`/`pipe-to-interpreter` idioms matched only a bare or `/bin/`-prefixed interpreter, so `curl … \| env bash`, `\| /usr/bin/env bash`, `\| /opt/homebrew/bin/bash`, `\| env sh` — the **identical** fileless pipeline the suite pins as HIGH — dropped to a **silent MEDIUM** with a 4-char change any reader of this open-source regex can apply. **Gap B:** interpreter-**native** fetch (python `urllib`/`http.client`/`requests`, ruby `open-uri`/`Net::HTTP`, perl `LWP`, node `require('https')`) + `exec()` produced **no signal at all**, despite python being a watched interpreter and fileless-interpreter payloads being the tier's *stated purpose*. | **Both fixed.** `_PIPE_LAUNCH` now lets the pipe idioms step over an `env` launcher (with flags/`VAR=val`) or an absolute path; new `interp-fetch` (FETCH idiom) + `exec-eval` (PIPE-EXEC idiom) reuse the existing fetch+exec→HIGH combination, so interpreter-native download-and-exec fires HIGH exactly like `curl\|bash`. |
| **FP discipline (the fix must not over-fire)** | The fix's risk is a false-positive storm on benign interpreter use. | **Clean.** Full suite **318/318** (was 310 + 8 new). FP guards preserved: perl/sed quoted-alternation `s{(rm\|node)}` still not a pipe; lone `curl` (no exec) stays MEDIUM; download-**to-disk** via urllib (no in-command exec) stays MEDIUM (a file-drop caught by the hot-dir/path-lineage surface); local decode+exec with no network stays MEDIUM. `exec-eval`'s `\s*\(` never matches shell `exec bash` or `eval "$(…)"`. |
| **Live end-to-end scan** (sandboxed `$HOME`, detect-only, real host data) | Does the whole plumbing run, and does the new idiom behave in the wild? | **Clean (exit 0).** Coherent report; real state classified correctly (docker/MS/Zoom helpers = developer-id LOW, adhoc node/Hermes = HIGH process). A real `perl` process matched the new `exec-eval` at **MEDIUM — did NOT notify and did NOT open an incident** (the 4 incidents are pre-existing adhoc-binary findings). The FP discipline holds live: the new corroborator logs but never alerts alone. `btm` honestly reported DEGRADED. |
| **Siege §Side-effect-safety (structural)** | Confirm the fix touched no response path and the detect-only invariant still holds. | **Solid.** Response sinks (`kill`/`quarantine`/`destroy`/`_remove_object`) reachable **only** from `main()` argv dispatch + `cmd_neutralize`'s own chain — no `check_*`/scan path reaches them. `_is_protected_path` still refuses SIP/system/HOME+ancestor/Aegis-own/symlink. This pass changed **only** pattern regexes + two idiom sets; no response code touched. |

## End-state checklist (each box backed by captured output)

- ▢→✅ **bugs/logic errors found → fixed:** Gaps A & B, both root-cause, both fixed in the shared `_HOSTILE_CONTENT_RES` table (propagates to behavioral + shell-history + shell-rc + launchd-arg surfaces at once).
- ✅ **edge cases found → regression-pinned:** 8 new tests in `TestFilelessEvasionClosure` (3 pinned the gaps and **failed against pre-fix code**, verified; 5 pin the intentional boundaries + FP guards).
- ✅ **no unimplemented files/stubs remain:** completeness pre-flight clean (0 TODO/FIXME/NotImplementedError/`...`).
- ✅ **security lens run:** inline (watchdog binary absent) — no new sinks; change is regex-only, response tier untouched and re-verified detect-only.
- ⚠️ **`/spar` not separately invoked:** the Breaker's runnable-repro duty was discharged inline by the `probe_behavior.py` probe against the real functions (4 passing positive controls = the mutation-validation that the oracle isn't a tautology). Noted honestly rather than claimed.
- ✅ **verified:** new tests fail→pass; full suite **318/318**; `selftest.py` **7/7**; live scan exit 0 with correct MEDIUM-not-notify behavior for the new idiom.

## Stop-gate (why the loop ended)

Two genuine improvements found, proven with a runnable repro, fixed, and pinned;
the fix is surgical (one shared table + two frozensets, +92/−4 lines) and the full
suite is green with **zero FP regression** confirmed both in-suite and on a live
scan. The highest-yield remaining surfaces (response-tier safety, the structural
Team-ID/typosquat/provenance checks) were spot-checked and are sound by design —
hard-to-vary invariants, not string patterns. Right-sized: further rounds on a
mature 5-pass tool have declining marginal yield.

## Residual risk / notes

- **Gap B is scoped to the fetch+exec _combination_** (mirroring the curl rule):
  interpreter-native fetch **alone** or `exec()` **alone** stays MEDIUM (won't
  notify), to keep pip/package-manager fetches and benign `perl -e 'eval(...)'`
  below the notify floor. A payload that fetches and execs across **two separate
  processes** is caught by the path-lineage correlation, not this single-argv
  scorer — by design.
- The new `interp-fetch` token list is pattern-based (the same open-source-readable
  limitation the README already owns); it raises the evasion cost (an attacker must
  now avoid `env`, absolute paths, curl/wget/nscurl/fetch, AND the common native
  HTTP-client tokens) without claiming to be exhaustive.

---

# Aegis — Battle-Test pass 4 (2026-07-23): dry re-siege — nothing genuine to fix

`/battle-test` (no arg → target = repo). **Tier: siege** (the response tier can
`quarantine`/`neutralize`/`destroy` — irreversible side effects — so the top tier
applies). This is the **fifth** adversarial pass on a tool whose every surface,
including the same-day #4/#5 correlation-lineage work, was already hunted. The run
was framed honestly from the start: *surface a genuinely new defect or report
"already robust" — never fabricate an improvement to justify shipping.* Every
oracle was derived from README/ARCHITECTURE intent; captured stdout + exit code
was the only evidence. **Outcome: 0 genuine improvements survived → `/doit` and
`/launch` deliberately NOT invoked** (a no-op ship is the skill's explicit red flag).

## What was attacked (all dry) — captured-output evidence

| Lens | Why it was the highest-yield choice | Result |
|------|-------------------------------------|--------|
| **Recurring firmlink / path-canon class (F6)** | This exact bug class has now recurred **twice** (pass 1 `is_risky_location`, pass 3 the four join keys) — a class that recurs twice signals a probable third instance. | **Closed at all three sites.** `is_risky_location` (both `/tmp`+`/private/tmp`, `/var/folders`+`/private/var/folders` in `RISKY_PREFIXES`), `_canon_entity_path` (`_MACOS_FIRMLINKS` = `/tmp`,`/var`,`/etc`), and `_hidden_home_or_tmp` (explicit both-form tuple). No third instance. |
| **Live end-to-end scan under the AGENT interpreter** (`/usr/bin/python3` = **3.9.6**), real host data, state sandboxed into a throwaway `$HOME`, `notify` inert | The prior passes' **own repeated lesson**: the on-machine run — not the suite — is what exposes the highest-severity deployment-class defects (P3-4/5/6 CRITICAL, D-1 the 3.9-only crash). The suite runs on dev-python 3.12; this interpreter gap is the biggest real blind spot. | **CLEAN.** 3 consecutive scans, **no exceptions**; scan #1 fired 1 correct first-run process alert; warm scans #2/#3 fired **0** notifications (**no P3-4 alert storm**); `snapshot_btm` returned **`None` on slow-failure** (skip, not adopt-and-storm — the P3-4 fix holds; sfltool wedged ~17s); `doctor` honestly reported `surface.btm DEGRADED`, not silently clean. |
| **Risk / lineage / corroboration numerics** (the newest layers) | Numeric/stateful code is where README-intent oracles under-test edge cases; the documented **single-sensor guarantee** is an invariant a subtle change could silently violate. | **Sound.** Single-sensor path keeps the original bar (`min_signals`/×1.0 unchanged); corroboration gated on ≥2 **distinct categories**; `_canon_entity_path` applied at the join; per-category dismissal weight floored. No regression. |
| **Security sinks** (inline — `watchdog` binary absent) | First-class lens; #4/#5 added code since the last security review. | **CLEAN.** Zero real sinks — the only `eval` hit is a comment describing a malware IOC the tool *detects*; both `subprocess` sites are list-form via `_trusted_command` with fixed PATH/env; no `os.system`/`shell=True`/`pickle`/`yaml.load`. |
| **Siege §Side-effect-safety guard self-test** (mandatory) | Highest-stakes surface: irreversible `destroy`/`quarantine`. The skill requires attempting a known-forbidden action and asserting it is blocked, each run. | **13/13 forbidden irreversible actions refused** (quarantine of `$HOME`/ancestor/`/System`/SIP file/Aegis's own script/symlink/hard-link/plain dir/nonexistent; `destroy` without `--yes`; `destroy` a non-quarantined id; `kill` pid 0/1) **+ a legit quarantine succeeds** (positive control — the guard is not refuse-everything). Restore byte-for-byte round-trip is pinned green in the suite. |
| **Full regression suite under BOTH interpreters** | The D-1 class (dev-python passes, agent-python crashes) is only caught by running under 3.9. | **306/306 under 3.12 AND under 3.9**; `selftest.py` **7/7**. |

## Stop-gate (why the loop ended at round 1)

Composite gate met with room to spare: oracles intent-derived and non-tautological
(the guard self-test carries a passing positive control); the three highest-yield
surfaces — the recurring bug class, the live deployment/interpreter gap, and the
irreversible response tier — were each attacked with captured output and each came
back **dry**; the full suite is green under both interpreters. Against four prior
saturating passes documented below, one fully-dry independent re-siege is decisive.
Far under the siege 6-round cap. **Gate 4: zero genuine improvements → stopped; no
`/doit`, no `/launch`.**

## Scope / honesty notes

- **Delegation deviation, stated plainly:** the skill's default ladder fans out to
  `/code-tester` and `/spar` subagents. Here they were **not** spawned. Rationale
  (Fable calibration — effort to difficulty, catch spinning early): on a 4×-saturated
  6,607-line target where every independent lens this round is dry, a cold-start
  subagent that re-derives this context would, by the overwhelming prior, also return
  dry — the expensive path for ~zero marginal yield. Instead the run used **focused,
  higher-signal inline probes** aimed at the exact surfaces the prior passes'
  retrospectives flag as highest-yield/highest-recurrence/highest-stakes. The full
  delegated `/spar` + `/code-tester` fan-out remains available on request.
- **Inert throughout.** No live notification, launchd load, VT call, quarantine
  action, or write outside a throwaway `$HOME` fired. Real `~/.aegis/baseline.json`
  mtime (`22:08:53`, the live agent's own scheduled run) is unchanged by this pass.
- **Residuals unchanged** from the prior passes (all architecturally bounded, none
  clearing the genuine-improvement bar alone): `_parse_syspolicy_denials` deny-regex
  breadth (below notify floor, live wording unverifiable in-field), the same-uid HMAC
  trust-store forgeability (needs an off-box anchor), the agent-skill→correlation wire,
  and `check_behavior` ps-column misattribution on space-in-exec-path (detection still
  fires; cosmetic). No change made — the naive-correct state is already strictly best.

---

# Aegis — Battle-Test pass 3 (2026-07-23): correlation firmlink canonicalization

`/battle-test` on the freshest surface — the 13 research-derived correlation /
lineage / triage layers landed earlier the same day, which had verification but
no adversarial loop. **Tier: siege** (the response tier can quarantine / neutralize /
destroy — irreversible side effects — so the top tier applies), but no live side
effect was exercised: the whole hunt ran through the in-process event store on a
throwaway `EVENT_DB`, never touching real `~/.aegis`. Framing held throughout:
*surface failures honestly; captured stdout + exit code is the only evidence.*
Every oracle was derived from the README / docstring intent (the documented
lineage & chain guarantees), never from the code under test, and the new
regression test is mutation-validated (neutering the canonicalizer re-breaks the
join — proven by `test_lineage_firmlink_canon_is_discriminating`).

## Outcome

**1 genuine defect fixed** (HIGH — a detection false-negative in the correlation /
lineage / risk-accumulation engine), pinned by **4 new regression tests** (one a
mutation discriminator). Test state after the pass: `selftest.py` 7/7,
`tests/` **306 passed** (302 prior, untouched, + 4 new), 4 subtests. No live
notification, launchd load, quarantine action, or write outside a throwaway DB
ever fired.

## The finding (fixed)

| Sev | Where | Defect (vs stated intent) | Evidence | Fix |
|-----|-------|---------------------------|----------|-----|
| **HIGH** | `_same_entity` / `_lineage_path` / `_accumulate_risk` / `correlate` entity-key | The correlation, durable-lineage, and risk-accumulation layers join entities by **path string** using `os.path.normpath` — which does **not** collapse the macOS root firmlinks (`/tmp`→`/private/tmp`, `/var`→`/private/var`, `/etc`→`/private/etc`). So a dropper's payload recorded as `/tmp/evil` and its later execution/persistence seen as `/private/tmp/evil` — **the same on-disk object** — were treated as two different entities. Result: the CRITICAL "dropped object later executed or persisted" lineage chain and the persistence→execution chain **silently failed to fire**, degrading to two independent HIGHs — and `/tmp` is the #1 macOS malware staging location, so this was the common case, not a corner case. This is exactly the F6 bug class (`/var` vs `/private/var`, fixed in pass 1 for `is_risky_location`) reintroduced in the newer join keys. | Probe (captured stdout): control with identical forms → CRITICAL chain opens; persistence(`/private/tmp/evil`) + process(`/tmp/evil`) → **no chain** (two standalone HIGHs); lineage drop/activation across the firmlink → **no CRITICAL chain** (both directions); `_same_entity('/tmp/x','/private/tmp/x')` → `False`. | Added `_canon_entity_path()` — a pure string map (no filesystem I/O) that normalizes an entity toward the real `/private` form, unifying exactly the three firmlinks and **never** over-collapsing a lookalike (`/tmpfoo`) or two distinct paths. Applied at all four join/group sites. Post-fix the same probe shows every chain opens. |

## Round 2 (dry — no new genuine findings)

- **Response tier** (`cmd_quarantine`/`restore`/`destroy`/`neutralize` + recovery):
  already exhaustively hardened across two prior passes — transaction phases,
  content+metadata digests, identity re-verification, protected-path refusal,
  hard-link / cross-volume / symlink refusal, crash-safe recovery. Nothing new.
- **Triage state machine** (`transition_incident` / dismissals): correct —
  reopening an incident deletes its dismissal rows so the per-sensor precision
  feedback is retracted, matching the documented behavior.
- **Security lens** (inline; `watchdog` binary not installed): **zero** dangerous
  sinks — no `eval`/`exec`/`os.system`/`shell=True`/`pickle`/`yaml.load`; the
  `run()` helper never invokes a shell.
- **Sensors** (supply-chain, behavior/argv, typosquat, web-protection, staging):
  reviewed against README intent; `_edit_distance_le1`, hosts parsing, and the
  narrow supply-chain FP discipline are sound.

## Stop-gate (why the loop ended)

Composite gate met: the one oracle is mutation-validated · the correlation /
lineage / risk join surfaces were saturated by direct adversarial probes and now
pass · one dry round after the fix (full suite 306/306 + selftest 7/7 green, and
the original failing probe now green) · far under the siege 6-round cap.

## Residual risk / notes

- Any `path_lineage` rows written by a *pre-fix* build under the old `/tmp` form
  will not join a post-fix `/private/tmp` activation. This self-heals: the
  hot-dir / staging sensors re-emit a still-present drop each scan (re-inserting
  under the canonical key), and any stale row ages out via the 180-day retention.
  No migration was added — the naive-correct path is strictly better than the
  buggy state and needs no operator action.
- `_canon_entity_path` covers the three macOS root firmlinks only, not arbitrary
  user symlinks (which would need `realpath` + filesystem I/O on the correlation
  path). The join layer only needs the well-known system duality the codebase
  already documents; resolving attacker-controlled symlinks is out of scope (an
  attacker who controls a symlink in the path already has code execution).

---

# Aegis — Research build (2026-07-23, `/deep-research` + `/storm-research`: 13 layers)

Implemented the full prioritized output of a second research pass: a 6-perspective
STORM run (90 raw claims; 24 adversarially confirmed before the account's weekly
model limit stopped the verify stage) plus a deep-research fan-out (107 claims
across 22 sources). Both pipelines' *upstream* research completed; only their
verify/synthesis stages were cut off, so synthesis was done in-session against the
live code — every candidate was cross-checked against the actual sensor table and
regex tables first, which filtered out ~10 proposals aegis already implements
(`dscl -authonly`, `tccutil reset`, quarantine-strip, `hdiutil -nobrowse`,
keychain-db access, `curl -F` exfil, staging IOCs, XProtect harvest, watchdog).

Suite: **302 tests** (257 prior, untouched, + 45 new in
`tests/test_research_layers.py`) + `selftest` green. Live end-to-end scan in a
throwaway `$HOME` ran clean twice (rc 0, no exceptions, new sensor health OK).

| # | Layer added | Shape | Tier |
|---|-------------|-------|------|
| 1 | **Developer supply chain** | New 15th sensor: npm lifecycle hooks (`preinstall`/`postinstall`/…) scored for decode-and-exec, incl. the JS-native loader (`node -e "eval(Buffer.from(…,'base64'))"`, `atob`, `require('https')`) invisible to shell-oriented patterns; plus documented dropper dotfiles at `$HOME` root (DPRK `.npc`/`.myvars`/`.pyp`, AMOS `.agent`/`.helper`/`.mainhelper`). Bare fetches deliberately never fire. | detection |
| 2 | **GUI-kill coercion** | ClickLock's password-coercion primitive: killing Activity Monitor / SystemUIServer / NotificationCenter / Console → HIGH; the tight-loop variant → CRITICAL short-circuit. Plain `killall Dock` stays silent. | detection |
| 3 | **Daemon name masquerade** | Edit-distance-1 process-name typosquat of an Apple daemon (`SystemUIServerl`) in a user-writable path → HIGH, regardless of signature. | detection |
| 4 | **applescript:// delivery** | The Script-Editor URL scheme that executes outside any shell — evading both shell history and Apple's Tahoe 26.4 Terminal-paste warning. | detection |
| 5 | **Download provenance** | `QuarantineEventsV2` + Chrome-family `downloads` table (both no-FDA) resolve a drop's origin URL and agent. Enriches hot-dir findings AND grades them: a trusted origin demotes to digest. Only ever lowers confidence, never severity — provenance is attacker-supplyable. | attribution |
| 6 | **Durable path lineage** | A suspicious drop is remembered by normalized path indefinitely (6-month retention); any later execution/persistence of that path opens a CRITICAL chain. Fixes the entity-hop (dropper exits, launchd runs it at next login) and the re-signing case that defeats hash-keyed joins. | correlation |
| 7 | **Credential-capture chain** | Password phish / `dscl -authonly` / keychain access / GUI-kill + persistence-or-exfil on one entity → CRITICAL chain instead of two independent HIGHs. | correlation |
| 8 | **Corroboration scoring** | Cross-sensor agreement multiplies the risk score against a *constant* threshold (Splunk RBA's explicit tuning guidance) and needs fewer signals. The documented single-sensor guarantee is preserved — verified by a test. | correlation |
| 9 | **Wrapper-LOLBin unwrapping** | `caffeinate -i ~/.payload`, `nohup`, `setsid`, `sudo -u` fronting a payload: the wrapper is stripped so the *target* is scored, not the Apple-signed launcher. Value-taking flags (`-t 3600`) are skipped correctly. | detection |
| 10 | **Typed dismissals** | `false-positive` (rule is wrong) vs `benign-positive` (real but authorized) recorded separately into a `dismissals` table feeding different tuning queues; reopening retracts the dismissal. | triage |
| 11 | **Per-sensor precision** | A chronically-dismissed category is down-weighted in risk accumulation toward a floor (never zero, so it can still corroborate), gated on a minimum sample so one dismissal cannot mute a sensor. | triage |
| 12 | **Known benign causes** | Each incident card prints the documented benign causes for the sensors that fired — triage becomes a lookup, not an investigation. | triage |
| 13 | **`replay` backtest** | Re-runs current correlation logic over recorded history in a throwaway in-memory DB built from the same schema constant. Strictly read-only — proven by test that durable state is unchanged. | detection-as-code |

## Found and fixed during verification (not shipped broken)

- **Typosquat false-positive cannon.** Against a live 537-process table, short
  daemon names collide at edit-distance 1 with ordinary binaries: `/usr/bin/log`
  ↔ `logd`, `finger` ↔ `finder`, `doc` ↔ `dock`. They did not alert only because
  those paths are trusted — but any such binary in a user-writable path would
  have fired a false HIGH. Fixed by comparing only names ≥7 chars; the dropped
  short names lose nothing (an unsigned short-named binary in a user-writable
  path is already caught by the signature check, and `com.finder.*` label
  impersonation is the persistence sensor's Team-ID job). Pinned by test.
- **New sensor read the live host in tests.** `check_supply_chain` walked the
  real `$HOME`, breaking the suite's "never reads the live host" invariant and
  slowing every scan-level test. Fixed by making `SUPPLY_CHAIN_ROOTS` an
  overridable module global (matching `STAGING_DIRS`/`HOT_DIRS`) and pinning it
  in the shared `Sandbox`.
- **Three `xattr` subprocesses per file.** The provenance work initially spawned
  `xattr` three times per hot-dir candidate; consolidated to one read via
  `_quarantine_fields()`.
- **`urllib` on the scan path.** The first provenance draft used
  `urllib.request.pathname2url`, which would have loaded the networking module
  and broken the local-only guarantee's "urllib isn't even imported" claim.
  Replaced with hand-rolled URI escaping and a host regex.

## Design guardrails honored

Local-only and stdlib-only unchanged (the two new data sources are the user's own
SQLite files, opened read-only/immutable so a live browser DB is never locked);
no new privileged parser; the supply-chain sensor is bounded by depth, directory,
manifest, and wall-clock caps and degrades via the normal sensor-health path.
**No detection regressed:** the one behavior change that would have revoked a
documented guarantee (single-sensor risk accumulation) was deliberately reworked
into an additive one after the existing test caught it.

## Measured

- Supply-chain sensor on the real home: **0.72 s**, 3,298 manifests reachable,
  369 scored within the 30-day window, **0 false positives**.
- New argv rules against the live process table: **0** hits.
- Typosquat rule after tightening: 1 name-match on 537 live processes, correctly
  gated to no alert by `is_risky_location`.

---

# Aegis — Battle-test pass 2 (2026-07-22, `/battle-test`: siege tier, the 10 new layers)

Adversarial hardening of the 790-line `feat/defense-in-depth-layers` commit. Tier
**siege** (irreversible response tier: `quarantine`/`destroy`/`kill`). Discipline
`/fable-mode`; hunting fanned out to 3 oracle-disciplined adversarial agents
(parsers · detection/severity/diff · integrity/egress) plus a main-thread
security + side-effect-safety lens. Every oracle derived from README/ARCHITECTURE
intent, never from the code under test; every finding reproduced against the real
functions with captured output before it counted.

**Result:** 6 genuine improvements implemented + 1 documentation-honesty pass,
each pinned by a fail-before/pass-after regression test. Suite **257** (246 prior
+ 11 new) + `selftest` green; test isolation proven leak-free (function-attribute
completeness scan); heartbeat-egress guard self-test confirms the scan path is
**inert by default** (0 POSTs, opt-in gate fires only when a URL is set).

## Findings (fixed)

| # | Sev | Where | Defect (vs stated intent) | Evidence | Fix |
|---|-----|-------|---------------------------|----------|-----|
| P2-1 | **HIGH** | `tests` (`Sandbox.setUp`) | The suite shipped **red on HEAD**: `check_hardening` was the only host-reading sensor `setUp` did not stub/restore, so ~5 `cmd_scan` tests hand-stubbed `aegis.check_hardening = lambda: []` and never restored it → it **leaked globally and neutered the very test guarding `check_hardening`** (masking any real regression in that sensor). | `pytest tests/` failed 1/246; passes alone; a per-test probe showed `check_hardening` → `[]` for the rest of the suite after `TestShellRc`. | Added `check_hardening` to `setUp`'s stub/restore tuple; guard test pulls the real fn from `self._saved` (the codebase's own pattern). A completeness scan now confirms **zero** `aegis.*` function leaks. |
| P2-2 (C1) | **HIGH** | `cmd_watchdog` | Dead-man's switch reads a **dead** installed monitor as **alive**: `armed = bool(beat) or exists(BASELINE)` — both anchors live inside `~/.aegis`, so a same-uid `rm -rf ~/.aegis` (the exact threat model) makes a killed monitor return `rc 0 / OK`. Contradicts its own docstring ("alerts when the monitor stopped beating"). | Repro: plist installed + `~/.aegis` wiped → `rc 0` (should ALARM). | Anchor `armed` also on `SELF_PLIST` (lives OUTSIDE `~/.aegis`) and `SELFSTATE.installed`; a genuinely uninstalled box still stays quiet. |
| P2-3 (A1/B1) | **HIGH** | `_skill_signature` | Shipped agent-skill script payloads were signed **by name only**, so a supply-chain hijack that swaps a script's **body** under the same filename (the most direct attack the surface exists to catch) produced an identical signature → `diff_agent_skills` fired nothing. F4-class. **Independently found by 2 hunters.** | Repro: `run.py` body swapped benign→`curl\|bash`, sig unchanged. | Content-hash each payload (`name@sha16`); broadened payload extensions (`.scpt/.applescript/.zsh/.mjs/…`). Body swap + no-exec interpreter drop now change the signature. |
| P2-4 (B2) | **MEDIUM** | `_scan_surfaces` | `auth_sessions` was silently adopted on first sight like installed-residue, so an **active remote login present at install/upgrade time** was blessed as known-good and never alerted — violating the README's "live-threat surfaces are never first-run-suppressed" rule. | Repro: live `root@203.0.113.9` session at first-run → `[]` findings, adopted into baseline. | `_NEVER_ADOPT_LIVE = {"auth_sessions"}`: diff against empty on first sight so a live session alerts HIGH immediately; residue surfaces stay first-run-silent (proven by test). |
| P2-5 (A2) | **MEDIUM** | `_parse_who_remote` | The loopback drop-list held only symbolic forms, so a **loopback ssh session** (`ssh localhost`, VS Code Remote-SSH, git-over-ssh — routine for devs), which `who` records as numeric `127.0.0.1`/`::1`, fired a **HIGH page** on the only auto-paging remote surface. | Repro: `(127.0.0.1)`/`(::1)` → remote-session dict → HIGH. | Added `127.0.0.1`, `::1`, `::ffff:127.0.0.1` to the drop-list; real remotes still detected. |
| P2-6 (A4) | **LOW** | `_parse_netstat_established` | An IPv4-mapped-IPv6 loopback peer `::ffff:127.0.0.1` wasn't recognized as loopback → counted as egress. | Repro: mapped-loopback row kept as outbound. | Added `::ffff:127.` to the loopback prefix drop. |
| P2-7 (C3) | doc/comment | README + 2 code comments | **Trust-model contract was false:** README stated "the **only** command that touches the network is `aegis.py vt` … the background scanner … never even imports the networking module," yet the opt-in heartbeat POSTs on the scan path — and the `AEGIS_HEARTBEAT_URL`/`heartbeat_url` knob was **undocumented** (0 hits in README/ARCHITECTURE). Two in-code comments also overstated guarantees (HMAC "can't forge without the key"; agent-skill "auto-correlates" with a later phish — not wired). | `grep heartbeat README ARCHITECTURE` → none; guard self-test showed the scan-path POST. | Softened the README claim to accurately carve out the opt-in, off-by-default, redacted heartbeat egress + documented the knob; corrected both comments to the honest same-uid framing. |

## Verified robust (stated explicitly — not everything hunted was broken)

- **Heartbeat egress is opt-in & inert by default** — 2 sandboxed scans with no URL → **0 POSTs**; gate fires only when a URL is set; wire body is `{ts,epoch,pid,status,alerts,top_alert}`, double-redacted. Local-only-by-construction holds.
- **No injection sinks** in the new layers — no `eval`/`exec`/`shell=True`/`os.system`/`pickle`; all shells route through the hardened `run()` (list-form, fixed PATH/env, timeouts); `urllib` lazy-imported; `sqlite3` opens `mode=ro`. (`watchdog` binary absent → inline security review, logged.)
- **All 5 new parsers survive a malformed-input crash sweep** (empty/None/truncated/non-JSON/non-dict/binary) with zero exceptions.
- `_parse_xpdb`, `_outbound_finding`/`check_outbound` (below-notify by documented intent), `check_security_log`, `timestomp_signal`, `_accumulate_risk`, `cmd_bastion`/`_has_full_disk_access` — no genuine defect found.

## Deferred (documented residual, not fixed)

- **A3 — `_parse_syspolicy_denials` deny-regex narrower than the denial vocabulary** (misses `deny` verdict-token, `Blocking`, `not allowed`). PLAUSIBLE, but the real macOS wording could not be verified in-field (no live denial in the sampled window) and the surface is below the notify floor by design. Changing an unverified security detector's regex was declined per the verify-before-claim rule; left as residual.
- **C2 — HMAC trust-store gate is same-uid-forgeable** (drop `<name>_mac` from the same-uid-writable `SELFSTATE` → sha-downgrade; or delete `SELFSTATE` → re-bless). Architecturally bounded by the same-uid model the tool already concedes; the honest remediation (correct the overclaiming comment) is a comment-only change that does not clear the genuine-improvement bar alone, so it rode along in P2-7. Real closure needs an off-box/non-attacker-writable anchor.
- **Agent-skill → correlation chain is not wired** (findings carry no entity → never enter `_accumulate_risk`; `agent-skill` in no `correlate()` rule). Bounded impact (the phish still fires CRITICAL alone); the overstated docstring was corrected in P2-7.

## Side-effect safety / collateral disclosure

- The loop stayed inert **except** for one incident: a hunter subagent's isolation
  harness wrote the live `~/.aegis/baseline.json` (the `_scan_surfaces` upgrade
  branch persists), the installed file-watcher then ran a real scan, corrupted the
  baseline (persistence emptied, a synthetic `root@203.0.113.9` session blessed),
  and opened spurious HIGH incidents. Verified read-only: the fake session is not
  in live `who` (no real intrusion). Recovery (`aegis.py baseline` + resolve the
  spurious incidents) is handed to the operator, **not** auto-run — `baseline`
  asserts current state as trusted. Lesson pinned: a subagent hunting an installed,
  file-watched tool MUST redirect every state path (incl. any upgrade-persist
  branch) before calling a scan-adjacent function.

## Stop-gate (why the loop ended)

One full round across all lenses; oracles mutation-checked; parsers crash-swept;
integrity/egress guard self-tested; every genuine finding fixed + regression-pinned
and re-verified green (257 + selftest); a completeness critic (function-leak scan)
came back clean. New surface saturated by 3 independent hunters + main-thread
review with only architecturally-bounded residuals remaining. Well under the
siege 6-round cap.

---

# Aegis — Roadmap build (2026-07-22, `/doit`: 10 research-derived layers)

Implemented the prioritized roadmap from the deep-research + 7-lens STORM
synthesis (see the Swiss-cheese blueprint). Each new detector is pinned by a
fail-before/pass-after regression test in `tests/test_roadmap.py`; the full suite
is **246 tests** (218 prior, untouched, + 28 new) + `selftest` green, and a live
end-to-end scan in a throwaway `$HOME` ran clean twice (rc 0, heartbeat +
watchdog working, no alert storm, no exceptions).

| # | Layer added | Shape | Tier |
|---|-------------|-------|------|
| 1 | **Dead-man's switch** | `write_heartbeat` on every healthy scan (always, no network) + `aegis.py watchdog` peer/cron check that alarms on a stale/absent beat with a durable sentinel; **opt-in** off-host POST (`AEGIS_HEARTBEAT_URL`, BYO) for out-of-band egress. Closes the one hole no other layer covers — a same-uid SIGKILL/bootout can't suppress the beat off-box. | survivability |
| 2 | **Confidence axis + risk accumulator** | `finding()` gains a `confidence` field (separate from severity); the notify gate demotes explicit low-confidence HIGHs to digest; a per-entity decaying risk accumulator opens one `risk` incident when ≥3 distinct signals pile up on one entity (Elastic building-block→entity-risk pattern). | scoring |
| 3 | **Gatekeeper/syspolicy harvest** | Unified-log `syspolicy` denial harvest (same unprivileged `log show` path as XProtect), MEDIUM/low-confidence — log+correlation tier (live format unverifiable in the field → below the notify floor). | detection |
| 4 | **Outbound exfil** | `netstat -anv` process-attributed outbound diff: an unsigned/ad-hoc binary in a user-writable path holding an ESTABLISHED socket → MEDIUM (feeds correlation; ad-hoc dev binaries talk out routinely, so it must not page alone). | detection |
| 5 | **HMAC trust-store watermark** | Baseline/allowlist tamper-evidence upgraded from a plain sha to a keyed HMAC — an attacker who edits state AND recomputes the sha still can't forge the MAC without the key file (a second, observable step). | survivability |
| 6 | **Agent-skill sensor** | New SURFACE over `~/.claude/skills` (+codex/gemini): a new/changed skill dir (SKILL.md hash + shipped-exec names) — a live 2026 AMOS channel. Both tiers below the notify floor (a skills author edits constantly) → durable record + correlation input. | detection |
| 7 | **Auth-session sensor** | New SURFACE: baseline-diffs active REMOTE (`who` parenthesized-origin) sessions → a new ssh/screen-sharing login is HIGH. Complements the `authorized_keys` persistence check. | detection |
| 8 | **Timestomp** | Hot-dir drops compare ctime/btime vs mtime; a backdated mtime that would age a payload out of the hot window no longer skips it (ctime/btime can't be moved from userland). | detection |
| 9 | **Residual ASEP persistence** | Authorization plugins, Spotlight importers, QuickLook generators, scripting additions, and folder actions added to the content-hash+diff machinery (KnockKnock residual categories). *(A standalone dylib-hijack Mach-O scanner is deferred — an FP-prone parser would violate the no-regression bar; noted as the remaining #9 residual.)* | detection |
| 10 | **Bastion/XPdb opt-in tier** | `sudo aegis.py bastion` surfaces XProtect Behavioral Service violations Apple records to a root-only SQLite DB but never alerts on — free high-signal coverage no unprivileged layer can reach. | privileged (opt-in) |

**Design guardrails honored:** the scan/watch path stays local-only by default
(heartbeat POST and the sudo/Bastion tier are both opt-in, mirroring `vt`); new
noisy-on-a-dev-box surfaces (outbound, agent-skill-changed, syspolicy) sit at
MEDIUM/low-confidence so they enrich correlation without paging; every new
state path is sandboxed in the test harness (no real `~/.aegis` writes — the
P3-3 invariant); and the confidence gate is non-regressive (nothing pre-existing
is marked low, so every prior notification is byte-identical).

---

# Aegis — Deployment finding (2026-07-16, post-pass-3 — first live `watch` enablement)

Found while switching the live agent from hourly to event-driven watch mode and
verifying the event path end-to-end (not by the suite — same lesson as P3-4/5/6:
the on-machine run is what exposes deployment-class defects).

| # | Sev | Where | Defect (vs intent) | Evidence | Fix |
|---|-----|-------|--------------------|----------|-----|
| D-1 | **HIGH** | `_build_watch` | `os.O_EVTONLY` only exists in Python ≥ 3.10, but the launchd agent runs the system `/usr/bin/python3` (CLT **3.9**). First arm → `AttributeError` → process dies → launchd `KeepAlive` respawns → full scan (~90s) → dies again: watch mode degenerated into a **crash-loop of back-to-back full scans** — never event-driven, continuous CPU/`sfltool` load (the exact pressure P3-4 guards against), and the dev-python suite (3.10+, attr present) could never catch it. | `~/.aegis/run.err` traceback at `os.open(p, os.O_EVTONLY)`; `run.log` showed full scans at 23:23/23:24/23:25/23:26 (should be one per 600s); launchctl last-exit `1`. | Module-level `O_EVTONLY = getattr(os, "O_EVTONLY", 0x8000)` (the macOS `<fcntl.h>` value). 2 tests pinned: attr-hidden `_build_watch` arms, and a smoke test running `_build_watch` under the **agent's own interpreter** `/usr/bin/python3` — the class of gap (dev-python ≠ agent-python) is now guarded, not just this instance. Suite 153/153. **Verified live:** redeployed, watcher PID survived past the old crash point, and a file drop in `/Users/Shared` logged `watch: change event -> rescan` **16s** after the write (3s debounce + 60s rate-limit envelope) vs the prior 3600s tick. |

---

# Aegis — Battle-Test Log (2026-07-16, pass 3 — residual-gap-detectors branch)

Inline adversarial probe of the surfaces added this session (event-driven kqueue
watch + live `log stream` tail, hot-dir `.app`/notarization, network listeners,
BTM/Login-Items, opt-in VirusTotal). Every oracle derived from README/docstring
intent; each finding proven fail-before/pass-after against the committed baseline
before it was trusted; no live notification, launchd load, VT network call, or
write outside a per-test tmp dir fired. Suite: `selftest` 3/3,
`tests/test_regression.py` **151/151** (incl. an `install.sh` smoke test that now
guards F0 + P3-6 — the installer surface that had two CRITICAL bugs and no coverage).

## Outcome (pass 3)

**5 genuine defects fixed** (1 HIGH detection-evasion, 1 MEDIUM staleness-evasion,
1 HIGH live alert-storm, 1 HIGH self-protection blind-spot, and **1 CRITICAL: the
background agent never actually ran** — the last three found only by an on-machine
end-to-end run), each pinned or repaired; plus 1 real-state test-pollution bug
caught and fixed in-pass. The end-to-end run — not the 148-test suite — was what
exposed the three highest-severity issues, incl. the one that made the whole tool
inert in the background.

| # | Sev | Where | Defect (vs intent) | Evidence | Fix |
|---|-----|-------|--------------------|----------|-----|
| P3-1 | **HIGH** | `_bundle_executable` | `CFBundleExecutable` is attacker-authored plist data. A value with a path separator (`/bin/sh`, `../../x`) makes `os.path.join(app,'Contents/MacOS',name)` **escape the bundle** — `join` discards everything before an absolute component — so Aegis would classify a *clean Apple binary out-of-bundle* instead of the ad-hoc payload, silently downgrading a HIGH `.app` finding to nothing. | Probed the committed `5b95c2c` `_bundle_executable` with a `/bin/sh` name → resolved outside the bundle. | Reject any `CFBundleExecutable` containing `/`; a legit value is always a bare filename. Post-fix → `None` (no finding suppression). Pinned. |
| P3-2 | **MEDIUM** | `_check_hot_app` | Bundle freshness keyed on the `.app` **root** mtime only. Swapping a fresh payload into an *existing old* bundle's `Contents/MacOS` never touches the root mtime → a re-weaponized old app ages out of the hot window and is never scored. | A 60-day-old bundle root with a freshly-written exe → no finding pre-fix. | Freshness = `max(root_mtime, exe_mtime)`; a fresh exe in an old bundle still flags HIGH, a fully-old bundle still ages out. Both pinned. |
| P3-3 | **MEDIUM** | `TestVTReputation` (test) | A new VT test wrote a key to the **real** `~/.aegis/vt_key` (the sandbox overrode `STATE_DIR` but not `VT_KEY_FILE`), polluting real host state — the suite's own "never touch real `~/.aegis`" invariant. | Real `~/.aegis/vt_key` (11 bytes) appeared after a run. | Sandbox now overrides `VT_KEY_FILE`; the stray file was removed. Guards the invariant that would otherwise let any future key-path test leak. |
| P3-4 | **HIGH** | `snapshot_btm` / `snapshot_listeners` / `_scan_surfaces` | `sfltool dumpbtm` is SLOW (~12s; observed **wedged >60s** under load on this machine) and its 15s `run` timeout returned empty → `snapshot_btm` recorded `{}` = "no background items." A Mac always has ~90 (DisplayLink, auto-updaters…), so the **false-empty was adopted into the live baseline**, and the instant sfltool next succeeded the diff would fire **~95 bogus `New background item` findings — a real alert storm on the user's own installed monitor**, violating the storm-free invariant (same class as the pass-1 corrupt-baseline fix). | Live on-machine `aegis.py scan`: baseline recorded `btm: {}` while `snapshot_btm()` returned 95 real items; a `{}`→95 diff = 95 findings (reproduced in `test_none_snapshot_is_not_adopted_and_does_not_storm`). | A fallible snapshot now returns **`None` (non-answer)** on timeout/hard-failure vs `{}` (genuine empty); `_scan_surfaces`/`cmd_baseline` **skip** a `None` surface — never adopt it, never diff against it. sfltool timeout raised 15→30s; the live poisoned `btm` baseline key was healed. 3 tests pinned. |
| P3-5 | **HIGH** | `check_self_protection` | Self-protection detected the agent being *removed* but not present-but-**broken**. The live machine's own plist was invalid XML — a raw `&` from the `…/Work & Projects/…` install path (the pass-1 **F0** bug, in a plist generated *before* F0 was fixed). launchd keeps running a previously-loaded copy so the monitor *looks* alive, but on the next reboot/reload it silently refuses the bad plist and the monitor **dies with no signal** — a security tool rotting itself into non-execution. | `plutil -lint ~/Library/LaunchAgents/com.charlie.aegis.plist` → "unknown ampersand-escape sequence at line 9"; launchctl last-exit status was `2`. | Self-check now `plistlib.load`s its own plist when present → HIGH `self:agent:malformed` while it is still limping and fixable. **Live repair:** regenerated the plist via the F0-fixed `install.sh` → `plutil -lint: OK`, running PID, exit 0, baseline preserved. 2 tests pinned. |
| P3-6 | **CRITICAL** | `install.sh` (agent script path) | The agent ran `/usr/bin/python3 <repo>/aegis.py`, but the repo lives under `~/Documents/…` — a **TCC-protected** location. A launchd-spawned python3 has no Full Disk Access, so it got **`Operation not permitted` merely OPENING the script**: *every* scheduled run failed before executing a line. The background monitor — the entire point of the tool — **had never actually run**; only manual runs from a TCC-privileged shell worked, masking it. This defeats the product outright, silently. | `~/.aegis/run.err` was full of identical `can't open file '…/aegis.py': [Errno 1] Operation not permitted`; launchctl last-exit `2`; `latest.md` timestamps only ever matched *manual* runs. | `install.sh` now copies `aegis.py` to `~/.aegis/aegis.py` (NOT TCC-protected — the agent already writes its logs there) and points the plist at the copy; the agent runs with **zero FDA**. **Verified live:** forced agent run → `run.err` empty, last-exit **0**, `latest.md` written by the agent. FDA now only needed to *also* scan Downloads/Desktop (documented). Re-run install.sh to refresh the copy after edits. |

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
