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
