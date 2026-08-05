# Aegis — a personal background security monitor for macOS, Linux and Windows

A small, honest **layered defense monitor** for your own machine, with an opt-in
**response tier** to act on what it finds. It runs in the background (launchd /
systemd user timer / Task Scheduler), watches the surfaces malware actually
uses on that OS, records the health of every sensor, correlates related signals
into incidents, and tells you when something new and suspicious appears. Only
when *you* run a response command by hand can it **quarantine, neutralize,
restore, or destroy** a reviewed threat. Zero third-party dependencies (Python
standard library only), **local-only** (no telemetry, no cloud), **no signing
cert required**.

The complete logic, workflow, safety invariants, and future power-tier gate are
in [ARCHITECTURE.md](ARCHITECTURE.md).

> It is not "Norton," and it deliberately doesn't pretend to be. The background
> scan is **detect-only and never destructive**; response is a separate, opt-in,
> reversible-by-default tier you invoke deliberately (see *Response tier* below).
> Read *Honest scope* too — the real-time-*blocking* ceiling is set by the OS,
> not by effort.

## One tool, three operating systems

Aegis is a single stdlib-only Python file. It detects its platform at import and
selects the sensors, path tables, trust model and scheduler that OS actually
has. A sensor with no meaning on a platform is **absent** from that platform's
registry — not reported as a broken or degraded sensor, because a launchd check
on Linux is not a coverage gap.

| Layer | macOS | Linux | Windows |
|---|---|---|---|
| **Persistence** | launchd agents/daemons, cron, login hooks, config profiles, background items (BTM) | systemd user+system units, XDG autostart, cron, `/etc/cron.d`, rc.local, profile.d | Run/RunOnce keys, Winlogon Shell/Userinit, Startup folders, scheduled tasks, services outside the protected trees |
| **"Who vouches for this binary"** | `codesign`: apple / app-store / developer-id / adhoc / unsigned / broken | package-manager ownership: dpkg/rpm/pacman `os-managed` vs `unmanaged` | Authenticode: os-signed / signed-valid / unsigned / broken |
| **Suspicious-exec rule** | unsigned/ad-hoc/broken in a user-writable path | **structural** — execution from a volatile dir, or a running binary deleted from disk (no ambient signing exists, so "unmanaged" is *not* treated as malicious: every locally built binary is unmanaged) | unsigned/broken in a user-writable path |
| **Process + argv** | two `ps` calls joined on pid — asking for `comm` and `args` together truncates the exec path to 16 chars | `/proc` directly (works on minimal containers with no `procps`, and no argv truncation) | one CIM query (`Win32_Process`) |
| **Network** | `lsof` listeners, `netstat` outbound | `/proc/net/tcp[6]` listeners + outbound, inode→pid via `/proc/*/fd` | `netstat -ano` listeners + outbound |
| **Fileless TTPs scored in argv** | `osascript` password phish, `xattr -c`, `hdiutil -nobrowse`, keychain copy, `curl\|bash` | `LD_PRELOAD` injection, `/etc/ld.so.preload` writes, memfd exec, `systemctl enable /tmp/...`, `/etc/shadow` + SSH key access | `powershell -enc`, IEX download cradles, LOLBin proxy exec (mshta/regsvr32/rundll32/certutil), Defender/AMSI tamper, LSASS + SAM-hive dumps, shadow-copy deletion |
| **OS engine harvest** | XProtect Remediator detections + definition age, Gatekeeper/syspolicy denials | `auth.log`/journal: SSH brute force, new accounts, privileged group adds, root logins | Event log: Defender detections (1116/1117), RTP disabled (5001), account creation (4720), audit-log cleared (1102), PowerShell script blocks (4104) |
| **OS-unique surface** | XProtect Behavioral (Bastion), agent skills, wallet integrity | **loaded kernel modules** (ring-0 rootkit), **new setuid-root binaries** | **WMI event subscriptions** (fileless persistence), **Defender exclusion changes** |
| **Hardening posture** | SIP, Gatekeeper, FileVault, firewall, stealth, Remote Login | SELinux/AppArmor enforcement, ufw/firewalld/nftables, sshd exposure + weak sshd settings, LUKS, unattended upgrades | Defender RTP + tamper protection + signature age, firewall profiles, BitLocker |
| **Change-driven watch** | kqueue (sub-second) + live XProtect log tail | short-cycle poll of the same watched path set | short-cycle poll of the same watched path set |
| **Background scheduling** | launchd agent | `systemd --user` service + timer | Scheduled Task |
| **Neutralize kill-chain** | `launchctl bootout` → kill → quarantine | `systemctl --user disable --now` → kill → quarantine | `schtasks /change /disable` → kill → quarantine |

Everything else — the finding contract, redaction, SQLite event store, dedup,
correlation and path lineage, incident lifecycle and reminders, typed
dismissals, risk accumulation, sensor health, the transactional quarantine store
with its protected-path refusals, replay, and the heartbeat/dead-man's switch —
is platform-independent and shared.

**Verification status.** All three platforms run the full suite in CI
(`.github/workflows/ci.yml`: Linux 3.9 + 3.12, macOS 3.12, Windows 3.9 + 3.12).

*Linux* is additionally proven by a live in-container siege that plants real
attacks (a systemd unit executing from `/tmp`, an XDG autostart entry, a live
`curl|bash` process, a binary deleted while running, a setuid-root backdoor, an
`ld.so.preload` rootkit write, a real non-loopback listener, an SSH brute-force
log) and asserts each is caught at the right severity.

*Windows* is no longer inference. `tests/win_live_harness.py` executes the
Windows code against a real Windows kernel on every CI run: real
`Get-AuthenticodeSignature` verdicts (including a tampered copy of an
embedded-signed binary), real `Win32_Process` + `GetOwner` attribution, a real
`winreg` enumeration of the real Run/Winlogon/Services hives, the full
`schtasks` lifecycle (register → query → parse back out of real CSV → disable →
delete → uninstall), the PowerShell probes' no-false-empty contract, and two
full scans.

That first real run mattered. Until it happened, **three Windows surfaces did
not work at all** and nothing could show it: `scan` crashed with
`UnicodeEncodeError` the moment it had anything to report (the report's severity
icons are not representable in cp1252); the Winlogon hijack check read a key
path that does not exist, so it inspected nothing; and the process sensor
returned zero processes on every machine, because its PowerShell built its field
separator with a backtick escape inside a single-quoted string. Two of those
were invisible to the existing tests **because the tests shared the bug's own
assumption** — the fake-registry fixture was built from the same wrong constant,
and the parser tests fed tab-separated fixtures straight to the parser without
ever running the PowerShell meant to produce them. A simulation inherits its
author's model of the system; only the system disagrees. See BATTLE-LOG.md.

What is still *not* proven: a GitHub-hosted runner is a real Windows kernel, but
it is not a domain-joined workstation. Defender real-time and tamper protection
are off there, the Security event log is not readable by the harness's principal
(correctly reported DEGRADED rather than silently empty), and no Group Policy
applies. Behaviour under an enterprise policy set remains untested, and that is
stated here rather than implied away.

---

## TL;DR — what it does

Runs `aegis.py scan` on an interval and reports/alerts on:

| Check | What it catches | Why it matters |
|---|---|---|
| **Persistence watch** | New/changed launchd agents & daemons + cron, each program hashed + signature-classified, diffed vs baseline — **arguments inspected** (`bash -c "curl…\|sh"`, `base64 -d\|sh`, `/dev/tcp`), **DYLD_* injection env flagged**, **an interpreter run against a hidden `$HOME`/tmp script caught** (AMOS `/bin/bash ~/.agent`), and **vendor-label impersonation caught** (a `com.apple.*` / `com.google.*` / `com.microsoft.*` plist whose program isn't signed by that vendor's Team ID — RustBucket's `com.apple.systemupdate` behind a hijacked cert, ClickFix's fake `com.google.keystone`) | The #1 macOS infostealer signal — AMOS/Atomic, Poseidon/Odyssey persist via `LaunchAgents`/`LaunchDaemons` |
| **Process watch** | Running processes whose executable is unsigned/ad-hoc **and** in a user-writable path | Malware runs ad-hoc-signed binaries from `/tmp`, `~/`, `/Users/Shared` |
| **Behavioral watch** *(new)* | The full **command line** of every same-user process, scored for the fileless-stealer TTPs: a fake `osascript … display dialog … hidden answer` **password phish** (CRITICAL), `dscl . -authonly` local-password check, `xattr -c/-d com.apple.quarantine` **provenance strip**, `hdiutil attach -nobrowse` **invisible DMG mount**, `tccutil reset`, a `login.keychain-db` copy, a `curl -F file=@/tmp/*.zip` **exfil POST**, and a `curl … \| bash/osascript` **fileless pipeline** | The dominant 2025-26 stealer TTP is fileless — it runs through Apple-signed interpreters (bash/osascript/curl) whose *path* is trusted, so only the argv reveals the attack. This is the biggest coverage gain in this release |
| **XProtect harvest** *(new)* | Reads Apple's own **XProtect Remediator** detections straight from the unified log (`com.apple.XProtectFramework.PluginAPI`) — a `status != NoThreatDetected` event means Apple's engine found/removed malware (CRITICAL) — plus flags **stale XProtect definitions** (>60 days) | Piggybacks Apple's professionally-maintained, always-updating signature/behavioral engine for free — no entitlement, no cloud. The single highest-value signal a signature-less tool can add |
| **Hot-dir watch** | Freshly-dropped unsigned Mach-O executables **and `.app` bundles** in Downloads/Desktop/tmp/Shared, tagged with **full download provenance** — not just *whether* a quarantine flag exists but **who** downloaded it and **from what URL**, resolved from the user's own `QuarantineEventsV2` store and the Chrome-family `downloads` table (both same-user-readable, **no Full Disk Access**). A binary with *no* quarantine flag bypassed Gatekeeper (side-loaded via `curl`/`scp`/AirDrop); one from a **trusted origin** (github/apple/brew/npm/pypi…) is demoted to the digest instead of notifying — provenance grades the finding, and because an attacker can supply it, it only ever *lowers* confidence, never severity, and never closes a finding (a timestomped file is never demoted). A fresh signed-but-**unnotarized** app additionally gets Gatekeeper's own `spctl` verdict surfaced (MEDIUM — a normal quarantined launch would refuse it, so one that runs was side-loaded or force-approved) | Catches a payload the moment it lands, before it runs — including the #1 delivery shape, a DMG/ZIP-dragged `.app`, which is a *directory* and invisible to any file-only check |
| **Staging watch** *(new)* | Documented stealer **loot-staging artifacts** in `/tmp`/`/Users/Shared` — `app.zip` (Atomic), `ledger.zip` (Odyssey/Poseidon), `salmonela.zip` (MacSync), `wid.txt`, `.pass`, `shub_*`, a copied `login.keychain-db` | Smash-and-grab stealers stage loot then exfil in under a minute, leaving no persistence — this catches the residue |
| **Developer supply chain** *(new)* | Install-time **npm lifecycle hooks** (`preinstall`/`postinstall`/…) that decode-and-execute or fetch-and-run — including the JS-native loader shape (`node -e "eval(Buffer.from(…,'base64'))"`, `atob`, `require('https')`) that no shell-oriented pattern can see — plus documented **dropper dotfiles** at `$HOME` root (`.npc`, `.myvars`, `.pyp` — DPRK; `.agent`, `.helper`, `.mainhelper`, `.logged` — AMOS) | The developer's own machine became the target: DPRK *Contagious Interview* shipped 300+ malicious npm packages whose install hook runs BeaverTail, and the Shai-Hulud worm hit 700+ packages with a credential-harvesting postinstall. **Deliberately narrow:** a bare network fetch never fires (esbuild/sharp/puppeteer legitimately download binaries in `postinstall`) — only an unambiguous exec/obfuscation idiom, or the fetch+exec combination, does. Measured on a real dev machine: 369 recently-changed manifests scored, **zero** false positives, 0.7 s |
| **GUI-kill coercion** *(new)* | A process killing **Activity Monitor / SystemUIServer / NotificationCenter / Console** — and the tight-loop variant (`while …; do killall …; sleep 0.2; done`) escalated to CRITICAL | ClickLock (Group-IB; 100+ victims across 33 countries since May 2026) kills the very apps you'd open to notice it, looping every 210 ms for up to ~35 days until you type your password, and kills NotificationCenter to suppress Gatekeeper warnings. "No legitimate use case." A plain `killall Dock` (ordinary troubleshooting) is deliberately **not** flagged |
| **Daemon name masquerade** *(new)* | A binary in a user-writable path whose name is **edit-distance 1** from an Apple system daemon (`SystemUIServerl` vs `SystemUIServer`, `cfprefsdd` vs `cfprefsd`) | ClickLock's reverse shell runs as `SystemUIServerl` to blend into `ps`/Activity Monitor. The *name* is the signal, so this fires regardless of signature — a validly-signed typosquat is still impersonating the OS |
| **applescript:// delivery** *(new)* | The `applescript://` URL scheme, which opens Script Editor pre-loaded with the payload | A 2026 ClickFix variant that executes **entirely outside any shell** — leaving no shell history *and* sidestepping Apple's own macOS Tahoe 26.4 Terminal-paste warning. The shell-history sensor is structurally blind here |
| **Web/phishing posture** | Parses `/etc/hosts` locally for a substantial hosts denylist and flags non-blocking redirects of sensitive identity/update domains or punycode names as HIGH. Missing blocklist coverage is INFO only because DNS or Network Extension filtering may exist outside Aegis's view | Adds an entitlement-free web-defense layer without phoning home, modifying DNS, or pretending that an unobservable network filter is absent |
| **Shell history** *(new)* | The recent tail of `~/.zsh_history`/`.bash_history`/fish for the **ClickFix terminal-paste** chain — `dscl . -authonly`, `curl … \| sh`, `xattr -c`, `hdiutil -nobrowse` — one alert per unique hostile command | ClickFix (fake-CAPTCHA paste) is now the dominant macOS initial-access vector; the payload is fetched inside a trusted Terminal so it never gets a quarantine xattr — history is the residue |
| **Wallet integrity** *(new)* | Content-hash of installed crypto-wallet configs + app binaries (Ledger Live `app.json`, Trezor Suite, Exodus); any change alerts HIGH | 2025 stealers hijack funds by rewriting Ledger Live's `app.json` or swapping wallet bundles for drainers (DigitStealer, Odyssey) |
| **Canary files** *(new, opt-in)* | Hidden decoy files you plant with `aegis.py canary`; any modification/deletion alerts CRITICAL | Attribution-independent ransomware / bulk-tamper tripwire — a process encrypting a folder trips a canary with near-zero false positives |
| **Shell startup files** | New or modified `~/.zshrc`/`.zprofile`/`.bashrc`/… (ATT&CK T1546.004); a download-and-run or reverse-shell idiom scores HIGH | ClickFix/AMOS chains drop a re-execing payload into your shell rc |
| **Login/Logout hooks** | Legacy `com.apple.loginwindow` LoginHook/LogoutHook | Rare-legit today; a classic persistence primitive |
| **Config profiles** | A newly-installed configuration profile | Adds trusted certs / proxies / MDM control — an adware & DPRK vector |
| **Extra persistence** | `/etc/crontab`, `/etc/periodic`, StartupItems, `/etc/rc.common` tamper — plus `/etc/hosts` (adware/phishing redirect), `/etc/pam.d` + `/etc/sudoers.d` (auth-chain backdoor, T1556), `sshd_config`, and **`~/.ssh/authorized_keys` / `~/.ssh/config`** (a newly-appearing key = the classic durable-remote-access implant, T1098.004; a `ProxyCommand` hijack runs code on every ssh) | Persistence surfaces beyond `LaunchAgents` and the user crontab |
| **Network listeners** *(new)* | A **new** process accepting connections *from the network* (non-loopback TCP LISTEN, via `lsof`), baseline-diffed. Unsigned/ad-hoc binary in a user-writable path listening → HIGH (bind-shell / rogue-server shape); anything else → MEDIUM (logged). Loopback dev servers and SIP-pinned Apple daemons are excluded by design — but an Apple-signed *interpreter* serving the network (`python3 -m http.server 0.0.0.0`, `nc -l`) **is** tracked | LuLu-tier *outbound* blocking needs an Apple entitlement; the *listening* side is visible unprivileged, and a reachable listener is rare, durable, and high-signal |
| **Browser extensions** | New Chromium-family / Firefox extension appearing | Malicious extensions exfiltrate sessions, cookies, wallet data |
| **Editor extensions** | New VSCode / Cursor / VSCodium / Windsurf extension | A backdoored editor extension is a live supply-chain vector (Objective-See's *Paradox*, 2025, shipped via a trojanised Cursor extension) |
| **Background items** *(capability-dependent)* | Where macOS permits `sfltool dumpbtm`, a **new** Login Item / SMAppService background agent is baseline-diffed. A new item with **no Team ID whose URL is in a user-writable path** → HIGH, else MEDIUM. If Apple requires interactive authorization, the sensor reports DEGRADED rather than clean. | Catches the modern persistence path the LaunchAgents-directory scan **cannot see** without pretending the data exists when macOS withholds it |
| **Self-protection** | Aegis's own launchd agent removed, **its own plist present-but-malformed** (invalid XML that launchd will silently refuse on the next reboot — the monitor dies with no signal), its append-only log truncated, or its **trust store (baseline/allowlist) edited out-of-band** | A monitor an attacker can silently disable, blind, or feed a poisoned baseline — or that quietly rots itself into non-execution — is theater |
| **Hardening posture** | SIP, Gatekeeper, FileVault, Application Firewall, stealth mode, Remote Login, **+ XProtect definition age** | Surfaces weak settings (a first run typically finds a control the operator assumed was on) |
| **Latch tamper** *(opt-in)* | A pre-claimed persistence surface (`chflags uchg` / deny-write ACE) found writable again with no authorized `unlatch` in the audit log | Attack-defined, not heuristic: nothing benign clears these flags. The `unlatch` gate refuses non-interactive callers, so malware cannot manufacture the authorization |
| **Credential decoy read** *(opt-in)* | A process blocked reading a FIFO honeytoken at a credential-shaped path, resolved to a pid | Zero-false-positive by construction — nothing legitimate knows the path exists. Composes with `freeze` to contain the reader while you look |
| **Unproven coverage** *(opt-in)* | A detector whose positive control has not been re-proven within its half-life, or is now failing | The difference between "nothing found" and "no longer able to find" — every intrusion starts by making the machine silent |

**Design principle — many imperfect layers, one honest decision path.** No
single sensor is treated as authoritative. Each scan stores redacted
observations, upserts recurring signals, records sensor health, correlates only
high-confidence multi-surface chains, and opens incidents with bounded reminders.
The first run records an **unverified** silent baseline (no day-one alert storm,
but also no claim that the existing state is clean). The shell-rc, profile, hook, extra-persistence,
browser-extension, wallet, **network-listener** and **shell-history** surfaces
extend this rule **per-surface**: each is adopted silently the first time it's seen (a months-old
`curl…|sh` install line already in your history is *residue*, not a live threat),
so *upgrading* Aegis on an existing install is also storm-free. The **live-threat**
surfaces — a running hostile process (behavioral), an XProtect detection, a `/tmp`
staging drop, a hot-dir binary, a modified canary, a weak hardening setting — are
*never* first-run-suppressed: those are current risks you must hear about even on
the very first scan. After that, only **new** findings at **HIGH+** raise a desktop
notification. Unresolved incidents remind at roughly 1 hour, 24 hours, and 72
hours, then stop; the durable incident remains until it is resolved. Everything
is written to local logs and SQLite so a missed notification is not lost. New
detections favour **hard-to-vary structural invariants** (a non-Apple
process copying `login.keychain-db`; a quarantine-xattr strip) over easily-shed
string patterns, because Aegis is open-source and an attacker can read its checks.

**Correlation remembers paths, not just moments.** The bounded same-entity window
cannot see the dominant 2025-26 shape: a dropper writes a payload and *exits*,
then a **separate** launchd job runs it at the next login — different process,
hours later, often re-signed so the content hash no longer matches. Widening the
window would only add noise, so instead a suspicious drop is **durably
remembered by path**, and the chain fires the moment anything later executes or
persists that path, however much later. The path is the one identifier that must
survive between the two stages for the attack to work at all.

**Alert fatigue is treated as a failure mode, not a fact of life.** Dismissing an
incident asks *which kind* it was — `false-positive` (the detection is wrong →
tune the rule) or `benign-positive` (real, but authorized → suppress this one) —
because conflating them is what makes tuning impossible. A sensor the operator
keeps dismissing is automatically **down-weighted** in risk accumulation (never
to zero, and reopening an incident retracts the dismissal). Each incident card
lists the **known benign causes** for the sensors that fired, so triage is a
lookup rather than an investigation. And corroboration is scored, not just
counted: two *different* sensors implicating one entity outranks the same number
of hits from one sensor.

---

## Install / use

```bash
# Register the background monitor for THIS OS (launchd agent on macOS,
# systemd --user timer on Linux, Scheduled Task on Windows). Idempotent:
# re-run to change mode/interval or to refresh the runtime copy.
python3 aegis.py install                 # a scan every hour (default)
python3 aegis.py install 1800            # ...every 30 minutes
python3 aegis.py install watch           # change-driven + 600s full-scan floor
python3 aegis.py uninstall               # remove the registration, keep evidence

# On macOS `bash install.sh [watch] [interval]` remains available and does the
# same thing; `aegis.py install` is the cross-platform equivalent.
```

```bash
# from the aegis/ directory:
python3 aegis.py scan          # run once, print report, establish baseline
python3 aegis.py status        # fast hardening posture + XProtect definition age
python3 aegis.py doctor        # coverage/permission/sensor-health diagnostics
python3 aegis.py report        # reprint the latest report
python3 aegis.py baseline      # accept current state as known-good (resets diff)
python3 aegis.py incidents     # active incidents, evidence count, and state
python3 aegis.py incident ID   # evidence, KNOWN BENIGN CAUSES for the sensors
                               #   that fired, and allowed lifecycle actions
python3 aegis.py incident ID false-positive   # the DETECTION was wrong (tune it)
python3 aegis.py incident ID benign-positive  # real event, but authorized
                               #   ...the two are recorded separately and feed
                               #   different tuning queues; reopening an incident
                               #   retracts the dismissal so it stops counting
python3 aegis.py replay [days] # backtest the CURRENT correlation logic against
                               #   recorded history (default 30d). READ-ONLY:
                               #   opens no incident, sends no notification —
                               #   run it after changing detection logic
python3 aegis.py allow PATH    # stop alerting on findings matching PATH
python3 aegis.py vt PATH|SHA   # OPT-IN VirusTotal reputation (BYO key; sends only
                               #   the hash, never the file; scan stays local-only)
python3 aegis.py canary        # plant ransomware canary/honeypot files (opt-in)
python3 aegis.py canary remove # ...and remove them
python3 aegis.py watchdog      # dead-man's switch: exit non-zero + alert if the
                               #   monitor has stopped beating (run from a 2nd
                               #   launchd agent/cron as a mutual-watchdog). Every
                               #   healthy scan writes a LOCAL beat; set
                               #   AEGIS_HEARTBEAT_URL (or heartbeat_url in
                               #   ~/.aegis/config.json) to ALSO POST a small
                               #   redacted beat off-box — OPT-IN, off by default
python3 aegis.py bastion       # macOS only, OPT-IN, needs sudo: surface Apple's
                               #   XProtect Behavioral (Bastion) violations it
                               #   records but never alerts on

# RESPONSE TIER — opt-in, run by hand on a reviewed finding (never automatic):
python3 aegis.py quarantine PATH     # atomically confine a file or valid .app bundle
python3 aegis.py quarantine-list     # list the store (ids to restore/destroy)
python3 aegis.py restore ID          # un-quarantine byte-for-byte (undo a false positive)
python3 aegis.py destroy ID --yes    # verified deletion from quarantine (IRREVERSIBLE)
python3 aegis.py kill PID            # terminate one of YOUR processes (SIGTERM→SIGKILL)
python3 aegis.py sandbox PATH        # refuse host execution; use a disposable VM
python3 aegis.py neutralize TARGET   # persistence kill-chain: unregister → kill →
                                     #   quarantine. TARGET = a launchd .plist (macOS),
                                     #   a systemd unit/.desktop file (Linux), or
                                     #   task:NAME / a Startup-folder file (Windows)

bash install.sh              # background it via launchd (hourly); one baseline first
bash install.sh 1800         # ...or every 30 min (re-run keeps your baseline)
bash install.sh watch        # ...or EVENT-DRIVEN (recommended): a stdlib kqueue over
                             #    the persistence/hot/staging/rc/history paths rescans
                             #    within SECONDS of a change (debounced, ≤1 event-scan
                             #    per minute), full scan every 10 min as a floor
bash uninstall.sh            # remove the launchd agent
python3 selftest.py                    # quick detection-logic smoke (stdlib only)
python3 -m unittest discover -s tests  # full regression suite (stdlib only)
```

State lives in `~/.aegis/`: `aegis.db` (events, signals, incidents, and sensor
health), `baseline.json`, `findings.jsonl`, `latest.md`, `seen.json`,
`allowlist.json`, `sigcache.json`, `actions.jsonl` (response audit), and
`quarantine/` (transaction journals plus sealed native objects). State files are
private to the user; JSON replacements and response transitions are flushed and
atomically published.

**Where the agent runs from (why it's a copy).** `install.sh` copies `aegis.py`
to `~/.aegis/aegis.py` and points the launchd agent there — **not** at the repo.
A repo under `~/Documents/…` sits in a **TCC-protected** location, and a
launchd-spawned `python3` has no Full Disk Access, so it gets *"Operation not
permitted"* merely **opening** the script — every scheduled run then fails with
no signal (this was live on the author's own machine: the background monitor had
never actually run). `~/.aegis` is not TCC-protected, so the copy runs with zero
setup. Manual `python3 aegis.py …` from the repo still works (your shell has TCC
access). **Re-run `install.sh` after editing `aegis.py`** to refresh the copy.

**Privacy permissions:** Observer Basic does not request Full Disk Access. Do
**not** grant it to the shared `/usr/bin/python3`; that would give unrelated
scripts the same access. `aegis.py doctor` reports inaccessible coverage as
degraded rather than clean. Broader access belongs in a future dedicated,
signed Aegis app whose identity and requested capability can be reviewed.

---

## Response tier — act on a finding (opt-in, staged, reversible-by-default)

The scan/watch path is **detect-only** and never touches your files. Acting on a
threat is a separate tier you invoke **by hand, on a finding you've reviewed** —
Aegis never auto-remediates. Its staged ladder mirrors **SentinelOne's**
*Kill → Quarantine → Remediate → Rollback*. Quarantine is reversible;
**Remediate (destroy) is the only irreversible step**, and by construction it
can act **only on something already
  quarantined** — there is *no* "delete a live path" command. This is the
  industry's **quarantine-first, never-delete-first** rule, encoded structurally.
- **Quarantine is a reversible store with restore metadata**, exactly as
  **Microsoft Defender** documents it: the original path, mode, owner, hash, and
  the `com.apple.quarantine` provenance are recorded so `restore` puts the file
  back **byte-for-byte**. A false positive costs you minutes, not data — the
  Defender "every automated action must be reviewable and reversible" doctrine.

| Command | What it does | Reversible? |
|---|---|---|
| `quarantine PATH` | Durably records `PREPARED`, then performs an exclusive same-volume rename into a mode-000 sealed container. The native file or valid `.app` bundle is preserved intact, including inode identity and bundle metadata. It refuses symlinks, hard-linked files, ordinary directories, protected paths, identity races, cross-volume moves, and unavailable audit storage. | ✅ `restore` |
| `restore ID` | Verifies the sealed object's identity, durably records intent, and performs an exclusive native rename. It never overwrites: if the original path is occupied, it chooses a unique `.restored.<id>` destination. | — |
| `destroy ID --yes` | **Irreversible.** Durably records approval, removes only an already-quarantined object, and verifies that the object is gone. It refuses without `--yes`. | ❌ |
| `kill PID` | Graceful-then-forced termination of a **same-user** process (`SIGTERM`→`SIGKILL`; `taskkill` then `/F` on Windows). Refuses other users' processes, `pid 0/1`, Aegis's own tree, and session-critical processes on every OS. | — |
| `sandbox PATH` | Refuses to execute an untrusted sample on the host. Use an isolated disposable VM for detonation; a deprecated userspace profile is not treated as a safe malware boundary. | — |
| `neutralize TARGET` | Ordered persistence kill-chain, same doctrine on every OS: **unregister first** (`launchctl bootout` / `systemctl --user disable --now` / `schtasks /change /disable`) so a `KeepAlive`/`Restart=always` job can't relaunch, then kill any surviving instance, then quarantine the job definition (+ its binary if risky). | ✅ (artifacts land in the store) |

Each quarantine item has an authoritative, crash-recoverable `txn.json` state
machine. The human-readable manifest is derived cache, never authority. Every
response action — success or refusal — is durably appended to
`~/.aegis/actions.jsonl`; if the audit cannot be written before mutation, the
mutation is refused.

### Protective tier — pre-commitment and reversible containment (opt-in)

The response tier above acts on a threat you have already identified. This tier
exists because of the honest limit stated in *Honest scope*: an unprivileged
process cannot **block**, because blocking is irreversible and only the kernel
may arbitrate it. Three things it can do without any privilege at all:

| Command | What it does | Reversible? |
|---|---|---|
| `freeze <pid>` | **Suspends** a same-user process tree (`SIGSTOP` / `NtSuspendProcess`). A veto must be privileged *because* it is irreversible; a freeze can be taken back, so it needs no arbitration — and since being wrong costs one `thaw`, it can act on weaker evidence than any irreversible verb. Suspends the root first (a stopped parent cannot fork), then sweeps descendants to a fixpoint. Refuses other users' processes, session-critical ones, and any **ancestor** of Aegis. | ✅ `thaw`, and auto-releases after 15 min unreviewed (**fail-open**) |
| `frozen` | The review queue. Deferred consent is the point: personal firewalls died of prompt fatigue because they asked *at attack time*. A frozen suspect has accomplished nothing and will still be there after breakfast. | — |
| `latch [on\|off\|status]` | Pre-claims the persistence surfaces so a dropper's write **fails**: `chflags uchg` (macOS) / deny-write ACE (Windows), both settable by the owner unprivileged. Linux has no unprivileged immutable flag, so there it is a mode change — a speed bump, labelled as one. | ✅ `unlatch` |
| `unlatch <path>` | Opens one surface for a real installer. Requires an interactive terminal **and** a typed one-time code — a script cannot satisfy it. That is deliberate: if malware could call `unlatch`, the "latch cleared without authorization" signal would be worth nothing. | — |
| `decoy [plant\|remove]` | FIFO honeytokens at credential-shaped paths (POSIX only; **absent** on Windows). A read *blocks*, and any read at all is an attacker by construction — nothing legitimate knows the paths exist. Never replaces a file that already exists. | ✅ `decoy remove` |
| `assay` | Positive controls: prove each detector still fires against a known-good synthetic stimulus, and record what is currently **proven** vs merely asserted. A control unproven past its half-life is reported as unproven coverage, never as a clean result. | — (read-only) |
| `notary [verify\|append]` | Hash-chains Aegis's own state and anchors it into the OS's **root-owned** log store, which a same-uid attacker may append to but cannot edit or erase. | — (read-only) |
| `clipboard [check\|guard\|restore]` | Inspects the clipboard for pasted-command attack shapes *before* you paste — the one moment a ClickFix payload is inert data rather than code running as you. | ✅ `clipboard restore` |

**What the notary does and does not prove**, stated separately because the two
halves are not equally strong: it is **erasure-resistant** (removing an anchor
needs root, so a sequence gap is real evidence, including the gap left by
killing Aegis) but only **partly forgery-resistant** — an attacker who reads
`hmac.key`, which a same-uid attacker can, may write a self-consistent local
chain. What they cannot do is make a *past* anchor say something else. The
regression suite tests exactly that adversary: a forged chain with every head
and MAC recomputed defeats all local checks and is still caught by the anchors.

**Honest limits of this tier:**

- **Freeze contains, it does not rewind.** It stops new reads, connections and
  forks; bytes already handed to the kernel's socket buffers still transmit.
- **A source-aware attacker can kill Aegis instead of evading it.** No
  unprivileged tool can prevent that. The notary is the answer: it cannot stop
  the kill, but it makes the kill leave a sequence gap that cannot be backfilled.
- **`curl … | sh` is never silently rewritten.** It is the documented install
  path for rustup and much else, so the clipboard grammar reports it and stops
  there. Only patterns with no legitimate use (fake password dialogs,
  `powershell -enc`, `mshta`, a trailing `\r` auto-execute) are substituted.
- **Clipboard content that does not match is never logged or persisted** — in
  any form, including hashes. Password managers put secrets there.
- **Nothing in this tier runs automatically off a heuristic.** Every verb is one
  you type after reviewing a finding. The architecture invariant is unchanged;
  what is new is that you now have *reversible* verbs to reach for.

**Hard safety rails** (all destructive verbs): quarantine-first-never-delete-first;
**protected-path refusal** (SIP/system/Apple locations, Aegis's own files, `$HOME`
and any ancestor of it — so a mistyped parent can't take your home directory);
same-user-only process actions; never-act-on-self; and symlinks, hard links,
cross-volume copy/delete, and arbitrary directory trees are refused. Valid
`.app` bundles are the only supported directory-shaped object.

**Honest caveats, stated plainly:**

- **No host detonation is offered.** A disposable VM is the minimum honest
  boundary for analyzing a suspect executable.
- **Quarantine is containment, not cryptography.** The original native object is
  moved into a private, non-traversable store so it can be restored without a
  lossy copy/reconstruction step. Another process already running as the same
  user can still attack user-owned state; Aegis does not claim tamper-proofing.
- **Secure erase is not claimed on APFS/SSD.** Wear levelling, snapshots, and
  copy-on-write defeat that promise. `destroy` means verified namespace deletion;
  FileVault is the at-rest control.

---

## Honest scope — what a solo build can and can't do (the research synthesis)

You asked how Norton/CrowdStrike/SentinelOne/Defender/Objective-See build this
and what's realistic solo. The short version, verified against Apple's own docs
and your machine:

**The industry stack, three tiers:**
1. **Built-in (Apple):** XProtect (signature scans), XProtect Remediator
   (behavioral, runs periodically), Gatekeeper + notarization (blocks unsigned/
   un-notarized launches), TCC (privacy gating). Already on your Mac.
2. **Free indie (Objective-See):** KnockKnock (enumerate persistence, snapshot),
   BlockBlock (real-time persistence *blocking*), LuLu (outbound firewall),
   RansomWhere. **Aegis lives at the KnockKnock tier** — detect + alert.
3. **Commercial EDR (CrowdStrike/SentinelOne/Defender):** the same event stream,
   *plus* a cloud threat-intel/reputation backend, ML detection models, a
   signature/sample pipeline, and a staffed SOC. Those four are the parts a solo
   dev *can't* reproduce — they're companies, not code.

**The hard ceiling — real-time *blocking*.** The sanctioned way to authorize or
deny process/file events is the **Endpoint Security framework (ES)** in a System Extension.
ES requires the restricted entitlement `com.apple.developer.endpoint-security.client`
— `es_new_client()` fails with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` without it
— **plus** Developer ID signing, a hardened/notarized app, system-extension user
activation, and Apple approval for the restricted entitlement. Observer Basic
has none of those powers and does not imitate them with root shell tooling.

**What that means for a viable niche:** between free Objective-See tools and
enterprise EDR there's room for a *unified, transparent, local-only* prosumer
monitor — but the honest MVP is detection, and the moat (the ES entitlement) is
also the gate that blocks you. Build the detector first; earn the entitlement
later only if this becomes a product.

**Where the 2025-26 threat wave actually is — and the honest coverage boundary.**
The dominant macOS threat is now the **infostealer** (AMOS/Atomic ≈ 40% of macOS
protection updates in 2025), delivered by **ClickFix** — a fake-CAPTCHA/"fix-it"
page that gets *you* to paste a command into Terminal (now the top initial-access
vector, not exploits). These runs are **fileless and often persistence-free**:
they drive Apple-signed interpreters (`bash`/`osascript`/`curl`), phish your
password with a fake `osascript` dialog, copy your keychain and browser data,
stage loot in `/tmp`, exfil in **under a minute**, and exit. Aegis's answer is the
new **behavioral tier** (process argv + unified log + XProtect harvest), which
targets exactly this residue. Two boundaries stated plainly:

- **Polling ≠ real-time.** A sub-minute smash-and-grab can complete *between* two
  hourly ticks. The behavioral/argv checks catch a payload that is **still
  running** or that left a durable trace (shell history, a `/tmp` archive, an
  XProtect log entry, a keychain copy) — not one that ran and vanished in the gap.
  **`install.sh watch` narrows this gap to seconds** for watched file-touch surfaces
  (a persistence write, a `/tmp` staging drop, an rc edit, a pasted ClickFix line
  hitting history — each triggers a kqueue rescan within ~3s, rate-limited to one
  event-scan/min), while argv/XProtect/listener sampling still runs at the
  full-scan floor. A periodic reconciliation remains mandatory because vnode
  events can coalesce or be missed. Even so it is detection *after* the write — Aegis **detects
  residue; it does not block.**
- **Same-user only.** An unprivileged agent can read the command line of *your*
  processes but not root's or another user's (`KERN_PROCARGS2`). Consumer stealers
  run as you, so this covers the common case — but a root-escalated payload's argv
  is invisible without going root (a privilege jump Aegis deliberately refuses).

Defensible claim: *"detects the residue of X-class activity within one poll."*
Not defensible, and not claimed: *"blocks malware."*

---

## Trust model (a monitor is itself a privileged surveillance surface)

A security tool sees everything, so it must be trustworthy *by construction*:
- **Local-only on the scan/watch path *by default*** — out of the box the
  automatic monitor never phones home; no telemetry, no cloud. The only
  network-touching feature you run **by hand** is `aegis.py vt` (VirusTotal
  reputation), which needs a key you supply and sends **only a hash, never a
  file**; with no key the scanner never even imports the networking module.
  The **one** background egress that exists is **off unless you deliberately
  turn it on**: the dead-man's-switch heartbeat (below) POSTs a small redacted
  liveness beat *only* if you set `AEGIS_HEARTBEAT_URL` or a `heartbeat_url` in
  `~/.aegis/config.json`. Unset (the default) → zero network calls on the scan
  path, and `urllib` is lazy-imported so it isn't even loaded.
- **Stdlib-only** — no pip packages = no supply-chain surface to audit.
- **Readable** — one stdlib-only program you can audit end to end; it invokes
  trusted system tools by absolute path with a fixed system `PATH` (`codesign`,
  `spctl`, `csrutil`, `launchctl`, `log`, `sfltool`, `lsof`, …).
- **Read-only to your system on the scan path** — the background monitor writes
  only inside `~/.aegis/`. It touches anything *outside* that directory **only**
  on an explicit response command you type by hand: `canary` plants decoy files;
  the response tier (`quarantine`/`restore`/`destroy`/`kill`/`neutralize`) acts on
  the specific target you name, gated by the protected-path/same-user rails above
  and logged to `actions.jsonl`. The automatic launchd scan is never destructive.
- **No new privileged parser.** Aegis deliberately does *not* ship a YARA/file
  scanner that parses untrusted binaries — that reintroduces the exact
  privileged-parser RCE surface (cf. Norton/Symantec CVE-2016-2208) that a minimal
  local tool exists to avoid. It **harvests Apple's XProtect detections** instead
  of re-implementing a scanner.

---

## Roadmap (if this grows past "personal tool")

- ✅ **Event-assisted observation — SHIPPED** as `install.sh watch`: a stdlib
  `select.kqueue` over the persistence/hot/staging/rc/history/wallet paths
  rescans within seconds of a change (debounced; ≤1 event-scan/min), full scan
  every 10 min as the floor. **Both halves now shipped:** a persistent
  `log stream` tail of Apple's XProtect subsystem is armed as an `EVFILT_READ`
  source on the same kqueue, so a live XProtect detection wakes a rescan the
  moment Apple's engine writes it — the rescan's windowed harvest then reports
  it through the one normal dedup/notify pipeline (the tail is a *wake source*,
  never a second parser to drift). The tail auto-respawns if it dies and its fd
  is drained on every wake, so a level-triggered read can't busy-spin.
- ✅ **Reputation — SHIPPED** as `aegis.py vt <path|sha256>`: an **opt-in, by-hand**
  VirusTotal lookup (BYO key via `AEGIS_VT_API_KEY` or `~/.aegis/vt_key`). It sends
  **only the sha256, never the file bytes**, and the scan/watch path makes **zero**
  network calls regardless — off by default, so the local-only guarantee stays
  literally true. No key ⇒ the command explains how to add one and does nothing.
- ✅ **Login-Item / SMAppService adapter — SHIPPED** via `sfltool dumpbtm`: when
  Apple exposes the inventory, a new Background Task Management item is diffed
  even without a `~/Library/LaunchAgents` plist. On macOS builds that require an
  interactive admin authorization, Aegis records a DEGRADED sensor and escalates
  repeated failures; it never converts denied inventory into an empty baseline.
- ✅ **Notarization introspection — SHIPPED for `.app` bundles**, where the
  `spctl -a -t exec` verdict is authoritative (fresh unsigned/ad-hoc app → HIGH;
  signed-but-unnotarized → MEDIUM). Bare CLI Mach-Os are *not* assessed — modern
  spctl rejects any non-app binary regardless of notarization ("valid but does
  not seem to be an app", verified on-host against `/bin/ls`), so the verdict
  carries no signal there. Standing caveat: a local tool can't see *online*
  ticket revocation, so notarization can be stale-good; the assessment itself is
  Apple's machinery and may consult Apple's servers (Aegis still sends nothing).
- ✅ **Web/phishing posture — SHIPPED, local/no-cloud:** Aegis parses `/etc/hosts`
  in one bounded pass, recognizes a StevenBlack-scale denylist, and alerts HIGH
  on non-blocking redirects of sensitive identity/update domains or punycode
  names. Missing hosts coverage stays INFO because DNS/Network Extension
  filtering may exist outside an unentitled process's view. The automatic path
  never downloads or installs third-party policy.
- **Power tier:** a separately signed/notarized app plus an ES system extension.
  Start in `NOTIFY` shadow mode, measure loss/drop/latency and false positives,
  then consider narrowly-scoped `AUTH` decisions with strict deadlines and a
  fail-open/fail-closed policy per event class. A Network Extension content filter
  is a separate entitlement and deployment surface. `eslogger` is diagnostics,
  not a production blocking architecture.

> **Note on the name.** "Norton" is a Gen Digital trademark; Aegis is *not*
> affiliated with it and does not claim to replace it. "Free Norton" is shorthand
> for *"a unified, local-only consumer security monitor"* — Aegis detects and
> alerts, and can quarantine / neutralize / destroy a threat **on command**, but it
> is not a *real-time blocking* antivirus (that needs Apple's ES entitlement).

## Verified

`selftest.py` passes: a real ad-hoc Mach-O in `/tmp` is detected + scored HIGH; a
new adhoc launch item in `/tmp` scores CRITICAL; a program-swap scores HIGH;
Developer-ID/Apple binaries are not over-flagged; `/bin/bash` classifies `apple`.
First-run against this machine correctly baselined 67 persistence items silently
and flagged the disabled firewall.

The `tests/` regression suite (**541 tests**, stdlib-only, fully sandboxed — never
touches real `~/.aegis` or fires a notification) pins the fixes from the
adversarial hardening pass ([BATTLE-LOG.md](BATTLE-LOG.md)) plus the
research-grounded detection surfaces added since: a signed interpreter + hostile
payload scores HIGH; a corrupt baseline refuses to silently re-trust; first-run
silence is scoped per-surface so a live threat present at install still alerts;
a swapped binary at an allowlisted path re-alerts (content hash in the
fingerprint); `/usr/local` and `/private/var/folders` are risky; the signature
cache invalidates on content change — including a same-size replacement whose
mtime was restored — and stays bounded.

The **protective tier** adds 51 tests in `tests/test_protective_tier.py`, each
pinning a property that would otherwise rot silently: a frozen process is proven
to make no progress and a thawed one to resume (asserted on work the child
actually performs, not on a process-state string); freeze refuses its own
ancestors, so it can never suspend the shell it runs under; an unreviewed freeze
auto-releases; `unlatch` refuses a non-interactive caller; a decoy never replaces
a real file; the assay uses no EICAR and persists no nonce; clipboard content
that does not match the grammar is proven absent from every file Aegis writes;
`curl … | sh` is proven to stay *suspect* and never get rewritten; and — the
load-bearing one — **a same-uid attacker who reads `hmac.key` and rewrites the
notary chain with every head and MAC recomputed defeats all local checks and is
still caught by the anchors in the root-owned log store.** That last test is the
difference between this design and the unprivileged Tripwire/AIDE clones that
die because the attacker rewrites the baseline.

One pre-existing defect surfaced while building it, and it was far larger than
the guard that exposed it. macOS `ps` truncates the `comm` column to 16
characters **when `args` is requested in the same call** — exactly how
`_iter_processes` queried it. Measured on the author's machine: **305 of 642
processes (47%) reported an executable path that does not exist on disk.** Every
consumer graded that prefix — `classify_signature()` answers `missing` for a path
that isn't there, and `is_risky_location()` answers `False` for a binary
genuinely running from a risky directory, so the **process sensor was scoring a
truncation**. Asked for on its own, `comm` is the full path (measured intact at
119 characters), so the fix is two `ps` calls joined on pid. After it, 21 of 627
— and those remaining are processes for which macOS genuinely reports a bare
name or a relative path, not truncation. Pinned by a test that runs against the
real process table rather than a fixture, because a fixture would have inherited
the same wrong assumption the code did.

The **web-protection + trust-cache tier** adds 8 fail-before/pass-after tests: a
substantial local hosts denylist is recognized; default hosts files are reported
as INFO without claiming DNS/NE protection is absent; sensitive-domain and
punycode redirects to non-blocking addresses score HIGH; deliberate loopback
blocks do not false-positive; unreadable hosts data degrades sensor health; the
sensor is wired into every scan; and a same-size, same-mtime executable
replacement is forced through strict `codesign` verification instead of reusing
a stale trusted cache entry. Two incident-lifecycle regressions additionally
prove an exact reviewed false positive stays suppressed while accumulating
evidence, but a resolved threat that recurs opens a fresh incident.

The **research-derived layer** adds 43 further fail-before/pass-after tests
([tests/test_research_layers.py](tests/test_research_layers.py)): a `curl|bash`
and a `node -e "eval(Buffer.from(…,'base64'))"` install hook are both caught while
five ordinary prebuilt-binary installers stay silent; a GUI-kill loop scores
CRITICAL while a plain `killall Dock` scores nothing; `SystemUIServerl` is caught
as a typosquat while the real daemon is not; a `caffeinate`/`sudo -u` wrapper
fronting a hidden payload is unwrapped and scored, while the same wrapper around
a legitimate app is not; a drop backdated **30 days** still chains to its later
execution; two sensors corroborating escalate sooner *without* regressing the
documented single-sensor guarantee; one dismissal cannot mute a sensor but six
can down-weight it; and `replay` is proven to leave durable state byte-identical.

The **response tier** pins files and valid `.app` bundles, native metadata-
preserving round trips, durable crash recovery after the source rename, audit-
failure refusal before mutation, manifest reconstruction from authoritative
transactions, hard-link/cross-volume/protected-path refusal, exclusive collision
restore, confirmed destroy approval, and the refusal to execute samples on-host.

The **layered core** pins privacy redaction before every persistence sink,
idempotent/private SQLite initialization, one event per observation, stable
signal occurrence counts, same-entity multi-layer correlation, incident lifecycle
validation, bounded reminders, durable degraded sensor health, recovery, and the
rule that an unavailable hardening probe is UNKNOWN rather than clean. Legacy
baselines are integrity-checked, migrated to hashed/redacted arguments, and
re-watermarked without generating upgrade-only persistence changes.

The **behavioral tier** (this release) is pinned against the 2025-26 stealer TTPs:
a fake `osascript … hidden answer` password prompt → **CRITICAL**; `dscl -authonly`,
`xattr -c com.apple.quarantine`, `hdiutil -nobrowse`, `tccutil reset`, a
`login.keychain-db` copy, a `curl -F file=@/tmp/*.zip` exfil, and a `curl…|bash`
fileless pipeline → **HIGH**; a lone benign `curl|bash` (no fetch+exec combo) stays
below the notify floor; a `|` inside a quoted `perl/sed` regex is **not** mistaken
for a shell pipe. An **XProtect Remediator** detection event parses to CRITICAL and
a clean `NoThreatDetected` scan to nothing. Same-user filtering and never-flag-self
are pinned. The earlier detectors remain pinned against **AMOS**, **RustBucket/
BlueNoroff** (now generalized to `com.google.*`/`com.microsoft.*` vendor
impersonation), **Cuckoo/ClickFix**, **Phexia**, and **Paradox**.

The **event/listener/app-bundle tier** (this release) is pinned by 14 tests: the
lsof parse drops loopback binds and keeps wildcard + non-loopback IPv6; Apple
platform daemons are skipped while `/usr/bin/python3`, `/usr/bin/nc` and any
third-party path stay tracked; a new ad-hoc listener from a user-writable path
scores HIGH and a signed one MEDIUM (below the notify floor); an unchanged
listener never re-alerts and the surface is adopted silently into the baseline;
a fresh ad-hoc `.app` bundle in a hot dir scores HIGH, a (stubbed)
signed-but-unnotarized one MEDIUM carrying Gatekeeper's verdict, a notarized one
stays silent, and a malformed bundle neither alerts nor raises; a real ad-hoc
binary is `spctl`-rejected; and the kqueue watch demonstrably wakes **within
seconds** of a file landing in a watched dir (and times out quietly without one).
`install.sh` output for both modes passes `plutil -lint` in a sandboxed `$HOME`
(launchctl stubbed), and re-running in scan mode leaves no `KeepAlive` residue.
The **live-tail + probe-hardening** follow-up adds 8 more: the `log stream` tail
spawns and terminates cleanly, real data on its fd wakes the same kqueue within
seconds, and the fd drains fully (no busy-spin); a booby-trapped
`CFBundleExecutable` with a path separator (`/bin/sh`, `../../x`) is refused so
it can't escape the bundle and misclassify a clean Apple binary
(fail-before/pass-after proven vs `5b95c2c`); a fresh payload swapped into an
*old* `.app` still flags HIGH because bundle freshness is `max(root, exe)` mtime
(likewise proven); and the lsof parser never raises on fuzzed/garbage input.

The **reputation + background-item tier** (this release) is pinned by 12 tests:
`sfltool dumpbtm` parsing separates real items from embedded sub-refs and never
raises on garbage; a new no-Team-ID item in a user-writable path scores HIGH, a
teamed one MEDIUM, a pre-existing one never re-alerts, and a `%20`-encoded URL
path is decoded for location scoring. The `vt` command **refuses without a key
and makes no network call** (the scan path's local-only guarantee is structural,
not incidental); the key is read env-first then file; a bad target is refused;
and with a stubbed `urlopen` the request carries **only the sha256** and the key
header — proving file bytes never leave the host. The lookup itself is exercised
against a fake transport (no live VT call in the suite). A **fallible snapshot**
(sfltool/lsof timing out) returns `None`, a *non-answer* the scan **skips** — so
a slow `sfltool dumpbtm` can never adopt a false-empty baseline and then storm
~90 bogus "new background item" alerts when it recovers (three tests pin the
None-skip and no-storm-on-diff behavior; found by an on-machine end-to-end scan).

**Live end-to-end run** on this machine (real data, sandboxed state): the full
`scan` completed, the behavioral check ran clean across ~500 real processes with
**zero false positives**, XProtect harvest parsed the unified log in ~1.5s, and the
run surfaced two real FPs that were then fixed and regression-pinned — a `perl`
one-liner whose regex alternation looked like a pipe, and the *legitimate* Google
Keystone agent (unresolvable program ⇒ now LOW, not a HIGH impersonation). Existing
shell history was adopted silently on first run; the second run was clean.

**Re-run for this release** (same method — real machine, sandboxed state): the
listener snapshot tracked **0 entries** on this Mac (loopback dev servers and
Apple platform daemons correctly excluded — zero baseline churn), the fresh-state
scan surfaced only true positives already known to this machine (its own CI
runners, a real `curl…|sh` install line in history, the disabled firewall), no
hot-dir or listener false positives appeared, and the second scan was quiet at
~2.3s warm.
