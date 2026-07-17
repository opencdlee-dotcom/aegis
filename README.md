# Aegis — a personal macOS background security monitor

A small, honest **detect-and-alert** security monitor for your own Mac, with an
opt-in **response tier** to act on what it finds. It runs in the background
(launchd), watches the surfaces macOS malware actually uses, and tells you when
something new and suspicious appears — then, only when *you* run a response
command by hand, it can **quarantine, neutralize, sandbox, or destroy** the
threat. Zero third-party dependencies (Python standard library only),
**local-only** (no telemetry, no cloud), **no signing cert required**.

> It is not "Norton," and it deliberately doesn't pretend to be. The background
> scan is **detect-only and never destructive**; response is a separate, opt-in,
> reversible-by-default tier you invoke deliberately (see *Response tier* below).
> Read *Honest scope* too — the real-time-*blocking* ceiling is set by Apple, not
> by effort.

---

## TL;DR — what it does

Runs `aegis.py scan` on an interval and reports/alerts on:

| Check | What it catches | Why it matters |
|---|---|---|
| **Persistence watch** | New/changed launchd agents & daemons + cron, each program hashed + signature-classified, diffed vs baseline — **arguments inspected** (`bash -c "curl…\|sh"`, `base64 -d\|sh`, `/dev/tcp`), **DYLD_* injection env flagged**, **an interpreter run against a hidden `$HOME`/tmp script caught** (AMOS `/bin/bash ~/.agent`), and **vendor-label impersonation caught** (a `com.apple.*` / `com.google.*` / `com.microsoft.*` plist whose program isn't signed by that vendor's Team ID — RustBucket's `com.apple.systemupdate` behind a hijacked cert, ClickFix's fake `com.google.keystone`) | The #1 macOS infostealer signal — AMOS/Atomic, Poseidon/Odyssey persist via `LaunchAgents`/`LaunchDaemons` |
| **Process watch** | Running processes whose executable is unsigned/ad-hoc **and** in a user-writable path | Malware runs ad-hoc-signed binaries from `/tmp`, `~/`, `/Users/Shared` |
| **Behavioral watch** *(new)* | The full **command line** of every same-user process, scored for the fileless-stealer TTPs: a fake `osascript … display dialog … hidden answer` **password phish** (CRITICAL), `dscl . -authonly` local-password check, `xattr -c/-d com.apple.quarantine` **provenance strip**, `hdiutil attach -nobrowse` **invisible DMG mount**, `tccutil reset`, a `login.keychain-db` copy, a `curl -F file=@/tmp/*.zip` **exfil POST**, and a `curl … \| bash/osascript` **fileless pipeline** | The dominant 2025-26 stealer TTP is fileless — it runs through Apple-signed interpreters (bash/osascript/curl) whose *path* is trusted, so only the argv reveals the attack. This is the biggest coverage gain in this release |
| **XProtect harvest** *(new)* | Reads Apple's own **XProtect Remediator** detections straight from the unified log (`com.apple.XProtectFramework.PluginAPI`) — a `status != NoThreatDetected` event means Apple's engine found/removed malware (CRITICAL) — plus flags **stale XProtect definitions** (>60 days) | Piggybacks Apple's professionally-maintained, always-updating signature/behavioral engine for free — no entitlement, no cloud. The single highest-value signal a signature-less tool can add |
| **Hot-dir watch** | Freshly-dropped unsigned Mach-O executables **and `.app` bundles** in Downloads/Desktop/tmp/Shared, tagged with **quarantine provenance** — a binary with *no* quarantine flag bypassed Gatekeeper (side-loaded via `curl`/`scp`/AirDrop). A fresh signed-but-**unnotarized** app additionally gets Gatekeeper's own `spctl` verdict surfaced (MEDIUM — a normal quarantined launch would refuse it, so one that runs was side-loaded or force-approved) | Catches a payload the moment it lands, before it runs — including the #1 delivery shape, a DMG/ZIP-dragged `.app`, which is a *directory* and invisible to any file-only check |
| **Staging watch** *(new)* | Documented stealer **loot-staging artifacts** in `/tmp`/`/Users/Shared` — `app.zip` (Atomic), `ledger.zip` (Odyssey/Poseidon), `salmonela.zip` (MacSync), `wid.txt`, `.pass`, `shub_*`, a copied `login.keychain-db` | Smash-and-grab stealers stage loot then exfil in under a minute, leaving no persistence — this catches the residue |
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
| **Background items** *(new)* | A **new** Login Item / SMAppService background agent from `sfltool dumpbtm` (macOS's own Background Task Management record), baseline-diffed. A new item with **no Team ID whose URL is in a user-writable path** → HIGH, else MEDIUM | Catches the modern persistence path the LaunchAgents-directory scan **cannot see**: an `SMAppService`-registered agent/daemon that never drops a plist in `~/Library/LaunchAgents` (how legit apps *and* 2024+ malware now register) |
| **Self-protection** | Aegis's own launchd agent removed, **its own plist present-but-malformed** (invalid XML that launchd will silently refuse on the next reboot — the monitor dies with no signal), its append-only log truncated, or its **trust store (baseline/allowlist) edited out-of-band** | A monitor an attacker can silently disable, blind, or feed a poisoned baseline — or that quietly rots itself into non-execution — is theater |
| **Hardening posture** | SIP, Gatekeeper, FileVault, Application Firewall, stealth mode, Remote Login, **+ XProtect definition age** | Surfaces weak settings (a first run typically finds a control the operator assumed was on) |

**Design principle — log everything, alert rarely, never repeat.** The first run
records a *silent* baseline (no day-one alert storm — the KnockKnock/LuLu "trust
what's already installed" rule). The shell-rc, profile, hook, extra-persistence,
browser-extension, wallet, **network-listener** and **shell-history** surfaces
extend this rule **per-surface**: each is adopted silently the first time it's seen (a months-old
`curl…|sh` install line already in your history is *residue*, not a live threat),
so *upgrading* Aegis on an existing install is also storm-free. The **live-threat**
surfaces — a running hostile process (behavioral), an XProtect detection, a `/tmp`
staging drop, a hot-dir binary, a modified canary, a weak hardening setting — are
*never* first-run-suppressed: those are current risks you must hear about even on
the very first scan. After that, only **new** findings at **HIGH+** raise a desktop
notification, and each fires **once**. Everything, always, is appended to a
durable log (`~/.aegis/findings.jsonl`) so nothing is lost if a notification is
missed. New detections favour **hard-to-vary structural invariants** (a non-Apple
process copying `login.keychain-db`; a quarantine-xattr strip) over easily-shed
string patterns, because Aegis is open-source and an attacker can read its checks.

---

## Install / use

```bash
# from the aegis/ directory:
python3 aegis.py scan          # run once, print report, establish baseline
python3 aegis.py status        # fast hardening posture + XProtect definition age
python3 aegis.py report        # reprint the latest report
python3 aegis.py baseline      # accept current state as known-good (resets diff)
python3 aegis.py allow PATH    # stop alerting on findings matching PATH
python3 aegis.py vt PATH|SHA   # OPT-IN VirusTotal reputation (BYO key; sends only
                               #   the hash, never the file; scan stays local-only)
python3 aegis.py canary        # plant ransomware canary/honeypot files (opt-in)
python3 aegis.py canary remove # ...and remove them

# RESPONSE TIER — opt-in, run by hand on a reviewed finding (never automatic):
python3 aegis.py quarantine PATH     # neutralize + confine a file to a reversible store
python3 aegis.py quarantine-list     # list the store (ids to restore/destroy)
python3 aegis.py restore ID          # un-quarantine byte-for-byte (undo a false positive)
python3 aegis.py destroy ID --yes    # securely erase a quarantined item (IRREVERSIBLE)
python3 aegis.py kill PID            # terminate one of YOUR processes (SIGTERM→SIGKILL)
python3 aegis.py sandbox PATH        # detonate a suspect binary in a deny-default jail
python3 aegis.py neutralize PLIST    # launchd kill-chain: bootout → kill → quarantine

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

State lives in `~/.aegis/`: `baseline.json`, `findings.jsonl` (durable log),
`latest.md` (last report), `seen.json` (dedup), `allowlist.json`, `sigcache.json`,
`actions.jsonl` (response-action audit), and `quarantine/` (the reversible store).

**Where the agent runs from (why it's a copy).** `install.sh` copies `aegis.py`
to `~/.aegis/aegis.py` and points the launchd agent there — **not** at the repo.
A repo under `~/Documents/…` sits in a **TCC-protected** location, and a
launchd-spawned `python3` has no Full Disk Access, so it gets *"Operation not
permitted"* merely **opening** the script — every scheduled run then fails with
no signal (this was live on the author's own machine: the background monitor had
never actually run). `~/.aegis` is not TCC-protected, so the copy runs with zero
setup. Manual `python3 aegis.py …` from the repo still works (your shell has TCC
access). **Re-run `install.sh` after editing `aegis.py`** to refresh the copy.

**Full Disk Access (optional):** with the copy install above, persistence /
process / hardening / shell-history / BTM / listener checks all work with **no**
FDA. To *also* scan `~/Downloads` and `~/Desktop` drops (themselves TCC-protected),
grant FDA to `/usr/bin/python3` in *System Settings ▸ Privacy & Security ▸ Full
Disk Access*.

---

## Response tier — act on a finding (opt-in, staged, reversible-by-default)

The scan/watch path is **detect-only** and never touches your files. Acting on a
threat is a separate tier you invoke **by hand, on a finding you've reviewed** —
Aegis never auto-remediates. Its shape is copied straight from how commercial
EDR does it (this is the research payload behind the design):

- **The staged ladder** mirrors **SentinelOne's** *Kill → Quarantine → Remediate
  → Rollback*. Quarantine is reversible; **Remediate (destroy) is the only
  irreversible step**, and by construction it can act **only on something already
  quarantined** — there is *no* "delete a live path" command. This is the
  industry's **quarantine-first, never-delete-first** rule, encoded structurally.
- **Quarantine is a reversible store with restore metadata**, exactly as
  **Microsoft Defender** documents it: the original path, mode, owner, hash, and
  the `com.apple.quarantine` provenance are recorded so `restore` puts the file
  back **byte-for-byte**. A false positive costs you minutes, not data — the
  Defender "every automated action must be reviewable and reversible" doctrine.

| Command | What it does | Reversible? |
|---|---|---|
| `quarantine PATH` | Copies the file into a confined store (`~/.aegis/quarantine/`, mode 700), **neutralizes** the stored bytes (repeating-key XOR so it can't be double-clicked into running and won't be re-flagged by another on-host scanner — the classic AV "neutered sample" trick), `chmod 000`, records restore metadata, then removes the original. **Verifies the store copy reconstructs to the original hash *before* deleting the original** (never-lose-data). | ✅ `restore` |
| `restore ID` | Reverses the neutralization, puts the file back at its recorded path (or `PATH.restored` if occupied), replays mode + quarantine xattr. | — |
| `destroy ID --yes` | **Irreversible.** Overwrites and unlinks a quarantined item. Refuses without `--yes`. | ❌ |
| `kill PID` | `SIGTERM`→`SIGKILL` a **same-user** process. Refuses other users' processes, `pid 0/1`, Aegis's own tree, and session-critical comms. | — |
| `sandbox PATH` | Detonates a suspect binary in a **deny-default Seatbelt jail** (`sandbox-exec`): no network, no filesystem writes, no keychain/App-Support reads — watch what it *tries* to do without letting it phone home or steal data. | — |
| `neutralize PLIST` | Ordered launchd kill-chain: **`launchctl bootout` first** (so a `KeepAlive` job can't relaunch), then kill any surviving instance, then quarantine the plist (+ its binary if risky). | ✅ (artifacts land in the store) |

Every response action — success **or** refusal — is appended to
`~/.aegis/actions.jsonl` as a durable audit trail.

**Hard safety rails** (all destructive verbs): quarantine-first-never-delete-first;
**protected-path refusal** (SIP/system/Apple locations, Aegis's own files, `$HOME`
and any ancestor of it — so a mistyped parent can't take your home directory);
same-user-only process actions; never-act-on-self; and directories/symlinks are
refused (regular files only).

**Honest caveats, stated plainly:**

- **`sandbox-exec` is Apple-deprecated but fully functional** (verified on macOS
  26; Apple itself and shipping CLIs like OpenAI's Codex still use `.sb` profiles).
  It's the *only* entitlement-free process jail available to a userspace tool — but
  it's a jail, **not a VM**; use a throwaway VM for true detonation, and know Apple
  could remove it in a future release.
- **Re-quarantining via the `com.apple.quarantine` xattr is a weaker lever than it
  looks.** On modern macOS, launch-approval also persists in the **MACL xattr and
  the provenance database**, so re-applying the quarantine flag may *not* force a
  full Gatekeeper re-evaluation of an app you already approved. Aegis's real
  containment is therefore **move-to-store + strip-exec + neutralize-bytes**, not
  the xattr — the xattr is only replayed on `restore` to preserve provenance.
- **Secure-erase is not guaranteed on APFS/SSD** (wear-levelling means a single
  overwrite can leave copies). FileVault is the real at-rest guarantee; `destroy`
  says so when it runs.

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

**The hard ceiling — real-time *blocking*.** Since macOS 11 (WWDC 2019) Apple
removed third-party kernel extensions; the sanctioned way to *block* a process/
file event is the **Endpoint Security framework (ESF)** in a System Extension.
ESF requires the restricted entitlement `com.apple.developer.endpoint-security.client`
— `es_new_client()` fails with `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` without it
— **plus** a Developer-ID cert **plus** notarization, and Apple approves the
entitlement case-by-case (often not for individuals). Your machine currently has
**0 signing identities and Xcode CLT only**, so the ESF/blocking path is closed
today. That's *why* Aegis is polling + userspace + detect-only: it's the maximal
useful tool that needs none of that gate.

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
  **`install.sh watch` narrows this gap to seconds** for every file-touch surface
  (a persistence write, a `/tmp` staging drop, an rc edit, a pasted ClickFix line
  hitting history — each triggers a kqueue rescan within ~3s, rate-limited to one
  event-scan/min), while argv/XProtect/listener sampling still runs at the
  full-scan floor. Even so it is detection *after* the write — Aegis **detects
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
- **Local-only on the scan/watch path** — the automatic monitor never phones home;
  no telemetry, no cloud. The **only** command that touches the network is
  `aegis.py vt`, which you run **by hand**, only with a key you supply, and which
  sends **only a hash, never a file** — the background scanner never invokes it and
  never even imports the networking module.
- **Stdlib-only** — no pip packages = no supply-chain surface to audit.
- **Readable** — one ~2,600-line file you can read end to end; it shells out only to
  Apple's own signed CLIs (`codesign`, `spctl`, `csrutil`, `launchctl`, `log`,
  `sfltool`, `lsof`, …).
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

- ✅ **Real-time (not polling) — SHIPPED** as `install.sh watch`: a stdlib
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
- ✅ **Login-Item / SMAppService coverage — SHIPPED** via `sfltool dumpbtm`
  (unprivileged): a new Background Task Management item is diffed even when it
  registers *without* a `~/Library/LaunchAgents` plist — the gap the directory
  scan structurally couldn't close.
- ✅ **Notarization introspection — SHIPPED for `.app` bundles**, where the
  `spctl -a -t exec` verdict is authoritative (fresh unsigned/ad-hoc app → HIGH;
  signed-but-unnotarized → MEDIUM). Bare CLI Mach-Os are *not* assessed — modern
  spctl rejects any non-app binary regardless of notarization ("valid but does
  not seem to be an app", verified on-host against `/bin/ls`), so the verdict
  carries no signal there. Standing caveat: a local tool can't see *online*
  ticket revocation, so notarization can be stale-good; the assessment itself is
  Apple's machinery and may consult Apple's servers (Aegis still sends nothing).
- **Web/phishing (local, no cloud):** a StevenBlack-style hosts blocklist check.
- **Blocking tier / eslogger power mode:** only as an explicit, opt-in, clearly
  privilege-raising mode (eslogger needs root + Full Disk Access) — never silently.
  A Developer-ID cert → notarization → ES entitlement → System Extension is the
  real-blocking path, worth it only as a product.

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

The `tests/` regression suite (**148 tests**, stdlib-only, fully sandboxed — never
touches real `~/.aegis` or fires a notification) pins the fixes from the
adversarial hardening pass ([BATTLE-LOG.md](BATTLE-LOG.md)) plus the
research-grounded detection surfaces added since: a signed interpreter + hostile
payload scores HIGH; a corrupt baseline refuses to silently re-trust; first-run
silence is scoped per-surface so a live threat present at install still alerts;
a swapped binary at an allowlisted path re-alerts (content hash in the
fingerprint); `/usr/local` and `/private/var/folders` are risky; the signature
cache invalidates on content change and stays bounded.

The **response tier** (this release) is pinned by 24 tests: a quarantined file's
stored bytes are neutralized (≠ the original), `chmod 000`, and the original is
removed only after the store copy is proven to reconstruct; `restore` returns the
file **byte-identical** and replays its mode; a name collision restores to
`PATH.restored`; `destroy` refuses without `--yes` and there is no live-path
delete; protected-path refusal covers SIP/system paths, Aegis's own files, `$HOME`
and its ancestors; `kill` refuses self/`pid 1`/other-user processes *without
signalling them*; `neutralize` quarantines a launchd plist; and `sandbox` runs a
benign binary to completion inside the real deny-default Seatbelt jail.

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
