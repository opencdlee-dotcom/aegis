# Aegis — a personal macOS background security monitor

A small, honest, **detect-and-alert** security monitor for your own Mac. It runs
in the background (launchd), watches the surfaces macOS malware actually uses,
and tells you when something new and suspicious appears — with **zero third-party
dependencies** (Python standard library only), **local-only** (no telemetry, no
cloud), and **no signing cert required**.

> It is not "Norton," and it deliberately doesn't pretend to be. Read *Honest
> scope* below — the ceiling is set by Apple, not by effort.

---

## TL;DR — what it does

Runs `aegis.py scan` on an interval and reports/alerts on:

| Check | What it catches | Why it matters |
|---|---|---|
| **Persistence watch** | New/changed launchd agents & daemons + cron, each program hashed + signature-classified, diffed vs baseline — **arguments inspected** (`bash -c "curl…\|sh"`, `base64 -d\|sh`, `/dev/tcp`), **DYLD_* injection env flagged**, **an interpreter run against a hidden `$HOME`/tmp script caught** (AMOS `/bin/bash ~/.agent`), and **vendor-label impersonation caught** (a `com.apple.*` / `com.google.*` / `com.microsoft.*` plist whose program isn't signed by that vendor's Team ID — RustBucket's `com.apple.systemupdate` behind a hijacked cert, ClickFix's fake `com.google.keystone`) | The #1 macOS infostealer signal — AMOS/Atomic, Poseidon/Odyssey persist via `LaunchAgents`/`LaunchDaemons` |
| **Process watch** | Running processes whose executable is unsigned/ad-hoc **and** in a user-writable path | Malware runs ad-hoc-signed binaries from `/tmp`, `~/`, `/Users/Shared` |
| **Behavioral watch** *(new)* | The full **command line** of every same-user process, scored for the fileless-stealer TTPs: a fake `osascript … display dialog … hidden answer` **password phish** (CRITICAL), `dscl . -authonly` local-password check, `xattr -c/-d com.apple.quarantine` **provenance strip**, `hdiutil attach -nobrowse` **invisible DMG mount**, `tccutil reset`, a `login.keychain-db` copy, a `curl -F file=@/tmp/*.zip` **exfil POST**, and a `curl … \| bash/osascript` **fileless pipeline** | The dominant 2025-26 stealer TTP is fileless — it runs through Apple-signed interpreters (bash/osascript/curl) whose *path* is trusted, so only the argv reveals the attack. This is the biggest coverage gain in this release |
| **XProtect harvest** *(new)* | Reads Apple's own **XProtect Remediator** detections straight from the unified log (`com.apple.XProtectFramework.PluginAPI`) — a `status != NoThreatDetected` event means Apple's engine found/removed malware (CRITICAL) — plus flags **stale XProtect definitions** (>60 days) | Piggybacks Apple's professionally-maintained, always-updating signature/behavioral engine for free — no entitlement, no cloud. The single highest-value signal a signature-less tool can add |
| **Hot-dir watch** | Freshly-dropped unsigned Mach-O executables in Downloads/Desktop/tmp/Shared, tagged with **quarantine provenance** — a binary with *no* quarantine flag bypassed Gatekeeper (side-loaded via `curl`/`scp`/AirDrop) | Catches a payload the moment it lands, before it runs |
| **Staging watch** *(new)* | Documented stealer **loot-staging artifacts** in `/tmp`/`/Users/Shared` — `app.zip` (Atomic), `ledger.zip` (Odyssey/Poseidon), `salmonela.zip` (MacSync), `wid.txt`, `.pass`, `shub_*`, a copied `login.keychain-db` | Smash-and-grab stealers stage loot then exfil in under a minute, leaving no persistence — this catches the residue |
| **Shell history** *(new)* | The recent tail of `~/.zsh_history`/`.bash_history`/fish for the **ClickFix terminal-paste** chain — `dscl . -authonly`, `curl … \| sh`, `xattr -c`, `hdiutil -nobrowse` — one alert per unique hostile command | ClickFix (fake-CAPTCHA paste) is now the dominant macOS initial-access vector; the payload is fetched inside a trusted Terminal so it never gets a quarantine xattr — history is the residue |
| **Wallet integrity** *(new)* | Content-hash of installed crypto-wallet configs + app binaries (Ledger Live `app.json`, Trezor Suite, Exodus); any change alerts HIGH | 2025 stealers hijack funds by rewriting Ledger Live's `app.json` or swapping wallet bundles for drainers (DigitStealer, Odyssey) |
| **Canary files** *(new, opt-in)* | Hidden decoy files you plant with `aegis.py canary`; any modification/deletion alerts CRITICAL | Attribution-independent ransomware / bulk-tamper tripwire — a process encrypting a folder trips a canary with near-zero false positives |
| **Shell startup files** | New or modified `~/.zshrc`/`.zprofile`/`.bashrc`/… (ATT&CK T1546.004); a download-and-run or reverse-shell idiom scores HIGH | ClickFix/AMOS chains drop a re-execing payload into your shell rc |
| **Login/Logout hooks** | Legacy `com.apple.loginwindow` LoginHook/LogoutHook | Rare-legit today; a classic persistence primitive |
| **Config profiles** | A newly-installed configuration profile | Adds trusted certs / proxies / MDM control — an adware & DPRK vector |
| **Extra persistence** | `/etc/crontab`, `/etc/periodic`, StartupItems, `/etc/rc.common` tamper | Persistence surfaces beyond `LaunchAgents` and the user crontab |
| **Browser extensions** | New Chromium-family / Firefox extension appearing | Malicious extensions exfiltrate sessions, cookies, wallet data |
| **Editor extensions** | New VSCode / Cursor / VSCodium / Windsurf extension | A backdoored editor extension is a live supply-chain vector (Objective-See's *Paradox*, 2025, shipped via a trojanised Cursor extension) |
| **Self-protection** | Aegis's own launchd agent removed, its append-only log truncated, or its **trust store (baseline/allowlist) edited out-of-band** | A monitor an attacker can silently disable, blind, or feed a poisoned baseline is theater |
| **Hardening posture** | SIP, Gatekeeper, FileVault, Application Firewall, stealth mode, Remote Login, **+ XProtect definition age** | Surfaces weak settings (a first run typically finds a control the operator assumed was on) |

**Design principle — log everything, alert rarely, never repeat.** The first run
records a *silent* baseline (no day-one alert storm — the KnockKnock/LuLu "trust
what's already installed" rule). The shell-rc, profile, hook, extra-persistence,
browser-extension, wallet and **shell-history** surfaces extend this rule
**per-surface**: each is adopted silently the first time it's seen (a months-old
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
python3 aegis.py canary        # plant ransomware canary/honeypot files (opt-in)
python3 aegis.py canary remove # ...and remove them

bash install.sh              # background it via launchd (hourly); one baseline first
bash install.sh 1800         # ...or every 30 min (re-run keeps your baseline)
bash uninstall.sh            # remove the launchd agent
python3 selftest.py                    # quick detection-logic smoke (stdlib only)
python3 -m unittest discover -s tests  # full regression suite (stdlib only)
```

State lives in `~/.aegis/`: `baseline.json`, `findings.jsonl` (durable log),
`latest.md` (last report), `seen.json` (dedup), `allowlist.json`, `sigcache.json`.

**Full Disk Access (optional):** grant it to `/usr/bin/python3` in *System
Settings ▸ Privacy & Security ▸ Full Disk Access* so Aegis can read TCC-protected
locations. Core persistence/hardening checks work without it.

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
  Aegis **detects residue within a poll interval; it does not block.**
- **Same-user only.** An unprivileged agent can read the command line of *your*
  processes but not root's or another user's (`KERN_PROCARGS2`). Consumer stealers
  run as you, so this covers the common case — but a root-escalated payload's argv
  is invisible without going root (a privilege jump Aegis deliberately refuses).

Defensible claim: *"detects the residue of X-class activity within one poll."*
Not defensible, and not claimed: *"blocks malware."*

---

## Trust model (a monitor is itself a privileged surveillance surface)

A security tool sees everything, so it must be trustworthy *by construction*:
- **Local-only** — never phones home; no telemetry, no cloud.
- **Stdlib-only** — no pip packages = no supply-chain surface to audit.
- **Readable** — one ~2,000-line file you can read end to end; it shells out only to
  Apple's own signed CLIs (`codesign`, `spctl`, `csrutil`, `launchctl`, `log`, …).
- **Read-only to your system** — it writes only inside `~/.aegis/`, with **one**
  explicit exception: `aegis.py canary` plants decoy files (only on that command).
- **No new privileged parser.** Aegis deliberately does *not* ship a YARA/file
  scanner that parses untrusted binaries — that reintroduces the exact
  privileged-parser RCE surface (cf. Norton/Symantec CVE-2016-2208) that a minimal
  local tool exists to avoid. It **harvests Apple's XProtect detections** instead
  of re-implementing a scanner.

---

## Roadmap (if this grows past "personal tool")

- **Real-time (not polling):** watch persistence dirs + `/tmp` via `select.kqueue`
  (in the stdlib) or an FSEvents helper for instant drops; tail `log stream` in a
  persistent subprocess for live behavioral events instead of windowed `log show`.
  This is the highest-value next step — it closes the sub-minute polling gap.
- **Reputation:** optional VirusTotal hash lookups for flagged binaries (bring your
  own API key; **off by default** so the local-only guarantee stays literally true).
- **Notarization introspection:** `spctl -a -t exec` verdict on hot-dir drops to
  distinguish notarized-Developer-ID from ad-hoc (with the honest caveat that a
  local tool can't see *online* ticket revocation, so notarization can be stale-good).
- **Web/phishing (local, no cloud):** a StevenBlack-style hosts blocklist check.
- **Blocking tier / eslogger power mode:** only as an explicit, opt-in, clearly
  privilege-raising mode (eslogger needs root + Full Disk Access) — never silently.
  A Developer-ID cert → notarization → ES entitlement → System Extension is the
  real-blocking path, worth it only as a product.

> **Note on the name.** "Norton" is a Gen Digital trademark; Aegis is *not*
> affiliated with it and does not claim to replace it. "Free Norton" is shorthand
> for *"a unified, local-only consumer security monitor"* — Aegis detects and
> alerts; it is not a blocking antivirus.

## Verified

`selftest.py` passes: a real ad-hoc Mach-O in `/tmp` is detected + scored HIGH; a
new adhoc launch item in `/tmp` scores CRITICAL; a program-swap scores HIGH;
Developer-ID/Apple binaries are not over-flagged; `/bin/bash` classifies `apple`.
First-run against this machine correctly baselined 67 persistence items silently
and flagged the disabled firewall.

The `tests/` regression suite (**86 tests**, stdlib-only, fully sandboxed — never
touches real `~/.aegis` or fires a notification) pins the fixes from the
adversarial hardening pass ([BATTLE-LOG.md](BATTLE-LOG.md)) plus the
research-grounded detection surfaces added since: a signed interpreter + hostile
payload scores HIGH; a corrupt baseline refuses to silently re-trust; first-run
silence is scoped per-surface so a live threat present at install still alerts;
a swapped binary at an allowlisted path re-alerts (content hash in the
fingerprint); `/usr/local` and `/private/var/folders` are risky; the signature
cache invalidates on content change and stays bounded.

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

**Live end-to-end run** on this machine (real data, sandboxed state): the full
`scan` completed, the behavioral check ran clean across ~500 real processes with
**zero false positives**, XProtect harvest parsed the unified log in ~1.5s, and the
run surfaced two real FPs that were then fixed and regression-pinned — a `perl`
one-liner whose regex alternation looked like a pipe, and the *legitimate* Google
Keystone agent (unresolvable program ⇒ now LOW, not a HIGH impersonation). Existing
shell history was adopted silently on first run; the second run was clean.
