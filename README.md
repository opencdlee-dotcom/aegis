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
| **Persistence watch** | New/changed launchd agents & daemons + cron, with each program hashed + code-signature-classified, diffed vs a known-good baseline — **arguments inspected** (`bash -c "curl…\|sh"`, `base64 -d\|sh`, `/dev/tcp` reverse shells) **and DYLD_* injection env flagged**, so a signed interpreter driven by a hostile payload is caught even though the binary itself is Apple-signed | The #1 macOS infostealer signal — AMOS/Atomic, Poseidon persist via `LaunchAgents` |
| **Process watch** | Running processes whose executable is unsigned/ad-hoc **and** in a user-writable path | Malware runs ad-hoc-signed binaries from `/tmp`, `~/`, `/Users/Shared` |
| **Hot-dir watch** | Freshly-dropped unsigned Mach-O executables in Downloads/Desktop/tmp/Shared, tagged with **quarantine provenance** — a binary with *no* quarantine flag bypassed Gatekeeper (side-loaded via `curl`/`scp`/AirDrop) | Catches a payload the moment it lands, before it runs |
| **Shell startup files** | New or modified `~/.zshrc`/`.zprofile`/`.bashrc`/… (ATT&CK T1546.004); a download-and-run or reverse-shell idiom scores HIGH | ClickFix/AMOS chains drop a re-execing payload into your shell rc |
| **Login/Logout hooks** | Legacy `com.apple.loginwindow` LoginHook/LogoutHook | Rare-legit today; a classic persistence primitive |
| **Config profiles** | A newly-installed configuration profile | Adds trusted certs / proxies / MDM control — an adware & DPRK vector |
| **Extra persistence** | `/etc/crontab`, `/etc/periodic`, StartupItems, `/etc/rc.common` tamper | Persistence surfaces beyond `LaunchAgents` and the user crontab |
| **Browser extensions** | New Chromium-family / Firefox extension appearing | Malicious extensions exfiltrate sessions, cookies, wallet data |
| **Self-protection** | Aegis's own launchd agent removed, or its append-only log truncated | A monitor an attacker can silently disable or blind is theater |
| **Hardening posture** | SIP, Gatekeeper, FileVault, Application Firewall, stealth mode, Remote Login | Surfaces weak settings (a first run typically finds a control the operator assumed was on) |

**Design principle — log everything, alert rarely, never repeat.** The first run
records a *silent* baseline (no day-one alert storm — the KnockKnock/LuLu "trust
what's already installed" rule). The shell-rc, profile, hook, extra-persistence
and browser-extension surfaces extend this rule **per-surface**: each is adopted
silently the first time it's seen, so *upgrading* Aegis on an existing install is
also storm-free. After that, only **new** findings at **HIGH+** raise a desktop
notification, and each fires **once**. Everything, always, is appended to a
durable log (`~/.aegis/findings.jsonl`) so nothing is lost if a notification is
missed.

---

## Install / use

```bash
# from the aegis/ directory:
python3 aegis.py scan        # run once, print report, establish baseline
python3 aegis.py status      # fast hardening posture only
python3 aegis.py report      # reprint the latest report
python3 aegis.py baseline    # accept current state as known-good (resets diff)
python3 aegis.py allow PATH  # stop alerting on findings matching PATH

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

---

## Trust model (a monitor is itself a privileged surveillance surface)

A security tool sees everything, so it must be trustworthy *by construction*:
- **Local-only** — never phones home; no telemetry, no cloud.
- **Stdlib-only** — no pip packages = no supply-chain surface to audit.
- **Readable** — one ~500-line file you can read end to end; it shells out only to
  Apple's own signed CLIs (`codesign`, `spctl`, `csrutil`, `launchctl`, …).
- **Read-only to your system** — it writes only inside `~/.aegis/`.

---

## Roadmap (if this grows past "personal tool")

- **Real-time (not polling):** watch persistence dirs via FSEvents (public API, no
  entitlement) for instant new-launch-item alerts — a Swift/`fswatch` helper.
- **Reputation:** optional VirusTotal hash lookups for flagged binaries (bring your
  own API key; off by default for privacy).
- **YARA rules:** scan flagged files with `yara` (Homebrew) for known families.
- **Blocking tier:** get a Developer-ID cert → notarize → apply for the ES
  entitlement → ship a System Extension. Only worth it as a real product.

## Verified

`selftest.py` passes: a real ad-hoc Mach-O in `/tmp` is detected + scored HIGH; a
new adhoc launch item in `/tmp` scores CRITICAL; a program-swap scores HIGH;
Developer-ID/Apple binaries are not over-flagged; `/bin/bash` classifies `apple`.
First-run against this machine correctly baselined 67 persistence items silently
and flagged the disabled firewall.

The `tests/` regression suite (21 tests, stdlib-only, fully sandboxed — never
touches real `~/.aegis` or fires a notification) pins the fixes from the
adversarial hardening pass documented in [BATTLE-LOG.md](BATTLE-LOG.md): a signed
interpreter + hostile payload scores HIGH; a corrupt baseline refuses to silently
re-trust; first-run silence is scoped to persistence so a live threat present at
install still alerts; a swapped binary at an allowlisted path re-alerts (content
hash in the fingerprint); `/usr/local` and `/private/var/folders` are treated as
risky; the signature cache invalidates on content change and stays bounded.
