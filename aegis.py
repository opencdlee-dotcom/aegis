#!/usr/bin/env python3
"""
Aegis - a personal macOS background security monitor (detect + opt-in response).

HONEST SCOPE
------------
This is a KnockKnock / osquery-tier *detection* tool with an opt-in RESPONSE
tier — not an antivirus and not a real-time *blocker*. Real-time blocking on
macOS requires Apple's Endpoint Security framework, which needs the restricted
`com.apple.developer.endpoint-security.client` entitlement PLUS a Developer-ID
signing certificate (Apple grants these case-by-case, often not to individuals).
Aegis deliberately uses only unprivileged, entitlement-free APIs and the stable
system CLIs, so it runs today with zero setup, no signing cert, and a minimal
attack/maintenance surface: Python standard library only, no third-party deps.

The scan/watch path is DETECT-ONLY and never destructive. Acting on a threat is
a separate, opt-in RESPONSE tier that you invoke by hand on a reviewed finding —
never automatically. It mirrors the industry ladder (SentinelOne Kill→Quarantine
→Remediate→Rollback; Microsoft Defender's reversible-store + review-every-action
doctrine): quarantine atomically confines a file or valid app bundle to a
REVERSIBLE store, restore reverses the native move without overwriting (a false
positive costs minutes, not data), and
destroy — the only irreversible verb — can act ONLY on an already-quarantined
item (quarantine-first, never-delete-first). Plus kill (same-user process),
sandbox (refuse host execution and require a disposable VM), and
neutralize (ordered bootout→kill→quarantine kill-chain for launchd persistence).

WHAT IT DOES (on an interval, via launchd)
------------------------------------------
  1. Persistence watch - enumerates third-party launchd agents/daemons + cron,
     resolves each program, hashes it, validates its code signature, inspects its
     arguments AND its DYLD_* injection env, catches an interpreter aimed at a
     hidden $HOME/tmp script (AMOS `/bin/bash ~/.agent`) and a com.apple.* label
     whose program isn't Apple-signed (RustBucket cert-hijack), and diffs against
     a known-good baseline. New/changed persistence is the #1 signal for macOS
     infostealers (AMOS/Atomic, Poseidon/Odyssey) that persist via launchd.
  2. Process watch      - flags running processes whose executable is
     unsigned / ad-hoc-signed AND lives in a user-writable location.
  3. Hot-dir watch      - flags freshly-dropped unsigned Mach-O executables AND
     .app bundles in Downloads / Desktop / tmp / Shared, annotated with
     quarantine provenance (a NO-quarantine binary bypassed Gatekeeper — a
     side-load signal); a signed-but-unnotarized fresh app gets Gatekeeper's
     own `spctl` verdict surfaced at MEDIUM.
  4. Hardening posture  - SIP, Gatekeeper, FileVault, Application Firewall,
     stealth mode, remote login (SSH). Reports weak settings.
  5. Shell startup files- baseline-diffs ~/.zshrc & friends (T1546.004); a
     download-and-run / reverse-shell idiom in one scores HIGH.
  6. Login/Logout hooks - legacy com.apple.loginwindow persistence primitives.
  7. Config profiles    - a newly-installed profile (trusted certs / MDM / proxy
     — an adware/DPRK vector).
  8. Extra persistence  - /etc/crontab, /etc/periodic, StartupItems, rc.common.
  9. Browser extensions - inventory diff (Chromium family + Firefox).
 10. Self-protection    - detects if Aegis's own launchd agent was removed, its
     plist is present-but-malformed (invalid XML launchd will refuse on reboot),
     or its append-only evidence log was truncated (a monitor an attacker can
     silently disable — or that quietly rots itself into non-execution — is theater).
 11. Network listeners  - a NEW process accepting connections from the network
     (non-loopback TCP LISTEN, via lsof): a bind shell / rogue server shape.
     Loopback dev servers and SIP-pinned Apple daemons are excluded by design.
 12. Background items    - `sfltool dumpbtm`: a NEW Login Item / SMAppService
     background agent, incl. ones that persist WITHOUT a LaunchAgents plist
     (the modern registration path the directory scan can't see).
 13. Web/phishing posture - locally parses `/etc/hosts` for a substantial domain
     denylist and HIGH-confidence DNS overrides (sensitive identity/update or
     punycode names redirected to a non-blocking address). Missing hosts-based
     coverage is INFO because DNS/Network Extension policy may be out of view.

  Surfaces 5-9, 11 and 12 are baseline-diffed and ADOPTED SILENTLY the first
  time each is seen (per-surface "trust what's already installed"), so upgrading
  Aegis on an existing install never produces a day-one alert storm.

  `watch` mode (bash install.sh watch) is EVENT-DRIVEN: a stdlib kqueue over
  the persistence/hot/staging/rc/history paths rescans within seconds of a
  change (debounced + rate-limited), with the interval scan as a floor —
  closing most of the polling-latency gap without any Apple entitlement. A
  persistent `log stream` tail of Apple's XProtect subsystem is armed on the
  same kqueue (EVFILT_READ), so a live XProtect detection wakes a rescan the
  instant Apple writes it; the tail is a wake source only — the rescan's
  windowed harvest still does the one authoritative parse/dedup/notify.

DESIGN PRINCIPLE: many imperfect layers, one honest decision path. The first run
establishes an UNVERIFIED silent baseline (no day-one storm and no clean claim).
Afterwards new HIGH+ findings and high-confidence multi-layer chains become
durable incidents with bounded reminders. Every observation and sensor result is
written locally so an unavailable sensor can never masquerade as clean coverage.

STATE  -> ~/.aegis/   (aegis.db, baseline.json, findings.jsonl, latest.md,
                       quarantine transactions, actions.jsonl audit, ...)
USAGE  -> aegis.py [scan|report|status|doctor|incidents|incident|baseline|
                    allow <path>|vt <path|sha>|
                    canary|watch]
          aegis.py [quarantine <path>|quarantine-list|restore <id>|
                    destroy <id> --yes|kill <pid>|sandbox <path>|neutralize <plist>]
"""

import json
import errno
import fcntl
import os
import plistlib
import re
import select
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import hashlib
import hmac
from contextlib import contextmanager
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Constants / paths
# --------------------------------------------------------------------------- #

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".aegis")
BASELINE = os.path.join(STATE_DIR, "baseline.json")
FINDINGS_LOG = os.path.join(STATE_DIR, "findings.jsonl")
LATEST_MD = os.path.join(STATE_DIR, "latest.md")
LATEST_JSON = os.path.join(STATE_DIR, "latest.json")
SEEN = os.path.join(STATE_DIR, "seen.json")
SIGCACHE = os.path.join(STATE_DIR, "sigcache.json")
ALLOWLIST = os.path.join(STATE_DIR, "allowlist.json")
RUN_LOG = os.path.join(STATE_DIR, "run.log")
EVENT_DB = os.path.join(STATE_DIR, "aegis.db")
BASELINE_SCHEMA_VERSION = 2
HOSTS_FILE = "/etc/hosts"

# A StevenBlack-style hosts denylist normally contains many thousands of
# entries. This is a posture threshold, not a claim that every smaller list is
# useless: below it Aegis emits INFO only and explicitly acknowledges that a DNS
# or Network Extension filter may be protecting the host out of view.
HOSTS_BLOCKLIST_MIN_DOMAINS = 1000
_HOSTS_BLOCK_ADDRESSES = frozenset(("0", "0.0.0.0", "127.0.0.1", "::", "::1"))
_SENSITIVE_HOST_ROOTS = frozenset((
    "apple.com", "icloud.com", "google.com", "gmail.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com",
    "github.com", "githubusercontent.com", "openai.com", "chatgpt.com",
    "virustotal.com",
))

# --- Response tier (opt-in; never automatic) --------------------------------- #
# The quarantine STORE: a confined, reversible holding area for native
# threat files. Mirrors the industry ladder (SentinelOne Kill→Quarantine→
# Remediate, Defender's reversible store with restore metadata): quarantine
# MOVES a file or valid app bundle here atomically, `restore` reverses the move,
# `destroy` is the only irreversible step and can ONLY act on an already-
# quarantined item (the "quarantine-first, never-delete-first" doctrine). Every
# response action is appended to a durable action log.
QUARANTINE_DIR = os.path.join(STATE_DIR, "quarantine")
QUARANTINE_MANIFEST = os.path.join(QUARANTINE_DIR, "manifest.json")
ACTION_LOG = os.path.join(STATE_DIR, "actions.jsonl")

# --- Reputation lookup (OPT-IN, off by default; NEVER on the scan path) ------- #
# The scan/watch path is local-only by construction — it makes ZERO network
# calls, and that guarantee is load-bearing to the trust model. `vt` is a
# separate, by-hand INVESTIGATION command (like the response tier): given a file
# or a hash, it queries VirusTotal's multi-engine reputation for that hash. It
# sends ONLY the sha256 — never the file bytes — so it can't leak file contents,
# and it runs only when you type it with a key present. Key: env AEGIS_VT_API_KEY
# or ~/.aegis/vt_key (chmod 600). No key ⇒ the command explains how to add one
# and does nothing. This keeps "the monitor never phones home" literally true
# while still offering reputation when you deliberately ask for it.
VT_KEY_FILE = os.path.join(STATE_DIR, "vt_key")
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

# --- Survivability: dead-man's switch + tamper-evidence ---------------------- #
# A same-uid attacker can SIGKILL Aegis or `launchctl bootout` its agent and
# blind every layer at once — silently (ATT&CK T1562.001). An unprivileged tool
# cannot PREVENT this, so the design is tamper-EVIDENCE, not tamper-prevention:
# the attacker may win locally, but must not win SILENTLY.
#   * HEARTBEAT_FILE: written on every healthy scan (ALWAYS, no network). Its
#     staleness is what an external watcher (or `aegis.py watchdog`) alarms on —
#     absence of the ping is the alert (the 2026 "alert on missing telemetry"
#     doctrine). A second launchd agent or cron calling `watchdog` is the
#     unprivileged mutual-watchdog.
#   * HEARTBEAT_URL (opt-in, BYO, off by default): if set, each healthy scan also
#     POSTs a heartbeat + any HIGH+ alert out-of-band, so "silence" travels off
#     the box the same session an attacker suppresses every LOCAL sink. Like `vt`
#     this is the ONLY networked path and is off unless YOU configure it, so the
#     scan/watch path stays local-only by default.
#   * HMAC-chained state: the self-protection trust-store check upgrades from a
#     plain hash to an hmac(key) so an attacker who edits baseline/allowlist AND
#     recomputes the plain hash still cannot forge the watermark without the key.
HEARTBEAT_FILE = os.path.join(STATE_DIR, "heartbeat.json")
HMAC_KEY_FILE = os.path.join(STATE_DIR, "hmac.key")  # 0600, not beside the data
AEGIS_CONFIG = os.path.join(STATE_DIR, "config.json")
WATCHDOG_ALERT = os.path.join(STATE_DIR, "watchdog_alert")  # durable sentinel
HEARTBEAT_STALE_SECS = 3 * 3600  # a scan every 10 min (watch) / hourly (interval)
# Opt-in off-host egress endpoint: env wins (inject for one run), else config.json.
HEARTBEAT_URL_ENV = "AEGIS_HEARTBEAT_URL"

# XProtect Behavioral Service (Bastion) violation DB — root-only (0600 root:wheel,
# UNIX perms not TCC). Apple records stealer-shape behavior here and never alerts;
# the opt-in `sudo aegis bastion` tier surfaces it. Path per macOS 15/26.
XPDB_PATH = "/var/protected/xprotect/db/XPdb"

# AI-agent skill directories — a live 2026 AMOS distribution channel (malicious
# OpenClaw/Claude "skills" that manipulate the agent into a fake password dialog,
# Trend Micro 2026). Same shape as the IDE-extension surface: a new skill dir or a
# changed SKILL.md is the signal. Symlinks resolve (the canonical skills tree is
# often a symlink into a projects folder). Directly relevant to an agent-heavy box.
AGENT_SKILL_ROOTS = [os.path.join(HOME, d) for d in (
    ".claude/skills", ".claude/plugins", ".codex/skills", ".gemini/extensions",
)]

# Absolute path of this script — never quarantine/kill/destroy Aegis itself.
_SELF_PATH = os.path.abspath(__file__)

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
NOTIFY_MIN_SEV = "HIGH"  # only >= this AND new gets a desktop notification

# launchd persistence directories (third-party). We deliberately skip
# /System/Library/Launch* - those are Apple-signed, SIP-protected, and pure noise.
PERSISTENCE_DIRS = [
    os.path.join(HOME, "Library", "LaunchAgents"),
    "/Library/" + "LaunchAgents",
    "/Library/" + "LaunchDaemons",
]

# Directories where a freshly-dropped executable is inherently suspicious.
HOT_DIRS = [
    os.path.join(HOME, "Downloads"),
    os.path.join(HOME, "Desktop"),
    "/tmp",
    "/private/tmp",
    "/Users/Shared",
]

# Path prefixes we treat as trusted-by-location (Apple-owned, read-only under
# SIP). NOTE: /usr/ is deliberately narrowed to its SIP subpaths — /usr/local is
# NOT SIP-protected (Homebrew's default Intel prefix is group-writable and a real
# malware drop target), so it must go through normal signature+location scoring.
TRUSTED_PREFIXES = ("/System/", "/usr/bin/", "/usr/lib/", "/usr/sbin/",
                    "/usr/libexec/", "/usr/share/", "/bin/", "/sbin/",
                    "/Library/Apple/")

# Path prefixes that are user-writable and therefore higher-risk for exec.
# /var is a symlink to /private/var on macOS, so the same location can appear
# under either form — list both. /usr/local (Intel Homebrew) and /opt/homebrew
# (Apple-Silicon Homebrew) are included per the note above: Homebrew chowns its
# prefix to the invoking user, so both are writable without sudo and a real
# malware drop target — neither is SIP-protected.
RISKY_PREFIXES = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders",
                  "/usr/local", "/opt/homebrew", "/Users/Shared", HOME)

MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # 32/64-bit
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # 32/64-bit LE
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # fat/universal
}

# Shell startup files (ATT&CK T1546.004). Readable with no special privilege; a
# documented execution-persistence surface — stealers append `curl…|sh` or a
# base64 blob here so a payload re-runs at every login/new-shell. We baseline
# their content hashes and alert on any NEW file or CHANGE.
SHELL_RC_FILES = [os.path.join(HOME, n) for n in (
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".config/fish/config.fish", ".config/fish/conf.d/aegis.fish",
)] + ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/bashrc"]

# Login/every-invocation-scoped rc files (sourced even by non-interactive shells
# and scripts). A NEWLY-appearing one is a high-signal persistence install — the
# DPRK/BlueNoroff "Hidden Risk" campaign used a fresh ~/.zshenv specifically
# because it runs on every zsh, not just interactive logins.
_LOGIN_SCOPED_RC = frozenset((
    ".zshenv", ".zprofile", ".zlogin", ".bash_profile", ".bash_login", ".profile"))

# Extra persistence surfaces beyond ~/Library/Launch* (already covered) and the
# user crontab. Files are content-hashed; dirs are walked one level for scripts.
# Only entries that EXIST are snapshotted, so a machine without them stays quiet.
# The hosts file (adware/phishing redirect), sshd config and the user's SSH trust
# files are here too: a NEWLY-appearing ~/.ssh/authorized_keys — or an edit to
# it — is the classic durable-remote-access implant (ATT&CK T1098.004), and an
# ~/.ssh/config ProxyCommand hijack runs code on every ssh.
EXTRA_PERSIST_FILES = ["/etc/crontab", "/etc/rc.common", "/etc/launchd.conf",
                       os.path.join(HOME, ".launchd.conf"),
                       "/etc/hosts", "/etc/ssh/sshd_config",
                       os.path.join(HOME, ".ssh", "authorized_keys"),
                       os.path.join(HOME, ".ssh", "config")]
# pam.d / sudoers.d: an added pam module line or sudoers drop-in is silent
# privilege persistence (T1556). Root-only-readable entries (most sudoers.d
# files) hash to None and are skipped — coverage degrades gracefully, and a
# world-readable drop or a pam edit (644 root:wheel — readable) is still caught.
EXTRA_PERSIST_DIRS = ["/etc/periodic", "/etc/emond.d/rules",
                      "/Library/StartupItems", "/System/Library/StartupItems",
                      "/etc/pam.d", "/etc/sudoers.d", "/etc/ssh/sshd_config.d",
                      # Residual ASEP surfaces from KnockKnock's 60+ categories,
                      # walked by the same content-hash+diff machinery: a NEW
                      # authorization plugin, Spotlight importer (.mdimporter),
                      # QuickLook generator, scripting addition (OSAX), or folder
                      # action bundle is a rarely-legit persistence install. Only
                      # the world-readable ones hash; existing plugins are
                      # baselined silently, so only a net-new one alerts.
                      "/Library/Security/SecurityAgentPlugins",
                      "/Library/Spotlight",
                      os.path.join(HOME, "Library", "Spotlight"),
                      "/Library/QuickLook",
                      os.path.join(HOME, "Library", "QuickLook"),
                      "/Library/ScriptingAdditions",
                      os.path.join(HOME, "Library", "ScriptingAdditions"),
                      os.path.join(HOME, "Library", "Workflows",
                                   "Applications", "Folder Actions")]

# Chromium-family + Firefox extension roots (in the user's own home — no special
# privilege). A newly-appearing extension ID is the signal; we diff the inventory.
BROWSER_EXT_ROOTS = [
    (os.path.join(HOME, "Library/Application Support/Google/Chrome"), "chromium"),
    (os.path.join(HOME, "Library/Application Support/BraveSoftware/Brave-Browser"), "chromium"),
    (os.path.join(HOME, "Library/Application Support/Microsoft Edge"), "chromium"),
    (os.path.join(HOME, "Library/Application Support/Chromium"), "chromium"),
    (os.path.join(HOME, "Library/Application Support/Vivaldi"), "chromium"),
    (os.path.join(HOME, "Library/Application Support/Firefox/Profiles"), "firefox"),
]

# IDE / code-editor extension dirs. A backdoored editor extension is a live 2025
# supply-chain vector (Objective-See's "Paradox" shipped via a trojanised Cursor
# extension in Open VSX) — and directly relevant to a developer's box. Layout is
# uniform: <root>/<publisher>.<name>-<version>/package.json.
IDE_EXT_ROOTS = [os.path.join(HOME, d) for d in (
    ".vscode/extensions", ".vscode-oss/extensions", ".vscode-insiders/extensions",
    ".cursor/extensions", ".windsurf/extensions",
)]

# Aegis's own launchd agent (label from install.sh). Self-protection self-learns
# that this exists; if it later vanishes, the monitor may have been disabled.
SELF_PLIST = os.path.join(HOME, "Library", "LaunchAgents", "com.charlie.aegis.plist")
SELFSTATE = os.path.join(STATE_DIR, "selfstate.json")

# Optional launcher between a pipe and the interpreter it feeds. A source-reading
# attacker evades a bare `| bash` matcher by fronting the interpreter with `env`
# (`| env bash`, `| /usr/bin/env bash`, `| env FOO=1 bash`) or a non-/bin absolute
# path (`| /opt/homebrew/bin/bash`) — the identical fileless pipeline. The path
# prefix is absolute-only (`/\S*/`) so it can't match relative junk like
# `grep foo/sh`; the perl/sed alternation FP guard is preserved by the interpreter
# patterns' own trailing boundary (`\b` / `(?=\s|$)`), unaffected by this prefix.
_PIPE_LAUNCH = r"(?:(?:/\S*/)?env\s+(?:-\S+\s+|[\w.]+=\S*\s+)*)?(?:/\S*/)?"

# High-signal hostile shell/command patterns, shared by argument inspection
# (launchd/cron) and file-content scanning (shell rc). Each is a "download-and-
# run", "reverse shell", or "obfuscated-decode-and-exec" idiom — the live tail of
# a 2025-era ClickFix / AMOS infection chain.
_HOSTILE_CONTENT_RES = [
    (re.compile(r"\b(?:curl|wget|nscurl|fetch)\b[^\n|]*\bhttps?://", re.I), "network-fetch"),
    (re.compile(r"\|\s*" + _PIPE_LAUNCH + r"(?:ba|z|d)?sh\b", re.I), "pipe-to-shell"),
    # Require a real command boundary after the interpreter (space/EOL) so a `|`
    # INSIDE a quoted regex alternation — e.g. perl/sed `s{(a|node|b)}` — is not
    # mistaken for a shell pipe into `node`. A genuine pipe reads `… | osascript`.
    (re.compile(r"\|\s*" + _PIPE_LAUNCH + r"(?:osascript|python[0-9.]*|perl|ruby|node|php)(?=\s|$)", re.I), "pipe-to-interpreter"),
    # Interpreter-NATIVE HTTP fetch (python urllib/http.client/requests, ruby
    # open-uri/Net::HTTP, perl LWP/HTTP::Tiny, node require('https')/http.get) —
    # the fetch half of a fileless download+exec that never shells out to curl.
    # A FETCH idiom (MEDIUM alone); HIGH only combined with an exec sink, exactly
    # like curl. Keeps pip/package-manager fetches (no exec) below the notify floor.
    (re.compile(r"\b(?:urllib\.request|urllib\.urlopen|urlopen|urlretrieve|"
                r"http\.client|httplib|requests\.(?:get|post)|open-uri|Net::HTTP|"
                r"URI\.open|HTTP::Tiny|LWP::|require\(\s*['\"]https?['\"]|"
                r"https?\.get\()", re.I), "interp-fetch"),
    # exec()/eval() of a string — the exec sink an interpreter one-liner uses to
    # run fetched/decoded bytes in memory. `\s*\(` requires the call form, so it
    # never fires on shell `exec bash` (no paren) or `eval "$(…)"` (a quote, not
    # a paren, follows). An exec idiom (MEDIUM alone); HIGH only with a fetch.
    (re.compile(r"\b(?:exec|eval)\s*\(", re.I), "exec-eval"),
    (re.compile(r"\bbase64\b\s+(?:--?d(?:ecode)?|-D)\b", re.I), "base64-decode"),
    (re.compile(r"\beval\b[^\n]*\$\(", re.I), "eval-subshell"),
    (re.compile(r"/dev/tcp/", re.I), "bash-reverse-shell"),
    (re.compile(r"\bn(?:c|cat)\b[^\n]*\s-[a-z]*e\b", re.I), "netcat-exec"),
    (re.compile(r"\bosascript\b[^\n]*do\s+shell\s+script", re.I), "osascript-shell"),
    (re.compile(r"\bpython[0-9.]*\b[^\n]*-c[^\n]*\bimport\s+(?:os|socket|pty|subprocess)", re.I), "python-oneliner"),
    (re.compile(r"\b(?:curl|wget)\b[^\n]*\bhttps?://\d{1,3}(?:\.\d{1,3}){3}", re.I), "raw-ip-fetch"),
    (re.compile(r"\blaunchctl\b\s+(?:load|bootstrap)\b[^\n]*/(?:tmp|var/folders|Users/Shared)", re.I), "launchctl-tmp"),
    (re.compile(r"display\s+dialog.*hidden\s+answer", re.I | re.S), "osascript-password-phish"),
    (re.compile(r"\bsecurity\b[^\n]*\b(?:dump-keychain|find-generic-password|find-internet-password)\b", re.I), "keychain-dump"),
    # ClickLock (Group-IB, 2026) coerces a password by killing the very apps a
    # user would open to notice/stop it — Activity Monitor, the menu-bar
    # (SystemUIServer), NotificationCenter (suppresses Gatekeeper warnings),
    # Console. A user practically never scripts killing THESE, so it is a high-
    # signal anti-analysis/coercion tell even outside the tight-loop shape.
    (re.compile(r"\b(?:killall|pkill)\b[^\n]*\b(?:Activity[ _]?Monitor|"
                r"SystemUIServer|NotificationCenter|Console|coreauthd)\b", re.I),
     "gui-kill-coercion"),
    # applescript:// URL scheme launches Script Editor pre-loaded with the
    # payload — executing OUTSIDE any shell, so it dodges shell history AND
    # Apple's Tahoe 26.4 Terminal-paste warning (Jamf/Netskope, 2026 ClickFix).
    (re.compile(r"\bapplescript://", re.I), "applescript-url-scheme"),
]

# launchd EnvironmentVariables keys that inject code into other processes.
_DYLD_INJECT_KEYS = ("DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH",
                     "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH")

# --------------------------------------------------------------------------- #
# BEHAVIORAL tier (research-grounded, 2025-26 macOS stealer wave).
#
# The dominant 2025 TTP (AMOS/Poseidon/ClickFix, per Sophos/SentinelOne/Jamf/
# Microsoft/Objective-See) is FILELESS: a signed interpreter (bash/osascript/
# curl — all Apple-signed, all in TRUSTED_PREFIXES) is driven by a hostile
# COMMAND LINE. Persistence-diffing and unsigned-binary checks are blind to it;
# the malice lives entirely in argv. So we sample the full process argv and the
# unified log — two entitlement-free, no-cloud sources — and score by STRUCTURAL
# invariants that are expensive for an attacker to vary (a non-Apple process
# copying login.keychain-db; a quarantine-xattr strip; a hidden-answer password
# dialog), not easily-shed strings.
#
# HONEST BOUNDARY: an unprivileged agent can only reliably read SAME-USER argv
# (KERN_PROCARGS2). Consumer smash-and-grab is same-user, so this holds for the
# common case; a root/multi-user payload's argv is invisible. Stated in README.
# --------------------------------------------------------------------------- #

# High-precision hostile process-argv signals. Each is rare-to-absent in normal
# use, so a single match is alert-worthy (the Bitdefender-ATC lesson applied via
# severity tiers: unambiguous → HIGH/CRITICAL, weak/context → MEDIUM won't-notify).
_HOSTILE_ARGV_RES = [
    # AMOS/Cthulhu core primitive: a fake system password prompt (hidden answer).
    (re.compile(r"\bosascript\b.*display\s+dialog.*(?:hidden\s+answer|default\s+answer)", re.I | re.S),
     "osascript-password-phish", "CRITICAL"),
    # ClickFix validates the phished password locally before proceeding.
    (re.compile(r"\bdscl\b\s+\.?\s+(?:-)?authonly\b", re.I), "dscl-authonly-passcheck", "HIGH"),
    # Provenance strip: defeats Aegis's own quarantine check if we only read xattrs
    # at rest — so we catch the STRIP invocation itself.
    (re.compile(r"\bxattr\b[^\n]*\s-[a-z]*(?:c|d|dr)\b[^\n]*com\.apple\.quarantine", re.I), "quarantine-strip", "HIGH"),
    (re.compile(r"\bxattr\b\s+-c\b", re.I), "xattr-clear-all", "HIGH"),
    # Invisible DMG mount (new ClickFix DMG variant, Unit42 2026).
    (re.compile(r"\bhdiutil\b\s+attach\b[^\n]*-nobrowse\b", re.I), "hdiutil-nobrowse", "HIGH"),
    # Wipes the TCC privacy DB — resets Aegis's own grants; a tamper signal.
    (re.compile(r"\btccutil\b\s+reset\b", re.I), "tccutil-reset", "HIGH"),
    # Keychain theft residue: copy login.keychain-db out, or dump it.
    (re.compile(r"login\.keychain-db\b", re.I), "keychain-db-access", "HIGH"),
    (re.compile(r"\bsecurity\b[^\n]*\b(?:dump-keychain|find-generic-password|find-internet-password)\b", re.I),
     "keychain-security-dump", "HIGH"),
    # Exfil POST of a staged archive (curl -F file=@/tmp/*.zip … to a remote host).
    (re.compile(r"\bcurl\b[^\n]*-F\b[^\n]*file=@[^\n]*\.(?:zip|tar|gz)", re.I), "curl-exfil-post", "HIGH"),
    # TLS-verification-disabled streaming download (curl -k | base64 -d | …).
    (re.compile(r"\bcurl\b[^\n]*\s-[a-z]*k\b[^\n]*\|\s*(?:base64|gunzip|(?:ba|z)?sh|osascript)", re.I),
     "curl-insecure-pipe", "HIGH"),
    # Fileless staging: nohup curl pulling a payload run in memory.
    (re.compile(r"\bnohup\b[^\n]*\bcurl\b", re.I), "nohup-curl-fileless", "HIGH"),
    # ClickLock (2026) password-coercion / anti-analysis: killing Activity
    # Monitor / SystemUIServer / NotificationCenter / Console. HIGH alone; the
    # tight-loop variant escalates to CRITICAL in _argv_signals (below).
    (re.compile(r"\b(?:killall|pkill)\b[^\n]*\b(?:Activity[ _]?Monitor|"
                r"SystemUIServer|NotificationCenter|Console|coreauthd)\b", re.I),
     "gui-kill-coercion", "HIGH"),
    # applescript:// URL-scheme execution (shell-history- and Terminal-warning-
    # evading Script Editor payload delivery).
    (re.compile(r"\bapplescript://", re.I), "applescript-url-scheme", "HIGH"),
]

# A tight loop wrapped around a GUI-kill: the ClickLock coercion primitive (kill
# Activity Monitor / Dock / Terminal every ~0.2s for hours until a password is
# typed). "No legitimate use case" (Group-IB), so the loop+kill COMBINATION is a
# short-circuit CRITICAL — it must not have to wait for risk accumulation.
_KILL_LOOP_RE = re.compile(
    r"\b(?:while|until|repeat|for)\b.{0,80}?\b(?:killall|pkill)\b", re.I | re.S)

# Anti-VM / sandbox / geo gates run BEFORE the payload — an early-warning signal
# on a real victim endpoint (where the malware WILL proceed). Lower severity
# (won't notify): legitimate tools also probe hardware, so this only corroborates.
_ANTIVM_ARGV_RES = [
    (re.compile(r"\bsysctl\b[^\n]*hw\.optional\.arm\.FEAT_", re.I), "antivm-cpu-feature-probe"),
    (re.compile(r"\bsystem_profiler\b[^\n]*SPHardwareDataType", re.I), "antivm-hardware-probe"),
    (re.compile(r"\bioreg\b[^\n]*(?:VMware|VirtualBox|QEMU|Parallels)", re.I), "antivm-hypervisor-probe"),
]

# Apple-signed interpreters/utilities whose OWN path is trusted, so behavioral
# scoring must key on their argv. (Superset of _INTERPRETERS — used to decide
# whether a trusted-path process is worth argv-inspecting.)
_ARGV_WATCH_BINS = frozenset((
    "bash", "sh", "zsh", "dash", "ksh", "osascript", "python", "python2",
    "python3", "perl", "ruby", "php", "node", "curl", "wget", "nscurl",
    "xattr", "hdiutil", "tccutil", "dscl", "security", "nohup", "sysctl",
    "system_profiler", "ioreg", "sqlite3", "ditto", "zip",
    # process-kill utilities: the ClickLock GUI-kill coercion vehicle. Scored
    # only when argv names a GUI-critical target (see gui-kill-coercion).
    "killall", "pkill",
    # file-move/copy/archive utilities: harmless alone, but the vehicle a
    # stealer uses to exfil a sensitive file (e.g. `cp login.keychain-db`).
    # Adding them only means their argv gets SCORED — _argv_signals still
    # requires a real hostile pattern (keychain-db, DYLD, xattr strip) to fire.
    "cp", "mv", "cat", "tar", "rsync", "dd",
))

# A watched interpreter/utility invoked ANYWHERE in an argv — used as a fallback
# pre-filter gate when the exec basename can't be trusted (a renamed binary, or
# an exec path containing spaces that shears clean tokenization). Longest names
# first so alternation prefers the more specific match. Word-boundary anchored,
# so "sh" won't match inside "bash" and "node" won't match "node_modules".
_ARGV_WATCH_RE = re.compile(
    r"\b(?:%s)\b" % "|".join(sorted(_ARGV_WATCH_BINS, key=len, reverse=True)),
    re.I)

# --- Apple's own engine (XProtect Remediator), harvested for free ------------ #
# XPR is Apple's periodic malware scanner/remediator (25 per-family modules on
# this machine). Its scan+detection activity is written to the unified log under
# this subsystem/category and is readable by an unentitled userspace process via
# `log show` — no root, no ES entitlement. A detection here is Apple's own
# professionally-maintained engine finding malware: the single highest-value
# signal a free tool can surface, because it inherits Apple's signature pipeline.
XPROTECT_SUBSYSTEM = "com.apple.XProtectFramework.PluginAPI"
XPROTECT_BUNDLES = [
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
    "/var/protected/xprotect/XProtect.bundle",
]
# A clean scan reports this; anything else (with a non-empty caused_by) is a hit.
XPROTECT_CLEAN_STATUS = "NoThreatDetected"
XPROTECT_STALE_DAYS = 60  # definitions older than this → surface (Apple ships ~monthly)

# --- Shell HISTORY (ClickFix terminal-paste residue) ------------------------- #
# ClickFix (now the dominant macOS initial-access vector, >500% growth 2024→25)
# tricks the user into pasting a command into Terminal. The payload is fetched by
# curl INSIDE an already-trusted Terminal, so it never gets a quarantine xattr and
# there is no DMG/Gatekeeper provenance to inspect — but the pasted command leaves
# a durable line in shell history. We scan recent history for the hostile idioms
# and the ClickFix chain markers, alerting once per unique offending command.
SHELL_HISTORY_FILES = [os.path.join(HOME, n) for n in (
    ".zsh_history", ".bash_history", ".sh_history",
    ".local/share/fish/fish_history",
)]
SHELL_HISTORY_TAIL = 400  # only inspect the most-recent N lines (cheap, recent-focused)

# --- /tmp loot-staging IOC filenames (smash-and-grab) ------------------------ #
# Persistence-free stealers stage loot in /tmp then curl-exfil in <1 min. These
# exact staging names are documented across the 2025 families (Atomic, Odyssey/
# Poseidon, MacSync, DigitStealer). A file matching one in a temp/shared dir is a
# high-signal indicator even if we miss the process. Also catch a copied keychain.
STAGING_IOC_RES = [
    (re.compile(r"^app\.zip$", re.I), "atomic-loot"),
    (re.compile(r"^ledger\.zip$", re.I), "odyssey-poseidon-loot"),
    (re.compile(r"^salmonela\.zip$", re.I), "macsync-loot"),
    (re.compile(r"^out\.zip$", re.I), "generic-loot-archive"),
    (re.compile(r"^wid\.txt$", re.I), "stealer-victim-id"),
    (re.compile(r"^\.pass$", re.I), "phished-password-stash"),
    (re.compile(r"^shub_", re.I), "shub-stealer-staging"),
    (re.compile(r"login\.keychain-db$", re.I), "staged-keychain-copy"),
    (re.compile(r"^FileGrabber$", re.I), "amos-filegrabber-dir"),
]
STAGING_DIRS = ["/tmp", "/private/tmp", "/Users/Shared"]

# --- Crypto-wallet integrity (wallet-drainer surface) ------------------------ #
# 2025 stealers don't just steal — they tamper with installed wallet apps to
# hijack funds: DigitStealer rewrites Ledger Live's app.json with attacker
# endpoints; Odyssey replaces Ledger Live / Trezor Suite bundles with drainers.
# We baseline-hash the config files + app main executables that EXIST; a change
# is HIGH (wallet apps update rarely and the blast radius is a drained wallet).
WALLET_CONFIG_FILES = [os.path.join(HOME, p) for p in (
    "Library/Application Support/Ledger Live/app.json",
    "Library/Application Support/Ledger Live/user.json",
)]
WALLET_APP_BINS = [
    "/Applications/Ledger Live.app/Contents/MacOS/Ledger Live",
    "/Applications/Trezor Suite.app/Contents/MacOS/Trezor Suite",
    "/Applications/Exodus.app/Contents/MacOS/Exodus",
    os.path.join(HOME, "Applications/Ledger Live.app/Contents/MacOS/Ledger Live"),
]

# --- Network listeners (bind-shell / rogue-server surface) -------------------- #
# LuLu-tier OUTBOUND blocking needs an Apple Network Extension entitlement, but
# the LISTENING side — a process accepting connections FROM the network — is
# visible to an unprivileged process via lsof. Loopback-only binds are skipped
# (dev servers churn on 127.0.0.1 constantly; a loopback bind is unreachable
# from outside). Apple platform daemons are skipped too UNLESS the binary is an
# interpreter/net-utility: rapportd/ControlCenter bind ephemeral wildcard ports
# every boot (pure churn), and SIP means malware can never BE at a platform
# path — but `/usr/bin/python3 -m http.server 0.0.0.0` or an `nc -l` IS exactly
# a bind-shell/staging-server shape. Baseline-diffed with per-surface silent
# adoption (existing listeners never storm).
LSOF_LISTEN_CMD = ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"]
_LISTENER_NET_UTILS = frozenset(("nc", "ncat", "socat"))

# --- Outbound connections (exfil-in-flight) ---------------------------------- #
# The listener surface catches the bind-shell shape; it is structurally blind to
# EXFIL, which is an OUTBOUND connection. `netstat -anv` attributes every socket
# to a `<proc>:<pid>` column WITHOUT root (verified on macOS 26) — including
# established outbound connections. We can't baseline-diff outbound (a browser
# opens hundreds), so this is a LIVE check that flags only SUSPICIOUS egress: an
# unsigned/ad-hoc binary in a user-writable path talking to the network, or a
# fileless-stealer interpreter/util (osascript/curl/nc/python/nohup) connecting
# outbound to a non-loopback host — especially a raw IP (AMOS C2 is bare-IP).
NETSTAT_CMD = ["netstat", "-anv", "-p", "tcp"]

# --- Auth sessions (remote login / screen sharing) --------------------------- #
# A canonical EDR sensor domain Aegis lacked. A personal Mac rarely has an ACTIVE
# remote login; `who` shows a remote host in parentheses for ssh/screen-sharing
# sessions. We baseline-diff the set of REMOTE sessions (local ttys/console are
# ignored — they churn every terminal), so a new ssh/screen-sharing origin is the
# signal. Complements the ~/.ssh/authorized_keys persistence check (that catches
# the implant; this catches the live session it enables).
WHO_CMD = ["who"]

# --- Known-vendor label impersonation (generalizes the com.apple.* check) ---- #
# A persistence LABEL claiming a well-known vendor whose backing program isn't
# signed by that vendor's Team ID is impersonating trusted software. ClickFix
# stages `com.google.keystone.agent.plist` (+ a fake GoogleUpdate.app) even when
# Google software isn't installed; ModStealer masquerades similarly. Map a label
# prefix → the substring that must appear in the program's signing authority/team.
VENDOR_LABEL_TEAMS = {
    "com.google.": ("Google", "EQHXZ8M8AV"),
    "com.microsoft.": ("Microsoft", "UBF8T346G9"),
    "com.dropbox.": ("Dropbox", "G7HH3F8CAK"),
}

# --- Canary / honeypot files (ransomware + mass-modification, near-zero-FP) --- #
# Attribution-independent tripwires: hidden decoy files with valid-looking
# content. Any modification/deletion of a canary is a high-confidence alarm
# (ransomware encrypting a folder, or bulk tampering). Opt-in: the user runs
# `aegis.py canary` to plant them (Aegis never writes outside ~/.aegis without
# an explicit command), and each scan verifies they're intact.
CANARY_DIRS = [os.path.join(HOME, d) for d in ("Documents", "Desktop", "Pictures")]
CANARY_NAME = ".aegis_canary_DO_NOT_DELETE.txt"
CANARY_STATE = os.path.join(STATE_DIR, "canaries.json")
CANARY_CONTENT = (
    "This is an Aegis canary file. It exists to detect ransomware and bulk file\n"
    "tampering. If a program modified or deleted it, Aegis will alert. Leave it.\n")

# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_state():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o700)
    except OSError:
        pass


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _sync_fd(fd):
    """Push a state mutation to stable storage as far as macOS permits."""
    os.fsync(fd)
    if sys.platform == "darwin":
        try:
            # F_FULLFSYNC is deliberately used by transactional response state:
            # fsync alone may only reach a drive's volatile write cache on macOS.
            fcntl.fcntl(fd, 51)
        except OSError:
            pass


def _sync_dir(path):
    try:
        fd = os.open(path or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some filesystems reject directory fsync. The file itself was still
        # synced; callers that require same-volume response semantics fail closed.
        pass


def save_json(path, obj):
    """Atomically and durably replace a JSON state file.

    A unique temp prevents concurrent writers from sharing ``path.tmp``. The
    replacement and parent directory are flushed so a successful return means
    readers see complete old JSON or complete new JSON, never a torn document.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp = "%s.tmp.%d.%d" % (path, os.getpid(), time.time_ns())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            fd = -1
            json.dump(obj, f, indent=2, sort_keys=True)
            f.flush()
            _sync_fd(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        _sync_dir(parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(tmp)
        except OSError:
            pass


_TRUSTED_TOOLS = {
    "chflags": "/usr/bin/chflags", "codesign": "/usr/bin/codesign",
    "crontab": "/usr/bin/crontab", "csrutil": "/usr/bin/csrutil",
    "defaults": "/usr/bin/defaults", "fdesetup": "/usr/bin/fdesetup",
    "launchctl": "/bin/launchctl", "log": "/usr/bin/log",
    "lsof": "/usr/sbin/lsof", "mdls": "/usr/bin/mdls",
    "osascript": "/usr/bin/osascript", "plutil": "/usr/bin/plutil",
    "profiles": "/usr/bin/profiles", "ps": "/bin/ps",
    "sfltool": "/usr/bin/sfltool", "spctl": "/usr/sbin/spctl",
    "sysctl": "/usr/sbin/sysctl", "xattr": "/usr/bin/xattr",
    "netstat": "/usr/sbin/netstat", "last": "/usr/bin/last",
    "who": "/usr/bin/who",
}


def _trusted_command(cmd):
    normalized = list(cmd)
    if normalized and not os.path.isabs(normalized[0]):
        normalized[0] = _TRUSTED_TOOLS.get(normalized[0], normalized[0])
    return normalized


def run(cmd, timeout=15):
    """Run a command, return (stdout, stderr, rc). Never raises."""
    try:
        safe_env = {
            "HOME": HOME, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C", "LC_ALL": "C",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
        }
        p = subprocess.run(
            _trusted_command(cmd), capture_output=True, text=True, timeout=timeout,
            check=False, env=safe_env
        )
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 124
    except FileNotFoundError:
        return "", "not-found", 127
    except Exception as e:  # pragma: no cover - defensive
        return "", str(e), 1


def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def is_risky_location(path):
    if not path:
        return False
    if any(path.startswith(p) for p in TRUSTED_PREFIXES):
        return False
    # A hidden component anywhere (/.foo/) is a classic hiding spot.
    if "/." in path:
        return True
    return any(path.startswith(p) for p in RISKY_PREFIXES)


def notify(title, message):
    """Best-effort macOS desktop notification. Never fatal."""
    try:
        run(
            [
                "osascript",
                "-e",
                "display notification %s with title %s"
                % (json.dumps(message), json.dumps(title)),
            ],
            timeout=8,
        )
    except Exception:
        pass


def log_run(msg):
    try:
        ensure_state()
        _rotate_log(RUN_LOG)
        with open(RUN_LOG, "a") as f:
            f.write("%s  %s\n" % (now_iso(), redact_sensitive(msg)))
        os.chmod(RUN_LOG, 0o600)
    except Exception:
        pass


def _rotate_log(path, max_bytes=10 * 1024 * 1024, generations=3):
    """Bound local evidence files without silently discarding recent history."""
    try:
        if os.path.getsize(path) < max_bytes:
            return
        for idx in range(generations, 0, -1):
            src = path if idx == 1 else "%s.%d" % (path, idx - 1)
            dst = "%s.%d" % (path, idx)
            if os.path.exists(src):
                os.replace(src, dst)
        _sync_dir(os.path.dirname(path))
    except OSError:
        pass


def _quarantine_fields(path):
    """One `xattr` read of com.apple.quarantine → (present, agent, event_uuid).
    Single-call so the hot-dir sweep does not spawn three subprocesses per file.
    Value layout: flags;hex-timestamp;AgentName;event-UUID."""
    out, _, rc = run(["xattr", "-p", "com.apple.quarantine", path], timeout=6)
    if rc != 0 or not out.strip():
        return (False, None, None)
    fields = out.strip().split(";")
    agent = fields[2].strip() if len(fields) >= 3 and fields[2].strip() else None
    uuid = fields[3].strip() if len(fields) >= 4 and fields[3].strip() else None
    return (True, agent, uuid)


def quarantine_origin(path):
    """Provenance from the com.apple.quarantine xattr, via Apple's `xattr` CLI
    (Python's os.getxattr is Linux-only — verified absent on macOS). Returns
    (present, agent): whether the file carries a Gatekeeper quarantine flag and
    the downloading agent name (Safari, Google Chrome, curl, Terminal, …).
    ABSENCE on a freshly-dropped executable is itself a signal — it means the
    file arrived by a channel that bypassed Gatekeeper (curl/scp/AirDrop/torrent),
    the exact side-load path AMOS/DMG-lure chains use."""
    present, agent, _uuid = _quarantine_fields(path)
    return (present, agent)


# The central download-provenance store — LSQuarantineEvent rows in the user's
# OWN preferences (no admin, no Full Disk Access; readable by stdlib sqlite3).
# Keyed by the event-UUID that the per-file quarantine xattr's 4th field carries,
# it maps a downloaded file back to the ORIGIN URL and the downloading agent.
_QUARANTINE_EVENTS_DB = os.path.join(
    HOME, "Library", "Preferences",
    "com.apple.LaunchServices.QuarantineEventsV2")

# Chrome-family History DBs are same-user-readable and NOT TCC-protected (unlike
# Safari): their `downloads` table (target_path, tab_url) is a second FDA-free
# origin source, useful when the QuarantineEventsV2 row was pruned or the file
# carries no quarantine xattr (curl/AirDrop side-load).
_CHROME_HISTORY_DBS = [os.path.join(HOME, p) for p in (
    "Library/Application Support/Google/Chrome/Default/History",
    "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
    "Library/Application Support/Microsoft Edge/Default/History",
    "Library/Application Support/Chromium/Default/History",
    "Library/Application Support/Vivaldi/Default/History",
)]

# Origin hosts we trust enough to DOWN-grade (never to suppress) a fresh-unsigned
# hot-dir drop: a binary a developer knowingly pulled from these is far likelier
# a legit tool than a ClickFix payload. Conservative allowlist — provenance only
# lowers confidence to route-to-digest, it never closes the finding.
_TRUSTED_ORIGIN_HOSTS = frozenset((
    "github.com", "objects.githubusercontent.com", "codeload.github.com",
    "raw.githubusercontent.com", "github-releases.githubusercontent.com",
    "apple.com", "developer.apple.com", "brew.sh", "formulae.brew.sh",
    "python.org", "nodejs.org", "npmjs.com", "registry.npmjs.org",
    "pypi.org", "files.pythonhosted.org", "docker.com", "jetbrains.com",
    "code.visualstudio.com", "gitlab.com", "sourceforge.net",
))


def _sqlite_uri_path(path):
    """Percent-encode the characters SQLite treats specially in a URI filename.
    Deliberately hand-rolled rather than urllib.request.pathname2url: importing
    urllib.request would load the networking module on the scan path, which the
    local-only guarantee says never happens (urllib stays lazy-imported for vt)."""
    return path.replace("%", "%25").replace("?", "%3f").replace("#", "%23")


def _sqlite_readonly(path):
    """Open a possibly-live SQLite DB read-only and immutably, so reading another
    process's browser/prefs DB never locks it or is blocked by a WAL lock. Returns
    a connection or None; the caller must close. immutable=1 is safe here because
    we only ever SELECT and tolerate a slightly stale snapshot."""
    if not os.path.exists(path):
        return None
    try:
        uri = "file:%s?immutable=1&mode=ro" % _sqlite_uri_path(path)
        return sqlite3.connect(uri, uri=True, timeout=2)
    except Exception:
        return None


# Host of a URL, without importing urllib (see _sqlite_uri_path). Tolerates
# userinfo (user:pass@host), a port, and a missing path.
_URL_HOST_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://(?:[^/@\s]*@)?([^/:?#\s]+)", re.I)


def _origin_host(url):
    m = _URL_HOST_RE.match(url or "")
    return m.group(1).lower().rstrip(".").lstrip(".") if m else None


def _origin_from_quarantine_db(uuid):
    if not uuid:
        return None
    db = _sqlite_readonly(_QUARANTINE_EVENTS_DB)
    if db is None:
        return None
    try:
        row = db.execute(
            "SELECT LSQuarantineDataURLString, LSQuarantineOriginURLString "
            "FROM LSQuarantineEvent WHERE LSQuarantineEventIdentifier=?",
            (uuid,)).fetchone()
        if row:
            return row[0] or row[1] or None
    except Exception:
        return None
    finally:
        db.close()
    return None


def _origin_from_chrome_history(path):
    """Look up a downloaded file's source tab_url in any Chrome-family History
    DB by exact target_path. Read-only/immutable; bounded to the newest match."""
    for hist in _CHROME_HISTORY_DBS:
        db = _sqlite_readonly(hist)
        if db is None:
            continue
        try:
            row = db.execute(
                "SELECT tab_url FROM downloads WHERE target_path=? "
                "ORDER BY start_time DESC LIMIT 1", (path,)).fetchone()
            if row and row[0]:
                return row[0]
        except Exception:
            pass
        finally:
            db.close()
    return None


def download_provenance(path):
    """Best-effort origin attribution for a dropped file, entirely inside the
    unprivileged/no-FDA envelope. Returns (present, agent, origin_url, trusted):
      present        — file carries a Gatekeeper quarantine flag
      agent          — downloading app from the quarantine xattr (curl/Chrome/…)
      origin_url     — source URL from QuarantineEventsV2 or Chrome `downloads`
      trusted        — True iff origin_url's host is on _TRUSTED_ORIGIN_HOSTS
    Used to enrich AND grade hot-dir findings: a benign trusted origin downgrades
    confidence (route-to-digest), a raw-IP/absent origin keeps it loud."""
    present, agent, uuid = _quarantine_fields(path)
    origin = _origin_from_quarantine_db(uuid) or _origin_from_chrome_history(path)
    host = _origin_host(origin) if origin else None
    trusted = bool(host and any(host == d or host.endswith("." + d)
                                for d in _TRUSTED_ORIGIN_HOSTS))
    return (present, agent, origin, trusted)


def _hostile_content(text):
    """Return the list of hostile-pattern names present in a blob of shell/command
    text (empty list = clean). Shared by shell-rc scanning and could back any
    future text surface."""
    if not text:
        return []
    return sorted({name for rx, name in _HOSTILE_CONTENT_RES if rx.search(text)})


# --------------------------------------------------------------------------- #
# Code-signature classification (grounded against real `codesign -dv` output)
# --------------------------------------------------------------------------- #

_sigcache = None


def _sig_stat(path):
    # Identity + ctime + nanosecond mtime + size. Updaters and attackers can
    # preserve a replacement's mtime and size; ctime cannot be restored by an
    # unprivileged same-user process, while inode/device catch atomic swaps.
    # Omitting these let a changed executable retain a stale trusted verdict.
    try:
        st = os.stat(path)
        return [st.st_dev, st.st_ino, st.st_ctime_ns, st.st_mtime_ns, st.st_size]
    except Exception:
        return None


def classify_signature(path):
    """
    Return {trust, team, authority}.
      trust in {apple, developer-id, signed-other, adhoc, unsigned, broken,
                missing, unknown}
    Only 'adhoc', 'unsigned', 'broken' are treated as suspicious for exec.
    Cached per PATH (not per path+mtime+size) with the stat-signature stored as a
    field, so a rebuilt binary OVERWRITES its own entry instead of orphaning a
    stale key — the cache stays one-entry-per-path and cheap on battery.
    """
    global _sigcache
    if _sigcache is None:
        _sigcache = load_json(SIGCACHE, {})

    if not path or not os.path.exists(path):
        return {"trust": "missing", "team": None, "authority": None}

    stat_sig = _sig_stat(path)
    cached = _sigcache.get(path)
    if cached and stat_sig is not None and cached.get("stat") == stat_sig:
        # LRU touch: move to newest so the insertion-order trim in
        # flush_sigcache() evicts genuinely least-recently-USED entries, not just
        # first-inserted ones (an hourly-hit path must outlive a dead one-off).
        _sigcache.pop(path, None)
        _sigcache[path] = cached
        return cached["result"]

    out, err, _ = run(["codesign", "-dv", "--verbose=4", path], timeout=12)
    text = (out or "") + (err or "")  # codesign writes detail to stderr

    result = {"trust": "unknown", "team": None, "authority": None}

    if "code object is not signed at all" in text:
        result["trust"] = "unsigned"
    else:
        authorities = [a.strip() for a in re.findall(r"Authority=(.+)", text)]
        m = re.search(r"TeamIdentifier=(.+)", text)
        team = m.group(1).strip() if m else None
        if team == "not set":
            team = None
        fm = re.search(r"flags=0x[0-9a-fA-F]+\((.*?)\)", text)
        flagset = fm.group(1) if fm else ""

        # Classify by the LEAF authority (authorities[0]) - the deepest chain
        # entries are always the Apple roots, so a substring match on "Apple"
        # would mislabel every Developer-ID app as Apple. Order matters.
        leaf = authorities[0] if authorities else None
        if "adhoc" in flagset:
            trust = "adhoc"
        elif leaf and leaf.startswith("Developer ID Application"):
            trust = "developer-id"
        elif leaf == "Software Signing":
            trust = "apple"
        elif leaf == "Apple Mac OS Application Signing":
            trust = "app-store"
        elif authorities:
            trust = "signed-other"
        else:
            trust = "unsigned"

        result["trust"] = trust
        result["team"] = team
        result["authority"] = authorities[0] if authorities else None

    # Integrity check - a tampered signature is a strong signal.
    if result["trust"] not in ("unsigned", "missing"):
        _, verr, vrc = run(["codesign", "--verify", "--strict", path], timeout=20)
        if vrc != 0 and "not signed" not in (verr or "").lower():
            result["trust"] = "broken"

    if stat_sig is not None:
        _sigcache.pop(path, None)  # overwrite any prior entry for this path
        _sigcache[path] = {"stat": stat_sig, "result": result}
    return result


def flush_sigcache():
    if _sigcache is not None:
        # Keep the cache from growing without bound.
        if len(_sigcache) > 5000:
            for k in list(_sigcache.keys())[: len(_sigcache) - 5000]:
                _sigcache.pop(k, None)
        save_json(SIGCACHE, _sigcache)


def suspicious_sig(trust):
    return trust in ("adhoc", "unsigned", "broken")


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #


_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|cookie)\b"
    r"(\s*[:=]\s*)([^\s&;,]+)")
_AUTH_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*(?:bearer|basic)?\s*)([^\s'\"]+)")
_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|token|api[_-]?key|secret|cookie)=)([^&\s]+)")
_URL_USERINFO_RE = re.compile(r"(https?://[^\s/@:]+:)([^\s/@]+)(@)", re.I)
_TOKEN_SHAPE_RE = re.compile(
    r"(?i)\b(?:sk-(?:live-)?[A-Za-z0-9_-]{12,}|gh[opusr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16})\b")


def redact_sensitive(value):
    """Remove common credential shapes before data crosses a persistence edge."""
    if value is None:
        return value
    text = str(value)
    text = _AUTH_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_ASSIGN_RE.sub(r"\1\2[REDACTED]", text)
    text = _QUERY_SECRET_RE.sub(r"\1[REDACTED]", text)
    text = _URL_USERINFO_RE.sub(r"\1[REDACTED]\3", text)
    return _TOKEN_SHAPE_RE.sub("[REDACTED]", text)


def _redact_value(value):
    if isinstance(value, str):
        return redact_sensitive(value)
    if isinstance(value, dict):
        return {str(k): _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_redact_value(v) for v in value]
    return value


CONFIDENCE_ORDER = {"high": 2, "medium": 1, "low": 0}


def finding(severity, category, title, detail, fingerprint, **extra):
    rule_id = extra.pop("rule_id", None)
    # Confidence is a SEPARATE axis from severity (Secureworks/Vectra/Sigma
    # two-axis model): severity = impact if real, confidence = how sure we are
    # this specific hit is a true positive (rule specificity × baseline rarity).
    # Kept as its own field so tuning one never silently moves the other, and so
    # the routing gate can demote a high-impact-but-noisy hit to digest without
    # lowering its recorded severity. Default 'medium'; only an EXPLICIT 'low'
    # ever routes below the notify floor, so existing callers are unaffected.
    confidence = extra.pop("confidence", "medium")
    if confidence not in CONFIDENCE_ORDER:
        confidence = "medium"
    slug = re.sub(r"[^a-z0-9]+", ".", title.lower()).strip(".")[:80]
    f = {
        "schema_version": 1,
        "ts": now_iso(),
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "title": title,
        "detail": redact_sensitive(detail),
        "fingerprint": fingerprint,
        "rule_id": rule_id or "aegis.%s.%s" % (category, slug or "finding"),
        "rule_version": 1,
    }
    f.update(_redact_value(extra))
    return f


# --------------------------------------------------------------------------- #
# Durable event -> signal -> incident core (stdlib SQLite; one sink, no SIEM).
# --------------------------------------------------------------------------- #

_REMINDER_DELAYS = (3600, 86400, 259200)
_ACTIVE_INCIDENT_STATES = ("OPEN", "ACK", "INVESTIGATING", "CONTAINED",
                           "RECOVERING", "MONITORING")


def _epoch(value=None):
    if value is None:
        return int(time.time())
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except Exception:
        return int(time.time())


# One definition of the event-store schema, shared by the durable store and the
# throwaway in-memory database `replay` builds — so a backtest can never drift
# from the real store's shape.
_EVENT_SCHEMA_SQL = """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS signals (
            id INTEGER PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            rule_id TEXT NOT NULL,
            rule_version INTEGER NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            attributes_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            scan_id TEXT,
            occurred_at INTEGER NOT NULL,
            observed_at INTEGER NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            signal_id INTEGER REFERENCES signals(id),
            incident_id INTEGER REFERENCES incidents(id),
            data_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON events(observed_at);
        CREATE INDEX IF NOT EXISTS idx_events_signal ON events(signal_id);
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            correlation_key TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            reminder_count INTEGER NOT NULL DEFAULT 0,
            next_reminder_at INTEGER,
            last_notified_at INTEGER,
            resolution TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_active
            ON incidents(status, next_reminder_at);
        CREATE INDEX IF NOT EXISTS idx_incidents_key
            ON incidents(correlation_key, status);
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            PRIMARY KEY(incident_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS path_lineage (
            path TEXT PRIMARY KEY,
            first_event_id INTEGER,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            category TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_lineage_seen ON path_lineage(last_seen);
        CREATE TABLE IF NOT EXISTS dismissals (
            id INTEGER PRIMARY KEY,
            incident_id INTEGER,
            correlation_key TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            dismissed_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dismissals_cat
            ON dismissals(category, dismissed_at);
        CREATE TABLE IF NOT EXISTS sensor_status (
            sensor_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            last_run_at INTEGER NOT NULL,
            last_ok_at INTEGER,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            item_count INTEGER NOT NULL DEFAULT 0,
            detail TEXT NOT NULL DEFAULT '',
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            episode_started_at INTEGER
        );
"""


def _event_connection():
    ensure_state()
    db = sqlite3.connect(EVENT_DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(_EVENT_SCHEMA_SQL)
    db.commit()
    try:
        os.chmod(EVENT_DB, 0o600)
    except OSError:
        pass
    return db


def init_event_store():
    db = _event_connection()
    db.close()


def _event_attributes(f):
    core = {"schema_version", "ts", "severity", "category", "title", "detail",
            "fingerprint", "rule_id", "rule_version", "sensor_id"}
    return _redact_value({k: v for k, v in f.items() if k not in core})


def _entity(f):
    for key in ("path", "program", "executable", "bundle", "pid", "label"):
        if f.get(key) not in (None, ""):
            return str(f[key])
    return ""


def _severity_max(a, b):
    return a if SEV_ORDER.get(a, -1) >= SEV_ORDER.get(b, -1) else b


def _upsert_incident(db, key, title, severity, kind, now, event_ids,
                     initially_notified=False):
    marks = ",".join("?" for _ in _ACTIVE_INCIDENT_STATES)
    row = db.execute(
        "SELECT * FROM incidents WHERE correlation_key=? AND status IN (%s) "
        "ORDER BY id DESC LIMIT 1" % marks,
        (key,) + _ACTIVE_INCIDENT_STATES).fetchone()
    if row:
        incident_id = row["id"]
        new_sev = _severity_max(row["severity"], severity)
        new_status = "OPEN" if (row["status"] == "ACK" and
                                SEV_ORDER[new_sev] > SEV_ORDER[row["severity"]]) \
            else row["status"]
        db.execute("UPDATE incidents SET severity=?, status=?, last_seen=?, "
                   "updated_at=? WHERE id=?",
                   (new_sev, new_status, now, now, incident_id))
    else:
        # FALSE_POSITIVE is a reviewed verdict on this exact correlation key.
        # Keep later occurrences attached as evidence instead of opening a new
        # incident every scan. Fingerprints include content hashes for mutable
        # executables, so a changed object gets a different key and alerts again.
        reviewed = db.execute(
            "SELECT * FROM incidents WHERE correlation_key=? AND "
            "status='FALSE_POSITIVE' ORDER BY id DESC LIMIT 1", (key,)).fetchone()
        if reviewed and SEV_ORDER.get(severity, -1) <= \
                SEV_ORDER.get(reviewed["severity"], -1):
            incident_id = reviewed["id"]
            db.execute("UPDATE incidents SET last_seen=?,updated_at=? WHERE id=?",
                       (now, now, incident_id))
        else:
            last_notified = now if initially_notified else None
            cur = db.execute(
                "INSERT INTO incidents(kind,correlation_key,title,severity,status,"
                "created_at,first_seen,last_seen,updated_at,reminder_count,"
                "next_reminder_at,last_notified_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (kind, key, title, severity, "OPEN", now, now, now, now, 0,
                 now + _REMINDER_DELAYS[0], last_notified))
            incident_id = cur.lastrowid
    for event_id in event_ids:
        db.execute("INSERT OR IGNORE INTO incident_events(incident_id,event_id) "
                   "VALUES(?,?)", (incident_id, event_id))
        db.execute("UPDATE events SET incident_id=? WHERE id=?",
                   (incident_id, event_id))
    return incident_id


# macOS root firmlinks: /tmp, /var, /etc are symlinks to /private/{tmp,var,etc},
# so the SAME on-disk object appears under either string form. Correlation,
# lineage, and risk-accumulation join entities by their PATH STRING, so without
# canonicalizing here a drop recorded as `/tmp/x` never joins an execution seen
# as `/private/tmp/x` (or vice versa) — and `/tmp` is the #1 malware staging
# location, so this is the common case, not a corner case. Same equivalence the
# codebase already encodes for is_risky_location (RISKY_PREFIXES lists both
# forms); this is that fix carried into the join keys. Pure string map — no
# filesystem I/O — and it only unifies the three real firmlinks (never
# over-collapses e.g. /tmpfoo or two distinct /Users paths).
_MACOS_FIRMLINKS = ("/tmp", "/var", "/etc")


def _canon_entity_path(value):
    """Normalize an entity string toward macOS's real (/private) path form so
    the same object joins regardless of which firmlink alias a sensor reported.
    Non-path entities (a pid, a launchd label) pass through unchanged."""
    if not value:
        return value
    p = os.path.normpath(value)
    for fl in _MACOS_FIRMLINKS:
        if p == fl or p.startswith(fl + "/"):
            return "/private" + p
    return p


def _same_entity(a, b):
    ea, eb = _entity(a), _entity(b)
    if not ea or not eb:
        return False
    if os.path.isabs(ea) and os.path.isabs(eb):
        return os.path.normcase(_canon_entity_path(ea)) == \
            os.path.normcase(_canon_entity_path(eb))
    return ea == eb


# Per-entity risk accumulation (Elastic building-block → entity-risk → higher-
# order pattern): weak signals that never notify alone should escalate when they
# PILE UP on one entity. Weight = severity × confidence; an entity that crosses
# the threshold from enough DISTINCT signals opens one 'risk' incident.
_RISK_SEV_WEIGHT = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0,
                    "INFO": 0.0}
_RISK_CONF_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}
RISK_WINDOW = 1800       # look-back seconds (matches the correlation window)
RISK_THRESHOLD = 4.0     # ~three medium-confidence MEDIUMs on one entity
RISK_MIN_SIGNALS = 3     # never escalate a single loud finding this way
# Splunk RBA's lesson is that CORROBORATION ACROSS SOURCES is the high-precision
# signal — its canonical rule demands distinct tactics from distinct sources.
# Applied here as a LOWER bar for diverse evidence rather than a higher bar for
# single-sensor evidence: two distinct sensors agreeing on one entity is stronger
# than three findings from one sensor, so it escalates a signal sooner. The
# single-sensor path keeps its original threshold — occurrences are already
# deduplicated by fingerprint, so three findings there are three DISTINCT
# signals, not one chatty detector repeating, and demoting it would revoke a
# documented capability rather than add precision.
RISK_MIN_SIGNALS_MULTI_SENSOR = 2
# Splunk's tuning guidance is explicit: keep the THRESHOLD constant and tune the
# SCORES around it. So corroboration is expressed as a score multiplier rather
# than a second threshold — two sensors independently implicating one entity is
# stronger evidence than the same count from one sensor.
RISK_CORROBORATION_BONUS = 1.5
# Per-sensor precision feedback (the detection-engineering loop): a category the
# operator keeps dismissing is, empirically, low-precision — so its contribution
# to accumulation decays. It never reaches zero: a down-weighted sensor must
# still be able to participate in a chain, it just stops driving escalation by
# itself. Requires a minimum sample so one dismissal cannot mute a sensor.
_PRECISION_MIN_SAMPLE = 4
_PRECISION_FLOOR = 0.25


def _category_dismissal_weights(db, now, window=90 * 86400):
    """{category: multiplier} from the operator's own dismissal history. A
    category dismissed as benign/false-positive most of the time is down-weighted
    toward _PRECISION_FLOOR; anything with too small a sample stays at 1.0."""
    weights = {}
    try:
        rows = db.execute(
            "SELECT category, COUNT(*) AS n FROM dismissals "
            "WHERE dismissed_at>=? AND category<>'' GROUP BY category",
            (now - window,)).fetchall()
    except Exception:
        return weights
    for row in rows:
        dismissed = int(row["n"])
        if dismissed < _PRECISION_MIN_SAMPLE:
            continue
        opened = db.execute(
            "SELECT COUNT(*) FROM incidents i JOIN incident_events ie "
            "ON ie.incident_id=i.id JOIN events e ON e.id=ie.event_id "
            "WHERE i.created_at>=? AND json_extract(e.data_json,'$.category')=?",
            (now - window, row["category"])).fetchone()[0]
        total = max(opened, dismissed)
        precision = max(0.0, (total - dismissed) / float(total)) if total else 1.0
        weights[row["category"]] = max(_PRECISION_FLOOR, precision)
    return weights


def _accumulate_risk(db, now, new_ids):
    """Open one 'risk' incident per entity whose recent findings sum past
    RISK_THRESHOLD from ≥ RISK_MIN_SIGNALS DISTINCT signals spanning at least
    provided at least one is new this scan. Cross-sensor corroboration both needs
    fewer signals and scores higher (RISK_CORROBORATION_BONUS) against the same
    constant threshold. Lets three MEDIUMs on one binary escalate where one alone
    stays below the notify floor — the middle tier between raw signals and the
    hand-written chain rules. No schema change; reuses the incident store."""
    rows = db.execute(
        "SELECT id, observed_at, data_json FROM events "
        "WHERE event_type='observation.finding' AND observed_at>=?",
        (now - RISK_WINDOW,)).fetchall()
    demote = _category_dismissal_weights(db, now)
    by_entity = {}
    for row in rows:
        try:
            f = json.loads(row["data_json"])
        except Exception:
            continue
        entity = _entity(f)
        if not entity:
            continue
        entity = _canon_entity_path(entity)
        category = f.get("category") or ""
        w = (_RISK_SEV_WEIGHT.get(f.get("severity"), 0.0)
             * _RISK_CONF_WEIGHT.get(f.get("confidence", "medium"), 0.7)
             * demote.get(category, 1.0))
        if w <= 0:
            continue
        ek = hashlib.sha256(entity.encode("utf-8", "replace")).hexdigest()[:16]
        b = by_entity.setdefault(ek, {"weight": 0.0, "fps": set(), "ids": set(),
                                      "cats": set(), "entity": entity,
                                      "new": False})
        fp = f.get("fingerprint")
        if fp in b["fps"]:
            continue  # count each distinct signal once, not once per rescan
        b["fps"].add(fp)
        b["weight"] += w
        b["ids"].add(row["id"])
        b["cats"].add(category)
        if row["id"] in new_ids:
            b["new"] = True
    for ek, b in by_entity.items():
        # Corroboration across sensors is the higher-precision evidence: it needs
        # fewer signals AND scores higher against the same constant threshold.
        # One sensor keeps the original bar, so no existing detection regresses.
        multi = len(b["cats"]) >= 2
        min_signals = RISK_MIN_SIGNALS_MULTI_SENSOR if multi else RISK_MIN_SIGNALS
        score = b["weight"] * (RISK_CORROBORATION_BONUS if multi else 1.0)
        if b["new"] and len(b["fps"]) >= min_signals \
                and score >= RISK_THRESHOLD:
            _upsert_incident(
                db, "risk:%s" % ek,
                "Accumulated risk on %s (%d signals across %d sensor%s, score %.1f)"
                % (b["entity"][:80], len(b["fps"]), len(b["cats"]),
                   "" if len(b["cats"]) == 1 else "s", score),
                "HIGH", "risk", now, sorted(b["ids"]))


# --------------------------------------------------------------------------- #
# Durable PATH LINEAGE — the fix for entity-hopping and slow-burn persistence.
#
# The time-boxed same-entity chains below cannot see the dominant 2025-26 shape:
# a dropper writes a payload at path P and EXITS, then a SEPARATE launchd job
# executes P at the next login — hours or days later, from a different process,
# often after the binary was re-signed (so a content hash no longer matches).
# A longer window is the wrong fix (it would only widen the noise). Instead we
# durably remember "a suspicious object appeared at P" and raise the chain the
# moment ANYTHING later executes or persists P, however much later that is.
#
# Keyed on the normalized PATH — not pid, not content hash — because the path is
# the one identifier that must survive between the drop and the execution for the
# attack to work at all (CrashStealer re-signs between stages, changing hashes).
# --------------------------------------------------------------------------- #

# Categories whose finding means "a suspicious object was placed at this path".
_LINEAGE_DROP_CATEGORIES = frozenset(("hot-dir", "staging", "supply-chain"))
# Categories whose finding means "this path is now being executed / persisted".
_LINEAGE_ACTIVATION_CATEGORIES = frozenset(
    ("persistence", "process", "behavior", "btm", "net-listener"))
_LINEAGE_RETENTION = 180 * 86400     # forget a drop after ~6 months


def _lineage_path(f):
    """The absolute filesystem path a finding is about, normalized, or None.
    Only absolute paths participate: a pid or a bare label cannot be joined
    across time the way a path can."""
    entity = _entity(f)
    if not entity or not os.path.isabs(entity):
        return None
    return os.path.normcase(_canon_entity_path(entity))


def _apply_path_lineage(db, new_events, now, initially_notified=False,
                        suppressed_categories=frozenset()):
    """Record suspicious drops durably, and raise a CRITICAL chain when a
    remembered path is later executed or persisted. Returns the set of event ids
    attached to a lineage incident."""
    attached = set()
    db.execute("DELETE FROM path_lineage WHERE last_seen < ?",
               (now - _LINEAGE_RETENTION,))
    for event_id, f in new_events:
        category = f.get("category")
        if category in suppressed_categories:
            continue
        path = _lineage_path(f)
        if not path:
            continue
        if category in _LINEAGE_DROP_CATEGORIES:
            db.execute(
                "INSERT INTO path_lineage(path,first_event_id,first_seen,"
                "last_seen,category,detail) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET last_seen=excluded.last_seen",
                (path, event_id, now, now, category,
                 redact_sensitive(str(f.get("title") or ""))[:200]))
    # Second pass: activations join against everything remembered (including a
    # drop recorded moments ago in the loop above — same-scan chains are real).
    for event_id, f in new_events:
        category = f.get("category")
        if category in suppressed_categories \
                or category not in _LINEAGE_ACTIVATION_CATEGORIES:
            continue
        path = _lineage_path(f)
        if not path:
            continue
        row = db.execute(
            "SELECT first_event_id, first_seen, category, detail "
            "FROM path_lineage WHERE path=?", (path,)).fetchone()
        if not row or row["first_event_id"] is None \
                or row["first_event_id"] == event_id:
            continue
        evidence = sorted({row["first_event_id"], event_id})
        age_h = max(0, (now - int(row["first_seen"]))) / 3600.0
        incident_id = _upsert_incident(
            db, "chain:lineage:%s" % hashlib.sha256(
                path.encode("utf-8", "replace")).hexdigest()[:16],
            "Dropped object later executed or persisted (%s -> %s)"
            % (row["category"], category),
            "CRITICAL", "correlation", now, evidence, initially_notified)
        db.execute(
            "UPDATE incidents SET title=? WHERE id=?",
            ("Dropped object later executed or persisted: %s (%s -> %s, %.1fh "
             "apart)" % (path[:120], row["category"], category, age_h),
             incident_id))
        attached.update(evidence)
    return attached


def _apply_correlations(db, new_events, now, initially_notified=False,
                        suppressed_categories=frozenset()):
    """Run a deliberately tiny set of high-precision, versioned chain rules."""
    rows = db.execute(
        "SELECT id,observed_at,data_json FROM events "
        "WHERE event_type='observation.finding' "
        "AND observed_at>=?", (now - 1800,)).fetchall()
    observations = [(row["id"], row["observed_at"],
                     json.loads(row["data_json"])) for row in rows]
    new_ids = {event_id for event_id, f in new_events
               if f.get("category") not in suppressed_categories}
    attached = set()

    def correlate(base_key, title, left_pred, right_pred, window=900):
        matches_by_entity = {}
        for left_id, left_at, left in observations:
            if not left_pred(left):
                continue
            for right_id, right_at, right in observations:
                if left_id == right_id or not right_pred(right):
                    continue
                if abs(left_at - right_at) > window:
                    continue
                if not _same_entity(left, right):
                    continue
                if left_id in new_ids or right_id in new_ids:
                    entity = _canon_entity_path(_entity(left) or _entity(right))
                    entity_key = hashlib.sha256(
                        entity.encode("utf-8", "replace")).hexdigest()[:16]
                    matches_by_entity.setdefault(entity_key, set()).update(
                        (left_id, right_id))
        for entity_key, matches in matches_by_entity.items():
            key = "%s:%s" % (base_key, entity_key)
            incident_id = _upsert_incident(
                db, key, title, "CRITICAL", "correlation", now,
                sorted(matches), initially_notified)
            # A signal may have opened a standalone incident in an earlier scan.
            # Once independent evidence promotes it into a chain, close those
            # active leaf incidents so the operator sees one case, not duplicates.
            marks = ",".join("?" for _ in _ACTIVE_INCIDENT_STATES)
            event_marks = ",".join("?" for _ in matches)
            db.execute(
                "UPDATE incidents SET status='RESOLVED',resolution=?,updated_at=?,"
                "next_reminder_at=NULL WHERE kind='signal' AND id<>? AND "
                "status IN (%s) AND id IN (SELECT incident_id FROM incident_events "
                "WHERE event_id IN (%s))" % (marks, event_marks),
                ("promoted into incident %d" % incident_id, now, incident_id) +
                _ACTIVE_INCIDENT_STATES + tuple(sorted(matches)))
            attached.update(matches)

    def has_marker(f, values):
        markers = set(f.get("markers") or [])
        text = (f.get("title", "") + " " + f.get("detail", "")).lower()
        return bool(markers.intersection(values) or
                    any(v.replace("-", " ") in text for v in values))

    correlate(
        "chain:clickfix", "Potential ClickFix / infostealer chain",
        lambda f: f.get("category") in ("behavior", "shell-history") and
        has_marker(f, {"fileless-fetch-exec", "password-phish",
                       "quarantine-strip", "invisible-dmg"}),
        lambda f: f.get("category") in ("persistence", "staging", "hot-dir"))
    correlate(
        "chain:persistence-execution", "Persistence followed by execution",
        lambda f: f.get("category") == "persistence",
        lambda f: f.get("category") in ("process", "behavior"))
    correlate(
        "chain:remote-access", "Remote-access persistence chain",
        lambda f: f.get("category") == "persistence",
        lambda f: f.get("category") == "net-listener")
    correlate(
        "chain:supply-chain", "Background-item execution chain",
        lambda f: f.get("category") == "btm",
        lambda f: f.get("category") in ("process", "hot-dir", "persistence"))
    # Credential capture followed by persistence or exfil. These two stages are
    # each individually explainable, but TOGETHER on one entity they are the
    # infostealer kill chain — worth a CRITICAL chain rather than two HIGHs that
    # each have to survive the notify floor on their own.
    correlate(
        "chain:credential-capture", "Credential capture with persistence/exfil",
        lambda f: has_marker(f, {
            "osascript-password-phish", "dscl-authonly-passcheck",
            "keychain-db-access", "keychain-security-dump", "keychain-dump",
            "gui-kill-coercion", "gui-kill-loop-coercion"}),
        lambda f: f.get("category") in ("persistence", "staging", "net-listener")
        or has_marker(f, {"curl-exfil-post", "fileless-fetch-exec"}))

    # Durable lineage: a remembered drop that is later executed/persisted, at any
    # distance in time. Runs BEFORE the uncorrelated-signal fallback so a joined
    # event becomes one chain incident instead of two standalone ones.
    attached.update(_apply_path_lineage(
        db, new_events, now, initially_notified, suppressed_categories))

    # Middle tier: pile-up of weak signals on one entity → one 'risk' incident.
    _accumulate_risk(db, now, new_ids)

    # Every uncorrelated HIGH+ signal still becomes one actionable incident.
    for event_id, f in new_events:
        if f.get("category") in suppressed_categories or event_id in attached \
                or SEV_ORDER.get(f.get("severity"), -1) \
                < SEV_ORDER["HIGH"]:
            continue
        _upsert_incident(db, "signal:" + f["fingerprint"], f["title"],
                         f["severity"], "signal", now, [event_id],
                         initially_notified)


def _record_health(db, health, now):
    for item in health:
        sensor_id = str(item.get("sensor_id") or "unknown")
        status = str(item.get("status") or "FAILED").upper()
        detail = redact_sensitive(item.get("detail") or "")[:500]
        prior = db.execute("SELECT * FROM sensor_status WHERE sensor_id=?",
                           (sensor_id,)).fetchone()
        failed = status != "OK"
        failures = (prior["consecutive_failures"] if prior else 0) + 1 \
            if failed else 0
        episode = (prior["episode_started_at"] if prior else None)
        if failed and episode is None:
            episode = now
        if not failed:
            episode = None
        db.execute("INSERT INTO sensor_status(sensor_id,status,last_run_at,last_ok_at,"
                   "duration_ms,item_count,detail,consecutive_failures,episode_started_at)"
                   " VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(sensor_id) DO UPDATE SET "
                   "status=excluded.status,last_run_at=excluded.last_run_at,"
                   "last_ok_at=excluded.last_ok_at,duration_ms=excluded.duration_ms,"
                   "item_count=excluded.item_count,detail=excluded.detail,"
                   "consecutive_failures=excluded.consecutive_failures,"
                   "episode_started_at=excluded.episode_started_at",
                   (sensor_id, status, now, now if not failed else
                    (prior["last_ok_at"] if prior else None),
                    int(item.get("duration_ms") or 0),
                    int(item.get("item_count") or 0), detail, failures, episode))
        event_data = {"sensor_id": sensor_id, "status": status, "detail": detail,
                      "consecutive_failures": failures}
        cur = db.execute("INSERT INTO events(occurred_at,observed_at,source,event_type,"
                         "data_json) VALUES(?,?,?,?,?)",
                         (now, now, sensor_id, "sensor.health",
                          json.dumps(event_data, sort_keys=True)))
        if failures >= 3:
            _upsert_incident(db, "sensor:" + sensor_id,
                             "Security coverage degraded: %s" % sensor_id,
                             "HIGH", "sensor-health", now, [cur.lastrowid])
        elif not failed:
            db.execute("UPDATE incidents SET status='RESOLVED',resolution=?,"
                       "updated_at=?,last_seen=?,next_reminder_at=NULL WHERE "
                       "correlation_key=? AND status IN (%s)" %
                       ",".join("?" for _ in _ACTIVE_INCIDENT_STATES),
                       ("sensor recovered", now, now, "sensor:" + sensor_id) +
                       _ACTIVE_INCIDENT_STATES)


def record_security_state(findings, sensor_health=(), now=None,
                          initially_notified=False,
                          suppressed_categories=frozenset()):
    now = _epoch(now)
    db = _event_connection()
    new_events = []
    try:
        with db:
            for original in findings:
                f = _redact_value(dict(original))
                occurred = _epoch(f.get("occurred_at") or f.get("ts") or now)
                attrs = _event_attributes(f)
                db.execute(
                    "INSERT INTO signals(fingerprint,rule_id,rule_version,category,"
                    "severity,title,detail,first_seen,last_seen,occurrence_count,"
                    "attributes_json) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT("
                    "fingerprint) DO UPDATE SET last_seen=excluded.last_seen,"
                    "severity=excluded.severity,title=excluded.title,detail=excluded.detail,"
                    "occurrence_count=signals.occurrence_count+1,"
                    "attributes_json=excluded.attributes_json",
                    (f["fingerprint"], f.get("rule_id") or "aegis.legacy",
                     int(f.get("rule_version") or 1), f["category"], f["severity"],
                     f["title"], f["detail"], now, now, 1,
                     json.dumps(attrs, sort_keys=True)))
                signal_id = db.execute("SELECT id FROM signals WHERE fingerprint=?",
                                       (f["fingerprint"],)).fetchone()[0]
                cur = db.execute(
                    "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                    "signal_id,data_json) VALUES(?,?,?,?,?,?)",
                    (occurred, now, f.get("sensor_id") or f["category"],
                     "observation.finding", signal_id,
                     json.dumps(f, sort_keys=True)))
                new_events.append((cur.lastrowid, f))
            _record_health(db, sensor_health, now)
            _apply_correlations(db, new_events, now, initially_notified,
                                frozenset(suppressed_categories))
            db.execute("INSERT INTO meta(key,value) VALUES('last_scan',?) ON "
                       "CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
        # Bound raw observations while retaining materialized signals/incidents.
        with db:
            db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events "
                       "ORDER BY id DESC LIMIT -1 OFFSET 50000)")
    finally:
        db.close()
    return {"events": len(new_events), "health": len(sensor_health)}


def _dict_rows(rows):
    return [dict(row) for row in rows]


def list_incidents(active_only=True):
    db = _event_connection()
    try:
        where, args = "", ()
        if active_only:
            marks = ",".join("?" for _ in _ACTIVE_INCIDENT_STATES)
            where, args = "WHERE i.status IN (%s)" % marks, _ACTIVE_INCIDENT_STATES
        rows = db.execute(
            "SELECT i.*,count(ie.event_id) AS evidence_count FROM incidents i "
            "LEFT JOIN incident_events ie ON ie.incident_id=i.id %s GROUP BY i.id "
            "ORDER BY CASE i.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
            "ELSE 1 END DESC,i.updated_at DESC" % where, args).fetchall()
        return _dict_rows(rows)
    finally:
        db.close()


def incident_detail(incident_id):
    db = _event_connection()
    try:
        row = db.execute("SELECT * FROM incidents WHERE id=?",
                         (incident_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["evidence"] = _dict_rows(db.execute(
            "SELECT e.id,e.observed_at,e.source,e.event_type,e.data_json FROM events e "
            "JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=? "
            "ORDER BY e.observed_at", (incident_id,)).fetchall())
        # Which sensors contributed — drives the known-benign-cause lookup that
        # makes triage a match-against-known-list instead of an investigation.
        result["categories"] = sorted(_incident_categories(db, incident_id))
        return result
    finally:
        db.close()


_INCIDENT_TRANSITIONS = {
    "OPEN": {"ACK", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"},
    "ACK": {"INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"CONTAINED", "RECOVERING", "MONITORING", "RESOLVED",
                      "FALSE_POSITIVE"},
    "CONTAINED": {"RECOVERING", "MONITORING", "RESOLVED"},
    "RECOVERING": {"MONITORING", "RESOLVED"},
    "MONITORING": {"INVESTIGATING", "RESOLVED"},
    "RESOLVED": {"OPEN"},
    "FALSE_POSITIVE": {"OPEN"},
}


def _incident_categories(db, incident_id):
    """The distinct sensor categories of an incident's evidence, for per-sensor
    dismissal accounting."""
    cats = set()
    rows = db.execute(
        "SELECT e.data_json FROM events e JOIN incident_events ie "
        "ON ie.event_id=e.id WHERE ie.incident_id=?", (incident_id,)).fetchall()
    for row in rows:
        try:
            category = json.loads(row["data_json"]).get("category")
        except Exception:
            continue
        if category:
            cats.add(str(category))
    return cats


def transition_incident(incident_id, new_status, now=None, reason_code=None):
    """Move an incident through its lifecycle. `reason_code` distinguishes the
    two dismissal kinds the SOC literature separates, because they need OPPOSITE
    handling and conflating them is the main alert-fatigue driver:
      false-positive  — the DETECTION was wrong (tune or retire the rule)
      benign-positive — the event was REAL but authorized (suppress this
                        instance; the rule itself is working)
    Both land in FALSE_POSITIVE (the suppression semantics are identical) but are
    recorded separately so the tuning queues, and the per-sensor precision
    feedback, can tell a broken rule from an expected-but-noisy one."""
    now = _epoch(now)
    new_status = str(new_status).upper().replace("-", "_")
    db = _event_connection()
    try:
        with db:
            row = db.execute("SELECT * FROM incidents WHERE id=?",
                             (incident_id,)).fetchone()
            if not row or new_status not in _INCIDENT_TRANSITIONS.get(row["status"], set()):
                return False
            next_at = now + _REMINDER_DELAYS[0] if new_status == "OPEN" else None
            resolution = new_status.lower() if new_status in \
                ("RESOLVED", "FALSE_POSITIVE") else None
            if new_status == "FALSE_POSITIVE" and reason_code:
                resolution = reason_code
            db.execute("UPDATE incidents SET status=?,updated_at=?,resolution=?,"
                       "next_reminder_at=?,reminder_count=? WHERE id=?",
                       (new_status, now, resolution, next_at,
                        0 if new_status == "OPEN" else row["reminder_count"],
                        incident_id))
            db.execute("INSERT INTO events(occurred_at,observed_at,source,event_type,"
                       "incident_id,data_json) VALUES(?,?,?,?,?,?)",
                       (now, now, "incident", "incident.lifecycle", incident_id,
                        json.dumps({"from": row["status"], "to": new_status,
                                    "reason_code": reason_code})))
            if new_status == "FALSE_POSITIVE":
                code = reason_code or "false-positive"
                cats = _incident_categories(db, incident_id) or {""}
                for category in cats:
                    db.execute(
                        "INSERT INTO dismissals(incident_id,correlation_key,"
                        "reason_code,category,dismissed_at) VALUES(?,?,?,?,?)",
                        (incident_id, row["correlation_key"], code, category, now))
            elif new_status == "OPEN":
                # Reopened: the dismissal was itself wrong, so it must stop
                # counting against the sensor's precision.
                db.execute("DELETE FROM dismissals WHERE incident_id=?",
                           (incident_id,))
        return True
    finally:
        db.close()


def claim_due_incident_reminders(now=None):
    now = _epoch(now)
    db = _event_connection()
    claimed = []
    try:
        with db:
            marks = ",".join("?" for _ in _ACTIVE_INCIDENT_STATES)
            rows = db.execute(
                "SELECT * FROM incidents WHERE status IN (%s) AND "
                "next_reminder_at IS NOT NULL AND next_reminder_at<=? "
                "ORDER BY severity DESC,next_reminder_at" % marks,
                _ACTIVE_INCIDENT_STATES + (now,)).fetchall()
            for row in rows:
                count = row["reminder_count"] + 1
                next_at = (row["created_at"] + _REMINDER_DELAYS[count]
                           if count < len(_REMINDER_DELAYS) else None)
                db.execute("UPDATE incidents SET reminder_count=?,last_notified_at=?,"
                           "next_reminder_at=? WHERE id=?",
                           (count, now, next_at, row["id"]))
                claimed.append(dict(row))
        return claimed
    finally:
        db.close()


def get_sensor_health():
    db = _event_connection()
    try:
        return _dict_rows(db.execute(
            "SELECT * FROM sensor_status ORDER BY sensor_id").fetchall())
    finally:
        db.close()


def _collect_sensor(sensor_id, fn, health, *args):
    started = time.monotonic()
    try:
        result = fn(*args)
        status = "DEGRADED" if result is None else "OK"
        detail = "sensor returned no reliable snapshot" if result is None else ""
        output = [] if result is None else result
    except Exception as e:
        status, detail, output = "FAILED", str(e), []
    duration = int((time.monotonic() - started) * 1000)
    health.append({"sensor_id": sensor_id, "status": status,
                   "detail": redact_sensitive(detail), "duration_ms": duration,
                   "item_count": len(output) if hasattr(output, "__len__") else 0})
    if isinstance(output, list):
        for f in output:
            if isinstance(f, dict):
                f.setdefault("sensor_id", sensor_id)
    return output


# --------------------------------------------------------------------------- #
# Check 1: persistence (launchd + cron) with baseline diff
# --------------------------------------------------------------------------- #


def _plist_program(d):
    prog = None
    args = d.get("ProgramArguments")
    if isinstance(d.get("Program"), str):
        prog = d["Program"]
    elif isinstance(args, list) and args:
        prog = args[0]
    # Resolve a bare command name to an absolute path if we can.
    if prog and not prog.startswith("/"):
        prog = shutil.which(prog) or prog
    return prog, args


def snapshot_persistence():
    """Return {plist_path: record} for all third-party launchd jobs."""
    snap = {}
    for d in PERSISTENCE_DIRS:
        try:
            entries = sorted(os.listdir(d))
        except Exception:
            continue
        for name in entries:
            if not name.endswith(".plist"):
                continue
            path = os.path.join(d, name)
            rec = {"label": name[:-6], "program": None, "args": None,
                   "args_sha256": None,
                   "sha256": None, "trust": "unknown", "run_at_load": False,
                   "authority": None, "env": None}
            try:
                with open(path, "rb") as f:
                    pl = plistlib.load(f)
            except Exception:
                pl = {}
            prog, args = _plist_program(pl if isinstance(pl, dict) else {})
            rec["label"] = (pl.get("Label") if isinstance(pl, dict) else None) or rec["label"]
            rec["program"] = prog
            if args is not None:
                raw_args = json.dumps(args, sort_keys=True, default=str)
                rec["args_sha256"] = hashlib.sha256(raw_args.encode()).hexdigest()
                rec["args"] = _redact_value(args)
            rec["run_at_load"] = bool(pl.get("RunAtLoad")) if isinstance(pl, dict) else False
            ev = pl.get("EnvironmentVariables") if isinstance(pl, dict) else None
            if isinstance(ev, dict):
                # keep only injection-relevant keys — the rest is noise/PII
                inj = {k: str(v) for k, v in ev.items() if k in _DYLD_INJECT_KEYS}
                rec["env"] = inj or None
            if prog and os.path.exists(prog):
                rec["sha256"] = sha256(prog)
                sig = classify_signature(prog)
                rec["trust"] = sig["trust"]
                rec["authority"] = sig["authority"]
            elif prog:
                rec["trust"] = "missing"
            snap[path] = rec
    return snap


# A signed interpreter is only as trustworthy as what it is told to run. AMOS/
# Poseidon-style launchd persistence hides behind Apple-signed interpreters
# (bash/python/osascript) driven by a hostile inline script, a piped network
# fetch, or a script stashed in a dotdir — so the binary's own signature/location
# says "safe" while the arguments are the payload.
_INTERPRETERS = frozenset((
    "bash", "sh", "zsh", "dash", "ksh", "env",
    "python", "python2", "python3", "perl", "ruby", "php", "osascript", "node",
))
_INLINE_EXEC_FLAGS = frozenset(("-c", "-e"))
_FETCH_RE = re.compile(r"\b(?:curl|wget|nscurl)\b.*?https?://", re.I | re.S)

# Apple-signed LOLBin launchers that merely WRAP the real payload. A launchd job
# whose ProgramArguments start with one of these looks benign if you only score
# argv[0] — `caffeinate -i ~/.payload` fronts an Apple binary in a trusted path
# while the payload is the argument (a documented 2026 persistence wrapper, and
# the same trick works with nohup/setsid/screen). The wrapper must be stripped so
# the interpreter/script-target scoring below sees the ACTUAL program.
_WRAPPER_LAUNCHERS = frozenset((
    "caffeinate", "nohup", "setsid", "stdbuf", "timeout", "gtimeout", "script",
    "screen", "tmux", "arch", "sudo", "doas",
))
# Wrapper flags that consume a following value (so it is not mistaken for the
# payload): caffeinate -t <sec>, timeout -s <sig>, screen -S <name>, arch -arch …
_WRAPPER_VALUE_FLAGS = frozenset(("-t", "-s", "-S", "-arch", "-u", "-c", "-w"))


def _unwrap_launchers(args, depth=4):
    """Strip leading LOLBin wrapper launchers (and their flags) from an argv list
    so the effective program is exposed. `env` is intentionally NOT handled here:
    it is already in _INTERPRETERS and carries KEY=VALUE assignments that the
    caller's own logic inspects. Returns the unwrapped argv (possibly unchanged)."""
    if not isinstance(args, list):
        return args
    out = [str(a) for a in args if a is not None]
    for _ in range(depth):
        if not out or os.path.basename(out[0]) not in _WRAPPER_LAUNCHERS:
            break
        rest = out[1:]
        i = 0
        while i < len(rest) and rest[i].startswith("-"):
            flag = rest[i]
            i += 1
            # `-t 30` style: skip the flag's value too (but not another flag).
            if flag in _WRAPPER_VALUE_FLAGS and i < len(rest) \
                    and not rest[i].startswith("-"):
                i += 1
        if i >= len(rest):
            break                      # wrapper with no payload — nothing to score
        out = rest[i:]
    return out


def _interp_fronted(args, program=None):
    """Is this process an interpreter driving a payload? The interpreter identity
    comes from the RESOLVED program (plist `Program` key) when present, falling
    back to args[0]. launchd lets ProgramArguments[0] be an arbitrary custom
    argv0 that need not equal the real binary, so a decoy argv0 (e.g.
    Program=/bin/bash, argv0="com.apple.softwareupdate") must not hide the
    interpreter — either basename being an interpreter counts."""
    if not isinstance(args, list) or not args:
        return False
    for cand in (program, args[0]):
        if cand is not None and os.path.basename(str(cand)) in _INTERPRETERS:
            return True
    return False


def _effective_argv(args, program=None):
    """(args, program) with any Apple-signed wrapper launcher stripped. When a
    wrapper WAS stripped, the resolved plist `Program` described the WRAPPER, not
    the payload, so it is dropped — the payload now fronts the argv and must be
    what the interpreter/script-target scoring sees."""
    if not isinstance(args, list) or not args:
        return args, program
    flat = [str(a) for a in args if a is not None]
    unwrapped = _unwrap_launchers(args)
    if unwrapped != flat:
        return unwrapped, None
    return args, program


def _script_target(args, program=None):
    """The script an interpreter is told to run: the first path-like, non-flag
    argument after the interpreter binary. None if the process isn't interpreter-
    fronted (by resolved program OR args[0]) or no such argument exists."""
    args, program = _effective_argv(args, program)
    if not isinstance(args, list) or len(args) < 2 or args[0] is None:
        return None
    if not _interp_fronted(args, program):
        return None
    for a in args[1:]:
        s = str(a)
        if s.startswith("-"):
            continue
        return s if s.startswith("/") else None
    return None


def _hidden_home_or_tmp(path):
    """A script location that is anomalous for a launchd job to point an
    interpreter at: a hidden file sitting DIRECTLY in $HOME (~/.agent, ~/.helper —
    the AMOS/Atomic 2025 pattern), or a temp/shared drop dir. Deliberately does
    NOT match conventional tool subdirs like ~/.local/bin or ~/.cargo/bin (those
    have a multi-segment path, so dirname != $HOME) — that would be a false-
    positive cannon against legitimate user tooling."""
    if not path:
        return False
    # Lexically normalize FIRST so a no-op `/./` or redundant separators can't
    # dodge the structural comparison (`~/./.agent` resolves to `~/.agent`, and
    # execvp/launchd run the same file). normpath is pure-lexical by design — we
    # do NOT want realpath here (it would hit the FS and resolve symlinks).
    norm = os.path.normpath(path)
    if norm.startswith(("/tmp", "/private/tmp", "/var/folders",
                        "/private/var/folders", "/Users/Shared")):
        return True
    return (os.path.dirname(norm) == HOME
            and os.path.basename(norm).startswith("."))


def _hostile_args(args, program=None):
    """Intent-derived (README: catch AMOS/Poseidon launchd persistence), and
    independent of the interpreter binary's own signature/location. True on the
    HIGH-PRECISION infostealer signals: a signed interpreter driven by an inline
    script (`bash -c …`, `osascript -e …`); a network fetch in the args
    (`curl|wget http…`); or any of the shared hostile idioms (`… | sh`,
    `base64 -d`, `/dev/tcp`, `nc -e`, raw-IP fetch, launchctl-load-from-tmp).
    Deliberately does NOT flag scripts merely living in a dotdir — legit tools
    live in ~/.local, ~/.cargo, ~/.pyenv, … and the tool's prime directive is
    'alert rarely' (a false HIGH is worse than a rare miss)."""
    if not isinstance(args, list) or not args or args[0] is None:
        return False
    # Strip Apple-signed wrapper LOLBins (caffeinate/nohup/setsid/sudo -u …) so
    # the payload — not the trusted wrapper — is what gets scored. A wrapper
    # pointed straight at a hidden $HOME/tmp file is itself the AMOS shape.
    joined_raw = " ".join(str(a) for a in args)
    args, program = _effective_argv(args, program)
    if args and _hidden_home_or_tmp(str(args[0])):
        return True
    rest = [str(a) for a in args[1:]]
    if _interp_fronted(args, program) and any(a in _INLINE_EXEC_FLAGS for a in rest):
        return True
    # interpreter pointed at a hidden script in $HOME root or a temp dir — the
    # AMOS `/bin/bash ~/.agent` / `.helper` 2025 persistence pattern. The binary
    # (bash) is Apple-signed and in a trusted path, so signature+location scoring
    # alone reads it as safe; the tell is WHERE the script it runs lives.
    tgt = _script_target(args, program)
    if tgt and _hidden_home_or_tmp(tgt):
        return True
    # Content-scan the ORIGINAL argv (wrapper included): unwrapping only ever
    # removes the launcher, so scanning the pre-unwrap string is a superset and
    # guarantees stripping a wrapper can never LOSE a hostile idiom.
    if _FETCH_RE.search(joined_raw):
        return True
    return bool(_hostile_content(joined_raw))


def _persistence_severity(rec):
    prog = rec.get("program")
    trust = rec.get("trust")
    label = rec.get("label") or ""
    if label.startswith("com.apple.") and trust not in ("apple", "app-store"):
        # A third-party plist (we never scan /System) whose LABEL claims to be
        # Apple's but whose program is not Apple-signed is impersonating the OS —
        # RustBucket/BlueNoroff shipped `com.apple.systemupdate` behind a hijacked
        # Developer-ID cert, which every signature-only check would wave through.
        return "CRITICAL" if is_risky_location(prog) else "HIGH"
    # Generalize OS-impersonation to well-known vendors: a label claiming to be
    # Google/Microsoft/Dropbox whose program isn't signed by that vendor's Team ID
    # is impersonating trusted software. ClickFix stages a fake
    # `com.google.keystone.agent` + GoogleUpdate.app even with no Google software
    # installed; ModStealer masquerades likewise. Verified against the signing
    # authority/team so a genuine vendor agent (correctly signed) is not flagged.
    for prefix, (_vendor, team) in VENDOR_LABEL_TEAMS.items():
        if label.startswith(prefix):
            # Impersonation requires a RESOLVABLE program that is NOT signed by the
            # vendor's Team ID. A vendor agent whose program we simply can't resolve
            # (trust unknown/missing — e.g. the real Google Keystone, whose plist
            # points at a path absent at scan time) is a weaker "missing" signal,
            # not an impostor — falling through avoids a HIGH FP on legit software.
            # Key on the non-forgeable Team ID (present in a Developer-ID leaf
            # authority as "… (TEAMID)"), NOT the vendor NAME — a substring match on
            # "Google" would be fooled by an authority reading "Not Google".
            if trust not in ("missing", "unknown") and team not in (rec.get("authority") or ""):
                return "CRITICAL" if is_risky_location(prog) else "HIGH"
    if rec.get("env"):
        # a launchd job that injects a dylib/lib path into what it spawns
        # (DYLD_INSERT_LIBRARIES &c.) is a code-injection persistence pattern.
        return "CRITICAL" if is_risky_location(prog) else "HIGH"
    if _hostile_args(rec.get("args"), rec.get("program")):
        # signed-interpreter + hostile payload: the #1 infostealer pattern.
        return "CRITICAL" if is_risky_location(prog) else "HIGH"
    if suspicious_sig(trust) and is_risky_location(prog):
        return "CRITICAL" if prog and prog.startswith(
            ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders")
        ) else "HIGH"
    if suspicious_sig(trust):
        return "HIGH"
    if trust == "missing":
        return "LOW"  # points at a program that isn't on disk: can't execute
    if is_risky_location(prog):
        return "MEDIUM"
    # An Apple-signed interpreter in a trusted path, but the SCRIPT it runs lives
    # in a user-writable location (Phexia: `osascript ~/Library/<random>`). Not a
    # notify-grade HIGH (legit agents run ~/Library helper scripts too), but worth
    # surfacing at MEDIUM rather than the LOW the interpreter's own path implies.
    tgt = _script_target(rec.get("args"), rec.get("program"))
    if tgt and is_risky_location(tgt):
        return "MEDIUM"
    return "LOW"


def _persistence_change_detail(label, old, rec,
                               prog_changed, env_changed, args_changed):
    """Human-readable before->after for the fields that actually mutated. The
    old message always printed the PROGRAM path on both sides, so an args- or
    env-only change rendered as the nonsensical 'args changed (X -> X)' with an
    identical program — uninterpretable, and the exact confusion that made a
    real (but benign) self-plist change look like garbage. Render each changed
    field's true old->new instead. Values are already redacted at snapshot;
    finding() redacts the detail once more."""
    def _args_str(v):
        a = v.get("args")
        if not a:
            return "(none)"
        if isinstance(a, (list, tuple)):
            return " ".join(str(x) for x in a)
        return str(a)

    def _env_str(v):
        e = v.get("env")
        return json.dumps(e, sort_keys=True) if e else "(none)"

    parts = []
    if prog_changed:
        op, np = old.get("program"), rec.get("program")
        if op != np:
            parts.append("program %s -> %s" % (op, np))
        else:  # same path, different bytes — a swapped binary
            parts.append("program bytes %s -> %s" % (
                (old.get("sha256") or "?")[:12], (rec.get("sha256") or "?")[:12]))
    if args_changed:
        parts.append("args [%s] -> [%s]" % (_args_str(old), _args_str(rec)))
    if env_changed:
        parts.append("env %s -> %s" % (_env_str(old), _env_str(rec)))
    return "%s: %s" % (label, "; ".join(parts))


def check_persistence(baseline_snap, current_snap):
    findings = []
    base = baseline_snap or {}
    for path, rec in current_snap.items():
        if path not in base:
            sev = _persistence_severity(rec)
            findings.append(finding(
                sev, "persistence", "New persistence item",
                "%s -> %s [%s]" % (rec["label"], rec.get("program") or "?",
                                   rec.get("trust")),
                "persistence:new:%s:%s" % (path, rec.get("sha256")),
                path=path, program=rec.get("program"), trust=rec.get("trust"),
                run_at_load=rec.get("run_at_load")))
        else:
            old = base[path]
            # An in-place mutation of an already-baselined plist can inject a
            # dylib (launchd EnvironmentVariables) or swap the payload argv
            # WITHOUT touching the program path or its bytes — invisible to a
            # program/hash-only diff. Compare env/args too, and rate the finding
            # by the mutated record (reusing _persistence_severity) so a
            # DYLD_INSERT_LIBRARIES injection surfaces at its true CRITICAL/HIGH.
            prog_changed = (old.get("program") != rec.get("program")
                            or old.get("sha256") != rec.get("sha256"))
            env_changed = (old.get("env") or None) != (rec.get("env") or None)
            args_changed = ((old.get("args_sha256") or old.get("args") or None) !=
                            (rec.get("args_sha256") or rec.get("args") or None))
            if prog_changed or env_changed or args_changed:
                # Fold the current sha256/env/args into the fingerprint (sha256
                # alone is unchanged on an env-only mutation) so a real change
                # re-alerts but a steady mutated state does not storm.
                fp = hashlib.sha256(repr(
                    (rec.get("sha256"), rec.get("env"),
                     rec.get("args_sha256") or rec.get("args"))
                ).encode()).hexdigest()[:16]
                # The mutated record's own risk drives severity (env-injection /
                # adhoc-in-tmp escalate to CRITICAL), but a swapped program binary
                # is inherently serious even if the replacement is validly signed
                # (supply-chain / stolen-cert swap), so a program/hash change never
                # scores below HIGH — the change itself is the signal.
                sev = _persistence_severity(rec)
                if prog_changed and SEV_ORDER[sev] < SEV_ORDER["HIGH"]:
                    sev = "HIGH"
                findings.append(finding(
                    sev, "persistence",
                    "Persistence item CHANGED",
                    _persistence_change_detail(
                        rec["label"], old, rec,
                        prog_changed, env_changed, args_changed),
                    "persistence:changed:%s:%s" % (path, fp),
                    path=path, program=rec.get("program"), trust=rec.get("trust")))
    for path, old in base.items():
        if path not in current_snap:
            findings.append(finding(
                "LOW", "persistence", "Persistence item removed",
                "%s (%s) no longer present" % (old.get("label"), path),
                "persistence:removed:%s" % path, path=path))
    return findings


def check_cron():
    findings = []
    out, _, rc = run(["crontab", "-l"], timeout=8)
    if rc == 0 and out.strip():
        lines = [l for l in out.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        if lines:
            findings.append(finding(
                "MEDIUM", "persistence", "User crontab entries present",
                "%d active line(s); command digest %s" % (
                    len(lines), hashlib.sha256(out.encode()).hexdigest()[:16]),
                "cron:user:%s" % hashlib.sha256(out.encode()).hexdigest()[:16]))
    return findings


# --------------------------------------------------------------------------- #
# Check 2: suspicious running processes
# --------------------------------------------------------------------------- #


# Apple system-daemon names a masquerading process typosquats. ClickLock (2026)
# ran its reverse shell as "SystemUIServerl" — one character off the real
# menu-bar daemon — to blend into a `ps`/Activity-Monitor listing. A binary whose
# NAME is edit-distance-1 from one of these but which runs from a user-writable
# path is a near-certain masquerade regardless of its signature.
#
# Only names of _TYPOSQUAT_MIN_LEN or more are compared. Short daemon names
# collide with ordinary commands at edit-distance 1 — `log` vs `logd`, `finger`
# vs `finder`, `dock` vs `doc` — which would fire a false HIGH on any such binary
# in a user-writable path (verified against a live 537-process table, where
# `/usr/bin/log` matches `logd`). The dropped short names lose little: an
# unsigned short-named binary in a user-writable path is already caught by the
# suspicious-signature check below, and vendor-label impersonation (com.finder.*)
# is covered by the persistence sensor's Team-ID check.
_TYPOSQUAT_MIN_LEN = 7
_APPLE_DAEMON_NAMES = frozenset((
    "systemuiserver", "windowserver", "loginwindow", "cfprefsd", "coreauthd",
    "spotlight", "mdworker", "launchd", "distnoted", "nsurlsessiond",
    "usereventagent", "controlcenter", "coreservicesd", "securityd",
    "notificationcenter", "backgroundtaskmanagementagent",
))


def _edit_distance_le1(a, b):
    """True if Levenshtein distance(a, b) <= 1 (one insert/delete/substitute)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    if la > lb:                       # make `a` the shorter of the two
        a, b, la, lb = b, a, lb, la
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True            # consume one extra char of the longer string
            j += 1
    return True


def _typosquats_apple_daemon(name):
    """The Apple daemon `name` impersonates within edit-distance 1, else None. An
    exact (case-insensitive) match is NOT returned: that is the real daemon or a
    same-name masquerade the signature/location checks already handle."""
    low = (name or "").lower()
    if len(low) < _TYPOSQUAT_MIN_LEN or low in _APPLE_DAEMON_NAMES:
        return None
    for real in _APPLE_DAEMON_NAMES:
        if len(real) >= _TYPOSQUAT_MIN_LEN and _edit_distance_le1(low, real):
            return real
    return None


def check_processes():
    findings = []
    out, _, rc = run(["ps", "-axo", "pid=,comm="], timeout=12)
    if rc != 0:
        return findings
    seen_paths = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        _pid, comm = parts
        if not comm.startswith("/"):
            continue
        if any(comm.startswith(p) for p in TRUSTED_PREFIXES):
            continue
        if comm in seen_paths:
            continue
        seen_paths.add(comm)
        sig = classify_signature(comm)
        # Apple-daemon name masquerade (ClickLock "SystemUIServerl"): the NAME is
        # the tell, so this fires regardless of signature — a validly-signed or
        # ad-hoc binary named one char off a system daemon, running from a
        # user-writable path, is impersonating the OS in the process list.
        squat = _typosquats_apple_daemon(os.path.basename(comm))
        if squat and is_risky_location(comm):
            sha = sha256(comm)
            findings.append(finding(
                "HIGH", "process", "Apple-daemon name masquerade",
                "%s (%s) runs from a user-writable path but its name is one "
                "character off the Apple system daemon %r — a process-name "
                "masquerade (ClickLock TTP)" % (comm, sig["trust"], squat),
                "process:typosquat:%s:%s" % (comm, sha),
                path=comm, trust=sig["trust"], typosquats=squat, sha256=sha,
                markers=["name-masquerade"]))
        if suspicious_sig(sig["trust"]) and is_risky_location(comm):
            # Fold the content hash into the fingerprint so a DIFFERENT binary
            # later reusing the same path is a new finding (and not silently
            # covered by an allowlist entry made for the earlier one).
            sha = sha256(comm)
            findings.append(finding(
                "HIGH", "process", "Suspicious running process",
                "%s (%s) running from user-writable path" % (comm, sig["trust"]),
                "process:%s:%s:%s" % (comm, sig["trust"], sha),
                path=comm, trust=sig["trust"], sha256=sha))
    return findings


# --------------------------------------------------------------------------- #
# Check 2b: BEHAVIORAL process-argv inspection (the fileless-stealer tier).
#
# check_processes() above keys on the executable PATH, so it is blind to the
# dominant 2025 TTP: a hostile command line driven through an Apple-signed
# interpreter (bash/osascript/curl), whose path is trusted and whose malice is
# entirely in argv. This reads the full argv of SAME-USER processes and scores
# the structural-invariant signals (password phish, quarantine strip, keychain
# copy, invisible DMG mount, exfil POST, tccutil reset) plus the shared hostile
# idioms. Same-user only (KERN_PROCARGS2) — the honest boundary for an
# unprivileged agent; consumer smash-and-grab is same-user.
# --------------------------------------------------------------------------- #


# Idioms that become a fileless-exec pipeline only in combination with a fetch —
# a lone one is common in benign dev work (a Homebrew/rustup `curl … | bash` in
# flight), so we notify only on the COMBINATION to keep the live-process check
# low-FP (the moderator's 'alert rarely' + Bitdefender-ATC threshold lesson).
_PIPE_EXEC_IDIOMS = frozenset((
    "pipe-to-shell", "pipe-to-interpreter", "osascript-shell", "base64-decode",
    "python-oneliner", "eval-subshell", "exec-eval"))
_FETCH_IDIOMS = frozenset(("network-fetch", "raw-ip-fetch", "interp-fetch"))


def _argv_signals(argv):
    """Return [(name, severity)] for hostile patterns in a live process's argv
    (empty = clean). Structural signals keep their assigned severity; the shared
    shell idioms notify (HIGH) only as a fetch+exec COMBINATION, else stay MEDIUM;
    anti-VM gates are MEDIUM corroborators below the notify floor."""
    if not argv:
        return []
    best = {}

    def add(name, sev):
        if name not in best or SEV_ORDER[sev] > SEV_ORDER[best[name]]:
            best[name] = sev

    for rx, name, sev in _HOSTILE_ARGV_RES:
        if rx.search(argv):
            add(name, sev)
    idioms = set(_hostile_content(argv))
    fetch = idioms & _FETCH_IDIOMS
    execp = idioms & _PIPE_EXEC_IDIOMS
    if fetch and execp:
        # network fetch piped into an interpreter = the fileless stealer pipeline.
        add("fileless-fetch-exec", "HIGH")
    # Unambiguous idioms are HIGH even alone (a reverse shell / netcat-exec is
    # never benign); the fetch/pipe idioms alone stay MEDIUM (benign-installer FP).
    for name in idioms:
        if name in ("bash-reverse-shell", "netcat-exec", "launchctl-tmp",
                    "osascript-password-phish", "keychain-dump"):
            add(name, "HIGH")
        else:
            add(name, "MEDIUM")
    for rx, name in _ANTIVM_ARGV_RES:
        if rx.search(argv):
            add(name, "MEDIUM")
    # A GUI-kill wrapped in a tight loop is the ClickLock coercion primitive —
    # escalate the HIGH kill signal to a short-circuit CRITICAL.
    if "gui-kill-coercion" in best and _KILL_LOOP_RE.search(argv):
        add("gui-kill-loop-coercion", "CRITICAL")
    return sorted(best.items())


def check_behavior():
    """Inspect running processes' full command lines for hostile behavior."""
    findings = []
    my_uid = str(os.getuid())
    my_pid = str(os.getpid())
    # -o …= suppresses headers; comm is the exec path, args is the full argv.
    out, _, rc = run(["ps", "-axo", "pid=,uid=,comm=,args="], timeout=15)
    if rc != 0:
        return findings
    seen = set()
    for line in out.splitlines():
        # Only pid and uid are guaranteed space-free (integers); split just those
        # off the left and keep the REST as one string. macOS `comm` prints the
        # full exec path, which can contain spaces, so splitting comm out as a
        # single token (the old split(None, 3)) sheared any spaced path and fed a
        # bogus basename to the pre-filter. `rest` holds comm+argv; the exec path
        # is duplicated at its head (argv[0] repeats comm) but that is harmless
        # prefix noise to the pattern scorer.
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, uid, argv = parts
        # Same-user only: an unprivileged process gets truncated/empty argv for
        # other users' processes, so a match there would be unreliable. And never
        # inspect our OWN scanning process (its argv legitimately carries these
        # patterns). We exclude self by the unspoofable real PID — NOT by an
        # "aegis" substring in argv, which an attacker reading this open-source
        # check could trivially abuse to evade detection (e.g. a phishing dialog
        # whose text reads "System aegis needs your password…").
        if uid != my_uid or pid == my_pid:
            continue
        base = os.path.basename(argv.split(None, 1)[0]) if argv else ""
        # Cheap pre-filter: only argv-inspect known interpreter/utility binaries
        # (keeps the regex work bounded on a 500-process list). A hostile chain
        # fronts one of these, carries an obvious network-fetch idiom, or — when
        # the attacker renamed the binary / dropped it at a spaced path so `base`
        # is unrecognizable — still NAMES a watched interpreter somewhere in argv.
        if (base not in _ARGV_WATCH_BINS
                and not _FETCH_RE.search(argv)
                and not _ARGV_WATCH_RE.search(argv)):
            continue
        signals = _argv_signals(argv)
        if not signals:
            continue
        top = max(signals, key=lambda s: SEV_ORDER[s[1]])[1]
        names = ", ".join(n for n, _ in signals)
        # Fingerprint on the binary + signal set + a hash of the argv, so the
        # same offending command alerts once but a new one re-alerts.
        fp = "behavior:%s:%s:%s" % (
            base, "|".join(sorted(n for n, _ in signals)),
            hashlib.sha256(argv.encode()).hexdigest()[:16])
        if fp in seen:
            continue
        seen.add(fp)
        command_sha = hashlib.sha256(argv.encode()).hexdigest()
        findings.append(finding(
            top, "behavior", "Suspicious process behavior",
            "%s triggered [%s]; command sha256=%s" %
            (base, names, command_sha[:16]),
            fp, program=argv.split(None, 1)[0] if argv else "",
            pid=pid, markers=[n for n, _ in signals], command_sha256=command_sha))
    return findings


# --------------------------------------------------------------------------- #
# Check 2c: harvest Apple's own XProtect Remediator detections + freshness.
#
# XPR is Apple's periodic malware scanner/remediator. Its scan+detection events
# are in the unified log and readable WITHOUT root or an ES entitlement. A
# detection here means Apple's professionally-maintained engine found malware —
# the highest-value signal a free, signature-less tool can surface. We also flag
# stale XProtect definitions (Apple ships ~monthly; a long gap implies a broken
# update path or MDM tampering).
# --------------------------------------------------------------------------- #


def check_xprotect(window_hours=None):
    findings = []

    # (a) Harvest detection events from the unified log since the last scan.
    #     Bound the window so `log show` stays cheap (≈1.5s for 2h on-host).
    if window_hours is None:
        window_hours = 6  # default cadence-sized window; capped below
    win = "%dh" % max(1, min(int(window_hours), 48))
    out, _, rc = run(["log", "show", "--last", win, "--style", "ndjson",
                      "--predicate",
                      'subsystem == "%s" AND category == "XPEvent.structured"'
                      % XPROTECT_SUBSYSTEM], timeout=45)
    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if not isinstance(ev, dict):
                continue  # non-object ndjson record — skip, never fatal
            msg = ev.get("eventMessage") or ""
            try:
                detail = json.loads(msg)
            except Exception:
                detail = {}
            if not isinstance(detail, dict):
                detail = {}  # valid non-object JSON (list/scalar) — treat as empty
            status = detail.get("status_message") or ""
            caused = detail.get("caused_by") or []
            # A clean scan is status "NoThreatDetected" with empty caused_by.
            # Anything else with evidence is a detection/remediation by Apple.
            if status and status != XPROTECT_CLEAN_STATUS and (caused or "Detect" in status
                                                               or "Remediat" in status
                                                               or "Threat" in status):
                fam = os.path.basename(ev.get("processImagePath") or "XProtectRemediator")
                fam = fam.replace("XProtectRemediator", "") or "?"
                ts = ev.get("timestamp") or ""
                findings.append(finding(
                    "CRITICAL", "xprotect",
                    "Apple XProtect Remediator flagged malware",
                    "module %s reported '%s' at %s%s — Apple's own engine "
                    "detected/remediated a threat. Investigate immediately."
                    % (fam, status, ts,
                       (" (%s)" % ", ".join(str(c) for c in caused[:3])) if caused else ""),
                    "xprotect:detect:%s:%s:%s" % (
                        fam, status,
                        hashlib.sha256((msg + ts).encode()).hexdigest()[:16]),
                    module=fam, status=status))

    # (b) Definition freshness — newest bundle mtime across the known locations.
    newest = None
    version = None
    for b in XPROTECT_BUNDLES:
        try:
            m = os.path.getmtime(b)
        except Exception:
            continue
        if newest is None or m > newest:
            newest = m
            info = os.path.join(b, "Contents", "Info.plist")
            v, _, vrc = run(["/usr/libexec/PlistBuddy", "-c",
                             "Print :CFBundleShortVersionString", info], timeout=6)
            if vrc == 0:
                version = v.strip()
    if newest is not None:
        age_days = (time.time() - newest) / 86400.0
        if age_days > XPROTECT_STALE_DAYS:
            findings.append(finding(
                "MEDIUM", "xprotect", "XProtect definitions are stale",
                "XProtect (v%s) last updated %.0f days ago (> %d). Apple ships "
                "updates roughly monthly; a long gap suggests a broken update "
                "path or MDM interference. Check Software Update."
                % (version or "?", age_days, XPROTECT_STALE_DAYS),
                "xprotect:stale:%s" % (version or "unknown")))
    return findings


# --------------------------------------------------------------------------- #
# Check 2d: shell HISTORY — ClickFix terminal-paste residue.
#
# ClickFix (dominant 2025 initial-access vector) tricks the user into pasting a
# command into Terminal. The payload is fetched by curl inside an already-trusted
# Terminal, so it never gets a quarantine xattr — but the pasted command leaves a
# durable line in shell history. We scan the recent tail for hostile idioms /
# ClickFix markers and alert once per unique offending command line.
# --------------------------------------------------------------------------- #


def check_shell_history():
    findings = []
    for path in SHELL_HISTORY_FILES:
        if not os.path.isfile(path):
            continue
        text = _read_text(path)
        if not text:
            continue
        lines = text.splitlines()[-SHELL_HISTORY_TAIL:]
        for raw in lines:
            # zsh EXTENDED_HISTORY prefixes ": <ts>:<dur>;cmd" — strip it.
            cmd = raw
            if cmd.startswith(":") and ";" in cmd:
                cmd = cmd.split(";", 1)[1]
            # Score with the SAME oracle as the live-process behavioral tier
            # (_argv_signals): a lone network fetch (`curl https://…`) is everyday
            # dev work and stays MEDIUM (logged, below the notify floor), while the
            # real ClickFix residue — `curl … | sh`, `dscl -authonly`, `xattr -c`,
            # `hdiutil -nobrowse`, a reverse shell — keeps its HIGH+. This unifies
            # history and process scoring and stops a benign curl from firing a HIGH
            # notification (README: "alert rarely").
            signals = _argv_signals(cmd)
            if not signals:
                continue
            top = max(signals, key=lambda s: SEV_ORDER[s[1]])[1]
            names = sorted(n for n, _ in signals)
            command_sha = hashlib.sha256(cmd.strip().encode()).hexdigest()
            findings.append(finding(
                top, "shell-history",
                "Hostile command in shell history",
                "%s triggered [%s]; command sha256=%s" %
                (os.path.basename(path), ", ".join(names), command_sha[:16]),
                "shellhist:%s:%s" % (
                    os.path.basename(path),
                    command_sha[:16]),
                path=path, markers=names, hostile=names,
                command_sha256=command_sha))
    return findings


# --------------------------------------------------------------------------- #
# Check 3: hot-directory freshly-dropped executables
# --------------------------------------------------------------------------- #


def _is_macho(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) in MACHO_MAGIC
    except Exception:
        return False


def gatekeeper_verdict(path):
    """Gatekeeper's own assessment (`spctl -a -t exec`) → (verdict, source).
    On an .app BUNDLE this is authoritative: 'accepted'/'Notarized Developer ID'
    vs 'rejected' (unnotarized, ad-hoc, unsigned). On a bare CLI Mach-O modern
    spctl rejects nearly everything ('valid but does not seem to be an app' —
    verified on-host, incl. /bin/ls), so it is only consulted for bundles.
    Honest note: the assessment is Apple's own machinery and may consult Apple's
    notarization service; Aegis itself still transmits nothing."""
    out, err, rc = run(["spctl", "-a", "-t", "exec", "-vv", path], timeout=12)
    text = (out or "") + (err or "")
    m = re.search(r"source=(.+)", text)
    return ("accepted" if rc == 0 else "rejected",
            m.group(1).strip() if m else None)


def _bundle_executable(app_path):
    """An .app bundle's main executable (Contents/MacOS/<CFBundleExecutable>),
    or None if the bundle is malformed or the executable is missing.
    CFBundleExecutable is attacker-authored plist data: a name containing a path
    separator ('/bin/sh', '../../x') would ESCAPE the bundle — os.path.join
    swallows everything before an absolute component — and make Aegis classify
    some other (clean, Apple) binary instead of the payload. A legit value is
    always a bare filename, so anything else is rejected."""
    try:
        with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
    except Exception:
        return None
    if not name or "/" in str(name):
        return None
    exe = os.path.join(app_path, "Contents", "MacOS", str(name))
    return exe if os.path.isfile(exe) else None


def _check_hot_app(path, st, cutoff):
    """Score a freshly-arrived .app bundle. The #1 macOS delivery vector
    (DMG/ZIP lure → drag the app out) lands an .app — a DIRECTORY, which the
    file-oriented Mach-O check below never sees. Unsigned/ad-hoc main executable
    → HIGH, same bar as a bare Mach-O. Signed-but-NOT-notarized → MEDIUM
    (logged, below the notify floor: self-built and legacy apps are common, but
    Gatekeeper would refuse a normal quarantined launch of one — so if it runs,
    it was side-loaded or force-approved). Notarized → silent (normal software).
    Freshness is the NEWEST of the bundle root and its main executable: swapping
    a payload into an old bundle's Contents/MacOS does not touch the .app root
    mtime, so root-only aging would be a trivial staleness evasion."""
    exe = _bundle_executable(path)
    if not exe:
        return []
    try:
        newest = max(st.st_mtime, os.stat(exe).st_mtime)
    except Exception:
        newest = st.st_mtime
    if newest < cutoff:
        return []
    sig = classify_signature(exe)
    when = datetime.fromtimestamp(newest).strftime("%Y-%m-%d")
    if suspicious_sig(sig["trust"]):
        sha = sha256(exe)
        # Same provenance grading as the bare-Mach-O path: a DMG-dragged .app is
        # the #1 delivery shape, so knowing WHERE it came from matters most here.
        quar, agent, origin, trusted_origin = download_provenance(path)
        prov = ("via %s" % agent if agent else
                ("quarantined" if quar else
                 "NO quarantine flag — side-loaded (bypassed Gatekeeper)"))
        if origin:
            prov += " from %s" % _origin_host(origin)
        return [finding(
            "HIGH", "hot-dir", "Unsigned app bundle in watched folder",
            "%s [%s], modified %s, %s" % (path, sig["trust"], when, prov),
            "hotdir:app:%s:%s:%s" % (path, sig["trust"], sha),
            path=path, trust=sig["trust"], sha256=sha,
            quarantined=quar, download_agent=agent,
            origin_url=origin, trusted_origin=trusted_origin,
            confidence=("low" if trusted_origin else "medium"))]
    if sig["trust"] in ("apple", "app-store"):
        return []
    verdict, source = gatekeeper_verdict(path)
    if verdict == "accepted":
        return []  # notarized — the normal shape of downloaded software
    sha = sha256(exe)
    return [finding(
        "MEDIUM", "hot-dir", "Un-notarized app in watched folder",
        "%s [%s] is signed but NOT notarized (Gatekeeper: %s%s), modified %s — "
        "a normal quarantined launch would be refused, so if it runs it was "
        "side-loaded or force-approved. Verify you built/trust it."
        % (path, sig["trust"], verdict,
           ", %s" % source if source else "", when),
        "hotdir:notary:%s:%s" % (path, sha),
        path=path, trust=sig["trust"], sha256=sha, gatekeeper=verdict)]


def check_hot_dirs(max_age_days=14):
    findings = []
    cutoff = time.time() - max_age_days * 86400
    for d in HOT_DIRS:
        try:
            entries = os.listdir(d)
        except Exception:
            continue
        for name in entries[:2000]:
            path = os.path.join(d, name)
            try:
                st = os.stat(path)
            except Exception:
                continue
            if name.endswith(".app") and os.path.isdir(path):
                # cutoff decided inside — bundle freshness is max(root, exe).
                findings.extend(_check_hot_app(path, st, cutoff))
                continue
            # Timestomp (T1070.006): a payload may backdate its mtime to age out
            # of the hot window. ctime/btime can't be moved from userland, so a
            # file whose mtime is old BUT whose ctime/btime is recent AND whose
            # timestamps are internally inconsistent is a backdated fresh drop —
            # do NOT let the mtime cutoff skip it.
            ts_reason = timestomp_signal(path, st)
            btime = getattr(st, "st_birthtime", None)
            backdated_fresh = (ts_reason is not None
                               and (st.st_ctime >= cutoff
                                    or (btime is not None and btime >= cutoff)))
            if st.st_mtime < cutoff and not backdated_fresh:
                continue
            if not os.path.isfile(path):
                continue
            if not _is_macho(path):
                continue
            sig = classify_signature(path)
            if suspicious_sig(sig["trust"]):
                sha = sha256(path)  # content hash → path reuse ≠ same fingerprint
                # Provenance enrichment (one xattr read): WHO downloaded it and
                # from WHERE, read from the user's own QuarantineEventsV2 /
                # Chrome downloads table (no FDA, no root). Turns "unsigned
                # binary appeared" into an attributable event — and grades it: a
                # drop from a trusted origin is demoted to digest, an
                # unattributed one stays loud.
                quar, agent, origin, trusted_origin = download_provenance(path)
                prov = ("via %s" % agent if agent else
                        ("quarantined" if quar else "NO quarantine flag — side-loaded (bypassed Gatekeeper)"))
                if origin:
                    prov += " from %s" % _origin_host(origin)
                ts_note = "; TIMESTOMP: %s" % ts_reason if ts_reason else ""
                # A trusted origin only LOWERS confidence (routing it to the
                # digest instead of a notification); it never lowers severity and
                # never closes the finding — provenance is an attacker-supplyable
                # hint, not an authority. A timestomped file is never demoted.
                demote = trusted_origin and not ts_reason
                findings.append(finding(
                    "HIGH", "hot-dir", "Unsigned executable in watched folder",
                    "%s [%s], modified %s, %s%s" % (
                        path, sig["trust"],
                        datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d"),
                        prov, ts_note),
                    "hotdir:%s:%s:%s" % (path, sig["trust"], sha),
                    path=path, trust=sig["trust"], sha256=sha,
                    quarantined=quar, download_agent=agent,
                    origin_url=origin, trusted_origin=trusted_origin,
                    confidence=("low" if demote else "medium"),
                    timestomp=ts_reason,
                    markers=(["timestomp"] if ts_reason else None)))
    return findings


# --------------------------------------------------------------------------- #
# Check 3b: /tmp loot-staging IOC filenames (smash-and-grab stealers).
#
# Persistence-free stealers stage loot in a temp dir then curl-exfil in under a
# minute — defeating both persistence-diffing and the Mach-O hot-dir check (the
# loot is a .zip, not an executable). These exact staging filenames are
# documented across the 2025 families; a match is a high-signal residue even if
# the sub-minute process was missed between poll ticks. Recent files only.
# --------------------------------------------------------------------------- #


def check_staging(max_age_days=3):
    findings = []
    cutoff = time.time() - max_age_days * 86400
    for d in STAGING_DIRS:
        try:
            entries = os.listdir(d)
        except Exception:
            continue
        for name in entries[:4000]:
            ioc = None
            for rx, label in STAGING_IOC_RES:
                if rx.search(name):
                    ioc = label
                    break
            if not ioc:
                continue
            path = os.path.join(d, name)
            try:
                st = os.stat(path)
            except Exception:
                continue
            if st.st_mtime < cutoff:
                continue
            findings.append(finding(
                "HIGH", "staging",
                "Stealer loot-staging artifact in temp dir",
                "%s (%s) — matches a documented 2025 macOS stealer staging "
                "pattern; a process may have staged loot here for exfiltration."
                % (path, ioc),
                "staging:%s:%s" % (path, int(st.st_mtime)),
                path=path, ioc=ioc))
    return findings


# --------------------------------------------------------------------------- #
# Check 3b2: developer-toolchain supply chain + known dropper dotfiles.
#
# In 2025-26 the developer's own machine became the target, and NONE of the other
# sensors observe package-manager activity:
#   * DPRK "Contagious Interview" shipped 300+ malicious npm packages whose
#     INSTALL-TIME lifecycle script (preinstall/postinstall) fetches and runs the
#     BeaverTail stealer, which then drops a Python InvisibleFerret backdoor.
#   * The Shai-Hulud worm compromised 700+ npm packages with a credential-
#     harvesting postinstall.
# Both leave a durable, unprivileged-readable artifact: the hostile lifecycle
# script sitting in an installed package's manifest, and a fixed set of hidden
# dropper files at $HOME root.
#
# FALSE-POSITIVE DISCIPLINE (the reason this is narrow): legitimate packages —
# esbuild, sharp, puppeteer, node-sass — routinely DOWNLOAD prebuilt binaries in
# postinstall. So a bare network fetch is deliberately NOT scored. Only an
# unambiguous exec/obfuscation idiom, or the fetch+exec COMBINATION, fires —
# exactly the rule the live-process argv scorer uses.
#
# SCOPE BOUNDARY: npm-family manifests only. A malicious pip package executes
# setup.py at install time and usually leaves no equivalent durable hook in the
# installed wheel, so there is no honest local artifact to diff — claiming pip
# coverage here would be theater.
# --------------------------------------------------------------------------- #

# The tree(s) this sensor reads. A module-level global (like STAGING_DIRS /
# HOT_DIRS) so tests can point it at a fixture instead of the live home.
SUPPLY_CHAIN_ROOTS = [HOME]

_PKG_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare",
                       "prepublish", "preprepare", "postprepare")
_PKG_MANIFEST_CAP = 4000     # hard cap on manifests inspected per scan
_PKG_DIR_CAP = 20000         # hard cap on directories visited per scan
_PKG_MAX_DEPTH = 8           # relative to $HOME
_PKG_MAX_AGE_DAYS = 30       # only recently-installed/changed manifests
_PKG_TIME_BUDGET = 20.0      # seconds; a scan runs hourly, never let it hang
_PKG_SKIP_DIRS = frozenset((
    "Library", "Applications", "Pictures", "Movies", "Music", "Public",
    ".Trash", ".git", ".hg", ".svn", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".cache", ".venv", "venv", ".rustup", ".cargo",
    "site-packages", ".gradle", ".m2", "Photos Library.photoslibrary",
))

# Idioms that are hostile in an INSTALL HOOK even standing alone (an installer
# never legitimately pipes a download into a shell or decodes a blob to run it).
_PKG_UNAMBIGUOUS = frozenset((
    "pipe-to-shell", "pipe-to-interpreter", "base64-decode", "eval-subshell",
    "bash-reverse-shell", "netcat-exec", "osascript-shell", "python-oneliner",
    "raw-ip-fetch", "launchctl-tmp", "applescript-url-scheme",
    "gui-kill-coercion", "osascript-password-phish", "keychain-dump",
))

# Hidden files at $HOME ROOT that are documented malware droppers/stashes. These
# are EXACT names in the home directory itself (not a subdir), where no ordinary
# tool puts a file — legitimate tooling lives in ~/.config, ~/.local, ~/.cargo.
_HOME_DROPPER_IOCS = {
    ".npc": "dprk-invisibleferret-dropper",
    ".myvars": "dprk-exfil-vars",
    ".pyp": "dprk-python-stage",
    ".mainhelper": "amos-backdoor-binary",
    ".agent": "amos-persistence-script",
    ".helper": "amos-stealer-payload",
    ".logged": "amos-campaign-id",
    ".sysinfo": "stealer-host-recon",
}


# The JS-native loader shape the shell-oriented idiom table cannot see: DPRK's
# "HexEval" packages run `node -e "eval(Buffer.from(<blob>,'base64')…)"`, decoding
# an embedded blob in-process — no `base64 -d`, no pipe, nothing for a shell
# regex to match. Split into an EXEC vector and a DECODE vector because either
# alone appears in ordinary build tooling; only the COMBINATION (decode a blob,
# then execute it) is the loader, and that is essentially never legitimate.
_PKG_JS_EXEC_RES = [
    (re.compile(r"\bnode\b[^\n]*\s-e\b", re.I), "node-inline-exec"),
    (re.compile(r"\beval\s*\(", re.I), "js-eval"),
    (re.compile(r"\bnew\s+Function\s*\(", re.I), "js-new-function"),
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]", re.I), "js-child-process"),
]
_PKG_JS_DECODE_RES = [
    (re.compile(r"Buffer\.from\s*\([^)]{0,80}?['\"](?:base64|hex)['\"]", re.I),
     "js-encoded-blob"),
    (re.compile(r"\batob\s*\(", re.I), "js-atob-decode"),
    (re.compile(r"\bfromCharCode\b", re.I), "js-charcode-obfuscation"),
]
# JS-native egress: the shell fetch idioms (curl/wget) never match an installer
# that pulls its second stage through node's own http/net modules — BeaverTail's
# actual shape. Paired with an exec vector below, this is the fetch-and-run hook.
_PKG_JS_NET_RES = [
    (re.compile(r"require\s*\(\s*['\"](?:https?|net|dgram)['\"]", re.I),
     "js-net-module"),
    (re.compile(r"\bfetch\s*\(\s*['\"]https?://", re.I), "js-fetch"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I), "raw-ip-url"),
]


def _pkg_hostile_script(script):
    """Hostile-idiom names in one lifecycle script, or [] if it is ordinary.
    Mirrors _argv_signals' rule: unambiguous idioms fire alone; a plain network
    fetch fires ONLY together with an exec idiom (else every prebuilt-binary
    installer would alert)."""
    script = script or ""
    idioms = set(_hostile_content(script))
    hits = idioms & _PKG_UNAMBIGUOUS
    if idioms & _FETCH_IDIOMS and idioms & _PIPE_EXEC_IDIOMS:
        hits = hits | {"fileless-fetch-exec"}
    js_exec = {n for rx, n in _PKG_JS_EXEC_RES if rx.search(script)}
    js_decode = {n for rx, n in _PKG_JS_DECODE_RES if rx.search(script)}
    js_net = {n for rx, n in _PKG_JS_NET_RES if rx.search(script)}
    if js_exec and js_decode:
        hits = hits | js_exec | js_decode | {"js-encoded-loader"}
    # An inline JS exec that ALSO reaches the network is the second-stage
    # fetcher shape (BeaverTail's installer), hostile without a decode step.
    elif js_exec and (js_net or idioms & _FETCH_IDIOMS):
        hits = hits | js_exec | js_net | {"js-network-loader"}
    return sorted(hits)


def _iter_package_manifests(cutoff):
    """Yield (manifest_path, mtime) for npm manifests changed since `cutoff`.
    Walks the user's own tree with pruning and hard caps. At a node_modules the
    INSTALLED packages' manifests are inspected one (or two, for @scoped) levels
    deep and then descent stops — that is exactly where a malicious dependency's
    postinstall lives, and it keeps a huge dependency tree from being walked."""
    started = time.time()
    dirs_seen = 0
    yielded = 0

    def fresh(path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return st.st_mtime if st.st_mtime >= cutoff else None

    for base_root in SUPPLY_CHAIN_ROOTS:
        for root, dirnames, filenames in os.walk(
                base_root, topdown=True, onerror=lambda e: None,
                followlinks=False):
            dirs_seen += 1
            if (dirs_seen > _PKG_DIR_CAP or yielded >= _PKG_MANIFEST_CAP
                    or time.time() - started > _PKG_TIME_BUDGET):
                return
            if os.path.basename(root) == "node_modules":
                for d in list(dirnames):
                    try:
                        bases = ([os.path.join(root, d, s) for s in os.listdir(
                            os.path.join(root, d))] if d.startswith("@") else
                            [os.path.join(root, d)])
                    except OSError:
                        continue
                    for pkg in bases[:500]:
                        mani = os.path.join(pkg, "package.json")
                        mtime = fresh(mani)
                        if mtime is not None:
                            yielded += 1
                            yield mani, mtime
                            if yielded >= _PKG_MANIFEST_CAP:
                                return
                dirnames[:] = []      # never descend INTO a dependency tree
                continue
            if root[len(base_root):].count(os.sep) >= _PKG_MAX_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames
                               if d not in _PKG_SKIP_DIRS
                               and (d == "node_modules" or not d.startswith("."))]
            if "package.json" in filenames:
                mani = os.path.join(root, "package.json")
                mtime = fresh(mani)
                if mtime is not None:
                    yielded += 1
                    yield mani, mtime


def check_supply_chain():
    findings = []
    # (a) Known dropper dotfiles sitting directly in $HOME.
    for base_root in SUPPLY_CHAIN_ROOTS:
        for name, family in _HOME_DROPPER_IOCS.items():
            path = os.path.join(base_root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if not os.path.isfile(path):
                continue
            findings.append(finding(
                "HIGH", "supply-chain",
                "Known malware dropper file in home directory",
                "%s matches the documented %s artifact — no legitimate tool "
                "places this file at the root of $HOME." % (path, family),
                "dropper:%s:%s" % (path, int(st.st_mtime)),
                path=path, ioc=family, markers=["dropper-dotfile"]))

    # (b) Hostile install-time lifecycle hooks in installed npm packages.
    cutoff = time.time() - _PKG_MAX_AGE_DAYS * 86400
    for mani, mtime in _iter_package_manifests(cutoff):
        try:
            with open(mani, "r", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        pkg_name = str(data.get("name") or os.path.basename(os.path.dirname(mani)))
        for key in _PKG_LIFECYCLE_KEYS:
            script = scripts.get(key)
            if not isinstance(script, str):
                continue
            hits = _pkg_hostile_script(script)
            if not hits:
                continue
            digest = hashlib.sha256(script.encode()).hexdigest()
            findings.append(finding(
                "HIGH", "supply-chain",
                "Malicious install hook in npm package",
                "%s: '%s' lifecycle script triggers [%s] — an install-time hook "
                "that fetches/decodes and executes code (Contagious Interview / "
                "Shai-Hulud shape). Manifest: %s" % (
                    pkg_name, key, ", ".join(hits), mani),
                "pkghook:%s:%s:%s" % (mani, key, digest[:16]),
                path=mani, package=pkg_name, lifecycle=key,
                script_sha256=digest, markers=hits))
    return findings


# --------------------------------------------------------------------------- #
# Check 3c: local web/phishing posture and hosts-file poisoning.
#
# `/etc/hosts` takes precedence over DNS, so it is both a useful entitlement-
# free blocking layer and a credential-phishing target. This sensor never
# downloads a list and never modifies the file: it verifies whether a substantial
# local denylist exists and flags non-blocking redirects of high-value identity /
# update domains. A missing denylist is INFO because DNS/NE filtering may exist
# outside this process's view; a hostile override is HIGH.
# --------------------------------------------------------------------------- #


def _hosts_block_address(address):
    address = (address or "").lower()
    return address in _HOSTS_BLOCK_ADDRESSES or address.startswith("127.")


def _sensitive_host(domain):
    return any(domain == root or domain.endswith("." + root)
               for root in _SENSITIVE_HOST_ROOTS)


def check_web_protection():
    try:
        with open(HOSTS_FILE, "r", errors="replace") as f:
            lines = f
            blocked = set()
            suspicious = set()
            findings = []
            for raw in lines:
                content = raw.split("#", 1)[0].strip()
                if not content:
                    continue
                fields = content.split()
                if len(fields) < 2:
                    continue
                address = fields[0].lower()
                for raw_domain in fields[1:]:
                    domain = raw_domain.strip().lower().rstrip(".")
                    if not domain or domain in ("localhost", "broadcasthost"):
                        continue
                    if _hosts_block_address(address):
                        blocked.add(domain)
                        continue
                    reason = None
                    if _sensitive_host(domain):
                        reason = "sensitive identity/update domain"
                    elif any(label.startswith("xn--")
                             for label in domain.split(".")):
                        reason = "punycode domain"
                    key = (address, domain, reason)
                    if reason and key not in suspicious:
                        suspicious.add(key)
                        findings.append(finding(
                            "HIGH", "web-protection",
                            "Suspicious hosts-file domain redirect",
                            "%s maps %s to %s instead of a blocking address — "
                            "%s overrides DNS locally and can redirect browser, "
                            "identity, or updater traffic. Verify or remove it."
                            % (HOSTS_FILE, domain, address, reason.capitalize()),
                            "web:hosts:redirect:%s:%s" % (domain, address),
                            path=HOSTS_FILE, domain=domain, address=address,
                            reason=reason))
    except (OSError, UnicodeError):
        return None

    if len(blocked) < HOSTS_BLOCKLIST_MIN_DOMAINS:
        findings.append(finding(
            "INFO", "web-protection",
            "No substantial local hosts-file blocklist detected",
            "%s blocks %d non-local domain%s (<%d). A DNS or Network "
            "Extension filter may still protect this Mac; Aegis cannot observe "
            "that from an unentitled local process."
            % (HOSTS_FILE, len(blocked), "" if len(blocked) == 1 else "s",
               HOSTS_BLOCKLIST_MIN_DOMAINS),
            "web:hosts:blocklist:below-threshold", path=HOSTS_FILE,
            blocked_domains=len(blocked),
            threshold=HOSTS_BLOCKLIST_MIN_DOMAINS))
    return findings


# --------------------------------------------------------------------------- #
# Check 4: hardening posture
# --------------------------------------------------------------------------- #


def check_hardening():
    findings = []

    def unknown(component, title, err):
        findings.append(finding(
            "MEDIUM", "coverage", "%s status is UNKNOWN" % title,
            "%s probe unavailable or unrecognized: %s" %
            (component, redact_sensitive(err or "empty output")),
            "hardening:%s:unknown" % component))

    out, err, rc = run(["csrutil", "status"])
    if rc != 0 or ("enabled" not in out.lower() and "disabled" not in out.lower()):
        unknown("sip", "System Integrity Protection", err or out)
    elif "disabled" in out.lower():
        findings.append(finding(
            "CRITICAL", "hardening", "System Integrity Protection is OFF",
            out.strip(), "hardening:sip:off"))

    out, err, rc = run(["spctl", "--status"])
    if rc != 0 or "assessments" not in out.lower():
        unknown("gatekeeper", "Gatekeeper", err or out)
    elif "disabled" in out.lower():
        findings.append(finding(
            "HIGH", "hardening", "Gatekeeper assessments disabled",
            out.strip(), "hardening:gatekeeper:off"))

    out, err, rc = run(["fdesetup", "status"])
    if rc != 0 or "filevault is" not in out.lower():
        unknown("filevault", "FileVault", err or out)
    elif "filevault is off" in out.lower():
        findings.append(finding(
            "MEDIUM", "hardening", "FileVault disk encryption is OFF",
            out.strip(), "hardening:filevault:off"))

    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    out, err, rc = run([fw, "--getglobalstate"])
    if rc != 0 or not out.strip():
        unknown("firewall", "Application Firewall", err or out)
    elif "state = 0" in out.lower() or "disabled" in out.lower():
        findings.append(finding(
            "MEDIUM", "hardening", "Application Firewall is OFF",
            out.strip(), "hardening:firewall:off"))
    out, err, rc = run([fw, "--getstealthmode"])
    if rc != 0 or not out.strip():
        unknown("stealth", "Firewall stealth mode", err or out)
    elif "off" in out.lower():
        findings.append(finding(
            "LOW", "hardening", "Firewall stealth mode is off",
            out.strip(), "hardening:stealth:off"))

    # Remote login (SSH) - loaded launchd label implies enabled.
    lout, lerr, lrc = run(["launchctl", "list"], timeout=8)
    if lrc != 0:
        unknown("ssh", "Remote Login", lerr or lout)
    elif "com.openssh.sshd" in lout:
        findings.append(finding(
            "MEDIUM", "hardening", "Remote Login (SSH) appears enabled",
            "com.openssh.sshd present in launchctl list",
            "hardening:ssh:on"))

    return findings


# --------------------------------------------------------------------------- #
# Extra baseline-diffed surfaces (shell rc, login hooks, config profiles, extra
# persistence files, browser extensions). Each is snapshotted to a small dict and
# diffed vs the baseline; the first time a surface is ever observed it is adopted
# SILENTLY (the KnockKnock "trust what's already installed" rule, applied
# per-surface so upgrading Aegis on an existing install is not an alert storm),
# then only NEW/CHANGED items alert. All are readable with no special privilege.
# --------------------------------------------------------------------------- #


def _read_text(path, limit=512 * 1024):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return None


def _diff_map(prior, cur, new_fn, changed_fn=None):
    """Generic snapshot diff: call new_fn(id, val) for keys absent from prior and
    changed_fn(id, val, old) for keys whose value changed. Callables return a
    finding (or None to skip). Never raises on a single bad entry."""
    findings = []
    prior = prior or {}
    for k, v in cur.items():
        try:
            if k not in prior:
                f = new_fn(k, v)
            elif changed_fn is not None and prior[k] != v:
                f = changed_fn(k, v, prior[k])
            else:
                f = None
            if f:
                findings.append(f)
        except Exception:
            continue
    return findings


# --- shell startup files (T1546.004) ------------------------------------------
def snapshot_shellrc():
    snap = {}
    for p in SHELL_RC_FILES:
        if not os.path.isfile(p):
            continue
        h = sha256(p)
        if h is None:
            continue
        snap[p] = {"sha256": h, "hostile": _hostile_content(_read_text(p) or "")}
    return snap


def diff_shellrc(prior, cur):
    def _mk(title, verb):
        def f(p, rec, *old):
            hs = rec.get("hostile") or []
            is_new = not old
            login_scoped = os.path.basename(p) in _LOGIN_SCOPED_RC
            sev = "HIGH" if (hs or (is_new and login_scoped)) else "MEDIUM"
            note = (" — hostile pattern(s): %s" % ", ".join(hs) if hs else
                    " — login-scoped rc newly created (runs on every shell)"
                    if (is_new and login_scoped) else "")
            tag = "new" if verb == "appeared" else "changed"
            return finding(sev, "shell-init", title, "%s %s%s" % (p, verb, note),
                           "shellrc:%s:%s:%s" % (tag, p, rec["sha256"]),
                           path=p, hostile=hs, sha256=rec["sha256"])
        return f
    return _diff_map(prior, cur, _mk("New shell startup file", "appeared"),
                     _mk("Shell startup file CHANGED", "changed"))


# --- legacy Login/Logout hooks ------------------------------------------------
def snapshot_loginhooks():
    snap = {}
    for key in ("LoginHook", "LogoutHook"):
        out, _, rc = run(["defaults", "read", "com.apple.loginwindow", key], timeout=6)
        if rc == 0 and out.strip():
            snap[key] = out.strip()
    return snap


def diff_loginhooks(prior, cur):
    def _mk(suffix):
        def f(k, v, *old):
            return finding("HIGH", "persistence", "%s %s" % (k, suffix),
                           "com.apple.loginwindow %s = %s (legacy login hook — "
                           "rare-legit, a classic persistence primitive)" % (k, v),
                           "loginhook:%s:%s:%s" % (
                               "changed" if old else "new", k,
                               hashlib.sha256(v.encode()).hexdigest()[:16]),
                           hook=k, program=v)
        return f
    return _diff_map(prior, cur, _mk("installed"), _mk("CHANGED"))


# --- configuration profiles ---------------------------------------------------
def snapshot_profiles():
    snap = {}
    out, _, rc = run(["profiles", "list"], timeout=12)
    if rc != 0:
        return snap
    for line in out.splitlines():
        m = re.search(r"profileIdentifier:\s*(\S+)", line)
        if m:
            snap[m.group(1)] = True
    return snap


def diff_profiles(prior, cur):
    def new_fn(ident, _v):
        return finding("HIGH", "config-profile",
                       "New configuration profile installed",
                       "profile %s installed — config profiles can add trusted "
                       "certs, proxies or MDM control (an adware/DPRK vector)"
                       % ident, "profile:%s" % ident, identifier=ident)
    return _diff_map(prior, cur, new_fn)


# --- extra persistence files (extended cron / periodic / StartupItems) --------
def snapshot_extra_persistence():
    snap = {}

    def add(p):
        if os.path.isfile(p):
            h = sha256(p)
            if h:
                snap[p] = h

    for p in EXTRA_PERSIST_FILES:
        add(p)
    # Walk a few levels deep, not one: /etc/periodic keeps its scripts under
    # daily/weekly/monthly/ and StartupItems keeps <Item>/<Item> two-deep, so a
    # flat listdir sees only the intermediate dirs and captures nothing. Bound
    # it (max depth + entry cap, followlinks=False) so a deep/looping tree can't
    # blow up — these surfaces are shallow.
    MAX_DEPTH = 3
    MAX_ENTRIES = 4000
    seen_entries = 0
    for root_d in EXTRA_PERSIST_DIRS:
        base_depth = root_d.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root_d, followlinks=False):
            if dirpath.rstrip("/").count("/") - base_depth >= MAX_DEPTH:
                dirnames[:] = []  # stop descending past the cap
            for name in sorted(filenames):
                add(os.path.join(dirpath, name))
                seen_entries += 1
                if seen_entries >= MAX_ENTRIES:
                    return snap
    return snap


def diff_extra_persistence(prior, cur):
    def _mk(title, verb):
        def f(p, h, *old):
            hs = _hostile_content(_read_text(p) or "")
            sev = "HIGH" if (hs or old) else "MEDIUM"
            extra = " — hostile: %s" % ", ".join(hs) if hs else ""
            tag = "changed" if old else "new"
            return finding(sev, "persistence", title, "%s %s%s" % (p, verb, extra),
                           "xpersist:%s:%s:%s" % (tag, p, h),
                           path=p, sha256=h, hostile=hs)
        return f
    return _diff_map(prior, cur, _mk("New system-persistence file", "appeared"),
                     _mk("System-persistence file CHANGED", "changed"))


# --- browser extensions -------------------------------------------------------
def _manifest_name(mf):
    try:
        with open(mf, "r", errors="replace") as f:
            name = json.load(f).get("name")
        if isinstance(name, str) and not name.startswith("__MSG_"):
            return name
    except Exception:
        pass
    return None


def _chromium_exts(root):
    out = {}
    try:
        profiles = os.listdir(root)
    except Exception:
        return out
    for prof in profiles:
        extdir = os.path.join(root, prof, "Extensions")
        try:
            ids = os.listdir(extdir)
        except Exception:
            continue
        for extid in ids:
            if extid.startswith(".") or extid == "Temp":
                continue
            name = extid
            try:
                for v in sorted(os.listdir(os.path.join(extdir, extid))):
                    nm = _manifest_name(os.path.join(extdir, extid, v, "manifest.json"))
                    if nm:
                        name = nm
                        break
            except Exception:
                pass
            out["%s/%s" % (prof, extid)] = name
    return out


def _firefox_exts(root):
    out = {}
    try:
        profs = os.listdir(root)
    except Exception:
        return out
    for prof in profs:
        try:
            for name in os.listdir(os.path.join(root, prof, "extensions")):
                if not name.startswith("."):
                    out["%s/%s" % (prof, name)] = name
        except Exception:
            continue
    return out


def snapshot_browserext():
    snap = {}
    for root, kind in BROWSER_EXT_ROOTS:
        if not os.path.isdir(root):
            continue
        exts = _chromium_exts(root) if kind == "chromium" else _firefox_exts(root)
        bname = os.path.basename(root)
        for k, v in exts.items():
            snap["%s:%s" % (bname, k)] = v
    return snap


def diff_browserext(prior, cur):
    def new_fn(k, name):
        return finding("MEDIUM", "browser-ext", "New browser extension",
                       "%s (%s) — verify you installed this; malicious "
                       "extensions exfiltrate sessions, cookies and wallet data"
                       % (k, name), "browserext:%s" % k, ext=k, name=name)
    return _diff_map(prior, cur, new_fn)


# --- IDE / editor extensions --------------------------------------------------
def snapshot_ide_ext():
    snap = {}
    for root in IDE_EXT_ROOTS:
        editor = os.path.basename(os.path.dirname(root))  # ".vscode", ".cursor"…
        try:
            entries = os.listdir(root)
        except Exception:
            continue
        for name in entries:
            if name.startswith(".") or name == "extensions.json":
                continue
            p = os.path.join(root, name)
            if not os.path.isdir(p):
                continue
            disp = _manifest_name(os.path.join(p, "package.json")) or name
            snap["%s:%s" % (editor, name)] = disp
    return snap


def diff_ide_ext(prior, cur):
    def new_fn(k, name):
        return finding("MEDIUM", "ide-ext", "New editor extension",
                       "%s (%s) — a backdoored VSCode/Cursor extension is a live "
                       "supply-chain vector; confirm you installed it"
                       % (k, name), "ideext:%s" % k, ext=k, name=name)
    return _diff_map(prior, cur, new_fn)


# --- crypto-wallet integrity --------------------------------------------------
# 2025 stealers tamper with installed wallet apps to hijack funds (DigitStealer
# rewrites Ledger Live's app.json; Odyssey swaps wallet bundles for drainers). We
# baseline-hash the wallet config files + app main executables that EXIST; a
# CHANGE is HIGH — wallet apps update rarely and the blast radius is a drained
# wallet. Only present files are snapshotted, so a machine without wallets is quiet.
def snapshot_wallet():
    snap = {}
    for p in WALLET_CONFIG_FILES + WALLET_APP_BINS:
        if os.path.isfile(p):
            h = sha256(p)
            if h:
                snap[p] = h
    return snap


def diff_wallet(prior, cur):
    def _mk(title, verb):
        def f(p, h, *old):
            kind = "config" if p.endswith(".json") else "application binary"
            return finding("HIGH", "wallet-integrity", title,
                           "%s (%s) %s — crypto-wallet apps are a wallet-drainer "
                           "target; verify this was a legitimate update, not a "
                           "malicious swap." % (p, kind, verb),
                           "wallet:%s:%s:%s" % ("changed" if old else "new", p, h),
                           path=p, sha256=h)
        return f
    return _diff_map(prior, cur, _mk("New wallet file", "appeared"),
                     _mk("Wallet file CHANGED", "changed"))


# --- Background Task Management (Login Items + SMAppService agents) ------------
# `sfltool dumpbtm` (Ventura+, unprivileged) is macOS's OWN authoritative record
# of every background item — login items and ServiceManagement-registered agents/
# daemons. It catches what the LaunchAgents-directory scan CANNOT: an
# SMAppService item registered via the API that never drops a plist in
# ~/Library/LaunchAgents (the modern persistence path — e.g. how legit apps and
# some 2024+ malware register). Baseline-diffed with silent first-sight adoption;
# a NEW item with no Team ID whose URL is in a user-writable path → HIGH, else
# MEDIUM (login items are usually legit; overlap with the launchd check is kept
# below the notify floor so a plist-backed item is not double-alerted at HIGH).
# The command is a module constant so tests can point it at a fixture/echo
# instead of the real (slow) sfltool — the same override pattern as LSOF_LISTEN_CMD.
BTM_DUMP_CMD = ["sfltool", "dumpbtm"]


def _parse_btm(text):
    """{identifier: {name, team, type, url}} from `sfltool dumpbtm`. A top-level
    item header is a line that is exactly '#<n>:' (embedded sub-refs read
    '#1: <id>' — content after the colon — so they don't match and can't be
    mistaken for items)."""
    items = {}
    cur = None

    def _flush(c):
        # Materialize an item ONCE it is fully read (next header or EOF), so
        # fields printed AFTER `Identifier:` (real sfltool prints URL last) land
        # in the stored record. An item is stored only if an `Identifier:` line
        # was seen (its value may be empty → fall back to the UUID).
        if not c or "_ident" not in c:
            return
        ident = c["_ident"] or c.get("_uuid")
        if not ident:
            return
        rec = {k: v for k, v in c.items() if not k.startswith("_")}
        # Stable shape so downstream always finds these keys.
        for f in ("name", "team", "type", "url"):
            rec.setdefault(f, None)
        items[ident] = rec

    for raw in (text or "").splitlines():
        s = raw.strip()
        if re.fullmatch(r"#\d+:", s):
            _flush(cur)
            cur = {}
            continue
        if cur is None or ": " not in s:
            continue
        key, val = s.split(": ", 1)
        key, val = key.strip(), val.strip()
        if key == "Identifier":
            cur["_ident"] = val or None
        elif key == "UUID":
            cur["_uuid"] = val
        elif key == "Name":
            cur["name"] = val
        elif key == "Team Identifier":
            cur["team"] = None if val in ("(null)", "") else val
        elif key == "Type":
            cur["type"] = val
        elif key in ("URL", "Executable Path"):
            cur.setdefault("url", val if val != "(null)" else None)
    _flush(cur)
    return items


def snapshot_btm():
    """{identifier: rec} of Background Task Management items, or None if sfltool
    could not be read this scan. Some macOS builds require interactive admin
    authorization; a launchd observer cannot and must not synthesize that grant.
    `sfltool dumpbtm` is also slow and can exceed the timeout; aegis.run() then
    returns empty. An empty result from a timeout/failure must NOT be
    recorded as 'no background items' — a Mac always has some (DisplayLink,
    auto-updaters …), so a false-empty adopted into the baseline would storm
    ~90 bogus 'new background item' findings the instant sfltool later succeeds.
    We therefore signal the non-answer as None (skipped by _scan_surfaces) so
    sensor health remains DEGRADED instead of silently baselining false-empty."""
    out, _, rc = run(BTM_DUMP_CMD, timeout=30)
    if rc != 0 or not out:
        return None  # timeout/failure — a non-answer, NOT "zero items"
    return _parse_btm(out)


def _btm_path_from_url(url):
    """A filesystem path from a BTM URL field (file:///… percent-encoded) for
    location scoring; None if it isn't a local file URL."""
    if not url or not url.startswith("file://"):
        return None
    from urllib.parse import unquote, urlparse
    return unquote(urlparse(url).path) or None


def diff_btm(prior, cur):
    def new_fn(ident, rec):
        url = rec.get("url")
        path = _btm_path_from_url(url)
        no_team = not rec.get("team")
        risky = bool(path and is_risky_location(path))
        sev = "HIGH" if (no_team and risky) else "MEDIUM"
        return finding(
            sev, "btm", "New background item (Login Item / SMAppService)",
            "%s [%s] registered as a background item%s%s — verify you installed "
            "it; SMAppService items persist WITHOUT a LaunchAgents plist."
            % (rec.get("name") or ident, rec.get("type") or "?",
               " team=%s" % rec["team"] if rec.get("team") else " (no Team ID)",
               " at %s" % path if path else ""),
            "btm:%s" % ident, identifier=ident, name=rec.get("name"),
            team=rec.get("team"), url=url, path=path)

    def changed_fn(ident, rec, old):
        # An in-place SMAppService hijack: the SAME identifier now backs a
        # different record (target swapped, Team ID stripped). Severity mirrors
        # new_fn — HIGH when the new target has no Team ID AND resolves to a
        # risky location, else MEDIUM.
        url = rec.get("url")
        path = _btm_path_from_url(url)
        no_team = not rec.get("team")
        risky = bool(path and is_risky_location(path))
        sev = "HIGH" if (no_team and risky) else "MEDIUM"
        return finding(
            sev, "btm", "Background item CHANGED (Login Item / SMAppService)",
            "%s [%s] background item was modified in place%s%s — its backing "
            "record changed (possible SMAppService hijack; persists WITHOUT a "
            "LaunchAgents plist)."
            % (rec.get("name") or ident, rec.get("type") or "?",
               " team=%s" % rec["team"] if rec.get("team") else " (no Team ID)",
               " now at %s" % path if path else ""),
            "btm:changed:%s:%s" % (ident, url or "?"),
            identifier=ident, name=rec.get("name"),
            team=rec.get("team"), url=url, path=path)

    return _diff_map(prior, cur, new_fn, changed_fn)


# --- network listeners ---------------------------------------------------------
# See the LSOF_LISTEN_CMD block up top for the design rationale (non-loopback
# only; platform daemons skipped unless interpreter-fronted; baseline-diffed).
def _listener_worth_tracking(path):
    """False for Apple platform daemons: SIP-pinned paths malware can never
    occupy, and they bind ephemeral wildcard ports every boot (churn, not
    signal). Kept anyway when the binary is an interpreter or net-utility —
    `/usr/bin/python3` serving 0.0.0.0 or `nc -l` is a classic payload shape."""
    if not path or not path.startswith("/"):
        return True  # unresolvable → keep; we cannot prove it is platform
    if any(path.startswith(p) for p in TRUSTED_PREFIXES):
        base = os.path.basename(path)
        return base in _ARGV_WATCH_BINS or base in _LISTENER_NET_UTILS
    return True


def _parse_lsof_listeners(text):
    """{pid: set(addr)} of NON-loopback TCP listen sockets from `lsof -Fpn`
    machine output (p<pid> / n<addr> field lines). IPv6 brackets handled;
    127.0.0.1 / ::1 / localhost binds dropped — unreachable from outside."""
    out = {}
    pid = None
    for line in (text or "").splitlines():
        if len(line) < 2:
            continue
        tag, val = line[0], line[1:].strip()
        if tag == "p":
            pid = val
        elif tag == "n" and pid is not None and ":" in val:
            host = val.rsplit(":", 1)[0].strip("[]")
            if host in ("127.0.0.1", "::1", "localhost"):
                continue
            out.setdefault(pid, set()).add(val)
    return out


def snapshot_listeners():
    """{'<exec-path>:<port>': exec-path} for every tracked non-loopback TCP
    listener. Keyed on path+port (not pid) so a routine process restart is not
    a 'new listener'; the same server on a new port — or a new binary on the
    same port — is."""
    # lsof exits non-zero when it hit ANY warning (unstattable fuse mount, a
    # vanished fd) while still emitting perfectly good records — so trust the
    # OUTPUT, not the exit code for WARNINGS. But a HARD failure (timeout=124,
    # binary-missing=127) is a non-answer, not "zero listeners": returning {}
    # there would adopt a false-empty baseline and later storm on the real
    # listeners. Signal those as None (skipped); genuine "ran fine, nothing
    # listening" stays {} (a common, legitimate state — unlike BTM).
    out, _, rc = run(LSOF_LISTEN_CMD, timeout=20)
    if rc in (124, 127):
        return None
    if not out:
        return {}
    snap = {}
    for pid, addrs in _parse_lsof_listeners(out).items():
        pout, _, prc = run(["ps", "-o", "comm=", "-p", pid], timeout=8)
        path = pout.strip() if prc == 0 and pout.strip() else None
        if not _listener_worth_tracking(path):
            continue
        for port in sorted({a.rsplit(":", 1)[1] for a in addrs}):
            snap["%s:%s" % (path or "?", port)] = path or "?"
    return snap


def diff_listeners(prior, cur):
    def new_fn(key, path):
        port = key.rsplit(":", 1)[1]
        trust = (classify_signature(path)["trust"]
                 if path.startswith("/") else "unknown")
        hostile = suspicious_sig(trust) and is_risky_location(path)
        return finding(
            "HIGH" if hostile else "MEDIUM",
            "net-listener", "New network listener",
            "%s is accepting connections on TCP port %s [%s]%s"
            % (path, port, trust,
               " — an unsigned/ad-hoc binary in a user-writable path listening "
               "on the network is a bind-shell / rogue-server shape" if hostile
               else " — reachable from the network; verify you started this"),
            "listener:%s" % key, path=path, port=port, trust=trust)
    return _diff_map(prior, cur, new_fn)


# --- Outbound connections (exfil-in-flight) ----------------------------------
# The attribution token `<proc>:<pid>` sits after the state + numeric byte
# columns, right before the 4–8-hex flags column. proc may contain spaces and is
# truncated ('Google Chrome He'), so we anchor on the segment AFTER 'ESTABLISHED'
# and take the first letter-led run before ':<pid>' (a numeric address never
# starts with a letter, so this can't grab a column).
_NETSTAT_PROC_RE = re.compile(r"([A-Za-z][\w .()\-/]*?):(\d+)\s+[0-9a-f]{4,}\b")


def _parse_netstat_established(text):
    """[(proc, pid, remote_ip, remote_port)] for ESTABLISHED **outbound** TCP from
    `netstat -anv`. The remote address is the 5th field in dotted IP.port form.
    Loopback remotes are dropped (not egress). Never raises on a malformed row."""
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("tcp"):
            continue
        if "ESTABLISHED" not in parts:
            continue
        remote = parts[4]
        rip, _, rport = remote.rpartition(".")
        if not rip or not rport.isdigit():
            continue
        if rip.startswith(("127.", "::1", "::ffff:127.", "fe80:")) \
                or rip in ("localhost", "*"):
            continue
        rhs = line.split("ESTABLISHED", 1)[1]
        m = _NETSTAT_PROC_RE.search(rhs)
        proc = m.group(1).strip() if m else "?"
        pid = m.group(2) if m else None
        rows.append((proc, pid, rip, rport))
    return rows


def _outbound_finding(path, rip, rport):
    """Score one outbound connection. A finding only for an unsigned/ad-hoc/broken
    binary in a user-writable path (the rogue-payload-phoning-home shape); None
    for a signed or system-path process (a browser/updater talking out is normal).
    MEDIUM/medium-confidence: logged + fed to correlation, below the notify floor
    (ad-hoc dev binaries talk to the network routinely — must not page alone)."""
    if not (path and path.startswith("/")):
        return None
    trust = classify_signature(path)["trust"]
    if not (suspicious_sig(trust) and is_risky_location(path)):
        return None
    return finding(
        "MEDIUM", "net-outbound", "Unsigned binary connected outbound",
        "%s [%s] in a user-writable path is connected to %s:%s — an "
        "ad-hoc/unsigned binary holding an outbound socket is a payload-"
        "phoning-home / exfil shape. Recorded for correlation."
        % (path, trust, rip, rport),
        "outbound:%s:%s:%s" % (path, rip, rport), path=path, program=path,
        remote=rip, port=rport, trust=trust, confidence="medium",
        markers=["outbound-exfil"])


def check_outbound():
    """Record the exfil shape the listener surface is structurally blind to: an
    unsigned/ad-hoc/broken binary in a user-writable path holding an ESTABLISHED
    outbound connection. We can't baseline-diff outbound (a browser opens
    hundreds) and `netstat -n` shows only numeric peers, so this scores live via
    _outbound_finding. Best-effort: a netstat non-answer yields no findings."""
    out, _, rc = run(NETSTAT_CMD, timeout=15)
    if rc in (124, 127) or not out:
        return []
    findings = []
    seen = set()
    for _proc, pid, rip, rport in _parse_netstat_established(out):
        path = None
        if pid:
            pout, _, prc = run(["ps", "-o", "comm=", "-p", pid], timeout=6)
            if prc == 0 and pout.strip():
                path = pout.strip()
        if not (path and path.startswith("/")):
            continue
        key = "%s:%s:%s" % (path, rip, rport)
        if key in seen:
            continue
        seen.add(key)
        f = _outbound_finding(path, rip, rport)
        if f:
            findings.append(f)
    return findings


# --- Unified-log security harvest (Gatekeeper / syspolicy denials) ------------
_SYSPOLICY_DENY_RE = re.compile(
    r"\b(?:denied|blocked|rejected|will not be permitted|gke.*deny)\b", re.I)


def _parse_syspolicy_denials(ndjson_text):
    """[(message, timestamp)] of Gatekeeper/syspolicy DENIAL events from
    `log show --style ndjson` output. A denial means something tried to run and
    was blocked — high-signal, low-volume. Pure/fixture-testable; tolerant of
    non-object records and non-JSON lines (never raises)."""
    hits = []
    for line in (ndjson_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        msg = ev.get("eventMessage") or ""
        if not isinstance(msg, str) or not _SYSPOLICY_DENY_RE.search(msg):
            continue
        hits.append((msg.strip(), ev.get("timestamp") or ""))
    return hits


def check_security_log(window_hours=None):
    """Harvest Gatekeeper/syspolicy DENIAL events from the unified log the same
    unprivileged `log show` way check_xprotect does — a new security domain for
    ~free. Kept at MEDIUM/low-confidence (log+correlation tier, below the notify
    floor): the live message format varies by OS build and can't be verified
    against a real denial in the field here, so it enriches without risking a
    noisy page. On any log-read failure it degrades to empty (never a storm)."""
    if window_hours is None:
        window_hours = 6
    win = "%dh" % max(1, min(int(window_hours), 48))
    out, _, rc = run(["log", "show", "--last", win, "--style", "ndjson",
                      "--predicate", 'subsystem == "com.apple.syspolicy"'],
                     timeout=45)
    if rc != 0 or not out:
        return []
    findings = []
    for msg, ts in _parse_syspolicy_denials(out):
        digest = hashlib.sha256(msg.encode("utf-8", "replace")).hexdigest()[:16]
        findings.append(finding(
            "MEDIUM", "gatekeeper", "Gatekeeper/syspolicy blocked a launch",
            "syspolicy denied/blocked an item at %s: %s — something the OS did "
            "not trust tried to run; verify it was expected." % (ts, msg[:240]),
            "gatekeeper:deny:%s" % digest, confidence="low",
            markers=["gatekeeper-deny"]))
    return findings


# --- Auth sessions (remote login / screen sharing) ---------------------------
def _parse_who_remote(text):
    """{user@host:tty: host} for REMOTE sessions only — a parenthesized origin at
    the end of a `who` line marks ssh / screen-sharing. Local console/ttys carry
    no host and are ignored (they churn on every terminal window)."""
    out = {}
    for line in (text or "").splitlines():
        m = re.search(r"\(([^)]+)\)\s*$", line)
        if not m:
            continue
        host = m.group(1).strip()
        # Drop loopback-equivalent origins in BOTH symbolic and numeric form:
        # macOS `who` records a loopback ssh peer (ssh localhost, VS Code
        # Remote-SSH to localhost, git-over-ssh loopback — routine for devs) as
        # the numeric 127.0.0.1 / ::1, which sshd does not reverse-resolve. Left
        # in, those fire a HIGH page on this surface's only auto-paging path.
        if not host or host in ("localhost", "127.0.0.1", "::1",
                                "::ffff:127.0.0.1", ":0", ":0.0"):
            continue
        parts = line.split()
        user = parts[0] if parts else "?"
        tty = parts[1] if len(parts) > 1 else "?"
        out["%s@%s:%s" % (user, host, tty)] = host
    return out


def snapshot_auth_sessions():
    """{session_key: origin_host} of active REMOTE login sessions, or None if
    `who` could not be read (a non-answer, not 'no sessions' — never adopt/diff a
    false-empty)."""
    out, _, rc = run(WHO_CMD, timeout=8)
    if rc in (124, 127):
        return None
    return _parse_who_remote(out)


def diff_auth_sessions(prior, cur):
    def new_fn(key, host):
        return finding(
            "HIGH", "auth-session", "New remote login session",
            "%s — a remote (ssh / screen-sharing) session appeared from %s. A "
            "personal Mac rarely has an active remote login; verify this is you "
            "(and that Remote Login / Screen Sharing being on is intended)."
            % (key, host), "auth-session:%s" % key, session=key, origin=host,
            confidence="medium", markers=["remote-access"])
    return _diff_map(prior, cur, new_fn)


# --- AI-agent skill directories (2026 AMOS supply-chain channel) --------------
_SKILL_SCRIPT_EXT = (".sh", ".py", ".js", ".mjs", ".rb", ".pl", ".command",
                     ".scpt", ".applescript", ".osascript", ".zsh", ".bash")


def _skill_signature(skill_dir):
    """A stable content signature for an agent-skill dir: the hash of its
    instruction file (SKILL.md — what an OpenClaw/Claude-skill attack weaponizes
    to drive a fake password dialog) plus a CONTENT hash of every executable /
    script payload it ships alongside. Payloads are hashed by BODY, not name: the
    most direct supply-chain hijack swaps a shipped script's contents under the
    same filename (F4-class), which a names-only signature could never see. Cheap;
    None-safe."""
    parts = []
    for cand in ("SKILL.md", "skill.md", "manifest.json", "plugin.json",
                 "AGENTS.md"):
        p = os.path.join(skill_dir, cand)
        if os.path.isfile(p):
            h = sha256(p)
            if h:
                parts.append("%s=%s" % (cand, h))
    execs = []
    try:
        for name in sorted(os.listdir(skill_dir)):
            fp = os.path.join(skill_dir, name)
            if os.path.isfile(fp) and (
                    os.access(fp, os.X_OK) or name.endswith(_SKILL_SCRIPT_EXT)):
                h = sha256(fp)
                execs.append("%s@%s" % (name, h[:16]) if h else name)
    except Exception:
        pass
    if execs:
        parts.append("exec=" + ",".join(execs))
    return "|".join(parts) or "empty"


def snapshot_agent_skills():
    """{root/skill: signature} for every installed AI-agent skill. Resolves
    symlinked roots (the canonical skills tree is often a symlink into a projects
    folder)."""
    snap = {}
    for root in AGENT_SKILL_ROOTS:
        try:
            names = sorted(os.listdir(root))
        except Exception:
            continue
        label = os.path.basename(root.rstrip("/")) or root
        for name in names:
            if name.startswith("."):
                continue
            d = os.path.join(root, name)
            if not os.path.isdir(d):
                continue
            snap["%s/%s" % (label, name)] = _skill_signature(d)
    return snap


def diff_agent_skills(prior, cur):
    # Both tiers stay BELOW the notify floor (MEDIUM): the owner authors skills,
    # so changes are routine — we want a durable RECORD, not an interrupt.
    # 'changed' is low-confidence because a skills author edits constantly; 'new'
    # is medium (a skill you did not add). NOTE: these findings carry only
    # skill=key (no path/program entity), so they do not currently feed
    # _accumulate_risk, and 'agent-skill' is in no correlate() rule — the
    # durable record is real, but the "auto-correlates with a later osascript
    # phish" chain is not yet wired. The phish itself still fires CRITICAL alone.
    def new_fn(key, sig):
        return finding(
            "MEDIUM", "agent-skill", "New AI-agent skill installed",
            "%s appeared — AI-agent skills run with your full privileges and are "
            "a live 2026 stealer channel (a malicious SKILL.md can drive a fake "
            "password dialog). Verify you installed it." % key,
            "agent-skill:new:%s" % key, skill=key, confidence="medium",
            markers=["agent-skill"])

    def changed_fn(key, sig, old):
        return finding(
            "MEDIUM", "agent-skill", "AI-agent skill changed",
            "%s was modified — its SKILL.md or a shipped script changed. Routine "
            "when you author skills; a change you did not make is a supply-chain "
            "hijack." % key,
            "agent-skill:changed:%s:%s"
            % (key, hashlib.sha256(sig.encode()).hexdigest()[:12]),
            skill=key, confidence="low", markers=["agent-skill"])

    return _diff_map(prior, cur, new_fn, changed_fn)


# --- Timestomp detection (T1070.006) -----------------------------------------
def timestomp_signal(path, st=None):
    """A reason string if a file's timestamps look tampered, else None. `touch`/
    `SetFile` move mtime/atime but CANNOT move ctime (inode-change time) or btime
    (birth time) from unprivileged userland — so an mtime that predates ctime by
    a wide margin, or an mtime far older than btime, is a strong backdating
    signal (a dropped payload made to look old to age out of a hot-dir window).
    Pass an existing os.stat result to avoid a redundant stat in a scan loop."""
    if st is None:
        try:
            st = os.stat(path)
        except Exception:
            return None
    mtime = st.st_mtime
    ctime = st.st_ctime
    btime = getattr(st, "st_birthtime", None)
    # mtime well BEFORE ctime: the content was 'last modified' before the inode
    # itself changed — impossible without backdating. 1h slop absorbs normal skew.
    if mtime < ctime - 3600:
        return ("mtime (%s) predates ctime (%s) by >1h — backdated timestamp"
                % (_fmt_epoch(mtime), _fmt_epoch(ctime)))
    if btime and mtime < btime - 3600:
        return ("mtime (%s) predates the file's birth time (%s) — backdated"
                % (_fmt_epoch(mtime), _fmt_epoch(btime)))
    return None


def _fmt_epoch(e):
    try:
        return datetime.fromtimestamp(e, timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    except Exception:
        return str(int(e))


# --- Survivability: HMAC-watermarked tamper-evidence -------------------------
def _hmac_key():
    """Load (or lazily create, 0600) the HMAC key that watermarks trust-store
    state. Kept in its OWN file, not beside the data: an attacker who edits
    baseline.json and recomputes a plain sha256 (what most tooling does) still
    can't forge the MAC without also reading the key — a second, observable step.
    (A same-uid attacker who DOES read the key can still forge; no unprivileged
    tool can close that. This raises the bar from trivial to deliberate.)"""
    try:
        with open(HMAC_KEY_FILE, "rb") as f:
            k = f.read()
        if len(k) >= 16:
            return k
    except Exception:
        pass
    k = os.urandom(32)
    try:
        fd = os.open(HMAC_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k)
    except FileExistsError:
        try:
            with open(HMAC_KEY_FILE, "rb") as f:
                return f.read()
        except Exception:
            return k
    except Exception:
        pass
    return k


def _hmac_file(path):
    """HMAC-SHA256 of a file's bytes under the local key, or None if unreadable."""
    try:
        h = hmac.new(_hmac_key(), digestmod=hashlib.sha256)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# --- Survivability: dead-man's-switch heartbeat ------------------------------
def _aegis_config():
    return load_json(AEGIS_CONFIG, {})


def _heartbeat_url():
    u = os.environ.get(HEARTBEAT_URL_ENV, "").strip()
    if u:
        return u
    u = _aegis_config().get("heartbeat_url")
    return u.strip() if isinstance(u, str) and u.strip() else None


def read_heartbeat():
    return load_json(HEARTBEAT_FILE, {})


def _post_heartbeat(url, beat):
    """Best-effort OUT-OF-BAND beat POST. Lazy-imports urllib so the default
    (no URL) scan path never even loads networking — the same local-only-by-
    construction guarantee as `vt`. Redacts before sending. Never raises."""
    try:
        import urllib.request
        body = redact_sensitive(json.dumps(beat, sort_keys=True)).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "aegis"})
        with urllib.request.urlopen(req, timeout=8):
            pass
        return True
    except Exception as e:
        log_run("heartbeat post failed: %s" % e)
        return False


def write_heartbeat(status="ok", alerts=0, top_alert=None):
    """Record a liveness beat on every healthy scan (ALWAYS — no network). An
    external watcher, a peer launchd agent, or `aegis.py watchdog` treats a STALE
    beat as the alarm: absence of the beat is the one signal a same-uid attacker
    who SIGKILLs or boots-out Aegis cannot suppress off-box. If (and ONLY if) an
    off-host URL is configured, ALSO POST the beat + top alert out-of-band so
    'silence' leaves the box the same run every LOCAL sink is being suppressed.
    Off by default → the scan/watch path stays local-only."""
    beat = {"ts": now_iso(), "epoch": int(time.time()), "pid": os.getpid(),
            "status": status, "alerts": int(alerts),
            "top_alert": redact_sensitive((top_alert or ""))[:200]}
    try:
        save_json(HEARTBEAT_FILE, beat)
    except Exception:
        pass
    url = _heartbeat_url()
    if url:
        _post_heartbeat(url, beat)
    return beat


# --- Opt-in privileged tier: XProtect Behavioral (Bastion) DB ----------------
def _parse_xpdb(db_path):
    """Return [(rule, process, item, ts)] of XProtect Behavioral Service (Bastion)
    violations from the root-only XPdb SQLite store. Apple RECORDS stealer-shape
    behavior here (a process touching browser data / Messages / keychain) but
    never alerts on it — so surfacing rows is free high-signal coverage. Read
    defensively across schema variants; never raises."""
    rows = []
    try:
        con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=8)
    except Exception:
        return rows
    try:
        con.row_factory = sqlite3.Row
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        target = next((t for t in tables
                       if "violation" in t.lower() or "event" in t.lower()
                       or "bastion" in t.lower()), tables[0] if tables else None)
        if not target:
            return rows
        for r in con.execute("SELECT * FROM \"%s\" LIMIT 2000" % target).fetchall():
            d = {k: r[k] for k in r.keys()}
            rule = str(d.get("rule") or d.get("rule_id") or d.get("policy") or "?")
            proc = str(d.get("process") or d.get("responsible") or
                       d.get("path") or d.get("initiating_process") or "?")
            item = str(d.get("target") or d.get("resource") or
                       d.get("file") or "")
            ts = str(d.get("timestamp") or d.get("time") or d.get("date") or "")
            rows.append((rule, proc, item, ts))
    except Exception:
        pass
    finally:
        con.close()
    return rows


# Registry: (baseline-key, snapshot-fn, diff-fn). Order = report order within tier.
SURFACES = [
    ("shellrc", snapshot_shellrc, diff_shellrc),
    ("loginhooks", snapshot_loginhooks, diff_loginhooks),
    ("profiles", snapshot_profiles, diff_profiles),
    ("extra_persist", snapshot_extra_persistence, diff_extra_persistence),
    ("browserext", snapshot_browserext, diff_browserext),
    ("ide_ext", snapshot_ide_ext, diff_ide_ext),
    ("wallet", snapshot_wallet, diff_wallet),
    ("listeners", snapshot_listeners, diff_listeners),
    ("btm", snapshot_btm, diff_btm),
    ("auth_sessions", snapshot_auth_sessions, diff_auth_sessions),
    ("agent_skills", snapshot_agent_skills, diff_agent_skills),
]

# Surfaces whose first-sight items are LIVE risks, not installed-residue: they
# must NOT be silently adopted on the very first scan (see _scan_surfaces). An
# active remote login present at install/upgrade time is a current-access threat
# the README's live-vs-residue rule says the user must hear about immediately.
_NEVER_ADOPT_LIVE = {"auth_sessions"}


# --------------------------------------------------------------------------- #
# Check 5: self-protection (a monitor an attacker can silently disable or blind
# is theater). Two low-false-positive tamper signals, no privilege required.
# --------------------------------------------------------------------------- #


def check_self_protection():
    findings = []
    st = load_json(SELFSTATE, {})

    # (a) Our own launchd agent vanished after we'd learned it exists — the
    # monitor may have been unloaded/deleted. Self-learned, so a machine that
    # never installed the agent is never falsely flagged.
    if not os.path.exists(SELF_PLIST) and st.get("installed"):
        findings.append(finding(
            "HIGH", "self-protection", "Aegis launchd agent is missing",
            "%s no longer exists — the background monitor may have been unloaded "
            "or deleted. Re-run install.sh if this was not intentional."
            % SELF_PLIST, "self:agent:removed"))
    # (a2) The agent plist EXISTS but is malformed — invalid XML (e.g. a raw '&'
    # from an install path like ".../Work & Projects/...", the F0 bug in an
    # install predating its fix). launchd may still run a previously-loaded copy,
    # so the monitor looks alive — but on the next reboot/reload launchd will
    # silently refuse the bad plist and the monitor dies with no signal. Catch it
    # WHILE it is still limping (and fixable) rather than after it is silently
    # gone. Only checked when the file exists (absence is handled above).
    elif os.path.exists(SELF_PLIST):
        try:
            with open(SELF_PLIST, "rb") as f:
                plistlib.load(f)
        except Exception:
            findings.append(finding(
                "HIGH", "self-protection", "Aegis launchd plist is malformed",
                "%s exists but is not valid — launchd will silently refuse to "
                "(re)load it on the next reboot and the monitor will stop "
                "running with no alert. Re-run install.sh to regenerate a valid "
                "agent." % SELF_PLIST, "self:agent:malformed"))

    # (b) The append-only findings log shrank since last scan — someone truncated
    # the durable evidence trail.
    prev = st.get("findings_size")
    try:
        cur_size = os.path.getsize(FINDINGS_LOG)
    except Exception:
        cur_size = 0
    if isinstance(prev, int) and cur_size < prev:
        findings.append(finding(
            "HIGH", "self-protection", "Findings log was truncated",
            "%s shrank from %d to %d bytes since the last scan — the append-only "
            "evidence log may have been tampered with." % (FINDINGS_LOG, prev, cur_size),
            "self:log:truncated:%d" % prev))

    # (c) Local trust-store tampering (moderator blind-spot): baseline.json and
    # allowlist.json live in ~/.aegis, writable by the SAME uid as the dominant
    # same-user stealer class. An attacker who poisons the baseline (blesses its
    # own persistence) or pre-inserts an allowlist entry makes Aegis diff against
    # corrupted ground truth. We record each file's HMAC (keyed watermark) right
    # after WE write it; a mismatch at the next scan means it changed by a hand
    # that wasn't ours. The keyed MAC raises the bar over a plain sha: naive
    # tooling that just recomputes sha256(edited-file) is caught. It is NOT a
    # same-uid barrier, though — the recorded watermarks live in SELFSTATE, which
    # a same-uid attacker can also rewrite: dropping the `<name>_mac` field
    # downgrades this check to the sha path (which the attacker then controls),
    # and deleting
    # SELFSTATE forces a clean re-record. That is the same same-uid limit the
    # _hmac_key docstring states plainly; closing it needs an off-box or
    # non-attacker-writable anchor (a configured heartbeat URL is one). Falls back
    # to the legacy sha watermark for installs upgraded before a MAC was recorded
    # (the next record_selfstate writes the MAC).
    for name, path in (("allowlist", ALLOWLIST), ("baseline", BASELINE)):
        recorded_mac = st.get("%s_mac" % name)
        recorded = recorded_mac or st.get("%s_sha" % name)
        exists = os.path.exists(path)
        cur_watermark = (_hmac_file(path) if recorded_mac else sha256(path)) \
            if exists else None
        cur_sha = sha256(path) if exists else None
        # `recorded` is only set once record_selfstate saw the file exist, so a
        # truthy `recorded` means it existed. cur_watermark is None => the file is
        # now gone (deletion — the more dangerous tamper: it forces the next scan
        # onto the first_run path, silently re-baselining current persistence as
        # known-good). A differing watermark => modification. Both are tampering.
        if recorded and cur_watermark != recorded:
            if cur_watermark is None:
                detail = ("%s was DELETED out-of-band — Aegis recorded its "
                          "integrity hash but the file is now gone. A missing "
                          "trust store forces the next scan to silently "
                          "re-baseline current persistence as known-good, "
                          "laundering any attacker-blessed state." % path)
            else:
                detail = ("%s changed since Aegis last wrote it — its integrity "
                          "hash no longer matches. If you did not run "
                          "`aegis.py baseline`/`allow`, the trust store may have "
                          "been poisoned to hide an intrusion." % path)
            findings.append(finding(
                "HIGH", "self-protection",
                "Aegis %s %s" % (name, "was DELETED out-of-band"
                                 if cur_sha is None else "modified out-of-band"),
                detail,
                "self:%s:tampered:%s" % (name, (cur_sha or "deleted")[:16])))
    return findings


def record_selfstate():
    """Persist self-protection watermarks AFTER a scan's log writes complete."""
    st = load_json(SELFSTATE, {})
    if os.path.exists(SELF_PLIST):
        st["installed"] = True
    try:
        st["findings_size"] = os.path.getsize(FINDINGS_LOG)
    except Exception:
        st["findings_size"] = 0
    # Record trust-store watermarks so the NEXT scan can detect out-of-band
    # edits: the keyed HMAC is the primary tamper watermark (an attacker can't
    # forge it without the key), and the plain sha is retained because
    # _migrate_baseline uses `baseline_sha` as its own out-of-band-edit guard.
    for name, path in (("allowlist", ALLOWLIST), ("baseline", BASELINE)):
        present = os.path.exists(path)
        st["%s_sha" % name] = sha256(path) if present else None
        st["%s_mac" % name] = _hmac_file(path) if present else None
    save_json(SELFSTATE, st)


# --------------------------------------------------------------------------- #
# Check 6: canary / honeypot files (ransomware + bulk-tamper tripwire).
#
# Attribution-independent, near-zero-FP (the moderator's recommendation over a
# statistically-weak entropy port): hidden decoy files with valid content. Any
# modification or deletion of a planted canary is a high-confidence alarm — a
# process encrypting a folder or bulk-tampering will hit them. Opt-in: the user
# runs `aegis.py canary` to plant (Aegis never writes outside ~/.aegis without an
# explicit command); each scan then verifies the planted canaries are intact.
# --------------------------------------------------------------------------- #


def check_canaries():
    findings = []
    state = load_json(CANARY_STATE, {})
    for path, expected in state.items():
        if not os.path.exists(path):
            findings.append(finding(
                "CRITICAL", "canary", "Canary file was DELETED",
                "%s no longer exists — a planted decoy was removed, a strong "
                "ransomware / bulk-tamper signal. Check the folder for mass "
                "encryption or deletion." % path, "canary:deleted:%s" % path,
                path=path))
            continue
        cur = sha256(path)
        if cur != expected:
            findings.append(finding(
                "CRITICAL", "canary", "Canary file was MODIFIED",
                "%s was altered — a planted decoy that nothing legitimate should "
                "touch changed content. Strong ransomware / bulk-tamper signal."
                % path, "canary:modified:%s:%s" % (path, (cur or "gone")[:16]),
                path=path))
    return findings


def _scan_surfaces(baseline, corrupt, first_run, health=None):
    """Diff every extra surface; silently adopt any not yet in the baseline.
    Returns (findings, baseline). Persists the baseline when an EXISTING install
    gains a newly-watched surface (so the next scan can diff); on the true first
    run cmd_scan writes the single authoritative baseline. A corrupt baseline is
    left untouched — its loud alert is handled in cmd_scan."""
    findings = []
    if corrupt:
        return findings, baseline
    if baseline is None:
        baseline = {}
    dirty = False
    for key, snap_fn, diff_fn in SURFACES:
        started = time.monotonic()
        try:
            cur = snap_fn()
            status = "DEGRADED" if cur is None else "OK"
            detail = "sensor returned no reliable snapshot" if cur is None else ""
        except Exception as e:
            cur = None
            status, detail = "FAILED", str(e)
        if health is not None:
            health.append({"sensor_id": "surface." + key, "status": status,
                           "detail": redact_sensitive(detail),
                           "duration_ms": int((time.monotonic() - started) * 1000),
                           "item_count": len(cur) if hasattr(cur, "__len__") else 0})
        # A snapshot fn returns None when its backing command could not be read
        # this scan (e.g. sfltool/lsof timed out). That is a NON-ANSWER, not an
        # empty world: never adopt it as a baseline and never diff against it
        # (both would fabricate findings the moment the command next succeeds).
        # Skip the surface for this scan; the prior baseline is left intact.
        if cur is None:
            continue
        prior = baseline.get(key)
        if prior is None:
            # First sighting → adopt silently (the KnockKnock "trust what's
            # already installed" rule) EXCEPT for live-threat surfaces: an active
            # remote login is a CURRENT-ACCESS risk, not residue, so per the
            # README's live-vs-residue principle it must alert even on the very
            # first scan (an intruder logged in at install/upgrade time must not
            # be blessed as known-good). Diff against empty to surface it, then
            # record so it does not re-alert next scan.
            if key in _NEVER_ADOPT_LIVE:
                findings += diff_fn({}, cur)
            baseline[key] = cur
            dirty = True
        else:
            findings += diff_fn(prior, cur)
    if dirty and not first_run:
        save_json(BASELINE, baseline)
    return findings, baseline


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def gather_all(baseline_snap, current_snap, health=None):
    health_sink = health if health is not None else []
    findings = []
    sensors = (
        ("persistence.diff", check_persistence, (baseline_snap, current_snap)),
        ("cron", check_cron, ()),
        ("process", check_processes, ()),
        ("behavior", check_behavior, ()),
        ("xprotect", check_xprotect, ()),
        ("shell-history", check_shell_history, ()),
        ("hot-dir", check_hot_dirs, ()),
        ("staging", check_staging, ()),
        ("supply-chain", check_supply_chain, ()),
        ("canary", check_canaries, ()),
        ("outbound", check_outbound, ()),
        ("security-log", check_security_log, ()),
        ("web-protection", check_web_protection, ()),
        ("hardening", check_hardening, ()),
        ("self-protection", check_self_protection, ()),
    )
    for sensor_id, fn, args in sensors:
        findings += _collect_sensor(sensor_id, fn, health_sink, *args)
    # Sort by severity desc, then category.
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["category"]))
    return findings


def write_report(findings, first_run, incidents=None, sensor_health=None):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    lines = []
    lines.append("# Aegis report - %s" % now_iso())
    lines.append("")
    if first_run:
        lines.append("> First run: baseline established. Persistence items above "
                     "are recorded as known-good; you will only be alerted about "
                     "NEW/changed persistence from now on.")
        lines.append("")
    summary = "  ".join("%s %s %d" % (SEV_ICON[s], s, counts[s])
                        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                        if counts.get(s))
    lines.append("**Summary:** %s" % (summary or "no findings"))
    lines.append("")
    degraded = [h for h in (sensor_health or []) if h.get("status") != "OK"]
    if degraded:
        lines.append("## Coverage health")
        for h in degraded:
            lines.append("- ? **%s: %s** — %s" %
                         (h.get("sensor_id"), h.get("status"),
                          h.get("detail") or "coverage unavailable"))
        lines.append("")
    if incidents:
        lines.append("## Active incidents")
        for incident in incidents:
            lines.append("- %s **#%s %s** — %s (%s evidence event%s)" % (
                SEV_ICON.get(incident.get("severity"), "?"), incident.get("id"),
                incident.get("title"), incident.get("status"),
                incident.get("evidence_count", 0),
                "" if incident.get("evidence_count") == 1 else "s"))
        lines.append("")
    if not findings:
        lines.append("_No findings._")
    else:
        cur = None
        for f in findings:
            if f["category"] != cur:
                cur = f["category"]
                lines.append("## %s" % cur)
            lines.append("- %s **%s** — %s" % (
                SEV_ICON[f["severity"]], f["title"], f["detail"]))
    md = "\n".join(lines) + "\n"
    with open(LATEST_MD, "w") as f:
        f.write(md)
    save_json(LATEST_JSON, {"ts": now_iso(), "findings": findings})
    return md


SEEN_MAX = 10000  # bound the dedup ledger; findings.jsonl is the durable record


def _cap_seen(seen):
    """Keep seen.json bounded for an hourly-forever tool: retain the most-recent
    SEEN_MAX fingerprints by timestamp. Everything ever seen still lives in the
    append-only findings.jsonl, so nothing durable is lost."""
    if len(seen) <= SEEN_MAX:
        return seen
    newest = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:SEEN_MAX]
    return dict(newest)


def emit(findings, first_run, adopt=frozenset()):
    """Append new findings to the durable log; notify on new >= HIGH.

    `adopt` is the set of categories being SILENTLY ADOPTED on this scan (an
    upgrade seeing a live, non-baseline surface for the first time — e.g. an
    install predating shell-history support). Their findings are still logged but
    never notified, so the residue they hold is not re-alerted as if it were new.
    """
    seen = load_json(SEEN, {})
    allow = set(load_json(ALLOWLIST, []))
    new_high = []
    _rotate_log(FINDINGS_LOG)
    with open(FINDINGS_LOG, "a") as log:
        for f in findings:
            fp = f["fingerprint"]
            if fp in allow:
                continue
            if fp in seen:
                continue
            seen[fp] = f["ts"]
            log.write(json.dumps(f) + "\n")
            # First-run silence is the KnockKnock "trust what's already installed"
            # rule — it applies to PERSISTENCE and SHELL-HISTORY only, the two
            # surfaces made of accreted-over-time RESIDUE (a launchd item, or a
            # months-old `curl|sh` install line). Suppressing them on the first
            # scan adopts the existing state silently (still LOGGED) so upgrading
            # Aegis on a busy machine is not an alert storm; NEW ones thereafter
            # alert. A payload already sitting in a hot dir, a suspicious RUNNING
            # process (behavior), an XProtect detection, /tmp staging, a modified
            # canary, or a weak hardening setting is a LIVE risk the user must
            # hear about even on the very first scan — those are never suppressed.
            suppressed = (
                (first_run and f["category"] in ("persistence", "shell-history"))
                or f["category"] in adopt)
            # Two-axis routing gate: notify only when severity clears the floor
            # AND confidence is not 'low'. A high-impact-but-noisy hit (explicit
            # confidence='low') is still logged/correlated but routed to the
            # digest tier instead of interrupting — the anti-fatigue rule that
            # keeps the tool trusted. Default 'medium' keeps every existing
            # finding's notify behavior byte-identical.
            low_conf = CONFIDENCE_ORDER.get(f.get("confidence", "medium"), 1) <= 0
            if not suppressed and not low_conf \
                    and SEV_ORDER[f["severity"]] >= SEV_ORDER[NOTIFY_MIN_SEV]:
                new_high.append(f)
    save_json(SEEN, _cap_seen(seen))

    if new_high:
        top = new_high[0]
        extra = " (+%d more)" % (len(new_high) - 1) if len(new_high) > 1 else ""
        notify("Aegis: %s" % top["severity"],
               "%s%s" % (top["title"], extra))
    return new_high


def load_baseline():
    """Return (baseline_or_None, corrupt). Distinguishes 'no baseline yet' (a
    legitimate silent first run) from 'baseline exists but won't parse'. The two
    must NOT collapse to the same None: silently re-baselining over a corrupt file
    would fold any planted persistence into known-good and erase the evidence."""
    if not os.path.exists(BASELINE):
        return None, False
    try:
        with open(BASELINE, "r") as f:
            data = json.load(f)
        return _migrate_baseline(data), False
    except Exception:
        return None, True


def _migrate_baseline(data):
    """Upgrade legacy raw-argv baselines without laundering tamper evidence."""
    if not isinstance(data, dict):
        return data
    records = data.get("persistence")
    if not isinstance(records, dict) or not any(
            isinstance(rec, dict) and "args_sha256" not in rec
            for rec in records.values()):
        return data

    # Rewrite only when the existing self-protection watermark agrees. If an
    # attacker changed the file out of band, leave it byte-for-byte untouched so
    # check_self_protection can report the mismatch instead of blessing it.
    state = load_json(SELFSTATE, {})
    recorded = state.get("baseline_sha")
    current = sha256(BASELINE)
    if recorded and recorded != current:
        return data

    for key, rec in list(records.items()):
        if not isinstance(rec, dict):
            continue
        raw_args = rec.get("args")
        if "args_sha256" not in rec:
            if raw_args is None:
                rec["args_sha256"] = None
            else:
                encoded = json.dumps(raw_args, sort_keys=True, default=str)
                rec["args_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
        records[key] = _redact_value(rec)
    data["schema_version"] = BASELINE_SCHEMA_VERSION
    data["trust"] = data.get("trust") or "unverified"
    save_json(BASELINE, data)
    state["baseline_sha"] = sha256(BASELINE)
    save_json(SELFSTATE, state)
    log_run("migrated baseline schema to v%d (legacy argv redacted)" %
            BASELINE_SCHEMA_VERSION)
    return data


@contextmanager
def _scan_lock():
    ensure_state()
    path = os.path.join(STATE_DIR, ".scan.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def cmd_scan(quiet=False):
    # A watch-triggered scan and a manual/interval scan may overlap. One writer
    # owns baseline/seen/sigcache/report state at a time; readers keep working.
    with _scan_lock():
        return _cmd_scan_locked(quiet)


def _cmd_scan_locked(quiet=False):
    ensure_state()
    health = []
    baseline, baseline_corrupt = load_baseline()
    first_run = baseline is None and not baseline_corrupt
    current = _collect_sensor("persistence.snapshot", snapshot_persistence,
                              health)

    findings = gather_all(baseline.get("persistence") if baseline else None,
                          current, health=health)

    # Extra baseline-diffed surfaces (shell rc, login hooks, config profiles,
    # extra persistence, browser extensions). Adopted silently on first sight,
    # diffed thereafter. `baseline` is returned possibly-mutated/persisted.
    surface_findings, baseline = _scan_surfaces(baseline, baseline_corrupt,
                                                first_run, health=health)
    findings += surface_findings

    if baseline_corrupt:
        # Do not silently re-baseline. Surface it loudly and let every current
        # item be evaluated as new (base was None ⇒ check_persistence saw {}).
        findings.insert(0, finding(
            "HIGH", "integrity", "Baseline file is unreadable/corrupt",
            "%s failed to parse; NOT re-baselining. All persistence is being "
            "re-evaluated as new. Run `aegis.py baseline` to re-establish a "
            "known-good baseline once you trust the current state." % BASELINE,
            "integrity:baseline:corrupt"))
    elif baseline is not None and baseline.get("trust", "unverified") != "verified":
        findings.append(finding(
            "INFO", "trust", "Baseline is adopted but not reviewed",
            "Existing state is being diffed to prevent alert storms, but it is not "
            "asserted known-good. Review the machine, then run `aegis.py baseline` "
            "to mark the current baseline verified.", "trust:baseline:unverified"))

    # Per-surface silent adoption on UPGRADE. shell-history is a LIVE (non-baseline)
    # surface, so an install that predates it must adopt whatever residue is already
    # in history silently on the first scan that supports it — otherwise a months-old
    # `curl…|sh` install line alerts as if it were a live threat. first_run already
    # covers the fresh-install case via emit()'s suppression; this covers upgrades
    # (README: upgrading Aegis on an existing install is storm-free, per-surface).
    adopt = set()
    if first_run:
        # single authoritative baseline write: persistence + every surface
        # snapshot (_scan_surfaces adopted them into `baseline` in memory).
        baseline = baseline or {}
        baseline["created"] = baseline.get("created") or now_iso()
        baseline["schema_version"] = BASELINE_SCHEMA_VERSION
        baseline["trust"] = "unverified"
        baseline["persistence"] = current
        baseline["shell_history_adopted"] = True
        save_json(BASELINE, baseline)
    elif baseline is not None and not baseline.get("shell_history_adopted"):
        adopt.add("shell-history")
        baseline["shell_history_adopted"] = True
        save_json(BASELINE, baseline)

    # Re-sort: surface findings (and any corrupt-baseline finding) were appended
    # after gather_all's sort.
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["category"]))

    new_high = emit(findings, first_run, adopt=adopt)
    suppressed_categories = set(adopt)
    if first_run:
        suppressed_categories.update(("persistence", "shell-history"))
    try:
        record_security_state(
            findings, sensor_health=health, initially_notified=bool(new_high),
            suppressed_categories=suppressed_categories)
        reminders = [] if new_high else claim_due_incident_reminders()
        if reminders:
            top = reminders[0]
            extra = " (+%d more open)" % (len(reminders) - 1) \
                if len(reminders) > 1 else ""
            notify("Aegis incident reminder",
                   "#%s %s%s" % (top["id"], top["title"], extra))
        incidents = list_incidents()
        persisted_health = get_sensor_health()
    except Exception as e:
        # The detector continues and its legacy evidence log remains available,
        # but the failure is durable and visible rather than silently "clean".
        log_run("event-store failure: %s" % e)
        incidents, persisted_health = [], health
    md = write_report(findings, first_run, incidents=incidents,
                      sensor_health=persisted_health)
    flush_sigcache()
    record_selfstate()
    # Dead-man's-switch beat: a completed scan is proof of life. Its ABSENCE is
    # what an external watcher / peer agent / `aegis.py watchdog` alarms on — the
    # one signal a same-uid attacker who kills or boots-out Aegis can't suppress
    # off-box. POSTs out-of-band only if a URL is configured (else local-only).
    write_heartbeat(status="ok", alerts=len(new_high),
                    top_alert=new_high[0]["title"] if new_high else None)
    log_run("scan: %d findings, %d new-high, first_run=%s"
            % (len(findings), len(new_high), first_run))

    if not quiet:
        print(md)
    return 0


def cmd_baseline(trust="verified"):
    with _scan_lock():
        return _cmd_baseline_locked(trust)


def _cmd_baseline_locked(trust="verified"):
    ensure_state()
    current = snapshot_persistence()
    b = {"created": now_iso(), "schema_version": BASELINE_SCHEMA_VERSION,
         "persistence": current, "trust": trust}
    for key, snap_fn, _diff in SURFACES:
        try:
            snap = snap_fn()
        except Exception:
            snap = None
        # A None snapshot means the backing command couldn't be read now; omit
        # the surface so the next scan adopts it once it can, rather than
        # baselining a false-empty (see snapshot_btm).
        if snap is not None:
            b[key] = snap
    save_json(BASELINE, b)
    flush_sigcache()
    record_selfstate()
    label = "reviewed/verified" if trust == "verified" else "adopted/unverified"
    print("Baseline reset: %d persistence item(s) + %d extra surface(s) recorded "
          "as %s." % (len(current), len(SURFACES), label))
    return 0


def cmd_canary(action="plant"):
    """Plant / remove ransomware canary (honeypot) files. Opt-in remediation-
    adjacent capability: this is the ONLY path by which Aegis writes outside
    ~/.aegis, and only on explicit user command."""
    ensure_state()
    if action == "remove":
        state = load_json(CANARY_STATE, {})
        removed = 0
        for path in list(state):
            try:
                if os.path.exists(path):
                    os.remove(path)
                removed += 1
            except Exception:
                pass
        save_json(CANARY_STATE, {})
        print("Removed %d canary file(s)." % removed)
        return 0
    # plant
    state = {}
    for d in CANARY_DIRS:
        if not os.path.isdir(d):
            continue
        path = os.path.join(d, CANARY_NAME)
        try:
            with open(path, "w") as f:
                f.write(CANARY_CONTENT)
            try:  # hide it from casual view (best-effort; not a security control)
                run(["chflags", "hidden", path], timeout=5)
            except Exception:
                pass
            state[path] = sha256(path)
        except Exception:
            continue
    save_json(CANARY_STATE, state)
    print("Planted %d canary file(s). Aegis will alert CRITICAL if any is "
          "modified or deleted (ransomware / bulk-tamper tripwire).\n"
          "Remove with: aegis.py canary remove" % len(state))
    return 0


def cmd_report():
    if os.path.exists(LATEST_MD):
        with open(LATEST_MD) as f:
            sys.stdout.write(f.read())
    else:
        print("No report yet. Run: aegis.py scan")
    return 0


def cmd_incidents(show_all=False):
    incidents = list_incidents(active_only=not show_all)
    if not incidents:
        print("No %sincidents." % ("recorded " if show_all else "active "))
        return 0
    print("# Aegis incidents (%d)\n" % len(incidents))
    for item in incidents:
        print("  #%s  %-12s %-8s %s\n      %s · %s evidence event%s" % (
            item["id"], item["status"], item["severity"], item["title"],
            item["correlation_key"], item["evidence_count"],
            "" if item["evidence_count"] == 1 else "s"))
    print("\nDetails/actions: aegis.py incident <id> [ack|investigate|contain|"
          "recover|monitor|resolve|false-positive|benign-positive|reopen]")
    return 0


_INCIDENT_ACTIONS = {
    "ack": "ACK", "investigate": "INVESTIGATING", "contain": "CONTAINED",
    "recover": "RECOVERING", "monitor": "MONITORING", "resolve": "RESOLVED",
    "false-positive": "FALSE_POSITIVE", "benign-positive": "FALSE_POSITIVE",
    "reopen": "OPEN",
}

# Documenting each sensor's EXPECTED benign causes turns triage from an
# investigation into a lookup — the single biggest triage-ergonomics lever for a
# one-person SOC. Shown on the incident card next to the evidence.
SENSOR_BENIGN_NOTES = {
    "persistence": "Homebrew services, Docker/VSCode helpers, backup agents, "
                   "and printer/VPN vendors all install launchd jobs.",
    "process": "Dev toolchains run unsigned binaries from ~/ (cargo/go build "
               "output, node_modules/.bin, pyenv shims).",
    "behavior": "Installer one-liners (Homebrew/rustup) legitimately pipe curl "
                "into a shell; CI and dotfile scripts use base64/eval.",
    "hot-dir": "Freshly downloaded developer tools land unsigned in ~/Downloads; "
               "check the origin URL recorded on the finding.",
    "staging": "Archivers and installers write .zip files to /tmp routinely — "
               "the IOC filename, not the archive itself, is the signal.",
    "supply-chain": "Some legitimate packages run build steps in postinstall; "
                    "the flagged idiom (decode-and-exec) is what matters.",
    "net-listener": "Dev servers, Docker, syncthing, and AirPlay bind ports; "
                    "loopback-only listeners are already excluded.",
    "btm": "Any app you install can register a login item or background agent.",
    "browserext": "Extensions you installed yourself appear here on first sight.",
    "ide_ext": "VSCode/Cursor extensions auto-update, which re-fires this.",
    "wallet": "Wallet apps rewrite their own config on update or account change.",
    "web-protection": "Editing /etc/hosts for local development is expected.",
    "hardening": "A deliberately disabled firewall or Remote Login you enabled.",
    "canary": "A backup/indexing tool touching the decoy file, or your own edit.",
    "self-protection": "Re-running install.sh or editing the trust store by hand.",
}


def _benign_note_for(item):
    """The benign-cause notes relevant to an incident, keyed on its evidence
    categories (falling back to the correlation key's own prefix)."""
    notes = []
    for category in sorted(item.get("categories") or ()):
        note = SENSOR_BENIGN_NOTES.get(category)
        if note and note not in notes:
            notes.append("%s: %s" % (category, note))
    return notes


def cmd_incident(incident_id, action=None, reason=None):
    try:
        incident_id = int(incident_id)
    except (TypeError, ValueError):
        print("usage: aegis.py incident <numeric-id> [action]")
        return 1
    if action:
        new_status = _INCIDENT_ACTIONS.get(action.lower())
        if not new_status:
            print("unknown incident action: %s" % action)
            return 1
        # A dismissal records WHICH kind it was, so a broken rule and an
        # authorized-but-noisy one feed different tuning queues.
        reason_code = None
        if new_status == "FALSE_POSITIVE":
            reason_code = reason or action.lower()
            if reason_code not in ("false-positive", "benign-positive"):
                reason_code = "false-positive"
        if not transition_incident(incident_id, new_status,
                                   reason_code=reason_code):
            current = incident_detail(incident_id)
            print("refuse: invalid transition from %s to %s" %
                  ((current or {}).get("status", "missing"), new_status))
            return 1
    item = incident_detail(incident_id)
    if not item:
        print("no such incident: %s" % incident_id)
        return 1
    print("# Incident #%s — %s\n\n  severity: %s\n  status:   %s\n  chain:    %s"
          "\n  opened:   %s\n  updated:  %s\n\nEvidence:" % (
              item["id"], item["title"], item["severity"], item["status"],
              item["correlation_key"],
              datetime.fromtimestamp(item["created_at"]).isoformat(),
              datetime.fromtimestamp(item["updated_at"]).isoformat()))
    for evidence in item.get("evidence", []):
        try:
            data = json.loads(evidence["data_json"])
            summary = data.get("title") or data.get("status") or evidence["event_type"]
        except Exception:
            summary = evidence["event_type"]
        print("  - %s · %s · %s" %
              (evidence["observed_at"], evidence["source"], summary))
    notes = _benign_note_for(item)
    if notes:
        print("\nKnown benign causes for these sensors (check before acting):")
        for note in notes:
            print("  · %s" % note)
    print("\nActions: ack | investigate | contain | recover | monitor | resolve"
          "\n         false-positive   (the DETECTION was wrong — rule needs tuning)"
          "\n         benign-positive  (real event, but authorized — suppress this one)"
          "\n         reopen")
    return 0


def cmd_replay(days=30):
    """Backtest the CURRENT correlation/scoring logic against recorded history.

    Detection-as-code's first discipline: a rule change must be replayed over
    real past telemetry before it ships, or you cannot tell a precision gain from
    a silent regression. This re-runs today's chain rules over the stored finding
    events in a THROWAWAY in-memory database, so it never creates an incident,
    never notifies, and never mutates durable state — it only reports what the
    current logic WOULD have opened over that window."""
    ensure_state()
    init_event_store()
    now = _epoch()
    since = now - int(days) * 86400
    src = _event_connection()
    try:
        rows = src.execute(
            "SELECT id,occurred_at,observed_at,source,event_type,data_json "
            "FROM events WHERE event_type='observation.finding' AND observed_at>=? "
            "ORDER BY observed_at", (since,)).fetchall()
        dismissals = src.execute(
            "SELECT category,reason_code,COUNT(*) AS n FROM dismissals "
            "WHERE dismissed_at>=? GROUP BY category,reason_code "
            "ORDER BY n DESC", (since,)).fetchall()
    finally:
        src.close()
    print("# Aegis replay — last %s days, %d recorded finding events\n"
          % (days, len(rows)))
    if not rows:
        print("No recorded findings in that window; nothing to replay.")
        return 0
    # Rebuild the events into a scratch DB and run the real correlation code.
    scratch = sqlite3.connect(":memory:")
    scratch.row_factory = sqlite3.Row
    scratch.executescript(_EVENT_SCHEMA_SQL)
    new_events = []
    with scratch:
        for row in rows:
            cur = scratch.execute(
                "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                "data_json) VALUES(?,?,?,?,?)",
                (row["occurred_at"], row["observed_at"], row["source"],
                 row["event_type"], row["data_json"]))
            try:
                new_events.append((cur.lastrowid, json.loads(row["data_json"])))
            except Exception:
                continue
        _apply_correlations(scratch, new_events, now, initially_notified=True)
        opened = _dict_rows(scratch.execute(
            "SELECT kind,severity,title,correlation_key FROM incidents "
            "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
            "ELSE 2 END, id").fetchall())
    scratch.close()
    by_kind = {}
    for item in opened:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    print("Incidents the CURRENT logic would open: %d" % len(opened))
    for kind in sorted(by_kind):
        print("  %-12s %d" % (kind, by_kind[kind]))
    print()
    for item in opened[:40]:
        print("  %-8s %-11s %s" % (item["severity"], item["kind"],
                                   item["title"][:96]))
    if len(opened) > 40:
        print("  … %d more" % (len(opened) - 40))
    if dismissals:
        print("\nDismissal history (per-sensor tuning queue):")
        for row in dismissals:
            print("  %-16s %-16s %d" % (row["category"] or "-",
                                        row["reason_code"], row["n"]))
        print("\n  false-positive → the rule is wrong; tune or retire it."
              "\n  benign-positive → the rule works; the activity was authorized.")
    print("\nReplay is read-only: no incident was created and nothing was notified.")
    return 0


def cmd_doctor():
    """Report actual coverage and liveness; UNKNOWN is never printed as green."""
    ensure_state()
    init_event_store()
    problems = []
    print("# Aegis doctor - %s\n" % now_iso())
    state_mode = os.stat(STATE_DIR).st_mode & 0o777
    print("  %s state directory             mode %03o" %
          ("✓" if state_mode == 0o700 else "?", state_mode))
    if state_mode != 0o700:
        problems.append("state permissions")
    for path in (os.path.join(HOME, "Downloads"), os.path.join(HOME, "Desktop")):
        try:
            iterator = os.scandir(path)
            try:
                next(iterator, None)
            finally:
                iterator.close()
            print("  ✓ %-27s readable" % path)
        except OSError as e:
            print("  ? %-27s unavailable: %s" % (path, e))
            problems.append(path)
    health = get_sensor_health()
    if not health:
        print("  ? sensors                     no completed scan recorded")
        problems.append("no sensor health")
    for item in health:
        mark = "✓" if item["status"] == "OK" else "?"
        print("  %s %-27s %-10s failures=%d %s" % (
            mark, item["sensor_id"], item["status"],
            item["consecutive_failures"], item["detail"] or ""))
        if item["status"] != "OK":
            problems.append(item["sensor_id"])
    incidents = list_incidents()
    print("\n  %s active incident%s" %
          (len(incidents), "" if len(incidents) == 1 else "s"))
    print("\nDoctor result: %s" % ("DEGRADED" if problems else "OK"))
    return 1 if problems else 0


def cmd_preflight():
    """Installer-only capability check; performs no scan and blesses no state."""
    ensure_state()
    try:
        init_event_store()
        if not hasattr(select, "kqueue"):
            raise RuntimeError("Python lacks macOS kqueue support")
        if sys.version_info < (3, 9):
            raise RuntimeError("Python 3.9 or newer is required")
    except Exception as e:
        print("Aegis preflight failed: %s" % e)
        return 1
    print("Aegis preflight OK: Python %s, kqueue, SQLite, private state" %
          sys.version.split()[0])
    return 0


def cmd_mark_uninstalled():
    """Installer lifecycle hook: intentional uninstall is not self-tampering."""
    ensure_state()
    state = load_json(SELFSTATE, {})
    state["installed"] = False
    state["uninstalled_at"] = now_iso()
    save_json(SELFSTATE, state)
    return 0


def cmd_status():
    ensure_state()
    findings = check_hardening()
    print("# Aegis hardening posture - %s\n" % now_iso())
    checks = [
        ("System Integrity Protection", "hardening:sip:off", "hardening:sip:unknown"),
        ("Gatekeeper", "hardening:gatekeeper:off", "hardening:gatekeeper:unknown"),
        ("FileVault", "hardening:filevault:off", "hardening:filevault:unknown"),
        ("Application Firewall", "hardening:firewall:off", "hardening:firewall:unknown"),
        ("Firewall stealth mode", "hardening:stealth:off", "hardening:stealth:unknown"),
        ("Remote Login (SSH) off", "hardening:ssh:on", "hardening:ssh:unknown"),
    ]
    bad = {f["fingerprint"]: f for f in findings}
    for label, fp, unknown_fp in checks:
        if fp in bad:
            print("  ✗ %-32s %s" % (label, bad[fp]["detail"]))
        elif unknown_fp in bad:
            print("  ? %-32s %s" % (label, bad[unknown_fp]["detail"]))
        else:
            print("  ✓ %-32s ok" % label)

    # Apple's own engine: report XProtect definition version/age (piggybacks the
    # professionally-maintained signature pipeline; a stale value is a red flag).
    newest, version = None, None
    for b in XPROTECT_BUNDLES:
        try:
            m = os.path.getmtime(b)
        except Exception:
            continue
        if newest is None or m > newest:
            newest = m
            info = os.path.join(b, "Contents", "Info.plist")
            v, _, vrc = run(["/usr/libexec/PlistBuddy", "-c",
                             "Print :CFBundleShortVersionString", info], timeout=6)
            version = v.strip() if vrc == 0 else None
    if newest is not None:
        age = (time.time() - newest) / 86400.0
        mark = "✓" if age <= XPROTECT_STALE_DAYS else "✗"
        print("  %s %-32s v%s, updated %.0f days ago"
              % (mark, "XProtect definitions", version or "?", age))
    health = get_sensor_health()
    if health:
        print("\n# Sensor coverage")
        for item in health:
            mark = "✓" if item["status"] == "OK" else "?"
            print("  %s %-32s %s%s" % (
                mark, item["sensor_id"], item["status"],
                (" — " + item["detail"]) if item["detail"] else ""))
    print("\n# Incidents\n  %d active" % len(list_incidents()))

    # Survivability (dead-man's switch) + capability posture.
    print("\n# Survivability")
    beat = read_heartbeat()
    if beat.get("epoch"):
        age = int(time.time()) - int(beat["epoch"])
        mark = "✓" if age <= HEARTBEAT_STALE_SECS else "✗"
        print("  %s %-32s last beat %d min ago (pid %s)"
              % (mark, "Heartbeat", age // 60, beat.get("pid", "?")))
    else:
        print("  ? %-32s no beat yet (run a scan)" % "Heartbeat")
    print("  %s %-32s %s" % (
        "✓" if _heartbeat_url() else "·", "Off-host heartbeat",
        "configured (out-of-band alerting on)" if _heartbeat_url()
        else "off (local-only; set AEGIS_HEARTBEAT_URL to enable)"))
    if os.path.exists(WATCHDOG_ALERT):
        try:
            with open(WATCHDOG_ALERT) as f:
                last = f.read().strip().splitlines()[-1]
        except Exception:
            last = "(unreadable)"
        print("  ✗ %-32s %s" % ("Watchdog ALERT (unresolved)", last))
    fda = _has_full_disk_access()
    print("  %s %-32s %s" % (
        "✓" if fda else "·", "Full Disk Access",
        "granted (Downloads/Desktop/Bastion in scope)" if fda
        else "not granted (Downloads/Desktop scan degraded; grant to python3)"))
    return 0


def _has_full_disk_access():
    """Silent FDA self-test: opening the per-user TCC.db does NOT raise a TCC
    prompt, so a successful read means this process holds Full Disk Access.
    Probed from whatever context calls it — note a launchd agent's grant differs
    from an interactive shell's, so `status` (interactive) and the agent may
    disagree; that is real, not a bug."""
    tcc = os.path.join(HOME, "Library", "Application Support",
                       "com.apple.TCC", "TCC.db")
    try:
        with open(tcc, "rb") as f:
            f.read(16)
        return True
    except Exception:
        return False


def _vt_api_key():
    """The VirusTotal API key from env (AEGIS_VT_API_KEY) or ~/.aegis/vt_key,
    or None. Env wins so a key can be injected for one call without touching
    disk. Whitespace-stripped; empty ⇒ None."""
    k = os.environ.get("AEGIS_VT_API_KEY", "").strip()
    if k:
        return k
    try:
        with open(VT_KEY_FILE) as f:
            return f.read().strip() or None
    except Exception:
        return None


def _looks_like_sha256(s):
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", s or ""))


def cmd_vt(target):
    """OPT-IN reputation lookup — the ONLY command that touches the network, and
    only when you type it with a key present. `target` is a file path (hashed
    locally; ONLY the sha256 is sent — never the bytes) or a bare sha256. Prints
    VirusTotal's multi-engine verdict. No key ⇒ prints how to add one, exits 2 —
    the scan/watch path is unaffected and stays local-only."""
    ensure_state()
    key = _vt_api_key()
    if not key:
        print("VirusTotal lookup is OFF (no API key — the scan path stays "
              "local-only regardless).\n  Add a free key (virustotal.com) via "
              "either:\n    export AEGIS_VT_API_KEY=<key>\n    printf %%s <key> "
              "> %s && chmod 600 %s" % (VT_KEY_FILE, VT_KEY_FILE))
        return 2
    if _looks_like_sha256(target):
        sha = target.lower()
    else:
        rp = os.path.realpath(target)
        if not os.path.isfile(rp):
            print("refuse: %s is not a file or a sha256" % target)
            return 1
        sha = sha256(rp)
        if not sha:
            print("error: could not hash %s" % rp)
            return 1
    import urllib.request  # lazy: the scan path never even imports urllib
    import urllib.error
    req = urllib.request.Request(VT_API_URL + sha, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("Not found on VirusTotal: %s\n  (unknown hash — no engine has "
                  "seen this file; treat as UNVETTED, not proven clean)" % sha)
            return 0
        if e.code == 401:
            print("error: VirusTotal rejected the API key (401)")
            return 1
        if e.code == 429:
            print("error: VirusTotal rate limit hit (429) — the free tier is "
                  "4 lookups/min; wait and retry")
            return 1
        print("error: VirusTotal HTTP %s" % e.code)
        return 1
    except Exception as e:
        print("error: VirusTotal lookup failed (%s)" % e)
        return 1
    stats = (((data.get("data") or {}).get("attributes") or {})
             .get("last_analysis_stats") or {})
    mal = stats.get("malicious", 0)
    susp = stats.get("suspicious", 0)
    total = sum(v for v in stats.values() if isinstance(v, int)) or 0
    verdict = ("MALICIOUS" if mal else "suspicious" if susp else "clean")
    print("VirusTotal verdict for %s\n  %s — %d malicious / %d suspicious / %d "
          "engines\n  https://www.virustotal.com/gui/file/%s"
          % (sha, verdict.upper(), mal, susp, total, sha))
    log_run("vt %s -> %s (%d/%d)" % (sha[:16], verdict, mal, total))
    return 0


def cmd_allow(path):
    ensure_state()
    allow = load_json(ALLOWLIST, [])
    added = 0
    # Allow by prefix match against any current finding fingerprint.
    data = load_json(LATEST_JSON, {"findings": []})
    for f in data.get("findings", []):
        if path in (f.get("path") or "") or path == f.get("fingerprint"):
            if f["fingerprint"] not in allow:
                allow.append(f["fingerprint"])
                added += 1
    save_json(ALLOWLIST, allow)
    print("Allowlisted %d finding(s) matching %r." % (added, path))
    return 0


# --------------------------------------------------------------------------- #
# Event-driven watch ("real-time, not polling" — the roadmap's top item). A
# stdlib kqueue over the dirs/files malware must TOUCH — persistence dirs, hot
# dirs, staging dirs, shell rc + history, wallet configs — triggers a rescan
# within seconds of a change instead of at the next interval tick. Debounced (a
# multi-file download burst is ONE scan) and rate-limited (a churning /tmp or a
# busy terminal writing history can never scan more than once per
# WATCH_MIN_GAP_SECS); a full scan still runs every `interval` seconds as a
# floor, so the non-file surfaces (process argv, XProtect log, listeners,
# hardening) are never starved. This closes most of the sub-minute polling gap
# honestly documented in the README: a payload's persistence write or /tmp
# staging drop now triggers detection in seconds, not at the next hourly tick.
# It is still detection-after-the-write, NOT blocking (that ceiling is Apple's).
# --------------------------------------------------------------------------- #

WATCH_DEBOUNCE_SECS = 3   # let a write burst settle so it costs one scan
WATCH_MIN_GAP_SECS = 60   # floor between event-triggered scans (battery bound)

# os.O_EVTONLY only exists in Python >= 3.10; the launchd agent runs the system
# /usr/bin/python3 (CLT Python 3.9), where the missing attr crashed _build_watch
# and turned watch mode into a KeepAlive crash-loop of back-to-back full scans.
# 0x8000 is O_EVTONLY from macOS <fcntl.h>.
O_EVTONLY = getattr(os, "O_EVTONLY", 0x8000)


def _watch_paths():
    """The dirs+files (that exist right now) whose change should trigger an
    immediate rescan. Rebuilt before every wait, so paths that appear later
    (a first wallet install, a new rc file) are picked up automatically."""
    paths = []
    for d in PERSISTENCE_DIRS + HOT_DIRS + STAGING_DIRS + EXTRA_PERSIST_DIRS:
        if os.path.isdir(d):
            paths.append(d)
    for f in (SHELL_RC_FILES + SHELL_HISTORY_FILES + WALLET_CONFIG_FILES
              + EXTRA_PERSIST_FILES):
        if os.path.isfile(f):
            paths.append(f)
    # Directory vnode events reliably expose entry create/delete/rename, but an
    # in-place write to an existing child can otherwise wait for reconciliation.
    # Arm the already-present high-value objects directly as well.
    for directory in PERSISTENCE_DIRS:
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for name in entries:
            child = os.path.join(directory, name)
            if name.endswith(".plist") and os.path.isfile(child):
                paths.append(child)
    for directory in HOT_DIRS:
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for name in entries:
            app = os.path.join(directory, name)
            if not name.lower().endswith(".app") or not os.path.isdir(app):
                continue
            paths.append(app)
            executable = _bundle_executable(app)
            if executable:
                paths.append(executable)
    return list(dict.fromkeys(paths))


def _build_watch(extra_read_fds=()):
    """A kqueue armed over _watch_paths() (EVFILT_VNODE: write/extend/delete/
    rename), plus EVFILT_READ on any `extra_read_fds` (the live log-stream tail
    — data arriving there wakes the loop exactly like a file change). Returns
    (kq, fds); caller must _close_watch(kq, fds) — extra fds are NOT closed
    here, they belong to their subprocess."""
    kq = select.kqueue()
    fds, evs = [], []
    fflags = (select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND |
              select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME)
    for p in _watch_paths():
        try:
            fd = os.open(p, O_EVTONLY)  # macOS: watch without blocking unmount
        except OSError:
            continue
        fds.append(fd)
        evs.append(select.kevent(
            fd, filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR, fflags=fflags))
    for fd in extra_read_fds:
        # Level-triggered (no EV_CLEAR): the caller drains the fd on every wake,
        # so a partial read can never wedge the loop into a busy spin.
        evs.append(select.kevent(
            fd, filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD))
    if evs:
        kq.control(evs, 0, 0)
    return kq, fds


def _wait_for_change(kq, timeout):
    """True if any watched path changed within `timeout` seconds."""
    try:
        return bool(kq.control(None, 64, timeout))
    except OSError:
        return False


def _close_watch(kq, fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        kq.close()
    except Exception:
        pass


def _spawn_xprotect_stream():
    """Persistent `log stream` tail of Apple's XProtect subsystem — the LIVE
    counterpart to check_xprotect()'s windowed harvest (the roadmap's remaining
    real-time half). Design: the tail is a WAKE SOURCE, not a second emit path —
    any event on the stream triggers an immediate scan, whose windowed harvest
    then picks the event up through the one normal report/dedup/notify pipeline
    (no duplicated parsing state to drift). XPR events are rare (~daily module
    runs), so the wake cost is nil. Returns a Popen with a non-blocking stdout,
    or None if `log` is unavailable — watch degrades to file events + the floor."""
    try:
        p = subprocess.Popen(
            _trusted_command(["log", "stream", "--style", "ndjson", "--predicate",
                              'subsystem == "%s" AND category == "XPEvent.structured"'
                              % XPROTECT_SUBSYSTEM]),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"HOME": HOME, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "LANG": "C", "LC_ALL": "C",
                 "TMPDIR": os.environ.get("TMPDIR", "/tmp")})
        os.set_blocking(p.stdout.fileno(), False)
        return p
    except Exception:
        return None


def _drain_fd(fd):
    """Consume whatever is buffered on a non-blocking fd (True if anything was
    read). Must be called on every wake for level-triggered read fds."""
    got = False
    while True:
        try:
            chunk = os.read(fd, 65536)
        except (BlockingIOError, InterruptedError):
            return got
        except OSError:
            return got
        if not chunk:
            return got
        got = True


def _stop_stream(proc):
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
    finally:
        for pipe in (proc.stdout, proc.stderr, proc.stdin):
            if pipe is not None:
                try:
                    pipe.close()
                except Exception:
                    pass


def cmd_watch(interval=600):
    """Foreground watch loop. Event-driven where kqueue exists (macOS: always):
    a change to a watched path rescans within ~WATCH_DEBOUNCE_SECS (rate-limited
    to one event scan per WATCH_MIN_GAP_SECS), and a full scan runs every
    `interval` seconds as a floor. Production: `bash install.sh watch` runs this
    under launchd KeepAlive. Falls back to plain interval polling if kqueue is
    somehow unavailable."""
    has_kq = hasattr(select, "kqueue")
    print("Aegis watch: %s. Ctrl-C to stop."
          % ("event-driven (kqueue + live XProtect tail) + full scan every %ds"
             % interval
             if has_kq else "interval polling every %ds (no kqueue)" % interval))
    stream = _spawn_xprotect_stream() if has_kq else None
    try:
        while True:
            try:
                started = time.time()
                cmd_scan(quiet=True)
                if not has_kq:
                    time.sleep(interval)
                    continue
                if stream is not None and stream.poll() is not None:
                    stream = _spawn_xprotect_stream()  # tail died → respawn
                extra = (stream.stdout.fileno(),) if stream else ()
                # A write landing between the scan above and this arm is missed
                # by the kqueue; the interval floor scan covers that ms-wide gap.
                kq, fds = _build_watch(extra)
                try:
                    if _wait_for_change(kq, interval):
                        time.sleep(WATCH_DEBOUNCE_SECS)  # settle the burst
                        if stream is not None:
                            # level-triggered read fd: MUST drain or spin
                            _drain_fd(stream.stdout.fileno())
                        remain = WATCH_MIN_GAP_SECS - (time.time() - started)
                        if remain > 0:
                            time.sleep(remain)  # rate-limit event scans
                        log_run("watch: change event -> rescan")
                finally:
                    _close_watch(kq, fds)
            except KeyboardInterrupt:
                print("\nstopped.")
                return 0
    finally:
        _stop_stream(stream)


# --------------------------------------------------------------------------- #
# RESPONSE TIER (opt-in; never automatic; staged and reversible-by-default).
#
# The scanner above is detect-only by design. This tier adds the ability to
# ACT on a finding — but only ever by explicit user command, mirroring the
# industry doctrine the research surfaced (SentinelOne's Kill→Quarantine→
# Remediate→Rollback ladder; Microsoft Defender's "every automated action must
# be reviewable and reversible" playbook):
#
#   quarantine <path>  atomically confine a file/app in a reversible store
#   restore <id>       reverse the native move without overwriting a destination
#   destroy <id>       verified-delete a quarantined item (IRREVERSIBLE; --yes)
#   kill <pid>         terminate a SAME-USER process (SIGTERM→SIGKILL)
#   sandbox <path>     refuse host execution; require a disposable VM
#   neutralize <plist> ordered kill-chain for launchd-backed malware
#
# Hard safety rails (all destructive verbs): quarantine-first-never-delete-first
# (`destroy` only touches the store, never a live path), protected-path refusal
# (SIP/system/Apple, Aegis's own files, $HOME and its ancestors), same-user-only
# process actions, never-act-on-self, and an append-only actions.jsonl audit.
# None of the ES-entitlement-gated real-time blocking is claimed; this is
# on-demand response to a file/process a human has reviewed.
# --------------------------------------------------------------------------- #


_RESPONSE_FAILPOINT = None  # tests inject process-crash boundaries here


def _response_checkpoint(stage):
    if _RESPONSE_FAILPOINT is not None:
        _RESPONSE_FAILPOINT(stage)


def _response_lock_path():
    return os.path.join(QUARANTINE_DIR, ".lock")


def _response_trash_dir():
    return os.path.join(QUARANTINE_DIR, ".trash")


def _response_tombstone_dir():
    return os.path.join(QUARANTINE_DIR, ".tombstones")


def _quarantine_item(qid):
    return os.path.join(QUARANTINE_DIR, qid)


def _quarantine_txn(qid):
    return os.path.join(_quarantine_item(qid), "txn.json")


def _quarantine_sealed(qid):
    return os.path.join(_quarantine_item(qid), "sealed")


def _quarantine_payload(qid):
    # No original extension and no .app suffix: Finder cannot launch this object.
    return os.path.join(_quarantine_sealed(qid), "payload")


def ensure_quarantine():
    ensure_state()
    for path in (QUARANTINE_DIR, _response_trash_dir(),
                 _response_tombstone_dir()):
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


@contextmanager
def _response_lock():
    ensure_quarantine()
    fd = os.open(_response_lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _strict_json(path):
    with open(path, "r") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _write_txn(txn):
    txn["updated_at"] = now_iso()
    save_json(_quarantine_txn(txn["id"]), txn)


def _object_digest(path):
    """Digest content, tree shape, symlink targets, and stat metadata.

    The digest is independent of the root pathname, so it remains stable across
    quarantine/restore renames. Internal symlinks are recorded, never followed.
    """
    if os.path.isfile(path) and not os.path.islink(path):
        st = os.lstat(path)
        return "file:%s:%o:%d:%d:%d" % (
            sha256(path), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid,
            st.st_mtime_ns)
    if not os.path.isdir(path) or os.path.islink(path):
        return None
    h = hashlib.sha256()

    def add_entry(full, rel):
        st = os.lstat(full)
        if stat.S_ISLNK(st.st_mode):
            kind, content = "link", os.readlink(full)
        elif stat.S_ISREG(st.st_mode):
            kind, content = "file", sha256(full) or "unreadable"
        elif stat.S_ISDIR(st.st_mode):
            kind, content = "dir", ""
        else:
            kind, content = "other", ""
        row = [rel, kind, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid,
               st.st_nlink, st.st_size, st.st_mtime_ns,
               getattr(st, "st_flags", 0), content]
        h.update((json.dumps(row, separators=(",", ":")) + "\n").encode())

    add_entry(path, ".")
    for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        for name in list(dirs):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path)
            add_entry(full, rel)
            if os.path.islink(full):
                dirs.remove(name)
        for name in files:
            full = os.path.join(root, name)
            add_entry(full, os.path.relpath(full, path))
    return "tree:" + h.hexdigest()


def _capture_identity(path):
    st = os.lstat(path)
    return {
        "dev": st.st_dev, "ino": st.st_ino,
        "kind": "app" if stat.S_ISDIR(st.st_mode) else "file",
        "nlink": st.st_nlink, "size": st.st_size,
        "mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid,
        "mtime_ns": st.st_mtime_ns, "atime_ns": st.st_atime_ns,
        "flags": getattr(st, "st_flags", 0), "digest": _object_digest(path),
    }


def _identity_matches(path, identity):
    try:
        current = _capture_identity(path)
    except (OSError, ValueError):
        return False
    return all(current.get(k) == identity.get(k)
               for k in ("dev", "ino", "kind", "nlink", "digest"))


def _valid_app_bundle(path):
    if not path.lower().endswith(".app") or not os.path.isdir(path):
        return False
    info = os.path.join(path, "Contents", "Info.plist")
    try:
        with open(info, "rb") as f:
            data = plistlib.load(f)
        exe = data.get("CFBundleExecutable") if isinstance(data, dict) else None
    except Exception:
        return False
    if not isinstance(exe, str) or not exe or os.path.basename(exe) != exe:
        return False
    executable = os.path.join(path, "Contents", "MacOS", exe)
    try:
        mode = os.lstat(executable).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def _validate_app_tree(path):
    """Reject bundle shapes whose live aliases would defeat containment."""
    root = os.path.realpath(path)
    for walk_root, dirs, files in os.walk(path, topdown=True, followlinks=False):
        for name in list(dirs) + files:
            item = os.path.join(walk_root, name)
            st = os.lstat(item)
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(item)
                try:
                    inside = os.path.commonpath((root, target)) == root
                except ValueError:
                    inside = False
                if not inside:
                    return False, "external symlink: %s" % item
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink != 1:
                    return False, "hard-linked file: %s" % item
            elif not stat.S_ISDIR(st.st_mode):
                return False, "special file: %s" % item
    return True, ""


def _rename_exclusive(src, dst):
    """Atomic rename that fails rather than overwriting a raced destination."""
    if sys.platform == "darwin":
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.renameatx_np
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p,
                       ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        if fn(-2, os.fsencode(src), -2, os.fsencode(dst), 0x00000004) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), dst)
        return
    # Development fallback. Production Aegis is macOS-only and always takes the
    # renameatx_np path above.
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "destination exists", dst)
    os.rename(src, dst)


def _sync_move(src, dst):
    _sync_dir(os.path.dirname(src))
    if os.path.dirname(src) != os.path.dirname(dst):
        _sync_dir(os.path.dirname(dst))


def _seal(qid):
    try:
        os.chmod(_quarantine_sealed(qid), 0o000)
        _sync_dir(_quarantine_item(qid))
    except OSError:
        pass


def _unseal(qid):
    os.chmod(_quarantine_sealed(qid), 0o700)


def _manifest_record(txn):
    identity = txn.get("identity") or {}
    return {
        "id": txn.get("id"), "orig_path": txn.get("original_path"),
        "sha256": txn.get("sha256"), "size": identity.get("size"),
        "mode": identity.get("mode"), "uid": identity.get("uid"),
        "gid": identity.get("gid"), "detection": txn.get("detection"),
        "ts": txn.get("created_at"), "kind": identity.get("kind"),
        "phase": txn.get("phase"),
    }


def _iter_transactions():
    ensure_quarantine()
    for name in sorted(os.listdir(QUARANTINE_DIR)):
        if name.startswith(".") or name == "manifest.json":
            continue
        path = os.path.join(QUARANTINE_DIR, name)
        if not os.path.isdir(path):
            continue
        try:
            yield name, _strict_json(os.path.join(path, "txn.json"))
        except Exception as e:
            yield name, {"id": name, "phase": "CORRUPT", "error": str(e)}


def _rebuild_quarantine_manifest():
    manifest = {}
    for qid, txn in _iter_transactions():
        if txn.get("phase") in ("QUARANTINED", "REVIEW_REQUIRED"):
            manifest[qid] = _manifest_record(txn)
    save_json(QUARANTINE_MANIFEST, manifest)
    return manifest


def _remove_object(path):
    if os.path.isdir(path) and not os.path.islink(path):
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for name in files:
                try:
                    item = os.path.join(root, name)
                    if not os.path.islink(item):
                        os.chmod(item, 0o600)
                except OSError:
                    pass
            for name in dirs:
                try:
                    item = os.path.join(root, name)
                    if not os.path.islink(item):
                        os.chmod(item, 0o700)
                except OSError:
                    pass
        os.chmod(path, 0o700)
        shutil.rmtree(path)
    else:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        os.remove(path)


def _write_tombstone(txn, outcome):
    tomb = dict(txn)
    tomb["phase"] = outcome
    tomb["completed_at"] = now_iso()
    save_json(os.path.join(_response_tombstone_dir(),
                           "%s.json" % txn["id"]), tomb)


def _recover_quarantine_locked():
    """Reconcile durable journals with filesystem reality; safe to repeat."""
    for qid, txn in list(_iter_transactions()):
        if txn.get("phase") == "CORRUPT":
            continue
        phase = txn.get("phase")
        source = txn.get("original_path")
        identity = txn.get("identity") or {}
        sealed = _quarantine_sealed(qid)
        payload = _quarantine_payload(qid)
        if os.path.isdir(sealed):
            try:
                _unseal(qid)
            except OSError:
                pass
        source_ok = bool(source and _identity_matches(source, identity))
        payload_ok = _identity_matches(payload, identity)

        if phase == "PREPARED":
            if source_ok and not os.path.lexists(payload):
                shutil.rmtree(_quarantine_item(qid), ignore_errors=True)
                continue
            if not os.path.lexists(source) and payload_ok:
                txn["phase"] = "QUARANTINED"
                txn["recovered_at"] = now_iso()
                _write_txn(txn)
            else:
                txn["phase"] = "REVIEW_REQUIRED"
                txn["recovery_error"] = "ambiguous PREPARED filesystem state"
                _write_txn(txn)
        elif phase == "RESTORE_PREPARED":
            dest = txn.get("restore_path")
            dest_ok = bool(dest and _identity_matches(dest, identity))
            if payload_ok and not (dest and os.path.lexists(dest)):
                txn["phase"] = "QUARANTINED"
                _write_txn(txn)
            elif dest_ok and not os.path.lexists(payload):
                txn["phase"] = "RESTORED"
                _write_txn(txn)
            else:
                txn["phase"] = "REVIEW_REQUIRED"
                txn["recovery_error"] = "ambiguous restore filesystem state"
                _write_txn(txn)
        elif phase in ("DESTROY_PREPARED", "DESTROYING"):
            trash = os.path.join(_response_trash_dir(), qid)
            for candidate in (payload, trash):
                if os.path.lexists(candidate):
                    _remove_object(candidate)
            txn["phase"] = "DESTROYED"
            _write_txn(txn)

        phase = txn.get("phase")
        if phase == "QUARANTINED" and not txn.get("audit_terminal"):
            if log_action("quarantine", txn.get("original_path"),
                          "recovered-ok", id=qid,
                          digest=identity.get("digest")):
                txn["audit_terminal"] = True
                _write_txn(txn)
        elif phase == "RESTORED":
            dest = txn.get("restore_path")
            if dest and _identity_matches(dest, identity):
                _write_tombstone(txn, "RESTORED")
                if log_action("restore", txn.get("original_path"), "recovered-ok",
                              id=qid, dest=dest):
                    shutil.rmtree(_quarantine_item(qid), ignore_errors=True)
                    continue
        elif phase == "DESTROYED":
            _write_tombstone(txn, "DESTROYED")
            if log_action("destroy", txn.get("original_path"), "recovered-ok",
                          id=qid):
                shutil.rmtree(_quarantine_item(qid), ignore_errors=True)
                continue
        if txn.get("phase") in ("QUARANTINED", "REVIEW_REQUIRED") \
                and os.path.isdir(sealed):
            _seal(qid)
    _rebuild_quarantine_manifest()


def recover_quarantine():
    with _response_lock():
        _recover_quarantine_locked()
    return 0


def log_action(action, target, result, **extra):
    """Checked, durable audit append. False means the action must not proceed."""
    rec = {"ts": now_iso(), "action": action, "target": target, "result": result}
    rec.update(extra)
    rec = _redact_value(rec)
    data = (json.dumps(rec, sort_keys=True) + "\n").encode("utf-8")
    try:
        ensure_state()
        _rotate_log(ACTION_LOG)
        fd = os.open(ACTION_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("short action-log write")
            _sync_fd(fd)
        finally:
            os.close(fd)
        os.chmod(ACTION_LOG, 0o600)
        _sync_dir(os.path.dirname(ACTION_LOG))
        log_run("%s %s -> %s" % (action, target, result))
        return True
    except Exception as e:
        log_run("AUDIT FAILURE %s %s -> %s (%s)" %
                (action, target, result, e))
        return False


# Top-level paths whose removal/quarantine would be catastrophic — refuse even
# though they exist and are "files" to os. HOME itself and any ancestor of HOME
# are added dynamically in _is_protected_path.
_PROTECTED_EXACT = frozenset((
    "/", "/Users", "/Applications", "/System", "/Library", "/bin", "/sbin",
    "/usr", "/etc", "/var", "/private", "/opt", HOME))


def _is_protected_path(path):
    """True if `path` must never be quarantined/destroyed. Refuses SIP/system/
    Apple locations (we can't and shouldn't touch them), Aegis's own files, the
    quarantine store itself, $HOME, and any ANCESTOR of $HOME (so a mistyped
    parent dir can't take the home directory with it)."""
    if not path:
        return True
    rp = os.path.realpath(path)
    if rp in _PROTECTED_EXACT:
        return True
    if any(rp == p or rp.startswith(p.rstrip("/") + "/") for p in TRUSTED_PREFIXES):
        return True
    # Aegis's own state, store, and script. Compare against REAL paths so a
    # symlinked ~/.aegis or script location is still covered (same reason as HOME).
    self_rp = os.path.realpath(_SELF_PATH)
    state_rp = os.path.realpath(STATE_DIR)
    if rp == self_rp or rp == state_rp or rp.startswith(state_rp + os.sep):
        return True
    # HOME itself, or any ANCESTOR of HOME (e.g. "/Users") — protects the home
    # tree. Compare against the REAL path of HOME so a symlinked/relocated home
    # (networked mount, /var-style indirection) is still covered.
    home_rp = os.path.realpath(HOME)
    if rp == home_rp or home_rp.startswith(rp.rstrip("/") + "/"):
        return True
    return False


def cmd_quarantine(path, detection="manual"):
    """Atomically confine a file or valid .app bundle in a durable transaction."""
    rp = os.path.realpath(path)
    if not os.path.lexists(path) or not os.path.exists(rp):
        print("refuse: %s does not exist" % path)
        log_action("quarantine", rp, "refused-missing")
        return 1
    if os.path.islink(path):
        # We resolved with realpath; refuse to act through a symlink to avoid
        # quarantining an unexpected target.
        print("refuse: %s is a symlink; pass the real target path" % path)
        log_action("quarantine", path, "refused-symlink")
        return 1
    is_app = os.path.isdir(rp) and _valid_app_bundle(rp)
    if os.path.isdir(rp) and not is_app:
        print("refuse: %s is a directory; only valid .app bundles can be "
              "quarantined as a tree" % rp)
        log_action("quarantine", rp, "refused-directory")
        return 1
    if not is_app and not os.path.isfile(rp):
        print("refuse: %s is not a regular file or valid .app" % rp)
        log_action("quarantine", rp, "refused-not-regular")
        return 1
    if is_app:
        safe_tree, unsafe_reason = _validate_app_tree(rp)
        if not safe_tree:
            print("refuse: unsafe app bundle tree (%s)" % unsafe_reason)
            log_action("quarantine", rp, "refused-unsafe-app-tree",
                       reason=unsafe_reason)
            return 1
    if _is_protected_path(rp):
        print("refuse: %s is a protected system/Aegis path and will not be "
              "quarantined" % rp)
        log_action("quarantine", rp, "refused-protected")
        return 1

    identity = _capture_identity(rp)
    if identity["kind"] == "file" and identity["nlink"] != 1:
        print("refuse: %s has %d hard links; moving one name would not contain "
              "the object" % (rp, identity["nlink"]))
        log_action("quarantine", rp, "refused-hardlinks",
                   nlink=identity["nlink"])
        return 1
    ensure_quarantine()
    if identity["dev"] != os.stat(QUARANTINE_DIR).st_dev:
        print("refuse: %s is on a different filesystem; cross-volume copy/delete "
              "is not crash-safe" % rp)
        log_action("quarantine", rp, "refused-cross-volume")
        return 1
    token = identity["digest"].split(":")[1][:10]
    qid = "%s-%s" % (datetime.now().strftime("%Y%m%dT%H%M%S%f"), token)
    item_dir = _quarantine_item(qid)
    payload = _quarantine_payload(qid)
    txn = {
        "schema": 1, "id": qid, "operation": "quarantine",
        "phase": "PREPARED", "original_path": rp, "identity": identity,
        "sha256": sha256(rp) if identity["kind"] == "file" else None,
        "detection": detection, "created_at": now_iso(), "audit_terminal": False,
    }
    with _response_lock():
        _recover_quarantine_locked()
        os.makedirs(_quarantine_sealed(qid), mode=0o700, exist_ok=False)
        _write_txn(txn)  # durable PREPARED always precedes the move
        if not log_action("quarantine", rp, "prepared", id=qid,
                          digest=identity["digest"]):
            shutil.rmtree(item_dir, ignore_errors=True)
            print("refuse: action audit is unavailable; source left untouched")
            return 1
        if not _identity_matches(rp, identity):
            shutil.rmtree(item_dir, ignore_errors=True)
            print("refuse: target changed after approval; source left untouched")
            log_action("quarantine", rp, "refused-identity-changed", id=qid)
            return 1
        _rename_exclusive(rp, payload)
        _sync_move(rp, payload)
        _response_checkpoint("after-quarantine-rename")
        if not _identity_matches(payload, identity):
            txn["phase"] = "REVIEW_REQUIRED"
            txn["recovery_error"] = "staged identity mismatch"
            _write_txn(txn)
            _seal(qid)
            _rebuild_quarantine_manifest()
            print("error: moved object failed identity verification; retained for review")
            return 1
        txn["phase"] = "QUARANTINED"
        _write_txn(txn)
        _seal(qid)
        _rebuild_quarantine_manifest()
        if not log_action("quarantine", rp, "ok", id=qid,
                          digest=identity["digest"]):
            print("error: object is contained, but terminal audit append failed; "
                  "recovery will retry")
            return 1
        txn["audit_terminal"] = True
        _write_txn(txn)
    print("Quarantined: %s\n  id:      %s\n  store:   sealed native object "
          "(metadata-preserving, same-volume transaction)\n  restore: aegis.py "
          "restore %s\n  destroy: aegis.py destroy %s --yes (irreversible)"
          % (rp, qid, qid, qid))
    return 0


def cmd_quarantine_list():
    recover_quarantine()
    manifest = load_json(QUARANTINE_MANIFEST, {})
    if not manifest:
        print("Quarantine store is empty.")
        return 0
    print("# Quarantine store (%d item%s)\n"
          % (len(manifest), "" if len(manifest) == 1 else "s"))
    for qid in sorted(manifest):
        m = manifest[qid]
        print("  %s  %s\n      from %s  (%s bytes, detected: %s)"
              % (qid, m.get("ts", "?"), m.get("orig_path", "?"),
                 m.get("size", "?"), m.get("detection", "?")))
    print("\nrestore: aegis.py restore <id>   destroy: aegis.py destroy <id> --yes")
    return 0


def cmd_restore(qid):
    """Restore by exclusive native rename; never overwrite a raced occupant."""
    with _response_lock():
        _recover_quarantine_locked()
        try:
            txn = _strict_json(_quarantine_txn(qid))
        except Exception:
            print("no such quarantine id: %s (see: aegis.py quarantine-list)" % qid)
            return 1
        if txn.get("phase") != "QUARANTINED":
            print("refuse: %s is in phase %s, not safely restorable"
                  % (qid, txn.get("phase")))
            return 1
        payload = _quarantine_payload(qid)
        _unseal(qid)
        if not _identity_matches(payload, txn["identity"]):
            txn["phase"] = "REVIEW_REQUIRED"
            txn["recovery_error"] = "payload identity mismatch before restore"
            _write_txn(txn)
            _seal(qid)
            _rebuild_quarantine_manifest()
            print("error: quarantine payload failed integrity verification")
            return 1
        dest = txn["original_path"]
        if os.path.lexists(dest):
            dest = "%s.restored.%s" % (dest, qid)
            n = 1
            while os.path.lexists(dest):
                dest = "%s.restored.%s.%d" % (txn["original_path"], qid, n)
                n += 1
            print("note: %s now exists; restoring to %s"
                  % (txn["original_path"], dest))
        txn["operation"] = "restore"
        txn["restore_path"] = dest
        txn["phase"] = "RESTORE_PREPARED"
        _write_txn(txn)
        if not log_action("restore", txn["original_path"], "prepared",
                          id=qid, dest=dest):
            txn["phase"] = "QUARANTINED"
            _write_txn(txn)
            _seal(qid)
            print("refuse: action audit is unavailable; item remains quarantined")
            return 1
        _response_checkpoint("after-restore-prepared")
        try:
            _rename_exclusive(payload, dest)
        except OSError as e:
            txn["phase"] = "QUARANTINED"
            txn["restore_error"] = str(e)
            _write_txn(txn)
            _seal(qid)
            print("error: restore destination became occupied; item remains "
                  "quarantined")
            return 1
        _sync_move(payload, dest)
        _response_checkpoint("after-restore-rename")
        if not _identity_matches(dest, txn["identity"]):
            txn["phase"] = "REVIEW_REQUIRED"
            txn["recovery_error"] = "restored identity mismatch"
            _write_txn(txn)
            print("error: restored object failed identity verification")
            return 1
        txn["phase"] = "RESTORED"
        _write_txn(txn)
        _write_tombstone(txn, "RESTORED")
        if not log_action("restore", txn["original_path"], "ok",
                          id=qid, dest=dest):
            print("error: object is restored, but terminal audit append failed; "
                  "recovery will retry")
            return 1
        shutil.rmtree(_quarantine_item(qid), ignore_errors=True)
        _rebuild_quarantine_manifest()
    print("Restored %s -> %s (verified content and native metadata identity)."
          % (qid, dest))
    return 0


def cmd_destroy(qid, confirmed=False):
    """IRREVERSIBLE verified deletion of an already-quarantined object."""
    with _response_lock():
        _recover_quarantine_locked()
        try:
            txn = _strict_json(_quarantine_txn(qid))
        except Exception:
            print("no such quarantine id: %s" % qid)
            return 1
        if txn.get("phase") != "QUARANTINED":
            print("refuse: %s is in phase %s" % (qid, txn.get("phase")))
            return 1
        if not confirmed:
            print("REFUSING without confirmation. `destroy` is IRREVERSIBLE and "
                  "the item cannot be restored afterwards.\n  Item: %s (from %s)"
                  "\n  Re-run: aegis.py destroy %s --yes"
                  % (qid, txn.get("original_path"), qid))
            log_action("destroy", txn.get("original_path"), "refused-confirmation",
                       id=qid)
            return 1
        txn["operation"] = "destroy"
        txn["phase"] = "DESTROY_PREPARED"
        txn["approval"] = hashlib.sha256(
            (qid + "\0" + txn["identity"]["digest"]).encode()).hexdigest()
        _write_txn(txn)
        if not log_action("destroy", txn.get("original_path"), "prepared",
                          id=qid, approval=txn["approval"]):
            txn["phase"] = "QUARANTINED"
            _write_txn(txn)
            _seal(qid)
            print("refuse: action audit is unavailable; item remains quarantined")
            return 1
        _response_checkpoint("after-destroy-prepared")
        _unseal(qid)
        payload = _quarantine_payload(qid)
        if not _identity_matches(payload, txn["identity"]):
            txn["phase"] = "REVIEW_REQUIRED"
            _write_txn(txn)
            _seal(qid)
            print("error: payload failed integrity verification; refusing destroy")
            return 1
        trash = os.path.join(_response_trash_dir(), qid)
        _rename_exclusive(payload, trash)
        _sync_move(payload, trash)
        txn["phase"] = "DESTROYING"
        _write_txn(txn)
        _remove_object(trash)
        _sync_dir(_response_trash_dir())
        if os.path.lexists(trash):
            print("error: verified deletion failed; recovery will retry")
            return 1
        txn["phase"] = "DESTROYED"
        _write_txn(txn)
        _write_tombstone(txn, "DESTROYED")
        if not log_action("destroy", txn.get("original_path"), "ok", id=qid,
                          approval=txn["approval"]):
            print("error: deletion completed, but terminal audit append failed; "
                  "recovery will retry")
            return 1
        shutil.rmtree(_quarantine_item(qid), ignore_errors=True)
        _rebuild_quarantine_manifest()
    print("Destroyed %s (from %s). Verified deletion completed; this cannot be "
          "undone. APFS/SSD secure erasure is not claimed."
          % (qid, txn.get("original_path")))
    return 0


# comm basenames we refuse to kill even if same-user — killing these wedges the
# session. (kernel_task/launchd/WindowServer run as root/_windowserver, so the
# same-user gate already excludes them; this is defence-in-depth for the rest.)
_PROTECTED_COMMS = frozenset((
    "launchd", "logind", "loginwindow", "WindowServer", "Dock", "Finder",
    "SystemUIServer", "coreauthd", "opendirectoryd", "cfprefsd", "Terminal",
    "iTerm2", "sshd", "aegis.py", "python3", "python"))


def cmd_kill(pid):
    """Terminate a SAME-USER process (SIGTERM, then SIGKILL if it survives).
    Refuses other users' processes (we have no right and no reliable argv),
    Aegis's own process tree, and a small set of session-critical comms."""
    try:
        pid = int(pid)
    except Exception:
        print("usage: aegis.py kill <pid>")
        return 1
    if pid in (0, 1, os.getpid(), os.getppid()):
        print("refuse: will not kill pid %d (self/parent/init)" % pid)
        log_action("kill", str(pid), "refused-self")
        return 1
    out, _, rc = run(["ps", "-o", "uid=,comm=", "-p", str(pid)], timeout=8)
    if rc != 0 or not out.strip():
        print("no such process: %d" % pid)
        return 1
    parts = out.strip().split(None, 1)
    puid = parts[0]
    comm = os.path.basename(parts[1]) if len(parts) > 1 else "?"
    if puid != str(os.getuid()):
        print("refuse: pid %d belongs to uid %s, not you; Aegis only acts on "
              "your own processes" % (pid, puid))
        log_action("kill", str(pid), "refused-other-user", uid=puid, comm=comm)
        return 1
    if comm in _PROTECTED_COMMS:
        print("refuse: pid %d is a session-critical process (%s)" % (pid, comm))
        log_action("kill", str(pid), "refused-protected-comm", comm=comm)
        return 1
    import signal as _signal
    try:
        os.kill(pid, _signal.SIGTERM)
    except ProcessLookupError:
        print("pid %d already gone" % pid)
        return 0
    except PermissionError:
        print("refuse: not permitted to signal pid %d" % pid)
        return 1
    for _ in range(10):  # up to ~1s for a graceful exit
        time.sleep(0.1)
        if run(["ps", "-p", str(pid)], timeout=5)[2] != 0:
            log_action("kill", str(pid), "ok-sigterm", comm=comm)
            print("Killed pid %d (%s) with SIGTERM." % (pid, comm))
            return 0
    try:
        os.kill(pid, _signal.SIGKILL)
    except Exception:
        pass
    gone = run(["ps", "-p", str(pid)], timeout=5)[2] != 0
    log_action("kill", str(pid), "ok-sigkill" if gone else "failed", comm=comm)
    print("%s pid %d (%s)%s" % ("Killed" if gone else "Could NOT kill", pid, comm,
                                " with SIGKILL." if gone else " — still running."))
    return 0 if gone else 1


def cmd_sandbox(path, extra_args=None):
    """Refuse host-side sample execution.

    ``sandbox-exec`` is deprecated, its policy language is not a supported
    third-party security boundary, and a useful process profile still exposes
    host data and IPC. Aegis therefore performs static observation only; dynamic
    analysis belongs in a disposable VM with no shared credentials or folders.
    """
    rp = os.path.realpath(path)
    if not os.path.isfile(rp):
        print("refuse: %s is not a file" % rp)
        return 1
    log_action("sandbox", rp, "refused-host-execution")
    print("refuse: Aegis will not execute a suspect sample on the host. Use static "
          "inspection here, or a disposable VM with no shared folders, clipboard, "
          "credentials, or production network for dynamic analysis.")
    return 2


def cmd_neutralize(plist_path):
    """Ordered kill-chain for a launchd-backed threat (a persistence finding):
      1) bootout the launchd job so it can't relaunch,
      2) SIGKILL any still-running same-user process for its program,
      3) quarantine the .plist (and, if it lives in a risky location, its binary).
    Unloading BEFORE killing matters: a KeepAlive job killed first is immediately
    respawned by launchd, so we remove the job definition first."""
    rp = os.path.realpath(plist_path)
    if not os.path.isfile(rp) or not rp.endswith(".plist"):
        print("usage: aegis.py neutralize <path-to-launchd-.plist>")
        return 1
    if _is_protected_path(rp):
        print("refuse: %s is a protected/system path" % rp)
        return 1
    try:
        with open(rp, "rb") as f:
            pl = plistlib.load(f)
    except Exception as e:
        print("error: could not parse plist (%s)" % e)
        return 1
    label = pl.get("Label") or os.path.basename(rp)[:-6]
    program, _args = _plist_program(pl if isinstance(pl, dict) else {})
    is_daemon = "/Library/LaunchDaemons/" in rp and not rp.startswith(HOME)

    print("Neutralizing launchd job: %s" % label)
    # 1) bootout — user domain is gui/<uid>; system LaunchDaemons need root.
    if is_daemon:
        print("  [1/3] system LaunchDaemon — bootout needs root; run:\n"
              "        sudo launchctl bootout system %s" % rp)
        log_action("neutralize", rp, "daemon-needs-root", label=label)
    else:
        dom = "gui/%d/%s" % (os.getuid(), label)
        _o, _e, brc = run(["launchctl", "bootout", dom], timeout=10)
        # Also try the file form; both are accepted across versions.
        run(["launchctl", "bootout", "gui/%d" % os.getuid(), rp], timeout=10)
        print("  [1/3] bootout %s -> %s" % (dom, "ok" if brc == 0 else "not loaded/none"))
        log_action("neutralize", rp, "bootout-%s" % ("ok" if brc == 0 else "noop"),
                   label=label)

    # 2) kill any surviving same-user process for the program.
    killed = 0
    if program:
        out, _, rc = run(["ps", "-axo", "pid=,uid=,comm="], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                p = line.split(None, 2)
                if len(p) == 3 and p[1] == str(os.getuid()) and p[2] == program:
                    try:
                        import signal as _signal
                        os.kill(int(p[0]), _signal.SIGKILL)
                        killed += 1
                    except Exception:
                        pass
    print("  [2/3] killed %d running instance(s) of %s" % (killed, program or "?"))

    # 3) quarantine the plist (stops reload next login), then the binary if risky.
    print("  [3/3] quarantining artifacts:")
    rc_plist = cmd_quarantine(rp, detection="neutralize:%s" % label)
    if program and os.path.isfile(program) and is_risky_location(program) \
            and not _is_protected_path(program):
        cmd_quarantine(program, detection="neutralize:%s:binary" % label)
    return 0 if rc_plist == 0 else 1


def cmd_watchdog():
    """Dead-man's-switch check: is the monitor still beating? Meant to be run by
    a SECOND launchd agent or cron (the unprivileged mutual-watchdog), or by an
    external monitor. Exits non-zero and raises a DURABLE alert (notification +
    a sentinel the next interactive session sees) when the last heartbeat is
    missing-though-armed or older than the tolerance — precisely the state a
    killed / booted-out / frozen Aegis leaves behind. Idempotent: clears the
    sentinel once the beat is healthy again."""
    ensure_state()
    beat = read_heartbeat()
    # "Armed" must survive an attacker WIPING ~/.aegis: anchor on the launchd
    # plist (which lives OUTSIDE ~/.aegis) and the recorded install marker, not
    # only on the two deletable state files. Otherwise `rm -rf ~/.aegis` on an
    # installed Mac makes a DEAD monitor read as a never-installed one and the
    # watchdog returns OK — the exact same-uid suppression the dead-man's switch
    # exists to catch. A genuinely fresh, uninstalled box has no plist and no
    # state, so it is correctly "not armed" (no false alarm before install).
    armed = (bool(beat) or os.path.exists(BASELINE) or os.path.exists(SELF_PLIST)
             or bool(load_json(SELFSTATE, {}).get("installed")))
    now = int(time.time())
    last = int(beat.get("epoch") or 0)
    age = now - last if last else None
    stale = armed and (age is None or age > HEARTBEAT_STALE_SECS)
    if stale:
        human = ("no heartbeat on record" if age is None
                 else "last beat %d min ago (> %d min tolerance)"
                 % (age // 60, HEARTBEAT_STALE_SECS // 60))
        msg = ("Aegis watchdog: the monitor is NOT beating — %s. It may have been "
               "killed, unloaded (launchctl bootout), frozen, or the Mac was "
               "asleep. Verify the agent is running (`launchctl list | grep "
               "aegis`) and re-run install.sh if needed." % human)
        try:
            with open(WATCHDOG_ALERT, "w") as f:
                f.write("%s  %s\n" % (now_iso(), msg))
            os.chmod(WATCHDOG_ALERT, 0o600)
        except Exception:
            pass
        notify("Aegis watchdog: monitor not beating", human)
        log_run("watchdog: STALE (%s)" % human)
        print(msg)
        return 1
    # Healthy — clear any stale sentinel from a prior firing.
    try:
        if os.path.exists(WATCHDOG_ALERT):
            os.remove(WATCHDOG_ALERT)
    except Exception:
        pass
    print("Aegis watchdog: OK — last heartbeat %d min ago (pid %s)."
          % ((age or 0) // 60, beat.get("pid", "?")))
    return 0


def cmd_bastion():
    """OPT-IN privileged tier: surface Apple's XProtect Behavioral Service
    (Bastion) violations. Apple records stealer-shape behavior (a process
    touching browser data / Messages / the keychain) to a root-only SQLite DB and
    NEVER alerts the user on it — so this is free high-signal coverage no
    unprivileged layer can reach. Needs `sudo` (the DB is 0600 root); read-only.
    Prints how to run it and exits 2 when the DB can't be read, so the default
    unprivileged scan path is unaffected."""
    ensure_state()
    if not os.path.exists(XPDB_PATH):
        print("XProtect Behavioral (Bastion) DB not present at %s — this macOS "
              "build may not ship it, or it has no records yet." % XPDB_PATH)
        return 2
    if not os.access(XPDB_PATH, os.R_OK):
        print("Bastion DB is root-only (0600). Re-run with elevation:\n"
              "    sudo %s bastion" % _SELF_PATH)
        return 2
    rows = _parse_xpdb(XPDB_PATH)
    if not rows:
        print("Bastion DB read OK — no behavioral violations recorded.")
        return 0
    print("# XProtect Behavioral (Bastion) violations — %d recorded\n" % len(rows))
    for rule, proc, item, ts in rows[:200]:
        print("  🟥 %s  rule=%s  process=%s%s"
              % (ts or "?", rule, proc, ("  target=%s" % item) if item else ""))
    print("\nApple records these but does not alert on them. A process touching "
          "browser/keychain/Messages data it shouldn't is a stealer signature — "
          "investigate any you don't recognize.")
    log_run("bastion: surfaced %d XPdb rows" % len(rows))
    return 0


HELP = """aegis.py - personal macOS security monitor (detect + opt-in response)

 DETECT (default; runs on a launchd interval, never destructive)
  scan             run all checks once; update report; alert on new HIGH+
  report           print the latest report
  status           print hardening, XProtect, sensor coverage, and incidents
  doctor           verify actual coverage/liveness (unknown is never green)
  incidents [all]  list active incidents (or complete history)
  incident <id> [ack|investigate|contain|recover|monitor|resolve|reopen|
                 false-positive|benign-positive]
                   ...the two dismissals are recorded separately and feed
                   different tuning queues: false-positive = the DETECTION was
                   wrong (tune the rule), benign-positive = the event was real
                   but authorized (suppress this instance, rule is fine)
  replay [days]    backtest the CURRENT correlation logic against recorded
                   history (default 30d). Read-only: opens no incident, sends
                   no notification — run it after changing detection logic
  baseline         reset the known-good persistence baseline to current state
  allow <path>     suppress future alerts for findings matching <path>
  vt <path|sha256> OPT-IN VirusTotal reputation for a file/hash (sends only the
                   hash, never the file; needs AEGIS_VT_API_KEY or ~/.aegis/vt_key;
                   the scan path stays local-only regardless)
  canary [remove]  plant (or remove) ransomware canary/honeypot files
  watch [secs]     event-driven monitor: kqueue rescan seconds after a watched
                   path changes + a full scan every [secs] (default 600) as a
                   floor. Production: bash install.sh watch
  watchdog         dead-man's switch: exit non-zero + alert if the monitor has
                   stopped beating (run from a 2nd launchd agent/cron as a
                   mutual-watchdog, or externally)
  bastion          OPT-IN, needs sudo: surface Apple's XProtect Behavioral
                   (Bastion) violations Apple records but never alerts on

 RESPOND (opt-in; you run these by hand on a reviewed finding — never automatic)
  quarantine <path>      atomically confine a file or valid .app bundle
  quarantine-list        list the quarantine store (ids to restore/destroy)
  restore <id>           reverse the native move without overwriting
  destroy <id> --yes     verified deletion from quarantine (IRREVERSIBLE)
  kill <pid>             terminate one of YOUR processes (SIGTERM->SIGKILL)
  sandbox <path> [args]  refuses host execution; use an isolated VM dynamically
  neutralize <plist>     kill-chain a launchd threat: bootout->kill->quarantine
"""


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "scan"
    if cmd == "scan":
        return cmd_scan()
    if cmd == "report":
        return cmd_report()
    if cmd == "status":
        return cmd_status()
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "preflight":  # installer-only
        return cmd_preflight()
    if cmd == "mark-uninstalled":  # uninstaller-only
        return cmd_mark_uninstalled()
    if cmd == "incidents":
        return cmd_incidents(show_all=(len(argv) > 2 and argv[2] == "all"))
    if cmd == "incident" and len(argv) > 2:
        return cmd_incident(argv[2], argv[3] if len(argv) > 3 else None,
                            argv[4] if len(argv) > 4 else None)
    if cmd == "replay":
        try:
            days = int(argv[2]) if len(argv) > 2 else 30
        except ValueError:
            print("usage: aegis.py replay [days]")
            return 1
        return cmd_replay(days)
    if cmd == "baseline":
        return cmd_baseline()
    if cmd == "baseline-unverified":  # installer-only: adopt, never bless
        return cmd_baseline(trust="unverified")
    if cmd == "allow" and len(argv) > 2:
        return cmd_allow(argv[2])
    if cmd == "vt" and len(argv) > 2:
        return cmd_vt(argv[2])
    if cmd == "canary":
        return cmd_canary(argv[2] if len(argv) > 2 else "plant")
    if cmd == "watch":
        return cmd_watch(int(argv[2]) if len(argv) > 2 else 600)
    if cmd == "watchdog":
        return cmd_watchdog()
    if cmd == "bastion":
        return cmd_bastion()
    # --- response tier (opt-in) ---
    if cmd == "quarantine" and len(argv) > 2:
        return cmd_quarantine(argv[2])
    if cmd in ("quarantine-list", "ql"):
        return cmd_quarantine_list()
    if cmd == "restore" and len(argv) > 2:
        return cmd_restore(argv[2])
    if cmd == "destroy" and len(argv) > 2:
        return cmd_destroy(argv[2], confirmed=("--yes" in argv[3:]))
    if cmd == "kill" and len(argv) > 2:
        return cmd_kill(argv[2])
    if cmd == "sandbox" and len(argv) > 2:
        return cmd_sandbox(argv[2], argv[3:])
    if cmd == "neutralize" and len(argv) > 2:
        return cmd_neutralize(argv[2])
    sys.stdout.write(HELP)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
