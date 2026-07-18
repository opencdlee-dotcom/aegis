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
doctrine): quarantine neutralizes and confines a file to a REVERSIBLE store,
restore undoes it byte-for-byte (a false positive costs minutes, not data), and
destroy — the only irreversible verb — can act ONLY on an already-quarantined
item (quarantine-first, never-delete-first). Plus kill (same-user process),
sandbox (detonate a suspect binary in a deny-default Seatbelt jail), and
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

DESIGN PRINCIPLE (from the alert-fatigue literature): *log everything, alert
rarely, never repeat*. The first run establishes a SILENT baseline (no day-one
alert storm - the KnockKnock/LuLu "trust what's already installed" rule).
Afterwards only genuinely-new findings at >= HIGH severity raise a macOS
notification, and each fingerprint fires at most once. Everything is written to
a durable append-only log so nothing is missed if a notification is.

STATE  -> ~/.aegis/   (baseline.json, findings.jsonl, latest.md, seen.json,
                       quarantine/ store + manifest, actions.jsonl audit, ...)
USAGE  -> aegis.py [scan|report|status|baseline|allow <path>|vt <path|sha>|
                    canary|watch]
          aegis.py [quarantine <path>|quarantine-list|restore <id>|
                    destroy <id> --yes|kill <pid>|sandbox <path>|neutralize <plist>]
"""

import json
import os
import plistlib
import re
import select
import shutil
import subprocess
import sys
import time
import hashlib
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

# --- Response tier (opt-in; never automatic) --------------------------------- #
# The quarantine STORE: a confined, reversible holding area for neutralized
# threat files. Mirrors the industry ladder (SentinelOne Kill→Quarantine→
# Remediate, Defender's reversible store with restore metadata): quarantine
# MOVES a file here and neutralizes it, `restore` reverses it byte-identically,
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

# Neutralization key for the stored sample. This is deliberate OBFUSCATION, not
# cryptography: a repeating-key XOR renders the quarantined bytes non-executable
# (a double-click / accidental run can't launch it) and stops another on-host
# scanner — or Aegis itself on the next pass — from re-flagging the store as live
# malware (the classic AV "neutered sample" trick). XOR is symmetric, so `restore`
# reverses it exactly. It is NOT a confidentiality control and is not claimed as one.
_QUAR_XOR_KEY = b"AegisQuarantine\x17"  # 16 bytes

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
                      "/etc/pam.d", "/etc/sudoers.d", "/etc/ssh/sshd_config.d"]

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

# High-signal hostile shell/command patterns, shared by argument inspection
# (launchd/cron) and file-content scanning (shell rc). Each is a "download-and-
# run", "reverse shell", or "obfuscated-decode-and-exec" idiom — the live tail of
# a 2025-era ClickFix / AMOS infection chain.
_HOSTILE_CONTENT_RES = [
    (re.compile(r"\b(?:curl|wget|nscurl|fetch)\b[^\n|]*\bhttps?://", re.I), "network-fetch"),
    (re.compile(r"\|\s*(?:/bin/)?(?:ba|z|d)?sh\b", re.I), "pipe-to-shell"),
    # Require a real command boundary after the interpreter (space/EOL) so a `|`
    # INSIDE a quoted regex alternation — e.g. perl/sed `s{(a|node|b)}` — is not
    # mistaken for a shell pipe into `node`. A genuine pipe reads `… | osascript`.
    (re.compile(r"\|\s*(?:/usr/bin/)?(?:osascript|python[0-9.]*|perl|ruby|node|php)(?=\s|$)", re.I), "pipe-to-interpreter"),
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
]

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
    os.makedirs(STATE_DIR, exist_ok=True)


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def run(cmd, timeout=15):
    """Run a command, return (stdout, stderr, rc). Never raises."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
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
        with open(RUN_LOG, "a") as f:
            f.write("%s  %s\n" % (now_iso(), msg))
    except Exception:
        pass


def quarantine_origin(path):
    """Provenance from the com.apple.quarantine xattr, via Apple's `xattr` CLI
    (Python's os.getxattr is Linux-only — verified absent on macOS). Returns
    (present, agent): whether the file carries a Gatekeeper quarantine flag and
    the downloading agent name (Safari, Google Chrome, curl, Terminal, …).
    ABSENCE on a freshly-dropped executable is itself a signal — it means the
    file arrived by a channel that bypassed Gatekeeper (curl/scp/AirDrop/torrent),
    the exact side-load path AMOS/DMG-lure chains use."""
    out, _, rc = run(["xattr", "-p", "com.apple.quarantine", path], timeout=6)
    if rc != 0 or not out.strip():
        return (False, None)
    # value: flags;hex-timestamp;AgentName;UUID
    fields = out.strip().split(";")
    agent = fields[2].strip() if len(fields) >= 3 and fields[2].strip() else None
    return (True, agent)


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
    # Nanosecond mtime + size. int(st_mtime) alone is content-blind within a
    # single second: a same-length replacement in the same second would serve a
    # stale classification. st_mtime_ns closes that window.
    try:
        st = os.stat(path)
        return [st.st_mtime_ns, st.st_size]
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


def finding(severity, category, title, detail, fingerprint, **extra):
    f = {
        "ts": now_iso(),
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "fingerprint": fingerprint,
    }
    f.update(extra)
    return f


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
            rec["args"] = args
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


def _script_target(args, program=None):
    """The script an interpreter is told to run: the first path-like, non-flag
    argument after the interpreter binary. None if the process isn't interpreter-
    fronted (by resolved program OR args[0]) or no such argument exists."""
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
    joined = " ".join(str(a) for a in args)
    if _FETCH_RE.search(joined):
        return True
    return bool(_hostile_content(joined))


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
            args_changed = (old.get("args") or None) != (rec.get("args") or None)
            if prog_changed or env_changed or args_changed:
                what = "+".join(w for w, c in (
                    ("program/hash", prog_changed), ("env", env_changed),
                    ("args", args_changed)) if c)
                # Fold the current sha256/env/args into the fingerprint (sha256
                # alone is unchanged on an env-only mutation) so a real change
                # re-alerts but a steady mutated state does not storm.
                fp = hashlib.sha256(repr(
                    (rec.get("sha256"), rec.get("env"), rec.get("args"))
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
                    "%s: %s changed (%s -> %s)" % (
                        rec["label"], what, old.get("program"),
                        rec.get("program")),
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
                "%d active line(s): %s" % (len(lines), " | ".join(lines[:3])),
                "cron:user:%s" % hashlib.sha256(out.encode()).hexdigest()[:16]))
    return findings


# --------------------------------------------------------------------------- #
# Check 2: suspicious running processes
# --------------------------------------------------------------------------- #


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
    "python-oneliner", "eval-subshell"))
_FETCH_IDIOMS = frozenset(("network-fetch", "raw-ip-fetch"))


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
        snippet = argv if len(argv) <= 200 else argv[:197] + "..."
        findings.append(finding(
            top, "behavior", "Suspicious process behavior",
            "%s [%s]: %s" % (base, names, snippet),
            fp, program=argv.split(None, 1)[0] if argv else "",
            pid=pid, signals=names))
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
            snippet = cmd.strip()
            snippet = snippet if len(snippet) <= 200 else snippet[:197] + "..."
            findings.append(finding(
                top, "shell-history",
                "Hostile command in shell history",
                "%s [%s]: %s" % (os.path.basename(path), ", ".join(names), snippet),
                "shellhist:%s:%s" % (
                    os.path.basename(path),
                    hashlib.sha256(cmd.strip().encode()).hexdigest()[:16]),
                path=path, hostile=names))
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
        quar, agent = quarantine_origin(path)
        prov = ("via %s" % agent if agent else
                ("quarantined" if quar else
                 "NO quarantine flag — side-loaded (bypassed Gatekeeper)"))
        return [finding(
            "HIGH", "hot-dir", "Unsigned app bundle in watched folder",
            "%s [%s], modified %s, %s" % (path, sig["trust"], when, prov),
            "hotdir:app:%s:%s:%s" % (path, sig["trust"], sha),
            path=path, trust=sig["trust"], sha256=sha,
            quarantined=quar, download_agent=agent)]
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
            if st.st_mtime < cutoff:
                continue
            if not os.path.isfile(path):
                continue
            if not _is_macho(path):
                continue
            sig = classify_signature(path)
            if suspicious_sig(sig["trust"]):
                sha = sha256(path)  # content hash → path reuse ≠ same fingerprint
                quar, agent = quarantine_origin(path)
                prov = ("via %s" % agent if agent else
                        ("quarantined" if quar else "NO quarantine flag — side-loaded (bypassed Gatekeeper)"))
                findings.append(finding(
                    "HIGH", "hot-dir", "Unsigned executable in watched folder",
                    "%s [%s], modified %s, %s" % (
                        path, sig["trust"],
                        datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d"),
                        prov),
                    "hotdir:%s:%s:%s" % (path, sig["trust"], sha),
                    path=path, trust=sig["trust"], sha256=sha,
                    quarantined=quar, download_agent=agent))
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
# Check 4: hardening posture
# --------------------------------------------------------------------------- #


def check_hardening():
    findings = []

    out, _, _ = run(["csrutil", "status"])
    if "enabled" not in out.lower():
        findings.append(finding(
            "CRITICAL", "hardening", "System Integrity Protection is OFF",
            out.strip() or "csrutil status not 'enabled'", "hardening:sip:off"))

    out, _, _ = run(["spctl", "--status"])
    if "assessments enabled" not in out.lower():
        findings.append(finding(
            "HIGH", "hardening", "Gatekeeper assessments disabled",
            out.strip() or "spctl --status not enabled", "hardening:gatekeeper:off"))

    out, _, _ = run(["fdesetup", "status"])
    if "filevault is on" not in out.lower():
        findings.append(finding(
            "MEDIUM", "hardening", "FileVault disk encryption is OFF",
            out.strip() or "fdesetup reports not on", "hardening:filevault:off"))

    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    out, _, _ = run([fw, "--getglobalstate"])
    if "state = 0" in out.lower() or "disabled" in out.lower():
        findings.append(finding(
            "MEDIUM", "hardening", "Application Firewall is OFF",
            out.strip(), "hardening:firewall:off"))
    out, _, _ = run([fw, "--getstealthmode"])
    if "off" in out.lower():
        findings.append(finding(
            "LOW", "hardening", "Firewall stealth mode is off",
            out.strip(), "hardening:stealth:off"))

    # Remote login (SSH) - loaded launchd label implies enabled.
    lout, _, _ = run(["launchctl", "list"], timeout=8)
    if "com.openssh.sshd" in lout:
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
    could not be read this scan. `sfltool dumpbtm` is SLOW (~12s on a typical
    machine) and under scan-time load it can exceed the timeout; aegis.run()
    then returns empty. An empty result from a timeout/failure must NOT be
    recorded as 'no background items' — a Mac always has some (DisplayLink,
    auto-updaters …), so a false-empty adopted into the baseline would storm
    ~90 bogus 'new background item' findings the instant sfltool later succeeds.
    We therefore signal the non-answer as None (skipped by _scan_surfaces) and
    give sfltool generous headroom so the normal-but-slow case still succeeds."""
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
            team=rec.get("team"), url=url)

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
            team=rec.get("team"), url=url)

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
]


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
    # corrupted ground truth. We record each file's hash right after WE write it;
    # a mismatch at the next scan means it changed by a hand that wasn't ours.
    for name, path in (("allowlist", ALLOWLIST), ("baseline", BASELINE)):
        recorded = st.get("%s_sha" % name)
        cur_sha = sha256(path) if os.path.exists(path) else None
        # `recorded` is only set once record_selfstate saw the file exist, so a
        # truthy `recorded` means it existed. cur_sha is None => the file is now
        # gone (deletion — the more dangerous tamper: it forces the next scan onto
        # the first_run path, silently re-baselining current persistence as
        # known-good). A differing hash => modification. Both are tampering.
        if recorded and cur_sha != recorded:
            if cur_sha is None:
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
    # Record trust-store hashes so the NEXT scan can detect out-of-band edits.
    for name, path in (("allowlist", ALLOWLIST), ("baseline", BASELINE)):
        st["%s_sha" % name] = sha256(path) if os.path.exists(path) else None
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


def _scan_surfaces(baseline, corrupt, first_run):
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
        try:
            cur = snap_fn()
        except Exception:
            cur = None
        # A snapshot fn returns None when its backing command could not be read
        # this scan (e.g. sfltool/lsof timed out). That is a NON-ANSWER, not an
        # empty world: never adopt it as a baseline and never diff against it
        # (both would fabricate findings the moment the command next succeeds).
        # Skip the surface for this scan; the prior baseline is left intact.
        if cur is None:
            continue
        prior = baseline.get(key)
        if prior is None:
            baseline[key] = cur  # first sighting → adopt silently
            dirty = True
        else:
            findings += diff_fn(prior, cur)
    if dirty and not first_run:
        save_json(BASELINE, baseline)
    return findings, baseline


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def gather_all(baseline_snap, current_snap):
    findings = []
    findings += check_persistence(baseline_snap, current_snap)
    findings += check_cron()
    findings += check_processes()
    findings += check_behavior()        # fileless-stealer argv tier
    findings += check_xprotect()        # harvest Apple's XProtect Remediator
    findings += check_shell_history()   # ClickFix terminal-paste residue
    findings += check_hot_dirs()
    findings += check_staging()         # /tmp loot-staging IOCs
    findings += check_canaries()        # ransomware/bulk-tamper tripwire (opt-in)
    findings += check_hardening()
    findings += check_self_protection()
    # Sort by severity desc, then category.
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["category"]))
    return findings


def write_report(findings, first_run):
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
            if not suppressed and SEV_ORDER[f["severity"]] >= SEV_ORDER[NOTIFY_MIN_SEV]:
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
            return json.load(f), False
    except Exception:
        return None, True


def cmd_scan(quiet=False):
    ensure_state()
    baseline, baseline_corrupt = load_baseline()
    first_run = baseline is None and not baseline_corrupt
    current = snapshot_persistence()

    findings = gather_all(baseline.get("persistence") if baseline else None,
                          current)

    # Extra baseline-diffed surfaces (shell rc, login hooks, config profiles,
    # extra persistence, browser extensions). Adopted silently on first sight,
    # diffed thereafter. `baseline` is returned possibly-mutated/persisted.
    surface_findings, baseline = _scan_surfaces(baseline, baseline_corrupt,
                                                first_run)
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

    md = write_report(findings, first_run)
    new_high = emit(findings, first_run, adopt=adopt)
    flush_sigcache()
    record_selfstate()
    log_run("scan: %d findings, %d new-high, first_run=%s"
            % (len(findings), len(new_high), first_run))

    if not quiet:
        print(md)
    return 0


def cmd_baseline():
    ensure_state()
    current = snapshot_persistence()
    b = {"created": now_iso(), "persistence": current}
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
    print("Baseline reset: %d persistence item(s) + %d extra surface(s) recorded "
          "as known-good." % (len(current), len(SURFACES)))
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


def cmd_status():
    ensure_state()
    findings = check_hardening()
    print("# Aegis hardening posture - %s\n" % now_iso())
    checks = [
        ("System Integrity Protection", "hardening:sip:off"),
        ("Gatekeeper", "hardening:gatekeeper:off"),
        ("FileVault", "hardening:filevault:off"),
        ("Application Firewall", "hardening:firewall:off"),
        ("Firewall stealth mode", "hardening:stealth:off"),
        ("Remote Login (SSH) off", "hardening:ssh:on"),
    ]
    bad = {f["fingerprint"]: f for f in findings}
    for label, fp in checks:
        if fp in bad:
            print("  ✗ %-32s %s" % (label, bad[fp]["detail"]))
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
    return 0


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
    return paths


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
            ["log", "stream", "--style", "ndjson", "--predicate",
             'subsystem == "%s" AND category == "XPEvent.structured"'
             % XPROTECT_SUBSYSTEM],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
#   quarantine <path>  neutralize + confine a file to a reversible store
#   restore <id>       un-quarantine: reverse the neutralization byte-for-byte
#   destroy <id>       securely erase a quarantined item (IRREVERSIBLE; --yes)
#   kill <pid>         terminate a SAME-USER process (SIGTERM→SIGKILL)
#   sandbox <path>     detonate a suspect binary in a deny-default Seatbelt jail
#   neutralize <plist> ordered kill-chain for launchd-backed malware
#
# Hard safety rails (all destructive verbs): quarantine-first-never-delete-first
# (`destroy` only touches the store, never a live path), protected-path refusal
# (SIP/system/Apple, Aegis's own files, $HOME and its ancestors), same-user-only
# process actions, never-act-on-self, and an append-only actions.jsonl audit.
# None of the ES-entitlement-gated real-time blocking is claimed; this is
# on-demand response to a file/process a human has reviewed.
# --------------------------------------------------------------------------- #


def ensure_quarantine():
    ensure_state()
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        os.chmod(QUARANTINE_DIR, 0o700)  # store is owner-only
    except Exception:
        pass


def log_action(action, target, result, **extra):
    """Durable, append-only audit of every response action (success OR refusal)."""
    rec = {"ts": now_iso(), "action": action, "target": target, "result": result}
    rec.update(extra)
    try:
        with open(ACTION_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    log_run("%s %s -> %s" % (action, target, result))


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


def _xor_copy(src, dst, key=_QUAR_XOR_KEY):
    """Stream src -> dst applying a repeating-key XOR. Returns the sha256 of the
    PLAINTEXT (pre-XOR) bytes so the caller can record it. Symmetric: calling it
    again on the XORed file reverses the transform."""
    h = hashlib.sha256()
    klen = len(key)
    i = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            out = bytes(b ^ key[(i + n) % klen] for n, b in enumerate(chunk))
            fo.write(out)
            i += len(chunk)
    return h.hexdigest()


def _xor_verify_plaintext_sha(quar_path, key=_QUAR_XOR_KEY):
    """Stream the XORed store file back through XOR and return the sha256 of the
    reconstructed plaintext — used to PROVE a quarantined item can be restored
    byte-identically BEFORE we unlink the original (the never-lose-data invariant)."""
    h = hashlib.sha256()
    klen = len(key)
    i = 0
    with open(quar_path, "rb") as fi:
        while True:
            chunk = fi.read(1 << 20)
            if not chunk:
                break
            plain = bytes(b ^ key[(i + n) % klen] for n, b in enumerate(chunk))
            h.update(plain)
            i += len(chunk)
    return h.hexdigest()


def _raw_quarantine_xattr(path):
    """The raw com.apple.quarantine xattr value (or None), so restore can replay
    the exact provenance the file carried. os.getxattr is absent on macOS
    (stdlib), so we shell out to Apple's `xattr` like the rest of the tool."""
    out, _, rc = run(["xattr", "-p", "com.apple.quarantine", path], timeout=6)
    return out.strip() if rc == 0 and out.strip() else None


def cmd_quarantine(path, detection="manual"):
    """Neutralize + confine a file to the reversible quarantine store.

    Order of operations is chosen so the ORIGINAL is never lost if any step
    fails: copy-with-neutralization into the store → verify the stored copy
    reconstructs to the original hash → only THEN unlink the original. A failure
    before the verify leaves the original exactly where it was."""
    ensure_quarantine()
    rp = os.path.realpath(path)

    if not os.path.exists(rp):
        print("refuse: %s does not exist" % path)
        log_action("quarantine", rp, "refused-missing")
        return 1
    if os.path.islink(path):
        # We resolved with realpath; refuse to act through a symlink to avoid
        # quarantining an unexpected target.
        print("refuse: %s is a symlink; pass the real target path" % path)
        log_action("quarantine", path, "refused-symlink")
        return 1
    if os.path.isdir(rp):
        print("refuse: %s is a directory; Aegis quarantines regular files only "
              "(a Mach-O, plist, or staged archive), not trees" % rp)
        log_action("quarantine", rp, "refused-directory")
        return 1
    if not os.path.isfile(rp):
        print("refuse: %s is not a regular file" % rp)
        log_action("quarantine", rp, "refused-not-regular")
        return 1
    if _is_protected_path(rp):
        print("refuse: %s is a protected system/Aegis path and will not be "
              "quarantined" % rp)
        log_action("quarantine", rp, "refused-protected")
        return 1

    try:
        st = os.stat(rp)
    except Exception as e:
        print("refuse: cannot stat %s (%s)" % (rp, e))
        return 1

    orig_sha = sha256(rp)
    qxattr = _raw_quarantine_xattr(rp)
    qid = "%s-%s" % (datetime.now().strftime("%Y%m%dT%H%M%S"),
                     (orig_sha or hashlib.sha256(rp.encode()).hexdigest())[:10])
    item_dir = os.path.join(QUARANTINE_DIR, qid)
    payload = os.path.join(item_dir, "payload.quar")
    try:
        os.makedirs(item_dir, exist_ok=False)
        os.chmod(item_dir, 0o700)
    except Exception as e:
        print("error: could not create store entry (%s)" % e)
        log_action("quarantine", rp, "error-store", detail=str(e))
        return 1

    # 1) Neutralize-copy into the store and 2) prove it reconstructs.
    try:
        copied_sha = _xor_copy(rp, payload)
        if copied_sha != orig_sha:
            raise ValueError("read mismatch during copy")
        if _xor_verify_plaintext_sha(payload) != orig_sha:
            raise ValueError("store copy does not reconstruct to the original")
        os.chmod(payload, 0o000)  # not readable/executable at rest
    except Exception as e:
        shutil.rmtree(item_dir, ignore_errors=True)
        print("error: neutralization/verify failed, original left untouched (%s)" % e)
        log_action("quarantine", rp, "error-verify", detail=str(e))
        return 1

    # 3) Only now remove the original — restore is provably possible.
    try:
        os.remove(rp)
    except Exception as e:
        shutil.rmtree(item_dir, ignore_errors=True)
        print("error: could not remove original (%s); nothing quarantined "
              "(check permissions; a system file may need sudo)" % e)
        log_action("quarantine", rp, "error-remove", detail=str(e))
        return 1

    meta = {"id": qid, "orig_path": rp, "sha256": orig_sha, "size": st.st_size,
            "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid,
            "quarantine_xattr": qxattr, "detection": detection, "ts": now_iso()}
    save_json(os.path.join(item_dir, "meta.json"), meta)
    manifest = load_json(QUARANTINE_MANIFEST, {})
    manifest[qid] = meta
    save_json(QUARANTINE_MANIFEST, manifest)
    log_action("quarantine", rp, "ok", id=qid, sha256=orig_sha)
    print("Quarantined: %s\n  id:      %s\n  store:   %s (neutralized, chmod 000)\n"
          "  restore: aegis.py restore %s\n  destroy: aegis.py destroy %s --yes  "
          "(irreversible)" % (rp, qid, payload, qid, qid))
    return 0


def cmd_quarantine_list():
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
    """Reverse a quarantine byte-for-byte: reconstruct the original, put it back
    at its recorded path (or path+'.restored' if something now occupies it),
    replay mode + quarantine xattr, and drop the store entry."""
    ensure_quarantine()
    manifest = load_json(QUARANTINE_MANIFEST, {})
    m = manifest.get(qid)
    if not m:
        print("no such quarantine id: %s (see: aegis.py quarantine-list)" % qid)
        return 1
    payload = os.path.join(QUARANTINE_DIR, qid, "payload.quar")
    if not os.path.exists(payload):
        print("error: store payload for %s is missing; cannot restore" % qid)
        log_action("restore", qid, "error-payload-missing")
        return 1
    dest = m["orig_path"]
    if os.path.exists(dest):
        dest = dest + ".restored"
        print("note: %s now exists; restoring to %s" % (m["orig_path"], dest))
    tmp = dest + ".aegis-restore.tmp"
    try:
        os.chmod(payload, 0o600)  # we chmod 000'd it at rest
        _xor_copy(payload, tmp)  # XOR is symmetric → writes plaintext back out
        # _xor_copy returns the sha of its INPUT (here the ciphertext), so verify
        # against the sha of the reconstructed OUTPUT instead.
        if sha256(tmp) != m.get("sha256"):
            raise ValueError("recovered hash does not match recorded original")
        os.replace(tmp, dest)
        os.chmod(dest, m.get("mode", 0o644))
    except Exception as e:
        try:
            os.remove(tmp)
        except Exception:
            pass
        print("error: restore failed (%s); store entry left intact" % e)
        log_action("restore", qid, "error", detail=str(e))
        return 1
    if m.get("quarantine_xattr"):
        run(["xattr", "-w", "com.apple.quarantine", m["quarantine_xattr"], dest],
            timeout=6)
    shutil.rmtree(os.path.join(QUARANTINE_DIR, qid), ignore_errors=True)
    manifest.pop(qid, None)
    save_json(QUARANTINE_MANIFEST, manifest)
    log_action("restore", m["orig_path"], "ok", id=qid, dest=dest)
    print("Restored %s -> %s (verified byte-identical to the original)."
          % (qid, dest))
    return 0


def cmd_destroy(qid, confirmed=False):
    """IRREVERSIBLE. Securely-ish erase a quarantined item from the store. This
    is the only destructive verb, and by construction it can act ONLY on
    something already quarantined — there is no 'delete a live path' command
    (the industry's quarantine-first-never-delete-first invariant)."""
    ensure_quarantine()
    manifest = load_json(QUARANTINE_MANIFEST, {})
    m = manifest.get(qid)
    if not m:
        print("no such quarantine id: %s" % qid)
        return 1
    if not confirmed:
        print("REFUSING without confirmation. `destroy` is IRREVERSIBLE and the "
              "item cannot be restored afterwards.\n  Item: %s (from %s)\n  "
              "Re-run: aegis.py destroy %s --yes" % (qid, m.get("orig_path"), qid))
        return 1
    item_dir = os.path.join(QUARANTINE_DIR, qid)
    payload = os.path.join(item_dir, "payload.quar")
    try:
        if os.path.exists(payload):
            os.chmod(payload, 0o600)
            size = os.path.getsize(payload)
            with open(payload, "r+b") as f:  # single overwrite pass, then unlink
                remaining = size
                while remaining > 0:
                    n = min(remaining, 1 << 20)
                    f.write(os.urandom(n))
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
    except Exception as e:
        print("warning: overwrite pass failed (%s); removing anyway" % e)
    shutil.rmtree(item_dir, ignore_errors=True)
    manifest.pop(qid, None)
    save_json(QUARANTINE_MANIFEST, manifest)
    log_action("destroy", m.get("orig_path"), "ok", id=qid, sha256=m.get("sha256"))
    print("Destroyed %s (from %s). This cannot be undone.\n"
          "Note: on an APFS/SSD volume a single overwrite is not a guaranteed "
          "secure-erase (wear-levelling); FileVault is the real at-rest guarantee."
          % (qid, m.get("orig_path")))
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


# Deny-default Seatbelt profile for detonating a suspect binary. Allows only
# what a process needs to start and read its own image; denies network, all
# writes, and the sensitive dirs. sandbox-exec/Seatbelt is deprecated by Apple
# but fully functional (macOS 26 verified; Apple itself and shipping CLIs still
# use .sb) — the only entitlement-free process-jail available to a userspace tool.
_SANDBOX_PROFILE = """(version 1)
(deny default)
(allow process-fork)
(allow process-exec)
(allow file-read*)
(allow sysctl-read)
(allow mach-lookup)
(deny network*)
(deny file-write*)
(deny file-read* (subpath "%s"))
(deny file-read* (subpath "%s"))
""" % (os.path.join(HOME, "Library", "Keychains"),
       os.path.join(HOME, "Library", "Application Support"))


def cmd_sandbox(path, extra_args=None):
    """Detonate/inspect a suspect binary inside a deny-default Seatbelt jail:
    no network, no filesystem writes, no keychain/App-Support reads. Lets you
    watch what it *tries* to do without letting it phone home or steal data.
    Honest caveat: this is a jail, not a VM — kernel bugs or a sandbox escape
    could still bite; use a throwaway VM for true detonation."""
    rp = os.path.realpath(path)
    if not os.path.isfile(rp):
        print("refuse: %s is not a file" % rp)
        return 1
    if not os.path.exists("/usr/bin/sandbox-exec"):
        print("error: /usr/bin/sandbox-exec is not present on this macOS")
        return 1
    ensure_state()
    prof = os.path.join(STATE_DIR, "sandbox.sb")
    try:
        with open(prof, "w") as f:
            f.write(_SANDBOX_PROFILE)
    except Exception as e:
        print("error: could not write sandbox profile (%s)" % e)
        return 1
    cmd = ["/usr/bin/sandbox-exec", "-f", prof, rp] + list(extra_args or [])
    print("Detonating in deny-default Seatbelt jail (no net, no writes):\n  %s\n"
          "  (deprecated-but-functional sandbox-exec; not a VM substitute)\n---"
          % " ".join(cmd))
    log_action("sandbox", rp, "launched")
    out, err, rc = run(cmd, timeout=30)
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err)
    print("--- sandboxed process exited rc=%d" % rc)
    return 0


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


HELP = """aegis.py - personal macOS security monitor (detect + opt-in response)

 DETECT (default; runs on a launchd interval, never destructive)
  scan             run all checks once; update report; alert on new HIGH+
  report           print the latest report
  status           print hardening posture + XProtect definition age (fast)
  baseline         reset the known-good persistence baseline to current state
  allow <path>     suppress future alerts for findings matching <path>
  vt <path|sha256> OPT-IN VirusTotal reputation for a file/hash (sends only the
                   hash, never the file; needs AEGIS_VT_API_KEY or ~/.aegis/vt_key;
                   the scan path stays local-only regardless)
  canary [remove]  plant (or remove) ransomware canary/honeypot files
  watch [secs]     event-driven monitor: kqueue rescan seconds after a watched
                   path changes + a full scan every [secs] (default 600) as a
                   floor. Production: bash install.sh watch

 RESPOND (opt-in; you run these by hand on a reviewed finding — never automatic)
  quarantine <path>      neutralize + confine a file to a reversible store
  quarantine-list        list the quarantine store (ids to restore/destroy)
  restore <id>           un-quarantine byte-for-byte (undo a false positive)
  destroy <id> --yes     securely erase a quarantined item (IRREVERSIBLE)
  kill <pid>             terminate one of YOUR processes (SIGTERM->SIGKILL)
  sandbox <path> [args]  detonate a suspect binary in a deny-default jail
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
    if cmd == "baseline":
        return cmd_baseline()
    if cmd == "allow" and len(argv) > 2:
        return cmd_allow(argv[2])
    if cmd == "vt" and len(argv) > 2:
        return cmd_vt(argv[2])
    if cmd == "canary":
        return cmd_canary(argv[2] if len(argv) > 2 else "plant")
    if cmd == "watch":
        return cmd_watch(int(argv[2]) if len(argv) > 2 else 600)
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
