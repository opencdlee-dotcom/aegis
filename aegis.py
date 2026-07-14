#!/usr/bin/env python3
"""
Aegis - a personal macOS background security monitor (detect-and-alert).

HONEST SCOPE
------------
This is a KnockKnock / osquery-tier *detection* tool, not an antivirus and not
a real-time *blocker*. Real-time blocking on macOS requires Apple's Endpoint
Security framework, which needs the restricted
`com.apple.developer.endpoint-security.client` entitlement PLUS a Developer-ID
signing certificate (Apple grants these case-by-case, often not to individuals).
Aegis deliberately uses only unprivileged, entitlement-free APIs and the stable
system CLIs, so it runs today with zero setup, no signing cert, and a minimal
attack/maintenance surface: Python standard library only, no third-party deps.

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
  3. Hot-dir watch      - flags freshly-dropped unsigned Mach-O executables in
     Downloads / Desktop / tmp / Shared, annotated with quarantine provenance
     (a NO-quarantine binary bypassed Gatekeeper — a side-load signal).
  4. Hardening posture  - SIP, Gatekeeper, FileVault, Application Firewall,
     stealth mode, remote login (SSH). Reports weak settings.
  5. Shell startup files- baseline-diffs ~/.zshrc & friends (T1546.004); a
     download-and-run / reverse-shell idiom in one scores HIGH.
  6. Login/Logout hooks - legacy com.apple.loginwindow persistence primitives.
  7. Config profiles    - a newly-installed profile (trusted certs / MDM / proxy
     — an adware/DPRK vector).
  8. Extra persistence  - /etc/crontab, /etc/periodic, StartupItems, rc.common.
  9. Browser extensions - inventory diff (Chromium family + Firefox).
 10. Self-protection    - detects if Aegis's own launchd agent was removed or its
     append-only evidence log was truncated (a monitor an attacker can silently
     disable is theater).

  Surfaces 5-9 are baseline-diffed and ADOPTED SILENTLY the first time each is
  seen (per-surface "trust what's already installed"), so upgrading Aegis on an
  existing install never produces a day-one alert storm.

DESIGN PRINCIPLE (from the alert-fatigue literature): *log everything, alert
rarely, never repeat*. The first run establishes a SILENT baseline (no day-one
alert storm - the KnockKnock/LuLu "trust what's already installed" rule).
Afterwards only genuinely-new findings at >= HIGH severity raise a macOS
notification, and each fingerprint fires at most once. Everything is written to
a durable append-only log so nothing is missed if a notification is.

STATE  -> ~/.aegis/   (baseline.json, findings.jsonl, latest.md, seen.json, ...)
USAGE  -> aegis.py [scan|report|status|baseline|allow <path>|watch]
"""

import json
import os
import plistlib
import re
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
# under either form — list both. /usr/local is included per the note above.
RISKY_PREFIXES = ("/tmp", "/private/tmp", "/var/folders", "/private/var/folders",
                  "/usr/local", "/Users/Shared", HOME)

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
EXTRA_PERSIST_FILES = ["/etc/crontab", "/etc/rc.common", "/etc/launchd.conf",
                       os.path.join(HOME, ".launchd.conf")]
EXTRA_PERSIST_DIRS = ["/etc/periodic", "/etc/emond.d/rules",
                      "/Library/StartupItems", "/System/Library/StartupItems"]

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


def _script_target(args):
    """The script an interpreter is told to run: the first path-like, non-flag
    argument after the interpreter binary. None if args[0] isn't an interpreter
    or no such argument exists."""
    if not isinstance(args, list) or len(args) < 2 or args[0] is None:
        return None
    if os.path.basename(str(args[0])) not in _INTERPRETERS:
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
    if path.startswith(("/tmp", "/private/tmp", "/var/folders",
                        "/private/var/folders", "/Users/Shared")):
        return True
    return (os.path.dirname(path) == HOME
            and os.path.basename(path).startswith("."))


def _hostile_args(args):
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
    base = os.path.basename(str(args[0]))
    rest = [str(a) for a in args[1:]]
    if base in _INTERPRETERS and any(a in _INLINE_EXEC_FLAGS for a in rest):
        return True
    # interpreter pointed at a hidden script in $HOME root or a temp dir — the
    # AMOS `/bin/bash ~/.agent` / `.helper` 2025 persistence pattern. The binary
    # (bash) is Apple-signed and in a trusted path, so signature+location scoring
    # alone reads it as safe; the tell is WHERE the script it runs lives.
    tgt = _script_target(args)
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
    if rec.get("env"):
        # a launchd job that injects a dylib/lib path into what it spawns
        # (DYLD_INSERT_LIBRARIES &c.) is a code-injection persistence pattern.
        return "CRITICAL" if is_risky_location(prog) else "HIGH"
    if _hostile_args(rec.get("args")):
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
    tgt = _script_target(rec.get("args"))
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
            if (old.get("program") != rec.get("program")
                    or old.get("sha256") != rec.get("sha256")):
                findings.append(finding(
                    "HIGH", "persistence", "Persistence item CHANGED",
                    "%s: program/hash changed (%s -> %s)" % (
                        rec["label"], old.get("program"), rec.get("program")),
                    "persistence:changed:%s:%s" % (path, rec.get("sha256")),
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
# Check 3: hot-directory freshly-dropped executables
# --------------------------------------------------------------------------- #


def _is_macho(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) in MACHO_MAGIC
    except Exception:
        return False


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
            if not os.path.isfile(path) or st.st_mtime < cutoff:
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
    for d in EXTRA_PERSIST_DIRS:
        try:
            for name in sorted(os.listdir(d)):
                add(os.path.join(d, name))
        except Exception:
            continue
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


# Registry: (baseline-key, snapshot-fn, diff-fn). Order = report order within tier.
SURFACES = [
    ("shellrc", snapshot_shellrc, diff_shellrc),
    ("loginhooks", snapshot_loginhooks, diff_loginhooks),
    ("profiles", snapshot_profiles, diff_profiles),
    ("extra_persist", snapshot_extra_persistence, diff_extra_persistence),
    ("browserext", snapshot_browserext, diff_browserext),
    ("ide_ext", snapshot_ide_ext, diff_ide_ext),
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
    save_json(SELFSTATE, st)


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
            cur = {}
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
    findings += check_hot_dirs()
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


def emit(findings, first_run):
    """Append new findings to the durable log; notify on new >= HIGH."""
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
            # rule — it applies to PERSISTENCE only. A payload already sitting in
            # a hot dir, a suspicious running process, or a weak hardening setting
            # is a live risk the user must hear about even on the very first scan;
            # suppressing those permanently (they'd land in `seen` and never
            # re-alert) would silence a threat that predated install.
            suppressed = first_run and f["category"] == "persistence"
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

    if first_run:
        # single authoritative baseline write: persistence + every surface
        # snapshot (_scan_surfaces adopted them into `baseline` in memory).
        baseline = baseline or {}
        baseline["created"] = baseline.get("created") or now_iso()
        baseline["persistence"] = current
        save_json(BASELINE, baseline)

    # Re-sort: surface findings (and any corrupt-baseline finding) were appended
    # after gather_all's sort.
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["category"]))

    md = write_report(findings, first_run)
    new_high = emit(findings, first_run)
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
            b[key] = snap_fn()
        except Exception:
            b[key] = {}
    save_json(BASELINE, b)
    flush_sigcache()
    record_selfstate()
    print("Baseline reset: %d persistence item(s) + %d extra surface(s) recorded "
          "as known-good." % (len(current), len(SURFACES)))
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


def cmd_watch(interval=300):
    """Foreground loop (for testing; production uses launchd StartInterval)."""
    print("Aegis watch: scanning every %ds. Ctrl-C to stop." % interval)
    while True:
        cmd_scan(quiet=True)
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nstopped.")
            return 0


HELP = """aegis.py - personal macOS security monitor (detect-and-alert)

  scan            run all checks once; update report; alert on new HIGH+
  report          print the latest report
  status          print hardening posture only (fast)
  baseline        reset the known-good persistence baseline to current state
  allow <path>    suppress future alerts for findings matching <path>
  watch [secs]    foreground loop (default 300s; prefer launchd in production)
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
    if cmd == "watch":
        return cmd_watch(int(argv[2]) if len(argv) > 2 else 300)
    sys.stdout.write(HELP)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
