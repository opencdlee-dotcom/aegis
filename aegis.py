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
     resolves each program, hashes it, validates its code signature, and diffs
     against a known-good baseline. New/changed persistence is the #1 signal for
     macOS infostealers (AMOS/Atomic, Poseidon) that persist via launchd.
  2. Process watch      - flags running processes whose executable is
     unsigned / ad-hoc-signed AND lives in a user-writable location.
  3. Hot-dir watch      - flags freshly-dropped unsigned Mach-O executables in
     Downloads / Desktop / tmp / Shared.
  4. Hardening posture  - SIP, Gatekeeper, FileVault, Application Firewall,
     stealth mode, remote login (SSH). Reports weak settings.

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
                   "authority": None}
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


def _hostile_args(args):
    """Intent-derived (README: catch AMOS/Poseidon launchd persistence), and
    independent of the interpreter binary's own signature/location. True on the
    two HIGH-PRECISION infostealer signals: a signed interpreter driven by an
    inline script (`bash -c …`, `osascript -e …`) or a network fetch in the args
    (`curl|wget http…`). Deliberately does NOT flag scripts merely living in a
    dotdir — legit tools live in ~/.local, ~/.cargo, ~/.pyenv, … and the tool's
    prime directive is 'alert rarely' (a false HIGH is worse than a rare miss)."""
    if not isinstance(args, list) or not args or args[0] is None:
        return False
    base = os.path.basename(str(args[0]))
    rest = [str(a) for a in args[1:]]
    if base in _INTERPRETERS and any(a in _INLINE_EXEC_FLAGS for a in rest):
        return True
    return bool(_FETCH_RE.search(" ".join(str(a) for a in args)))


def _persistence_severity(rec):
    prog = rec.get("program")
    trust = rec.get("trust")
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
                findings.append(finding(
                    "HIGH", "hot-dir", "Unsigned executable in watched folder",
                    "%s [%s], modified %s" % (
                        path, sig["trust"],
                        datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")),
                    "hotdir:%s:%s:%s" % (path, sig["trust"], sha),
                    path=path, trust=sig["trust"], sha256=sha))
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
# Orchestration
# --------------------------------------------------------------------------- #


def gather_all(baseline_snap, current_snap):
    findings = []
    findings += check_persistence(baseline_snap, current_snap)
    findings += check_cron()
    findings += check_processes()
    findings += check_hot_dirs()
    findings += check_hardening()
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

    if baseline_corrupt:
        # Do not silently re-baseline. Surface it loudly and let every current
        # item be evaluated as new (base was None ⇒ check_persistence saw {}).
        findings.insert(0, finding(
            "HIGH", "integrity", "Baseline file is unreadable/corrupt",
            "%s failed to parse; NOT re-baselining. All persistence is being "
            "re-evaluated as new. Run `aegis.py baseline` to re-establish a "
            "known-good baseline once you trust the current state." % BASELINE,
            "integrity:baseline:corrupt"))
        findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["category"]))

    if first_run:
        save_json(BASELINE, {"created": now_iso(), "persistence": current})

    md = write_report(findings, first_run)
    new_high = emit(findings, first_run)
    flush_sigcache()
    log_run("scan: %d findings, %d new-high, first_run=%s"
            % (len(findings), len(new_high), first_run))

    if not quiet:
        print(md)
    return 0


def cmd_baseline():
    ensure_state()
    current = snapshot_persistence()
    save_json(BASELINE, {"created": now_iso(), "persistence": current})
    flush_sigcache()
    print("Baseline reset: %d persistence item(s) recorded as known-good."
          % len(current))
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
