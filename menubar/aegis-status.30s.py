#!/usr/bin/env python3
# <xbar.title>Aegis Status</xbar.title>
# <xbar.version>v1.0</xbar.version>
# <xbar.author>Aegis</xbar.author>
# <xbar.desc>One-glance Aegis security-monitor status: heartbeat, open incidents, degraded sensors. Strictly read-only on Aegis state.</xbar.desc>
# <xbar.dependencies>python3</xbar.dependencies>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
"""One-glance Aegis status for the macOS menu bar (xbar / SwiftBar).

STRICTLY READ-ONLY on Aegis state, by construction:
  * the SQLite store is opened with `mode=ro&immutable=1` (the same idiom
    aegis.py uses to read other processes' DBs) — it cannot lock, journal,
    or modify the file, and it never creates one that is absent;
  * every other read is `open(..., "r")` with a hard byte cap;
  * there is no `os.makedirs`, no write-mode `open`, no delete, and no
    networking import anywhere in this file.

STANDALONE on purpose: it never imports aegis.py (the runtime copy may live
anywhere), so the three tiny readers it needs — heartbeat, incidents, sensor
health — are re-implemented here against the documented shapes. The staleness
tolerance mirrors `cmd_watchdog`'s HEARTBEAT_STALE_SECS.

Failure doctrine: a plugin that crashes renders NOTHING in the menu bar, which
would silently remove the very indicator this exists to provide. So every
reader degrades its own line and main() cannot exit non-zero — the worst state
still renders a title.

States, most important first:
  💀        the monitor is dead (heartbeat missing-though-installed or stale)
  ⚠️ N      N incidents are open (worst severity colors the dropdown)
  🛡️        heartbeat fresh, no open incidents
  ⚪        ~/.aegis absent/empty — Aegis is simply not installed (calm)
"""
import json
import os
import sqlite3
import sys
import time

STATE_DIR = os.environ.get("AEGIS_STATE_DIR") or \
    os.path.join(os.path.expanduser("~"), ".aegis")
DB_FILE = os.path.join(STATE_DIR, "aegis.db")
HEARTBEAT_FILE = os.path.join(STATE_DIR, "heartbeat.json")
LATEST_MD = os.path.join(STATE_DIR, "latest.md")
BASELINE = os.path.join(STATE_DIR, "baseline.json")
AUTOPROTECT_FILE = os.path.join(STATE_DIR, "autoprotect.json")
RUNTIME = os.path.join(STATE_DIR, "aegis.py")   # install.sh's runtime copy

HEARTBEAT_STALE_SECS = 3 * 3600   # mirrors aegis.py cmd_watchdog tolerance
ACTIVE_STATES = ("OPEN", "ACK", "INVESTIGATING", "CONTAINED",
                 "RECOVERING", "MONITORING")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_COLOR = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "#b58900",
             "LOW": "blue", "INFO": "gray"}
MAX_JSON_BYTES = 1 << 16   # heartbeat.json is ~200 bytes; anything huge is wrong
MAX_INCIDENTS = 5


# --------------------------------------------------------------------------- #
# Readers — each bounded, each returns a benign default instead of raising.
# --------------------------------------------------------------------------- #

def read_heartbeat():
    """heartbeat.json as written by aegis.py write_heartbeat(); {} on any
    problem. The read is byte-capped so a corrupt/hostile giant file costs one
    bounded read, never a slurp."""
    try:
        with open(HEARTBEAT_FILE, "r", encoding="utf-8", errors="replace") as f:
            beat = json.loads(f.read(MAX_JSON_BYTES))
        return beat if isinstance(beat, dict) else {}
    except Exception:
        return {}


def read_autoprotect():
    """autoprotect.json as written by aegis.py's Auto-Protect tier; {} on any
    problem or when the tier has never been armed. Same bounded-read doctrine
    as read_heartbeat."""
    try:
        with open(AUTOPROTECT_FILE, "r", encoding="utf-8",
                  errors="replace") as f:
            state = json.loads(f.read(MAX_JSON_BYTES))
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


def _sqlite_readonly(path):
    """The aegis.py read-only open idiom: immutable+ro URI, so reading a live
    WAL db never locks it, never creates journal files, and structurally
    cannot write. Returns a connection or None."""
    if not os.path.exists(path):
        return None
    try:
        uri = "file:%s?immutable=1&mode=ro" % (
            path.replace("%", "%25").replace("?", "%3f").replace("#", "%23"))
        return sqlite3.connect(uri, uri=True, timeout=2)
    except Exception:
        return None


def _query(db, sql, args=()):
    """One bounded SELECT; [] instead of an exception (missing table, corrupt
    page, schema drift — every one degrades a line, never the plugin)."""
    try:
        return db.execute(sql, args).fetchall()
    except Exception:
        return []


def read_store():
    """The three tiny reads from aegis.db: open incidents (count + worst-first
    top slice), degraded sensors, and the last-scan epoch. Every field is None/
    empty when unavailable."""
    out = {"open_count": None, "incidents": [], "degraded": [],
           "last_scan": None}
    db = _sqlite_readonly(DB_FILE)
    if db is None:
        return out
    try:
        marks = ",".join("?" for _ in ACTIVE_STATES)
        rows = _query(db, "SELECT count(*) FROM incidents WHERE status IN (%s)"
                      % marks, ACTIVE_STATES)
        if rows:
            out["open_count"] = int(rows[0][0])
        out["incidents"] = [
            {"id": r[0], "severity": str(r[1]), "title": str(r[2]),
             "status": str(r[3])}
            for r in _query(
                db, "SELECT id,severity,title,status FROM incidents "
                    "WHERE status IN (%s) ORDER BY CASE severity "
                    "WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
                    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,"
                    "updated_at DESC LIMIT %d" % (marks, MAX_INCIDENTS),
                ACTIVE_STATES)]
        out["degraded"] = [
            {"sensor_id": str(r[0]), "status": str(r[1])}
            for r in _query(
                db, "SELECT sensor_id,status FROM sensor_status "
                    "WHERE status != 'OK' ORDER BY sensor_id LIMIT 10")]
        rows = _query(db, "SELECT value FROM meta WHERE key='last_scan'")
        if rows:
            try:
                out["last_scan"] = int(float(rows[0][0]))
            except Exception:
                pass
    finally:
        try:
            db.close()
        except Exception:
            pass
    return out


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _clean(text, cap=80):
    """Menu-safe text: '|' would let db-sourced text (an attacker-influenced
    incident title) inject xbar params into its own line, and newlines would
    forge extra lines. Both are stripped, and the length is capped."""
    text = str(text).replace("|", "/").replace("\n", " ").replace("\r", " ")
    return text[:cap]


def _rel(age_secs):
    if age_secs < 0:
        age_secs = 0
    if age_secs < 90:
        return "just now"
    if age_secs < 5400:
        return "%d min ago" % (age_secs // 60)
    if age_secs < 172800:
        return "%d h ago" % (age_secs // 3600)
    return "%d d ago" % (age_secs // 86400)


def _worst_severity(incidents):
    worst = "INFO"
    for inc in incidents:
        if SEV_RANK.get(inc["severity"], 0) > SEV_RANK.get(worst, 0):
            worst = inc["severity"]
    return worst


def render():
    lines = []
    installed = any(os.path.exists(p) for p in
                    (HEARTBEAT_FILE, DB_FILE, BASELINE, LATEST_MD))
    if not installed:
        # Calm by design: an absent ~/.aegis is a machine without Aegis, not an
        # emergency. (A wiped state dir on a machine that HAD Aegis is the
        # watchdog's job — the plugin cannot see outside the state dir.)
        lines.append("⚪ Aegis: not installed")
        lines.append("---")
        lines.append("No Aegis state at %s" % _clean(STATE_DIR))
        lines.append("Install: python3 aegis.py install | font=Menlo")
        return lines

    now = int(time.time())
    beat = read_heartbeat()
    try:
        last_beat = int(beat.get("epoch") or 0)
    except Exception:
        last_beat = 0
    beat_age = (now - last_beat) if last_beat else None
    # cmd_watchdog doctrine: installed-with-no-beat is DEAD, never fresh.
    dead = beat_age is None or beat_age > HEARTBEAT_STALE_SECS

    store = read_store()
    open_count = store["open_count"]
    worst = _worst_severity(store["incidents"])

    # ---- title: the one-glance verdict, most important state first ----------
    if dead:
        lines.append("💀 Aegis")
    elif open_count:
        lines.append("⚠️ %d" % open_count)
    else:
        lines.append("🛡️")
    lines.append("---")

    # ---- status lines --------------------------------------------------------
    if dead:
        detail = ("no heartbeat on record" if beat_age is None else
                  "last beat %s (tolerance %d min)"
                  % (_rel(beat_age), HEARTBEAT_STALE_SECS // 60))
        lines.append("Monitor NOT beating — %s | color=red" % detail)
        lines.append("Check: launchctl list / aegis.py watchdog | font=Menlo")
    if store["last_scan"]:
        lines.append("Last scan: %s" % _rel(now - store["last_scan"]))
    else:
        lines.append("Last scan: unavailable | color=gray")
    ap = read_autoprotect()
    if ap.get("mode") == "shadow":
        tally = ap.get("tally") if isinstance(ap.get("tally"), dict) else {}
        try:
            wq = int(tally.get("would-quarantine") or 0)
            wf = int(tally.get("would-freeze") or 0)
        except Exception:
            wq = wf = 0
        lines.append("Auto-Protect: shadow — %d would-quarantine · %d "
                     "would-freeze" % (wq, wf))

    # ---- incidents ------------------------------------------------------------
    if open_count:
        lines.append("---")
        lines.append("Open incidents (%d): | color=%s"
                     % (open_count, SEV_COLOR.get(worst, "red")))
        for inc in store["incidents"]:
            lines.append("#%s %s — %s | color=%s" % (
                inc["id"], _clean(inc["severity"], 8), _clean(inc["title"]),
                SEV_COLOR.get(inc["severity"], "gray")))
        if open_count > len(store["incidents"]):
            lines.append("… %d more | color=gray"
                         % (open_count - len(store["incidents"])))
    elif open_count is None:
        lines.append("Incidents: unavailable (db unreadable) | color=gray")

    # ---- degraded sensors -----------------------------------------------------
    if store["degraded"]:
        lines.append("---")
        lines.append("Degraded sensors: | color=gray")
        for h in store["degraded"]:
            lines.append("%s: %s | color=gray"
                         % (_clean(h["sensor_id"], 40), _clean(h["status"], 12)))

    # ---- heartbeat age ---------------------------------------------------------
    lines.append("---")
    if beat_age is not None:
        lines.append("Heartbeat: %s (pid %s)"
                     % (_rel(beat_age), _clean(beat.get("pid", "?"), 12)))
    else:
        lines.append("Heartbeat: none on record | color=red")

    # ---- actions ----------------------------------------------------------------
    lines.append("---")
    if os.path.exists(LATEST_MD):
        lines.append('Open latest report | shell="/usr/bin/open" param1="%s"'
                     % LATEST_MD)
    if os.path.exists(RUNTIME):
        py = sys.executable or "/usr/bin/python3"
        lines.append('Incidents in Terminal | shell="%s" param1="%s" '
                     'param2=incidents terminal=true' % (py, RUNTIME))
        lines.append('Scan now | shell="%s" param1="%s" param2=scan '
                     'terminal=true refresh=true' % (py, RUNTIME))
    else:
        lines.append("Runtime copy not found (run install) | color=gray")
    lines.append("Refresh | refresh=true")
    return lines


def main():
    # A Windows/pipe stdout may be cp1252, where the icons raise and kill the
    # render — pin utf-8 exactly as aegis.py does for its own report.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        print("\n".join(render()))
    except Exception as e:
        # Last-ditch: a broken plugin must still render SOMETHING.
        print("❓ Aegis")
        print("---")
        print("plugin error: %s" % _clean(e, 120))
    return 0


if __name__ == "__main__":
    sys.exit(main())
