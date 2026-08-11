#!/usr/bin/env python3
"""Regression suite for the xbar/SwiftBar menu-bar plugin (menubar/aegis-status.30s.py).

The plugin is a STANDALONE, stdlib-only, strictly READ-ONLY viewer of Aegis
state, so this suite exercises it the way xbar does: as a subprocess, against a
sandboxed fake state dir selected via AEGIS_STATE_DIR. It never imports the
plugin (the plugin never imports aegis either) and never touches real ~/.aegis.

Every single invocation is wrapped in a full before/after inventory of the
sandbox (every path + size + mtime_ns), because the plugin's core doctrine is
that it is structurally incapable of writing Aegis state: a crashed assertion
here means the plugin created, deleted, or modified a file — a doctrine breach,
not a cosmetic bug.

Run:  python3 -m unittest discover -s tests        (from the repo root)
  or: python3 tests/test_menubar.py
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(_REPO, "menubar", "aegis-status.30s.py")

# Mirrors the incidents/meta/sensor_status tables of _EVENT_SCHEMA_SQL in
# aegis.py (the plugin reads only these three). Kept as a literal copy rather
# than imported, because the plugin's whole point is reading a db it did not
# create with code that imports nothing from aegis.
_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE incidents (
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
CREATE TABLE sensor_status (
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


def _inventory(root):
    """Full sandbox inventory: every dir + every file with size and mtime_ns.
    atime is deliberately excluded (reading legitimately advances it); any
    change in the path set, a size, or an mtime is a WRITE."""
    if not os.path.isdir(root):
        return ("ABSENT", root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            entries.append(("dir", os.path.relpath(os.path.join(dirpath, name), root)))
        for name in filenames:
            p = os.path.join(dirpath, name)
            st = os.stat(p)
            entries.append(("file", os.path.relpath(p, root),
                            st.st_size, st.st_mtime_ns))
    return sorted(entries)


class MenubarBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis-menubar-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, "state")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)

    # -- fixture builders ----------------------------------------------------
    def make_state(self):
        os.makedirs(self.state, exist_ok=True)
        return self.state

    def write_heartbeat(self, age_secs=0, **extra):
        self.make_state()
        beat = {"ts": "test", "epoch": int(time.time()) - age_secs,
                "pid": 4242, "status": "ok", "alerts": 0, "top_alert": ""}
        beat.update(extra)
        with open(os.path.join(self.state, "heartbeat.json"), "w",
                  encoding="utf-8") as f:
            json.dump(beat, f)

    def write_db(self, incidents=(), sensors=(), last_scan=None):
        """incidents: (title, severity, status) tuples; sensors:
        (sensor_id, status) tuples."""
        self.make_state()
        db = sqlite3.connect(os.path.join(self.state, "aegis.db"))
        db.executescript(_SCHEMA)
        now = int(time.time())
        for title, severity, status in incidents:
            db.execute(
                "INSERT INTO incidents(kind,correlation_key,title,severity,"
                "status,created_at,first_seen,last_seen,updated_at) "
                "VALUES('signal',?,?,?,?,?,?,?,?)",
                ("key:" + title, title, severity, status, now, now, now, now))
        for sensor_id, status in sensors:
            db.execute(
                "INSERT INTO sensor_status(sensor_id,status,last_run_at) "
                "VALUES(?,?,?)", (sensor_id, status, now))
        if last_scan is not None:
            db.execute("INSERT INTO meta(key,value) VALUES('last_scan',?)",
                       (str(int(last_scan)),))
        db.commit()
        db.close()

    def write_latest_md(self, body="# Aegis report - test\n\n_No findings._\n"):
        self.make_state()
        with open(os.path.join(self.state, "latest.md"), "w",
                  encoding="utf-8") as f:
            f.write(body)

    def write_runtime(self):
        """The install.sh runtime copy the dropdown actions point at."""
        self.make_state()
        with open(os.path.join(self.state, "aegis.py"), "w",
                  encoding="utf-8") as f:
            f.write("# fake runtime copy for the action lines\n")

    def healthy_state(self):
        self.write_heartbeat(age_secs=60)
        self.write_db(last_scan=time.time() - 120)
        self.write_latest_md()
        self.write_runtime()

    # -- the one way this suite ever runs the plugin --------------------------
    def run_plugin(self, state_dir=None):
        """Run the plugin exactly as xbar would, with the READ-ONLY PROOF
        wrapped around every invocation: the full sandbox inventory must be
        byte-identical before and after, and the exit code must be 0 (a
        non-zero xbar plugin renders NOTHING in the menu bar)."""
        state_dir = state_dir or self.state
        env = dict(os.environ)
        env["AEGIS_STATE_DIR"] = state_dir
        env["HOME"] = self.home        # belt: even a ~ fallback stays sandboxed
        env["PYTHONIOENCODING"] = "utf-8"
        before = _inventory(state_dir)
        proc = subprocess.run(
            [sys.executable, PLUGIN], env=env, capture_output=True,
            encoding="utf-8", errors="replace", timeout=30)
        after = _inventory(state_dir)
        self.assertEqual(before, after,
                         "plugin WROTE to the state dir — read-only doctrine "
                         "breached")
        self.assertEqual(proc.returncode, 0,
                         "plugin exited non-zero (renders nothing in the menu "
                         "bar)\nstderr:\n%s" % proc.stderr)
        return proc.stdout

    def title(self, out):
        lines = [l for l in out.splitlines() if l.strip()]
        self.assertTrue(lines, "plugin rendered no output at all")
        return lines[0]


class TestPluginFile(MenubarBase):
    def test_exists_is_executable_and_stdlib_shebang(self):
        self.assertTrue(os.path.isfile(PLUGIN), "plugin file missing")
        with open(PLUGIN, "r", encoding="utf-8") as f:
            first = f.readline().strip()
        self.assertEqual(first, "#!/usr/bin/env python3")
        if os.name == "posix":
            self.assertTrue(os.access(PLUGIN, os.X_OK),
                            "plugin must be chmod +x for xbar/SwiftBar")

    def test_plugin_never_imports_aegis_or_networking(self):
        import ast
        with open(PLUGIN, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        for banned in ("aegis", "urllib", "socket", "http", "requests"):
            self.assertNotIn(banned, imported,
                             "plugin must stay standalone and offline: %r"
                             % banned)


class TestHealthy(MenubarBase):
    def test_healthy_state_is_shield_with_report_action(self):
        self.healthy_state()
        out = self.run_plugin()
        self.assertIn("\U0001F6E1", self.title(out))         # 🛡️
        self.assertNotIn("⚠", self.title(out))          # no ⚠ when clean
        self.assertIn("Open latest report", out)
        self.assertIn("latest.md", out)
        self.assertIn("Last scan", out)
        self.assertIn("Heartbeat", out)
        self.assertNotIn("not installed", out)

    def test_runtime_actions_use_xbar_shell_params(self):
        self.healthy_state()
        out = self.run_plugin()
        self.assertIn("Incidents in Terminal", out)
        self.assertIn("Scan now", out)
        self.assertIn("shell=", out)
        self.assertIn("terminal=true", out)
        self.assertIn("param1=", out)


class TestIncidents(MenubarBase):
    def test_open_high_incident_warns_with_count_and_title(self):
        self.write_heartbeat(age_secs=60)
        self.write_db(
            incidents=[("Credential capture with persistence", "HIGH", "OPEN")],
            last_scan=time.time() - 60)
        out = self.run_plugin()
        self.assertIn("⚠", self.title(out))              # ⚠
        self.assertIn("1", self.title(out))
        self.assertIn("Credential capture with persistence", out)
        self.assertIn("color=orange", out)   # worst severity colors the dropdown

    def test_incidents_count_all_but_list_caps_at_five_most_severe_first(self):
        rows = [("noise incident %d" % i, "MEDIUM", "ACK") for i in range(6)]
        rows.append(("the critical one", "CRITICAL", "OPEN"))
        self.write_heartbeat(age_secs=60)
        self.write_db(incidents=rows, last_scan=time.time())
        out = self.run_plugin()
        self.assertIn("7", self.title(out))                   # full count in title
        listed = [l for l in out.splitlines() if "incident" in l.lower()
                  and "#" in l]
        self.assertLessEqual(len(listed), 5)
        self.assertIn("the critical one", out)
        self.assertLess(out.index("the critical one"),
                        out.index("noise incident"),
                        "most severe must sort first")

    def test_resolved_incidents_do_not_count(self):
        self.write_heartbeat(age_secs=60)
        self.write_db(incidents=[("old news", "HIGH", "RESOLVED"),
                                 ("was wrong", "HIGH", "FALSE_POSITIVE")],
                      last_scan=time.time())
        out = self.run_plugin()
        self.assertIn("\U0001F6E1", self.title(out))
        self.assertNotIn("old news", out)

    def test_hostile_incident_title_cannot_forge_menu_params(self):
        # A '|' in a title would let attacker-controlled db text inject xbar
        # params (e.g. shell=) into its own dropdown line. The invariant: no
        # attacker text may land in a PARAM segment (anything after a '|') —
        # once its '|' is neutralized it is inert display text.
        self.write_heartbeat(age_secs=60)
        self.write_db(incidents=[
            ("evil | shell=/bin/sh param1=-c param2=pwned", "HIGH", "OPEN")],
            last_scan=time.time())
        out = self.run_plugin()
        for line in out.splitlines():
            if "evil" in line:
                for params in line.split("|")[1:]:
                    self.assertNotIn("shell=", params)
                    self.assertNotIn("param2=pwned", params)


class TestDeadMonitor(MenubarBase):
    def test_stale_heartbeat_is_skull(self):
        self.write_heartbeat(age_secs=4 * 3600)   # past the 3h tolerance
        self.write_db(last_scan=time.time() - 4 * 3600)
        out = self.run_plugin()
        self.assertIn("\U0001F480", self.title(out))          # 💀
        self.assertIn("not beating", out.lower())

    def test_missing_heartbeat_on_installed_state_is_skull(self):
        # Same doctrine as cmd_watchdog: armed with no beat is DEAD, not fresh.
        self.write_db(last_scan=time.time())
        self.write_latest_md()
        out = self.run_plugin()
        self.assertIn("\U0001F480", self.title(out))

    def test_dead_monitor_outranks_open_incidents(self):
        self.write_heartbeat(age_secs=4 * 3600)
        self.write_db(incidents=[("still open", "CRITICAL", "OPEN")],
                      last_scan=time.time() - 4 * 3600)
        out = self.run_plugin()
        self.assertIn("\U0001F480", self.title(out),
                      "a dead monitor is the most important state")
        self.assertIn("still open", out)   # incidents still shown below

    def test_fresh_heartbeat_is_not_skull(self):
        self.write_heartbeat(age_secs=30)
        self.write_db(last_scan=time.time())
        out = self.run_plugin()
        self.assertNotIn("\U0001F480", self.title(out))


class TestNotInstalled(MenubarBase):
    def test_absent_dir_is_calm_not_installed(self):
        missing = os.path.join(self.tmp, "never-created")
        out = self.run_plugin(state_dir=missing)
        self.assertIn("not installed", out)
        self.assertNotIn("\U0001F480", out)
        self.assertNotIn("⚠", out)

    def test_empty_dir_is_calm_not_installed(self):
        self.make_state()   # exists but holds no aegis state at all
        out = self.run_plugin()
        self.assertIn("not installed", out)
        self.assertNotIn("\U0001F480", out)


class TestResilience(MenubarBase):
    def test_corrupt_db_and_heartbeat_still_render_a_title(self):
        self.make_state()
        with open(os.path.join(self.state, "aegis.db"), "wb") as f:
            f.write(b"this is not a sqlite database " * 64)
        with open(os.path.join(self.state, "heartbeat.json"), "w",
                  encoding="utf-8") as f:
            f.write("{corrupt json!!")
        out = self.run_plugin()
        self.assertTrue(self.title(out))
        self.assertIn("---", out)   # still a well-formed xbar menu

    def test_valid_db_missing_tables_degrades_not_crashes(self):
        self.make_state()
        db = sqlite3.connect(os.path.join(self.state, "aegis.db"))
        db.execute("CREATE TABLE unrelated (x)")
        db.commit()
        db.close()
        self.write_heartbeat(age_secs=60)
        out = self.run_plugin()
        self.assertTrue(self.title(out))

    def test_oversized_heartbeat_is_bounded_not_slurped(self):
        self.make_state()
        with open(os.path.join(self.state, "heartbeat.json"), "w",
                  encoding="utf-8") as f:
            f.write(" " * (1 << 22) + "{}")   # 4 MB of padding
        self.write_db(last_scan=time.time())
        out = self.run_plugin()
        self.assertTrue(self.title(out))


class TestReadOnlyProof(MenubarBase):
    def test_full_state_inventory_identical_across_repeated_runs(self):
        # run_plugin() already asserts before==after on EVERY invocation in
        # this file; this test makes the doctrine explicit against the richest
        # state (db + WAL-less db, heartbeat, report, runtime, quarantine dir)
        # and repeated invocations.
        self.healthy_state()
        os.makedirs(os.path.join(self.state, "quarantine"))
        with open(os.path.join(self.state, "quarantine", "manifest.json"), "w",
                  encoding="utf-8") as f:
            f.write("{}")
        baseline = _inventory(self.state)
        for _ in range(3):
            self.run_plugin()
        self.assertEqual(baseline, _inventory(self.state))

    def test_absent_dir_is_never_created(self):
        missing = os.path.join(self.tmp, "never-created")
        self.run_plugin(state_dir=missing)
        self.assertFalse(os.path.exists(missing),
                         "plugin must never create the state dir")


if __name__ == "__main__":
    unittest.main()
