#!/usr/bin/env python3
"""The operator's own LaunchAgents: one payload edit is one fact (2026-09-23).

Persistence on the operator's own ~/Library/LaunchAgents was the largest
residue after Phase 1 of the precision plan: 44 of the re-opened noise
incidents. Measured on the live store, three separate gaps:

  1. ONE edit to ~/Ai/Universe/tools/aikit/schedule/run.py (4a1646366adf ->
     25ee9a4593c2) minted seven HIGH incidents, #383 and #392-#397 -- one per
     `com.aikit.*` plist that runs it. The program-bytes case had already
     learned that one OS binary updating is one fact however many jobs call
     it; a shared PAYLOAD script still keyed per plist.

  2. Custody DID reach that payload -- `_custody(run.py, sha)` answered
     `local-commit` (MEDIUM) on 193 of the 217 scans that recorded it. The 23
     scans that recorded `custody: null` / HIGH were the ones where git did
     not answer: each plist there took 11-190 s to grade (a probe timeout is
     10-15 s), against 0-1 s in the scans that answered. Seven plists sharing
     one payload asked git seven times per scan, and every non-answer flipped
     the case back to HIGH. And #319 (~/.local/bin/improver) was never asked
     at all: an extension-less payload fails `_intent_worthy`, and the intent
     receipt for its bytes (a588f96d11b4) binds the SOURCE path the agent
     wrote, ~/Ai/001/ARC/VSCode Projects/improver/improver.py, not the
     installed copy.

  3. A NEW persistence finding named its launcher only inside the subject;
     the flat evidence carried neither the launcher's bytes nor the payload's.

Every assertion here is one of those facts, or the safety property that keeps
the fix from becoming a blind spot: attack-defined jobs are never folded or
graded, a first-sight non-answer still alarms, and an affirmative "foreign"
answer from git is never overridden by a carried rung.

Trust comes from conftest (SUSPICIOUS_TRUST), never a macOS literal, and the
paths are dict keys and stubbed provenance, so every class runs on all bodies.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aegis  # noqa: E402
from conftest import SUSPICIOUS_TRUST  # noqa: E402

UV = "/Users/me/.local/bin/uv"
RUN = "/Users/me/Ai/Universe/tools/aikit/schedule/run.py"
UV_SHA = "94" + "1" * 62
OLD = "4a" + "0" * 62
NEW = "25" + "e" * 62
IMPROVER = "/Users/me/.local/bin/improver"
IMPROVER_SRC = "/Users/me/Ai/001/ARC/VSCode Projects/improver/improver.py"
LABELS = ("aikit-tests", "doctor", "mdsync-verify", "render", "smash-prune",
          "tree-lint", "universe-ledger")


def _job(name, target=RUN, target_sha=OLD, args=None, env=None, trust=None):
    """A launchd record in the exact shape snapshot_persistence() emits."""
    trust = SUSPICIOUS_TRUST if trust is None else trust
    if args is None:
        args = [UV, "run", target, name]
    path = "/Users/me/Library/LaunchAgents/com.aikit.%s.plist" % name
    return path, {
        "label": "com.aikit." + name, "program": UV, "sha256": UV_SHA,
        "trust": trust, "run_at_load": False, "authority": None, "env": env,
        "args": args,
        "args_sha256": aegis.hashlib.sha256(json.dumps(
            args, sort_keys=True, default=str).encode()).hexdigest(),
        "script_target": target, "target_sha": target_sha}


def _snaps(names=LABELS, new=NEW, **kw):
    base, cur = {}, {}
    for name in names:
        path, rec = _job(name, **kw)
        base[path] = rec
        cur[path] = dict(rec, target_sha=new)
    return base, cur


def _changed(findings):
    return [f for f in findings if f["title"] == "Persistence item CHANGED"]


class LedgerSandbox(unittest.TestCase):
    """Every ledger this grading reads or writes, in a throwaway dir, and
    git stubbed: the paths above exist nowhere, and a real `git` against
    them would only ever answer None -- which is one of the cases under
    test, so it must be chosen, not inherited."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_payload_case_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        for k, v in (("STATE_DIR", self.state),
                     ("INTENT_FILE", os.path.join(self.state, "intent.jsonl")),
                     ("CUSTODY_FILE", os.path.join(self.state,
                                                   "custody.jsonl")),
                     ("HMAC_KEY_FILE", os.path.join(self.state, "hmac.key")),
                     ("RUN_LOG", os.path.join(self.state, "run.log")),
                     ("_git_provenance", self._git)):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        self.git_answer = None
        self.git_asked = []

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _git(self, path):
        self.git_asked.append(path)
        return self.git_answer

    def _receipt(self, path, sha, mac=None, tool="claude-code"):
        """One intent record as `aegis.py intent hook` writes it, MAC'd with
        the sandbox key -- for a path that need not exist. A real file would
        have to live in a temp dir, and a payload in a temp drop dir is the
        AMOS shape: attack-defined, never graded, which is not what these
        tests are about."""
        ts = aegis.now_iso()
        rec = {"ts": ts, "path": path, "sha256": sha, "tool": tool,
               "mac": mac or aegis._intent_mac(ts, path, sha, tool)}
        with open(aegis.INTENT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class OnePayloadEditIsOneCase(LedgerSandbox):
    """#383, #392-#397: seven plists, one run.py, one edit."""

    def test_seven_jobs_sharing_a_payload_become_one_finding(self):
        base, cur = _snaps()
        out = _changed(aegis.check_persistence(base, cur))
        self.assertEqual(len(out), 1, [f["fingerprint"] for f in out])
        f = out[0]
        self.assertEqual(f["fingerprint"],
                         "persistence:payload-update:%s:%s" % (RUN, NEW))
        self.assertEqual(f["case_fingerprint"],
                         "persistence:payload-update:%s" % RUN)
        self.assertEqual(f["path"], RUN)

    def test_every_referring_job_survives_as_evidence(self):
        """Collapsing must not destroy information: the one finding names
        all seven jobs, which none of the seven incidents it replaces could."""
        base, cur = _snaps()
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["referrer_count"], 7)
        self.assertEqual(sorted(f["referrer_paths"]), sorted(base))
        for name in LABELS:
            self.assertIn("com.aikit." + name, f["detail"])
        self.assertIn("%s -> %s" % (OLD[:12], NEW[:12]), f["detail"])

    def test_the_shared_payload_is_graded_once(self):
        """Seven plists asked git about the same file seven times per scan,
        and each probe was another chance to time out."""
        base, cur = _snaps()
        aegis.check_persistence(base, cur)
        self.assertEqual(self.git_asked, [RUN])

    def test_a_lone_job_is_keyed_on_its_payload_too(self):
        """The identity may not depend on how many jobs happen to share the
        script, or a second job appearing would move the case."""
        base, cur = _snaps(names=("doctor",))
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["case_fingerprint"],
                         "persistence:payload-update:%s" % RUN)

    def test_the_next_edit_is_not_a_silenced_recurrence(self):
        base, cur = _snaps(names=("doctor", "render"))
        first = _changed(aegis.check_persistence(base, cur))[0]
        base2 = {k: dict(v, target_sha=NEW) for k, v in base.items()}
        cur2 = {k: dict(v, target_sha="ff" * 32) for k, v in base.items()}
        second = _changed(aegis.check_persistence(base2, cur2))[0]
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["case_fingerprint"],
                         second["case_fingerprint"])

    def test_distinct_payloads_stay_distinct(self):
        base, cur = _snaps(names=("a", "b"))
        b2, c2 = _snaps(names=("c", "d"), target="/Users/me/tools/other.py")
        base.update(b2)
        cur.update(c2)
        out = _changed(aegis.check_persistence(base, cur))
        self.assertEqual(sorted(f["path"] for f in out),
                         sorted([RUN, "/Users/me/tools/other.py"]))

    def test_a_job_whose_config_also_changed_keeps_its_own_case(self):
        """An argv, env or program change riding along is a different event
        -- the repointed job this sensor exists for -- and must never be
        folded into the payload's case."""
        base, cur = _snaps()
        path = sorted(base)[0]
        cur[path] = dict(cur[path], args=[UV, "run", RUN, "evil"],
                         args_sha256="0" * 64)
        out = _changed(aegis.check_persistence(base, cur))
        per_job = [f for f in out if f["path"] == path]
        grouped = [f for f in out if f["path"] == RUN]
        self.assertEqual(len(per_job), 1)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["referrer_count"], 6)
        self.assertNotIn(path, grouped[0]["referrer_paths"])

    def test_an_attack_defined_job_is_never_folded_or_graded(self):
        """A dylib-injection env on the job keeps its own full-severity case,
        whatever custody the payload has."""
        self.git_answer = "self-committed"
        env = {"DYLD_INSERT_LIBRARIES": "/Users/me/x.dylib"}
        base, cur = _snaps(names=("evil",), env=env)
        out = _changed(aegis.check_persistence(base, cur))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["path"], sorted(base)[0])
        self.assertIsNone(out[0].get("custody"))
        self.assertIn(out[0]["severity"], ("HIGH", "CRITICAL"))


class PayloadCustodyReachesTheBytes(LedgerSandbox):
    """What the ladder can prove about the payload, asked once."""

    def test_local_commit_demotes_one_step(self):
        self.git_answer = "local-commit"
        base, cur = _snaps()
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["custody"], "local-commit")
        self.assertEqual(f["severity"], "MEDIUM")

    def test_no_answer_at_first_sight_keeps_the_full_alarm(self):
        """Fail toward suspicion: nothing known about these bytes, nothing
        demoted."""
        base, cur = _snaps()
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertIsNone(f.get("custody"))
        self.assertEqual(f["severity"], "HIGH")

    def test_a_git_non_answer_after_an_answer_does_not_flip_to_high(self):
        """The 23 scans: git answered local-commit, then timed out on the
        next scan, and the case went back to HIGH. The answer already given
        about these exact bytes is remembered, so a later non-answer carries
        it at the weakest rung instead of reading as a stranger's file."""
        self.git_answer = "local-commit"
        base, cur = _snaps()
        first = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(first["severity"], "MEDIUM")
        aegis._CUSTODY_CARRY_CACHE.clear()       # a new process, same ledger
        self.git_answer = None                   # git timed out
        again = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(again["custody"], "copy-of-graded")
        self.assertEqual(again["severity"], "MEDIUM")
        self.assertEqual(again["fingerprint"], first["fingerprint"])

    def test_an_affirmative_foreign_answer_is_never_overridden(self):
        """A carried rung fills a non-answer; it does not argue with git.
        `remote-foreign` says the bytes are someone else's history."""
        self.git_answer = "local-commit"
        base, cur = _snaps()
        aegis.check_persistence(base, cur)
        aegis._CUSTODY_CARRY_CACHE.clear()
        self.git_answer = "remote-foreign"
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["custody"], "remote-foreign")
        self.assertEqual(f["severity"], "HIGH")

    def test_a_matching_intent_receipt_is_self_attested_low(self):
        self._receipt(RUN, NEW)
        base, cur = _snaps()
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["custody"], "self-attested")
        self.assertEqual(f["severity"], "LOW")

    def test_a_receipt_for_the_same_bytes_elsewhere_carries_one_step(self):
        """#319: the agent wrote improver.py (receipt a588f96d11b4) and an
        install step copied the bytes to ~/.local/bin/improver -- no
        extension, so `_intent_worthy` refused to ask, and a receipt bound to
        the source path cannot match the copy's path. Same bytes, proven
        written under supervision, moved: the weakest rung, one step."""
        self._receipt(IMPROVER_SRC, NEW)
        self.assertFalse(aegis._intent_worthy(IMPROVER))
        base, cur = _snaps(names=("improver",), target=IMPROVER)
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(f["custody"], "copy-of-graded")
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertIn(IMPROVER_SRC, f["detail"])

    def test_a_receipt_for_different_bytes_carries_nothing(self):
        self._receipt(IMPROVER_SRC, "ab" * 32)
        base, cur = _snaps(names=("improver",), target=IMPROVER)
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertIsNone(f.get("custody"))
        self.assertEqual(f["severity"], "HIGH")

    def test_a_forged_receipt_carries_nothing(self):
        """A record whose MAC does not verify is a non-match, exactly as
        _intent_attested treats it -- at the payload's own path or any
        other."""
        self._receipt(IMPROVER_SRC, NEW, mac="0" * 64)
        self._receipt(IMPROVER, NEW, mac="0" * 64)
        base, cur = _snaps(names=("improver",), target=IMPROVER)
        f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertIsNone(f.get("custody"))
        self.assertEqual(f["severity"], "HIGH")


class NewItemCarriesItsProducer(LedgerSandbox):
    """#287/#288/#295/#300/#302/#307: seven benign-positive verdicts on one
    scheduler kit, which only become one producer class if the NEW finding
    says what launched it and what it runs."""

    def test_the_new_finding_carries_launcher_and_payload_bytes(self):
        path, rec = _job("doctor")
        f = aegis.check_persistence({}, {path: rec})[0]
        self.assertEqual(f["title"], "New persistence item")
        self.assertEqual(f["program_sha"], UV_SHA)
        self.assertEqual(f["target_sha"], OLD)
        self.assertEqual(f["script_target"], RUN)
        self.assertEqual(f["subject"]["program_sha"], UV_SHA)
        self.assertEqual(f["subject"]["target"], RUN)
        self.assertEqual(f["subject"]["target_sha"], OLD)
        self.assertEqual(
            aegis._finding_producer_classes(f),
            [("persistence:#producer:%s:%s:%s" % (UV_SHA, RUN,
                                                  SUSPICIOUS_TRUST), path)])

    def test_seven_siblings_share_one_producer_class(self):
        cur = dict(_job(name) for name in LABELS)
        out = aegis.check_persistence({}, cur)
        classes = [c for f in out for c in aegis._finding_producer_classes(f)]
        self.assertEqual(len({k for k, _obs in classes}), 1)
        self.assertEqual(len({obs for _k, obs in classes}), 7)


class OneVerdictAcceptsEveryReferringJob(LedgerSandbox):
    """The case is one fact, so one benign-positive must promote every job
    that runs the reviewed bytes -- otherwise the sensor re-asserts the fact
    on every scan for six of the seven, forever (the store's `Persistence
    baseline is written only on first run` defect)."""

    def setUp(self):
        super().setUp()
        self.saved = {}
        for name, fn in (("EVENT_DB", "t.db"), ("BASELINE", "baseline.json"),
                         ("SELFSTATE", "selfstate.json")):
            self.saved[name] = getattr(aegis, name)
            setattr(aegis, name, os.path.join(self.state, fn))
        self.now = aegis._epoch()
        self.base, self.live = _snaps(names=("a", "b", "c"))
        aegis.save_json(aegis.BASELINE,
                        {"persistence": dict(self.base), "created": "x"})
        self._real_snapshot = aegis.snapshot_persistence
        aegis.snapshot_persistence = lambda: self.live

    def tearDown(self):
        aegis.snapshot_persistence = self._real_snapshot
        for name, value in self.saved.items():
            setattr(aegis, name, value)
        super().tearDown()

    def _findings(self):
        base = aegis.load_baseline()[0].get("persistence") or {}
        return aegis.check_persistence(base, aegis.snapshot_persistence())

    def _open_case_incident(self, f):
        db = aegis._event_connection()
        with db:
            cur = db.execute(
                "INSERT INTO events(occurred_at,observed_at,source,event_type,"
                "data_json) VALUES(?,?,?,?,?)",
                (self.now, self.now, "persistence", "observation.finding",
                 json.dumps(f)))
            i = aegis._upsert_incident(
                db, "signal:" + f["case_fingerprint"], f["title"],
                f["severity"], "signal", self.now, [cur.lastrowid],
                subject=f.get("subject"))
        db.close()
        return i

    def test_one_verdict_promotes_all_three_jobs(self):
        f = _changed(self._findings())[0]
        i = self._open_case_incident(f)
        self.assertEqual(sorted(aegis._accept_into_baseline([i])),
                         sorted(self.base))
        self.assertEqual(self._findings(), [])

    def test_a_job_that_moved_on_after_the_verdict_is_not_blessed(self):
        f = _changed(self._findings())[0]
        i = self._open_case_incident(f)
        moved = sorted(self.live)[0]
        self.live[moved] = dict(self.live[moved], target_sha="ff" * 32)
        accepted = aegis._accept_into_baseline([i])
        self.assertEqual(sorted(accepted), sorted(self.live)[1:])
        left = _changed(self._findings())
        self.assertEqual([x["referrer_paths"] for x in left], [[moved]])


class TheStoreFoldsPerJobPayloadCases(unittest.TestCase):
    """A fix the operator cannot see is indistinguishable from no fix: the
    per-plist incidents already minted fold into the one payload case."""

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE incidents(id INTEGER PRIMARY KEY, kind TEXT,
              correlation_key TEXT, title TEXT, severity TEXT, status TEXT,
              created_at INT, first_seen INT, last_seen INT, updated_at INT,
              reminder_count INT DEFAULT 0, next_reminder_at INT,
              last_notified_at INT, resolution TEXT, subject_json TEXT,
              last_novel_at INT);
            CREATE TABLE events(id INTEGER PRIMARY KEY, incident_id INT,
              data_json TEXT);
            CREATE TABLE incident_events(incident_id INT, event_id INT);
        """)
        self.n = 0

    def tearDown(self):
        self.db.close()

    def _inc(self, plist, detail, status="OPEN", created=0, target=RUN):
        self.n += 1
        i = self.n
        self.db.execute(
            "INSERT INTO incidents(id,kind,correlation_key,title,severity,"
            "status,created_at,first_seen,last_seen,updated_at) "
            "VALUES(?,'signal',?,'Persistence item CHANGED','HIGH',?,?,0,0,0)",
            (i, "signal:persistence:changed:" + plist, status, created))
        data = {"detail": detail, "path": plist, "script_target": target,
                "program": UV}
        self.db.execute("INSERT INTO events(id,incident_id,data_json) "
                        "VALUES(?,?,?)", (i, i, json.dumps(data)))
        self.db.execute("INSERT INTO incident_events(incident_id,event_id) "
                        "VALUES(?,?)", (i, i))
        return i

    def _seven(self, **kw):
        return [self._inc(
            "/Users/me/Library/LaunchAgents/com.aikit.%s.plist" % name,
            "com.aikit.%s: payload %s bytes 4a1646366adf -> 25ee9a4593c2"
            % (name, RUN), **kw) for name in LABELS]

    def _run(self, now=1000):
        return aegis._fold_payload_update_cases(self.db, now)

    def _keys(self, status="OPEN"):
        return sorted(r["correlation_key"] for r in self.db.execute(
            "SELECT correlation_key FROM incidents WHERE status=?", (status,)))

    def test_seven_open_incidents_fold_into_one_case(self):
        self._seven()
        self.assertEqual(self._run(), 6)
        self.assertEqual(self._keys(),
                         ["signal:persistence:payload-update:" + RUN])
        rows = self.db.execute(
            "SELECT resolution FROM incidents WHERE status='FALSE_POSITIVE'"
        ).fetchall()
        self.assertEqual(len(rows), 6)
        for row in rows:
            self.assertTrue(row["resolution"].startswith("superseded:"),
                            row["resolution"])

    def test_the_survivor_inherits_every_job_s_evidence(self):
        self._seven()
        self._run()
        keep = self.db.execute(
            "SELECT id FROM incidents WHERE status='OPEN'").fetchone()["id"]
        n = self.db.execute("SELECT COUNT(*) c FROM incident_events WHERE "
                            "incident_id=?", (keep,)).fetchone()["c"]
        self.assertEqual(n, 7)

    def test_the_fold_lands_on_the_key_the_sensor_now_mints(self):
        """Folding onto any other key would leave the survivor orphaned and
        the next scan would mint a second case beside it."""
        self._seven()
        self._run()
        with LedgerSandboxScope():
            base, cur = _snaps()
            f = _changed(aegis.check_persistence(base, cur))[0]
        self.assertEqual(self._keys(), ["signal:" + f["case_fingerprint"]])

    def test_a_config_change_riding_along_is_never_folded(self):
        for plist, detail in (
                ("/L/a.plist", "a: args [x] -> [y]; payload %s bytes "
                               "4a1646366adf -> 25ee9a4593c2" % RUN),
                ("/L/b.plist", "b: payload %s bytes 4a1646366adf -> "
                               "25ee9a4593c2; env (none) -> {}" % RUN),
                ("/L/c.plist", "c: program bytes aaaaaaaaaaaa -> "
                               "bbbbbbbbbbbb"),
                ("/L/d.plist", "d: program /bin/bash -> /tmp/evil")):
            self._inc(plist, detail)
        self.assertEqual(self._run(), 0)
        self.assertEqual(len(self._keys()), 4)
        self.assertFalse(any("payload-update" in k for k in self._keys()))

    def test_evidence_that_disagrees_with_itself_is_left_alone(self):
        """The payload named in the detail must be the recorded
        script_target, or this cannot tell which file the case is about."""
        self._inc("/L/a.plist", "a: payload %s bytes 4a1646366adf -> "
                                "25ee9a4593c2" % RUN, target="/elsewhere.py")
        self._run()
        self.assertEqual(self._keys(), ["signal:persistence:changed:/L/a.plist"])

    def test_it_never_touches_an_incident_from_the_current_scan(self):
        self._seven(created=1000)
        self.assertEqual(self._run(now=1000), 0)
        self.assertEqual(len(self._keys()), 7)

    def test_already_adjudicated_rows_are_untouched(self):
        self._seven(status="FALSE_POSITIVE")
        self.assertEqual(self._run(), 0)
        self.assertEqual(len(self._keys("FALSE_POSITIVE")), 7)
        self.assertFalse(any("payload-update" in k
                             for k in self._keys("FALSE_POSITIVE")))

    def test_it_is_registered_to_run_once(self):
        fns = {row[0]: row[1] for row in aegis._STORE_MIGRATIONS}
        self.assertIs(fns.get("persistence_payload_case_20260923"),
                      aegis._fold_payload_update_cases)


class LedgerSandboxScope(object):
    """LedgerSandbox's isolation as a context manager, for the one migration
    test that also has to ask the live sensor what key it mints."""

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_payload_case_")
        self._saved = {}
        for k, v in (("INTENT_FILE", os.path.join(self.tmp, "intent.jsonl")),
                     ("CUSTODY_FILE", os.path.join(self.tmp, "custody.jsonl")),
                     ("HMAC_KEY_FILE", os.path.join(self.tmp, "hmac.key")),
                     ("_git_provenance", lambda path: None)):
            self._saved[k] = getattr(aegis, k)
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(aegis, k, v)
        aegis._CUSTODY_CARRY_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)
        return False


if __name__ == "__main__":
    unittest.main()
