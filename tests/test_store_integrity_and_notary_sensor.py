#!/usr/bin/env python3
"""Aegis as its OWN subject: the two controls that verify the machinery every
other verdict rests on, plus the event store's integrity and retention.

Five defects, one theme — the monitor could not report on itself:

  R1 The notary only ran when a HUMAN typed `aegis.py notary`. _notary_verify
     checked chain linkage, per-link MACs, sequence gaps, anchor-vs-local head
     mismatch, shadow anchors and tail truncation, and nothing called it from a
     scan. A control that runs only once you already suspect is a confirmation.
  R2 The chain's state digest covered the trust stores and the open-incident
     set — not actions.jsonl (the audit log a latch:cleared finding tells the
     operator to read), not config.json (which decides whether the off-box beat
     leaves at all), and not the running aegis.py.
  R3 There was no store-integrity path anywhere: zero occurrences of
     quick_check, DatabaseError, backup or VACUUM in 23k lines. A corrupt
     aegis.db cost one run.log line while findings kept flowing, and incidents,
     correlation, custody and tolerance went silent forever, invisibly.
  R4 `PRAGMA journal_mode=WAL`'s ANSWER was discarded, and the whole schema was
     re-executed on EVERY connection open.
  R5 sensor.health rows (~45 per scan, unconditional) shared one 50,000-row cap
     with observation.finding rows and could evict detection history in a day.

Same contract as the rest of the suite: stdlib only, every ~/.aegis path
redirected into a throwaway dir, nothing here touches a live install.
"""
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402


class WitnessSandbox(unittest.TestCase):
    """Redirect every path these two tiers read or write.

    EVENT_DB is here because _notary_state_digest reaches the store through
    list_incidents, and NOTARY_FILE/ACTION_LOG/AEGIS_CONFIG because the digest
    now hashes them: a sandbox that covers only "what writes today" rots the
    first time something new reads."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_witness_")
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self._saved = {}
        for key, rel in (("STATE_DIR", ""),
                         ("EVENT_DB", "aegis.db"),
                         ("NOTARY_FILE", "notary.jsonl"),
                         ("RUN_LOG", "run.log"),
                         ("FINDINGS_LOG", "findings.jsonl"),
                         ("BASELINE", "baseline.json"),
                         ("ALLOWLIST", "allowlist.json"),
                         ("SELFSTATE", "selfstate.json"),
                         ("ACTION_LOG", "actions.jsonl"),
                         ("AEGIS_CONFIG", "config.json"),
                         ("HMAC_KEY_FILE", "hmac.key")):
            self._saved[key] = getattr(aegis, key)
            setattr(aegis, key, self.state if not rel
                    else os.path.join(self.state, rel))
        for key, value in self._saved.items():
            self.addCleanup(setattr, aegis, key, value)
        self.addCleanup(self._rmtree)

    def _rmtree(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def patch(self, name, value):
        """Swap a module attribute for this test only.

        The original is read ONCE, here, and the cleanup is bound to that VALUE
        — never to a lambda that re-reads the attribute later. A helper that
        saved per-call and restored by re-reading put a STUB back and poisoned
        27 unrelated tests; this shape cannot."""
        original = getattr(aegis, name)
        self.addCleanup(setattr, aegis, name, original)
        setattr(aegis, name, value)
        return original

    def run_log(self):
        try:
            with open(aegis.RUN_LOG, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""


def corrupt(path):
    """Garble everything after the 16-byte 'SQLite format 3\\0' magic.

    Deliberately leaves the magic: the file still opens as a database (SQLite
    reads lazily), so this reproduces the dangerous case — a store that LOOKS
    present and answers `connect()` — rather than the obvious one."""
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.seek(16)
        f.write((b"\xde\xad\xbe\xef" * (size // 4 + 1))[:size - 16])


def health_rows(count, status="OK"):
    return [{"sensor_id": "probe-%02d" % i, "status": status, "detail": "",
             "duration_ms": 1, "item_count": 0} for i in range(count)]


# --------------------------------------------------------------------------- #
# R1 — the notary verifies on every scan, not only when a human asks
# --------------------------------------------------------------------------- #
class TestNotaryIsASensor(WitnessSandbox):

    def setUp(self):
        super(TestNotaryIsASensor, self).setUp()
        # Never touch the platform log store from a test: emitting is stubbed
        # to a status string, and reading back defaults to "channel
        # unavailable" so the local half is what is under test.
        self.patch("_notary_emit_anchor", lambda seq, head: "stubbed")
        self.patch("_notary_read_anchors", lambda hours=24: None)
        self.patch("_NOTARY_ANCHOR_LAST", 0)

    def _chain(self, links=3):
        for _ in range(links):
            aegis.notary_append()

    def test_a_fresh_install_with_no_chain_is_not_a_finding(self):
        """The first link is written at the END of the first scan, so the
        sensor legitimately sees no file on that run. Absence of history is not
        evidence of tampering."""
        self.assertFalse(os.path.exists(aegis.NOTARY_FILE))
        self.assertEqual([], aegis.check_notary())

    def test_a_first_run_single_link_chain_is_not_a_finding(self):
        self._chain(links=1)
        self.assertEqual([], aegis.check_notary())

    def test_an_intact_chain_is_not_a_finding(self):
        self._chain()
        self.assertEqual([], aegis.check_notary())

    def test_a_broken_link_is_reported_by_the_sensor(self):
        """The defect in one test: this chain break was fully detectable and
        nothing on the scan path ever looked."""
        self._chain()
        with open(aegis.NOTARY_FILE, encoding="utf-8") as f:
            lines = f.read().splitlines()
        lines[1] = lines[1].replace('"state": "', '"state": "0', 1)
        with open(aegis.NOTARY_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        out = aegis.check_notary()
        self.assertEqual(1, len(out), "a broken chain produced no finding")
        self.assertEqual("HIGH", out[0]["severity"])
        self.assertEqual("self-protection", out[0]["category"])
        self.assertTrue(out[0]["fingerprint"].startswith("notary:broken:"))

    def test_a_mac_that_does_not_verify_is_high_not_critical(self):
        """Local-only evidence stays HIGH: a same-uid attacker holding
        hmac.key could have produced a consistent chain, so this is 'tampering
        was not silent', never proof of an unforgeable record."""
        self._chain()
        with open(aegis.NOTARY_FILE, encoding="utf-8") as f:
            body = f.read()
        with open(aegis.NOTARY_FILE, "w", encoding="utf-8") as f:
            f.write(body.replace('"mac": "', '"mac": "0', 1))
        out = aegis.check_notary()
        self.assertEqual(1, len(out))
        self.assertEqual("HIGH", out[0]["severity"])

    def test_an_anchor_the_local_chain_contradicts_is_critical(self):
        """The other pole. A root-owned anchor disagreeing with the local file
        is the one piece of evidence a same-uid attacker could not
        stage-manage, so it outranks any purely local inconsistency."""
        self._chain(links=2)
        self.patch("_notary_read_anchors",
                   lambda hours=24: ({1: "f" * 64}, set()))
        out = aegis.check_notary()
        self.assertEqual(1, len(out))
        self.assertEqual("CRITICAL", out[0]["severity"])
        self.assertIn(aegis._NOTARY_EXTERNAL_MARK, out[0]["detail"])

    def test_the_severity_split_reads_the_same_words_the_problem_carries(self):
        """_NOTARY_EXTERNAL_MARK is one definition used by both the message and
        the classifier. If someone rewords one of the three externally
        corroborated problems without the constant, this fails."""
        self._chain(links=2)
        self.patch("_notary_read_anchors",
                   lambda hours=24: ({1: "f" * 64}, {1}))
        problems, _checked, _status = aegis._notary_verify()
        self.assertTrue(problems)
        self.assertTrue(
            all(aegis._NOTARY_EXTERNAL_MARK in p for p in problems),
            "an anchor-corroborated problem stopped naming the OS log store, "
            "so check_notary would grade it HIGH instead of CRITICAL: %r"
            % problems)

    def test_the_expensive_anchor_read_is_throttled_inside_one_process(self):
        """The external half shells out to `log show` (~4s). A one-shot scan is
        a fresh process and always pays it; a change-driven `watch` loop must
        not pay it on every burst."""
        calls = []

        def counting(hours=24):
            calls.append(hours)
            return ({}, set())

        self._chain()
        self.patch("_notary_read_anchors", counting)
        aegis.check_notary()
        self.assertEqual(1, len(calls))
        aegis.check_notary()
        self.assertEqual(1, len(calls), "the anchor read ran twice in one "
                                        "process inside the throttle window")
        aegis._NOTARY_ANCHOR_LAST = 0          # restored by patch() cleanup
        aegis.check_notary()
        self.assertEqual(2, len(calls), "the throttle never expires")

    def test_skipping_the_anchor_half_still_verifies_the_local_chain(self):
        self._chain()
        problems, checked, status = aegis._notary_verify(with_anchors=False)
        self.assertEqual("not-checked", status)
        self.assertEqual(3, checked)
        self.assertEqual([], problems)

    def test_an_unreadable_anchor_channel_never_arms_the_throttle(self):
        """A platform whose log store cannot be read back must be retried, not
        silently treated as checked for the next hour."""
        self._chain()
        aegis.check_notary()                   # _notary_read_anchors -> None
        self.assertEqual(0, aegis._NOTARY_ANCHOR_LAST)


# --------------------------------------------------------------------------- #
# R2 — the digest covers the program, the audit log and the config
# --------------------------------------------------------------------------- #
class TestStateDigestCoverage(WitnessSandbox):

    def _write(self, path, text):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_an_edit_to_the_audit_log_changes_the_digest(self):
        """actions.jsonl is the file a latch:cleared finding literally tells
        the operator to read, and the chain committed to none of it."""
        self._write(aegis.ACTION_LOG, '{"action": "quarantine"}\n')
        before = aegis._notary_state_digest()
        self._write(aegis.ACTION_LOG, '{"action": "nothing happened"}\n')
        self.assertNotEqual(before, aegis._notary_state_digest())

    def test_an_edit_to_the_config_changes_the_digest(self):
        """config.json decides whether the off-box beat leaves the box at all,
        so editing it is how you silence the one witness out of reach."""
        self._write(aegis.AEGIS_CONFIG, '{"heartbeat_url": "https://a/b"}')
        before = aegis._notary_state_digest()
        self._write(aegis.AEGIS_CONFIG, "{}")
        self.assertNotEqual(before, aegis._notary_state_digest())

    def test_a_swapped_program_changes_the_digest(self):
        self.patch("_running_code_sha", lambda: "a" * 64)
        before = aegis._notary_state_digest()
        self.patch("_running_code_sha", lambda: "b" * 64)
        self.assertNotEqual(before, aegis._notary_state_digest())

    def test_the_recorded_install_pin_changes_the_digest(self):
        self.patch("_running_code_sha", lambda: "a" * 64)
        aegis.save_json(aegis.SELFSTATE, {"code_sha": "a" * 64})
        before = aegis._notary_state_digest()
        aegis.save_json(aegis.SELFSTATE, {"code_sha": "c" * 64})
        self.assertNotEqual(before, aegis._notary_state_digest())

    def test_the_digest_is_stable_when_nothing_moved(self):
        """The other direction: a digest that changed every call would make
        every chain link meaningless and every verification useless."""
        self.patch("_running_code_sha", lambda: "a" * 64)
        self._write(aegis.ACTION_LOG, "{}\n")
        self.assertEqual(aegis._notary_state_digest(),
                         aegis._notary_state_digest())

    def test_changing_the_digest_never_invalidates_links_already_written(self):
        """Heads are recomputed from the STORED state string, never from a
        fresh digest — which is why extending this function is safe on a
        machine with months of chain behind it."""
        self.patch("_notary_emit_anchor", lambda seq, head: "stubbed")
        self.patch("_notary_read_anchors", lambda hours=24: None)
        aegis.notary_append()
        aegis.notary_append()
        self._write(aegis.ACTION_LOG, "wholly different bytes\n")
        problems, _checked, _status = aegis._notary_verify()
        self.assertEqual([], problems)


# --------------------------------------------------------------------------- #
# R3 — the store can say that it is the thing that broke
# --------------------------------------------------------------------------- #
class TestStoreIntegritySensor(WitnessSandbox):

    def test_no_store_yet_is_not_a_finding(self):
        self.assertFalse(os.path.exists(aegis.EVENT_DB))
        self.assertEqual([], aegis.check_store_integrity())

    def test_a_healthy_store_is_not_a_finding(self):
        aegis.init_event_store()
        self.assertEqual([], aegis.check_store_integrity())

    def test_a_corrupt_store_is_high(self):
        aegis.init_event_store()
        corrupt(aegis.EVENT_DB)
        out = aegis.check_store_integrity()
        self.assertEqual(1, len(out), "a corrupt event store produced no "
                                      "finding at all")
        self.assertEqual("HIGH", out[0]["severity"])
        self.assertEqual("self-protection", out[0]["category"])
        self.assertTrue(out[0]["fingerprint"].startswith("store:integrity:"))

    def test_a_dropped_table_is_caught_by_the_sanity_read(self):
        """quick_check verifies page structure and says nothing about whether
        the tables this program needs still exist: a store missing `incidents`
        is a perfectly healthy database and a completely useless monitor."""
        aegis.init_event_store()
        raw = sqlite3.connect(aegis.EVENT_DB)
        raw.execute("DROP TABLE incidents")
        raw.commit()
        raw.close()
        out = aegis.check_store_integrity()
        self.assertEqual(1, len(out))
        self.assertEqual("HIGH", out[0]["severity"])

    def test_a_failed_open_is_recorded_where_the_store_cannot_be(self):
        """The failure that had nowhere to go: the store is the only durable
        sink and the store is what is broken. _event_connection re-raises (every
        caller has a failure path) but leaves a sidecar behind first."""
        aegis.init_event_store()
        corrupt(aegis.EVENT_DB)
        self.assertRaises(sqlite3.DatabaseError, aegis._event_connection)
        self.assertTrue(os.path.exists(aegis._store_sidecar(".failure.json")))
        self.assertIn("event store could not be opened", self.run_log())

    def test_a_transient_open_failure_is_reported_once_then_cleared(self):
        """A `database is locked` must become one MEDIUM, not a permanent
        finding — and must not be silent either."""
        aegis.init_event_store()
        aegis.save_json(aegis._store_sidecar(".failure.json"),
                        {"ts": "2026-09-03T00:00:00Z", "epoch": 1,
                         "error": "database is locked"})
        out = aegis.check_store_integrity()
        self.assertEqual(1, len(out))
        self.assertEqual("MEDIUM", out[0]["severity"])
        self.assertFalse(os.path.exists(aegis._store_sidecar(".failure.json")))
        self.assertEqual([], aegis.check_store_integrity())

    def test_both_sensors_run_on_every_scan(self):
        """The wiring, read off the real table without running a single
        sensor."""
        captured = []
        real = aegis._collect_sensor
        self.addCleanup(setattr, aegis, "_collect_sensor", real)
        aegis._collect_sensor = lambda sid, fn, health, *a: (
            captured.append(sid) or [])
        aegis.gather_all({}, {}, health=[])
        self.assertIn("notary", captured)
        self.assertIn("event-store", captured)


# --------------------------------------------------------------------------- #
# R3b — there is something to fall back to
# --------------------------------------------------------------------------- #
class TestStoreBackup(WitnessSandbox):

    def test_a_backup_is_taken_rotated_and_throttled(self):
        aegis.init_event_store()
        db = aegis._event_connection()
        try:
            self.assertTrue(aegis._backup_event_store(db))
            bak = aegis._store_sidecar(".bak")
            self.assertTrue(os.path.exists(bak))
            # The copy must itself be a database, or it is not a backup.
            probe = sqlite3.connect(bak)
            self.assertEqual("ok",
                             probe.execute("PRAGMA quick_check(1)").fetchone()[0])
            probe.close()

            self.assertFalse(aegis._backup_event_store(db),
                             "a second backup ran inside the daily window")
            os.utime(bak, (1, 1))              # backdate well past the window
            self.assertTrue(aegis._backup_event_store(db))
            self.assertTrue(os.path.exists(aegis._store_sidecar(".bak.1")),
                            "the previous copy was overwritten, not rotated")
        finally:
            db.close()

    def test_a_scan_that_writes_the_store_also_backs_it_up(self):
        aegis.record_security_state(
            [aegis.finding("LOW", "behavior", "probe", "d", "fp:backup:1")],
            sensor_health=health_rows(2))
        self.assertTrue(os.path.exists(aegis._store_sidecar(".bak")))


# --------------------------------------------------------------------------- #
# R4 — the schema is created once, and WAL's answer is read
# --------------------------------------------------------------------------- #
class TestConnectionOpen(WitnessSandbox):

    def _tables(self):
        db = sqlite3.connect(aegis.EVENT_DB)
        try:
            return {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            db.close()

    def test_a_fresh_store_still_gets_the_whole_schema(self):
        aegis.init_event_store()
        self.assertTrue({"incidents", "events", "signals", "dismissals"}
                        <= self._tables())
        db = sqlite3.connect(aegis.EVENT_DB)
        self.assertEqual(aegis._EVENT_SCHEMA_VERSION,
                         db.execute("PRAGMA user_version").fetchone()[0])
        db.close()

    def test_the_schema_is_not_re_executed_on_a_second_open(self):
        """~30 CREATE IF NOT EXISTS statements plus executescript's implicit
        COMMIT, taking a write lock, on every open — the main 'database is
        locked' amplifier. Proven by removing a table the schema would recreate
        and showing that a plain reopen does NOT bring it back."""
        aegis.init_event_store()
        raw = sqlite3.connect(aegis.EVENT_DB)
        raw.execute("DROP TABLE dismissals")
        raw.commit()
        raw.close()

        db = aegis._event_connection()
        db.close()
        self.assertNotIn("dismissals", self._tables(),
                         "the schema was re-executed on a stamped store")

    def test_a_store_stamped_at_an_older_version_is_migrated(self):
        """The other direction: the stamp must not become a way to skip a
        migration. A store at user_version 0 — which is every store written
        before this change — takes the create-and-migrate path."""
        aegis.init_event_store()
        raw = sqlite3.connect(aegis.EVENT_DB)
        raw.execute("DROP TABLE dismissals")
        raw.execute("PRAGMA user_version=0")
        raw.commit()
        raw.close()

        db = aegis._event_connection()
        db.close()
        self.assertIn("dismissals", self._tables(),
                      "an unstamped store skipped schema creation")

    def test_a_pre_existing_store_still_gains_the_late_added_columns(self):
        """The ALTER migrations live inside the version branch now, so a store
        that predates subject_json must still gain it on first open."""
        raw = sqlite3.connect(aegis.EVENT_DB)
        raw.executescript(
            "CREATE TABLE incidents (id INTEGER PRIMARY KEY, kind TEXT, "
            "correlation_key TEXT, title TEXT, severity TEXT, status TEXT, "
            "created_at INTEGER, first_seen INTEGER, last_seen INTEGER, "
            "updated_at INTEGER, reminder_count INTEGER DEFAULT 0, "
            "next_reminder_at INTEGER, last_notified_at INTEGER, "
            "resolution TEXT);")
        raw.commit()
        raw.close()

        db = aegis._event_connection()
        try:
            cols = {r[1] for r in db.execute("PRAGMA table_info(incidents)")}
        finally:
            db.close()
        self.assertIn("subject_json", cols)
        self.assertIn("last_novel_at", cols)

    def test_the_granted_journal_mode_is_read_back(self):
        """`PRAGMA journal_mode=WAL` answers with the mode it actually granted
        and that answer was thrown away — so a store that could not do WAL left
        readers blocking the writer with nothing anywhere saying so."""
        aegis._JOURNAL_MODE = None
        db = aegis._event_connection()
        try:
            actual = db.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            db.close()
        self.assertIsNotNone(aegis._JOURNAL_MODE)
        self.assertEqual(str(actual).lower(), str(aegis._JOURNAL_MODE).lower())

    def test_a_store_that_cannot_do_wal_says_so(self):
        """The negative leg, portably: an in-memory store is always
        journal_mode=memory, so this is a real refusal of WAL rather than a
        stubbed one."""
        self.patch("EVENT_DB", ":memory:")
        aegis._JOURNAL_MODE = None
        db = aegis._event_connection()
        db.close()
        self.assertEqual("memory", str(aegis._JOURNAL_MODE).lower())
        self.assertIn("journal_mode=memory", self.run_log())


# --------------------------------------------------------------------------- #
# R5 — a liveness heartbeat cannot outbid the evidence
# --------------------------------------------------------------------------- #
class TestHealthRowsCannotEvictFindings(WitnessSandbox):

    def _counts(self):
        db = sqlite3.connect(aegis.EVENT_DB)
        try:
            return {kind: db.execute(
                "SELECT count(*) FROM events WHERE event_type=?",
                (kind,)).fetchone()[0]
                for kind in ("observation.finding", "sensor.health")}
        finally:
            db.close()

    def test_a_flood_of_health_rows_leaves_the_finding_history_alone(self):
        """The caps are scaled down (5 instead of 50,000/10,000) so the test
        runs in a second; the arithmetic being proven is identical. A sub-HIGH
        finding is used deliberately — those do NOT open an incident, so their
        event rows are the unreferenced ones the cap actually prunes, which is
        exactly the detection history `replay` and the retro-hunt read."""
        self.patch("_EVENT_CAP", 5)
        self.patch("_HEALTH_EVENT_CAP", 5)

        aegis.record_security_state(
            [aegis.finding("LOW", "behavior", "an old observation", "d",
                           "fp:evict:keep-me")])
        self.assertEqual(1, self._counts()["observation.finding"])

        for _ in range(4):
            aegis.record_security_state([], sensor_health=health_rows(20))

        counts = self._counts()
        self.assertEqual(1, counts["observation.finding"],
                         "80 health rows evicted the finding history")
        self.assertLessEqual(counts["sensor.health"], 5,
                             "the health bucket stopped bounding anything")

    def test_the_finding_bucket_still_bounds_itself(self):
        """The other direction: separating the buckets must not turn the
        finding cap off."""
        self.patch("_EVENT_CAP", 3)
        self.patch("_HEALTH_EVENT_CAP", 3)
        for i in range(8):
            aegis.record_security_state(
                [aegis.finding("LOW", "behavior", "obs %d" % i, "d",
                               "fp:evict:%d" % i)])
        self.assertLessEqual(self._counts()["observation.finding"], 3)


if __name__ == "__main__":
    unittest.main()
