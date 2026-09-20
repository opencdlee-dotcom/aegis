import json
import sqlite3
import pytest

import aegis


@pytest.fixture(autouse=True)
def isolated_receipts(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(aegis, "INTENT_FILE", str(tmp_path / "intent.jsonl"))


def test_successful_build_receipt_proposes_origin_without_live_grade(tmp_path):
    db = store()
    paths = [tmp_path / "main", tmp_path / "helper", tmp_path / "unrelated"]
    for ident, path in enumerate(paths, 1):
        path.write_text(str(ident))
        incident(db, ident, aegis.sha256(str(path)), grade="HIGH")
        sub = {"kind": "process", "raw_path": str(path), "path": str(path),
               "content": aegis.sha256(str(path))}
        db.execute("UPDATE incidents SET subject_json=?,last_seen=? WHERE id=?",
                   (json.dumps(sub), aegis._epoch(), ident))
        db.execute("UPDATE events SET observed_at=? WHERE id=?", (aegis._epoch(), ident))
    aegis._intent_observe({"tool_name": "declared_build", "cwd": str(tmp_path),
                          "status": "success", "tool_input": {"outputs": [str(p) for p in paths[:2]]}},
                         "build-wrapper", build=True)
    report = aegis._workflow_report(db)
    shared = next(c for c in report["cases"] if len(c["members"]) == 2)
    assert shared["attention"] == "expected"
    assert all(m["proposed_grade"] == "MEDIUM" for m in shared["members"])
    assert all(m["current_grade"] == "HIGH" for m in shared["members"])
    paths[1].write_text("changed")
    assert len(aegis._workflow_report(db)["cases"]) == 3


def test_expected_host_never_seen_is_visible(tmp_path):
    aegis.save_json(str(tmp_path / "config.json"), {"workflow_expected_hosts": ["claude-code", "codex", "hermes"]})
    report = aegis._workflow_report(store())
    assert report["integration_health"]["hosts"]["hermes"]["status"] == "never_seen"


@pytest.mark.parametrize("failure", ["failed", "unknown", "stale", "future", "malformed"])
def test_ineligible_receipt_never_proposes_origin(tmp_path, failure):
    path = tmp_path / "main"
    path.write_text("build")
    db = store()
    incident(db, 1, aegis.sha256(str(path)), grade="HIGH")
    db.execute("UPDATE incidents SET subject_json=?,last_seen=?", (json.dumps({
        "kind": "process", "raw_path": str(path), "content": aegis.sha256(str(path))}), aegis._epoch()))
    record = {"version": 1, "ts": aegis.now_iso(), "host": "build-wrapper",
              "project": str(tmp_path), "status": "success", "outputs": [
                  {"path": str(path), "sha256": aegis.sha256(str(path)), "observation": "hashed"}]}
    if failure in ("failed", "unknown"):
        record["status"] = failure
    elif failure == "stale":
        record["ts"] = "2000-01-01T00:00:00+00:00"
    elif failure == "future":
        record["ts"] = "2999-01-01T00:00:00+00:00"
    aegis._intent_append(".receipts", record)
    if failure == "malformed":
        with open(aegis.INTENT_FILE + ".receipts", "a") as stream:
            stream.write("{bad}")
    member = aegis._workflow_report(db)["cases"][0]["members"][0]
    assert member["proposed_grade"] is None
    assert member["attention"] == "review"


def test_verified_artifact_members_group_but_hostile_member_stays_urgent(tmp_path, monkeypatch):
    # Signature/scope verification is covered by the real-key artifact suite.
    db = store()
    paths = [tmp_path / "main", tmp_path / "helper", tmp_path / "sibling"]
    components = {}
    for ident, path in enumerate(paths, 1):
        path.write_text(str(ident))
        digest = aegis.sha256(str(path))
        incident(db, ident, digest, grade="HIGH", attack=ident == 2)
        db.execute("UPDATE incidents SET subject_json=? WHERE id=?", (json.dumps({
            "kind": "process", "raw_path": str(path), "content": digest}), ident))
        if ident < 3:
            components[path.name] = digest
    monkeypatch.setattr(aegis, "_artifact_receipt", lambda p: {"components": components}
                        if p in [str(x) for x in paths[:2]] else None)
    report = aegis._workflow_report(db)
    assert len(report["cases"]) == 2
    shared = report["cases"][0]
    assert shared["attention"] == "urgent"
    assert [m["attention"] for m in shared["members"]] == ["expected", "urgent"]
    assert report["cases"][1]["members"][0]["origin"] is None


@pytest.mark.parametrize("kind,trust,expected", [("process", "adhoc", "expected"),
                                               ("process", "broken", "review"),
                                               ("beacon", "adhoc", "review")])
def test_distribution_only_explains_exact_process_origin(monkeypatch, kind, trust, expected):
    db = store()
    incident(db, 1, "a" * 64, grade="HIGH")
    db.execute("UPDATE incidents SET subject_json=?", (json.dumps({
        "kind": kind, "raw_path": "/work/app", "content": "a" * 64, "trust": trust}),))
    monkeypatch.setattr(aegis, "_distribution_receipt", lambda p: {
        "source_id": "app@1:archive", "components": {p: "a" * 64}}, raising=False)
    member = aegis._workflow_report(db)["cases"][0]["members"][0]
    assert member["attention"] == expected
    assert member["current_grade"] == "HIGH"
    assert member["proposed_grade"] == ("MEDIUM" if expected == "expected" else None)


def store():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE incidents (id INTEGER, status TEXT, severity TEXT,
            subject_json TEXT, correlation_key TEXT, last_seen REAL, title TEXT);
        CREATE TABLE events (id INTEGER, observed_at REAL, data_json TEXT, event_type TEXT);
        CREATE TABLE incident_events (incident_id INTEGER, event_id INTEGER);
    """)
    return db


def incident(db, ident, content=None, severity="HIGH", grade="MEDIUM", attack=False):
    sub = {"kind": "process", "path": "/work/app", "raw_path": "/work/app",
           "content": content}
    db.execute("INSERT INTO incidents VALUES (?, 'OPEN', ?, ?, ?, 100, 'test')",
               (ident, severity, json.dumps(sub), "signal:process:%s" % ident))
    if grade:
        data = {"fingerprint": "process:%s" % ident, "severity": grade,
                "attack_defined": attack}
        db.execute("INSERT INTO events VALUES (?, 100, ?, 'observation.finding')",
                   (ident, json.dumps(data)))
        db.execute("INSERT INTO incident_events VALUES (?, ?)", (ident, ident))


def test_content_grouping_never_teaches_or_hides_unknown_member():
    db = store()
    incident(db, 1, "a" * 64)
    incident(db, 2, "a" * 64, grade="HIGH")
    incident(db, 3, "b" * 64)
    incident(db, 4, grade=None)
    before = list(db.iterdump())
    report = aegis._workflow_report(db)
    assert report["self_check"] == "PASS"
    assert report["incident_count"] == 4
    assert len(report["cases"]) == 3
    shared = next(c for c in report["cases"] if len(c["members"]) == 2)
    assert shared["attention"] == "review"
    assert shared["severity"] == "HIGH"
    assert [m["attention"] for m in shared["members"]] == ["expected", "review"]
    assert "incomplete" in report["cases"][-1]["members"][0]["reason"]
    assert before == list(db.iterdump())


def test_harmful_counterpart_stays_urgent_with_same_content():
    db = store()
    incident(db, 1, "a" * 64)
    incident(db, 2, "a" * 64, severity="CRITICAL", grade="CRITICAL", attack=True)
    case = aegis._workflow_report(db)["cases"][0]
    assert case["attention"] == "urgent"
    assert case["severity"] == "CRITICAL"


def test_shadow_seven_days_cannot_manufacture_operational_success(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "STATE_DIR", str(tmp_path))
    db = store()
    incident(db, 1, "a" * 64)
    state = {"policy": aegis._WORKFLOW_POLICY, "started_at": 100, "samples": []}
    aegis.save_json(str(tmp_path / "workflow-shadow.json"), state)
    aegis._workflow_shadow_capture(db, now=101)
    aegis._workflow_shadow_capture(db, now=102)
    state = aegis.load_json(str(tmp_path / "workflow-shadow.json"), {})
    assert len(state["samples"]) == 1  # recurring snapshot is not a new observation
    status = aegis._workflow_shadow_evaluate(state, now=100 + 8 * 86400)
    assert status["window_complete"] is True
    assert status["enable_ready"] is False
    assert status["result"] == "INSUFFICIENT_EVIDENCE"


def test_critical_original_severity_never_quieted_by_lower_grade():
    db = store()
    incident(db, 1, severity="CRITICAL", grade="LOW")
    assert aegis._workflow_report(db)["cases"][0]["attention"] == "urgent"


def test_quarantine_stripping_stays_urgent_even_with_lower_attached_grade():
    db = store()
    incident(db, 1, "a" * 64)
    data = {"fingerprint": "process:1", "severity": "MEDIUM",
            "markers": ["quarantine-strip"]}
    db.execute("UPDATE events SET data_json=?", (json.dumps(data),))
    assert aegis._workflow_report(db)["cases"][0]["attention"] == "urgent"


def test_cli_routes_without_running_scan(monkeypatch):
    seen = []
    monkeypatch.setattr(aegis, "cmd_workflows", lambda action: seen.append(action) or 0)
    assert aegis.main(["aegis.py", "workflows", "start"]) == 0
    assert seen == ["start"]
