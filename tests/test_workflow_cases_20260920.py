import json
import sqlite3

import aegis


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
