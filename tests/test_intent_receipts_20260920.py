"""Real file observations, no production state and no implicit agent trust."""
import io
import json
import sys

import aegis
import pytest


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "INTENT_FILE", str(tmp_path / "intent.jsonl"))
    monkeypatch.setattr(aegis, "HMAC_KEY_FILE", str(tmp_path / "key"))
    return tmp_path


def hook(monkeypatch, payload, host="claude-code"):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert aegis.cmd_intent(["aegis", "intent", "hook", host]) == 0


def receipts(root):
    return [json.loads(x) for x in (root / "intent.jsonl.receipts").read_text().splitlines()]


def test_failed_write_is_observation_only(sandbox, monkeypatch):
    path = sandbox / "partial.py"
    path.write_text("partial")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"file_path": str(path)},
                       "hook_event_name": "PostToolUseFailure"})
    assert not aegis._intent_attested(str(path), aegis.sha256(path))
    assert receipts(sandbox)[0]["status"] == "failed"


def test_successful_write_and_identity(sandbox, monkeypatch):
    path = sandbox / "ok.py"
    path.write_text("ok")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"file_path": str(path)},
                       "hook_event_name": "PostToolUse", "session_id": "session-secret",
                       "tool_use_id": "call-secret", "prompt": "never retain this"})
    assert aegis._intent_attested(str(path), aegis.sha256(path))
    record = receipts(sandbox)[0]
    assert record["host"] == "claude-code"
    assert record["session"] and "session-secret" not in json.dumps(record)
    assert "never retain this" not in json.dumps(record)


def test_patch_records_every_output_in_shadow(sandbox, monkeypatch):
    for name in ("a.py", "b.py"):
        (sandbox / name).write_text(name)
    hook(monkeypatch, {"tool_name": "apply_patch", "cwd": str(sandbox),
                       "status": "success", "tool_input": {"patch":
                       "*** Begin Patch\n*** Add File: a.py\n+x\n*** Update File: b.py\n@@\n-x\n+y\n*** End Patch"}}, "codex")
    rows = receipts(sandbox)
    assert len(rows[0]["outputs"]) == 2
    assert rows[0]["shadow"] is True
    assert not aegis._intent_attested(str(sandbox / "a.py"), aegis.sha256(sandbox / "a.py"))


def test_missing_success_does_not_attest(sandbox, monkeypatch):
    path = sandbox / "unknown.py"
    path.write_text("ok")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)}})
    assert not aegis._intent_attested(str(path), aegis.sha256(path))
    assert receipts(sandbox)[0]["status"] == "unknown"


def test_health_tracks_invalid_unsupported_oversized(sandbox, monkeypatch, capsys):
    for raw in ("{", "x" * ((1 << 20) + 1), '{"tool_name":"Bash"}'):
        monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
        assert aegis.cmd_intent(["aegis", "intent", "hook", "hermes"]) == 0
    assert aegis.cmd_intent(["aegis", "intent", "health"]) == 0
    health = json.loads(capsys.readouterr().out)
    assert health["counts"] == {"parse_error": 1, "oversize": 1, "unsupported": 1}


def test_build_declared_output_and_failed_partial(sandbox):
    for code, status in ((0, "success"), (3, "failed")):
        path = sandbox / ("built%d.bin" % code)
        command = [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('build'); sys.exit(int(sys.argv[2]))", str(path), str(code)]
        assert aegis.cmd_intent(["aegis", "intent", "build", str(sandbox), path.name, "--"] + command) == code
        row = receipts(sandbox)[-1]
        assert row["status"] == status
        assert row["outputs"][0]["sha256"] == aegis.sha256(path)
        assert not aegis._intent_attested(str(path), aegis.sha256(path))


@pytest.mark.parametrize("response", [{"is_error": True}, {"exit_code": 7}, {"error": "sensitive message"}])
def test_failure_overrides_success(sandbox, monkeypatch, response):
    path = sandbox / "failed.py"
    path.write_text("partial")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)},
                       "hook_event_name": "PostToolUse", "status": "success",
                       "tool_response": response})
    assert not aegis._intent_attested(str(path), aegis.sha256(path))
    assert receipts(sandbox)[0]["status"] == "failed"
    assert "sensitive message" not in json.dumps(receipts(sandbox))


def test_unknown_host_and_no_arbitrary_shell_inference(sandbox, monkeypatch):
    path = sandbox / "unknown.py"
    path.write_text("ok")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)},
                       "status": "success"}, "invented-host")
    assert not aegis._intent_attested(str(path), aegis.sha256(path))
    hook(monkeypatch, {"tool_name": "Bash", "tool_input": {"file_path": str(path)},
                       "status": "success"})
    assert len(receipts(sandbox)) == 1


def test_ledger_failure_is_durable(sandbox, monkeypatch):
    path = sandbox / "ok.py"
    path.write_text("ok")
    monkeypatch.setattr(aegis, "intent_record", lambda *args: False)
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)},
                       "status": "success"})
    assert "ledger_write_failure" in (sandbox / "intent.jsonl.health").read_text()


def test_build_scope_refuses_before_execution(sandbox):
    assert aegis.cmd_intent(["aegis", "intent", "build", str(sandbox), "../escape", "--", "not-a-command"]) == 2
