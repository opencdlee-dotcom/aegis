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
    assert health["hosts"]["codex"]["state"] == "unobserved"
    assert health["hosts"]["hermes"]["last_outcome"] == "unsupported"


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
    monkeypatch.setattr(aegis, "intent_record", lambda *args, **kwargs: False)
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)},
                       "status": "success"})
    assert "ledger_write_failure" in (sandbox / "intent.jsonl.health").read_text()


def test_build_scope_refuses_before_execution(sandbox):
    assert aegis.cmd_intent(["aegis", "intent", "build", str(sandbox), "../escape", "--", "not-a-command"]) == 2


@pytest.mark.parametrize("tool,result", [
    ("write_file", {"bytes_written": 2}),
    ("patch", {"success": True}),
])
def test_real_hermes_completion_uses_resolved_output(sandbox, monkeypatch, tool, result):
    path = sandbox / "actual.py"
    path.write_text("ok")
    result.update({"resolved_path": str(path), "files_modified": [str(path)]})
    hook(monkeypatch, {"hook_event_name": "post_tool_call", "tool_name": tool,
                       "tool_input": {"path": "wrong-cwd.py"}, "cwd": str(sandbox),
                       "extra": {"status": "ok", "result": json.dumps(result),
                                 "tool_call_id": "hermes-call"}}, "hermes")
    row = receipts(sandbox)[0]
    assert row["status"] == "success"
    assert row["outputs"][0]["path"] == str(path.resolve())
    assert row["outputs"][0]["sha256"] == aegis.sha256(path)
    assert row["call"]
    # Newly supported Hermes evidence must stay in the shadow rollout.
    assert row["shadow"] is True
    assert not aegis._intent_attested(str(path), aegis.sha256(path))


def test_hermes_failed_tool_preserves_observation(sandbox, monkeypatch):
    path = sandbox / "partial.py"
    path.write_text("partial")
    hook(monkeypatch, {"hook_event_name": "post_tool_call", "tool_name": "write_file",
                       "tool_input": {"path": str(path)}, "cwd": str(sandbox),
                       "extra": {"status": "error", "result": json.dumps({"error": "secret"})}}, "hermes")
    row = receipts(sandbox)[0]
    assert row["status"] == "failed"
    assert "secret" not in json.dumps(row)


@pytest.mark.parametrize("cwd", [None, "", "relative-cwd"])
def test_missing_absolute_cwd_never_resolves_relative_output(sandbox, monkeypatch, cwd):
    monkeypatch.chdir(sandbox)
    (sandbox / "relative.py").write_text("wrong file")
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": "relative.py"},
                       "status": "success", "cwd": cwd})
    assert not aegis._intent_attested(str(sandbox / "relative.py"), aegis.sha256(sandbox / "relative.py"))
    assert not (sandbox / "intent.jsonl.receipts").exists()


def test_notebook_path_is_supported(sandbox, monkeypatch):
    path = sandbox / "example.ipynb"
    path.write_text("{}")
    hook(monkeypatch, {"hook_event_name": "PostToolUse", "tool_name": "NotebookEdit",
                       "tool_input": {"notebook_path": str(path)}})
    assert receipts(sandbox)[0]["outputs"][0]["sha256"] == aegis.sha256(path)


def test_receipt_tampering_and_observation_race_fail_closed(sandbox, monkeypatch):
    path = sandbox / "race.py"
    path.write_text("initial")
    initial = aegis.sha256(path)
    path.write_text("changed")
    assert not aegis.intent_record(str(path), expected_sha=initial)
    hook(monkeypatch, {"tool_name": "Write", "tool_input": {"path": str(path)}, "status": "success"})
    row = receipts(sandbox)[0]
    assert aegis._intent_receipt_valid(row)
    row["outputs"][0]["sha256"] = "f" * 64
    assert not aegis._intent_receipt_valid(row)


def test_corrupt_health_and_missing_build_output(sandbox, capsys):
    (sandbox / "intent.jsonl.health").write_text('{broken\n')
    assert aegis.cmd_intent(["aegis", "intent", "health"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["health_corrupt"] == 1
    assert aegis.cmd_intent(["aegis", "intent", "build", str(sandbox), "missing", "--", sys.executable, "-c", "pass"]) == 1
    assert "outputs_unverified" in (sandbox / "intent.jsonl.health").read_text()


def test_codex_namespaced_raw_patch_is_observed_unknown(sandbox, monkeypatch):
    path = sandbox / "sample.py"
    path.write_text("ok")
    hook(monkeypatch, {"tool_name": "functions.apply_patch", "cwd": str(sandbox),
                       "tool_input": "*** Begin Patch\n*** Add File: sample.py\n+ok\n*** End Patch"}, "codex")
    row = receipts(sandbox)[0]
    assert row["operation"] == "apply_patch"
    assert row["status"] == "unknown"
    assert row["outputs"][0]["sha256"] == aegis.sha256(path)
    assert aegis._intent_receipt_valid(row)


def test_hermes_relative_task_path_is_not_resolved_using_host_cwd(sandbox, monkeypatch):
    path = sandbox / "same-name.py"
    path.write_text("host cwd file is not the task output")
    hook(monkeypatch, {"hook_event_name": "post_tool_call", "tool_name": "write_file",
                       "tool_input": {"path": path.name}, "cwd": str(sandbox),
                       "extra": {"status": "ok", "result": '{"bytes_written": 2}'}}, "hermes")
    assert not (sandbox / "intent.jsonl.receipts").exists()
    assert "parse_error" in (sandbox / "intent.jsonl.health").read_text()
