# Agent write receipts

`uv run ~/.aegis/aegis.py intent hook claude-code` reads one JSON event from
standard input. Hook exit status stays zero so editing remains usable; verify
delivery using `uv run ~/.aegis/aegis.py intent health` and the receipt ledger.
Do not infer coverage from a zero hook exit code.

Accepted host labels: `claude-code`, `codex`, `hermes`, `vscode`, `chatgpt`.
These are adapter labels, **not proof that a host has an installed hook**.
Browser-only ChatGPT has no implied local integration. Unknown hosts can
produce observations but cannot supply a successful write attestation.

The existing Claude integration delivers `Write`, `Edit`, `MultiEdit` and
`NotebookEdit` from its `PostToolUse` hook. `PostToolUseFailure`, an explicit
failed status, response error or nonzero response exit code overrides success.
A payload without completion evidence produces an unknown observation.

Other adapters must normalize their actual completion contract into this
shape; do not send the model's proposed action before execution:

```json
{
  "tool_name": "write_file",
  "tool_input": {"path": "src/example.py"},
  "cwd": "project absolute path supplied by the adapter",
  "status": "success",
  "session_id": "host session identifier",
  "call_id": "host tool-call identifier"
}
```

`Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `write_file` and `edit_file`
accept `file_path`, `path` or `notebook_path`. `apply_patch` accepts patch text
in `tool_input.patch` or `tool_input.input`; add/update/move targets are
observed individually. A failed patch may have partial writes: existing
outputs are hashed and retained with failed status, never successful custody.
Deleted paths do not produce content provenance.

For a shell build, use `intent build <project> <relative-output> [...] --
<command> [args]`. The wrapper executes the argument vector directly, with
the project as working directory and a ten-minute timeout. Declare files,
not directories or globs. Outputs outside the project are refused before
execution and checked again afterward. A successful command with missing
outputs records that gap; it does not fabricate hashes. Arbitrary shell hook
events are unsupported, because a command string cannot establish outputs.
The build command's exit code is preserved; a receipt write failure makes a
successful build wrapper return nonzero. The wrapper does not sandbox the
build, and descendants may outlive a timed-out parent process.

Receipts contain version, observation timestamp, host, hashed session/call
identities, project, operation, completion status and observed output hashes.
They exclude commands, patch bodies, prompts, response contents and raw
session identities. Paths remain local evidence. Limits: one MiB event,
64 paths, 64 MiB total observed contents per event; a larger/unreadable output
is explicitly marked. Receipt/health logs retain two bounded generations
(rotation after two MiB), so health counts cover retained deliveries only.
They do not prove every expected host event arrived.

New patch and build receipts are **shadow-only observations**, with no grading
or incident changes. Successful direct writes preserve the existing
`self-attested` intent grade. This is same-user evidence, not authorization:
an attacker already executing as the user can forge it. No receipt is a
blanket exemption from behavioral detection. Real host canaries and separately
reviewed policy promotion are required before claiming broader coverage.

The health log records parse errors, oversize events, unsupported operations,
success, unknown completion, failed completion and ledger-write failures.
If the state volume itself cannot be written, stderr reports that health
could not be persisted; no local implementation can make a durable record on
an unwritable volume.
