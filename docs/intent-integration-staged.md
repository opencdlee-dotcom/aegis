# Staged integration changes — not activated

No live configuration or hook trust allowlist was changed by this patch.
These entries require review, normal host trust approval where applicable,
and a real host write/patch canary before coverage is claimed. Preserve every
existing entry; append or replace only the corresponding Aegis entry.

## Hermes

Add under `hooks.post_tool_call` in `~/.hermes/config.yaml`:

```yaml
- matcher: 'write_file|patch'
  command: >-
    uv run python -c "import os,runpy,sys; p=os.path.expanduser('~/.aegis/aegis.py'); sys.argv=[p,'intent','hook','hermes']; runpy.run_path(p,run_name='__main__')"
  timeout: 10
```

The Python launcher deliberately expands the home path inside Python:
Hermes invokes an argv vector with `shell=False`, so shell variable expansion
and `~` expansion inside the second command argument cannot be assumed.
This command does not approve the hook. Use the host's normal interactive
trust flow after review; do not edit its trust allowlist or hashes manually.

Verified against this machine's installed Hermes source:

- `~/.hermes/hermes-agent/agent/shell_hooks.py`: `_serialize_payload` emits
  `hook_event_name=post_tool_call`, `tool_input`, `cwd`, and `extra`.
- `~/.hermes/hermes-agent/model_tools.py`: completion identity/result/status
  arrive as `extra.tool_call_id`, `extra.result`, `extra.status`.
- `~/.hermes/hermes-agent/tools/file_tools.py`: successful writes include
  absolute `resolved_path` / `files_modified`. Patches emit the resolved
  modified paths, and the patch result includes `success`.

The adapter reads the JSON result string, requires completion evidence,
and prefers actual resolved outputs. A tool error overrides an `ok` envelope.
Hermes's hook `cwd` is its process directory; tool task directories can
differ. Therefore relative Hermes output paths lacking resolved absolute
paths fail ingestion visibly rather than being guessed. These newly supported
Hermes receipts remain shadow-only.

## Codex

Replace only the Aegis item under `hooks.PostToolUse` in `~/.codex/hooks.json`
with this proposed entry:

```json
{
  "matcher": "Write|Edit|MultiEdit|NotebookEdit|apply_patch|functions.apply_patch",
  "hooks": [
    {
      "type": "command",
      "command": "uv run python -c \"import os,runpy,sys; p=os.path.expanduser('~/.aegis/aegis.py'); sys.argv=[p,'intent','hook','codex']; runpy.run_path(p,run_name='__main__')\"",
      "timeout": 10
    }
  ]
}
```

The existing matcher omits `apply_patch`; this is an observed configuration
gap. The exact installed Codex delivery schema has **not** been demonstrated
by a real host callback. This proposed matcher is consequently not a claim of
coverage. Record a disposable multi-file patch through the host and inspect
the resulting receipt and health before declaring it supported. A hook
trust change must use the normal human approval flow.

The parser supports `apply_patch` patch text under `tool_input.patch` or
`tool_input.input`, including multi-file add/update/move targets. Namespaced
`functions.apply_patch` and raw string tool input are also accepted; absent
explicit success evidence remains unknown and does not become provenance.
Relative paths require an explicit absolute cwd. If actual delivery differs,
add a fixture from the observed schema before activating the adapter.

## Claude and verification

The existing Claude matcher already includes `MultiEdit` and `NotebookEdit`;
`notebook_path` is supported and tested. No proposed configuration change.

For each host, create a disposable file through its real write tool, modify
two disposable files through its real patch tool where supported, and compare
receipt hashes with the files. Inspect `intent health`: unobserved hosts stay
unobserved; observed delivery alone is not a successful canary. Ensure failed
tool completion records failed/unknown observations without success custody.
Do not use synthetic stdin replay as proof of host hook installation.
