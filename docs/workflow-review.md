# Workflow review and shadow evaluation

`uv run ~/.aegis/aegis.py workflows report` writes and prints the minimized
`~/.aegis/workflow-review.json`: original severity, current evidence grade,
attention and the missing proof for every active incident. The first field is
the runtime inventory/severity self-check. A failed check is an error, never a
clean report.

Exact observed SHA-256 content links process/beacon observations where their
stored subjects contain that evidence. Directory proximity, agent names and
shared networks do not link cases. Older beacon records without content stay
separate. Helpers with different contents also stay separate until verified
artifact membership is available; this view does not invent those links.

Each member retains its own attention: expected (fresh sub-HIGH evidence from
the existing lifecycle grader), review (missing origin/destination proof or
incomplete history), or urgent (CRITICAL, protected detections, attack-defined
evidence or strong hostile command markers). A case displays its strongest
member's attention and original severity. Grouping cannot turn another member
benign, close an incident or train acquired tolerance.

`uv run ~/.aegis/aegis.py workflows start` starts the seven-day shadow clock
and records the initial decision snapshot. Repeating start preserves that clock.
Subsequent normal scans retain changed snapshots in `workflow-shadow.json`,
bounded to 10,000 records with explicit truncation status. Coverage failures go
to the normal durable run log and degraded sensor list. These samples are
proposed decision counts, not desktop deliveries or independent benign events.
Existing notifications continue unchanged.

`uv run ~/.aegis/aegis.py workflows status` or `workflows evaluate` writes and
prints `workflow-evaluation.json`. Seven elapsed days never enable a policy.
Evaluation reports insufficient evidence until a separately reviewed comparison
can establish the preceding comparable week's verified-routine repeat
interruptions, positive controls, host canaries, sensor coverage and CPU cost.
The 90% reduction target is not inferred from fewer grouped rows or sparse
samples. No automatic promotion exists.
