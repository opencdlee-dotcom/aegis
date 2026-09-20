# AI workflow execution

Base: `1e57b19`; approved plan: AI-WORKFLOW-PLAN-2026-09-19.md.

- [x] Capture consistent live backup and classify every starting incident with evidence/missing facts.
- [x] Implement successful agent-write/patch/build receipts and durable integration health; prove failure before and success after.
- [x] Implement exact-content signed artifact transfer, default shadow, with tamper/expiry/revocation controls.
- [x] Implement evidence-bound workflow grouping, attention/missing-proof reporting and seven-day shadow snapshots.
- [x] Investigate current package origins and actual host adapter coverage; no permission broadening or fabricated benign labels.
- [ ] Run native suite, detection selftest, simulated-platform comparison and independent security review.
- [ ] Push scoped PR and complete remote CI; install reviewed source, verify hash and consumer-entry-point probes.
- [ ] Start shadow observation, preserve rollback and publish measured improvements plus remaining time-dependent gates.

Optional pre-action blocking remains outside this implementation: the approved plan explicitly treats it as separately approved follow-on. No new blocking, broad trust exclusions, roster/key provisioning or automatic policy activation.

## Core change proved

The same isolated failed-write payload against baseline `1e57b19` and the new
runtime reproduced an actual provenance defect: the baseline attested the
partial output; the new runtime did not. The same successful two-file patch
produced zero output receipts before and two authenticated, exact-hash shadow
outputs after. This proves a change to evidence ingestion, not just presentation.

Independent adversarial review at `dee9e12` passed 124 targeted tests and
repeated forged-receipt and broken-copy probes. Missing MACs cannot establish
origin, and a proven executable cannot quiet an attached unproven/broken copy.
Real SSH-key tests exercise artifact signatures, expiry, signer revocation,
scope, extra files, content replacement and framework links.

The local backlog audit preserves all 26 starting incidents: 17 process,
five beacon, two behavior, one hot-directory and one agent-target incident.
Current official uv and llama.cpp release archives matched installed binaries;
the current Node distribution matched Node/npm components. These comparisons
do not establish safety of historical missing bytes or authorize destinations.
Machine-specific evidence and the SQLite backup remain local, outside git.

## Operational completion gates

- Native full suite, simulated-platform delta and remote CI are release gates;
  consult the final PR checks and local execution report for their final results.
- Deployment must match the reviewed source hash and repeat the core probe
  against `~/.aegis/aegis.py`, the actual consumer entry point.
- New grading remains shadow-only. Seven days is a minimum observation window,
  not an automatic enable switch. Snapshot counts cannot prove a 90% reduction
  in delivered routine notifications; baseline classification, positive controls,
  real host canaries, coverage and CPU measurements remain acceptance gates.
- The existing Claude callback has delivery evidence. Codex patch delivery and
  Hermes integration require the staged host configuration and normal human
  hook trust flow in [integration instructions](intent-integration-staged.md).
  Parser replays do not prove a live callback. No hook trust hash is edited.
- Build/artifact receipts establish exact-byte origin. They never grant broad
  SSH-network, folder, application-name or AI-generated-code trust.
