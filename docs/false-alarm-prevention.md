# False-alarm prevention and review

## Decision

Keep high-severity alerts tied to evidence that needs action. Routine software
updates, repeated sightings, and developer builds should remain visible without
being presented as new intrusions. A low warning count alone is not success:
the benign examples and their malicious counterparts must both pass tests.

## Implemented plan

1. Review the live incident queue and group duplicate observations by subject.
2. Connect case-keyed incidents to their actual evidence when applying custody
   regrades. Require every constituent fingerprint's latest grade to be below
   HIGH; one trusted copy must not clear an unexplained copy elsewhere.
3. Derive correlation severity from its evidence, never below its strongest leg.
   Do not combine two views of the same background-item registration into an
   execution chain, or combine an OS binary update with unrelated shell activity.
4. Count recurring endpoint rotation over observation history, rather than one
   socket snapshot. Preserve each endpoint in evidence and retain fixed-endpoint
   detection. Fold old duplicate cases without deleting their observations.
5. Distinguish local/private-address fetches from public bare-IP fetches while
   preserving download-and-execute detection on every network. Restrict the
   separator-based precision adjustment to nohup and disk-mount coincidence
   heuristics. Keep conservative matching for sensitive composites because a
   process table loses shell quoting and argument boundaries.
6. Group narrowly identified harness scratch paths without normalizing arbitrary
   payload URLs or weakening exact-fingerprint recurrence detection.
7. Recognize completed Playwright installations only when a linked
   `playwright-core` manifest names the exact browser revision. Reject missing,
   malformed, mismatched, and symlink-escaped receipts. Package origin is weak
   evidence, not an integrity guarantee; broken signatures keep warning severity.
8. Apply the existing OS-update custody checks to unchanged agent configurations
   whose resolved system binary updates: same target, Apple platform signature,
   protected path, and SIP enabled. Unknown or disabled SIP earns no demotion.

## SSH and shared folders

The reviewed queue contained no SSH/authentication incident. Enabling SSH or
using a shared folder does not justify trusting everything reachable through it.
Keep authentication changes, unknown keys/origins, hostile commands, and altered
executables detectable. Use existing exact identity trust only after reviewing
the specific key or origin. A CGNAT address is not proof of fleet membership;
the range is `100.64.0.0/10`, and `100.60.218.24` is outside it.

For a copied executable, retain the existing content-bound custody mechanism:
one changed byte invalidates the inherited grade. When reconciling older
observations, require the original file still to exist, verify its hash against
the observation, and establish its build/package provenance again now. Never
import historical grades solely because they were previously recorded.

## Learning discipline

- `false-positive` means the detection was wrong and the rule needs correction.
- `benign-positive` means the activity occurred and was reviewed as authorized.
  Do not fabricate benign verdicts to reach the learning threshold.
- Machine regrades do not write human dismissal labels or train acquired
  tolerance. A historical critical incident is not silently lowered.
- Every new noise fix gets a benign reproducer plus a threatening counterpart.
  Preserve exact evidence and a reopening path for changed behavior/content.
- Unknown or incomplete evidence stays reviewable. Broken signatures require
  investigation or repair at the source; they are not cured by allowlisting.

## Verification

Focused regressions cover shared-case closure, critical-leaf preservation,
public versus local IPs, private-network download/execute, quoted and flattened
URL exfiltration, payload-URL identity, same-plist correlation, OS custody,
Playwright receipt validation, and broken-signature retention. The full suite,
real detection self-test, simulated Windows comparison against the base, and
installed-runtime checks are the release gates.

This remains an unprivileged local monitor with separately invoked response.
These changes improve alert quality; they do not add a commercial antivirus
engine or OS-enforced real-time blocking.
