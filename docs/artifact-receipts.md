# Copied build origin receipts (shadow)

`aegis.py artifact create ROOT SPEC KEY OUTPUT` signs a dedicated artifact
directory using an explicitly supplied SSH key. It never creates keys, grants
access to a key, or changes the already pinned `~/.aegis/allowed_signers` roster.
The roster must permit the separate `aegis-artifact` signature namespace.
Signing is an explicit foreground operation using the existing signing helper.

The JSON spec has `version: 1`, `world`, `project`, `source_revision` (full git
revision) or `dirty_digest` (SHA-256), `recipe`, `toolchain`, `dependency_digest`
(SHA-256), `platform` (Python sys.platform), `principal`, `issued` and `expires`
(Unix seconds), and `components` (relative file names). A signature attests the
signer's claims about source and recipe, not reproducibility or malware absence.
The command hashes the actual components and verifies the resulting signature.
Use an output receipt outside ROOT. Every file in ROOT must be listed; symlinks
are rejected, including internal links. Maximum: 1024 files, 256 MiB, 31 days.

Transfer ROOT and the receipt by any transport. On the receiver,
`aegis.py artifact verify ROOT RECEIPT WORLD PROJECT` checks the receiving
world/project, platform, dates, currently pinned signer and all current bytes.
`aegis.py artifact receive ROOT RECEIPT WORLD PROJECT` additionally stores the
receipt and the receiver-selected root in a local binding. Root moves require
another explicit receive. Unknown signer, roster removal/revocation, changed
bytes, added helpers, symlink substitution and out-of-scope replay fail closed.
Removing a key from the pinned roster revokes future use immediately.

The binary grader currently adds only a SHADOW note, retaining its severity.
Network findings and attack-defined behavior receive no artifact demotion.
No copied trust ledger, HMAC secret, dismissal or network allowlist is imported.
The local receiver binding shares Aegis's existing same-user observer boundary;
it is not protection against a principal that can rewrite the monitor itself.

Each lookup rechecks signature and complete bytes with no persistent cache.
This is bounded correctness-first behavior; large active artifacts need a
measured scan-cost evaluation before enabling any grading policy. Unsupported
large or symlink-heavy bundles retain their existing grading.
