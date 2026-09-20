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
Use an output receipt outside ROOT. Every file and symlink in ROOT must be
listed, using real component paths rather than paths through directory aliases.
Relative internal symlinks are stored as exact link text and their real targets
must remain inside ROOT. Escapes, dangling links, resolution cycles and links
to ancestor directories fail closed. Framework `Versions/Current` links work.
Maximum: 20,000 components, 1 GiB, 4096 directories, 31 days; receipt 8 MiB.
These bounds cover the read-only September 20 measurement of the installed
bioREADr bundle: 14,536 files, 610,408,543 bytes, 255 directories, 26 file links.

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

Each lookup checks expiry, complete manifest and pinned roster bytes, and the
entire tree's device/inode/mode/size/mtime/ctime plus link text, including empty
directories. A changed identity requires signature and complete byte checking.
Successful checks are cached only in memory and reset when each scan begins;
no persistent cache is imported. Added helpers and same-size modifications
with restored mtime invalidate immediately through membership/ctime checks.
This remains a polling observer: concurrent writes after a check are not
prevented, and an adversary capable of forging filesystem metadata is outside
the stat-cache boundary.

Measured on that installed bundle: initial tree stat 0.145 seconds, all hashes
2.618 seconds, subsequent tree stat 0.081 seconds. These are one local sample,
not a CPU-budget claim. Multiple findings avoid rehashing the same 610 MB but
still pay for full-tree stat checks. Measure scan cost before policy activation.
