# Official distribution evidence, in shadow

`uv run ~/.aegis/aegis.py distribution verify PACKAGE VERSION ARCHIVE ROOT`
compares installed components to a previously downloaded official `.tar.gz`.
The archive must retain its original release filename. Supported origins are
`uv` (astral-sh/uv), `llama.cpp` (ggml-org/llama.cpp), and `node` (nodejs.org;
version includes the `v`). These are explicit foreground network requests to
fixed official metadata endpoints, never a scan-time cloud connection or
telemetry. The command fetches the official asset digest, verifies the archive,
then compares existing regular files under ROOT without extraction or execution.

Only matching components earn a local MAC-bound, path/content-specific origin
proof, expiring after 30 days. Mismatches are reported. Missing archive files and
symlink aliases are not new proof subjects; aliases can resolve to a verified
component at lookup. This is a component comparison, not a proof that every
installed file belongs to the package, nor that a package is malware-free.

The current workflow report can propose quieter treatment for a matching
structural process warning. Broken signatures, changed bytes, behavioral and
network findings do not gain that treatment. Existing grades/alerts remain
unchanged during shadow evaluation. SHA/MAC evidence remains same-user context,
not a privilege boundary; a compromised user can tamper with the monitor itself.

No install command is run and no known-good verdict is copied from another host.
The local proof store is bounded to 128 records and 8 MiB on lookup; archives
are bounded to 256 MiB compressed, 1 GiB expanded and 20,000 regular components.
