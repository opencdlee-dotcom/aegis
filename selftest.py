#!/usr/bin/env python3
"""Self-test for aegis detection logic. Pollutes no ~/.aegis state: it calls the
check_* functions directly (they return findings; they do not emit/log/notify)."""
import os
import subprocess
import sys

import aegis

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


# (1) END-TO-END: a real ad-hoc Mach-O dropped into a watched dir must be HIGH.
binp = "/tmp/aegis_selftest_bin"
srcp = "/tmp/aegis_selftest.c"
with open(srcp, "w") as f:
    f.write("int main(){return 0;}")
subprocess.run(["clang", "-o", binp, srcp], check=False,
               capture_output=True)
try:
    hot = aegis.check_hot_dirs()
    hit = [f for f in hot if f.get("path") == binp]
    check("adhoc Mach-O in /tmp is detected", len(hit) == 1)
    if hit:
        check("...and scored HIGH", hit[0]["severity"] == "HIGH")
        check("...classified adhoc/unsigned",
              hit[0]["trust"] in ("adhoc", "unsigned"))
finally:
    for p in (binp, srcp):
        try:
            os.remove(p)
        except OSError:
            pass

# (2) UNIT: persistence-diff severity on a synthetic baseline vs current.
base = {"/keep": {"program": "/bin/bash", "sha256": "x", "label": "keep"}}
cur = {
    "/keep": {"program": "/tmp/hijack", "sha256": "y", "label": "keep",
              "trust": "adhoc"},                       # program swapped = tamper
    "/new-evil": {"program": "/tmp/payload", "sha256": "d", "label": "evil",
                  "trust": "adhoc"},                   # brand-new adhoc in /tmp
    "/new-legit": {"program": "/Applications/Foo.app/Contents/MacOS/Foo",
                   "sha256": "e", "label": "foo", "trust": "developer-id"},
}
fs = aegis.check_persistence(base, cur)
sev = {}
for f in fs:
    sev.setdefault(f["title"], []).append(f)

new = {f["detail"].split(" -> ")[0]: f["severity"]
       for f in sev.get("New persistence item", [])}
check("new adhoc launch item in /tmp = CRITICAL",
      any("/tmp/payload" in f["detail"] and f["severity"] == "CRITICAL"
          for f in sev.get("New persistence item", [])))
check("program-swap on existing item >= HIGH",
      any(f["severity"] in ("HIGH", "CRITICAL")
          for f in sev.get("Persistence item CHANGED", [])))
check("new developer-id app item is not HIGH/CRITICAL",
      all(f["severity"] in ("LOW", "MEDIUM")
          for f in sev.get("New persistence item", [])
          if "developer-id" in f.get("trust", "")))

# (3) Signature classifier sanity against real system binaries.
check("/bin/bash classifies apple",
      aegis.classify_signature("/bin/bash")["trust"] == "apple")

print()
if fails:
    print("FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL SELF-TESTS PASSED")
