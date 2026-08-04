#!/usr/bin/env python3
"""Self-test for aegis detection logic on THIS machine (macOS, Linux, Windows).
Pollutes no ~/.aegis state: it calls the check_* functions directly (they return
findings; they do not emit/log/notify)."""
import os
import shutil
import subprocess
import sys
import tempfile

import aegis

fails = []


def check(name, cond):
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("platform: %s" % aegis.PLATFORM)

# (1) END-TO-END: a real, freshly-built native executable dropped in an isolated
# watched dir must be detected. What makes it suspicious differs per platform —
# an unsigned Mach-O/PE on the signature platforms, an executable ELF in a
# volatile dir on Linux — so the assertion is "detected and HIGH", not a
# particular trust string.
with tempfile.TemporaryDirectory(prefix="aegis_selftest_") as tmp:
    binp = os.path.join(tmp, "aegis_selftest_bin" + (".exe" if aegis.IS_WIN
                                                     else ""))
    srcp = os.path.join(tmp, "aegis_selftest.c")
    state = os.path.join(tmp, ".aegis")
    os.makedirs(state)
    with open(srcp, "w") as f:
        f.write("int main(){return 0;}")
    compiler = None
    for candidate in ("/usr/bin/clang", "/usr/bin/cc", "/usr/bin/gcc",
                      "clang", "cc", "gcc"):
        if os.path.exists(candidate) or shutil.which(candidate):
            compiler = candidate
            break
    built = bool(compiler) and subprocess.run(
        [compiler, "-o", binp, srcp], check=False,
        capture_output=True).returncode == 0
    if not built:
        print("  SKIP native-executable drop test (no C compiler available)")
    else:
        if aegis.IS_LINUX:
            os.chmod(binp, 0o755)  # on Linux the exec bit is the signal
        saved = (aegis.HOT_DIRS, aegis.SIGCACHE, aegis._sigcache,
                 aegis._TEMP_DROP_DIRS)
        aegis.HOT_DIRS = [tmp]
        aegis.SIGCACHE = os.path.join(state, "sigcache.json")
        aegis._sigcache = {}
        # Treat the isolated dir as a volatile drop dir so the Linux scoring
        # path sees the same "dropper staging" shape it would in /tmp.
        aegis._TEMP_DROP_DIRS = tuple(saved[3]) + (tmp,)
        try:
            hot = aegis.check_hot_dirs()
            hit = [f for f in hot if f.get("path") == binp]
            check("freshly-built executable in an isolated hot dir is detected",
                  len(hit) == 1)
            if hit:
                check("...and scored HIGH", hit[0]["severity"] == "HIGH")
        finally:
            (aegis.HOT_DIRS, aegis.SIGCACHE, aegis._sigcache,
             aegis._TEMP_DROP_DIRS) = saved

# (2) UNIT: persistence-diff severity on a synthetic baseline vs current. The
# paths are platform-appropriate so the "volatile temp dir" rule is exercised
# on the machine actually running the test.
_VOLATILE = (aegis._TEMP_DROP_DIRS[0] if aegis._TEMP_DROP_DIRS else "/tmp")
_evil = os.path.join(_VOLATILE, "payload")
_hijack = os.path.join(_VOLATILE, "hijack")
_trusted_prog = (aegis.TRUSTED_PREFIXES[0].rstrip("/\\") + os.sep + "trusted")
base = {"/keep": {"program": _trusted_prog, "sha256": "x", "label": "keep"}}
cur = {
    "/keep": {"program": _hijack, "sha256": "y", "label": "keep",
              "trust": "adhoc"},                       # program swapped = tamper
    "/new-evil": {"program": _evil, "sha256": "d", "label": "evil",
                  "trust": "adhoc"},                   # brand-new drop in temp
    "/new-legit": {"program": _trusted_prog, "sha256": "e", "label": "foo",
                   "trust": "developer-id"},
}
fs = aegis.check_persistence(base, cur)
sev = {}
for f in fs:
    sev.setdefault(f["title"], []).append(f)

new = {f["detail"].split(" -> ")[0]: f["severity"]
       for f in sev.get("New persistence item", [])}
check("new persistence item launching from a volatile temp dir = CRITICAL",
      any(_evil in f["detail"] and f["severity"] == "CRITICAL"
          for f in sev.get("New persistence item", [])))
check("program-swap on existing item >= HIGH",
      any(f["severity"] in ("HIGH", "CRITICAL")
          for f in sev.get("Persistence item CHANGED", [])))
check("new developer-id app item is not HIGH/CRITICAL",
      all(f["severity"] in ("LOW", "MEDIUM")
          for f in sev.get("New persistence item", [])
          if "developer-id" in f.get("trust", "")))

# (3) Trust classifier sanity against a REAL system binary on this machine.
# Each platform vouches for its own binaries differently (codesign / package
# manager / Authenticode), so the expected verdict differs — what must hold
# everywhere is that a stock system binary is NOT judged suspicious.
if aegis.IS_MAC:
    _probe, _want = "/bin/bash", ("apple",)
elif aegis.IS_LINUX:
    _probe = "/bin/sh" if os.path.exists("/bin/sh") else "/usr/bin/env"
    _want = ("os-managed", "unmanaged")   # container images often ship unowned
else:
    _probe = os.path.join(aegis.WIN_SYSTEMROOT, "System32", "notepad.exe")
    _want = ("os-signed", "signed-valid")
_trust = aegis.classify_signature(_probe)["trust"]
check("%s classifies as %s (got %s)" % (_probe, "/".join(_want), _trust),
      _trust in _want)
check("a stock system binary is never scored suspicious",
      not aegis.suspicious_sig(_trust))

print()
if fails:
    print("FAILED: " + ", ".join(fails))
    sys.exit(1)
print("ALL SELF-TESTS PASSED")
