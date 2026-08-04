#!/usr/bin/env python3
"""Windows LIVE harness — the paths a fake `winreg` can never prove.

`tests/test_cross_platform.py` covers Windows text->record parsing and, since
the `WindowsPersistenceLivePlumbing` class, executes `_snapshot_persistence_
windows()` end-to-end against an *injected fake* winreg with `run` stubbed. That
catches structural defects. It does not catch anything that depends on what real
Windows actually returns:

  * Authenticode verdicts from a real `Get-AuthenticodeSignature` (including the
    tamper case, which is the only thing standing between a modified signed
    binary and a `trust=os-signed` pass);
  * process owners from a real `Get-CimInstance Win32_Process` + `GetOwner`
    (and whether that query completes inside its timeout on a real box);
  * a real `winreg` enumeration of the real Run/Winlogon/Services hives -- in
    particular whether `_WIN_LOGON_EXPECT` matches the *actual* Shell/Userinit
    values, since a mismatch is a CRITICAL false positive on every Windows host;
  * `schtasks` registration: a real task created, queried, parsed back out of
    real `schtasks /query /fo csv /v` output, seen as disabled, and removed;
  * whether a full `scan` survives contact with a real Windows machine.

Run it with an explicit opt-in so it can never fire during an ordinary test run
on someone's workstation (it creates a real scheduled task and writes real
registry values -- both under names it owns, both removed in `finally`):

    set AEGIS_WIN_LIVE=1 && python tests\\win_live_harness.py

Every check prints its captured evidence. Exit code is the number of failures.
"""
import os
import shutil
import sys
import tempfile
import traceback

if os.name != "nt":
    print("win_live_harness: not Windows (os.name=%r) -- nothing to do" % os.name)
    sys.exit(0)

if os.environ.get("AEGIS_WIN_LIVE") != "1":
    print("win_live_harness: set AEGIS_WIN_LIVE=1 to run "
          "(it registers a real scheduled task)")
    sys.exit(0)

# Sandbox the state directory BEFORE importing aegis: HOME/STATE_DIR are derived
# at import time, and `run()` re-exports USERPROFILE to every subprocess, so this
# one assignment keeps the whole harness -- including schtasks' view of the
# user profile -- inside a throwaway tree. The registry and the task scheduler
# are deliberately NOT sandboxed: they are the things under test.
_SANDBOX = tempfile.mkdtemp(prefix="aegis_winlive_")
os.environ["USERPROFILE"] = _SANDBOX
os.environ["HOME"] = _SANDBOX

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402  (import must follow the env sandbox above)
import winreg  # noqa: E402

FAILS = []
NOTES = []


def check(name, cond, evidence=""):
    print(("  PASS  " if cond else "  FAIL  ") + name)
    if evidence:
        for line in str(evidence).splitlines()[:12]:
            print("        | " + line)
    if not cond:
        FAILS.append(name)
    return cond


def note(name, evidence=""):
    """Environment-dependent observation: recorded, never a pass/fail gate."""
    print("  NOTE  " + name)
    if evidence:
        for line in str(evidence).splitlines()[:12]:
            print("        | " + line)
    NOTES.append(name)


def section(title):
    print("\n== %s ==" % title)


print("aegis live-Windows harness")
print("platform: %s  python: %s" % (aegis.PLATFORM, sys.version.split()[0]))
print("state sandbox: %s" % aegis.STATE_DIR)
print("windir: %s   systemroot: %s" % (os.environ.get("windir"),
                                       aegis.WIN_SYSTEMROOT))

_NOTEPAD = os.path.join(aegis.WIN_SYSTEMROOT, "System32", "notepad.exe")
_TASK = aegis.SELF_WIN_TASK
_RUNKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUNVAL = "AegisLiveHarness"


# --------------------------------------------------------------------------- #
# 1. Authenticode — real Get-AuthenticodeSignature verdicts.
#
# The tamper case is the load-bearing one. Aegis's macOS side has a documented
# rule that a genuine improvement may never remove the strict-verify gate,
# because it is the only thing that catches a modified Apple-signed binary.
# `HashMismatch -> trust=broken` is the Windows form of that gate, and until now
# it had only ever been asserted against a hand-written status string.
# --------------------------------------------------------------------------- #
section("1. Authenticode (real Get-AuthenticodeSignature)")
try:
    import time as _t
    _t0 = _t.time()
    signed = aegis._classify_windows(_NOTEPAD)
    _sig_cost = _t.time() - _t0
    check("a Microsoft-signed system binary classifies os-signed",
          signed.get("trust") == "os-signed", repr(signed))
    note("one uncached signature classification costs %.2fs of PowerShell "
         "start-up -- the stat-cache is what keeps a warm scan cheap on "
         "Windows, exactly as it does for codesign on macOS" % _sig_cost)

    tmpdir = tempfile.mkdtemp(prefix="aegis_sig_", dir=_SANDBOX)

    # Tampered: flip one byte in the middle of a validly signed PE. The
    # Authenticode digest covers everything but the checksum field and the
    # certificate table (both at known offsets, neither near the midpoint), so
    # a mid-file edit must produce HashMismatch.
    tampered = os.path.join(tmpdir, "tampered.exe")
    shutil.copyfile(_NOTEPAD, tampered)
    with open(tampered, "r+b") as f:
        f.seek(0, os.SEEK_END)
        mid = f.tell() // 2
        f.seek(mid)
        b = f.read(1)
        f.seek(mid)
        f.write(bytes([b[0] ^ 0xFF]))
    t = aegis._classify_windows(tampered)
    check("a tampered copy of a signed binary classifies broken "
          "(NOT os-signed) -- the Windows tamper gate",
          t.get("trust") == "broken", repr(t))

    unsigned = os.path.join(tmpdir, "unsigned.exe")
    with open(unsigned, "wb") as f:
        f.write(b"MZ" + os.urandom(4096))
    u = aegis._classify_windows(unsigned)
    check("an unsigned file is never trusted",
          u.get("trust") == "unsigned", repr(u))

    check("suspicious_sig() agrees the tampered binary is suspicious",
          aegis.suspicious_sig(t.get("trust")) is True,
          "suspicious_sig(%r) = %r" % (t.get("trust"),
                                       aegis.suspicious_sig(t.get("trust"))))
    check("suspicious_sig() does NOT flag the genuine system binary",
          aegis.suspicious_sig(signed.get("trust")) is False,
          "suspicious_sig(%r) = %r" % (signed.get("trust"),
                                       aegis.suspicious_sig(signed.get("trust"))))
except Exception:
    check("Authenticode block completed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
# 2. CIM process enumeration — real Win32_Process + GetOwner.
# --------------------------------------------------------------------------- #
section("2. Process enumeration (real Get-CimInstance Win32_Process)")
try:
    import time as _time
    t0 = _time.time()
    procs = list(aegis._iter_processes())
    elapsed = _time.time() - t0
    check("the CIM query returned processes", len(procs) >= 5,
          "%d processes in %.1fs" % (len(procs), elapsed))
    if elapsed > 45:
        note("CIM enumeration took %.1fs against a 60s timeout -- thin margin "
             "on a busier machine" % elapsed)

    me = str(os.getpid())
    mine = [p for p in procs if p[0] == me]
    check("this very process appears in the enumeration", len(mine) == 1,
          repr(mine[:1]))
    if mine:
        pid, owner, exe, argv = mine[0]
        check("GetOwner attributed our own process to us "
              "(_same_owner is the same-user response boundary)",
              aegis._same_owner(owner),
              "owner=%r  _own_owner()=%r" % (owner, aegis._own_owner()))
        check("our executable path came back absolute",
              bool(exe) and os.path.isabs(exe), "exe=%r" % exe)
        check("our command line came back non-empty", bool(argv.strip()),
              "argv=%r" % argv[:160])

    foreign = [p for p in procs if not aegis._same_owner(p[1])]
    note("%d of %d processes are owned by another principal (SYSTEM etc.) and "
         "are therefore outside the kill/quarantine boundary"
         % (len(foreign), len(procs)))
except Exception:
    check("process enumeration block completed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
# 3. Real winreg enumeration — the actual hives on this machine.
# --------------------------------------------------------------------------- #
section("3. Persistence snapshot (real winreg + real schtasks)")
planted = False
try:
    # (a) The Winlogon expectations must match the REAL values. If they do not,
    #     aegis manufactures a Winlogon-deviation finding on every Windows host
    #     it is ever installed on -- a permanent false positive.
    with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Winlogon") as k:
        for name, pattern in aegis._WIN_LOGON_EXPECT.items():
            try:
                val, _t = winreg.QueryValueEx(k, name)
            except OSError as e:
                note("Winlogon\\%s not readable: %s" % (name, e))
                continue
            check("real Winlogon\\%s matches the healthy-shape regex "
                  "(no false deviation)" % name,
                  bool(pattern.match(str(val).strip())),
                  "value=%r  pattern=%r" % (val, pattern.pattern))

    # (b) A real Run-key value, planted and then read back through the real
    #     enumeration loop.
    payload = os.path.join(aegis.WIN_APPDATA, "aegis_live_payload.exe")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUNKEY) as k:
        winreg.SetValueEx(k, _RUNVAL, 0, winreg.REG_SZ,
                          '"%s" --quiet' % payload)
    planted = True

    snap = aegis._snapshot_persistence_windows()
    check("the persistence snapshot is a dict", isinstance(snap, dict),
          "%d entries" % len(snap))

    want = "HKCU\\%s\\%s" % (_RUNKEY, _RUNVAL)
    rec = snap.get(want)
    check("the planted HKCU Run value was enumerated out of the real registry",
          rec is not None, "key=%s" % want)
    if rec:
        check("its program was parsed off the quoted command line",
              (rec.get("program") or "").lower() == payload.lower(),
              repr({k2: rec.get(k2) for k2 in
                    ("program", "run_at_load", "severity", "trust")}))
        check("it is marked run_at_load", rec.get("run_at_load") is True,
              repr(rec.get("run_at_load")))

    note("snapshot surfaces present: %s" % ", ".join(sorted({
        ("run-key" if s.startswith("HK") and "Winlogon" not in s else
         "winlogon" if "Winlogon" in s else
         s.split(":", 1)[0]) for s in snap})) or "(none)")
except Exception:
    check("registry snapshot block completed", False, traceback.format_exc())
finally:
    if planted:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUNKEY, 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, _RUNVAL)
            print("  cleanup: removed HKCU\\%s\\%s" % (_RUNKEY, _RUNVAL))
        except OSError as e:
            print("  cleanup FAILED for HKCU\\%s\\%s: %s" % (_RUNKEY, _RUNVAL, e))


# --------------------------------------------------------------------------- #
# 4. schtasks registration round-trip + self-protection.
#
# This is the whole install lifecycle the Linux side already proves with real
# systemd: register, confirm the scheduler knows about it, see it in our own
# persistence snapshot (which proves the CSV parser against REAL schtasks
# output), detect an attacker disabling it, and stay silent on a deliberate
# uninstall.
# --------------------------------------------------------------------------- #
section("4. schtasks lifecycle (real Task Scheduler)")
installed = False
try:
    rc = aegis.cmd_install(mode="scan", interval=3600)
    check("aegis.py install returned 0", rc == 0, "rc=%r" % rc)
    installed = rc == 0

    out, err, qrc = aegis.run(["schtasks", "/query", "/tn", _TASK], timeout=30)
    check("Task Scheduler reports the task exists", qrc == 0,
          (out or err or "").strip())

    snap2 = aegis._snapshot_persistence_windows()
    task_keys = [k for k in snap2 if k.startswith("task:")]
    hit = [k for k in task_keys if _TASK.lower() in k.lower()]
    check("our real task round-tripped through `schtasks /query /fo csv /v` "
          "and the CSV parser", bool(hit),
          "task keys: %s" % (", ".join(task_keys[:8]) or "(none)"))
    if hit:
        trec = snap2[hit[0]]
        check("the task's program was parsed off the real CSV row",
              bool(trec.get("program")),
              repr({k2: trec.get(k2) for k2 in ("program", "severity")}))

    findings = aegis.check_self_protection()
    agent = [f for f in findings if str(f.get("fingerprint", "")).startswith("self:agent")]
    check("a healthy installed task raises no self-protection alert",
          not agent, repr(agent))

    aegis.run(["schtasks", "/change", "/tn", _TASK, "/disable"], timeout=30)
    findings = aegis.check_self_protection()
    disabled = [f for f in findings
                if f.get("fingerprint") == "self:agent:disabled"]
    check("disabling the task is caught as HIGH self:agent:disabled",
          bool(disabled) and disabled[0].get("severity") == "HIGH",
          repr(disabled[:1]))

    aegis.run(["schtasks", "/delete", "/tn", _TASK, "/f"], timeout=30)
    findings = aegis.check_self_protection()
    removed = [f for f in findings if f.get("fingerprint") == "self:agent:removed"]
    check("deleting the task is caught as HIGH self:agent:removed",
          bool(removed) and removed[0].get("severity") == "HIGH",
          repr(removed[:1]))

    # A deliberate uninstall is not tampering: it must clear `installed` so the
    # self-protection check goes quiet rather than nagging forever.
    aegis.cmd_uninstall()
    installed = False
    findings = aegis.check_self_protection()
    agent = [f for f in findings if str(f.get("fingerprint", "")).startswith("self:agent")]
    check("a deliberate uninstall silences self-protection "
          "(uninstall is not tampering)", not agent, repr(agent))
except Exception:
    check("schtasks lifecycle block completed", False, traceback.format_exc())
finally:
    if installed:
        aegis.run(["schtasks", "/delete", "/tn", _TASK, "/f"], timeout=30)
        print("  cleanup: deleted scheduled task %s" % _TASK)


# --------------------------------------------------------------------------- #
# 5. The PowerShell-backed probes — do they come back with real data, and do
#    they honour the "false-empty is a lie" rule (None on failure, never {}).
# --------------------------------------------------------------------------- #
section("5. PowerShell probes (posture, exclusions, WMI, events, listeners)")
try:
    fw = aegis._check_hardening_windows()
    unknown = [f for f in fw if str(f.get("fingerprint", "")) == "hardening:posture:unknown"]
    check("the security-posture script executed (no posture-unknown finding)",
          not unknown, repr(unknown[:1]))
    note("hardening findings: %s"
         % (", ".join("%s/%s" % (f.get("severity"), f.get("title"))
                      for f in fw) or "(none -- machine is hardened)"))

    excl = aegis.snapshot_win_exclusions()
    check("Defender exclusion probe returned a snapshot, not a DEGRADED None",
          isinstance(excl, dict), "%r" % (excl if excl != {} else "{} (none set)"))

    wmi = aegis.snapshot_wmi_subscriptions()
    check("WMI-subscription probe returned a snapshot, not a DEGRADED None",
          isinstance(wmi, dict),
          "%r" % (wmi if wmi != {} else "{} (no subscriptions)"))

    ev = aegis.check_windows_event_log()
    if ev is None:
        note("Security event log is not readable by this principal -- reported "
             "DEGRADED, which is the honest verdict, not a silent empty")
    else:
        note("event-log check returned %d finding(s)" % len(ev))

    lis = aegis._snapshot_listeners_windows()
    check("the netstat listener snapshot parsed", isinstance(lis, dict),
          "%d listener(s): %s" % (len(lis), ", ".join(list(lis)[:6])))
except Exception:
    check("PowerShell probe block completed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
# 6. Full scan, twice — the whole plumbing against a real machine, and no
#    duplicate storm on the second pass.
# --------------------------------------------------------------------------- #
section("6. Full scan end-to-end")
try:
    notified = []
    real_notify = aegis.notify
    aegis.notify = lambda *a, **k: notified.append(a)
    try:
        rc1 = aegis.cmd_scan(quiet=True)
        n1 = len(notified)
        rc2 = aegis.cmd_scan(quiet=True)
        n2 = len(notified) - n1
    finally:
        aegis.notify = real_notify

    check("scan #1 completed cleanly", rc1 in (0, 1), "rc=%r" % rc1)
    check("scan #2 completed cleanly", rc2 in (0, 1), "rc=%r" % rc2)
    check("scan #2 did not re-storm scan #1's findings", n2 <= n1,
          "notifications: scan1=%d scan2=%d" % (n1, n2))
    check("the markdown report was written", os.path.exists(aegis.LATEST_MD),
          aegis.LATEST_MD)
    for artifact in ("baseline.json", "aegis.db"):
        p = os.path.join(aegis.STATE_DIR, artifact)
        check("scan produced %s" % artifact, os.path.exists(p), p)

    # The report is written and read back through separate handles, and then
    # printed to a PIPE (not a console) -- the exact combination that made
    # `scan` die with UnicodeEncodeError before the encoding fix, because the
    # severity icons are not representable in cp1252.
    import subprocess
    self_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "aegis.py")
    env = dict(os.environ)
    env["USERPROFILE"] = _SANDBOX
    env["HOME"] = _SANDBOX
    p = subprocess.run([sys.executable, self_path, "report"],
                       capture_output=True, timeout=120, env=env)
    check("`aegis.py report` survives having its stdout redirected to a pipe "
          "(severity icons vs the ANSI codepage)", p.returncode == 0,
          (p.stderr or b"").decode("utf-8", "replace")[-600:]
          or "%d bytes of report on stdout" % len(p.stdout))
except Exception:
    check("full-scan block completed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
section("summary")
print("checks failed: %d" % len(FAILS))
for f in FAILS:
    print("  FAILED: " + f)
print("environment notes: %d" % len(NOTES))
try:
    shutil.rmtree(_SANDBOX, ignore_errors=True)
except Exception:
    pass
sys.exit(1 if FAILS else 0)
