#!/usr/bin/env python3
"""Every finding declares who authored its subject, or says why it cannot.

Aegis has a good answer to "is this the operator's own work, or an attack" —
the custody ladder. `_git_provenance()` grades a file `self-committed` (this
machine's own git identity created the commit), `fleet-signed` (the signature
verifies against a PINNED device roster, so it was made on one of the
operator's machines), `remote-foreign`, `local-commit`, `worktree`,
`untracked`. Above that sit `self-attested` (a supervised agent session
recorded a signed intent entry for exactly this content at write time),
`operator-vouched` (the file's own note: "the only one code running as the
operator cannot mint silently"), and package receipts. `_demote()` lowers
severity by that rung and never suppresses, never touches attack-DEFINED
evidence, and only ever moves down. `_RISK_CUSTODY_WEIGHT` keeps the demoted
findings from summing back into a HIGH.

Measured when this file was written: **139 `finding()` call sites, 10 passed a
rung.** Wiring `_diff_map`'s `subject_fn` for the four path-keyed surfaces took
that to 14; the remaining 61 debt sites are the rest of this file's roster. There is no post-hoc enrichment — `_collect_sensor` sets only
`sensor_id` — so the other 129 emit findings the grader is structurally unable
to demote, because they never tell it who authored the subject. That is the
whole of the benign-positive problem this monitor keeps re-solving one surface
at a time: not a missing discriminator, an unwired one. The operator's own
agents writing their own launchd jobs, MCP registrations, git hooks and skills
land in categories that cannot be graded, so they alarm at full severity
forever, and each round the fix is applied to whichever single surface produced
the last live incident.

This file is the ratchet. It is a ROSTER, in the shape of
test_sensor_invariants.py: a new emitter that names neither a rung nor a reason
fails here BY NAME, on the commit that adds it.

Three rosters, and the rule for each:

  GRADED               passes custody= or provenance=. May only grow.
  NO_AUTHORED_SUBJECT  a category whose subject has no author to grade — a
                       posture bit, an OS engine's own verdict, or one of
                       aegis's own tripwires (attack-defined by construction,
                       which `_demote` refuses to grade anyway). Adding a
                       category here is a claim that custody is MEANINGLESS
                       for it, not merely absent, so it carries its reason.
  CUSTODY_DEBT         the subject IS operator-authorable and the rung is
                       simply missing. May only shrink.

Where the leverage is, for whoever pays this down: 24 of the 65 debt sites are
`new_fn`/`changed_fn` closures inside ~20 `diff_*` surfaces, and every one of
them is fed to the same `_diff_map(prior, cur, new_fn, changed_fn)`. The reason
`_diff_map` cannot grade them today is that custody is PATH-shaped
(`_custody(path, sha)`) while the diff key is surface-specific — a path here,
an identifier there, a socket key elsewhere. The fix is one optional
`subject_fn` on `_diff_map` that answers "what is the subject of this key", so
the rung is attached once in the shared code instead of 24 times in closures.
Same lesson as the outbound sensor's "the socket was never the subject".

That hook now exists (`_grade_by_subject`), and four surfaces use it —
`diff_shellrc`, `diff_wallet`, `diff_python_site`, `diff_extra_persistence`,
the ones whose key IS a path and whose value carries the content hash. The other
~21 need a line each saying what their key stands for, which is a decision per
surface and not a sweep. GradeBySubject below exercises the hook; the roster
here only proves the wiring exists, never that it works.
"""
import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

# A category whose subject has no author aegis could grade. Each entry is a
# claim that custody is MEANINGLESS here, not just missing — so it needs a
# reason, and adding one should feel heavier than adding a debt entry.
NO_AUTHORED_SUBJECT = {
    "hardening": "machine posture (FileVault, SIP, firewall) — a setting off is not an artifact anyone authored",
    "coverage": "aegis reporting the reach of its own sensors",
    "integrity": "the event store's own structural health",
    "self-protection": "aegis's own files and state",
    "vouch-store": "the custody store itself; grading it with custody would be circular",
    "intel": "operator-imported indicators, already an explicit operator act",
    "xprotect": "an OS engine's own verdict, not an artifact this program can trace to an author",
    "xprotect-corpus": "the OS engine's definition corpus",
    "amfid": "an OS engine's own verdict",
    "defender": "an OS engine's own verdict",
    "gatekeeper": "an OS engine's own verdict",
    "sysmon": "an OS engine's own verdict",
    "auth-log": "an OS engine's own verdict",
    "event-log": "an OS engine's own verdict",
    "canary": "aegis's own tripwire — a tripped canary is attack-defined evidence, which _demote() refuses to grade",
    "decoy": "aegis's own tripwire — attack-defined by construction",
    "latch": "aegis's own tripwire — attack-defined by construction",
    "assay": "aegis's own tripwire — attack-defined by construction",
}

GRADED = {
    ("_beacon_from_sightings", "net-beacon"),
    ("_first_sight_agent_config", "agent-surface"),
    ("_outbound_findings", "net-outbound"),
    ("check_persistence", "persistence"),
    ("check_processes", "process"),
    ("diff_agent_surface", "agent-surface"),
    ("diff_extra_persistence._mk.f", "persistence"),
    ("diff_listeners.new_fn", "net-listener"),
    ("diff_python_site._mk.f", "persistence"),
    ("diff_shellrc._mk.f", "shell-init"),
    ("diff_wallet._mk.f", "wallet-integrity"),
}

CUSTODY_DEBT = {
    ("_assay_lanes.lane_writ_enforcement.probe", "shellrc"): 1,
    ("_check_hot_app", "hot-dir"): 2,
    ("_cmd_scan_locked", "trust"): 1,
    ("_ext_cap_finding", "extension-capability"): 1,
    ("_first_sight_agent_config", "agent-surface"): 1,
    ("_hot_elf_finding", "hot-dir"): 1,
    ("check_agent_surface_coverage", "agent-surface"): 1,
    ("check_behavior", "behavior"): 1,
    ("check_browser_automation", "session-theft"): 3,
    ("check_clipboard", "clipboard"): 1,
    ("check_cron", "persistence"): 2,
    ("check_hot_dirs", "hot-dir"): 1,
    ("check_persistence", "persistence"): 2,
    ("check_processes", "process"): 1,
    ("check_shell_history", "shell-history"): 1,
    ("check_staging", "staging"): 1,
    ("check_supply_chain", "supply-chain"): 2,
    ("check_web_protection", "web-protection"): 2,
    ("diff_agent_skills.changed_fn", "agent-skill"): 1,
    ("diff_agent_skills.new_fn", "agent-skill"): 1,
    ("diff_appinit.changed_fn", "appinit"): 1,
    ("diff_appinit.new_fn", "appinit"): 1,
    ("diff_auth_sessions.new_fn", "auth-session"): 1,
    ("diff_browserext.new_fn", "browser-ext"): 1,
    ("diff_btm.changed_fn", "btm"): 1,
    ("diff_btm.new_fn", "btm"): 1,
    ("diff_btm_store.changed_fn", "btm"): 1,
    ("diff_btm_store.new_fn", "btm"): 1,
    ("diff_com_hijack.changed_fn", "com-hijack"): 1,
    ("diff_com_hijack.new_fn", "com-hijack"): 1,
    ("diff_git_hooks", "git-surface"): 3,
    ("diff_ide_ext.new_fn", "ide-ext"): 1,
    ("diff_ifeo.changed_fn", "ifeo"): 1,
    ("diff_ifeo.new_fn", "ifeo"): 1,
    ("diff_kernel_modules.new_fn", "kernel-module"): 1,
    ("diff_loginhooks._mk.f", "persistence"): 1,
    ("diff_netconfig.changed_fn", "network-config"): 4,
    ("diff_netconfig.new_fn", "network-config"): 3,
    ("diff_profile_payloads.changed_fn", "config-profile"): 1,
    ("diff_profiles.new_fn", "config-profile"): 1,
    ("diff_session_binding.changed_fn", "session-binding"): 1,
    ("diff_session_binding.new_fn", "session-binding"): 1,
    ("diff_suid.changed_fn", "suid"): 1,
    ("diff_suid.new_fn", "suid"): 1,
    ("diff_tcc._grant_finding", "tcc"): 1,
    ("diff_wmi_subscriptions.changed_fn", "wmi"): 1,
    ("diff_wmi_subscriptions.new_fn", "wmi"): 1,
}

# Pinned totals. Both are ratchets: sites may move from DEBT to GRADED, never
# the other way, and a brand-new emitter belongs in one of the three rosters
# before it belongs on main.
DEBT_SITES_MAX = 61
MIN_CALL_SITES = 130


class _SubjectGraded(ast.NodeVisitor):
    """Functions that hand _diff_map a subject_fn, so their findings are graded
    at runtime rather than at the call site.

    Without this the roster measures a SYNTACTIC proxy (does this call pass
    custody=) for a RUNTIME property (does this finding carry a rung), and the
    moment grading moved into _diff_map the proxy stopped tracking the thing it
    proxies -- reporting debt that had actually been paid. Same class of defect
    as the sensors this file exists to police.
    """

    def __init__(self):
        self.stack = []
        self.surfaces = set()

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if (isinstance(node.func, ast.Name) and node.func.id == "_diff_map"
                and any(k.arg == "subject_fn" for k in node.keywords)):
            if self.stack:
                self.surfaces.add(self.stack[0])
        self.generic_visit(node)


class _Emitters(ast.NodeVisitor):
    """(category, qualified function, lineno, carries_a_rung) per finding()."""

    def __init__(self, subject_graded=()):
        self.stack = []
        self.rows = []
        self.subject_graded = frozenset(subject_graded)

    def visit_FunctionDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == "finding":
            cat = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                cat = node.args[1].value
            kw = {k.arg for k in node.keywords if k.arg}
            graded = bool(kw & {"custody", "provenance"})
            # ...or the surface hands _diff_map a subject_fn, which attaches the
            # rung and demotes for every finding it returns.
            if not graded and self.stack and self.stack[0] in self.subject_graded:
                graded = True
            self.rows.append((cat, ".".join(self.stack) or "<module>",
                              node.lineno, graded))
        self.generic_visit(node)


def _emitters():
    # AST, not grep: aegis.py embeds installer templates as string literals,
    # and a textual search for finding( matches inside them.
    with open(aegis.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    sg = _SubjectGraded()
    sg.visit(tree)
    v = _Emitters(sg.surfaces)
    v.visit(tree)
    return v.rows


class CustodyRoster(unittest.TestCase):
    def test_the_walk_is_not_vacuous(self):
        rows = _emitters()
        self.assertGreaterEqual(
            len(rows), MIN_CALL_SITES,
            "found only %d finding() call sites; the AST walk has stopped "
            "matching and every other assertion in this file is now vacuous"
            % len(rows))

    def test_every_emitter_is_accounted_for(self):
        unaccounted = []
        for cat, fn, lineno, graded in _emitters():
            if graded or cat in NO_AUTHORED_SUBJECT or (fn, cat) in CUSTODY_DEBT:
                continue
            unaccounted.append((fn, cat, lineno))
        self.assertEqual(
            unaccounted, [],
            "These findings name no custody rung and no reason they cannot "
            "have one. Pass custody=/provenance= (see _custody and "
            "_git_provenance), or add the category to NO_AUTHORED_SUBJECT with "
            "its reason, or — if the rung is simply missing for now — add the "
            "pair to CUSTODY_DEBT. Deciding at write time is the point: %r"
            % (unaccounted,))

    def test_graded_emitters_never_regress(self):
        still = {(fn, cat) for cat, fn, _l, g in _emitters() if g}
        lost = sorted(GRADED - still)
        self.assertEqual(
            lost, [],
            "These emitters used to pass a custody rung and no longer do. "
            "Custody is the only thing standing between the operator's own "
            "work and a full-severity alarm on it: %r" % (lost,))

    def test_debt_only_shrinks(self):
        rows = _emitters()
        debt = {}
        for cat, fn, _l, graded in rows:
            if graded or cat in NO_AUTHORED_SUBJECT:
                continue
            debt[(fn, cat)] = debt.get((fn, cat), 0) + 1
        added = sorted(set(debt) - set(CUSTODY_DEBT))
        self.assertEqual(
            added, [],
            "New ungraded emitters on an operator-authorable subject. Every "
            "one of these will alarm at full severity on the operator's own "
            "work, because the grader is never told who wrote it: %r"
            % (added,))
        self.assertLessEqual(
            sum(debt.values()), DEBT_SITES_MAX,
            "custody debt grew from %d sites to %d"
            % (DEBT_SITES_MAX, sum(debt.values())))

    def test_a_category_is_never_both_unauthored_and_in_debt(self):
        both = sorted({cat for (_fn, cat) in CUSTODY_DEBT}
                      & set(NO_AUTHORED_SUBJECT))
        self.assertEqual(
            both, [],
            "A category cannot both have no author to grade and owe a rung. "
            "One of the two rosters is wrong about it: %r" % (both,))

    def test_the_rosters_describe_this_tree(self):
        # A roster that has drifted from the source is worse than none: it
        # reads as coverage while asserting nothing.
        rows = _emitters()
        seen = {(fn, cat) for cat, fn, _l, _g in rows}
        stale = sorted((set(CUSTODY_DEBT) | GRADED) - seen)
        self.assertEqual(
            stale, [],
            "Roster entries that name emitters this tree no longer has. "
            "Remove them — a stale roster silently stops checking: %r"
            % (stale,))


class GradeBySubject(unittest.TestCase):
    """_diff_map's subject_fn hook, exercised rather than merely present.

    The roster above is an AST audit: it proves the wiring EXISTS. Only this
    proves the wiring WORKS, and the refusals matter more than the happy path --
    a demotion applied where it should not be is a security regression, while a
    demotion missed is only noise.
    """

    def setUp(self):
        self._real = aegis._custody
        aegis._custody = lambda path, sha: ("self-committed", "NOTE")

    def tearDown(self):
        aegis._custody = self._real

    @staticmethod
    def _one(new_fn, subject_fn):
        return aegis._diff_map({}, {"/tmp/x": "sha"}, new_fn,
                               subject_fn=subject_fn)

    def test_the_rung_lands_and_the_severity_demotes(self):
        out = self._one(
            lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp"),
            lambda k, v: (k, v))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["custody"], "self-committed")
        # self-committed is _SELF_CUSTODY, whose target is LOW.
        self.assertEqual(out[0]["severity"], "LOW")
        self.assertIn("NOTE", out[0]["detail"])

    def test_a_finding_that_already_carries_a_rung_is_left_alone(self):
        out = self._one(
            lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp",
                                       custody="operator-vouched"),
            lambda k, v: (k, v))
        self.assertEqual(out[0]["custody"], "operator-vouched")
        self.assertEqual(out[0]["severity"], "HIGH",
                         "the surface graded it itself; this must not re-grade")

    def test_attack_defined_evidence_is_never_demoted(self):
        out = self._one(
            lambda k, v: aegis.finding("CRITICAL", "persistence", "t", "d",
                                       "fp", attack_defined=True),
            lambda k, v: (k, v))
        self.assertEqual(
            out[0]["severity"], "CRITICAL",
            "knowing who wrote a payload is not a reason to stop calling it "
            "a payload")
        self.assertIsNone(out[0].get("custody"))

    def test_a_raising_subject_fn_leaves_the_finding_at_full_severity(self):
        def boom(k, v):
            raise RuntimeError("no subject")
        out = self._one(
            lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp"),
            boom)
        self.assertEqual(out[0]["severity"], "HIGH",
                         "failing to establish custody is a reason to keep "
                         "alarming, never to stop")

    def test_no_subject_means_no_grading(self):
        out = self._one(
            lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp"),
            lambda k, v: None)
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertIsNone(out[0].get("custody"))

    def test_no_rung_means_no_change(self):
        aegis._custody = lambda path, sha: (None, "")
        out = self._one(
            lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp"),
            lambda k, v: (k, v))
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertIsNone(out[0].get("custody"))

    def test_omitting_subject_fn_is_byte_for_byte_the_old_behaviour(self):
        mk = lambda k, v: aegis.finding("HIGH", "persistence", "t", "d", "fp")
        out = aegis._diff_map({}, {"/tmp/x": "sha"}, mk)
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertIsNone(out[0].get("custody"))


if __name__ == "__main__":
    unittest.main()
