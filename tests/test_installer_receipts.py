#!/usr/bin/env python3
"""Two installers that are not package managers, and the receipts they leave.

`_package_receipt` reads the receipts of Homebrew, VS Code, pipx, uv's own
interpreters, winget, Chocolatey and the distro package managers. Two more
installers on a developer's machine leave a receipt that is just as readable,
and their binaries were the residue of the live queue:

  * the cargo-dist installer (`curl ... | sh` for uv, and every Rust tool that
    ships with it) writes `<config>/<app>/<app>-receipt.json`, naming the
    install prefix and the binaries it put there. `~/.local/bin/uv` is ad-hoc
    signed by construction, so as a process it read as an unvouched binary in
    a user-writable path, and as the PROGRAM of seven LaunchAgents it did the
    same seven more times.
  * Playwright downloads its browsers into a per-user cache and writes
    `INSTALLATION_COMPLETE` beside each `<browser>-<revision>/` directory only
    after the download and extract finished. Its Firefox is a "Nightly.app"
    whose seal reads broken, and its headless shell is ad-hoc.

Both receipts are forgeable by anything running as the operator's uid, exactly
like the Homebrew receipt the ladder already trusts. That is the tier's
contract, and the last class pins it: one step, never below MEDIUM, and never
for attack-defined evidence.

Synthetic trees only. The live checks at the bottom read this body's own
receipts and skip wherever they are absent.
"""
import glob
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aegis  # noqa: E402

REAL_MAC = sys.platform == "darwin" and aegis.IS_MAC


class ReceiptSandbox(unittest.TestCase):
    """A synthetic HOME, and every environment variable either installer
    consults pointed inside it or removed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aegis_installer_receipt_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        saved_home = aegis.HOME
        aegis.HOME = self.home
        self.addCleanup(setattr, aegis, "HOME", saved_home)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for k in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                  "PLAYWRIGHT_BROWSERS_PATH"):
            os.environ.pop(k, None)
        os.environ["LOCALAPPDATA"] = os.path.join(self.tmp, "localappdata")
        aegis._CARGO_DIST_CACHE.clear()
        self.addCleanup(aegis._CARGO_DIST_CACHE.clear)

    def touch(self, path, text="x"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def symlink_or_skip(self, target, link):
        os.makedirs(os.path.dirname(link), exist_ok=True)
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as e:
            self.skipTest("cannot create a symlink here: %s" % e)
        return link


class CargoDistReceipt(ReceiptSandbox):
    """`<config>/<app>/<app>-receipt.json`, as the uv 0.11.6 installer (cargo-dist
    0.31.0) writes it: `${XDG_CONFIG_HOME:-$HOME/.config}/<app>` on posix,
    `%XDG_CONFIG_HOME%` else `%LOCALAPPDATA%` on Windows."""

    def config_root(self):
        if aegis.IS_WIN:
            return os.environ["LOCALAPPDATA"]
        return os.path.join(self.home, ".config")

    def install(self, prefix, binaries=("tool", "toolx"), layout="flat",
                app="tool", raw=None, root=None):
        receipt = {"binaries": list(binaries), "binary_aliases": {},
                   "install_layout": layout, "install_prefix": prefix,
                   "provider": {"source": "cargo-dist", "version": "0.31.0"},
                   "source": {"app_name": app, "name": app, "owner": "acme",
                              "release_type": "github"},
                   "version": "1.2.3"}
        self.touch(os.path.join(root or self.config_root(), app,
                                app + "-receipt.json"),
                   raw if raw is not None else json.dumps(receipt))
        bindir = (os.path.join(prefix, "bin")
                  if layout in ("hierarchical", "cargo-home") else prefix)
        return [self.touch(os.path.join(bindir, b)) for b in binaries
                if os.path.basename(b) == b]

    def prefix(self):
        return os.path.join(self.home, ".local", "bin")

    def test_a_listed_binary_under_the_install_prefix_answers(self):
        tool, toolx = self.install(self.prefix())
        self.assertEqual(aegis._package_receipt(tool),
                         "cargo-dist:acme/tool@1.2.3")
        self.assertEqual(aegis._package_receipt(toolx),
                         "cargo-dist:acme/tool@1.2.3")

    def test_a_sibling_the_receipt_does_not_list_does_not(self):
        """The install prefix is ~/.local/bin, which every other installer and
        every hand-copied binary shares. Only the files the receipt names are
        its own."""
        self.install(self.prefix())
        other = self.touch(os.path.join(self.prefix(), "other"))
        self.assertIsNone(aegis._package_receipt(other))

    def test_a_same_named_copy_outside_the_install_prefix_does_not(self):
        self.install(self.prefix())
        copy = self.touch(os.path.join(self.home, "Downloads", "tool"))
        self.assertIsNone(aegis._package_receipt(copy))

    def test_malformed_json_is_no_answer(self):
        tool = self.touch(os.path.join(self.prefix(), "tool"))
        self.install(self.prefix(), raw="{not json")
        self.assertIsNone(aegis._cargo_dist_receipt(tool))
        self.assertIsNone(aegis._package_receipt(tool))

    def test_a_receipt_of_the_wrong_shape_is_no_answer(self):
        tool = self.touch(os.path.join(self.prefix(), "tool"))
        for raw in ('[]', '{"binaries":"tool","install_prefix":"%s"}'
                    % self.prefix().replace("\\", "\\\\"),
                    '{"binaries":["tool"],"install_prefix":"relative/bin"}'):
            aegis._CARGO_DIST_CACHE.clear()
            self.install(self.prefix(), raw=raw)
            self.assertIsNone(aegis._package_receipt(tool), raw)

    def test_a_symlink_into_the_install_prefix_resolves(self):
        tool, _ = self.install(self.prefix())
        link = self.symlink_or_skip(
            tool, os.path.join(self.home, "bin", "tool-link"))
        self.assertEqual(aegis._package_receipt(link),
                         "cargo-dist:acme/tool@1.2.3")

    def test_a_binary_name_that_climbs_out_of_the_prefix_is_refused(self):
        """A receipt is a same-uid file. A `binaries` entry with a separator in
        it would turn it into a vouch for any path on the disk."""
        self.install(self.prefix(), binaries=("../../outside",))
        outside = self.touch(os.path.join(self.home, "outside"))
        self.assertIsNone(aegis._package_receipt(outside))

    def test_only_a_receipt_named_for_its_own_directory_is_read(self):
        tool = self.touch(os.path.join(self.prefix(), "tool"))
        receipt = {"binaries": ["tool"], "install_prefix": self.prefix(),
                   "source": {"name": "tool", "owner": "acme"},
                   "version": "1"}
        self.touch(os.path.join(self.config_root(), "tool",
                                "other-receipt.json"), json.dumps(receipt))
        self.touch(os.path.join(self.config_root(), "tool-receipt.json"),
                   json.dumps(receipt))
        self.assertIsNone(aegis._package_receipt(tool))

    def test_a_cargo_home_layout_installs_under_bin(self):
        """The installer's hierarchical layouts record the root and put the
        binaries one level down, in bin/."""
        cargo = os.path.join(self.home, ".cargo")
        tool, _ = self.install(cargo, layout="cargo-home")
        self.assertEqual(tool, os.path.join(cargo, "bin", "tool"))
        self.assertEqual(aegis._package_receipt(tool),
                         "cargo-dist:acme/tool@1.2.3")

    def test_xdg_config_home_is_honoured(self):
        xdg = os.path.join(self.tmp, "xdg-config")
        os.environ["XDG_CONFIG_HOME"] = xdg
        tool, _ = self.install(self.prefix(), root=xdg)
        self.assertEqual(aegis._package_receipt(tool),
                         "cargo-dist:acme/tool@1.2.3")

    def test_the_parse_is_cached_for_the_scan_and_reset_with_it(self):
        tool, _ = self.install(self.prefix())
        self.assertTrue(aegis._package_receipt(tool))
        os.remove(os.path.join(self.config_root(), "tool",
                               "tool-receipt.json"))
        self.assertTrue(aegis._package_receipt(tool),
                        "the receipts are parsed once per scan")
        aegis._reset_custody_probes()
        self.assertIsNone(aegis._package_receipt(tool),
                          "the next scan must read the disk again")

    def test_the_config_roots_follow_the_installer(self):
        with mock.patch.object(aegis, "IS_WIN", False):
            self.assertEqual(aegis._cargo_dist_config_roots(),
                             [os.path.join(self.home, ".config")])
        with mock.patch.object(aegis, "IS_WIN", True):
            self.assertEqual(aegis._cargo_dist_config_roots(),
                             [os.environ["LOCALAPPDATA"]])
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmp, "xdg")
        with mock.patch.object(aegis, "IS_WIN", False):
            self.assertEqual(aegis._cargo_dist_config_roots(),
                             [os.path.join(self.tmp, "xdg"),
                              os.path.join(self.home, ".config")])


class PlaywrightReceipt(ReceiptSandbox):
    """`<cache>/ms-playwright/<browser>-<revision>/INSTALLATION_COMPLETE`,
    written by Playwright's download worker after extract, never before."""

    def cache_root(self):
        roots = aegis._playwright_roots()
        self.assertEqual(len(roots), 1, roots)
        return roots[0]

    def browser(self, root, name="firefox-1543", marker=True):
        exe = self.touch(os.path.join(root, name, "firefox", "Nightly.app",
                                      "Contents", "MacOS", "firefox"))
        if marker:
            self.touch(os.path.join(root, name, "INSTALLATION_COMPLETE"), "")
        return exe

    def test_a_completed_install_answers(self):
        exe = self.browser(self.cache_root())
        self.assertEqual(aegis._package_receipt(exe),
                         "playwright:firefox-1543")

    def test_an_install_without_its_marker_does_not(self):
        """An interrupted download leaves the directory and no marker; so does
        a tree that was only made to look like one."""
        exe = self.browser(self.cache_root(), marker=False)
        self.assertIsNone(aegis._package_receipt(exe))

    def test_the_cache_root_and_the_browser_dir_themselves_do_not(self):
        root = self.cache_root()
        self.browser(root)
        self.assertIsNone(aegis._package_receipt(root))
        self.assertIsNone(aegis._package_receipt(
            os.path.join(root, "firefox-1543")))

    def test_a_directory_not_shaped_browser_revision_does_not(self):
        """Playwright keeps its own non-browser state under the same root
        (`daemon/`, `.links/`). A marker there is not one it wrote."""
        root = self.cache_root()
        for name in ("daemon", ".links", "firefox"):
            exe = self.browser(root, name=name)
            self.assertIsNone(aegis._package_receipt(exe), name)

    def test_the_same_tree_outside_any_cache_root_does_not(self):
        """The marker is only evidence where Playwright writes it. The same
        tree copied anywhere else, including a sibling whose name merely
        starts with the root's, answers nothing."""
        root = self.cache_root()
        for elsewhere in (os.path.join(self.tmp, "elsewhere"),
                          root + "-evil"):
            exe = self.browser(elsewhere)
            self.assertIsNone(aegis._package_receipt(exe), elsewhere)

    def test_playwright_browsers_path_is_honoured(self):
        custom = os.path.join(self.tmp, "custom-browsers")
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = custom
        exe = self.browser(custom, name="chromium_headless_shell-1223")
        self.assertEqual(aegis._package_receipt(exe),
                         "playwright:chromium_headless_shell-1223")

    def test_the_hidden_and_relative_forms_of_the_override_are_not_roots(self):
        """"0" means node_modules/playwright-core/.local-browsers and a relative
        value resolves against the installing process's cwd. Neither is
        knowable from here, so neither is guessed."""
        default = aegis._playwright_roots()
        for value in ("0", "relative/browsers"):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = value
            self.assertEqual(aegis._playwright_roots(), default, value)

    def test_the_default_root_follows_playwright(self):
        flags = {"mac": (True, False), "win": (False, True),
                 "linux": (False, False)}
        want = {
            "mac": os.path.join(self.home, "Library", "Caches",
                                "ms-playwright"),
            "win": os.path.join(os.environ["LOCALAPPDATA"], "ms-playwright"),
            "linux": os.path.join(self.home, ".cache", "ms-playwright"),
        }
        for body, (is_mac, is_win) in flags.items():
            with mock.patch.object(aegis, "IS_MAC", is_mac), \
                    mock.patch.object(aegis, "IS_WIN", is_win):
                self.assertEqual(aegis._playwright_roots(), [want[body]],
                                 body)
        os.environ["XDG_CACHE_HOME"] = os.path.join(self.tmp, "xdg-cache")
        with mock.patch.object(aegis, "IS_MAC", False), \
                mock.patch.object(aegis, "IS_WIN", False):
            self.assertEqual(aegis._playwright_roots(),
                             [os.path.join(self.tmp, "xdg-cache",
                                           "ms-playwright")])


class AnInstallerReceiptIsVouchedTierOnly(ReceiptSandbox):
    """Same-uid-forgeable, like the Homebrew receipt: one step, never below
    MEDIUM, and nothing at all for attack-defined evidence."""

    def graded(self, path, attack_defined=False):
        with mock.patch.object(aegis, "_vouch_covers", lambda *a: False), \
                mock.patch.object(aegis, "_custody_remember",
                                  lambda *a, **k: None):
            return aegis._grade_binary("HIGH", path,
                                       attack_defined=attack_defined)

    def test_both_grade_as_package_managed(self):
        self.assertIn("package-managed", aegis._VOUCHED_CUSTODY)
        prefix = os.path.join(self.home, ".local", "bin")
        tool = self.touch(os.path.join(prefix, "tool"))
        self.touch(os.path.join(self.home, ".config", "tool",
                                "tool-receipt.json"),
                   json.dumps({"binaries": ["tool"],
                               "install_prefix": prefix}))
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.home, ".config")
        exe = self.touch(os.path.join(aegis._playwright_roots()[0],
                                      "webkit-2359", "pw_run.sh"))
        self.touch(os.path.join(aegis._playwright_roots()[0], "webkit-2359",
                                "INSTALLATION_COMPLETE"), "")
        for path in (tool, exe):
            sev, rung, _ = self.graded(path)
            self.assertEqual((sev, rung), ("MEDIUM", "package-managed"), path)
            self.assertEqual(self.graded(path, attack_defined=True),
                             ("HIGH", None, None), path)


@unittest.skipUnless(REAL_MAC, "reads this Mac's own installer receipts")
class LiveReceiptsOnThisMac(unittest.TestCase):
    """A fixture cannot test a parser: read the receipts the real installers
    wrote on this body. Skipped wherever they are absent."""

    def setUp(self):
        aegis._CARGO_DIST_CACHE.clear()
        self.addCleanup(aegis._CARGO_DIST_CACHE.clear)

    def test_uv_answers_from_its_cargo_dist_receipt(self):
        uv = os.path.expanduser("~/.local/bin/uv")
        receipt = os.path.expanduser("~/.config/uv/uv-receipt.json")
        if not (os.path.isfile(uv) and os.path.isfile(receipt)):
            self.skipTest("no cargo-dist uv install on this body")
        self.assertTrue(
            (aegis._package_receipt(uv) or "").startswith(
                "cargo-dist:astral-sh/uv@"),
            aegis._package_receipt(uv))

    def test_the_playwright_browsers_answer(self):
        root = os.path.expanduser("~/Library/Caches/ms-playwright")
        found = []
        for pat in ("firefox-*/firefox/Nightly.app/Contents/MacOS/firefox",
                    "chromium_headless_shell-*/chrome-headless-shell-mac-*/"
                    "chrome-headless-shell"):
            for exe in glob.glob(os.path.join(root, pat)):
                d = os.path.relpath(exe, root).split(os.sep)[0]
                if os.path.isfile(os.path.join(root, d,
                                               "INSTALLATION_COMPLETE")):
                    found.append((exe, d))
        if not found:
            self.skipTest("no completed Playwright browser on this body")
        for exe, d in found:
            self.assertEqual(aegis._package_receipt(exe), "playwright:" + d)


if __name__ == "__main__":
    unittest.main()
