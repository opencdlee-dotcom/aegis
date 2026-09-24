#!/usr/bin/env python3
"""Installers that are not package managers, and the receipts they leave.

`_package_receipt` reads the receipts of Homebrew, VS Code, pipx, uv's own
interpreters, winget, Chocolatey and the distro package managers. Four more
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
  * rustup writes `lib/rustlib/components` in every toolchain, and a
    `manifest-<component>` listing each file that component installed. The
    toolchain's `cargo` and `rustc` are ad-hoc (#539, #540).
  * `cargo install` records every crate it installed, and the binaries it put
    in `<CARGO_HOME>/bin`, in `<CARGO_HOME>/.crates2.json`.

All four receipts are forgeable by anything running as the operator's uid, exactly
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
                  "PLAYWRIGHT_BROWSERS_PATH", "RUSTUP_HOME", "CARGO_HOME"):
            os.environ.pop(k, None)
        os.environ["LOCALAPPDATA"] = os.path.join(self.tmp, "localappdata")
        for cache in (aegis._CARGO_DIST_CACHE, aegis._RUSTUP_CACHE,
                      aegis._CARGO_INSTALL_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)

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


class RustupToolchainReceipt(ReceiptSandbox):
    """`<RUSTUP_HOME>/toolchains/<tc>/lib/rustlib/components` names the
    installed components; `manifest-<component>` beside it lists what each one
    wrote, as `file:<path>` or `dir:<path>` relative to the toolchain root.
    The format is copied from a real rustup install (rust-installer-version 3).
    """

    TC = "stable-aarch64-apple-darwin"

    def toolchain(self, rustup_home=None, manifests=None, components=None):
        root = os.path.join(rustup_home or os.path.join(self.home, ".rustup"),
                            "toolchains", self.TC)
        if manifests is None:
            manifests = {
                "cargo-aarch64-apple-darwin":
                    "file:bin/cargo\nfile:etc/bash_completion.d/cargo\n",
                "rustc-aarch64-apple-darwin":
                    "file:bin/rust-lldb\nfile:bin/rustc\nfile:bin/rustdoc\n",
                "rust-docs-aarch64-apple-darwin": "dir:share/doc/rust/html\n",
            }
        if components is None:
            components = list(manifests)
        rustlib = os.path.join(root, "lib", "rustlib")
        self.touch(os.path.join(rustlib, "components"),
                   "".join(c + "\n" for c in components))
        for comp, body in manifests.items():
            self.touch(os.path.join(rustlib, "manifest-" + comp), body)
        for name in ("cargo", "rustc", "rustdoc"):
            self.touch(os.path.join(root, "bin", name))
        return root

    def label(self, comp):
        return "rustup:%s:%s" % (self.TC, comp)

    def test_a_file_a_component_manifest_lists_answers(self):
        root = self.toolchain()
        self.assertEqual(
            aegis._package_receipt(os.path.join(root, "bin", "cargo")),
            self.label("cargo-aarch64-apple-darwin"))
        self.assertEqual(
            aegis._package_receipt(os.path.join(root, "bin", "rustc")),
            self.label("rustc-aarch64-apple-darwin"))

    def test_a_file_no_manifest_lists_does_not(self):
        root = self.toolchain()
        dropped = self.touch(os.path.join(root, "bin", "cargo-dropped"))
        self.assertIsNone(aegis._package_receipt(dropped))

    def test_a_manifest_no_installed_component_names_is_not_read(self):
        """`components` is rustup's own list of what is installed. A manifest
        beside it that the list does not name is not one rustup wrote."""
        root = self.toolchain(manifests={"cargo-x": "file:bin/cargo\n",
                                         "extra-x": "file:bin/extra\n"},
                              components=["cargo-x"])
        extra = self.touch(os.path.join(root, "bin", "extra"))
        self.assertIsNone(aegis._package_receipt(extra))
        self.assertEqual(
            aegis._package_receipt(os.path.join(root, "bin", "cargo")),
            self.label("cargo-x"))

    def test_a_component_name_with_a_separator_is_refused(self):
        root = self.toolchain(manifests={}, components=["sub/extra-x"])
        self.touch(os.path.join(root, "lib", "rustlib", "manifest-sub",
                                "extra-x"), "file:bin/extra\n")
        extra = self.touch(os.path.join(root, "bin", "extra"))
        self.assertIsNone(aegis._package_receipt(extra))

    def test_a_dir_entry_vouches_for_nothing_beneath_it(self):
        """A `dir:` line names a directory the component unpacked. A file
        dropped into it later was not part of the install, so only `file:`
        lines are read."""
        root = self.toolchain()
        dropped = self.touch(os.path.join(root, "share", "doc", "rust",
                                          "html", "dropped"))
        self.assertIsNone(aegis._package_receipt(dropped))

    def test_the_same_tree_outside_a_rustup_home_does_not(self):
        root = self.toolchain(rustup_home=os.path.join(self.tmp, "elsewhere"))
        self.assertIsNone(
            aegis._package_receipt(os.path.join(root, "bin", "cargo")))

    def test_a_symlink_into_the_toolchain_resolves(self):
        root = self.toolchain()
        link = self.symlink_or_skip(os.path.join(root, "bin", "cargo"),
                                    os.path.join(self.home, "bin", "cargo"))
        self.assertEqual(aegis._package_receipt(link),
                         self.label("cargo-aarch64-apple-darwin"))

    def test_a_listed_file_swapped_for_a_link_out_does_not(self):
        """The manifest names a path inside the toolchain. A link at that path
        runs whatever it points to, which the manifest never named."""
        root = self.toolchain()
        elsewhere = self.touch(os.path.join(self.tmp, "elsewhere-bin"))
        cargo = os.path.join(root, "bin", "cargo")
        os.remove(cargo)
        self.symlink_or_skip(elsewhere, cargo)
        self.assertIsNone(aegis._package_receipt(cargo))

    def test_a_missing_components_list_is_no_answer(self):
        root = self.toolchain()
        os.remove(os.path.join(root, "lib", "rustlib", "components"))
        self.assertIsNone(
            aegis._package_receipt(os.path.join(root, "bin", "cargo")))

    def test_rustup_home_is_honoured(self):
        custom = os.path.join(self.tmp, "custom-rustup")
        os.environ["RUSTUP_HOME"] = custom
        root = self.toolchain(rustup_home=custom)
        self.assertEqual(
            aegis._package_receipt(os.path.join(root, "bin", "cargo")),
            self.label("cargo-aarch64-apple-darwin"))

    def test_the_homes_follow_rustup(self):
        default = os.path.join(self.home, ".rustup")
        self.assertEqual(aegis._rustup_homes(), [default])
        os.environ["RUSTUP_HOME"] = "relative/rustup"
        self.assertEqual(aegis._rustup_homes(), [default])
        os.environ["RUSTUP_HOME"] = os.path.join(self.tmp, "r")
        self.assertEqual(aegis._rustup_homes(),
                         [os.path.join(self.tmp, "r"), default])

    def test_the_parse_is_cached_for_the_scan_and_reset_with_it(self):
        root = self.toolchain()
        cargo = os.path.join(root, "bin", "cargo")
        self.assertTrue(aegis._package_receipt(cargo))
        os.remove(os.path.join(root, "lib", "rustlib", "components"))
        self.assertTrue(aegis._package_receipt(cargo),
                        "the manifests are parsed once per scan")
        aegis._reset_custody_probes()
        self.assertIsNone(aegis._package_receipt(cargo),
                          "the next scan must read the disk again")

    def test_the_proxies_in_cargo_bin_are_left_alone(self):
        """`~/.cargo/bin/cargo` is a link to, or a copy of, the rustup binary,
        and rustup-init leaves no receipt for rustup itself: settings.toml
        names the default toolchain and update-hashes/<tc> holds a
        channel-manifest hash, and neither records rustup's own bytes. So the
        proxies get no rung, even beside a fully receipted toolchain."""
        self.toolchain()
        self.touch(os.path.join(self.home, ".rustup", "settings.toml"),
                   'default_toolchain = "%s"\n' % self.TC)
        bindir = os.path.join(self.home, ".cargo", "bin")
        rustup = self.touch(os.path.join(bindir, "rustup"), "rustup-bytes")
        proxy = os.path.join(bindir, "cargo")
        shutil.copy(rustup, proxy)
        self.assertIsNone(aegis._package_receipt(rustup))
        self.assertIsNone(aegis._package_receipt(proxy))


class CargoInstallReceipt(ReceiptSandbox):
    """`<CARGO_HOME>/.crates2.json` is cargo's own record of `cargo install`.
    Each key is `"<crate> <version> (<source>)"` and lists the `bins` that the
    install put in `<CARGO_HOME>/bin`. The shape is copied from a real file."""

    KEY = ("tool 1.2.3 "
           "(registry+https://github.com/rust-lang/crates.io-index)")

    def install(self, cargo_home=None, installs=None, raw=None):
        cargo_home = cargo_home or os.path.join(self.home, ".cargo")
        if installs is None:
            installs = {self.KEY: {"version_req": None, "bins": ["tool"],
                                   "features": [], "profile": "release"}}
        self.touch(os.path.join(cargo_home, ".crates2.json"),
                   raw if raw is not None
                   else json.dumps({"installs": installs}))
        return cargo_home

    def test_a_listed_bin_answers(self):
        tool = self.touch(os.path.join(self.install(), "bin", "tool"))
        self.assertEqual(aegis._package_receipt(tool),
                         "cargo-install:tool@1.2.3")

    def test_a_bin_the_record_does_not_list_does_not(self):
        bindir = os.path.join(self.install(), "bin")
        for name in ("other", "rustup", "cargo"):
            path = self.touch(os.path.join(bindir, name))
            self.assertIsNone(aegis._package_receipt(path), name)

    def test_a_same_named_copy_outside_cargo_bin_does_not(self):
        self.install()
        copy = self.touch(os.path.join(self.home, "Downloads", "tool"))
        self.assertIsNone(aegis._package_receipt(copy))

    def test_a_malformed_or_misshapen_record_is_no_answer(self):
        tool = os.path.join(self.home, ".cargo", "bin", "tool")
        self.touch(tool)
        for raw in ("{not json", "[]", '{"installs": []}',
                    '{"installs": {"tool 1.2.3 (x)": {"bins": "tool"}}}',
                    '{"installs": {"tool 1.2.3 (x)": ["tool"]}}'):
            aegis._CARGO_INSTALL_CACHE.clear()
            self.install(raw=raw)
            self.assertIsNone(aegis._package_receipt(tool), raw)

    def test_a_bin_name_that_climbs_out_of_bin_is_refused(self):
        cargo_home = self.install(installs={
            self.KEY: {"bins": ["../outside"]}})
        outside = self.touch(os.path.join(cargo_home, "outside"))
        self.assertIsNone(aegis._package_receipt(outside))

    def test_a_symlink_into_cargo_bin_resolves(self):
        tool = self.touch(os.path.join(self.install(), "bin", "tool"))
        link = self.symlink_or_skip(tool, os.path.join(self.home, "bin", "t"))
        self.assertEqual(aegis._package_receipt(link),
                         "cargo-install:tool@1.2.3")

    def test_a_listed_bin_swapped_for_a_link_out_does_not(self):
        """cargo writes a file at `bin/<name>`. A link there runs whatever it
        points to, which the record never named."""
        bindir = os.path.join(self.install(), "bin")
        elsewhere = self.touch(os.path.join(self.tmp, "elsewhere-bin"))
        tool = self.symlink_or_skip(elsewhere, os.path.join(bindir, "tool"))
        self.assertIsNone(aegis._package_receipt(tool))
        self.assertIsNone(aegis._package_receipt(elsewhere))

    def test_cargo_home_is_honoured(self):
        custom = os.path.join(self.tmp, "custom-cargo")
        os.environ["CARGO_HOME"] = custom
        tool = self.touch(os.path.join(self.install(custom), "bin", "tool"))
        self.assertEqual(aegis._package_receipt(tool),
                         "cargo-install:tool@1.2.3")

    def test_the_homes_follow_cargo(self):
        default = os.path.join(self.home, ".cargo")
        self.assertEqual(aegis._cargo_homes(), [default])
        os.environ["CARGO_HOME"] = "relative/cargo"
        self.assertEqual(aegis._cargo_homes(), [default])
        os.environ["CARGO_HOME"] = os.path.join(self.tmp, "c")
        self.assertEqual(aegis._cargo_homes(),
                         [os.path.join(self.tmp, "c"), default])

    def test_the_parse_is_cached_for_the_scan_and_reset_with_it(self):
        cargo_home = self.install()
        tool = self.touch(os.path.join(cargo_home, "bin", "tool"))
        self.assertTrue(aegis._package_receipt(tool))
        os.remove(os.path.join(cargo_home, ".crates2.json"))
        self.assertTrue(aegis._package_receipt(tool),
                        "the record is parsed once per scan")
        aegis._reset_custody_probes()
        self.assertIsNone(aegis._package_receipt(tool),
                          "the next scan must read the disk again")


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

    def test_the_rust_toolchain_receipts_grade_as_package_managed(self):
        tc = os.path.join(self.home, ".rustup", "toolchains", "stable-x")
        rustlib = os.path.join(tc, "lib", "rustlib")
        self.touch(os.path.join(rustlib, "components"), "cargo-x\n")
        self.touch(os.path.join(rustlib, "manifest-cargo-x"),
                   "file:bin/cargo\n")
        cargo = self.touch(os.path.join(tc, "bin", "cargo"))
        cargo_home = os.path.join(self.home, ".cargo")
        self.touch(os.path.join(cargo_home, ".crates2.json"),
                   json.dumps({"installs": {"tool 1.0.0 (x)":
                                            {"bins": ["tool"]}}}))
        tool = self.touch(os.path.join(cargo_home, "bin", "tool"))
        for path in (cargo, tool):
            sev, rung, _ = self.graded(path)
            self.assertEqual((sev, rung), ("MEDIUM", "package-managed"), path)
            self.assertEqual(self.graded(path, attack_defined=True),
                             ("HIGH", None, None), path)


@unittest.skipUnless(REAL_MAC, "reads this Mac's own installer receipts")
class LiveReceiptsOnThisMac(unittest.TestCase):
    """A fixture cannot test a parser: read the receipts the real installers
    wrote on this body. Skipped wherever they are absent."""

    def setUp(self):
        for cache in (aegis._CARGO_DIST_CACHE, aegis._RUSTUP_CACHE,
                      aegis._CARGO_INSTALL_CACHE):
            cache.clear()
            self.addCleanup(cache.clear)

    def test_the_rustup_toolchain_cargo_and_rustc_answer(self):
        home = (os.environ.get("RUSTUP_HOME")
                or os.path.expanduser("~/.rustup"))
        found = []
        for tc in sorted(glob.glob(os.path.join(home, "toolchains", "*"))):
            if not os.path.isfile(os.path.join(tc, "lib", "rustlib",
                                               "components")):
                continue
            for name in ("cargo", "rustc"):
                exe = os.path.join(tc, "bin", name)
                if os.path.isfile(exe):
                    found.append((exe, os.path.basename(tc), name))
        if not found:
            self.skipTest("no rustup toolchain on this body")
        for exe, tc, name in found:
            got = aegis._package_receipt(exe) or ""
            self.assertTrue(got.startswith("rustup:%s:%s-" % (tc, name)),
                            (exe, got))

    def test_the_cargo_install_bins_on_disk_answer(self):
        home = (os.environ.get("CARGO_HOME")
                or os.path.expanduser("~/.cargo"))
        try:
            with open(os.path.join(home, ".crates2.json")) as f:
                installs = json.load(f).get("installs") or {}
        except (OSError, ValueError):
            installs = {}
        found = []
        for key, rec in installs.items():
            crate, version = key.split(" ")[:2]
            for b in rec.get("bins") or []:
                if os.path.isfile(os.path.join(home, "bin", b)):
                    found.append((os.path.join(home, "bin", b),
                                  "cargo-install:%s@%s" % (crate, version)))
        if not found:
            self.skipTest("no cargo-install binary present on this body")
        for exe, want in found:
            self.assertEqual(aegis._package_receipt(exe), want)

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
