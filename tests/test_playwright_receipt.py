"""Playwright origin evidence never amounts to a blanket cache allowlist."""
import json
from unittest import mock

import pytest

import aegis


@pytest.fixture
def install(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, "HOME", str(tmp_path))
    monkeypatch.setattr(aegis, "IS_MAC", True)
    monkeypatch.setattr(aegis, "IS_WIN", False)
    cache = tmp_path / "Library" / "Caches" / "ms-playwright"
    browser = cache / "webkit-2359"
    browser.mkdir(parents=True)
    binary = browser / "browser"
    binary.write_text("fixture")
    (browser / "INSTALLATION_COMPLETE").touch()
    package = tmp_path / "node_modules" / "playwright-core"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "playwright-core"}))
    (package / "browsers.json").write_text(json.dumps({
        "browsers": [{"name": "webkit", "revision": "2359"}]}))
    (cache / ".links").mkdir()
    (cache / ".links" / "owner").write_text(str(package))
    return cache, browser, binary, package


def test_complete_matching_receipt(install):
    _, _, binary, _ = install
    assert aegis._package_receipt(str(binary)) == "playwright:webkit@2359"


@pytest.mark.parametrize("invalid", ["marker", "link", "name", "revision",
                                     "browser", "json", "shape"])
def test_incomplete_or_mismatched_receipt_fails_closed(install, invalid):
    cache, browser, binary, package = install
    if invalid == "marker":
        (browser / "INSTALLATION_COMPLETE").unlink()
    elif invalid == "link":
        (cache / ".links" / "owner").write_text(str(package / "missing"))
    elif invalid == "name":
        (package / "package.json").write_text('{"name":"other"}')
    else:
        data = {"revision": '{"browsers":[{"name":"webkit","revision":"2358"}]}',
                "browser": '{"browsers":[{"name":"firefox","revision":"2359"}]}',
                "json": "{", "shape": '{"browsers":null}'}
        (package / "browsers.json").write_text(data[invalid])
    assert aegis._playwright_receipt(str(binary)) is None


@pytest.mark.parametrize("escape", ["binary", "marker", "manifest", "link"])
def test_symlink_escape_fails_closed(install, tmp_path, escape):
    cache, browser, binary, package = install
    target = {"binary": binary, "marker": browser / "INSTALLATION_COMPLETE",
              "manifest": package / "browsers.json",
              "link": cache / ".links" / "owner"}[escape]
    outside = tmp_path / "outside"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert aegis._playwright_receipt(str(binary)) is None


def test_attack_defined_evidence_never_consults_receipts(install):
    _, _, binary, _ = install
    with mock.patch.object(aegis, "_package_receipt") as receipt:
        assert aegis._grade_binary("HIGH", str(binary), attack_defined=True) == (
            "HIGH", None, None)
    receipt.assert_not_called()
