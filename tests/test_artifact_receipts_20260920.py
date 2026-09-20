import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aegis


def make_link(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if sys.platform == 'win32' and getattr(exc, 'winerror', None) == 1314:
            pytest.skip('Windows symlink privilege unavailable for this link-specific test')
        raise


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    if not shutil.which('ssh-keygen'):
        pytest.skip('ssh-keygen unavailable')
    # simbody changes grading flags, not the host kernel. Only the real
    # subprocess adapter needs the actual host's environment/tool mapping.
    # Native runs retain the unmodified production verifier and trust roster.
    if aegis.IS_WIN != (sys.platform == 'win32'):
        native_run = aegis.run
        def host_run(*args, **kwargs):
            with patch.multiple(aegis, IS_WIN=sys.platform == 'win32',
                                IS_MAC=sys.platform == 'darwin',
                                IS_LINUX=sys.platform.startswith('linux')):
                return native_run(*args, **kwargs)
        monkeypatch.setattr(aegis, 'run', host_run)
    key = tmp_path / 'key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    roster = tmp_path / 'signers'
    roster.write_text('builder ' + key.with_suffix('.pub').read_text())
    monkeypatch.setattr(aegis, 'FLEET_SIGNERS', str(roster))
    monkeypatch.setattr(aegis, 'STATE_DIR', str(tmp_path / 'state'))
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'app').write_bytes(b'known build')
    manifest = {'version': 1, 'world': 'brain', 'project': 'demo',
                'source_revision': 'a' * 40, 'dirty_digest': None,
                'recipe': 'build-v1', 'toolchain': 'compiler-v1',
                'dependency_digest': 'b' * 64, 'platform': sys.platform,
                'principal': 'builder', 'issued': aegis._epoch(),
                'expires': aegis._epoch() + 3600, 'components': ['app']}
    spec = tmp_path / 'spec.json'
    spec.write_text(json.dumps(manifest))
    receipt = tmp_path / 'receipt.json'
    assert aegis.cmd_artifact(['aegis', 'artifact', 'create', str(source), str(spec), str(key), str(receipt)]) == 0
    copied = tmp_path / 'copied'
    shutil.copytree(source, copied)
    return copied, receipt, roster


def receive(artifact):
    root, receipt, _ = artifact
    return aegis.cmd_artifact(['aegis', 'artifact', 'receive', str(root), str(receipt), 'brain', 'demo'])


def test_real_signature_copy_and_shadow(artifact, monkeypatch):
    root, _, _ = artifact
    assert receive(artifact) == 0
    assert aegis._artifact_receipt(str(root / 'app'))['project'] == 'demo'
    for name in ('_vouch_covers', '_package_receipt', '_build_output_rung', '_custody_carried', '_vouch_superseded_note'):
        monkeypatch.setattr(aegis, name, lambda *a, **kw: None)
    severity, rung, note = aegis._grade_binary('HIGH', str(root / 'app'))
    assert (severity, rung) == ('HIGH', None)
    assert 'shadow' in note.lower()
    assert aegis._grade_binary('CRITICAL', str(root / 'app'), attack_defined=True) == ('CRITICAL', None, None)
    (root / 'app').write_bytes(b'changed build')
    assert aegis._artifact_receipt(str(root / 'app')) is None
    assert aegis._grade_binary('HIGH', str(root / 'app'))[:2] == ('HIGH', None)


@pytest.mark.parametrize('failure', ['revoked', 'project', 'world', 'platform', 'expired', 'symlink', 'scope', 'unknown', 'extra'])
def test_rejected_receipts(artifact, failure, tmp_path):
    root, receipt, roster = artifact
    assert receive(artifact) == 0
    if failure == 'revoked':
        roster.write_text('')
    elif failure == 'extra':
        (root / 'injected-library').write_bytes(b'new helper')
    elif failure == 'symlink':
        outside = tmp_path / 'outside'
        outside.write_bytes((root / 'app').read_bytes())
        (root / 'app').unlink()
        make_link(root / 'app', outside)
    elif failure == 'scope':
        other = tmp_path / 'other'
        shutil.copytree(root, other)
        assert aegis._artifact_receipt(str(other / 'app')) is None
        return
    else:
        record = json.loads(receipt.read_text())
        record[{'unknown': 'principal', 'expired': 'expires'}.get(failure, failure)] = 0 if failure == 'expired' else 'wrong'
        record['sig'] = aegis._vouch_sign(aegis._vouch_canonical(record), str(tmp_path / 'key'), 'aegis-artifact')
        receipt.write_text(json.dumps(record))
        assert receive(artifact) == 1
        return
    assert aegis._artifact_receipt(str(root / 'app')) is None


def test_real_cli_verify(artifact, tmp_path):
    root, receipt, roster = artifact
    state = tmp_path / '.aegis'
    state.mkdir()
    shutil.copyfile(roster, state / 'allowed_signers')
    env = dict(os.environ, HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    result = subprocess.run([sys.executable, aegis.__file__, 'artifact', 'verify',
                             str(root), str(receipt), 'brain', 'demo'],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'shadow only' in result.stdout


def test_framework_links_and_cache(artifact, tmp_path, monkeypatch):
    root, receipt, _ = artifact
    framework = root / 'Contents' / 'Frameworks' / 'Demo.framework'
    version = framework / 'Versions' / 'A'
    version.mkdir(parents=True)
    (version / 'Demo').write_bytes(b'framework code')
    make_link(framework / 'Versions' / 'Current', 'A', directory=True)
    make_link(framework / 'Demo', 'Versions/Current/Demo')
    spec = json.loads(receipt.read_text())
    spec['components'] = ['app', 'Contents/Frameworks/Demo.framework/Versions/A/Demo',
                          'Contents/Frameworks/Demo.framework/Versions/Current',
                          'Contents/Frameworks/Demo.framework/Demo']
    spec_path = tmp_path / 'framework-spec.json'
    spec_path.write_text(json.dumps(spec))
    signed = tmp_path / 'framework-receipt.json'
    assert aegis.cmd_artifact(['aegis', 'artifact', 'create', str(root), str(spec_path),
                               str(tmp_path / 'key'), str(signed)]) == 0
    copied = tmp_path / 'Copied.app'
    shutil.copytree(root, copied, symlinks=True)
    assert aegis.cmd_artifact(['aegis', 'artifact', 'receive', str(copied), str(signed), 'brain', 'demo']) == 0
    original = aegis._artifact_components
    calls = []
    def counted(*args):
        calls.append(1)
        return original(*args)
    monkeypatch.setattr(aegis, '_artifact_components', counted)
    aegis._ARTIFACT_SCAN_CACHE.clear()
    assert aegis._artifact_receipt(str(copied / 'app'))
    assert aegis._artifact_receipt(str(copied / 'Contents/Frameworks/Demo.framework/Demo'))
    assert aegis._artifact_receipt(str(copied / 'Contents/Frameworks/Demo.framework/Versions/Current/Demo'))
    assert len(calls) == 1
    target = copied / 'Contents/Frameworks/Demo.framework/Versions/A/Demo'
    old = target.stat()
    target.write_bytes(b'changed   code')
    os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))
    assert aegis._artifact_receipt(str(copied / 'app')) is None
    target.write_bytes(b'framework code')
    assert aegis._artifact_receipt(str(copied / 'app'))
    (copied / 'new-helper').write_bytes(b'unlisted')
    assert aegis._artifact_receipt(str(copied / 'app')) is None


def test_link_cycles_rejected(artifact):
    root, _, _ = artifact
    make_link(root / 'loop', 'loop')
    with pytest.raises(ValueError):
        aegis._artifact_components(str(root), ['app', 'loop'])
    (root / 'loop').unlink()
    make_link(root / 'loop', '.', directory=True)
    with pytest.raises(ValueError):
        aegis._artifact_components(str(root), ['app', 'loop'])


def test_malformed_unrelated_binding_does_not_hide_valid_receipt(artifact, monkeypatch):
    root, _, _ = artifact
    assert receive(artifact) == 0
    directory = Path(aegis.STATE_DIR) / 'artifact_receipts'
    valid = next(directory.iterdir()).name
    (directory / 'unrelated.json').write_text('{invalid')
    original = os.listdir
    monkeypatch.setattr(os, 'listdir', lambda path: ['unrelated.json', valid]
                        if path == str(directory) else original(path))
    assert aegis._artifact_receipt(str(root / 'app'))
    assert any('artifact binding' in row[1]
               for row in aegis._UNEXAMINED.get('(direct)', []))


def test_bad_current_receipt_never_falls_back_to_backup(artifact):
    root, _, _ = artifact
    assert receive(artifact) == 0
    directory = Path(aegis.STATE_DIR) / 'artifact_receipts'
    current = next(directory.iterdir())
    (directory / 'old-good.json').write_bytes(current.read_bytes())
    current.write_text('{invalid')
    assert aegis._artifact_receipt(str(root / 'app')) is None
