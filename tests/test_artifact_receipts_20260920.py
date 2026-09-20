import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aegis


@pytest.fixture
def artifact(tmp_path, monkeypatch):
    if not shutil.which('ssh-keygen'):
        pytest.skip('ssh-keygen unavailable')
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
        (root / 'app').symlink_to(outside)
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
