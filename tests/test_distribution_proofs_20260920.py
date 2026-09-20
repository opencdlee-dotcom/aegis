import hashlib
import io
import json
import tarfile

import pytest
import aegis


def fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(aegis, 'STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setattr(aegis, 'HMAC_KEY_FILE', str(tmp_path / 'key'))
    root = tmp_path / 'install'
    root.mkdir()
    (root / 'uv').write_bytes(b'official binary')
    archive = tmp_path / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        info = tarfile.TarInfo('release/uv')
        info.size = len(b'official binary')
        tar.addfile(info, io.BytesIO(b'official binary'))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return root, archive, digest


def test_verified_archive_proof_follows_exact_bytes_not_future_versions(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    proof = aegis._distribution_prove('uv', '0.11.6', str(archive), digest,
                                     'https://github.com/astral-sh/uv/releases/tag/0.11.6', str(root))
    assert proof['matched_components'] == 1
    assert aegis._distribution_receipt(str(root / 'uv'))['package'] == 'uv'
    (root / 'uv').write_bytes(b'changed binary')
    assert aegis._distribution_receipt(str(root / 'uv')) is None


def test_changed_download_or_installed_bytes_do_not_get_proof(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        aegis._distribution_prove('uv', '0.11.6', str(archive), '0' * 64, 'official', str(root))
    (root / 'uv').write_bytes(b'modified')
    proof = aegis._distribution_prove('uv', '0.11.6', str(archive), digest, 'official', str(root))
    assert proof['matched_components'] == 0
    assert aegis._distribution_receipt(str(root / 'uv')) is None


def test_ledger_tamper_is_not_origin(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    aegis._distribution_prove('uv', '0.11.6', str(archive), digest, 'official', str(root))
    ledger = tmp_path / 'state' / 'distribution-proofs.json'
    records = json.loads(ledger.read_text())
    records[0]['package'] = 'attacker claim'
    ledger.write_text(json.dumps(records))
    assert aegis._distribution_receipt(str(root / 'uv')) is None


def test_expired_proof_is_not_origin(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    now = aegis._epoch()
    aegis._distribution_prove('uv', '0.11.6', str(archive), digest, 'official', str(root))
    monkeypatch.setattr(aegis, '_epoch', lambda: now + 31 * 86400)
    assert aegis._distribution_receipt(str(root / 'uv')) is None


def test_cli_uses_official_digest_and_does_not_accept_claimed_source(tmp_path, monkeypatch):
    import urllib.request
    root, archive, digest = fixture(tmp_path, monkeypatch)
    requests = []
    def metadata(request, timeout):
        requests.append(request.full_url)
        return io.BytesIO(json.dumps({'assets': [{'name': archive.name,
            'digest': 'sha256:' + digest}]}).encode())
    monkeypatch.setattr(urllib.request, 'urlopen', metadata)
    assert aegis.main(['aegis.py', 'distribution', 'verify', 'uv', '0.11.6',
                       str(archive), str(root)]) == 0
    assert requests == ['https://api.github.com/repos/astral-sh/uv/releases/tags/0.11.6']
    assert aegis._distribution_receipt(str(root / 'uv')) is not None
    assert aegis.cmd_distribution(['aegis.py', 'distribution', 'verify',
        'https://attacker.invalid', '0.11.6', str(archive), str(root)]) == 1
    assert len(requests) == 1


def test_cli_missing_official_digest_does_not_mint_proof(tmp_path, monkeypatch):
    import urllib.request
    root, archive, digest = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(
        json.dumps({'assets': [{'name': archive.name}]}).encode()))
    assert aegis.cmd_distribution(['aegis.py', 'distribution', 'verify',
        'uv', '0.11.6', str(archive), str(root)]) == 1
    assert aegis._distribution_receipt(str(root / 'uv')) is None


@pytest.mark.parametrize('value', [[], {'assets': None}, {'assets': [None]},
    {'assets': [{'name': 'release.tar.gz', 'digest': None}]}])
def test_cli_malformed_metadata_returns_failure(tmp_path, monkeypatch, value):
    import urllib.request
    root, archive, digest = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(json.dumps(value).encode()))
    assert aegis.cmd_distribution(['aegis.py', 'distribution', 'verify',
        'uv', '0.11.6', str(archive), str(root)]) == 1


def test_archive_metadata_member_budget(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    with tarfile.open(archive, 'w:gz') as tar:
        for index in range(40001):
            info = tarfile.TarInfo('release/d' + str(index))
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='member budget'):
        aegis._distribution_prove('uv', '1', str(archive), digest, 'official', str(root))


def test_archive_escape_is_never_read_or_extracted(tmp_path, monkeypatch):
    root, archive, digest = fixture(tmp_path, monkeypatch)
    with tarfile.open(archive, 'w:gz') as tar:
        info = tarfile.TarInfo('release/../uv')
        info.size = 1
        tar.addfile(info, io.BytesIO(b'x'))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        aegis._distribution_prove('uv', '1', str(archive), digest, 'official', str(root))
