"""A mount attribute is evidence, not an intrusion verdict by itself."""
from unittest import mock

from conftest import aegis
from test_regression import Sandbox


class MountSignalPrecision(Sandbox):
    def observe(self, nonce, suffix=""):
        argv = ("/bin/bash -c source /opt/operator/.claude/shell-snapshots/"
                "snapshot-bash-%s-abc.sh 2>/dev/null || true && "
                "hdiutil attach /opt/images/build.dmg -nobrowse%s") % (nonce, suffix)
        with mock.patch.object(aegis, "_iter_processes", return_value=[
                ("123", "operator", "/bin/bash", argv)]), \
                mock.patch.object(aegis, "_same_owner", return_value=True), \
                mock.patch.object(aegis, "_annotate_ancestry"):
            return self._saved["check_behavior"]()[0]

    def test_session_churn_records_evidence_without_interrupts_or_incidents(self):
        observations = [self.observe(str(1789621597725 + index)) for index in range(20)]
        self.assertNotEqual(observations[0]["fingerprint"], observations[1]["fingerprint"])
        for index, finding in enumerate(observations):
            self.assertEqual("MEDIUM", finding["severity"])
            self.assertEqual(["hdiutil-nobrowse"], finding["markers"])
            routes = aegis.route_findings([finding])
            self.assertEqual(aegis.ROUTE_DIGEST, routes[finding["fingerprint"]]["route"])
            aegis.record_security_state([finding], now=1_700_000_000 + index * 60)
        db = aegis._event_connection()
        try:
            self.assertEqual(20, db.execute("SELECT count(*) FROM signals").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT count(*) FROM incidents").fetchone()[0])
            self.assertEqual(0, db.execute("SELECT count(*) FROM dismissals").fetchone()[0])
        finally:
            db.close()

    def test_mount_plus_quarantine_stripping_still_interrupts(self):
        finding = self.observe("1789621597725", "; xattr -d com.apple.quarantine /opt/images/app")
        self.assertEqual("HIGH", finding["severity"])
        self.assertIn("quarantine-strip", finding["markers"])
        self.assertEqual(aegis.ROUTE_INTERRUPT,
                         aegis.route_findings([finding])[finding["fingerprint"]]["route"])

    def test_mount_plus_password_phishing_stays_critical(self):
        finding = self.observe("1789621597725", '; osascript -e \'display dialog "Password" default answer "" with hidden answer\'')
        self.assertEqual("CRITICAL", finding["severity"])
        self.assertIn("osascript-password-phish", finding["markers"])
