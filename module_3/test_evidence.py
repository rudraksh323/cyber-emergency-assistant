"""Isolated tests for Module 3 evidence handling."""

import tempfile
import unittest
from pathlib import Path

from module_3.evidence import (
    MANIFEST_NAME,
    check_hosts_file,
    collect_evidence,
    hash_evidence,
    verify_evidence,
)


class EvidenceCollectionTests(unittest.TestCase):
    def test_linux_collection_writes_commands_and_hosts_copy(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            hosts = root / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

            collected = collect_evidence(
                root / "evidence",
                os_name="Linux",
                hosts_file=hosts,
                command_runner=lambda command: "output for " + " ".join(command),
            )

            self.assertEqual(len(collected), 5)
            self.assertIn("processes.txt", collected)
            self.assertIn("hosts_file_copy.txt", collected)
            self.assertIn(
                "output for ps aux",
                (root / "evidence" / "processes.txt").read_text(encoding="utf-8"),
            )

    def test_unsupported_os_still_preserves_hosts_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            hosts = root / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")

            collected = collect_evidence(
                root / "evidence",
                os_name="Unsupported",
                hosts_file=hosts,
                command_runner=lambda command: "not called",
            )

            self.assertEqual(collected, ["hosts_file_copy.txt"])


class HostsFileTests(unittest.TestCase):
    def test_clean_hosts_file_has_no_findings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hosts = Path(temporary_directory) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            self.assertEqual(check_hosts_file(hosts), [])

    def test_poisoned_hosts_file_reports_watched_domains(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hosts = Path(temporary_directory) / "hosts"
            hosts.write_text(
                "127.0.0.1 localhost\n"
                "203.0.113.10 hdfcbank.com\n"
                "203.0.113.11 updates.avast.com # suspicious redirect\n",
                encoding="utf-8",
            )

            findings = check_hosts_file(hosts)

            self.assertEqual(len(findings), 2)
            self.assertIn("hdfcbank.com", findings[0])
            self.assertIn("updates.avast.com", findings[1])

    def test_commented_redirect_is_ignored(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            hosts = Path(temporary_directory) / "hosts"
            hosts.write_text("# 203.0.113.10 paypal.com\n", encoding="utf-8")
            self.assertEqual(check_hosts_file(hosts), [])


class IntegrityTests(unittest.TestCase):
    def test_hash_and_verify_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence = Path(temporary_directory)
            (evidence / "processes.txt").write_text("example process", encoding="utf-8")
            (evidence / "connections.txt").write_text("example socket", encoding="utf-8")

            hashes = hash_evidence(evidence)
            results = verify_evidence(evidence)

            self.assertEqual(len(hashes), 2)
            self.assertTrue(all(results.values()))
            self.assertNotIn(MANIFEST_NAME, hashes)

    def test_verification_detects_changed_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence = Path(temporary_directory)
            evidence_file = evidence / "processes.txt"
            evidence_file.write_text("original", encoding="utf-8")
            hash_evidence(evidence)

            evidence_file.write_text("changed", encoding="utf-8")

            self.assertFalse(verify_evidence(evidence)["processes.txt"])


if __name__ == "__main__":
    unittest.main()
