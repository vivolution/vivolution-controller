from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "deploy" / "playbooks" / "restore-replacement-controller.yml"
JOURNAL_HELPER = ROOT / "deploy" / "scripts" / "controller_restore_journal.py"


class ReplacementRestoreStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK.read_text(encoding="utf-8")
        cls.journal_source = JOURNAL_HELPER.read_text(encoding="utf-8")

    def test_restore_is_exactly_acknowledged_and_digest_pinned(self) -> None:
        self.assertIn("RESTORE_QUALIFIED_BACKUP_TO_REPLACEMENT_CP1", self.source)
        self.assertIn("cp_import_dump_stat.stat.checksum", self.source)
        self.assertIn("cp_import_expected_sha256", self.source)
        self.assertIn("cp_import_fixed_dump_path", self.source)

    def test_restore_uses_isolated_database_and_integrity_gate(self) -> None:
        self.assertIn("vivolution_import_", self.source)
        self.assertIn("restore-integrity-check.sql", self.source)
        self.assertIn("--exit-on-error", self.source)
        self.assertIn("TABLE DATA cp_security rls_signing_key' not in", self.source)

    def test_swap_is_rollback_safe_and_plaintext_is_removed(self) -> None:
        self.assertIn("vivolution_preimport_", self.source)
        self.assertIn("vivolution_failedimport_", self.source)
        self.assertIn("SWAP_STARTED", self.source)
        self.assertIn("ROLLBACK_STARTED", self.source)
        self.assertIn("READINESS_VERIFIED", self.source)
        self.assertIn("--single-transaction", self.source)
        self.assertIn("state: absent", self.source)
        self.assertIn("RESTORE_SELECTED_VERIFIED_BACKUP", self.source)

    def test_restore_uses_a_root_owned_observed_state_journal(self) -> None:
        self.assertIn("cp1-restore-transaction-v1.json", self.source)
        self.assertIn("--production", self.source)
        self.assertIn("cp_import_observed_databases", self.source)
        self.assertIn("RESUME_SELECTED_AFTER_SWAP", self.source)
        self.assertIn("RESUME_ROLLBACK", self.source)
        self.assertIn("os.O_NOFOLLOW", self.journal_source)
        self.assertIn("os.fsync", self.journal_source)
        self.assertIn("os.replace", self.journal_source)
        self.assertIn("metadata.st_uid != 0", self.journal_source)

    def test_restore_holds_one_fixed_exclusive_lock_for_the_whole_transaction(self) -> None:
        self.assertIn("force_handlers: true", self.source)
        self.assertIn("cp1-restore-transaction-v1.lock", self.source)
        self.assertIn("vivolution-cp1-restore-transaction-lock.service", self.source)
        self.assertIn("/usr/bin/systemd-run", self.source)
        self.assertIn("--property=RuntimeMaxSec=3600", self.source)
        self.assertIn("/usr/bin/flock", self.source)
        self.assertIn("--exclusive", self.source)
        self.assertIn("--nonblock", self.source)
        self.assertIn("--no-fork", self.source)
        self.assertIn("Prove another process cannot enter", self.source)
        self.assertIn("cp_import_lock_probe.rc != 1", self.source)
        self.assertGreaterEqual(
            self.source.count("Release the restore transaction lock"), 2
        )

    def test_restored_operator_must_be_admin_login_eligible(self) -> None:
        integrity = (
            ROOT / "deploy" / "tests" / "restore-integrity-check.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("AND is_superuser", integrity)
        self.assertIn("AND is_staff", integrity)
        self.assertIn("AND is_active", integrity)
        self.assertIn("password NOT LIKE '!%'", integrity)


if __name__ == "__main__":
    unittest.main()
