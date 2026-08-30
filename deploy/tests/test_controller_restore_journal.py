from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "scripts" / "controller_restore_journal.py"
SPEC = importlib.util.spec_from_file_location("controller_restore_journal", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
journal_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = journal_module
SPEC.loader.exec_module(journal_module)


class ControllerRestoreJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = "a" * 64
        token = self.digest[:16]
        self.identity = journal_module.RestoreIdentity(
            expected_sha256=self.digest,
            main_database="vivolution",
            import_database=f"vivolution_import_{token}",
            previous_database=f"vivolution_preimport_{token}",
            failed_database=f"vivolution_failedimport_{token}",
        )
        self.main = self.identity.main_database
        self.imported = self.identity.import_database
        self.previous = self.identity.previous_database
        self.failed = self.identity.failed_database

    def action(self, phase: str | None, databases: set[str]) -> str:
        value = None if phase is None else self.identity.journal(phase)
        return journal_module.reconcile_action(value, databases, self.identity)

    def test_every_import_and_swap_crash_checkpoint_has_one_safe_action(self) -> None:
        cases = (
            (None, {self.main}, "START"),
            ("IMPORT_STARTED", {self.main}, "BEGIN_IMPORT"),
            ("IMPORT_STARTED", {self.main, self.imported}, "RESTART_IMPORT"),
            ("PREPARED", {self.main, self.imported}, "RESUME_PREPARED"),
            ("SWAP_STARTED", {self.main, self.imported}, "RESUME_SWAP"),
            (
                "SWAP_STARTED",
                {self.main, self.previous},
                "RESUME_SELECTED_AFTER_SWAP",
            ),
            ("SELECTED", {self.main, self.previous}, "RESUME_READINESS"),
            (
                "READINESS_VERIFIED",
                {self.main, self.previous},
                "FINALIZE_COMPLETE",
            ),
            (
                "ROLLBACK_STARTED",
                {self.main, self.previous},
                "RESUME_ROLLBACK",
            ),
            (
                "ROLLBACK_STARTED",
                {self.main, self.failed},
                "FINALIZE_ROLLBACK",
            ),
            ("ROLLED_BACK", {self.main, self.failed}, "ROLLED_BACK"),
            ("COMPLETE", {self.main, self.previous}, "COMPLETE"),
        )
        for phase, databases, expected in cases:
            with self.subTest(phase=phase, databases=databases):
                self.assertEqual(self.action(phase, databases), expected)

    def test_atomic_database_transaction_cannot_be_misclassified(self) -> None:
        with self.assertRaisesRegex(
            journal_module.RestoreJournalError, "conflicts with observed"
        ):
            self.action("SWAP_STARTED", {self.previous, self.imported})
        with self.assertRaisesRegex(
            journal_module.RestoreJournalError, "conflicts with observed"
        ):
            self.action("ROLLBACK_STARTED", {self.main, self.previous, self.failed})

    def test_deterministic_database_without_journal_is_refused(self) -> None:
        with self.assertRaisesRegex(
            journal_module.RestoreJournalError, "without a durable journal"
        ):
            self.action(None, {self.main, self.imported})

    def test_identity_is_digest_bound_and_rejects_cross_restore_replay(self) -> None:
        other = journal_module.RestoreIdentity(
            expected_sha256="b" * 64,
            main_database="vivolution",
            import_database=f"vivolution_import_{'b' * 16}",
            previous_database=f"vivolution_preimport_{'b' * 16}",
            failed_database=f"vivolution_failedimport_{'b' * 16}",
        )
        with self.assertRaisesRegex(
            journal_module.RestoreJournalError, "exact identity"
        ):
            journal_module.reconcile_action(
                self.identity.journal("PREPARED"),
                {other.main_database, other.import_database},
                other,
            )

    def test_atomic_journal_transitions_are_ordered_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal_path = Path(directory) / "restore.json"
            journal_module.transition(
                journal_path,
                self.identity,
                "IMPORT_STARTED",
                production=False,
            )
            self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
            value = journal_module.load_journal(
                journal_path, self.identity, production=False
            )
            self.assertEqual(value, self.identity.journal("IMPORT_STARTED"))
            journal_module.transition(
                journal_path, self.identity, "PREPARED", production=False
            )
            self.assertEqual(
                journal_module.load_journal(
                    journal_path, self.identity, production=False
                )["phase"],
                "PREPARED",
            )
            self.assertEqual(
                [path.name for path in Path(directory).iterdir()], ["restore.json"]
            )
            with self.assertRaisesRegex(
                journal_module.RestoreJournalError, "transition"
            ):
                journal_module.transition(
                    journal_path, self.identity, "SELECTED", production=False
                )

    def test_symlink_permissive_and_extended_journals_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            linked = root / "restore.json"
            linked.symlink_to(target)
            with self.assertRaises(OSError):
                journal_module.load_journal(linked, self.identity, production=False)

            linked.unlink()
            linked.write_text(
                json.dumps(self.identity.journal("IMPORT_STARTED")), encoding="utf-8"
            )
            linked.chmod(0o644)
            with self.assertRaisesRegex(
                journal_module.RestoreJournalError, "mode must be 0600"
            ):
                journal_module.load_journal(linked, self.identity, production=False)

            value = self.identity.journal("IMPORT_STARTED")
            value["unexpected"] = True
            linked.write_text(json.dumps(value), encoding="utf-8")
            linked.chmod(0o600)
            with self.assertRaisesRegex(
                journal_module.RestoreJournalError, "exact identity"
            ):
                journal_module.load_journal(linked, self.identity, production=False)

    def test_bounded_clear_only_removes_an_exact_preselection_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal_path = Path(directory) / "restore.json"
            journal_module.transition(
                journal_path,
                self.identity,
                "IMPORT_STARTED",
                production=False,
            )
            with self.assertRaisesRegex(
                journal_module.RestoreJournalError, "phase changed"
            ):
                journal_module.clear_journal(
                    journal_path,
                    self.identity,
                    "PREPARED",
                    production=False,
                )
            journal_module.clear_journal(
                journal_path,
                self.identity,
                "IMPORT_STARTED",
                production=False,
            )
            self.assertFalse(journal_path.exists())

            journal_module.transition(
                journal_path,
                self.identity,
                "IMPORT_STARTED",
                production=False,
            )
            journal_module.transition(
                journal_path, self.identity, "PREPARED", production=False
            )
            journal_module.transition(
                journal_path, self.identity, "SWAP_STARTED", production=False
            )
            journal_module.transition(
                journal_path, self.identity, "SELECTED", production=False
            )
            with self.assertRaisesRegex(
                journal_module.RestoreJournalError, "pre-selection"
            ):
                journal_module.clear_journal(
                    journal_path,
                    self.identity,
                    "SELECTED",
                    production=False,
                )

if __name__ == "__main__":
    unittest.main()
