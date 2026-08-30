from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
RLS_CHECK = ROOT / "deploy" / "tests" / "rls-fixtures-check.sql"
PLAYBOOK = ROOT / "deploy" / "playbooks" / "qualify-backup-restore.yml"


class BackupRestoreQualificationStaticTests(unittest.TestCase):
    def test_visibility_counts_are_bounded_to_qualification_identities(self) -> None:
        source = RLS_CHECK.read_text(encoding="utf-8")
        self.assertIn("Every count below is bounded", source)
        for table in (
            "core_tenantcontext",
            "core_configurationversion",
            "core_auditevent",
            "core_customeraccount",
            "core_m365tenant",
        ):
            self.assertNotIn(f"SELECT count(*) FROM {table})", source)
            self.assertNotIn(f"SELECT count(*) FROM {table};", source)
        self.assertIn(
            "core_edgecluster WHERE exclusive_customer_account_id IN (", source
        )
        self.assertIn(
            "core_edgenode WHERE cluster_id IN (\n"
            "        SELECT id FROM core_edgecluster WHERE "
            "exclusive_customer_account_id IN (",
            source,
        )
        for suffix in ("a0", "b0", "a1", "b1", "a2", "b2", "a4", "b4", "a5", "b5"):
            self.assertGreaterEqual(
                source.count(f"00000000-0000-4000-8000-0000000000{suffix}"),
                2,
            )

    def test_playbook_retains_the_exact_sanitized_visibility_matrix(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn(
            "['0|0|0', '0|0|0|0', '0|0|0', '0|0|0', '0|0|0',",
            source,
        )
        self.assertIn("'0|1|0|1|0|1', '2|2|2', '2|2|0|0'", source)
        self.assertIn("no_log: true", source)


if __name__ == "__main__":
    unittest.main()
