from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def read(relative_path):
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


class TurnkeyDatabaseSessionStaticTests(unittest.TestCase):
    def test_runtime_uses_exact_shared_database_session_alias(self):
        defaults = read("deploy/roles/controller_services/defaults/main.yml")
        turnkey_play = read("installer/ansible/install-controller.yml")
        environment = read(
            "deploy/roles/controller_services/templates/runtime.env.j2"
        )
        settings = read("controller/cp1/settings.py")

        self.assertIn("cp_controller_session_engine: file", defaults)
        self.assertNotIn("cp_controller_session_engine: db", defaults)
        self.assertIn("cp_controller_session_engine: db", turnkey_play)
        self.assertIn(
            "DJANGO_SESSION_ENGINE={{ cp_controller_session_engine }}", environment
        )
        self.assertIn(
            "DJANGO_SESSION_COOKIE_AGE_SECONDS={{ cp_controller_session_cookie_age }}",
            environment,
        )
        self.assertIn('def env_session_engine(name="DJANGO_SESSION_ENGINE", default="file")', settings)
        self.assertIn('"db": "django.contrib.sessions.backends.db"', settings)

    def test_runtime_acl_grants_only_required_ephemeral_table_deletes(self):
        sql = read(
            "deploy/roles/postgres_local/templates/runtime-privileges.sql.j2"
        )

        self.assertIn("ELSIF existing_relation.relname = 'django_session' THEN", sql)
        self.assertIn(
            "ELSIF existing_relation.relname = 'core_enrollmentchallenge' THEN",
            sql,
        )
        self.assertIn(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO %I", sql
        )
        self.assertIn("ELSIF relation.relname = 'django_session' THEN", sql)
        for privilege in ("'SELECT'", "'INSERT'", "'UPDATE'", "'DELETE'"):
            self.assertIn(privilege, sql)
        self.assertIn(
            "CP_RUNTIME_PRIVILEGES_OK=shared-db-sessions-challenge-retention-auth-readonly-core-dml",
            sql,
        )

    def test_reconcile_and_read_only_checks_require_the_same_contract_marker(self):
        expected = (
            "CP_RUNTIME_PRIVILEGES_OK=shared-db-sessions-challenge-retention-auth-readonly-core-dml"
        )
        reconcile = read(
            "deploy/roles/postgres_local/tasks/runtime_privileges.yml"
        )
        check = read(
            "deploy/roles/postgres_local/tasks/runtime_privileges_check.yml"
        )

        self.assertIn(expected, reconcile)
        self.assertIn(expected, check)
        self.assertNotIn("file-sessions-auth-readonly-core-dml", reconcile + check)


if __name__ == "__main__":
    unittest.main()
