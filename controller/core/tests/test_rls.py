from uuid import uuid4

from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase, skipUnlessDBFeature

from core.rls import tenant_scope


class TenantScopeUnitTests(SimpleTestCase):
    def test_invalid_tenant_id_is_rejected_before_database_use(self):
        with self.assertRaisesMessage(ValueError, "must be a UUID"):
            with tenant_scope("not-a-uuid"):
                pass

    def test_valid_tenant_id_is_a_noop_on_non_postgresql_test_backend(self):
        marker = []
        with tenant_scope(uuid4()):
            marker.append("inside")
        self.assertEqual(marker, ["inside"])


@skipUnlessDBFeature("supports_transactions")
class PostgreSQLRLSCatalogTests(TransactionTestCase):
    def test_scoped_tables_have_rls_and_policy(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL integration test")

        expected = {
            "core_tenantcontext",
            "core_configurationversion",
            "core_auditevent",
        }
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_policy p ON p.polrelid = c.oid
                WHERE n.nspname = current_schema()
                  AND c.relrowsecurity
                  AND p.polname = 'tenant_context_isolation'
                """
            )
            actual = {row[0] for row in cursor.fetchall()}

        self.assertTrue(expected.issubset(actual))
