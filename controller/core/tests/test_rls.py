import hashlib
import hmac
import time
from uuid import uuid4

from django.db import DatabaseError, connection, transaction
from django.test import (
    SimpleTestCase,
    TransactionTestCase,
    override_settings,
    skipUnlessDBFeature,
)

from core.models import (
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)
from core.rls import _build_context_token, operator_scope, tenant_scope

TEST_SIGNING_KEY = "1f" * 32
TEST_NONCE = "2a" * 16


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

    def test_tenant_token_is_canonical_and_hmac_signed(self):
        tenant_id = uuid4()
        token = _build_context_token(
            tenant_context_id=tenant_id,
            signing_key=TEST_SIGNING_KEY,
            expires_at=2_000_000_000,
            nonce=TEST_NONCE,
        )

        payload, signature = token.rsplit("|", 1)
        self.assertEqual(
            payload,
            f"v1|tenant|{tenant_id}|2000000000|{TEST_NONCE}",
        )
        self.assertEqual(
            signature,
            hmac.new(bytes.fromhex(TEST_SIGNING_KEY), payload.encode(), hashlib.sha256).hexdigest(),
        )

    def test_operator_token_cannot_select_a_tenant(self):
        with self.assertRaisesMessage(ValueError, "cannot also select a tenant"):
            _build_context_token(
                tenant_context_id=uuid4(),
                operator=True,
                signing_key=TEST_SIGNING_KEY,
            )

    def test_signing_key_and_nonce_are_strictly_validated(self):
        with self.assertRaisesMessage(ValueError, "64 lowercase hex"):
            _build_context_token(operator=True, signing_key="not-a-key")
        with self.assertRaisesMessage(ValueError, "32 lowercase hex"):
            _build_context_token(
                operator=True,
                signing_key=TEST_SIGNING_KEY,
                nonce="not-a-nonce",
            )


@skipUnlessDBFeature("supports_transactions")
class PostgreSQLRLSCatalogTests(TransactionTestCase):
    def test_scoped_tables_use_signed_only_security_definer_policy(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL integration test")

        expected = {
            ("core_tenantcontext", "tenant_context_isolation", "r"),
            ("core_tenantcontext", "operator_context_only", "*"),
            ("core_configurationversion", "tenant_context_isolation", "*"),
            ("core_auditevent", "tenant_context_isolation", "*"),
            ("core_customeraccount", "operator_context_only", "*"),
            ("core_customeraccount", "tenant_metadata_read", "r"),
            ("core_m365tenant", "operator_context_only", "*"),
            ("core_m365tenant", "tenant_metadata_read", "r"),
            ("core_edgecluster", "operator_context_only", "*"),
            ("core_edgenode", "operator_context_only", "*"),
        }
        signed_tenant = "cp_security.rls_context_allows(tenant_context_id)"
        signed_operator = "cp_security.rls_context_allows(NULL::uuid)"
        expected_expressions = {
            ("core_tenantcontext", "tenant_context_isolation", "r"): (
                "cp_security.rls_context_allows(id)",
                None,
            ),
            ("core_configurationversion", "tenant_context_isolation", "*"): (
                signed_tenant,
                signed_tenant,
            ),
            ("core_auditevent", "tenant_context_isolation", "*"): (
                signed_tenant,
                signed_tenant,
            ),
            ("core_customeraccount", "tenant_metadata_read", "r"): (
                "(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE"
                "((tenant_context.customer_account_id=core_customeraccount.id)AND"
                "cp_security.rls_context_allows(tenant_context.id))))",
                None,
            ),
            ("core_m365tenant", "tenant_metadata_read", "r"): (
                "(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE"
                "((tenant_context.m365_tenant_id=core_m365tenant.id)AND"
                "cp_security.rls_context_allows(tenant_context.id))))",
                None,
            ),
        }
        for table in (
            "core_tenantcontext",
            "core_customeraccount",
            "core_m365tenant",
            "core_edgecluster",
            "core_edgenode",
        ):
            expected_expressions[(table, "operator_context_only", "*")] = (
                signed_operator,
                signed_operator,
            )
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    c.relname,
                    p.polname,
                    p.polpermissive,
                    p.polcmd,
                    p.polroles,
                    c.relrowsecurity,
                    pg_get_userbyid(c.relowner) = current_user,
                    pg_get_expr(p.polqual, p.polrelid),
                    pg_get_expr(p.polwithcheck, p.polrelid)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_policy p ON p.polrelid = c.oid
                WHERE n.nspname = 'public'
                  AND c.relrowsecurity
                  AND c.relname = ANY(%s)
                """,
                [sorted({item[0] for item in expected})],
            )
            policies = cursor.fetchall()
            cursor.execute(
                """
                SELECT
                    p.prosecdef,
                    p.proconfig,
                    pg_get_userbyid(p.proowner) = current_user
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'cp_security'
                  AND p.proname = 'rls_context_allows'
                """
            )
            function_security = cursor.fetchone()

            cursor.execute(
                """
                SELECT
                    pg_get_userbyid(n.nspowner) = current_user,
                    pg_get_userbyid(c.relowner) = current_user
                FROM pg_namespace n
                JOIN pg_class c ON c.relnamespace = n.oid
                WHERE n.nspname = 'cp_security'
                  AND c.relname = 'rls_signing_key'
                """
            )
            security_ownership = cursor.fetchone()

        self.assertEqual(len(policies), len(expected))
        self.assertEqual(
            {(policy[0], policy[1], policy[3]) for policy in policies},
            expected,
        )
        for policy in policies:
            self.assertTrue(policy[2])
            self.assertEqual(policy[4], [0])
            self.assertTrue(policy[5])
            self.assertTrue(policy[6])
            key = (policy[0], policy[1], policy[3])
            actual_expressions = tuple(
                "".join(expression.split()) if expression is not None else None
                for expression in policy[7:9]
            )
            self.assertEqual(actual_expressions, expected_expressions[key])
        self.assertIsNotNone(function_security)
        self.assertTrue(function_security[0])
        self.assertIn("search_path=pg_catalog, pg_temp", function_security[1])
        self.assertTrue(function_security[2])
        self.assertEqual(security_ownership, (True, True))


@override_settings(
    RLS_CONTEXT_SIGNING_KEY=TEST_SIGNING_KEY,
    RLS_CONTEXT_TTL_SECONDS=60,
)
class PostgreSQLSignedContextBehaviorTests(TransactionTestCase):
    rls_tables = (
        "core_tenantcontext",
        "core_configurationversion",
        "core_auditevent",
        "core_customeraccount",
        "core_m365tenant",
        "core_edgecluster",
        "core_edgenode",
    )

    def setUp(self):
        super().setUp()
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL integration test")

        first_customer = CustomerAccount.objects.create(name="Tenant A", slug="rls-test-a")
        second_customer = CustomerAccount.objects.create(name="Tenant B", slug="rls-test-b")
        first_m365 = M365Tenant.objects.create(
            customer_account=first_customer,
            entra_tenant_id=uuid4(),
            display_name="Tenant A M365",
        )
        second_m365 = M365Tenant.objects.create(
            customer_account=second_customer,
            entra_tenant_id=uuid4(),
            display_name="Tenant B M365",
        )
        self.first_tenant = TenantContext.objects.create(
            customer_account=first_customer,
            m365_tenant=first_m365,
            name="primary",
        )
        self.second_tenant = TenantContext.objects.create(
            customer_account=second_customer,
            m365_tenant=second_m365,
            name="primary",
        )
        self.first_version = ConfigurationVersion.objects.create(
            tenant_context=self.first_tenant,
            version=1,
        )
        self.second_version = ConfigurationVersion.objects.create(
            tenant_context=self.second_tenant,
            version=1,
        )
        self.edge_cluster = EdgeCluster.objects.create(
            name="rls-test-cluster",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
        )
        self.edge_node = EdgeNode.objects.create(
            cluster=self.edge_cluster,
            name="rls-test-node",
            node_index=1,
            architecture=EdgeNode.Architecture.ARM64,
        )

        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO cp_security.rls_signing_key AS installed_key
                    (singleton, key_material)
                VALUES (true, decode(%s, 'hex'))
                ON CONFLICT (singleton) DO UPDATE
                SET key_material = EXCLUDED.key_material,
                    rotated_at = statement_timestamp()
                """,
                [TEST_SIGNING_KEY],
            )
            for table in self.rls_tables:
                cursor.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')

    def tearDown(self):
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                for table in self.rls_tables:
                    cursor.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        super().tearDown()

    @staticmethod
    def _set_raw_context(token):
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('app.rls_context', %s, true)", [token])

    def test_legacy_contexts_are_denied_after_signed_only_cutover(self):
        with transaction.atomic():
            self._set_raw_context("")
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.is_operator', 'true', true)")
            self.assertEqual(TenantContext.objects.count(), 0)

        with transaction.atomic():
            self._set_raw_context("")
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.is_operator', '', true)")
                cursor.execute(
                    "SELECT set_config('app.tenant_context_id', %s, true)",
                    [str(self.first_tenant.id)],
                )
            self.assertEqual(
                list(TenantContext.objects.values_list("id", flat=True)),
                [],
            )

    def test_forged_signed_operator_context_is_denied(self):
        forged_token = (
            "v1|operator|-|"
            f"{int(time.time()) + 60}|{TEST_NONCE}|{'0' * 64}"
        )
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.is_operator', '', true)")
                cursor.execute("SELECT set_config('app.tenant_context_id', '', true)")
            self._set_raw_context(forged_token)
            self.assertEqual(TenantContext.objects.count(), 0)
            self.assertEqual(ConfigurationVersion.objects.count(), 0)
            self.assertEqual(CustomerAccount.objects.count(), 0)
            self.assertEqual(EdgeCluster.objects.count(), 0)

    def test_forged_and_expired_tenant_contexts_are_denied(self):
        forged = (
            f"v1|tenant|{self.first_tenant.id}|{int(time.time()) + 60}|"
            f"{TEST_NONCE}|{'0' * 64}"
        )
        expired = _build_context_token(
            tenant_context_id=self.first_tenant.id,
            signing_key=TEST_SIGNING_KEY,
            expires_at=int(time.time()) - 1,
            nonce=TEST_NONCE,
        )
        for token in (forged, expired):
            with self.subTest(token=token), transaction.atomic():
                self._set_raw_context(token)
                self.assertEqual(TenantContext.objects.count(), 0)
                self.assertEqual(ConfigurationVersion.objects.count(), 0)

    def test_valid_tenant_context_reads_only_its_rows(self):
        with tenant_scope(self.first_tenant.id):
            self.assertEqual(
                list(TenantContext.objects.values_list("id", flat=True)),
                [self.first_tenant.id],
            )
            self.assertEqual(
                list(ConfigurationVersion.objects.values_list("id", flat=True)),
                [self.first_version.id],
            )

    def test_global_metadata_requires_signed_operator_context(self):
        with tenant_scope(self.first_tenant.id):
            self.assertEqual(
                list(CustomerAccount.objects.values_list("id", flat=True)),
                [self.first_tenant.customer_account_id],
            )
            self.assertEqual(
                list(M365Tenant.objects.values_list("id", flat=True)),
                [self.first_tenant.m365_tenant_id],
            )
            self.assertEqual(EdgeCluster.objects.count(), 0)
            self.assertEqual(EdgeNode.objects.count(), 0)
            with self.assertRaises(DatabaseError), transaction.atomic():
                CustomerAccount.objects.create(name="Denied", slug="denied")

        with operator_scope():
            self.assertEqual(CustomerAccount.objects.count(), 2)
            self.assertEqual(M365Tenant.objects.count(), 2)
            self.assertEqual(EdgeCluster.objects.count(), 1)
            self.assertEqual(EdgeNode.objects.count(), 1)
            self.first_tenant.customer_account.status = CustomerAccount.Status.SUSPENDED
            self.first_tenant.customer_account.save(update_fields=["status"])

    def test_valid_operator_context_reads_all_rows(self):
        with operator_scope():
            self.assertEqual(TenantContext.objects.count(), 2)
            self.assertEqual(ConfigurationVersion.objects.count(), 2)

    def test_nested_operator_scope_restores_outer_tenant_scope(self):
        with tenant_scope(self.first_tenant.id):
            self.assertEqual(TenantContext.objects.count(), 1)
            with operator_scope():
                self.assertEqual(TenantContext.objects.count(), 2)
            self.assertEqual(
                list(TenantContext.objects.values_list("id", flat=True)),
                [self.first_tenant.id],
            )

    def test_nested_tenant_scope_restores_outer_operator_scope(self):
        with operator_scope():
            self.assertEqual(TenantContext.objects.count(), 2)
            with tenant_scope(self.first_tenant.id):
                self.assertEqual(
                    list(TenantContext.objects.values_list("id", flat=True)),
                    [self.first_tenant.id],
                )
            self.assertEqual(TenantContext.objects.count(), 2)

    def test_tenant_context_denies_cross_tenant_updates_and_inserts(self):
        with tenant_scope(self.first_tenant.id):
            own_updates = ConfigurationVersion.objects.filter(pk=self.first_version.id).update(
                state=ConfigurationVersion.State.VALIDATED
            )
            cross_tenant_updates = ConfigurationVersion.objects.filter(
                pk=self.second_version.id
            ).update(state=ConfigurationVersion.State.VALIDATED)

            self.assertEqual(own_updates, 1)
            self.assertEqual(cross_tenant_updates, 0)
            with self.assertRaises(DatabaseError), transaction.atomic():
                ConfigurationVersion.objects.create(
                    tenant_context_id=self.second_tenant.id,
                    version=2,
                )

    def test_tenant_cannot_rebind_or_create_tenant_contexts(self):
        with tenant_scope(self.first_tenant.id):
            self.assertEqual(
                TenantContext.objects.filter(pk=self.first_tenant.id).update(
                    customer_account_id=self.second_tenant.customer_account_id,
                    m365_tenant_id=self.second_tenant.m365_tenant_id,
                    status=TenantContext.Status.SUSPENDED,
                ),
                0,
            )
            with self.assertRaises(DatabaseError), transaction.atomic():
                TenantContext.objects.create(
                    customer_account_id=self.first_tenant.customer_account_id,
                    m365_tenant_id=self.first_tenant.m365_tenant_id,
                    name="denied",
                )

        with operator_scope():
            self.assertEqual(
                TenantContext.objects.filter(pk=self.first_tenant.id).update(
                    status=TenantContext.Status.SUSPENDED
                ),
                1,
            )
