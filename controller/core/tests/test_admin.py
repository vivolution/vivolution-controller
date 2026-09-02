from datetime import timedelta

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, User
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from core.models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    EnrollmentClaim,
    EnrollmentGrant,
    M365Tenant,
    TenantContext,
)


class OperatorAdminSmokeTests(TestCase):
    def test_identity_and_permission_models_are_not_runtime_administered(self):
        self.assertNotIn(User, admin.site._registry)
        self.assertNotIn(Group, admin.site._registry)

    def setUp(self):
        self.operator = get_user_model().objects.create_superuser(
            username="operator", email="operator@example.test", password="test-only-password"
        )
        self.client.force_login(self.operator)

    def test_registered_model_changelists_render(self):
        model_names = (
            "customeraccount",
            "m365tenant",
            "tenantcontext",
            "edgecluster",
            "edgenode",
            "enrollmentgrant",
            "enrollmentclaim",
            "configurationversion",
            "auditevent",
        )
        for model_name in model_names:
            with self.subTest(model_name=model_name):
                response = self.client.get(reverse(f"admin:core_{model_name}_changelist"))
                self.assertEqual(response.status_code, 200)

    def test_audit_events_cannot_be_added_or_deleted_through_admin(self):
        request = RequestFactory().get("/admin/")
        request.user = self.operator
        model_admin = admin.site._registry[AuditEvent]

        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_delete_permission(request))
        self.assertFalse(model_admin.has_change_permission(request))

    def test_runtime_managed_core_records_cannot_be_deleted_through_admin(self):
        request = RequestFactory().get("/admin/")
        request.user = self.operator
        for model in (
            CustomerAccount,
            M365Tenant,
            TenantContext,
            EdgeCluster,
            EdgeNode,
            ConfigurationVersion,
        ):
            with self.subTest(model=model.__name__):
                self.assertFalse(admin.site._registry[model].has_delete_permission(request))

    def test_edge_identity_and_runtime_state_are_read_only(self):
        model_admin = admin.site._registry[EdgeNode]
        self.assertTrue(
            {
                "cluster",
                "name",
                "node_index",
                "generation",
                "architecture",
                "status",
                "last_seen_at",
                "last_heartbeat_sequence",
                "last_boot_id",
                "observed_inventory_digest",
                "observed_release_digest",
                "observed_health",
            }.issubset(model_admin.readonly_fields)
        )
        request = RequestFactory().get("/admin/")
        request.user = self.operator
        for field in ("cluster", "name", "node_index", "architecture"):
            with self.subTest(field=field):
                self.assertNotIn(field, model_admin.get_readonly_fields(request))
                self.assertIn(field, model_admin.get_readonly_fields(request, EdgeNode()))

    def test_admin_can_create_an_expected_node_with_an_explicit_slot(self):
        cluster = EdgeCluster.objects.create(
            name="admin-create-cluster",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
        )
        response = self.client.post(
            reverse("admin:core_edgenode_add"),
            {
                "cluster": str(cluster.id),
                "name": "admin-created-edge",
                "node_index": "1",
                "architecture": EdgeNode.Architecture.AMD64,
                "_save": "Save",
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        node = EdgeNode.objects.get(name="admin-created-edge")
        self.assertEqual(node.node_index, 1)
        self.assertEqual(node.generation, 1)
        self.assertEqual(node.status, EdgeNode.Status.EXPECTED)

        action_url = reverse("admin:core_edgenode_changelist")
        selection = {
            "action": "issue_grant",
            "_selected_action": str(node.id),
        }
        confirmation = self.client.post(action_url, selection)
        self.assertEqual(confirmation.status_code, 200, confirmation.content)
        self.assertContains(confirmation, "Pinned enrollment-client source digest")
        self.assertEqual(EnrollmentGrant.objects.filter(node=node).count(), 0)

        issued = self.client.post(
            action_url,
            {**selection, "issue_confirmation": "yes"},
        )
        self.assertEqual(issued.status_code, 200, issued.content)
        self.assertContains(issued, "Enrollment grant issued")
        self.assertEqual(EnrollmentGrant.objects.filter(node=node).count(), 1)

    def test_enrollment_records_are_read_only(self):
        request = RequestFactory().get("/admin/")
        request.user = self.operator
        for model in (EnrollmentGrant, EnrollmentClaim):
            with self.subTest(model=model.__name__):
                model_admin = admin.site._registry[model]
                self.assertFalse(model_admin.has_add_permission(request))
                self.assertFalse(model_admin.has_change_permission(request))
                self.assertFalse(model_admin.has_delete_permission(request))

    def test_confirmation_binding_rejects_a_historical_claim(self):
        cluster = EdgeCluster.objects.create(
            name="binding-cluster",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
        )
        node = EdgeNode.objects.create(
            cluster=cluster,
            name="binding-edge",
            node_index=1,
            generation=2,
            architecture=EdgeNode.Architecture.AMD64,
        )

        claims = []
        for generation, marker in ((1, "1"), (2, "2")):
            grant = EnrollmentGrant.objects.create(
                node=node,
                token_digest=marker * 64,
                expected_release_digest="sha256:" + marker * 64,
                expires_at=timezone.now() + timedelta(minutes=10),
                issued_by=self.operator,
            )
            claims.append(
                EnrollmentClaim.objects.create(
                    grant=grant,
                    node=node,
                    generation=generation,
                    public_key=marker * 43,
                    public_key_fingerprint="sha256:" + marker * 64,
                    request_body_digest=marker * 64,
                    request_signature=marker * 86,
                    client_nonce_digest=marker * 64,
                    inventory_digest="sha256:" + marker * 64,
                    release_digest="sha256:" + marker * 64,
                )
            )

        historical, current = claims
        request = RequestFactory().post(
            "/admin/",
            {
                "claim_binding": (
                    f"{node.id}|{historical.id}|{node.generation}|"
                    f"{historical.public_key_fingerprint}"
                )
            },
        )
        request.user = self.operator
        model_admin = admin.site._registry[EdgeNode]
        queryset = EdgeNode.objects.filter(pk=node.pk)
        self.assertIsNone(model_admin._confirmed_claims(request, queryset))

        request = RequestFactory().post(
            "/admin/",
            {
                "claim_binding": (
                    f"{node.id}|{current.id}|{node.generation}|"
                    f"{current.public_key_fingerprint}"
                )
            },
        )
        request.user = self.operator
        self.assertEqual(
            model_admin._confirmed_claims(request, queryset),
            [(node, current)],
        )
