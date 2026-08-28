from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, User
from django.test import RequestFactory, TestCase
from django.urls import reverse

from core.models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
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
