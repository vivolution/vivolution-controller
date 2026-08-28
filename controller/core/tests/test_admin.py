from django.contrib import admin
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from core.models import AuditEvent


class OperatorAdminSmokeTests(TestCase):
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
