import uuid

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from core.models import (
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)


class ModelTests(TestCase):
    def setUp(self):
        self.customer = CustomerAccount.objects.create(name="Customer A", slug="customer-a")
        self.m365_tenant = M365Tenant.objects.create(
            customer_account=self.customer,
            entra_tenant_id=uuid.uuid4(),
            display_name="Customer A Microsoft 365",
        )
        self.tenant_context = TenantContext.objects.create(
            customer_account=self.customer,
            m365_tenant=self.m365_tenant,
            name="primary",
        )

    def test_tenant_context_rejects_cross_customer_m365_tenant(self):
        other = CustomerAccount.objects.create(name="Customer B", slug="customer-b")
        context = TenantContext(
            customer_account=other,
            m365_tenant=self.m365_tenant,
            name="invalid",
        )

        with self.assertRaisesMessage(ValidationError, "another customer account"):
            context.full_clean()

    def test_cluster_mode_requires_correct_exclusive_owner_shape(self):
        invalid = EdgeCluster(
            name="shared-with-owner",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
            exclusive_customer_account=self.customer,
        )

        with self.assertRaises(ValidationError):
            invalid.full_clean()

    def test_edge_node_slots_are_unique_and_bounded(self):
        cluster = EdgeCluster.objects.create(
            name="edge-a", service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED
        )
        EdgeNode.objects.create(
            cluster=cluster,
            name="edge-a-1",
            node_index=1,
            architecture=EdgeNode.Architecture.ARM64,
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            EdgeNode.objects.create(
                cluster=cluster,
                name="edge-a-duplicate-slot",
                node_index=1,
                architecture=EdgeNode.Architecture.ARM64,
            )

    def test_published_configuration_requires_digest_and_timestamp(self):
        version = ConfigurationVersion(
            tenant_context=self.tenant_context,
            version=1,
            state=ConfigurationVersion.State.PUBLISHED,
        )

        with self.assertRaises(ValidationError) as raised:
            version.full_clean()

        self.assertIn("artifact_digest", raised.exception.message_dict)
        self.assertIn("published_at", raised.exception.message_dict)

        version.artifact_digest = "sha256:" + "a" * 64
        version.published_at = timezone.now()
        version.full_clean()

    def test_configuration_version_is_unique_per_tenant(self):
        ConfigurationVersion.objects.create(tenant_context=self.tenant_context, version=1)

        with self.assertRaises(IntegrityError), transaction.atomic():
            ConfigurationVersion.objects.create(tenant_context=self.tenant_context, version=1)
