import io

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from core.models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)

TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"


class PocInventoryCommandTests(TestCase):
    def run_command(self):
        output = io.StringIO()
        call_command(
            "reconcile_vivolution_poc",
            entra_tenant_id=TENANT_ID,
            primary_domain="",
            stdout=output,
        )
        return output.getvalue().strip()

    def test_command_creates_bounded_pending_inventory(self):
        self.assertEqual(self.run_command(), "VIVOLUTION_POC_INVENTORY_RECONCILED")

        customer = CustomerAccount.objects.get(slug="vivolution-technologies-llc")
        m365 = M365Tenant.objects.get(entra_tenant_id=TENANT_ID)
        tenant = TenantContext.objects.get(customer_account=customer, name="Vivolution POC")
        cluster = EdgeCluster.objects.get(name="cluster-uaen-poc-01")

        self.assertEqual(customer.status, CustomerAccount.Status.ACTIVE)
        self.assertEqual(m365.status, M365Tenant.Status.PENDING)
        self.assertEqual(m365.primary_domain, "")
        self.assertEqual(tenant.status, TenantContext.Status.ACTIVE)
        self.assertEqual(cluster.status, EdgeCluster.Status.PLANNED)
        self.assertEqual(cluster.service_mode, EdgeCluster.ServiceMode.SHARED_ENHANCED)
        self.assertIsNone(cluster.exclusive_customer_account_id)
        self.assertEqual(
            list(
                EdgeNode.objects.filter(cluster=cluster)
                .order_by("node_index")
                .values_list("name", "node_index", "architecture", "status")
            ),
            [
                ("sbc1", 1, EdgeNode.Architecture.AMD64, EdgeNode.Status.EXPECTED),
                ("sbc2", 2, EdgeNode.Architecture.AMD64, EdgeNode.Status.EXPECTED),
            ],
        )
        configuration = ConfigurationVersion.objects.get(tenant_context=tenant, version=1)
        self.assertEqual(configuration.state, ConfigurationVersion.State.DRAFT)
        self.assertEqual(AuditEvent.objects.count(), 1)

    def test_command_is_idempotent(self):
        self.run_command()
        self.assertEqual(self.run_command(), "VIVOLUTION_POC_INVENTORY_PRESENT")
        self.assertEqual(CustomerAccount.objects.count(), 1)
        self.assertEqual(M365Tenant.objects.count(), 1)
        self.assertEqual(TenantContext.objects.count(), 1)
        self.assertEqual(EdgeCluster.objects.count(), 1)
        self.assertEqual(EdgeNode.objects.count(), 2)
        self.assertEqual(ConfigurationVersion.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.count(), 1)

    def test_command_refuses_cross_customer_or_noncanonical_inputs(self):
        other = CustomerAccount.objects.create(name="Other", slug="other")
        M365Tenant.objects.create(
            customer_account=other,
            entra_tenant_id=TENANT_ID,
            display_name="Other",
            primary_domain="example.invalid",
        )
        with self.assertRaises(CommandError):
            self.run_command()

        with self.assertRaises(CommandError):
            call_command(
                "reconcile_vivolution_poc",
                entra_tenant_id="NOT-A-UUID",
                primary_domain="",
            )

        with self.assertRaises(CommandError):
            call_command(
                "reconcile_vivolution_poc",
                entra_tenant_id=TENANT_ID,
                primary_domain="not a domain",
            )
