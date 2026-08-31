import io

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from core.management.commands.transition_vivolution_poc_m365_authority import (
    ACKNOWLEDGEMENT,
    AUDIT_ACTION,
    SOURCE_ENTRA_TENANT_ID,
    TARGET_ENTRA_TENANT_ID,
    TARGET_PRIMARY_DOMAIN,
)
from core.models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)


class PocM365AuthorityTransitionCommandTests(TestCase):
    def setUp(self):
        call_command(
            "reconcile_vivolution_poc",
            entra_tenant_id=SOURCE_ENTRA_TENANT_ID,
            primary_domain="",
            stdout=io.StringIO(),
        )

    def transition(self, **overrides):
        values = {
            "from_entra_tenant_id": SOURCE_ENTRA_TENANT_ID,
            "to_entra_tenant_id": TARGET_ENTRA_TENANT_ID,
            "to_primary_domain": TARGET_PRIMARY_DOMAIN,
            "acknowledge": ACKNOWLEDGEMENT,
        }
        values.update(overrides)
        output = io.StringIO()
        call_command(
            "transition_vivolution_poc_m365_authority",
            stdout=output,
            **values,
        )
        return output.getvalue().strip()

    def test_transition_is_atomic_audited_and_idempotent(self):
        self.assertEqual(
            self.transition(), "VIVOLUTION_POC_M365_AUTHORITY_TRANSITIONED"
        )
        source = M365Tenant.objects.get(entra_tenant_id=SOURCE_ENTRA_TENANT_ID)
        target = M365Tenant.objects.get(entra_tenant_id=TARGET_ENTRA_TENANT_ID)
        tenant = TenantContext.objects.get(name="Vivolution POC")

        self.assertEqual(source.status, M365Tenant.Status.DISABLED)
        self.assertEqual(source.primary_domain, "")
        self.assertIsNone(source.verified_at)
        self.assertEqual(target.status, M365Tenant.Status.PENDING)
        self.assertEqual(target.primary_domain, TARGET_PRIMARY_DOMAIN)
        self.assertIsNone(target.verified_at)
        self.assertEqual(tenant.m365_tenant, target)

        event = AuditEvent.objects.get(action=AUDIT_ACTION)
        self.assertEqual(event.tenant_context, tenant)
        self.assertEqual(event.target_type, "M365Tenant")
        self.assertEqual(event.target_id, TARGET_ENTRA_TENANT_ID)
        self.assertEqual(
            event.detail,
            {
                "fromEntraTenantId": SOURCE_ENTRA_TENANT_ID,
                "primaryDomain": TARGET_PRIMARY_DOMAIN,
                "scope": "FIRST_TENANT_POC",
                "toEntraTenantId": TARGET_ENTRA_TENANT_ID,
                "verificationState": "PENDING_EVIDENCE_BOUND_CP1_VERIFICATION",
            },
        )

        self.assertEqual(self.transition(), "VIVOLUTION_POC_M365_AUTHORITY_PRESENT")
        self.assertEqual(AuditEvent.objects.filter(action=AUDIT_ACTION).count(), 1)
        self.assertEqual(M365Tenant.objects.count(), 2)

        output = io.StringIO()
        call_command(
            "reconcile_vivolution_poc",
            entra_tenant_id=TARGET_ENTRA_TENANT_ID,
            primary_domain=TARGET_PRIMARY_DOMAIN,
            stdout=output,
        )
        self.assertEqual(output.getvalue().strip(), "VIVOLUTION_POC_INVENTORY_PRESENT")

        cluster = EdgeCluster.objects.get(name="cluster-uaen-poc-01")
        cluster.status = EdgeCluster.Status.ACTIVE
        cluster.save()
        EdgeNode.objects.filter(cluster=cluster).update(status=EdgeNode.Status.ONLINE)
        configuration = ConfigurationVersion.objects.get(version=1)
        configuration.state = ConfigurationVersion.State.PUBLISHED
        configuration.artifact_digest = "sha256:" + "b" * 64
        configuration.published_at = timezone.now()
        configuration.save()
        self.assertEqual(self.transition(), "VIVOLUTION_POC_M365_AUTHORITY_PRESENT")

        target.status = M365Tenant.Status.VERIFIED
        target.verified_at = timezone.now()
        target.save()
        self.assertEqual(self.transition(), "VIVOLUTION_POC_M365_AUTHORITY_PRESENT")

    def test_terminal_state_rejects_inconsistent_verification_pairs(self):
        self.transition()
        target = M365Tenant.objects.get(entra_tenant_id=TARGET_ENTRA_TENANT_ID)

        target.status = M365Tenant.Status.PENDING
        target.verified_at = timezone.now()
        target.save()
        with self.assertRaises(CommandError):
            self.transition()

        target.status = M365Tenant.Status.VERIFIED
        target.verified_at = None
        target.save()
        with self.assertRaises(CommandError):
            self.transition()

    def test_transition_rejects_any_input_other_than_the_fixed_contract(self):
        cases = (
            {"from_entra_tenant_id": TARGET_ENTRA_TENANT_ID},
            {"to_entra_tenant_id": SOURCE_ENTRA_TENANT_ID},
            {"to_primary_domain": "voice.vivolution.ae"},
            {"acknowledge": "yes"},
            {"from_entra_tenant_id": SOURCE_ENTRA_TENANT_ID.upper()},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(CommandError):
                self.transition(**values)
        self.assertFalse(
            M365Tenant.objects.filter(entra_tenant_id=TARGET_ENTRA_TENANT_ID).exists()
        )

    def test_transition_refuses_published_or_validated_configuration(self):
        configuration = ConfigurationVersion.objects.get(version=1)
        configuration.state = ConfigurationVersion.State.VALIDATED
        configuration.save()
        with self.assertRaises(CommandError):
            self.transition()

        configuration.state = ConfigurationVersion.State.PUBLISHED
        configuration.artifact_digest = "sha256:" + "a" * 64
        configuration.published_at = timezone.now()
        configuration.save()
        with self.assertRaises(CommandError):
            self.transition()

    def test_transition_refuses_target_collision_or_source_fanout(self):
        customer = CustomerAccount.objects.get(slug="vivolution-technologies-llc")
        M365Tenant.objects.create(
            customer_account=customer,
            entra_tenant_id=TARGET_ENTRA_TENANT_ID,
            display_name="Divergent",
            primary_domain=TARGET_PRIMARY_DOMAIN,
        )
        with self.assertRaises(CommandError):
            self.transition()

        M365Tenant.objects.filter(entra_tenant_id=TARGET_ENTRA_TENANT_ID).delete()
        source = M365Tenant.objects.get(entra_tenant_id=SOURCE_ENTRA_TENANT_ID)
        TenantContext.objects.create(
            customer_account=customer,
            m365_tenant=source,
            name="Unexpected fanout",
        )
        with self.assertRaises(CommandError):
            self.transition()

    def test_terminal_state_requires_its_single_audit_event(self):
        self.transition()
        event = AuditEvent.objects.get(action=AUDIT_ACTION)
        event.detail = {"scope": "tampered"}
        event.save()
        with self.assertRaises(CommandError):
            self.transition()

    def test_transition_refuses_a_preexisting_transition_audit_event(self):
        tenant = TenantContext.objects.get(name="Vivolution POC")
        AuditEvent.objects.create(
            tenant_context=tenant,
            action=AUDIT_ACTION,
            target_type="M365Tenant",
            target_id=TARGET_ENTRA_TENANT_ID,
            detail={
                "fromEntraTenantId": SOURCE_ENTRA_TENANT_ID,
                "primaryDomain": TARGET_PRIMARY_DOMAIN,
                "scope": "FIRST_TENANT_POC",
                "toEntraTenantId": TARGET_ENTRA_TENANT_ID,
                "verificationState": "PENDING_EVIDENCE_BOUND_CP1_VERIFICATION",
            },
        )

        with self.assertRaises(CommandError):
            self.transition()

        self.assertFalse(
            M365Tenant.objects.filter(entra_tenant_id=TARGET_ENTRA_TENANT_ID).exists()
        )
        source = M365Tenant.objects.get(entra_tenant_id=SOURCE_ENTRA_TENANT_ID)
        tenant.refresh_from_db()
        self.assertEqual(source.status, M365Tenant.Status.PENDING)
        self.assertEqual(tenant.m365_tenant, source)
        self.assertEqual(AuditEvent.objects.filter(action=AUDIT_ACTION).count(), 1)
