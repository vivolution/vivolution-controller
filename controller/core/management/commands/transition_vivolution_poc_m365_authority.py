import uuid

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core.models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)


CUSTOMER_NAME = "Vivolution Technologies LLC"
CUSTOMER_SLUG = "vivolution-technologies-llc"
TENANT_NAME = "Vivolution POC"
M365_DISPLAY_NAME = "Vivolution Technologies LLC"
CLUSTER_NAME = "cluster-uaen-poc-01"

# The first Azure build deliberately used its subscription directory while the
# actual Microsoft 365 tenant was still unknown.  Public tenant discovery later
# identified the bounded replacement below.  Keeping both identifiers fixed in
# code prevents this repair command from becoming a general tenant-rebinding
# primitive.
SOURCE_ENTRA_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
TARGET_ENTRA_TENANT_ID = "151cd01a-1e81-40a9-b898-d8646e1a8760"
TARGET_PRIMARY_DOMAIN = "vivolution.ae"
ACKNOWLEDGEMENT = (
    "TRANSITION VIVOLUTION POC M365 TENANT AUTHORITY TO "
    + TARGET_ENTRA_TENANT_ID
)
AUDIT_ACTION = "poc.m365_authority.transitioned"


class Command(BaseCommand):
    help = (
        "Atomically replace the bounded POC's provisional Azure guest-directory "
        "record with the discovered Vivolution Microsoft 365 tenant."
    )

    def add_arguments(self, parser):
        parser.add_argument("--from-entra-tenant-id", required=True)
        parser.add_argument("--to-entra-tenant-id", required=True)
        parser.add_argument("--to-primary-domain", required=True)
        parser.add_argument("--acknowledge", required=True)

    @staticmethod
    def _require(condition, message):
        if not condition:
            raise CommandError(message)

    @staticmethod
    def _canonical_uuid(value, option):
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as exc:
            raise CommandError(f"{option} must be one canonical UUID") from exc
        if str(parsed) != value:
            raise CommandError(f"{option} must use canonical lowercase UUID form")
        return parsed

    @staticmethod
    def _validate_new(instance):
        try:
            instance.full_clean()
        except ValidationError as exc:
            raise CommandError(str(exc)) from exc

    def _validate_fixed_inputs(self, options):
        source = self._canonical_uuid(
            options["from_entra_tenant_id"], "--from-entra-tenant-id"
        )
        target = self._canonical_uuid(
            options["to_entra_tenant_id"], "--to-entra-tenant-id"
        )
        domain = options["to_primary_domain"]
        acknowledgement = options["acknowledge"]
        self._require(
            str(source) == SOURCE_ENTRA_TENANT_ID,
            "the source Entra tenant differs from the fixed provisional directory",
        )
        self._require(
            str(target) == TARGET_ENTRA_TENANT_ID,
            "the target Entra tenant differs from the discovered Vivolution tenant",
        )
        self._require(
            domain == TARGET_PRIMARY_DOMAIN,
            "the target primary domain differs from the fixed Vivolution domain",
        )
        self._require(
            acknowledgement == ACKNOWLEDGEMENT,
            "the exact Microsoft 365 tenant-authority acknowledgement is required",
        )
        return source, target

    def _require_common_inventory(self):
        customer = (
            CustomerAccount.objects.select_for_update()
            .filter(slug=CUSTOMER_SLUG)
            .first()
        )
        self._require(customer is not None, "the bounded Vivolution customer is absent")
        self._require(customer.name == CUSTOMER_NAME, "the customer name differs")
        self._require(
            customer.status == CustomerAccount.Status.ACTIVE,
            "the customer is not ACTIVE",
        )

        tenant = (
            TenantContext.objects.select_for_update()
            .filter(customer_account=customer, name=TENANT_NAME)
            .first()
        )
        self._require(tenant is not None, "the bounded Vivolution tenant context is absent")
        self._require(
            tenant.status == TenantContext.Status.ACTIVE,
            "the bounded Vivolution tenant context is not ACTIVE",
        )

        return customer, tenant

    def _require_pre_transition_state(self, tenant):
        cluster = (
            EdgeCluster.objects.select_for_update().filter(name=CLUSTER_NAME).first()
        )
        self._require(cluster is not None, "the bounded POC Edge cluster is absent")
        self._require(
            cluster.status == EdgeCluster.Status.PLANNED,
            "tenant authority cannot change after the POC cluster leaves PLANNED",
        )
        nodes = list(
            EdgeNode.objects.select_for_update()
            .filter(cluster=cluster)
            .order_by("node_index")
        )
        self._require(
            [(node.name, node.node_index, node.status) for node in nodes]
            == [
                ("sbc1", 1, EdgeNode.Status.EXPECTED),
                ("sbc2", 2, EdgeNode.Status.EXPECTED),
            ],
            "tenant authority cannot change after the bounded Edge inventory diverges",
        )

        configurations = list(
            ConfigurationVersion.objects.select_for_update()
            .filter(tenant_context=tenant)
            .order_by("version")
        )
        self._require(configurations, "the bounded POC has no configuration version")
        self._require(
            all(
                item.state == ConfigurationVersion.State.DRAFT
                and item.artifact_digest == ""
                and item.published_at is None
                for item in configurations
            ),
            "tenant authority cannot change after a configuration leaves unsigned DRAFT",
        )

    @staticmethod
    def _expected_audit_detail():
        return {
            "fromEntraTenantId": SOURCE_ENTRA_TENANT_ID,
            "primaryDomain": TARGET_PRIMARY_DOMAIN,
            "scope": "FIRST_TENANT_POC",
            "toEntraTenantId": TARGET_ENTRA_TENANT_ID,
            "verificationState": "PENDING_EVIDENCE_BOUND_CP1_VERIFICATION",
        }

    @staticmethod
    def _exact_terminal_state(source, target, tenant):
        if source is None or target is None:
            return False
        target_verification_state_is_exact = (
            target.status == M365Tenant.Status.PENDING
            and target.verified_at is None
        ) or (
            target.status == M365Tenant.Status.VERIFIED
            and target.verified_at is not None
        )
        return (
            source.status == M365Tenant.Status.DISABLED
            and source.primary_domain == ""
            and source.verified_at is None
            and source.display_name == M365_DISPLAY_NAME
            and target_verification_state_is_exact
            and target.primary_domain == TARGET_PRIMARY_DOMAIN
            and target.display_name == M365_DISPLAY_NAME
            and tenant.m365_tenant_id == target.id
        )

    def handle(self, *args, **options):
        source_uuid, target_uuid = self._validate_fixed_inputs(options)

        with transaction.atomic():
            customer, tenant = self._require_common_inventory()
            tenants = {
                item.entra_tenant_id: item
                for item in M365Tenant.objects.select_for_update()
                .filter(entra_tenant_id__in=(source_uuid, target_uuid))
                .order_by("entra_tenant_id")
            }
            source = tenants.get(source_uuid)
            target = tenants.get(target_uuid)
            events = list(
                AuditEvent.objects.select_for_update()
                .filter(
                    tenant_context=tenant,
                    action=AUDIT_ACTION,
                    target_type="M365Tenant",
                    target_id=TARGET_ENTRA_TENANT_ID,
                )
                .order_by("id")
            )

            if self._exact_terminal_state(source, target, tenant):
                self._require(
                    source.customer_account_id == customer.id
                    and target.customer_account_id == customer.id,
                    "terminal tenant records cross the bounded customer authority",
                )
                self._require(
                    len(events) == 1
                    and events[0].detail == self._expected_audit_detail(),
                    "terminal tenant authority lacks exactly one transition audit event",
                )
                self.stdout.write("VIVOLUTION_POC_M365_AUTHORITY_PRESENT")
                return

            self._require_pre_transition_state(tenant)
            self._require(
                not events,
                "pre-transition state already contains a tenant-authority audit event",
            )
            self._require(source is not None, "the provisional M365 tenant is absent")
            self._require(target is None, "the target M365 tenant already exists divergently")
            self._require(
                source.customer_account_id == customer.id,
                "the provisional M365 tenant belongs to another customer",
            )
            self._require(
                source.display_name == M365_DISPLAY_NAME
                and source.primary_domain == ""
                and source.status == M365Tenant.Status.PENDING
                and source.verified_at is None,
                "the provisional M365 tenant is not the exact unverified placeholder",
            )
            self._require(
                tenant.m365_tenant_id == source.id,
                "the bounded tenant context is not bound to the provisional authority",
            )
            self._require(
                TenantContext.objects.filter(m365_tenant=source).count() == 1,
                "the provisional M365 tenant has an unexpected tenant-context fanout",
            )

            target = M365Tenant(
                customer_account=customer,
                entra_tenant_id=target_uuid,
                display_name=M365_DISPLAY_NAME,
                primary_domain=TARGET_PRIMARY_DOMAIN,
                status=M365Tenant.Status.PENDING,
            )
            self._validate_new(target)
            target.save(force_insert=True)

            tenant.m365_tenant = target
            self._validate_new(tenant)
            tenant.save()

            source.status = M365Tenant.Status.DISABLED
            source.full_clean()
            source.save()

            AuditEvent.objects.create(
                tenant_context=tenant,
                action=AUDIT_ACTION,
                target_type="M365Tenant",
                target_id=TARGET_ENTRA_TENANT_ID,
                detail=self._expected_audit_detail(),
            )

        self.stdout.write("VIVOLUTION_POC_M365_AUTHORITY_TRANSITIONED")
