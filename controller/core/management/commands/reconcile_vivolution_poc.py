import re
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
REGION = "uaenorth"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


class Command(BaseCommand):
    help = (
        "Idempotently reconcile the bounded Vivolution first-tenant POC inventory. "
        "It never verifies Microsoft 365 or marks an Edge node online."
    )

    def add_arguments(self, parser):
        parser.add_argument("--entra-tenant-id", required=True)
        parser.add_argument("--primary-domain", default="")

    @staticmethod
    def _save_new(instance):
        try:
            instance.full_clean()
        except ValidationError as exc:
            raise CommandError(str(exc)) from exc
        instance.save(force_insert=True)

    @staticmethod
    def _require(condition, message):
        if not condition:
            raise CommandError(message)

    def handle(self, *args, **options):
        try:
            entra_tenant_id = uuid.UUID(options["entra_tenant_id"])
        except (AttributeError, TypeError, ValueError) as exc:
            raise CommandError("--entra-tenant-id must be one canonical UUID") from exc
        if str(entra_tenant_id) != options["entra_tenant_id"].lower():
            raise CommandError("--entra-tenant-id must use canonical lowercase UUID form")

        primary_domain = options["primary_domain"].strip().lower()
        if primary_domain and DOMAIN_RE.fullmatch(primary_domain) is None:
            raise CommandError("--primary-domain must be empty or one canonical DNS name")

        changed = False
        with transaction.atomic():
            customer = (
                CustomerAccount.objects.select_for_update().filter(slug=CUSTOMER_SLUG).first()
            )
            if customer is None:
                customer = CustomerAccount(
                    name=CUSTOMER_NAME,
                    slug=CUSTOMER_SLUG,
                    status=CustomerAccount.Status.ACTIVE,
                )
                self._save_new(customer)
                changed = True
            else:
                self._require(
                    customer.name == CUSTOMER_NAME,
                    "customer slug is bound to another name",
                )
                self._require(
                    customer.status == CustomerAccount.Status.ACTIVE,
                    "the Vivolution customer account is not ACTIVE",
                )

            m365 = (
                M365Tenant.objects.select_for_update()
                .filter(entra_tenant_id=entra_tenant_id)
                .first()
            )
            if m365 is None:
                m365 = M365Tenant(
                    customer_account=customer,
                    entra_tenant_id=entra_tenant_id,
                    display_name=M365_DISPLAY_NAME,
                    primary_domain=primary_domain,
                    status=M365Tenant.Status.PENDING,
                )
                self._save_new(m365)
                changed = True
            else:
                self._require(
                    m365.customer_account_id == customer.id,
                    "the Entra tenant is bound to another customer account",
                )
                self._require(
                    m365.display_name == M365_DISPLAY_NAME,
                    "the Entra tenant is bound to another display name",
                )
                self._require(
                    m365.primary_domain == primary_domain,
                    "the Entra tenant is bound to another primary domain",
                )
                self._require(
                    m365.status != M365Tenant.Status.DISABLED,
                    "the Entra tenant is DISABLED",
                )

            tenant = (
                TenantContext.objects.select_for_update()
                .filter(customer_account=customer, name=TENANT_NAME)
                .first()
            )
            if tenant is None:
                tenant = TenantContext(
                    customer_account=customer,
                    m365_tenant=m365,
                    name=TENANT_NAME,
                    status=TenantContext.Status.ACTIVE,
                )
                self._save_new(tenant)
                changed = True
            else:
                self._require(
                    tenant.m365_tenant_id == m365.id,
                    "the POC tenant context is bound to another M365 tenant",
                )
                self._require(
                    tenant.status == TenantContext.Status.ACTIVE,
                    "the POC tenant context is not ACTIVE",
                )

            cluster = EdgeCluster.objects.select_for_update().filter(name=CLUSTER_NAME).first()
            if cluster is None:
                cluster = EdgeCluster(
                    name=CLUSTER_NAME,
                    service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
                    exclusive_customer_account=None,
                    region=REGION,
                    status=EdgeCluster.Status.PLANNED,
                )
                self._save_new(cluster)
                changed = True
            else:
                self._require(
                    cluster.service_mode == EdgeCluster.ServiceMode.SHARED_ENHANCED,
                    "the POC cluster service mode differs",
                )
                self._require(
                    cluster.exclusive_customer_account_id is None,
                    "shared cluster has an owner",
                )
                self._require(cluster.region == REGION, "the POC cluster region differs")
                self._require(
                    cluster.status != EdgeCluster.Status.RETIRED,
                    "the POC cluster is RETIRED",
                )

            for index, name in ((1, "sbc1"), (2, "sbc2")):
                node = (
                    EdgeNode.objects.select_for_update()
                    .filter(cluster=cluster, node_index=index)
                    .first()
                )
                if node is None:
                    node = EdgeNode(
                        cluster=cluster,
                        name=name,
                        node_index=index,
                        architecture=EdgeNode.Architecture.AMD64,
                        status=EdgeNode.Status.EXPECTED,
                    )
                    self._save_new(node)
                    changed = True
                else:
                    self._require(node.name == name, "POC node slot is bound to another name")
                    self._require(
                        node.architecture == EdgeNode.Architecture.AMD64,
                        "POC node architecture differs",
                    )
                    self._require(node.status != EdgeNode.Status.RETIRED, "a POC node is RETIRED")

            configuration = (
                ConfigurationVersion.objects.select_for_update()
                .filter(tenant_context=tenant, version=1)
                .first()
            )
            if configuration is None:
                configuration = ConfigurationVersion(
                    tenant_context=tenant,
                    version=1,
                    state=ConfigurationVersion.State.DRAFT,
                )
                self._save_new(configuration)
                changed = True

            if changed:
                AuditEvent.objects.create(
                    tenant_context=tenant,
                    action="poc.inventory.reconciled",
                    target_type="EdgeCluster",
                    target_id=CLUSTER_NAME,
                    detail={
                        "clusterStatus": cluster.status,
                        "m365Status": m365.status,
                        "nodeCount": 2,
                        "scope": "FIRST_TENANT_POC",
                    },
                )

        marker = (
            "VIVOLUTION_POC_INVENTORY_RECONCILED" if changed else "VIVOLUTION_POC_INVENTORY_PRESENT"
        )
        self.stdout.write(marker)
