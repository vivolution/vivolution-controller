"""Live PostgreSQL qualification of Django ORM behavior under signed RLS."""

import os
from uuid import UUID

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cp1.settings")

import django  # noqa: E402

django.setup()

from core.models import (  # noqa: E402
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    M365Tenant,
    TenantContext,
)
from core.rls import operator_scope, tenant_scope  # noqa: E402

TENANT_A = UUID("00000000-0000-4000-8000-0000000000a1")
TENANT_B = UUID("00000000-0000-4000-8000-0000000000b1")
CUSTOMER_A = UUID("00000000-0000-4000-8000-0000000000a0")
CUSTOMER_B = UUID("00000000-0000-4000-8000-0000000000b0")
M365_A = UUID("00000000-0000-4000-8000-0000000000a2")
M365_B = UUID("00000000-0000-4000-8000-0000000000b2")
VERSION_A = UUID("00000000-0000-4000-8000-0000000000a4")
VERSION_B = UUID("00000000-0000-4000-8000-0000000000b4")


def visible_ids(queryset):
    return sorted(str(value) for value in queryset.values_list("id", flat=True))


with tenant_scope(TENANT_A):
    assert visible_ids(TenantContext.objects.filter(id__in=[TENANT_A, TENANT_B])) == [
        str(TENANT_A)
    ]
    assert visible_ids(
        ConfigurationVersion.objects.filter(id__in=[VERSION_A, VERSION_B])
    ) == [str(VERSION_A)]
    assert visible_ids(CustomerAccount.objects.filter(id__in=[CUSTOMER_A, CUSTOMER_B])) == [
        str(CUSTOMER_A)
    ]
    assert visible_ids(M365Tenant.objects.filter(id__in=[M365_A, M365_B])) == [str(M365_A)]
    assert EdgeCluster.objects.count() == 0
    assert CustomerAccount.objects.filter(pk=CUSTOMER_A).update(status="SUSPENDED") == 0
    assert (
        TenantContext.objects.filter(pk=TENANT_A).update(
            customer_account_id=CUSTOMER_B,
            m365_tenant_id=M365_B,
            status="SUSPENDED",
        )
        == 0
    )

with operator_scope():
    assert visible_ids(TenantContext.objects.filter(id__in=[TENANT_A, TENANT_B])) == [
        str(TENANT_A),
        str(TENANT_B),
    ]
    with tenant_scope(TENANT_B):
        assert visible_ids(TenantContext.objects.filter(id__in=[TENANT_A, TENANT_B])) == [
            str(TENANT_B)
        ]
    assert visible_ids(TenantContext.objects.filter(id__in=[TENANT_A, TENANT_B])) == [
        str(TENANT_A),
        str(TENANT_B),
    ]

print("CP_ORM_RLS_OK=signed-tenant-joins-and-operator")
