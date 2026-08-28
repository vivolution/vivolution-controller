from contextlib import contextmanager
from uuid import UUID

from django.db import connection, transaction


def _validated_uuid(value):
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("tenant_context_id must be a UUID") from exc


def set_local_rls_context(*, tenant_context_id=None, operator=False):
    if connection.vendor != "postgresql":
        return
    tenant_value = "" if tenant_context_id is None else _validated_uuid(tenant_context_id)
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('app.tenant_context_id', %s, true)", [tenant_value])
        cursor.execute("SELECT set_config('app.is_operator', %s, true)", ["true" if operator else "false"])


@contextmanager
def tenant_scope(tenant_context_id):
    """Open a transaction whose PostgreSQL RLS scope is one technical tenant."""

    tenant_id = _validated_uuid(tenant_context_id)
    if connection.vendor != "postgresql":
        yield
        return
    with transaction.atomic():
        set_local_rls_context(tenant_context_id=tenant_id, operator=False)
        yield
