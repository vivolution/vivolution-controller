import hashlib
import hmac
import re
import secrets
import time
from contextlib import contextmanager
from uuid import UUID

from django.conf import settings
from django.db import connection, transaction

_SIGNING_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_TOKEN_VERSION = "v1"


def _validated_uuid(value):
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("tenant_context_id must be a UUID") from exc


def _signing_key_bytes(signing_key=None):
    value = settings.RLS_CONTEXT_SIGNING_KEY if signing_key is None else signing_key
    if not isinstance(value, str) or not _SIGNING_KEY_RE.fullmatch(value):
        raise ValueError("RLS_CONTEXT_SIGNING_KEY must be exactly 64 lowercase hex characters")
    return bytes.fromhex(value)


def _build_context_token(
    *,
    tenant_context_id=None,
    operator=False,
    signing_key=None,
    expires_at=None,
    nonce=None,
):
    """Return a short-lived context token understood by the PostgreSQL RLS policy."""

    if operator and tenant_context_id is not None:
        raise ValueError("an operator RLS context cannot also select a tenant")

    if operator:
        mode = "operator"
        tenant_value = "-"
    else:
        if tenant_context_id is None:
            raise ValueError("a tenant RLS context requires tenant_context_id")
        mode = "tenant"
        tenant_value = _validated_uuid(tenant_context_id)

    expiry = (
        int(time.time()) + settings.RLS_CONTEXT_TTL_SECONDS
        if expires_at is None
        else int(expires_at)
    )
    nonce_value = secrets.token_hex(16) if nonce is None else str(nonce)
    if not _NONCE_RE.fullmatch(nonce_value):
        raise ValueError("RLS context nonce must be exactly 32 lowercase hex characters")

    payload = f"{_TOKEN_VERSION}|{mode}|{tenant_value}|{expiry}|{nonce_value}"
    signature = hmac.new(
        _signing_key_bytes(signing_key), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload}|{signature}"


def set_local_rls_context(*, tenant_context_id=None, operator=False):
    """Install the bridge and signed RLS contexts for the active transaction."""

    if connection.vendor != "postgresql":
        return
    if connection.get_autocommit():
        raise RuntimeError("an RLS context requires an active database transaction")

    token = _build_context_token(
        tenant_context_id=tenant_context_id,
        operator=operator,
    )
    tenant_value = "" if operator else _validated_uuid(tenant_context_id)
    _set_raw_local_contexts(
        token=token,
        tenant_context_id=tenant_value,
        is_operator="true" if operator else "",
    )


def _read_raw_local_context():
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('app.rls_context', true)")
        return cursor.fetchone()[0] or ""


def _read_raw_local_contexts():
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT current_setting('app.rls_context', true), "
            "current_setting('app.tenant_context_id', true), "
            "current_setting('app.is_operator', true)"
        )
        values = cursor.fetchone()
    return tuple(value or "" for value in values)


def _set_raw_local_context(token):
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('app.rls_context', %s, true)", [token])


def _set_raw_local_contexts(*, token, tenant_context_id, is_operator):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('app.rls_context', %s, true), "
            "set_config('app.tenant_context_id', %s, true), "
            "set_config('app.is_operator', %s, true)",
            [token, tenant_context_id, is_operator],
        )


@contextmanager
def _signed_scope(*, tenant_context_id=None, operator=False):
    if connection.vendor != "postgresql":
        yield
        return

    with transaction.atomic():
        previous_contexts = _read_raw_local_contexts()
        set_local_rls_context(
            tenant_context_id=tenant_context_id,
            operator=operator,
        )
        try:
            yield
        except BaseException:
            # Rolling back this atomic block restores the GUC value from the
            # outer transaction/savepoint. A query is unsafe once rollback is
            # required, so restoration is deliberately left to PostgreSQL.
            raise
        else:
            _set_raw_local_contexts(
                token=previous_contexts[0],
                tenant_context_id=previous_contexts[1],
                is_operator=previous_contexts[2],
            )


@contextmanager
def tenant_scope(tenant_context_id):
    """Open a transaction whose signed PostgreSQL RLS scope is one technical tenant."""

    tenant_id = _validated_uuid(tenant_context_id)
    with _signed_scope(tenant_context_id=tenant_id):
        yield


@contextmanager
def operator_scope():
    """Open a transaction with a short-lived signed operator RLS context."""

    with _signed_scope(operator=True):
        yield
