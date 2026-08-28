from django.db import DatabaseError, connection, transaction
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .rls import set_local_rls_context


@require_GET
@never_cache
def liveness(request):
    return JsonResponse({"status": "ok"})


@require_GET
@never_cache
def readiness(request):
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT EXISTS ("
                    "SELECT 1 FROM django_migrations "
                    "WHERE app = %s AND name = %s"
                    ")",
                    ["core", "0003_signed_rls_context"],
                )
                migrated = cursor.fetchone()[0]
            signed_context_ready = True
            if migrated and connection.vendor == "postgresql":
                set_local_rls_context(operator=True)
                with connection.cursor() as cursor:
                    cursor.execute("SELECT cp_security.rls_context_allows(NULL)")
                    signed_context_ready = cursor.fetchone()[0]
    except DatabaseError:
        return JsonResponse({"status": "unavailable"}, status=503)

    if not migrated:
        return JsonResponse({"status": "migrations_pending"}, status=503)
    if not signed_context_ready:
        return JsonResponse({"status": "rls_key_mismatch"}, status=503)
    return JsonResponse({"status": "ready"})
