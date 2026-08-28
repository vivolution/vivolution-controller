from django.db import DatabaseError, connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET


@require_GET
@never_cache
def liveness(request):
    return JsonResponse({"status": "ok"})


@require_GET
@never_cache
def readiness(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS ("
                "SELECT 1 FROM django_migrations "
                "WHERE app = %s AND name = %s"
                ")",
                ["core", "0002_enable_rls"],
            )
            migrated = cursor.fetchone()[0]
    except DatabaseError:
        return JsonResponse({"status": "unavailable"}, status=503)

    if not migrated:
        return JsonResponse({"status": "migrations_pending"}, status=503)
    return JsonResponse({"status": "ready"})
