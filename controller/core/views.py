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
                    ["core", "0004_signed_only_rls_context"],
                )
                migrated = cursor.fetchone()[0]
            signed_context_ready = True
            signed_policy_ready = True
            if migrated and connection.vendor == "postgresql":
                set_local_rls_context(operator=True)
                with connection.cursor() as cursor:
                    cursor.execute("SELECT cp_security.rls_context_allows(NULL)")
                    signed_context_ready = cursor.fetchone()[0]
                    cursor.execute(
                        """
                        SELECT
                            count(*) = 10
                            AND count(DISTINCT c.relname) = 7
                            AND bool_and(COALESCE(
                                p.polpermissive
                                AND p.polroles = ARRAY[0]::oid[]
                                AND c.relrowsecurity
                                AND (
                                    (c.relname IN (
                                        'core_configurationversion',
                                        'core_auditevent'
                                     ) AND p.polname = 'tenant_context_isolation'
                                       AND p.polcmd = '*'
                                       AND regexp_replace(
                                            pg_get_expr(p.polqual, p.polrelid),
                                            '[[:space:]]+', '', 'g'
                                           ) =
                                           'cp_security.rls_context_allows(tenant_context_id)'
                                       AND regexp_replace(
                                            pg_get_expr(p.polwithcheck, p.polrelid),
                                            '[[:space:]]+', '', 'g'
                                           ) =
                                           'cp_security.rls_context_allows(tenant_context_id)') OR
                                    (c.relname = 'core_tenantcontext'
                                     AND p.polname = 'tenant_context_isolation'
                                     AND p.polcmd = 'r'
                                     AND regexp_replace(
                                          pg_get_expr(p.polqual, p.polrelid),
                                          '[[:space:]]+', '', 'g'
                                         ) = 'cp_security.rls_context_allows(id)'
                                     AND p.polwithcheck IS NULL) OR
                                    (c.relname IN (
                                        'core_tenantcontext',
                                        'core_customeraccount',
                                        'core_m365tenant',
                                        'core_edgecluster',
                                        'core_edgenode'
                                     ) AND p.polname = 'operator_context_only'
                                       AND p.polcmd = '*'
                                       AND regexp_replace(
                                            pg_get_expr(p.polqual, p.polrelid),
                                            '[[:space:]]+', '', 'g'
                                           ) = 'cp_security.rls_context_allows(NULL::uuid)'
                                       AND regexp_replace(
                                            pg_get_expr(p.polwithcheck, p.polrelid),
                                            '[[:space:]]+', '', 'g'
                                           ) = 'cp_security.rls_context_allows(NULL::uuid)') OR
                                    (c.relname = 'core_customeraccount'
                                     AND p.polname = 'tenant_metadata_read'
                                     AND p.polcmd = 'r'
                                     AND regexp_replace(
                                          pg_get_expr(p.polqual, p.polrelid),
                                          '[[:space:]]+', '', 'g'
                                         ) =
                                         '(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE((tenant_context.customer_account_id=core_customeraccount.id)ANDcp_security.rls_context_allows(tenant_context.id))))'
                                     AND p.polwithcheck IS NULL) OR
                                    (c.relname = 'core_m365tenant'
                                     AND p.polname = 'tenant_metadata_read'
                                     AND p.polcmd = 'r'
                                     AND regexp_replace(
                                          pg_get_expr(p.polqual, p.polrelid),
                                          '[[:space:]]+', '', 'g'
                                         ) =
                                         '(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE((tenant_context.m365_tenant_id=core_m365tenant.id)ANDcp_security.rls_context_allows(tenant_context.id))))'
                                     AND p.polwithcheck IS NULL)
                                ),
                                false
                            ))
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        JOIN pg_policy p ON p.polrelid = c.oid
                        WHERE n.nspname = 'public'
                          AND c.relname = ANY(%s)
                        """,
                        [
                            [
                                "core_tenantcontext",
                                "core_configurationversion",
                                "core_auditevent",
                                "core_customeraccount",
                                "core_m365tenant",
                                "core_edgecluster",
                                "core_edgenode",
                            ],
                        ],
                    )
                    signed_policy_ready = cursor.fetchone()[0]
    except DatabaseError:
        return JsonResponse({"status": "unavailable"}, status=503)

    if not migrated:
        return JsonResponse({"status": "migrations_pending"}, status=503)
    if not signed_context_ready:
        return JsonResponse({"status": "rls_key_mismatch"}, status=503)
    if not signed_policy_ready:
        return JsonResponse({"status": "rls_policy_mismatch"}, status=503)
    return JsonResponse({"status": "ready"})
