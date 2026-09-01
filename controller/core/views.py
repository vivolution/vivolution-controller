from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.db import DatabaseError, connection, transaction
from django.http import HttpResponseNotFound, JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .rls import set_local_rls_context

DOCUMENT_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "base-uri 'none'",
        "connect-src 'none'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self'",
        "manifest-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        "script-src 'none'",
        "style-src 'self'",
        "worker-src 'none'",
    )
)


def _render_document(request, template_name):
    response = render(
        request,
        template_name,
        {"vivolution_release_id": settings.VIVOLUTION_RELEASE_ID},
    )
    response.headers["Content-Security-Policy"] = DOCUMENT_CONTENT_SECURITY_POLICY
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


@never_cache
@require_GET
@staff_member_required(login_url="admin:login")
def documentation(request):
    """Render release-matched operator guidance for authenticated staff."""

    return _render_document(request, "core/documentation.html")


@never_cache
@require_GET
def recovery(request):
    """Render a deliberately static recovery landing page without database access."""

    return _render_document(request, "core/recovery.html")


@never_cache
def unsupported_password_change(request):
    """Fail closed until installer-owned credential rotation is implemented."""

    return HttpResponseNotFound(
        "Operator password rotation is not available in this release."
    )


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
                    ["core", "0006_enrollment_rls"],
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
                            count(*) = 13
                            AND count(DISTINCT c.relname) = 10
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
                                        'core_edgenode',
                                        'core_enrollmentgrant',
                                        'core_enrollmentclaim',
                                        'core_enrollmentchallenge'
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
                                "core_enrollmentgrant",
                                "core_enrollmentclaim",
                                "core_enrollmentchallenge",
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
