from django.conf import settings
from django.contrib import admin, messages
from django.contrib.admin import helpers
from django.contrib.auth.models import Group, User
from django.template.response import TemplateResponse

from .enrollment import (
    EdgeAPIError,
    approve_enrollment_claim,
    issue_enrollment_grant,
    revoke_enrollment_claim,
)
from .models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    EnrollmentClaim,
    EnrollmentGrant,
    M365Tenant,
    TenantContext,
)

admin.site.site_header = "Vivolution Control Plane"
admin.site.site_title = "Vivolution CP"
admin.site.index_title = "Controller configuration"

# Operator identity is provisioned only by the owner-credential deployment
# command. The runtime database role cannot mutate passwords, superuser/staff
# flags, groups, or permissions, so those models must not be exposed here.
for authentication_model in (User, Group):
    if admin.site.is_registered(authentication_model):
        admin.site.unregister(authentication_model)


class NoDeleteAdminMixin:
    def has_delete_permission(self, request, obj=None):
        return False


class ReadOnlyAdminMixin(NoDeleteAdminMixin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(CustomerAccount)
class CustomerAccountAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = ("name", "slug", "status", "updated_at")
    list_filter = ("status",)
    search_fields = ("name", "slug")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(M365Tenant)
class M365TenantAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = ("display_name", "customer_account", "entra_tenant_id", "status")
    list_filter = ("status",)
    search_fields = ("display_name", "primary_domain", "entra_tenant_id")
    autocomplete_fields = ("customer_account",)
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(TenantContext)
class TenantContextAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = ("name", "customer_account", "m365_tenant", "status")
    list_filter = ("status",)
    search_fields = ("name", "customer_account__name", "m365_tenant__display_name")
    autocomplete_fields = ("customer_account", "m365_tenant")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(EdgeCluster)
class EdgeClusterAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = ("name", "service_mode", "exclusive_customer_account", "region", "status")
    list_filter = ("service_mode", "status", "region")
    search_fields = ("name",)
    autocomplete_fields = ("exclusive_customer_account",)
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(EdgeNode)
class EdgeNodeAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = (
        "name",
        "cluster",
        "slot",
        "generation",
        "architecture",
        "status",
        "current_fingerprint",
        "last_seen_at",
    )
    list_filter = ("architecture", "status")
    search_fields = ("name", "cluster__name")
    autocomplete_fields = ("cluster",)
    readonly_fields = (
        "id",
        "cluster",
        "name",
        "node_index",
        "generation",
        "architecture",
        "status",
        "last_seen_at",
        "last_heartbeat_sequence",
        "last_boot_id",
        "observed_inventory_digest",
        "observed_release_digest",
        "observed_health",
        "created_at",
        "updated_at",
    )
    actions = ("issue_grant", "approve_claim", "revoke_claim")

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            editable_on_add = {"cluster", "name", "node_index", "architecture"}
            return tuple(
                field for field in self.readonly_fields if field not in editable_on_add
            )
        return self.readonly_fields

    @admin.display(description="Slot", ordering="node_index")
    def slot(self, obj):
        return "A" if obj.node_index == 1 else "B"

    @admin.display(description="Current key fingerprint")
    def current_fingerprint(self, obj):
        claim = next(
            (
                item
                for item in obj.enrollment_claims.all()
                if item.generation == obj.generation
            ),
            None,
        )
        return claim.public_key_fingerprint if claim else "—"

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("enrollment_claims")

    @admin.action(description="Issue a display-once enrollment grant")
    def issue_grant(self, request, queryset):
        if queryset.count() != 1:
            self.message_user(request, "Select exactly one node.", level=messages.ERROR)
            return None
        node = queryset.get()
        if request.POST.get("issue_confirmation") != "yes":
            return TemplateResponse(
                request,
                "admin/core/edgenode/issue_grant.html",
                {
                    **self.admin_site.each_context(request),
                    "title": "Issue enrollment grant",
                    "node": node,
                    "release_digest": settings.EDGE_ENROLLMENT_RELEASE_DIGEST,
                    "action_checkbox_name": helpers.ACTION_CHECKBOX_NAME,
                },
            )
        release_digest = settings.EDGE_ENROLLMENT_RELEASE_DIGEST
        try:
            grant, token = issue_enrollment_grant(
                node=node,
                actor=request.user,
                release_digest=release_digest,
            )
        except (EdgeAPIError, ValueError) as exc:
            self.message_user(
                request,
                exc.message if isinstance(exc, EdgeAPIError) else str(exc),
                level=messages.ERROR,
            )
            return None
        response = TemplateResponse(
            request,
            "admin/core/edgenode/grant_issued.html",
            {
                **self.admin_site.each_context(request),
                "title": "Enrollment grant issued",
                "node": node,
                "grant": grant,
                "grant_token": token,
                "controller_origin": settings.VIVOLUTION_CONTROLLER_ORIGIN,
            },
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return response

    def _current_claim_rows(self, queryset):
        rows = []
        for node in queryset:
            claim = node.enrollment_claims.filter(generation=node.generation).first()
            rows.append({"node": node, "claim": claim})
        return rows

    def _confirmation(self, request, queryset, *, action_name, title, template_name):
        return TemplateResponse(
            request,
            template_name,
            {
                **self.admin_site.each_context(request),
                "title": title,
                "rows": self._current_claim_rows(queryset),
                "action_name": action_name,
                "action_checkbox_name": helpers.ACTION_CHECKBOX_NAME,
            },
        )

    def _confirmed_claims(self, request, queryset):
        bindings = {}
        for value in request.POST.getlist("claim_binding"):
            parts = value.split("|", 3)
            if len(parts) != 4:
                return None
            bindings[parts[0]] = tuple(parts[1:])
        confirmed = []
        for node in queryset:
            claim = node.enrollment_claims.filter(generation=node.generation).first()
            if claim is None:
                return None
            expected = bindings.get(str(node.id))
            actual = (
                str(claim.id),
                str(node.generation),
                claim.public_key_fingerprint,
            )
            if expected != actual:
                return None
            confirmed.append((node, claim))
        return confirmed

    @admin.action(description="Approve pending enrollment claim")
    def approve_claim(self, request, queryset):
        if request.POST.get("confirmation") != "yes":
            return self._confirmation(
                request,
                queryset,
                action_name="approve_claim",
                title="Confirm exact enrollment fingerprints",
                template_name="admin/core/edgenode/confirm_approval.html",
            )
        confirmed = self._confirmed_claims(request, queryset)
        if confirmed is None:
            self.message_user(
                request,
                "The selected claim, generation, or fingerprint changed. Review it again.",
                level=messages.ERROR,
            )
            return None
        approved = 0
        for node, claim in confirmed:
            try:
                approve_enrollment_claim(claim=claim, actor=request.user)
            except EdgeAPIError as exc:
                self.message_user(request, f"{node}: {exc.message}", level=messages.ERROR)
            else:
                approved += 1
        if approved:
            self.message_user(request, f"Approved {approved} enrollment claim(s).")

    @admin.action(description="Revoke current node identity")
    def revoke_claim(self, request, queryset):
        if request.POST.get("confirmation") != "yes":
            return self._confirmation(
                request,
                queryset,
                action_name="revoke_claim",
                title="Confirm node identity revocation",
                template_name="admin/core/edgenode/confirm_revocation.html",
            )
        confirmed = self._confirmed_claims(request, queryset)
        if confirmed is None:
            self.message_user(
                request,
                "The selected claim, generation, or fingerprint changed. Review it again.",
                level=messages.ERROR,
            )
            return None
        revoked = 0
        for node, claim in confirmed:
            revoke_enrollment_claim(
                claim=claim,
                actor=request.user,
                reason="Revoked by an authenticated operator through Django admin.",
            )
            revoked += 1
        if revoked:
            self.message_user(request, f"Revoked {revoked} node identity(s).")


@admin.register(EnrollmentGrant)
class EnrollmentGrantAdmin(ReadOnlyAdminMixin, admin.ModelAdmin):
    list_display = ("id", "node", "expected_release_digest", "expires_at", "claimed_at")
    list_filter = ("claimed_at", "revoked_at")
    search_fields = ("id", "node__name", "node__cluster__name")
    fields = (
        "id",
        "node",
        "expected_release_digest",
        "expires_at",
        "issued_by",
        "claimed_at",
        "revoked_at",
        "created_at",
        "updated_at",
    )
    readonly_fields = fields


@admin.register(EnrollmentClaim)
class EnrollmentClaimAdmin(ReadOnlyAdminMixin, admin.ModelAdmin):
    list_display = (
        "id",
        "node",
        "generation",
        "public_key_fingerprint",
        "approved_at",
        "revoked_at",
    )
    list_filter = ("approved_at", "revoked_at")
    search_fields = ("id", "node__name", "node__cluster__name", "public_key_fingerprint")
    fields = (
        "id",
        "node",
        "generation",
        "public_key_fingerprint",
        "inventory_digest",
        "release_digest",
        "approved_at",
        "approved_by",
        "revoked_at",
        "revoked_by",
        "revocation_reason",
        "last_status_at",
        "created_at",
        "updated_at",
    )
    readonly_fields = fields


@admin.register(ConfigurationVersion)
class ConfigurationVersionAdmin(NoDeleteAdminMixin, admin.ModelAdmin):
    list_display = ("tenant_context", "version", "state", "artifact_digest", "published_at")
    list_filter = ("state",)
    search_fields = ("tenant_context__name", "artifact_digest")
    autocomplete_fields = ("tenant_context",)
    readonly_fields = ("id", "created_by", "created_at", "updated_at")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("occurred_at", "action", "tenant_context", "actor", "target_type")
    list_filter = ("action", "target_type")
    search_fields = ("action", "target_type", "target_id", "request_id")
    readonly_fields = (
        "id",
        "tenant_context",
        "actor",
        "action",
        "target_type",
        "target_id",
        "request_id",
        "detail",
        "occurred_at",
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False
