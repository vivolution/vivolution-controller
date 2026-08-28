from django.contrib import admin

from .models import (
    AuditEvent,
    ConfigurationVersion,
    CustomerAccount,
    EdgeCluster,
    EdgeNode,
    M365Tenant,
    TenantContext,
)


@admin.register(CustomerAccount)
class CustomerAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "status", "updated_at")
    list_filter = ("status",)
    search_fields = ("name", "slug")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(M365Tenant)
class M365TenantAdmin(admin.ModelAdmin):
    list_display = ("display_name", "customer_account", "entra_tenant_id", "status")
    list_filter = ("status",)
    search_fields = ("display_name", "primary_domain", "entra_tenant_id")
    autocomplete_fields = ("customer_account",)
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(TenantContext)
class TenantContextAdmin(admin.ModelAdmin):
    list_display = ("name", "customer_account", "m365_tenant", "status")
    list_filter = ("status",)
    search_fields = ("name", "customer_account__name", "m365_tenant__display_name")
    autocomplete_fields = ("customer_account", "m365_tenant")
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(EdgeCluster)
class EdgeClusterAdmin(admin.ModelAdmin):
    list_display = ("name", "service_mode", "exclusive_customer_account", "region", "status")
    list_filter = ("service_mode", "status", "region")
    search_fields = ("name",)
    autocomplete_fields = ("exclusive_customer_account",)
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(EdgeNode)
class EdgeNodeAdmin(admin.ModelAdmin):
    list_display = ("name", "cluster", "node_index", "architecture", "status", "last_seen_at")
    list_filter = ("architecture", "status")
    search_fields = ("name", "cluster__name")
    autocomplete_fields = ("cluster",)
    readonly_fields = ("id", "created_at", "updated_at")


@admin.register(ConfigurationVersion)
class ConfigurationVersionAdmin(admin.ModelAdmin):
    list_display = ("tenant_context", "version", "state", "artifact_digest", "published_at")
    list_filter = ("state",)
    search_fields = ("tenant_context__name", "artifact_digest")
    autocomplete_fields = ("tenant_context", "created_by")
    readonly_fields = ("id", "created_at", "updated_at")


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
