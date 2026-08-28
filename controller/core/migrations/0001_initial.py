import uuid

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="CustomerAccount",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=200)),
                ("slug", models.SlugField(max_length=80, unique=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("ACTIVE", "Active"),
                            ("SUSPENDED", "Suspended"),
                            ("DECOMMISSIONED", "Decommissioned"),
                        ],
                        default="ACTIVE",
                        max_length=20,
                    ),
                ),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="EdgeCluster",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.SlugField(max_length=80, unique=True)),
                (
                    "service_mode",
                    models.CharField(
                        choices=[
                            ("SHARED_ENHANCED", "Shared Enhanced"),
                            ("EXCLUSIVE", "Exclusive"),
                        ],
                        max_length=24,
                    ),
                ),
                ("region", models.CharField(blank=True, max_length=80)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("PLANNED", "Planned"),
                            ("ACTIVE", "Active"),
                            ("MAINTENANCE", "Maintenance"),
                            ("RETIRED", "Retired"),
                        ],
                        default="PLANNED",
                        max_length=20,
                    ),
                ),
                (
                    "exclusive_customer_account",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="exclusive_edge_clusters",
                        to="core.customeraccount",
                    ),
                ),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="M365Tenant",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("entra_tenant_id", models.UUIDField(unique=True)),
                ("display_name", models.CharField(max_length=200)),
                ("primary_domain", models.CharField(blank=True, max_length=253)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("PENDING", "Pending verification"),
                            ("VERIFIED", "Verified"),
                            ("DISABLED", "Disabled"),
                        ],
                        default="PENDING",
                        max_length=20,
                    ),
                ),
                ("verified_at", models.DateTimeField(blank=True, null=True)),
                (
                    "customer_account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="m365_tenants",
                        to="core.customeraccount",
                    ),
                ),
            ],
            options={"ordering": ["display_name"]},
        ),
        migrations.CreateModel(
            name="TenantContext",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=120)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("ACTIVE", "Active"),
                            ("SUSPENDED", "Suspended"),
                            ("DECOMMISSIONED", "Decommissioned"),
                        ],
                        default="ACTIVE",
                        max_length=20,
                    ),
                ),
                (
                    "customer_account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="tenant_contexts",
                        to="core.customeraccount",
                    ),
                ),
                (
                    "m365_tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="tenant_contexts",
                        to="core.m365tenant",
                    ),
                ),
            ],
            options={"ordering": ["customer_account__name", "name"]},
        ),
        migrations.CreateModel(
            name="EdgeNode",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.SlugField(max_length=80)),
                ("node_index", models.PositiveSmallIntegerField(help_text="Expected HA slot: 1 or 2")),
                (
                    "architecture",
                    models.CharField(choices=[("AMD64", "amd64"), ("ARM64", "arm64")], max_length=10),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("EXPECTED", "Expected"),
                            ("ONLINE", "Online"),
                            ("DEGRADED", "Degraded"),
                            ("OFFLINE", "Offline"),
                            ("RETIRED", "Retired"),
                        ],
                        default="EXPECTED",
                        max_length=20,
                    ),
                ),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                (
                    "cluster",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="nodes",
                        to="core.edgecluster",
                    ),
                ),
            ],
            options={"ordering": ["cluster__name", "node_index"]},
        ),
        migrations.CreateModel(
            name="ConfigurationVersion",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("version", models.PositiveBigIntegerField()),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("DRAFT", "Draft"),
                            ("VALIDATED", "Validated"),
                            ("PUBLISHED", "Published"),
                            ("RETIRED", "Retired"),
                        ],
                        default="DRAFT",
                        max_length=20,
                    ),
                ),
                (
                    "artifact_digest",
                    models.CharField(
                        blank=True,
                        max_length=71,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Use an empty value or a lowercase sha256:<64 hex characters> digest.",
                                regex="^$|^sha256:[0-9a-f]{64}$",
                            )
                        ],
                    ),
                ),
                ("published_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_configuration_versions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant_context",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="configuration_versions",
                        to="core.tenantcontext",
                    ),
                ),
            ],
            options={"ordering": ["tenant_context", "-version"]},
        ),
        migrations.CreateModel(
            name="AuditEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("action", models.CharField(max_length=120)),
                ("target_type", models.CharField(max_length=120)),
                ("target_id", models.CharField(blank=True, max_length=128)),
                ("request_id", models.UUIDField(default=uuid.uuid4, editable=False)),
                ("detail", models.JSONField(blank=True, default=dict)),
                ("occurred_at", models.DateTimeField(auto_now_add=True)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant_context",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="audit_events",
                        to="core.tenantcontext",
                    ),
                ),
            ],
            options={"ordering": ["-occurred_at"]},
        ),
        migrations.AddConstraint(
            model_name="edgecluster",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("exclusive_customer_account__isnull", False), ("service_mode", "EXCLUSIVE"))
                    | models.Q(
                        ("exclusive_customer_account__isnull", True),
                        ("service_mode", "SHARED_ENHANCED"),
                    )
                ),
                name="ck_cluster_exclusive_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantcontext",
            constraint=models.UniqueConstraint(
                fields=("customer_account", "name"), name="uq_tenant_context_name"
            ),
        ),
        migrations.AddConstraint(
            model_name="edgenode",
            constraint=models.UniqueConstraint(fields=("cluster", "name"), name="uq_edge_node_name"),
        ),
        migrations.AddConstraint(
            model_name="edgenode",
            constraint=models.UniqueConstraint(
                fields=("cluster", "node_index"), name="uq_edge_node_slot"
            ),
        ),
        migrations.AddConstraint(
            model_name="edgenode",
            constraint=models.CheckConstraint(
                condition=models.Q(("node_index__gte", 1), ("node_index__lte", 2)),
                name="ck_edge_node_slot_range",
            ),
        ),
        migrations.AddIndex(
            model_name="configurationversion",
            index=models.Index(
                fields=["tenant_context", "-created_at"], name="cfg_tenant_created_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="configurationversion",
            constraint=models.UniqueConstraint(
                fields=("tenant_context", "version"), name="uq_config_tenant_version"
            ),
        ),
        migrations.AddConstraint(
            model_name="configurationversion",
            constraint=models.CheckConstraint(
                condition=models.Q(("version__gte", 1)), name="ck_config_version_positive"
            ),
        ),
        migrations.AddConstraint(
            model_name="configurationversion",
            constraint=models.CheckConstraint(
                condition=(
                    ~models.Q(("state", "PUBLISHED"))
                    | (~models.Q(("artifact_digest", "")) & models.Q(("published_at__isnull", False)))
                ),
                name="ck_published_config_complete",
            ),
        ),
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(
                fields=["tenant_context", "-occurred_at"], name="audit_tenant_time_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(fields=["request_id"], name="audit_request_idx"),
        ),
    ]
