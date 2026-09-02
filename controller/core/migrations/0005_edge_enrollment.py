import uuid

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0004_signed_only_rls_context"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="EnrollmentChallenge",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "purpose",
                    models.CharField(
                        choices=[
                            ("CLAIM", "Initial claim"),
                            ("STATUS", "Claim status"),
                            ("HEARTBEAT", "Heartbeat"),
                        ],
                        max_length=16,
                    ),
                ),
                ("nonce_digest", models.CharField(editable=False, max_length=64)),
                (
                    "client_nonce_digest",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                ("key_fingerprint", models.CharField(editable=False, max_length=71)),
                ("audience", models.URLField(editable=False, max_length=2048)),
                ("expires_at", models.DateTimeField()),
                (
                    "consumed_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "request_body_digest",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "request_signature",
                    models.CharField(blank=True, editable=False, max_length=86),
                ),
                (
                    "request_id",
                    models.UUIDField(blank=True, editable=False, null=True, unique=True),
                ),
                (
                    "result_claim_id",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                (
                    "result_status",
                    models.CharField(blank=True, editable=False, max_length=20),
                ),
                (
                    "result_approved_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "result_revoked_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="EnrollmentClaim",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("generation", models.PositiveIntegerField()),
                ("public_key", models.CharField(editable=False, max_length=43)),
                (
                    "public_key_fingerprint",
                    models.CharField(editable=False, max_length=71, unique=True),
                ),
                (
                    "request_body_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                ("request_signature", models.CharField(editable=False, max_length=86)),
                (
                    "client_nonce_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "inventory_digest",
                    models.CharField(
                        max_length=71,
                        validators=[
                            django.core.validators.RegexValidator(
                                message=(
                                    "Use an empty value or a lowercase "
                                    "sha256:<64 hex characters> digest."
                                ),
                                regex="^$|^sha256:[0-9a-f]{64}$",
                            )
                        ],
                    ),
                ),
                (
                    "release_digest",
                    models.CharField(
                        max_length=71,
                        validators=[
                            django.core.validators.RegexValidator(
                                message=(
                                    "Use an empty value or a lowercase "
                                    "sha256:<64 hex characters> digest."
                                ),
                                regex="^$|^sha256:[0-9a-f]{64}$",
                            )
                        ],
                    ),
                ),
                (
                    "approved_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "revoked_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "revocation_reason",
                    models.CharField(blank=True, editable=False, max_length=240),
                ),
                (
                    "last_status_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
            ],
            options={
                "ordering": ["node__cluster__name", "node__node_index", "-generation"]
            },
        ),
        migrations.CreateModel(
            name="EnrollmentGrant",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("token_digest", models.CharField(editable=False, max_length=64, unique=True)),
                (
                    "expected_release_digest",
                    models.CharField(
                        max_length=71,
                        validators=[
                            django.core.validators.RegexValidator(
                                message=(
                                    "Use an empty value or a lowercase "
                                    "sha256:<64 hex characters> digest."
                                ),
                                regex="^$|^sha256:[0-9a-f]{64}$",
                            )
                        ],
                    ),
                ),
                ("expires_at", models.DateTimeField()),
                (
                    "claimed_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "revoked_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddField(
            model_name="edgenode",
            name="generation",
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="edgenode",
            name="last_boot_id",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="edgenode",
            name="last_heartbeat_sequence",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="edgenode",
            name="observed_health",
            field=models.CharField(
                blank=True,
                choices=[("HEALTHY", "Healthy"), ("DEGRADED", "Degraded")],
                editable=False,
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="edgenode",
            name="observed_inventory_digest",
            field=models.CharField(
                blank=True,
                editable=False,
                max_length=71,
                validators=[
                    django.core.validators.RegexValidator(
                        message=(
                            "Use an empty value or a lowercase "
                            "sha256:<64 hex characters> digest."
                        ),
                        regex="^$|^sha256:[0-9a-f]{64}$",
                    )
                ],
            ),
        ),
        migrations.AddField(
            model_name="edgenode",
            name="observed_release_digest",
            field=models.CharField(
                blank=True,
                editable=False,
                max_length=71,
                validators=[
                    django.core.validators.RegexValidator(
                        message=(
                            "Use an empty value or a lowercase "
                            "sha256:<64 hex characters> digest."
                        ),
                        regex="^$|^sha256:[0-9a-f]{64}$",
                    )
                ],
            ),
        ),
        migrations.AlterField(
            model_name="edgenode",
            name="status",
            field=models.CharField(
                choices=[
                    ("EXPECTED", "Expected"),
                    ("PENDING_APPROVAL", "Pending approval"),
                    ("APPROVED", "Approved"),
                    ("ONLINE", "Online"),
                    ("DEGRADED", "Degraded"),
                    ("OFFLINE", "Offline"),
                    ("REVOKED", "Revoked"),
                    ("RETIRED", "Retired"),
                ],
                default="EXPECTED",
                max_length=20,
            ),
        ),
        migrations.AddConstraint(
            model_name="edgenode",
            constraint=models.CheckConstraint(
                condition=models.Q(("generation__gte", 1)),
                name="ck_edge_node_generation_positive",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentchallenge",
            name="node",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="enrollment_challenges",
                to="core.edgenode",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentclaim",
            name="approved_by",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="approved_enrollment_claims",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="enrollmentclaim",
            name="node",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="enrollment_claims",
                to="core.edgenode",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentclaim",
            name="revoked_by",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="revoked_enrollment_claims",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="enrollmentchallenge",
            name="claim",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="challenges",
                to="core.enrollmentclaim",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentgrant",
            name="issued_by",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="issued_enrollment_grants",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="enrollmentgrant",
            name="node",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="enrollment_grants",
                to="core.edgenode",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentclaim",
            name="grant",
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="claim",
                to="core.enrollmentgrant",
            ),
        ),
        migrations.AddField(
            model_name="enrollmentchallenge",
            name="grant",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="challenges",
                to="core.enrollmentgrant",
            ),
        ),
        migrations.AddIndex(
            model_name="enrollmentgrant",
            index=models.Index(
                fields=["node", "expires_at"], name="grant_node_expiry_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentgrant",
            constraint=models.CheckConstraint(
                condition=~models.Q(("expected_release_digest", "")),
                name="ck_grant_release_digest_present",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentgrant",
            constraint=models.CheckConstraint(
                condition=models.Q(("expires_at__gt", models.F("created_at"))),
                name="ck_grant_expiry_after_create",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.UniqueConstraint(
                fields=("node", "generation"), name="uq_claim_node_generation"
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.CheckConstraint(
                condition=models.Q(("generation__gte", 1)),
                name="ck_claim_generation_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.CheckConstraint(
                condition=~models.Q(("inventory_digest", "")),
                name="ck_claim_inventory_digest_present",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.CheckConstraint(
                condition=~models.Q(("release_digest", "")),
                name="ck_claim_release_digest_present",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("approved_at__isnull", True), ("approved_by__isnull", True)),
                    models.Q(
                        ("approved_at__isnull", False),
                        ("approved_by__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="ck_claim_approval_pair",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentclaim",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(("revoked_at__isnull", True), ("revoked_by__isnull", True)),
                    models.Q(
                        ("revoked_at__isnull", False),
                        ("revoked_by__isnull", False),
                    ),
                    _connector="OR",
                ),
                name="ck_claim_revocation_pair",
            ),
        ),
        migrations.AddIndex(
            model_name="enrollmentchallenge",
            index=models.Index(
                fields=["node", "purpose", "expires_at"],
                name="challenge_node_exp_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="enrollmentchallenge",
            index=models.Index(
                fields=["node", "expires_at"],
                name="challenge_node_ret_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentchallenge",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(
                        ("claim__isnull", True),
                        ("grant__isnull", False),
                        ("purpose", "CLAIM"),
                    ),
                    models.Q(
                        ("claim__isnull", False),
                        ("grant__isnull", True),
                        ("purpose__in", ("STATUS", "HEARTBEAT")),
                    ),
                    _connector="OR",
                ),
                name="ck_challenge_scope_shape",
            ),
        ),
        migrations.AddConstraint(
            model_name="enrollmentchallenge",
            constraint=models.CheckConstraint(
                condition=models.Q(("expires_at__gt", models.F("created_at"))),
                name="ck_challenge_expiry_after_create",
            ),
        ),
    ]
