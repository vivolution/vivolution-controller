import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models

SHA256_DIGEST_VALIDATOR = RegexValidator(
    regex=r"^$|^sha256:[0-9a-f]{64}$",
    message="Use an empty value or a lowercase sha256:<64 hex characters> digest.",
)


class UUIDTimestampedModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class CustomerAccount(UUIDTimestampedModel):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        SUSPENDED = "SUSPENDED", "Suspended"
        DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned"

    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=80, unique=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class M365Tenant(UUIDTimestampedModel):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending verification"
        VERIFIED = "VERIFIED", "Verified"
        DISABLED = "DISABLED", "Disabled"

    customer_account = models.ForeignKey(
        CustomerAccount, on_delete=models.PROTECT, related_name="m365_tenants"
    )
    entra_tenant_id = models.UUIDField(unique=True)
    display_name = models.CharField(max_length=200)
    primary_domain = models.CharField(max_length=253, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["display_name"]

    def __str__(self):
        return f"{self.display_name} ({self.entra_tenant_id})"


class TenantContext(UUIDTimestampedModel):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        SUSPENDED = "SUSPENDED", "Suspended"
        DECOMMISSIONED = "DECOMMISSIONED", "Decommissioned"

    customer_account = models.ForeignKey(
        CustomerAccount, on_delete=models.PROTECT, related_name="tenant_contexts"
    )
    m365_tenant = models.ForeignKey(
        M365Tenant, on_delete=models.PROTECT, related_name="tenant_contexts"
    )
    name = models.CharField(max_length=120)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)

    class Meta:
        ordering = ["customer_account__name", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["customer_account", "name"], name="uq_tenant_context_name"
            )
        ]

    def clean(self):
        super().clean()
        if self.m365_tenant_id and self.customer_account_id:
            if self.m365_tenant.customer_account_id != self.customer_account_id:
                raise ValidationError(
                    {"m365_tenant": "The Microsoft 365 tenant belongs to another customer account."}
                )

    def __str__(self):
        return f"{self.customer_account}: {self.name}"


class EdgeCluster(UUIDTimestampedModel):
    class ServiceMode(models.TextChoices):
        SHARED_ENHANCED = "SHARED_ENHANCED", "Shared Enhanced"
        EXCLUSIVE = "EXCLUSIVE", "Exclusive"

    class Status(models.TextChoices):
        PLANNED = "PLANNED", "Planned"
        ACTIVE = "ACTIVE", "Active"
        MAINTENANCE = "MAINTENANCE", "Maintenance"
        RETIRED = "RETIRED", "Retired"

    name = models.SlugField(max_length=80, unique=True)
    service_mode = models.CharField(max_length=24, choices=ServiceMode.choices)
    exclusive_customer_account = models.ForeignKey(
        CustomerAccount,
        on_delete=models.PROTECT,
        related_name="exclusive_edge_clusters",
        null=True,
        blank=True,
    )
    region = models.CharField(max_length=80, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNED)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        service_mode="EXCLUSIVE", exclusive_customer_account__isnull=False
                    )
                    | models.Q(
                        service_mode="SHARED_ENHANCED",
                        exclusive_customer_account__isnull=True,
                    )
                ),
                name="ck_cluster_exclusive_owner",
            )
        ]

    def __str__(self):
        return self.name


class EdgeNode(UUIDTimestampedModel):
    class Architecture(models.TextChoices):
        AMD64 = "AMD64", "amd64"
        ARM64 = "ARM64", "arm64"

    class Status(models.TextChoices):
        EXPECTED = "EXPECTED", "Expected"
        PENDING_APPROVAL = "PENDING_APPROVAL", "Pending approval"
        APPROVED = "APPROVED", "Approved"
        ONLINE = "ONLINE", "Online"
        DEGRADED = "DEGRADED", "Degraded"
        OFFLINE = "OFFLINE", "Offline"
        REVOKED = "REVOKED", "Revoked"
        RETIRED = "RETIRED", "Retired"

    class Health(models.TextChoices):
        HEALTHY = "HEALTHY", "Healthy"
        DEGRADED = "DEGRADED", "Degraded"

    cluster = models.ForeignKey(EdgeCluster, on_delete=models.PROTECT, related_name="nodes")
    name = models.SlugField(max_length=80)
    node_index = models.PositiveSmallIntegerField(help_text="Expected HA slot: 1 or 2")
    generation = models.PositiveIntegerField(default=1)
    architecture = models.CharField(max_length=10, choices=Architecture.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.EXPECTED)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_heartbeat_sequence = models.PositiveBigIntegerField(default=0, editable=False)
    last_boot_id = models.UUIDField(null=True, blank=True, editable=False)
    observed_inventory_digest = models.CharField(
        max_length=71,
        blank=True,
        validators=[SHA256_DIGEST_VALIDATOR],
        editable=False,
    )
    observed_release_digest = models.CharField(
        max_length=71,
        blank=True,
        validators=[SHA256_DIGEST_VALIDATOR],
        editable=False,
    )
    observed_health = models.CharField(
        max_length=16,
        choices=Health.choices,
        blank=True,
        editable=False,
    )

    class Meta:
        ordering = ["cluster__name", "node_index"]
        constraints = [
            models.UniqueConstraint(fields=["cluster", "name"], name="uq_edge_node_name"),
            models.UniqueConstraint(
                fields=["cluster", "node_index"], name="uq_edge_node_slot"
            ),
            models.CheckConstraint(
                condition=models.Q(node_index__gte=1, node_index__lte=2),
                name="ck_edge_node_slot_range",
            ),
            models.CheckConstraint(
                condition=models.Q(generation__gte=1),
                name="ck_edge_node_generation_positive",
            ),
        ]

    def __str__(self):
        return f"{self.cluster}/{self.name}"


class EnrollmentGrant(UUIDTimestampedModel):
    """Hash-only, display-once authority to attempt one exact node claim."""

    node = models.ForeignKey(
        EdgeNode,
        on_delete=models.PROTECT,
        related_name="enrollment_grants",
    )
    token_digest = models.CharField(max_length=64, unique=True, editable=False)
    expected_release_digest = models.CharField(
        max_length=71,
        validators=[SHA256_DIGEST_VALIDATOR],
    )
    expires_at = models.DateTimeField()
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="issued_enrollment_grants",
    )
    claimed_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["node", "expires_at"], name="grant_node_expiry_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(expected_release_digest=""),
                name="ck_grant_release_digest_present",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("created_at")),
                name="ck_grant_expiry_after_create",
            ),
        ]

    def __str__(self):
        return f"Enrollment grant {self.id} for {self.node}"


class EnrollmentClaim(UUIDTimestampedModel):
    """The node key and inventory bound by a successfully proved claim."""

    grant = models.OneToOneField(
        EnrollmentGrant,
        on_delete=models.PROTECT,
        related_name="claim",
    )
    node = models.ForeignKey(
        EdgeNode,
        on_delete=models.PROTECT,
        related_name="enrollment_claims",
    )
    generation = models.PositiveIntegerField()
    public_key = models.CharField(max_length=43, editable=False)
    public_key_fingerprint = models.CharField(max_length=71, unique=True, editable=False)
    request_body_digest = models.CharField(max_length=64, editable=False)
    request_signature = models.CharField(max_length=86, editable=False)
    client_nonce_digest = models.CharField(max_length=64, editable=False)
    inventory_digest = models.CharField(max_length=71, validators=[SHA256_DIGEST_VALIDATOR])
    release_digest = models.CharField(max_length=71, validators=[SHA256_DIGEST_VALIDATOR])
    approved_at = models.DateTimeField(null=True, blank=True, editable=False)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="approved_enrollment_claims",
        null=True,
        blank=True,
        editable=False,
    )
    revoked_at = models.DateTimeField(null=True, blank=True, editable=False)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="revoked_enrollment_claims",
        null=True,
        blank=True,
        editable=False,
    )
    revocation_reason = models.CharField(max_length=240, blank=True, editable=False)
    last_status_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ["node__cluster__name", "node__node_index", "-generation"]
        constraints = [
            models.UniqueConstraint(
                fields=["node", "generation"],
                name="uq_claim_node_generation",
            ),
            models.CheckConstraint(
                condition=models.Q(generation__gte=1),
                name="ck_claim_generation_positive",
            ),
            models.CheckConstraint(
                condition=~models.Q(inventory_digest=""),
                name="ck_claim_inventory_digest_present",
            ),
            models.CheckConstraint(
                condition=~models.Q(release_digest=""),
                name="ck_claim_release_digest_present",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(approved_at__isnull=True, approved_by__isnull=True)
                    | models.Q(approved_at__isnull=False, approved_by__isnull=False)
                ),
                name="ck_claim_approval_pair",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(revoked_at__isnull=True, revoked_by__isnull=True)
                    | models.Q(revoked_at__isnull=False, revoked_by__isnull=False)
                ),
                name="ck_claim_revocation_pair",
            ),
        ]

    def __str__(self):
        return f"Claim {self.id} for {self.node}"


class EnrollmentChallenge(UUIDTimestampedModel):
    class Purpose(models.TextChoices):
        CLAIM = "CLAIM", "Initial claim"
        STATUS = "STATUS", "Claim status"
        HEARTBEAT = "HEARTBEAT", "Heartbeat"

    node = models.ForeignKey(
        EdgeNode,
        on_delete=models.PROTECT,
        related_name="enrollment_challenges",
    )
    grant = models.ForeignKey(
        EnrollmentGrant,
        on_delete=models.PROTECT,
        related_name="challenges",
        null=True,
        blank=True,
    )
    claim = models.ForeignKey(
        EnrollmentClaim,
        on_delete=models.PROTECT,
        related_name="challenges",
        null=True,
        blank=True,
    )
    purpose = models.CharField(max_length=16, choices=Purpose.choices)
    nonce_digest = models.CharField(max_length=64, editable=False)
    client_nonce_digest = models.CharField(max_length=64, blank=True, editable=False)
    key_fingerprint = models.CharField(max_length=71, editable=False)
    audience = models.URLField(max_length=2048, editable=False)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True, editable=False)
    request_body_digest = models.CharField(max_length=64, blank=True, editable=False)
    request_signature = models.CharField(max_length=86, blank=True, editable=False)
    request_id = models.UUIDField(null=True, blank=True, unique=True, editable=False)
    result_claim_id = models.UUIDField(null=True, blank=True, editable=False)
    result_status = models.CharField(max_length=20, blank=True, editable=False)
    result_approved_at = models.DateTimeField(null=True, blank=True, editable=False)
    result_revoked_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["node", "purpose", "expires_at"],
                name="challenge_node_exp_idx",
            ),
            models.Index(
                fields=["node", "expires_at"],
                name="challenge_node_ret_idx",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(purpose="CLAIM", grant__isnull=False, claim__isnull=True)
                    | models.Q(
                        purpose__in=("STATUS", "HEARTBEAT"),
                        grant__isnull=True,
                        claim__isnull=False,
                    )
                ),
                name="ck_challenge_scope_shape",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("created_at")),
                name="ck_challenge_expiry_after_create",
            ),
        ]

    def __str__(self):
        return f"{self.purpose} challenge {self.id} for {self.node}"


class ConfigurationVersion(UUIDTimestampedModel):
    class State(models.TextChoices):
        DRAFT = "DRAFT", "Draft"
        VALIDATED = "VALIDATED", "Validated"
        PUBLISHED = "PUBLISHED", "Published"
        RETIRED = "RETIRED", "Retired"

    tenant_context = models.ForeignKey(
        TenantContext, on_delete=models.PROTECT, related_name="configuration_versions"
    )
    version = models.PositiveBigIntegerField()
    state = models.CharField(max_length=20, choices=State.choices, default=State.DRAFT)
    artifact_digest = models.CharField(
        max_length=71, blank=True, validators=[SHA256_DIGEST_VALIDATOR]
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="created_configuration_versions",
        null=True,
        blank=True,
    )
    published_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["tenant_context", "-version"]
        constraints = [
            models.UniqueConstraint(
                fields=["tenant_context", "version"], name="uq_config_tenant_version"
            ),
            models.CheckConstraint(
                condition=models.Q(version__gte=1), name="ck_config_version_positive"
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(state="PUBLISHED")
                    | (
                        ~models.Q(artifact_digest="")
                        & models.Q(published_at__isnull=False)
                    )
                ),
                name="ck_published_config_complete",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_context", "-created_at"], name="cfg_tenant_created_idx"
            )
        ]

    def clean(self):
        super().clean()
        if self.state == self.State.PUBLISHED:
            errors = {}
            if not self.artifact_digest:
                errors["artifact_digest"] = "A published version requires an artifact digest."
            if self.published_at is None:
                errors["published_at"] = "A published version requires a publication time."
            if errors:
                raise ValidationError(errors)

    def __str__(self):
        return f"{self.tenant_context} v{self.version}"


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_context = models.ForeignKey(
        TenantContext,
        on_delete=models.PROTECT,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=120)
    target_type = models.CharField(max_length=120)
    target_id = models.CharField(max_length=128, blank=True)
    request_id = models.UUIDField(default=uuid.uuid4, editable=False)
    detail = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(
                fields=["tenant_context", "-occurred_at"], name="audit_tenant_time_idx"
            ),
            models.Index(fields=["request_id"], name="audit_request_idx"),
        ]

    def __str__(self):
        return f"{self.occurred_at}: {self.action}"
