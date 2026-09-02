from django.contrib import admin
from django.urls import path
from django.views.generic import RedirectView

from core.edge_views import (
    enrollment_challenge,
    enrollment_claim,
    enrollment_status,
    node_challenge,
    node_heartbeat,
)
from core.views import (
    documentation,
    liveness,
    readiness,
    recovery,
    unsupported_password_change,
)

urlpatterns = [
    path(
        "",
        RedirectView.as_view(pattern_name="admin:index", permanent=False),
        name="home",
    ),
    path("health/live", liveness, name="liveness"),
    path("health/ready", readiness, name="readiness"),
    path(
        "api/edge/v1/enrollment/challenge",
        enrollment_challenge,
        name="edge-enrollment-challenge",
    ),
    path(
        "api/edge/v1/enrollment/claim",
        enrollment_claim,
        name="edge-enrollment-claim",
    ),
    path(
        "api/edge/v1/node/challenge",
        node_challenge,
        name="edge-node-challenge",
    ),
    path(
        "api/edge/v1/enrollment/status",
        enrollment_status,
        name="edge-enrollment-status",
    ),
    path(
        "api/edge/v1/node/heartbeat",
        node_heartbeat,
        name="edge-node-heartbeat",
    ),
    path("docs/", documentation, name="documentation"),
    path("recovery/", recovery, name="recovery"),
    # The runtime role cannot update auth rows and reconcile restores the
    # installer-owned credential. Intercept Django's built-in endpoints until
    # a complete, durable credential-rotation workflow is released.
    path("admin/password_change/", unsupported_password_change),
    path("admin/password_change/done/", unsupported_password_change),
    path("admin/", admin.site.urls),
]
