from django.contrib import admin
from django.urls import path
from django.views.generic import RedirectView

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
    path("docs/", documentation, name="documentation"),
    path("recovery/", recovery, name="recovery"),
    # The runtime role cannot update auth rows and reconcile restores the
    # installer-owned credential. Intercept Django's built-in endpoints until
    # a complete, durable credential-rotation workflow is released.
    path("admin/password_change/", unsupported_password_change),
    path("admin/password_change/done/", unsupported_password_change),
    path("admin/", admin.site.urls),
]
