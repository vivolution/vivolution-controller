from django.contrib import admin
from django.urls import path

from core.views import liveness, readiness


urlpatterns = [
    path("health/live", liveness, name="liveness"),
    path("health/ready", readiness, name="readiness"),
    path("admin/", admin.site.urls),
]
