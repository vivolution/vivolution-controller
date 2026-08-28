from unittest.mock import patch

from django.db import OperationalError
from django.test import SimpleTestCase, TestCase
from django.urls import reverse


class LivenessTests(SimpleTestCase):
    def test_liveness_does_not_require_database(self):
        response = self.client.get(reverse("liveness"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertEqual(
            response["Cache-Control"],
            "max-age=0, no-cache, no-store, must-revalidate, private",
        )

    def test_health_endpoints_reject_state_changing_methods(self):
        self.assertEqual(self.client.post(reverse("liveness")).status_code, 405)
        self.assertEqual(self.client.post(reverse("readiness")).status_code, 405)


class ReadinessTests(TestCase):
    def test_readiness_requires_core_rls_migration(self):
        response = self.client.get(reverse("readiness"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ready"})

    def test_database_failure_is_reported_without_details(self):
        with patch(
            "core.views.connection.cursor",
            side_effect=OperationalError("sensitive detail"),
        ):
            response = self.client.get(reverse("readiness"))

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "unavailable"})
        self.assertNotContains(response, "sensitive detail", status_code=503)
