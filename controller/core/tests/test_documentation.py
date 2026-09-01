from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from core.views import DOCUMENT_CONTENT_SECURITY_POLICY


def assert_document_security(test_case, response):
    test_case.assertIn("no-store", response.headers["Cache-Control"])
    test_case.assertEqual(
        response.headers["Content-Security-Policy"],
        DOCUMENT_CONTENT_SECURITY_POLICY,
    )
    test_case.assertEqual(
        response.headers["Cross-Origin-Resource-Policy"],
        "same-origin",
    )
    test_case.assertEqual(
        response.headers["X-Robots-Tag"],
        "noindex, nofollow, noarchive",
    )


@override_settings(VIVOLUTION_RELEASE_ID="cp1-test-release")
class PublicRecoveryTests(SimpleTestCase):
    def test_root_redirects_to_configuration_console(self):
        response = self.client.get(reverse("home"))

        self.assertRedirects(
            response,
            reverse("admin:index"),
            fetch_redirect_response=False,
        )

    def test_recovery_is_public_database_independent_and_release_matched(self):
        # SimpleTestCase rejects any accidental database query. Keep this page
        # usable while the database or controller application is recovering.
        response = self.client.get(reverse("recovery"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Vivolution Control Plane Recovery")
        self.assertContains(response, "cp1-test-release")
        self.assertContains(response, reverse("admin:login"))
        self.assertContains(response, "/health/live")
        self.assertContains(response, "support-bundle")
        self.assertContains(
            response,
            "/var/lib/vivolution/installer/credentials.txt",
        )
        self.assertContains(response, "unavailable / planned")
        self.assertNotContains(response, "DATABASE_URL")
        assert_document_security(self, response)

    def test_recovery_rejects_state_changing_methods(self):
        self.assertEqual(self.client.post(reverse("recovery")).status_code, 405)


@override_settings(VIVOLUTION_RELEASE_ID="cp1-test-release")
class OperatorDocumentationTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()

    def test_anonymous_user_is_sent_to_existing_admin_login(self):
        response = self.client.get(reverse("documentation"))

        self.assertRedirects(
            response,
            f"{reverse('admin:login')}?next={reverse('documentation')}",
            fetch_redirect_response=False,
        )
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_authenticated_non_staff_user_cannot_read_operator_guidance(self):
        user = self.user_model.objects.create_user(
            username="customer",
            password="test-only-password",
        )
        self.client.force_login(user)

        response = self.client.get(reverse("documentation"))

        self.assertRedirects(
            response,
            f"{reverse('admin:login')}?next={reverse('documentation')}",
            fetch_redirect_response=False,
        )

    def test_staff_documentation_is_detailed_secure_and_release_matched(self):
        operator = self.user_model.objects.create_user(
            username="operator",
            password="test-only-password",
            is_staff=True,
        )
        self.client.force_login(operator)

        response = self.client.get(reverse("documentation"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Controller Configuration Guide")
        self.assertContains(response, "cp1-test-release")
        self.assertContains(response, "Customer account")
        self.assertContains(response, "Microsoft 365 tenant")
        self.assertContains(response, "Edge cluster")
        self.assertContains(response, "Issue a display-once enrollment grant")
        self.assertContains(response, "Approve pending enrollment claim")
        self.assertContains(response, "Revoke current node identity")
        self.assertContains(response, "enrollment and heartbeat visibility only")
        self.assertContains(response, "Configuration version")
        self.assertContains(response, "One standalone Controller")
        self.assertContains(response, "Multi-controller HA")
        self.assertContains(response, "/v0.3.0-rc6/install.sh")
        self.assertContains(response, "External HTTPS load balancer")
        self.assertContains(response, "support-bundle")
        self.assertContains(response, "unavailable / planned")
        self.assertContains(response, "/static/core/docs.css")
        assert_document_security(self, response)

    def test_admin_console_uses_product_branding_and_links_to_documentation(self):
        operator = self.user_model.objects.create_superuser(
            username="owner",
            email="owner@example.test",
            password="test-only-password",
        )
        self.client.force_login(operator)

        response = self.client.get(reverse("admin:index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Vivolution Control Plane")
        self.assertContains(response, "Controller configuration")
        self.assertContains(response, reverse("documentation"))
        self.assertContains(response, "Documentation")
        self.assertNotContains(response, reverse("admin:password_change"))
        self.assertNotContains(response, "Change password")

    def test_installer_owned_password_change_endpoints_fail_closed(self):
        operator = self.user_model.objects.create_superuser(
            username="owner",
            email="owner@example.test",
            password="test-only-password",
        )
        self.client.force_login(operator)

        for endpoint in (
            reverse("admin:password_change"),
            reverse("admin:password_change_done"),
        ):
            with self.subTest(endpoint=endpoint):
                response = self.client.get(endpoint)
                self.assertEqual(response.status_code, 404)
                self.assertContains(
                    response,
                    "password rotation is not available in this release",
                    status_code=404,
                )
                self.assertIn("no-store", response.headers["Cache-Control"])

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_shared_database_session_authenticates_on_another_controller(self):
        operator = self.user_model.objects.create_user(
            username="round-robin-operator",
            password="test-only-password",
            is_staff=True,
        )
        self.client.force_login(operator)
        signed_session = self.client.cookies[settings.SESSION_COOKIE_NAME].value

        other_controller = Client()
        other_controller.cookies[settings.SESSION_COOKIE_NAME] = signed_session
        response = other_controller.get(reverse("documentation"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Controller Configuration Guide")

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies"
    )
    def test_optional_signed_cookie_authenticates_on_another_controller(self):
        operator = self.user_model.objects.create_user(
            username="stateless-operator",
            password="test-only-password",
            is_staff=True,
        )
        self.client.force_login(operator)
        signed_session = self.client.cookies[settings.SESSION_COOKIE_NAME].value

        other_controller = Client()
        other_controller.cookies[settings.SESSION_COOKIE_NAME] = signed_session
        response = other_controller.get(reverse("documentation"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Controller Configuration Guide")

    @override_settings(SESSION_ENGINE="django.contrib.sessions.backends.db")
    def test_database_logout_revokes_replayed_session_on_every_controller(self):
        operator = self.user_model.objects.create_user(
            username="revoked-operator",
            password="test-only-password",
            is_staff=True,
        )
        self.client.force_login(operator)
        revoked_session = self.client.cookies[settings.SESSION_COOKIE_NAME].value

        logout_response = self.client.post(reverse("admin:logout"))
        self.assertIn(logout_response.status_code, (200, 302))

        other_controller = Client()
        other_controller.cookies[settings.SESSION_COOKIE_NAME] = revoked_session
        response = other_controller.get(reverse("documentation"))

        self.assertRedirects(
            response,
            f"{reverse('admin:login')}?next={reverse('documentation')}",
            fetch_redirect_response=False,
        )

    def test_documentation_rejects_state_changing_methods(self):
        operator = self.user_model.objects.create_user(
            username="operator",
            password="test-only-password",
            is_staff=True,
        )
        self.client.force_login(operator)

        self.assertEqual(self.client.post(reverse("documentation")).status_code, 405)
