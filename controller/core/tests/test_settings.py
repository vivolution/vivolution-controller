from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from cp1 import settings
from cp1.settings import (
    database_config,
    env_bool,
    env_controller_origin,
    env_int,
    env_release_id,
    env_session_engine,
)


class SettingsHelpersTests(SimpleTestCase):
    def test_operator_sessions_remain_legacy_safe_file_backed_by_default(self):
        self.assertEqual(
            settings.SESSION_ENGINE,
            "django.contrib.sessions.backends.file",
        )
        self.assertEqual(settings.SESSION_COOKIE_AGE, 3600)
        self.assertFalse(settings.SESSION_SAVE_EVERY_REQUEST)
        self.assertEqual(settings.SESSION_FILE_PATH, "/tmp")

    def test_session_engine_accepts_only_db_file_or_signed_cookies(self):
        supported_engines = {
            "db": "django.contrib.sessions.backends.db",
            "file": "django.contrib.sessions.backends.file",
            "signed_cookies": "django.contrib.sessions.backends.signed_cookies",
        }
        for configured_value, expected_engine in supported_engines.items():
            with self.subTest(configured_value=configured_value):
                with patch.dict(
                    "os.environ",
                    {"SESSION_ENGINE_UNDER_TEST": configured_value},
                ):
                    self.assertEqual(
                        env_session_engine("SESSION_ENGINE_UNDER_TEST"),
                        expected_engine,
                    )

        for invalid_value in (
            "cached_db",
            "django.contrib.sessions.backends.db",
            "django.contrib.sessions.backends.signed_cookies",
            "SIGNED_COOKIES",
            " signed_cookies ",
        ):
            with self.subTest(invalid_value=invalid_value):
                with patch.dict(
                    "os.environ",
                    {"SESSION_ENGINE_UNDER_TEST": invalid_value},
                ):
                    with self.assertRaises(ImproperlyConfigured):
                        env_session_engine("SESSION_ENGINE_UNDER_TEST")

    def test_session_cookie_age_is_hard_bounded(self):
        for invalid_age in (299, 28801):
            with self.subTest(invalid_age=invalid_age):
                with patch.dict(
                    "os.environ",
                    {"SESSION_AGE_UNDER_TEST": str(invalid_age)},
                ):
                    with self.assertRaises(ImproperlyConfigured):
                        env_int(
                            "SESSION_AGE_UNDER_TEST",
                            3600,
                            minimum=300,
                            maximum=28800,
                        )

    def test_database_url_is_parsed_without_logging_credentials(self):
        with patch.dict("os.environ", {"DB_CONN_MAX_AGE": "30"}):
            config = database_config(
                "postgresql://cp_user:p%40ss@db.example.test:6432/control%20plane"
                "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fca.pem&ignored=value"
            )

        self.assertEqual(config["NAME"], "control plane")
        self.assertEqual(config["USER"], "cp_user")
        self.assertEqual(config["PASSWORD"], "p@ss")
        self.assertEqual(config["HOST"], "db.example.test")
        self.assertEqual(config["PORT"], "6432")
        self.assertEqual(config["CONN_MAX_AGE"], 30)
        self.assertEqual(
            config["OPTIONS"],
            {"sslmode": "verify-full", "sslrootcert": "/etc/ssl/ca.pem"},
        )

    def test_non_postgresql_database_url_is_rejected(self):
        with self.assertRaisesMessage(ImproperlyConfigured, "postgres"):
            database_config("sqlite:///tmp/db.sqlite3")

    def test_invalid_boolean_is_rejected(self):
        with patch.dict("os.environ", {"SETTING_UNDER_TEST": "perhaps"}):
            with self.assertRaises(ImproperlyConfigured):
                env_bool("SETTING_UNDER_TEST")

    def test_bounded_integer_is_validated(self):
        with patch.dict("os.environ", {"SETTING_UNDER_TEST": "61"}):
            self.assertEqual(
                env_int("SETTING_UNDER_TEST", 60, minimum=5, maximum=300),
                61,
            )
        with patch.dict("os.environ", {"SETTING_UNDER_TEST": "301"}):
            with self.assertRaises(ImproperlyConfigured):
                env_int("SETTING_UNDER_TEST", 60, minimum=5, maximum=300)

    def test_controller_origin_is_canonicalized(self):
        with patch.dict(
            "os.environ",
            {"ORIGIN_UNDER_TEST": "https://Controller.Voice.Example.COM.:443/"},
        ):
            self.assertEqual(
                env_controller_origin("ORIGIN_UNDER_TEST"),
                "https://controller.voice.example.com",
            )

    def test_controller_origin_rejects_non_origin_and_ip_values(self):
        invalid_values = (
            "http://controller.example.com",
            "https://127.0.0.1",
            "https://[2001:db8::1]",
            "https://controller.example.com:8443",
            "https://controller.example.com:notaport",
            "https://user@controller.example.com",
            "https://controller.example.com/path",
            "https://controller.example.com?query=yes",
            "https://controller.example.com#fragment",
            "https://singlelabel",
            "https://-bad.example.com",
        )
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with patch.dict(
                    "os.environ",
                    {"ORIGIN_UNDER_TEST": invalid_value},
                ):
                    with self.assertRaises(ImproperlyConfigured):
                        env_controller_origin("ORIGIN_UNDER_TEST")

    def test_release_identifier_is_bounded_and_safe_for_display(self):
        with patch.dict("os.environ", {"RELEASE_UNDER_TEST": "cp1-2026.08.31+1"}):
            self.assertEqual(
                env_release_id("RELEASE_UNDER_TEST"),
                "cp1-2026.08.31+1",
            )

        for invalid_value in ("", "contains spaces", "<script>", "x" * 129):
            with self.subTest(invalid_value=invalid_value):
                with patch.dict(
                    "os.environ",
                    {"RELEASE_UNDER_TEST": invalid_value},
                ):
                    with self.assertRaises(ImproperlyConfigured):
                        env_release_id("RELEASE_UNDER_TEST")
