from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from cp1.settings import database_config, env_bool


class SettingsHelpersTests(SimpleTestCase):
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
