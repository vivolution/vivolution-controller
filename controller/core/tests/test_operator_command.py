import io
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.core.management import call_command
from django.test import TestCase


class ReconcileOperatorCommandTests(TestCase):
    username = "cpadmin"
    password = "test-only-operator-password"

    def run_command(self):
        output = io.StringIO()
        with patch.dict(
            "os.environ",
            {"DJANGO_SUPERUSER_PASSWORD": self.password},
        ):
            call_command("reconcile_operator", self.username, stdout=output)
        return output.getvalue().strip()

    def test_command_creates_and_idempotently_preserves_operator_hash(self):
        self.assertEqual(self.run_command(), "VIVOLUTION_ADMIN_RECONCILED")
        operator = get_user_model().objects.get(username=self.username)
        original_hash = operator.password

        self.assertTrue(operator.is_active)
        self.assertTrue(operator.is_staff)
        self.assertTrue(operator.is_superuser)
        self.assertTrue(operator.check_password(self.password))
        self.assertEqual(self.run_command(), "VIVOLUTION_ADMIN_PRESENT")

        operator.refresh_from_db()
        self.assertEqual(operator.password, original_hash)

    def test_command_repairs_flags_and_password_without_runtime_privileges(self):
        operator = get_user_model().objects.create_user(
            username=self.username,
            password="incorrect-password",
            is_active=False,
            is_staff=False,
            is_superuser=False,
        )

        self.assertEqual(self.run_command(), "VIVOLUTION_ADMIN_RECONCILED")
        operator.refresh_from_db()
        self.assertTrue(operator.is_active)
        self.assertTrue(operator.is_staff)
        self.assertTrue(operator.is_superuser)
        self.assertTrue(operator.check_password(self.password))

    def test_command_reports_and_applies_required_password_rehash(self):
        weak_hasher = PBKDF2PasswordHasher()
        weak_hasher.iterations = 1
        operator = get_user_model().objects.create_user(
            username=self.username,
            password=self.password,
            is_active=True,
            is_staff=True,
            is_superuser=True,
        )
        operator.password = weak_hasher.encode(self.password, weak_hasher.salt())
        operator.save(update_fields=["password"])
        weak_hash = operator.password

        self.assertEqual(self.run_command(), "VIVOLUTION_ADMIN_RECONCILED")
        operator.refresh_from_db()
        self.assertNotEqual(operator.password, weak_hash)
        self.assertTrue(operator.check_password(self.password))
        self.assertEqual(self.run_command(), "VIVOLUTION_ADMIN_PRESENT")
