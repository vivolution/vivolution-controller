import os

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = "Idempotently reconcile one owner-managed CP1 operator account."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")
        if not password:
            raise CommandError("DJANGO_SUPERUSER_PASSWORD is required")

        user_model = get_user_model()
        username = options["username"]
        with transaction.atomic():
            try:
                operator = user_model.objects.select_for_update().get(username=username)
                created = False
            except user_model.DoesNotExist:
                operator = user_model(username=username)
                created = True

            changed_fields = []
            for field_name in ("is_active", "is_staff", "is_superuser"):
                if not getattr(operator, field_name):
                    setattr(operator, field_name, True)
                    changed_fields.append(field_name)

            password_rehash_required = False

            def require_password_rehash(_raw_password):
                nonlocal password_rehash_required
                password_rehash_required = True

            password_matches = check_password(
                password,
                operator.password,
                setter=require_password_rehash,
            )
            if not password_matches or password_rehash_required:
                operator.set_password(password)
                changed_fields.append("password")

            if created:
                operator.save(force_insert=True)
            elif changed_fields:
                operator.save(update_fields=sorted(set(changed_fields)))

        if created or changed_fields:
            self.stdout.write("VIVOLUTION_ADMIN_RECONCILED")
        else:
            self.stdout.write("VIVOLUTION_ADMIN_PRESENT")
