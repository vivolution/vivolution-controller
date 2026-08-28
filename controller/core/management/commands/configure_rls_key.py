from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from core.rls import _signing_key_bytes


class Command(BaseCommand):
    help = "Install or rotate the database copy of the signed RLS context key."

    def handle(self, *args, **options):
        if connection.vendor != "postgresql":
            raise CommandError("configure_rls_key requires PostgreSQL")

        try:
            _signing_key_bytes(settings.RLS_CONTEXT_SIGNING_KEY)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        with connection.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO cp_security.rls_signing_key AS installed_key
                        (singleton, key_material, rotated_at)
                    VALUES (true, decode(%s, 'hex'), statement_timestamp())
                    ON CONFLICT (singleton) DO UPDATE
                    SET key_material = EXCLUDED.key_material,
                        rotated_at = EXCLUDED.rotated_at
                    WHERE installed_key.key_material IS DISTINCT FROM EXCLUDED.key_material
                    """,
                    [settings.RLS_CONTEXT_SIGNING_KEY],
                )
            except Exception as exc:
                raise CommandError(
                    "could not configure the RLS key; apply core migrations first"
                ) from exc
            changed = cursor.rowcount == 1

        status = "rotated" if changed else "already current"
        self.stdout.write(self.style.SUCCESS(f"Signed RLS context key is {status}."))
