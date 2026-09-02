from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

POLICY_NAME = "operator_context_only"
ENROLLMENT_TABLES = (
    "core_enrollmentgrant",
    "core_enrollmentclaim",
    "core_enrollmentchallenge",
)


def protect_enrollment_tables(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        for table in ENROLLMENT_TABLES:
            quoted_table = schema_editor.quote_name(table)
            cursor.execute(
                """
                SELECT
                    pg_get_userbyid(c.relowner) = current_user,
                    NOT c.relrowsecurity,
                    (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) = 0
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname = %s
                  AND c.relkind IN ('r', 'p')
                """,
                [table],
            )
            if cursor.fetchone() != (True, True, True):
                raise RuntimeError(f"operator-only RLS precondition is invalid for {table}")
            cursor.execute(
                f"""
                CREATE POLICY {POLICY_NAME} ON {quoted_table}
                FOR ALL
                TO PUBLIC
                USING (cp_security.rls_context_allows(NULL))
                WITH CHECK (cp_security.rls_context_allows(NULL))
                """
            )
            cursor.execute(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY")


def refuse_insecure_reverse(apps, schema_editor):
    raise IrreversibleError("enrollment inventory cannot be downgraded to tables without RLS")


class Migration(migrations.Migration):
    atomic = True
    dependencies = [("core", "0005_edge_enrollment")]

    operations = [
        migrations.RunPython(
            protect_enrollment_tables,
            reverse_code=refuse_insecure_reverse,
        )
    ]
