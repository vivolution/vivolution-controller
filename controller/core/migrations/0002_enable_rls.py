from django.db import migrations

POLICY_NAME = "tenant_context_isolation"
SCOPED_TABLES = {
    "core_tenantcontext": "id",
    "core_configurationversion": "tenant_context_id",
    "core_auditevent": "tenant_context_id",
}


def enable_rls(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        for table, tenant_column in SCOPED_TABLES.items():
            quoted_table = schema_editor.quote_name(table)
            quoted_column = schema_editor.quote_name(tenant_column)
            cursor.execute(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY")
            cursor.execute(
                f"""
                CREATE POLICY {POLICY_NAME} ON {quoted_table}
                FOR ALL
                USING (
                    COALESCE(current_setting('app.is_operator', true), '') = 'true'
                    OR {quoted_column} = NULLIF(
                        current_setting('app.tenant_context_id', true), ''
                    )::uuid
                )
                WITH CHECK (
                    COALESCE(current_setting('app.is_operator', true), '') = 'true'
                    OR {quoted_column} = NULLIF(
                        current_setting('app.tenant_context_id', true), ''
                    )::uuid
                )
                """
            )


def disable_rls(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        for table in reversed(SCOPED_TABLES):
            quoted_table = schema_editor.quote_name(table)
            cursor.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {quoted_table}")
            cursor.execute(f"ALTER TABLE {quoted_table} DISABLE ROW LEVEL SECURITY")


class Migration(migrations.Migration):
    dependencies = [("core", "0001_initial")]

    operations = [migrations.RunPython(enable_rls, reverse_code=disable_rls)]
