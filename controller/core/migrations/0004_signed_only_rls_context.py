from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

POLICY_NAME = "tenant_context_isolation"
OPERATOR_POLICY_NAME = "operator_context_only"
TENANT_METADATA_READ_POLICY_NAME = "tenant_metadata_read"
SCOPED_TABLES = {
    "core_tenantcontext": "id",
    "core_configurationversion": "tenant_context_id",
    "core_auditevent": "tenant_context_id",
}
OPERATOR_TABLES = (
    "core_customeraccount",
    "core_m365tenant",
    "core_edgecluster",
    "core_edgenode",
)
TENANT_METADATA_RELATIONSHIPS = {
    "core_customeraccount": "tenant_context.customer_account_id = core_customeraccount.id",
    "core_m365tenant": "tenant_context.m365_tenant_id = core_m365tenant.id",
}


def enforce_signed_only_context(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                EXISTS (
                    SELECT 1
                    FROM pg_namespace n
                    WHERE n.nspname = 'cp_security'
                      AND pg_get_userbyid(n.nspowner) = current_user
                ),
                EXISTS (
                    SELECT 1
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'cp_security'
                      AND c.relname = 'rls_signing_key'
                      AND c.relkind IN ('r', 'p')
                      AND pg_get_userbyid(c.relowner) = current_user
                ),
                EXISTS (
                    SELECT 1
                    FROM pg_proc p
                    JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'cp_security'
                      AND p.oid = to_regprocedure(
                          'cp_security.rls_context_allows(uuid)'
                      )
                      AND pg_get_userbyid(p.proowner) = current_user
                      AND p.prosecdef
                      AND COALESCE(p.proconfig, ARRAY[]::text[]) @>
                          ARRAY['search_path=pg_catalog, pg_temp']::text[]
                )
            """
        )
        if cursor.fetchone() != (True, True, True):
            raise RuntimeError("signed RLS schema ownership or validator hardening is invalid")

        for table, tenant_column in SCOPED_TABLES.items():
            quoted_table = schema_editor.quote_name(table)
            quoted_column = schema_editor.quote_name(tenant_column)
            cursor.execute(
                """
                SELECT
                    pg_get_userbyid(c.relowner) = current_user,
                    c.relrowsecurity,
                    (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) = 1,
                    EXISTS (
                        SELECT 1
                        FROM pg_policy p
                        WHERE p.polrelid = c.oid
                          AND p.polname = %s
                          AND p.polpermissive
                          AND p.polcmd = '*'
                          AND p.polroles = ARRAY[0]::oid[]
                    )
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relname = %s
                  AND c.relkind IN ('r', 'p')
                """,
                [POLICY_NAME, table],
            )
            if cursor.fetchone() != (True, True, True, True):
                raise RuntimeError(f"RLS bridge policy contract is invalid for {table}")

            signed_expression = f"cp_security.rls_context_allows({quoted_column})"
            if table == "core_tenantcontext":
                cursor.execute(f"DROP POLICY {POLICY_NAME} ON {quoted_table}")
                cursor.execute(
                    f"""
                    CREATE POLICY {POLICY_NAME} ON {quoted_table}
                    FOR SELECT
                    TO PUBLIC
                    USING ({signed_expression})
                    """
                )
                operator_expression = "cp_security.rls_context_allows(NULL)"
                cursor.execute(
                    f"""
                    CREATE POLICY {OPERATOR_POLICY_NAME} ON {quoted_table}
                    FOR ALL
                    TO PUBLIC
                    USING ({operator_expression})
                    WITH CHECK ({operator_expression})
                    """
                )
            else:
                cursor.execute(
                    f"""
                    ALTER POLICY {POLICY_NAME} ON {quoted_table}
                    TO PUBLIC
                    USING ({signed_expression})
                    WITH CHECK ({signed_expression})
                    """
                )

        for table in OPERATOR_TABLES:
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
                raise RuntimeError(
                    f"operator-only RLS precondition is invalid for {table}"
                )

            operator_expression = "cp_security.rls_context_allows(NULL)"
            cursor.execute(
                f"""
                CREATE POLICY {OPERATOR_POLICY_NAME} ON {quoted_table}
                FOR ALL
                TO PUBLIC
                USING ({operator_expression})
                WITH CHECK ({operator_expression})
                """
            )
            if table in TENANT_METADATA_RELATIONSHIPS:
                cursor.execute(
                    f"""
                    CREATE POLICY {TENANT_METADATA_READ_POLICY_NAME} ON {quoted_table}
                    FOR SELECT
                    TO PUBLIC
                    USING (
                        EXISTS (
                            SELECT 1
                            FROM core_tenantcontext AS tenant_context
                            WHERE {TENANT_METADATA_RELATIONSHIPS[table]}
                              AND cp_security.rls_context_allows(tenant_context.id)
                        )
                    )
                    """
                )
            cursor.execute(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY")


def refuse_insecure_reverse(apps, schema_editor):
    raise IrreversibleError(
        "signed-only RLS policies cannot restore caller-controlled settings"
    )


class Migration(migrations.Migration):
    atomic = True
    dependencies = [("core", "0003_signed_rls_context")]

    operations = [
        migrations.RunPython(
            enforce_signed_only_context,
            reverse_code=refuse_insecure_reverse,
        )
    ]
