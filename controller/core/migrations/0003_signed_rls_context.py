from django.db import migrations
from django.db.migrations.exceptions import IrreversibleError

POLICY_NAME = "tenant_context_isolation"
SCOPED_TABLES = {
    "core_tenantcontext": "id",
    "core_configurationversion": "tenant_context_id",
    "core_auditevent": "tenant_context_id",
}

# This migration is deliberately a compatibility bridge. New application
# releases emit an authenticated token, while the immediately preceding Lab
# release still emits the two legacy transaction-local settings. Migration
# 0004 removes the legacy clauses only after a signed-capable N-1 release has
# been deployed and proven recoverable.
LEGACY_CONTEXT_ALLOWS = """
    COALESCE(current_setting('app.is_operator', true), '') = 'true'
    OR {tenant_column} = NULLIF(
        current_setting('app.tenant_context_id', true), ''
    )::uuid
"""


def install_signed_context_policy(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("CREATE SCHEMA IF NOT EXISTS cp_security")
        cursor.execute(
            """
            SELECT n.nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
            FROM pg_namespace n
            WHERE n.nspname = 'cp_security'
            """
        )
        if cursor.fetchone() != (True,):
            raise RuntimeError("cp_security must be owned by the migration role")

        cursor.execute("REVOKE ALL ON SCHEMA cp_security FROM PUBLIC")
        cursor.execute("GRANT USAGE ON SCHEMA cp_security TO PUBLIC")
        cursor.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA cp_security REVOKE ALL ON TABLES FROM PUBLIC"
        )
        cursor.execute(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA cp_security REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
        )

        cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cursor.execute(
            """
            SELECT n.nspname
            FROM pg_extension e
            JOIN pg_namespace n ON n.oid = e.extnamespace
            WHERE e.extname = 'pgcrypto'
            """
        )
        pgcrypto_row = cursor.fetchone()
        if pgcrypto_row is None:
            raise RuntimeError("the pgcrypto extension is required for signed RLS contexts")
        pgcrypto_schema = schema_editor.quote_name(pgcrypto_row[0])

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cp_security.rls_signing_key (
                singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                key_material bytea NOT NULL CHECK (octet_length(key_material) = 32),
                rotated_at timestamp with time zone NOT NULL DEFAULT statement_timestamp()
            )
            """
        )
        cursor.execute("REVOKE ALL ON TABLE cp_security.rls_signing_key FROM PUBLIC")

        cursor.execute(
            f"""
            CREATE OR REPLACE FUNCTION cp_security.rls_context_allows(row_tenant uuid)
            RETURNS boolean
            LANGUAGE plpgsql
            STABLE
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $function$
            DECLARE
                token_value text := current_setting('app.rls_context', true);
                token_parts text[];
                mode_value text;
                tenant_value text;
                expiry_value bigint;
                nonce_value text;
                signature_value text;
                payload_value text;
                signing_key bytea;
                expected_signature text;
                now_epoch bigint := floor(extract(epoch FROM statement_timestamp()))::bigint;
            BEGIN
                IF token_value IS NULL OR length(token_value) > 256 THEN
                    RETURN false;
                END IF;

                token_parts := string_to_array(token_value, '|');
                IF cardinality(token_parts) <> 6 OR token_parts[1] <> 'v1' THEN
                    RETURN false;
                END IF;

                mode_value := token_parts[2];
                tenant_value := token_parts[3];
                nonce_value := token_parts[5];
                signature_value := token_parts[6];

                IF token_parts[4] !~ '^[0-9]{{1,12}}$'
                   OR nonce_value !~ '^[0-9a-f]{{32}}$'
                   OR signature_value !~ '^[0-9a-f]{{64}}$' THEN
                    RETURN false;
                END IF;

                expiry_value := token_parts[4]::bigint;
                IF expiry_value <= now_epoch OR expiry_value > now_epoch + 300 THEN
                    RETURN false;
                END IF;

                IF mode_value = 'operator' THEN
                    IF tenant_value <> '-' THEN
                        RETURN false;
                    END IF;
                ELSIF mode_value = 'tenant' THEN
                    IF tenant_value !~
                       '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$' THEN
                        RETURN false;
                    END IF;
                ELSE
                    RETURN false;
                END IF;

                SELECT key_material
                INTO signing_key
                FROM cp_security.rls_signing_key
                WHERE singleton;
                IF NOT FOUND THEN
                    RETURN false;
                END IF;

                payload_value := token_parts[1] || '|' || token_parts[2] || '|' ||
                    token_parts[3] || '|' || token_parts[4] || '|' || token_parts[5];
                expected_signature := encode(
                    {pgcrypto_schema}.hmac(
                        convert_to(payload_value, 'UTF8'), signing_key, 'sha256'
                    ),
                    'hex'
                );
                IF {pgcrypto_schema}.digest(convert_to(signature_value, 'UTF8'), 'sha256') <>
                   {pgcrypto_schema}.digest(convert_to(expected_signature, 'UTF8'), 'sha256') THEN
                    RETURN false;
                END IF;

                IF mode_value = 'operator' THEN
                    RETURN true;
                END IF;
                RETURN row_tenant IS NOT NULL AND row_tenant = tenant_value::uuid;
            EXCEPTION
                WHEN others THEN
                    RETURN false;
            END
            $function$
            """
        )
        cursor.execute(
            "REVOKE ALL ON FUNCTION cp_security.rls_context_allows(uuid) FROM PUBLIC"
        )
        cursor.execute(
            "GRANT EXECUTE ON FUNCTION cp_security.rls_context_allows(uuid) TO PUBLIC"
        )

        for table, tenant_column in SCOPED_TABLES.items():
            quoted_table = schema_editor.quote_name(table)
            quoted_column = schema_editor.quote_name(tenant_column)
            compatibility_expression = (
                "cp_security.rls_context_allows({tenant_column}) OR "
                "({legacy_expression})"
            ).format(
                tenant_column=quoted_column,
                legacy_expression=LEGACY_CONTEXT_ALLOWS.format(
                    tenant_column=quoted_column
                ),
            )
            cursor.execute(f"DROP POLICY IF EXISTS {POLICY_NAME} ON {quoted_table}")
            cursor.execute(
                f"""
                CREATE POLICY {POLICY_NAME} ON {quoted_table}
                FOR ALL
                USING ({compatibility_expression})
                WITH CHECK ({compatibility_expression})
                """
            )
            cursor.execute(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY")


def refuse_insecure_reverse(apps, schema_editor):
    raise IrreversibleError("signed RLS contexts cannot be downgraded to trusted GUCs")


class Migration(migrations.Migration):
    dependencies = [("core", "0002_enable_rls")]

    operations = [
        migrations.RunPython(
            install_signed_context_policy,
            reverse_code=refuse_insecure_reverse,
        )
    ]
