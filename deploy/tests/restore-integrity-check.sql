\set ON_ERROR_STOP on

SELECT
    (EXISTS (
        SELECT 1 FROM django_migrations
        WHERE app = 'core' AND name = '0004_signed_only_rls_context'
    ))::text || '|' ||
    ((SELECT count(*) FROM auth_user WHERE username = 'cpadmin' AND is_superuser) = 1)::text || '|' ||
    ((
        SELECT count(*) = 10
           AND count(DISTINCT c.relname) = 7
           AND bool_and(COALESCE(
               p.polpermissive
               AND p.polroles = ARRAY[0]::oid[]
               AND c.relrowsecurity
               AND (
                   (c.relname IN (
                        'core_configurationversion',
                        'core_auditevent'
                    ) AND p.polname = 'tenant_context_isolation'
                      AND p.polcmd = '*'
                      AND regexp_replace(
                          pg_get_expr(p.polqual, p.polrelid),
                          '[[:space:]]+', '', 'g'
                      ) = 'cp_security.rls_context_allows(tenant_context_id)'
                      AND regexp_replace(
                          pg_get_expr(p.polwithcheck, p.polrelid),
                          '[[:space:]]+', '', 'g'
                      ) = 'cp_security.rls_context_allows(tenant_context_id)') OR
                   (c.relname = 'core_tenantcontext'
                    AND p.polname = 'tenant_context_isolation'
                    AND p.polcmd = 'r'
                    AND regexp_replace(
                        pg_get_expr(p.polqual, p.polrelid),
                        '[[:space:]]+', '', 'g'
                    ) = 'cp_security.rls_context_allows(id)'
                    AND p.polwithcheck IS NULL) OR
                   (c.relname IN (
                        'core_tenantcontext',
                        'core_customeraccount',
                        'core_m365tenant',
                        'core_edgecluster',
                        'core_edgenode'
                    ) AND p.polname = 'operator_context_only'
                      AND p.polcmd = '*'
                      AND regexp_replace(
                          pg_get_expr(p.polqual, p.polrelid),
                          '[[:space:]]+', '', 'g'
                      ) = 'cp_security.rls_context_allows(NULL::uuid)'
                      AND regexp_replace(
                          pg_get_expr(p.polwithcheck, p.polrelid),
                          '[[:space:]]+', '', 'g'
                      ) = 'cp_security.rls_context_allows(NULL::uuid)') OR
                   (c.relname = 'core_customeraccount'
                    AND p.polname = 'tenant_metadata_read'
                    AND p.polcmd = 'r'
                    AND regexp_replace(
                        pg_get_expr(p.polqual, p.polrelid),
                        '[[:space:]]+', '', 'g'
                    ) = '(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE((tenant_context.customer_account_id=core_customeraccount.id)ANDcp_security.rls_context_allows(tenant_context.id))))'
                    AND p.polwithcheck IS NULL) OR
                   (c.relname = 'core_m365tenant'
                    AND p.polname = 'tenant_metadata_read'
                    AND p.polcmd = 'r'
                    AND regexp_replace(
                        pg_get_expr(p.polqual, p.polrelid),
                        '[[:space:]]+', '', 'g'
                    ) = '(EXISTS(SELECT1FROMcore_tenantcontexttenant_contextWHERE((tenant_context.m365_tenant_id=core_m365tenant.id)ANDcp_security.rls_context_allows(tenant_context.id))))'
                    AND p.polwithcheck IS NULL)
               ),
               false
           ))
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_policy p ON p.polrelid = c.oid
        WHERE n.nspname = 'public'
          AND c.relname IN (
              'core_tenantcontext',
              'core_configurationversion',
              'core_auditevent',
              'core_customeraccount',
              'core_m365tenant',
              'core_edgecluster',
              'core_edgenode'
          )
    ))::text || '|' ||
    (EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.oid = to_regprocedure('cp_security.rls_context_allows(uuid)')
          AND n.nspname = 'cp_security'
          AND pg_get_userbyid(p.proowner) = :'owner_role'
          AND p.prosecdef
          AND COALESCE(p.proconfig, ARRAY[]::text[]) @>
              ARRAY['search_path=pg_catalog, pg_temp']::text[]
    ))::text || '|' ||
    ((SELECT count(*) FROM cp_security.rls_signing_key) = 1)::text || '|' ||
    ((
        NOT has_table_privilege(
            :'runtime_role', 'cp_security.rls_signing_key',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_attribute attribute
            CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
            WHERE attribute.attrelid = 'cp_security.rls_signing_key'::regclass
              AND attribute.attacl IS NOT NULL
              AND privilege.grantee = (
                  SELECT oid FROM pg_roles WHERE rolname = :'runtime_role'
              )
        )
    ))::text || '|' ||
    (EXISTS (
        SELECT 1
        FROM pg_database database
        WHERE database.datname = current_database()
          AND pg_get_userbyid(database.datdba) = :'owner_role'
    ) AND EXISTS (
        SELECT 1
        FROM pg_namespace namespace
        WHERE namespace.nspname = 'cp_security'
          AND pg_get_userbyid(namespace.nspowner) = :'owner_role'
    ) AND EXISTS (
        SELECT 1
        FROM pg_namespace namespace
        WHERE namespace.nspname = 'public'
          AND pg_get_userbyid(namespace.nspowner) IN (
              :'owner_role', 'pg_database_owner'
          )
    ))::text || '|' ||
    (NOT EXISTS (
        SELECT 1
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname IN ('public', 'cp_security')
          AND pg_get_userbyid(relation.relowner) <> :'owner_role'
    ))::text || '|' ||
    ((
        has_database_privilege(:'runtime_role', current_database(), 'CONNECT')
        AND NOT has_database_privilege(:'runtime_role', current_database(), 'CREATE')
        AND NOT has_database_privilege(:'runtime_role', current_database(), 'TEMPORARY')
        AND has_schema_privilege(:'runtime_role', 'public', 'USAGE')
        AND NOT has_schema_privilege(:'runtime_role', 'public', 'CREATE')
        AND NOT EXISTS (
            SELECT 1
            FROM pg_database database
            CROSS JOIN LATERAL aclexplode(
                COALESCE(database.datacl, acldefault('d', database.datdba))
            ) privilege
            WHERE database.datname = current_database()
              AND privilege.grantee = 0
        )
    ))::text;
