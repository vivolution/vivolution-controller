\set ON_ERROR_STOP on

SELECT
    (EXISTS (
        SELECT 1 FROM django_migrations
        WHERE app = 'core' AND name = '0003_signed_rls_context'
    ))::text || '|' ||
    ((SELECT count(*) FROM auth_user WHERE username = 'cpadmin' AND is_superuser) = 1)::text || '|' ||
    (
        SELECT count(*)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_policy p ON p.polrelid = c.oid
        WHERE n.nspname = current_schema()
          AND c.relrowsecurity
          AND p.polname = 'tenant_context_isolation'
          AND c.relname IN (
              'core_tenantcontext',
              'core_configurationversion',
              'core_auditevent'
            )
    )::text || '|' ||
    (EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'cp_security'
          AND p.proname = 'rls_context_allows'
          AND p.prosecdef
    ))::text || '|' ||
    ((SELECT count(*) FROM cp_security.rls_signing_key) = 1)::text || '|' ||
    (NOT EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) acl
        WHERE n.nspname = 'cp_security'
          AND c.relname = 'rls_signing_key'
          AND acl.grantee = 0
          AND acl.privilege_type = 'SELECT'
    ))::text;
