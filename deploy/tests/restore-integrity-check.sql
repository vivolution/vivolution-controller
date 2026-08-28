\set ON_ERROR_STOP on

SELECT
    ((SELECT count(*) FROM django_migrations) > 0)::text || '|' ||
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
    )::text;
