\set ON_ERROR_STOP on
\getenv rls_signing_key RLS_CONTEXT_SIGNING_KEY
\if :{?rls_signing_key}
\else
SELECT 1 / 0;
\endif
SELECT (:'rls_signing_key' ~ '^[0-9a-f]{64}$')::int AS rls_key_valid \gset
\if :rls_key_valid
\else
SELECT 1 / 0;
\endif

BEGIN;

-- No context is fail-closed.
SET LOCAL app.rls_context = '';
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);
SELECT
    (SELECT count(*) FROM core_customeraccount) || '|' ||
    (SELECT count(*) FROM core_m365tenant) || '|' ||
    (SELECT count(*) FROM core_edgecluster) || '|' ||
    (SELECT count(*) FROM core_edgenode);

-- The legacy caller-controlled settings no longer grant either tenant or operator rights.
SET LOCAL app.is_operator = 'true';
SET LOCAL app.tenant_context_id = '00000000-0000-4000-8000-0000000000a1';
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

-- A syntactically valid but forged operator token is denied.
SELECT set_config(
    'app.rls_context',
    'v1|operator|-|' || (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
        '|11111111111111111111111111111111|' || repeat('0', 64),
    true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

-- A syntactically valid but forged tenant token is also denied.
SELECT set_config(
    'app.rls_context',
    'v1|tenant|00000000-0000-4000-8000-0000000000a1|' ||
        (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
        '|22222222222222222222222222222222|' || repeat('0', 64),
    true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

-- Build a valid, short-lived tenant-A token using the application-held qualification key.
SELECT
    'v1|tenant|00000000-0000-4000-8000-0000000000a1|' ||
    (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
    '|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AS rls_payload \gset
SELECT encode(
    public.hmac(convert_to(:'rls_payload', 'UTF8'), decode(:'rls_signing_key', 'hex'), 'sha256'),
    'hex'
) AS rls_signature \gset
SELECT set_config(
    'app.rls_context', :'rls_payload' || '|' || :'rls_signature', true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000a1') || '|' ||
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000b1') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000a4') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000b4') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000a5') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000b5');
SELECT
    (SELECT count(*) FROM core_customeraccount) || '|' ||
    (SELECT count(*) FROM core_m365tenant) || '|' ||
    (SELECT count(*) FROM core_edgecluster) || '|' ||
    (SELECT count(*) FROM core_edgenode);
-- Tenant-linked customer/M365 metadata remains readable for ORM joins, while
-- the operator-only DML policy keeps those same rows non-writable.
WITH updated AS (
    UPDATE core_customeraccount
    SET status = 'SUSPENDED'
    WHERE id = '00000000-0000-4000-8000-0000000000a0'
    RETURNING 1
)
SELECT count(*) FROM updated;
WITH updated AS (
    UPDATE core_tenantcontext
    SET customer_account_id = '00000000-0000-4000-8000-0000000000b0',
        m365_tenant_id = '00000000-0000-4000-8000-0000000000b2',
        status = 'SUSPENDED'
    WHERE id = '00000000-0000-4000-8000-0000000000a1'
    RETURNING 1
)
SELECT count(*) FROM updated;

-- Same-tenant UPDATE succeeds; cross-tenant UPDATE is invisible and affects zero rows.
WITH updated AS (
    UPDATE core_configurationversion
    SET state = 'VALIDATED'
    WHERE id = '00000000-0000-4000-8000-0000000000a4'
    RETURNING 1
)
SELECT count(*) FROM updated;
WITH updated AS (
    UPDATE core_configurationversion
    SET state = 'VALIDATED'
    WHERE id = '00000000-0000-4000-8000-0000000000b4'
    RETURNING 1
)
SELECT count(*) FROM updated;

-- Cross-tenant INSERT must fail its WITH CHECK expression with SQLSTATE 42501.
DO $block$
BEGIN
    BEGIN
        INSERT INTO core_configurationversion
            (id, created_at, updated_at, version, state, artifact_digest, published_at,
             created_by_id, tenant_context_id)
        VALUES
            ('00000000-0000-4000-8000-0000000000b7', now(), now(), 2, 'DRAFT', '', NULL,
             NULL, '00000000-0000-4000-8000-0000000000b1');
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'cross-tenant insert was accepted';
    EXCEPTION
        WHEN insufficient_privilege THEN NULL;
    END;
END
$block$;

-- Tenant B receives the mirror-image view.
SELECT
    'v1|tenant|00000000-0000-4000-8000-0000000000b1|' ||
    (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
    '|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' AS rls_payload \gset
SELECT encode(
    public.hmac(convert_to(:'rls_payload', 'UTF8'), decode(:'rls_signing_key', 'hex'), 'sha256'),
    'hex'
) AS rls_signature \gset
SELECT set_config(
    'app.rls_context', :'rls_payload' || '|' || :'rls_signature', true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000a1') || '|' ||
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000b1') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000a4') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000b4') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000a5') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000b5');

-- A valid operator token sees every scoped row.
SELECT
    'v1|operator|-|' || (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
    '|cccccccccccccccccccccccccccccccc' AS rls_payload \gset
SELECT encode(
    public.hmac(convert_to(:'rls_payload', 'UTF8'), decode(:'rls_signing_key', 'hex'), 'sha256'),
    'hex'
) AS rls_signature \gset
SELECT set_config(
    'app.rls_context', :'rls_payload' || '|' || :'rls_signature', true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);
SELECT
    (SELECT count(*) FROM core_customeraccount) || '|' ||
    (SELECT count(*) FROM core_m365tenant) || '|' ||
    (SELECT count(*) FROM core_edgecluster) || '|' ||
    (SELECT count(*) FROM core_edgenode);
WITH updated AS (
    UPDATE core_customeraccount
    SET status = 'SUSPENDED'
    WHERE id = '00000000-0000-4000-8000-0000000000a0'
    RETURNING 1
)
SELECT count(*) FROM updated;
WITH updated AS (
    UPDATE core_tenantcontext
    SET status = 'SUSPENDED'
    WHERE id = '00000000-0000-4000-8000-0000000000a1'
    RETURNING 1
)
SELECT count(*) FROM updated;

-- The runtime identity can invoke the validator through policies but has no
-- table- or column-level path to the signing key.
SELECT (
    has_table_privilege(
        current_user, 'cp_security.rls_signing_key', 'SELECT'
    ) OR EXISTS (
        SELECT 1
        FROM pg_attribute attribute
        CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
        WHERE attribute.attrelid = 'cp_security.rls_signing_key'::regclass
          AND attribute.attacl IS NOT NULL
          AND privilege.grantee = (
              SELECT oid FROM pg_roles WHERE rolname = current_user
          )
    )
)::int;

ROLLBACK;
