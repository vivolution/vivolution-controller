\set ON_ERROR_STOP on
\getenv rls_signing_key RLS_CONTEXT_SIGNING_KEY
SELECT (:'rls_signing_key' ~ '^[0-9a-f]{64}$')::int AS rls_key_valid \gset
\if :rls_key_valid
\else
SELECT 1 / 0;
\endif

BEGIN;

-- The N-1 controller's legacy operator scope remains usable during bridge rollout.
SET LOCAL app.rls_context = '';
SET LOCAL app.tenant_context_id = '';
SET LOCAL app.is_operator = 'true';
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

-- The N-1 controller's tenant scope also remains correctly isolated.
SET LOCAL app.is_operator = '';
SET LOCAL app.tenant_context_id = '00000000-0000-4000-8000-0000000000a1';
SELECT
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000a1') || '|' ||
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000b1');

-- The bridge controller's signed operator scope is accepted by the same policy.
SET LOCAL app.tenant_context_id = '';
SELECT
    'v1|operator|-|' || (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
    '|dddddddddddddddddddddddddddddddd' AS rls_payload \gset
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

-- With both legacy settings cleared, a forged signed token remains fail-closed.
SET LOCAL app.is_operator = '';
SET LOCAL app.tenant_context_id = '';
SELECT set_config(
    'app.rls_context',
    'v1|operator|-|' || (extract(epoch FROM clock_timestamp())::bigint + 60)::text ||
        '|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee|' || repeat('0', 64),
    true
) AS ignored \gset
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

ROLLBACK;
