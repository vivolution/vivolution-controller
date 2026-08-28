\set ON_ERROR_STOP on
BEGIN;

INSERT INTO core_customeraccount
    (id, created_at, updated_at, name, slug, status)
VALUES
    ('00000000-0000-4000-8000-0000000000a0', now(), now(), 'RLS Qualification A', 'rls-qualification-a', 'ACTIVE'),
    ('00000000-0000-4000-8000-0000000000b0', now(), now(), 'RLS Qualification B', 'rls-qualification-b', 'ACTIVE');

INSERT INTO core_m365tenant
    (id, created_at, updated_at, entra_tenant_id, display_name, primary_domain, status, verified_at, customer_account_id)
VALUES
    (
        '00000000-0000-4000-8000-0000000000a2', now(), now(),
        '00000000-0000-4000-8000-0000000000a3', 'RLS Qualification A',
        'rls-a.invalid', 'VERIFIED', now(), '00000000-0000-4000-8000-0000000000a0'
    ),
    (
        '00000000-0000-4000-8000-0000000000b2', now(), now(),
        '00000000-0000-4000-8000-0000000000b3', 'RLS Qualification B',
        'rls-b.invalid', 'VERIFIED', now(), '00000000-0000-4000-8000-0000000000b0'
    );

INSERT INTO core_tenantcontext
    (id, created_at, updated_at, name, status, customer_account_id, m365_tenant_id)
VALUES
    (
        '00000000-0000-4000-8000-0000000000a1', now(), now(), 'RLS A', 'ACTIVE',
        '00000000-0000-4000-8000-0000000000a0', '00000000-0000-4000-8000-0000000000a2'
    ),
    (
        '00000000-0000-4000-8000-0000000000b1', now(), now(), 'RLS B', 'ACTIVE',
        '00000000-0000-4000-8000-0000000000b0', '00000000-0000-4000-8000-0000000000b2'
    );

INSERT INTO core_configurationversion
    (id, created_at, updated_at, version, state, artifact_digest, published_at, created_by_id, tenant_context_id)
VALUES
    (
        '00000000-0000-4000-8000-0000000000a4', now(), now(), 1, 'DRAFT', '', NULL, NULL,
        '00000000-0000-4000-8000-0000000000a1'
    ),
    (
        '00000000-0000-4000-8000-0000000000b4', now(), now(), 1, 'DRAFT', '', NULL, NULL,
        '00000000-0000-4000-8000-0000000000b1'
    );

INSERT INTO core_auditevent
    (id, action, target_type, target_id, request_id, detail, occurred_at, actor_id, tenant_context_id)
VALUES
    (
        '00000000-0000-4000-8000-0000000000a5', 'rls.verify', 'qualification', 'a',
        '00000000-0000-4000-8000-0000000000a6', '{}'::jsonb, now(), NULL,
        '00000000-0000-4000-8000-0000000000a1'
    ),
    (
        '00000000-0000-4000-8000-0000000000b5', 'rls.verify', 'qualification', 'b',
        '00000000-0000-4000-8000-0000000000b6', '{}'::jsonb, now(), NULL,
        '00000000-0000-4000-8000-0000000000b1'
    );

COMMIT;
