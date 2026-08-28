\set ON_ERROR_STOP on
BEGIN;

SET LOCAL app.is_operator = 'false';
SET LOCAL app.tenant_context_id = '';
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

SET LOCAL app.tenant_context_id = '00000000-0000-4000-8000-0000000000a1';
SELECT
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000a1') || '|' ||
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000b1') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000a4') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000b4') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000a5') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000b5');

SET LOCAL app.tenant_context_id = '00000000-0000-4000-8000-0000000000b1';
SELECT
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000a1') || '|' ||
    (SELECT count(*) FROM core_tenantcontext WHERE id = '00000000-0000-4000-8000-0000000000b1') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000a4') || '|' ||
    (SELECT count(*) FROM core_configurationversion WHERE id = '00000000-0000-4000-8000-0000000000b4') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000a5') || '|' ||
    (SELECT count(*) FROM core_auditevent WHERE id = '00000000-0000-4000-8000-0000000000b5');

SET LOCAL app.is_operator = 'true';
SET LOCAL app.tenant_context_id = '';
SELECT
    (SELECT count(*) FROM core_tenantcontext) || '|' ||
    (SELECT count(*) FROM core_configurationversion) || '|' ||
    (SELECT count(*) FROM core_auditevent);

ROLLBACK;
