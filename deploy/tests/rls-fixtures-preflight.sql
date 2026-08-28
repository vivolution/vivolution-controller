\set ON_ERROR_STOP on

SELECT
    (SELECT count(*) FROM core_auditevent WHERE id IN (
        '00000000-0000-4000-8000-0000000000a5',
        '00000000-0000-4000-8000-0000000000b5'
    )) +
    (SELECT count(*) FROM core_configurationversion WHERE id IN (
        '00000000-0000-4000-8000-0000000000a4',
        '00000000-0000-4000-8000-0000000000b4'
    )) +
    (SELECT count(*) FROM core_tenantcontext WHERE id IN (
        '00000000-0000-4000-8000-0000000000a1',
        '00000000-0000-4000-8000-0000000000b1'
    )) +
    (SELECT count(*) FROM core_m365tenant WHERE id IN (
        '00000000-0000-4000-8000-0000000000a2',
        '00000000-0000-4000-8000-0000000000b2'
    )) +
    (SELECT count(*) FROM core_customeraccount WHERE id IN (
        '00000000-0000-4000-8000-0000000000a0',
        '00000000-0000-4000-8000-0000000000b0'
    ));
