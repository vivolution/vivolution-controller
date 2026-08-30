using './dns-acme.bicep'

// Populate these only from the exact outputs of the reviewed core POC
// deployment. The example is intentionally non-deployable.
param cp1PublicIpv4 = '192.0.2.9'
param sbc1PublicIpv4 = '192.0.2.10'
param sbc2PublicIpv4 = '192.0.2.11'
param sbc1PrincipalId = '00000000-0000-0000-0000-000000000000'
param sbc2PrincipalId = '00000000-0000-0000-0000-000000000001'
