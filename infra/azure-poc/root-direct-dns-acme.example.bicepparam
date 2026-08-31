using './root-direct-dns-acme.bicep'

// Populate only from the reviewed generation-3 replacement plan and live CP1
// identity. Documentation addresses and nil principals make this example
// deliberately non-deployable.
param carrierPublicIpv4 = '192.0.2.9'
param sbc1PublicIpv4 = '192.0.2.10'
param sbc2PublicIpv4 = '192.0.2.11'
param cp1PrincipalId = '00000000-0000-0000-0000-000000000000'
param sbc1PrincipalId = '00000000-0000-0000-0000-000000000001'
param sbc2PrincipalId = '00000000-0000-0000-0000-000000000002'
