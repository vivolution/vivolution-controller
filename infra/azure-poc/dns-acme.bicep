targetScope = 'subscription'

@allowed([
  'DNS_Zones'
])
param dnsResourceGroupName string = 'DNS_Zones'

@allowed([
  'voice.vivolution.ae'
])
param dnsZoneName string = 'voice.vivolution.ae'

@description('Static public IPv4 assigned to the replacement CP1 by the core POC deployment.')
param cp1PublicIpv4 string

@description('Static public IPv4 assigned to SBC1 by the core POC deployment.')
param sbc1PublicIpv4 string

@description('Static public IPv4 assigned to SBC2 by the core POC deployment.')
param sbc2PublicIpv4 string

@description('System-assigned managed-identity principal ID of SBC1.')
param sbc1PrincipalId string

@description('System-assigned managed-identity principal ID of SBC2.')
param sbc2PrincipalId string

module dnsAcmeZone 'modules/dns-acme-zone.bicep' = {
  name: 'viv-sbc-poc-dns-acme-zone'
  scope: resourceGroup(dnsResourceGroupName)
  params: {
    cp1PublicIpv4: cp1PublicIpv4
    dnsZoneName: dnsZoneName
    sbc1PrincipalId: sbc1PrincipalId
    sbc1PublicIpv4: sbc1PublicIpv4
    sbc2PrincipalId: sbc2PrincipalId
    sbc2PublicIpv4: sbc2PublicIpv4
  }
}

output sbc1Fqdn string = dnsAcmeZone.outputs.sbc1Fqdn
output sbc2Fqdn string = dnsAcmeZone.outputs.sbc2Fqdn
output sbc1WildcardFqdn string = dnsAcmeZone.outputs.sbc1WildcardFqdn
output sbc2WildcardFqdn string = dnsAcmeZone.outputs.sbc2WildcardFqdn
output sbc1AcmeZoneName string = dnsAcmeZone.outputs.sbc1AcmeZoneName
output sbc2AcmeZoneName string = dnsAcmeZone.outputs.sbc2AcmeZoneName
output sbc1AcmeZoneScope string = dnsAcmeZone.outputs.sbc1AcmeZoneScope
output sbc2AcmeZoneScope string = dnsAcmeZone.outputs.sbc2AcmeZoneScope
output sbc1AcmeChallengeFqdn string = dnsAcmeZone.outputs.sbc1AcmeChallengeFqdn
output sbc2AcmeChallengeFqdn string = dnsAcmeZone.outputs.sbc2AcmeChallengeFqdn
output cp1StagingFqdn string = dnsAcmeZone.outputs.cp1StagingFqdn
