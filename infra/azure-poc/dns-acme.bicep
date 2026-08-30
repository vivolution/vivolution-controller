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

var edgeAcmeTxtRoleDefinitionGuid = 'c502c211-fd81-49aa-8ec3-45854ecd5e23'

resource edgeAcmeTxtRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: edgeAcmeTxtRoleDefinitionGuid
  properties: {
    roleName: 'Vivolution Edge ACME TXT Record Operator'
    description: 'Discover one assigned public DNS child zone and manage only its TXT record sets for ACME DNS-01.'
    type: 'CustomRole'
    permissions: [
      {
        actions: [
          'Microsoft.Network/dnszones/read'
          'Microsoft.Network/dnszones/TXT/read'
          'Microsoft.Network/dnszones/TXT/write'
          'Microsoft.Network/dnszones/TXT/delete'
          'Microsoft.ResourceGraph/resources/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

module dnsAcmeZone 'modules/dns-acme-zone.bicep' = {
  name: 'viv-sbc-poc-dns-acme-zone'
  scope: resourceGroup(dnsResourceGroupName)
  params: {
    cp1PublicIpv4: cp1PublicIpv4
    dnsZoneName: dnsZoneName
    edgeAcmeTxtRoleDefinitionId: edgeAcmeTxtRoleDefinition.id
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
output edgeAcmeTxtRoleDefinitionId string = edgeAcmeTxtRoleDefinition.id
