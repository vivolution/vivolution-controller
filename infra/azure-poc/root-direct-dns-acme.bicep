targetScope = 'subscription'

@allowed([
  'DNS_Zones'
])
param dnsResourceGroupName string = 'DNS_Zones'

@allowed([
  'vivolution.ae'
])
param dnsZoneName string = 'vivolution.ae'

@description('Current static public IPv4 of the replacement CP1/carrier gateway.')
param carrierPublicIpv4 string

@description('Reviewed generation-3 static public IPv4 assigned to SBC1.')
param sbc1PublicIpv4 string

@description('Reviewed generation-3 static public IPv4 assigned to SBC2.')
param sbc2PublicIpv4 string

@description('System-assigned managed-identity principal ID of the replacement CP1.')
param cp1PrincipalId string

@description('System-assigned managed-identity principal ID of generation-3 SBC1.')
param sbc1PrincipalId string

@description('System-assigned managed-identity principal ID of generation-3 SBC2.')
param sbc2PrincipalId string

var directAcmeTxtRoleDefinitionGuid = 'c5498bfb-a31f-40dd-b636-0f53e530ed53'

resource directAcmeTxtRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: directAcmeTxtRoleDefinitionGuid
  properties: {
    roleName: 'Vivolution Direct POC ACME TXT Record Operator'
    description: 'Discover one assigned direct-routing public DNS child zone and manage only its TXT record sets for ACME DNS-01.'
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

module rootDirectDnsAcme 'modules/root-direct-dns-acme-zone.bicep' = {
  name: 'viv-sbc-poc-root-direct-dns-acme'
  scope: resourceGroup(dnsResourceGroupName)
  params: {
    carrierPublicIpv4: carrierPublicIpv4
    cp1PrincipalId: cp1PrincipalId
    directAcmeTxtRoleDefinitionId: directAcmeTxtRoleDefinition.id
    dnsZoneName: dnsZoneName
    sbc1PrincipalId: sbc1PrincipalId
    sbc1PublicIpv4: sbc1PublicIpv4
    sbc2PrincipalId: sbc2PrincipalId
    sbc2PublicIpv4: sbc2PublicIpv4
  }
}

output carrierFqdn string = rootDirectDnsAcme.outputs.carrierFqdn
output sbc1Fqdn string = rootDirectDnsAcme.outputs.sbc1Fqdn
output sbc2Fqdn string = rootDirectDnsAcme.outputs.sbc2Fqdn
output childZoneNames array = rootDirectDnsAcme.outputs.childZoneNames
output challengeFqdns array = rootDirectDnsAcme.outputs.challengeFqdns
output directAcmeTxtRoleDefinitionId string = directAcmeTxtRoleDefinition.id
