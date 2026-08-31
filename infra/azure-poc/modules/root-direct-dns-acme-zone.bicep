targetScope = 'resourceGroup'

@allowed([
  'vivolution.ae'
])
param dnsZoneName string

param carrierPublicIpv4 string
param sbc1PublicIpv4 string
param sbc2PublicIpv4 string
param cp1PrincipalId string
param sbc1PrincipalId string
param sbc2PrincipalId string
param directAcmeTxtRoleDefinitionId string

var acmeZoneTags = {
  environment: 'poc'
  managedBy: 'bicep'
  profile: 'DIRECT_ROUTING_PRIVATE_PBX_POC'
  purpose: 'direct-routing-private-pbx-poc-acme-dns01'
  workload: 'vivolution-sbc'
}

resource rootZone 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: dnsZoneName
}

// These are three additive, node-isolated ACME boundaries. The existing
// voice.vivolution.ae zone and its delegated children are not referenced or
// mutated by this deployment.
resource sbc1AcmeZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: 'acme-sbc1.${dnsZoneName}'
  location: 'global'
  tags: acmeZoneTags
}

resource sbc2AcmeZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: 'acme-sbc2.${dnsZoneName}'
  location: 'global'
  tags: acmeZoneTags
}

resource carrierAcmeZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: 'acme-carrier.${dnsZoneName}'
  location: 'global'
  tags: acmeZoneTags
}

resource sbc1A 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: rootZone
  name: 'sbc1'
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: sbc1PublicIpv4
      }
    ]
  }
}

resource sbc2A 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: rootZone
  name: 'sbc2'
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: sbc2PublicIpv4
      }
    ]
  }
}

resource carrierA 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: rootZone
  name: 'carrier'
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: carrierPublicIpv4
      }
    ]
  }
}

resource sbc1AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01' = {
  parent: rootZone
  name: 'acme-sbc1'
  properties: {
    TTL: 3600
    NSRecords: [
      { nsdname: sbc1AcmeZone.properties.nameServers[0] }
      { nsdname: sbc1AcmeZone.properties.nameServers[1] }
      { nsdname: sbc1AcmeZone.properties.nameServers[2] }
      { nsdname: sbc1AcmeZone.properties.nameServers[3] }
    ]
  }
}

resource sbc2AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01' = {
  parent: rootZone
  name: 'acme-sbc2'
  properties: {
    TTL: 3600
    NSRecords: [
      { nsdname: sbc2AcmeZone.properties.nameServers[0] }
      { nsdname: sbc2AcmeZone.properties.nameServers[1] }
      { nsdname: sbc2AcmeZone.properties.nameServers[2] }
      { nsdname: sbc2AcmeZone.properties.nameServers[3] }
    ]
  }
}

resource carrierAcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01' = {
  parent: rootZone
  name: 'acme-carrier'
  properties: {
    TTL: 3600
    NSRecords: [
      { nsdname: carrierAcmeZone.properties.nameServers[0] }
      { nsdname: carrierAcmeZone.properties.nameServers[1] }
      { nsdname: carrierAcmeZone.properties.nameServers[2] }
      { nsdname: carrierAcmeZone.properties.nameServers[3] }
    ]
  }
}

resource sbc1ChallengeAlias 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: rootZone
  name: '_acme-challenge.sbc1'
  properties: {
    TTL: 60
    CNAMERecord: { cname: '_acme-challenge.acme-sbc1.${dnsZoneName}.' }
  }
}

resource sbc2ChallengeAlias 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: rootZone
  name: '_acme-challenge.sbc2'
  properties: {
    TTL: 60
    CNAMERecord: { cname: '_acme-challenge.acme-sbc2.${dnsZoneName}.' }
  }
}

resource carrierChallengeAlias 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: rootZone
  name: '_acme-challenge.carrier'
  properties: {
    TTL: 60
    CNAMERecord: { cname: '_acme-challenge.acme-carrier.${dnsZoneName}.' }
  }
}

// Lego deletes the challenge TXT record set after issuance. Authority is on
// the durable child zone and deliberately excludes zone writes/deletes and
// every non-TXT record type. No management lock is placed on a child zone,
// because an inherited CanNotDelete lock would also prevent TXT cleanup.
resource sbc1AcmeTxtOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbc1AcmeZone.id, sbc1PrincipalId, directAcmeTxtRoleDefinitionId)
  scope: sbc1AcmeZone
  properties: {
    principalId: sbc1PrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: directAcmeTxtRoleDefinitionId
  }
}

resource sbc2AcmeTxtOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbc2AcmeZone.id, sbc2PrincipalId, directAcmeTxtRoleDefinitionId)
  scope: sbc2AcmeZone
  properties: {
    principalId: sbc2PrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: directAcmeTxtRoleDefinitionId
  }
}

resource carrierAcmeTxtOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(carrierAcmeZone.id, cp1PrincipalId, directAcmeTxtRoleDefinitionId)
  scope: carrierAcmeZone
  properties: {
    principalId: cp1PrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: directAcmeTxtRoleDefinitionId
  }
}

output carrierFqdn string = 'carrier.${dnsZoneName}'
output sbc1Fqdn string = 'sbc1.${dnsZoneName}'
output sbc2Fqdn string = 'sbc2.${dnsZoneName}'
output childZoneNames array = [
  sbc1AcmeZone.name
  sbc2AcmeZone.name
  carrierAcmeZone.name
]
output challengeFqdns array = [
  '_acme-challenge.${sbc1AcmeZone.name}'
  '_acme-challenge.${sbc2AcmeZone.name}'
  '_acme-challenge.${carrierAcmeZone.name}'
]
