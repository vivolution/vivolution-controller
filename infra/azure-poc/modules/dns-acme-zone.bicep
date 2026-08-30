targetScope = 'resourceGroup'

@allowed([
  'voice.vivolution.ae'
])
param dnsZoneName string

@description('Static public IPv4 assigned to the replacement CP1.')
param cp1PublicIpv4 string

@description('Static public IPv4 assigned to SBC1 by the core POC deployment.')
param sbc1PublicIpv4 string

@description('Static public IPv4 assigned to SBC2 by the core POC deployment.')
param sbc2PublicIpv4 string

@description('System-assigned managed-identity principal ID of SBC1.')
param sbc1PrincipalId string

@description('System-assigned managed-identity principal ID of SBC2.')
param sbc2PrincipalId string

@description('Subscription custom-role ID limited to child-zone discovery and TXT record-set lifecycle.')
param edgeAcmeTxtRoleDefinitionId string

var sbc1RecordName = 'sbc1'
var sbc2RecordName = 'sbc2'
var cp1StagingRecordName = 'cp1-poc'
var sbc1AcmeZoneName = 'acme-${sbc1RecordName}.${dnsZoneName}'
var sbc2AcmeZoneName = 'acme-${sbc2RecordName}.${dnsZoneName}'
var sbc1AcmeDelegationName = 'acme-${sbc1RecordName}'
var sbc2AcmeDelegationName = 'acme-${sbc2RecordName}'
var acmeRecordName = '_acme-challenge'
var acmeZoneTags = {
  workload: 'vivolution-sbc'
  environment: 'poc'
  managedBy: 'bicep'
  purpose: 'edge-acme-dns01'
}
resource dnsZone 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: dnsZoneName
}

// Lego deletes the entire TXT record set during challenge cleanup. Keep RBAC
// on a durable, node-isolated child zone rather than on that ephemeral record.
// The supplied custom role can discover this zone and mutate TXT record sets,
// but cannot update or delete the zone or touch any other record type.
resource sbc1AcmeZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: sbc1AcmeZoneName
  location: 'global'
  tags: acmeZoneTags
}

resource sbc2AcmeZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: sbc2AcmeZoneName
  location: 'global'
  tags: acmeZoneTags
}

resource cp1StagingA 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: dnsZone
  name: cp1StagingRecordName
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: cp1PublicIpv4
      }
    ]
  }
}

resource sbc1A 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: dnsZone
  name: sbc1RecordName
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
  parent: dnsZone
  name: sbc2RecordName
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: sbc2PublicIpv4
      }
    ]
  }
}

resource sbc1WildcardA 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: dnsZone
  name: '*.${sbc1RecordName}'
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: sbc1PublicIpv4
      }
    ]
  }
}

resource sbc2WildcardA 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: dnsZone
  name: '*.${sbc2RecordName}'
  properties: {
    TTL: 60
    ARecords: [
      {
        ipv4Address: sbc2PublicIpv4
      }
    ]
  }
}

resource sbc1AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01' = {
  parent: dnsZone
  name: sbc1AcmeDelegationName
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
  parent: dnsZone
  name: sbc2AcmeDelegationName
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

resource sbc1AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: dnsZone
  name: '${acmeRecordName}.${sbc1RecordName}'
  properties: {
    TTL: 60
    CNAMERecord: {
      cname: '${acmeRecordName}.${sbc1AcmeZoneName}.'
    }
  }
}

resource sbc2AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = {
  parent: dnsZone
  name: '${acmeRecordName}.${sbc2RecordName}'
  properties: {
    TTL: 60
    CNAMERecord: {
      cname: '${acmeRecordName}.${sbc2AcmeZoneName}.'
    }
  }
}

// A CanNotDelete lock on the zone is intentionally forbidden: Azure inherits
// it to record sets and would turn Lego cleanup into a non-fatal 409 warning.
resource sbc1AcmeTxtOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbc1AcmeZone.id, sbc1PrincipalId, edgeAcmeTxtRoleDefinitionId)
  scope: sbc1AcmeZone
  properties: {
    principalId: sbc1PrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: edgeAcmeTxtRoleDefinitionId
  }
}

resource sbc2AcmeTxtOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sbc2AcmeZone.id, sbc2PrincipalId, edgeAcmeTxtRoleDefinitionId)
  scope: sbc2AcmeZone
  properties: {
    principalId: sbc2PrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: edgeAcmeTxtRoleDefinitionId
  }
}

output sbc1Fqdn string = '${sbc1RecordName}.${dnsZoneName}'
output sbc2Fqdn string = '${sbc2RecordName}.${dnsZoneName}'
output sbc1WildcardFqdn string = '*.${sbc1RecordName}.${dnsZoneName}'
output sbc2WildcardFqdn string = '*.${sbc2RecordName}.${dnsZoneName}'
output sbc1AcmeZoneName string = sbc1AcmeZone.name
output sbc2AcmeZoneName string = sbc2AcmeZone.name
output sbc1AcmeZoneScope string = sbc1AcmeZone.id
output sbc2AcmeZoneScope string = sbc2AcmeZone.id
output sbc1AcmeChallengeFqdn string = '${acmeRecordName}.${sbc1AcmeZone.name}'
output sbc2AcmeChallengeFqdn string = '${acmeRecordName}.${sbc2AcmeZone.name}'
output cp1StagingFqdn string = '${cp1StagingRecordName}.${dnsZoneName}'
