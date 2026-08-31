targetScope = 'resourceGroup'

@allowed([
  'a806949c-240f-4541-8c61-fd97f6d1f953'
])
@description('Exact Azure subscription containing the bounded POC. The guard also binds the signed-in tenant.')
param targetSubscriptionId string

@allowed([
  'rg-vivolution-sbc-poc-uaenorth'
])
@description('Exact existing POC resource group. This overlay never creates or deletes the group or its NSG.')
param targetResourceGroupName string

@allowed([
  'viv-sbc-poc-cp1-nsg'
])
@description('Exact existing CP1 NSG. The guard proves its six synthetic base rules before admitting this overlay.')
param existingCp1NetworkSecurityGroupName string

resource existingCp1NetworkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2023-11-01' existing = {
  name: existingCp1NetworkSecurityGroupName
}

resource allowGeneration3CarrierSignaling 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration3CarrierSignaling'
  properties: {
    description: 'POC generation-3 SBC mutual-TLS signaling to the exact private CP1 carrier listener.'
    access: 'Allow'
    direction: 'Inbound'
    priority: 320
    protocol: 'Tcp'
    sourceAddressPrefixes: [
      '10.20.2.6/32'
      '10.20.2.7/32'
    ]
    sourcePortRange: '*'
    destinationAddressPrefix: '10.20.1.4/32'
    destinationPortRange: '5061'
  }
}

resource allowGeneration3CarrierMedia 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration3CarrierMedia'
  properties: {
    description: 'POC generation-3 tenant RTP allocation to the exact private CP1 carrier media allocation.'
    access: 'Allow'
    direction: 'Inbound'
    priority: 330
    protocol: 'Udp'
    sourceAddressPrefixes: [
      '10.20.2.6/32'
      '10.20.2.7/32'
    ]
    sourcePortRange: '20000-20255'
    destinationAddressPrefix: '10.20.1.4/32'
    destinationPortRange: '30000-30127'
  }
}

output overlayContract object = {
  authority: {
    subscriptionId: targetSubscriptionId
    resourceGroupName: targetResourceGroupName
  }
  existingNetworkSecurityGroupId: existingCp1NetworkSecurityGroup.id
  rules: [
    {
      id: allowGeneration3CarrierSignaling.id
      name: allowGeneration3CarrierSignaling.name
      priority: 320
    }
    {
      id: allowGeneration3CarrierMedia.id
      name: allowGeneration3CarrierMedia.name
      priority: 330
    }
  ]
}
