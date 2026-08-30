@description('Azure region for all network resources.')
param location string

@description('Name of the virtual network.')
param vnetName string

@description('Address space assigned to the virtual network.')
param vnetAddressPrefix string

@description('Name of the management subnet used by CP1.')
param managementSubnetName string

@description('Address prefix assigned to the management subnet.')
param managementSubnetPrefix string

@description('Name of the edge subnet used by SBC1 and SBC2.')
param edgeSubnetName string

@description('Address prefix assigned to the edge subnet.')
param edgeSubnetPrefix string

@description('Tags applied to the virtual network.')
param tags object

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: managementSubnetName
        properties: {
          addressPrefix: managementSubnetPrefix
          defaultOutboundAccess: false
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: edgeSubnetName
        properties: {
          addressPrefix: edgeSubnetPrefix
          defaultOutboundAccess: false
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}
