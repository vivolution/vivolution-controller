targetScope = 'subscription'

@allowed([
  'a806949c-240f-4541-8c61-fd97f6d1f953'
])
@description('Exact Azure subscription that contains the bounded POC resource group.')
param targetSubscriptionId string

@allowed([
  'rg-vivolution-sbc-poc-uaenorth'
])
@description('Existing POC resource group. This template never creates or deletes it.')
param targetResourceGroupName string

@allowed([
  'uaenorth'
])
@description('Azure region. The replacement POC is intentionally restricted to UAE North.')
param location string

@allowed([
  'viv-sbc-poc-vnet'
])
@description('Existing POC virtual network referenced without modification.')
param existingVirtualNetworkName string

@allowed([
  'snet-edge'
])
@description('Existing Edge subnet referenced without modification.')
param existingEdgeSubnetName string

@allowed([
  'viv-sbc-poc-edge-as'
])
@description('Existing Edge availability set referenced without modification.')
param existingAvailabilitySetName string

@allowed([
  'DIRECT_ROUTING_PRIVATE_PBX_POC'
])
@description('Replacement nodes are permanently bound to the bounded private-PBX Direct Routing POC profile; production Direct Routing remains global-PBX only.')
param edgeRuntimeProfile string

@allowed([
  3
])
@description('Replacement Edge generation. Generation 2 synthetic nodes remain untouched.')
param edgeGeneration int

@description('Immutable UTC deadline for the bounded parallel acceptance window. The guarded wrapper rejects expiry or extension after any replacement resource exists.')
param parallelAcceptanceDeadlineUtc string

@allowed([
  'viv-sbc-dr-sbc1-g3'
])
@description('Distinct generation-3 replacement VM name for SBC1.')
param sbc1NodeName string

@allowed([
  'viv-sbc-dr-sbc2-g3'
])
@description('Distinct generation-3 replacement VM name for SBC2.')
param sbc2NodeName string

@allowed([
  '10.20.2.6'
])
@description('Unused fixed private address reserved for the SBC1 generation-3 replacement.')
param sbc1PrivateIpAddress string

@allowed([
  '10.20.2.7'
])
@description('Unused fixed private address reserved for the SBC2 generation-3 replacement.')
param sbc2PrivateIpAddress string

@allowed([
  '10.20.1.4/32'
])
@description('Exact existing CP1 private /32 used for control-plane HTTPS and the same-VNet carrier/fixture path. Public-IP hairpinning is forbidden.')
param cp1PrivatePrefix string

@minLength(1)
@description('Approved globally routable administrator IPv4 /32 prefixes. Preflight requires an exact separately supplied set.')
param administratorSourcePrefixes array

@description('Current Microsoft Direct Routing signaling IPv4 CIDRs. Preflight requires the reviewed exact set.')
param microsoftSignalingSourcePrefixes array

@description('Current Microsoft Direct Routing media IPv4 CIDRs. Preflight requires the reviewed exact set.')
param microsoftMediaSourcePrefixes array

@allowed([
  '3478-3481'
])
@description('Microsoft Media Processor ICE/STUN UDP source and destination port range.')
param microsoftMediaIcePortRange string

@allowed([
  '49152-53247'
])
@description('Microsoft Media Processor high UDP source and destination port range.')
param microsoftMediaHighPortRange string

@allowed([
  5061
])
@description('Microsoft and carrier-gateway remote mutual-TLS destination port.')
param remoteTlsPort int

@allowed([
  15061
])
@description('First-tenant local PBX mutual-TLS listener on each Edge.')
param localPbxTlsListenerPort int

@allowed([
  30000
])
@description('First UDP port advertised by the CP1 carrier gateway.')
param pbxMediaDestinationPortStart int

@allowed([
  30127
])
@description('Last UDP port advertised by the CP1 carrier gateway.')
param pbxMediaDestinationPortEnd int

@allowed([
  20000
])
@description('First local UDP port in the Edge RTPengine cluster pool.')
param rtpMediaPortStart int

@allowed([
  10000
])
@description('Number of local UDP ports in the Edge RTPengine cluster pool.')
param rtpMediaPortCount int

@allowed([
  20000
])
@description('First local UDP port in the Vivolution first-tenant allocation.')
param tenantRtpMediaPortStart int

@allowed([
  256
])
@description('Number of local UDP ports in the Vivolution first-tenant allocation.')
param tenantRtpMediaPortCount int

@allowed([
  'Standard_B2als_v2'
])
@description('Fixed low-cost two-vCPU VM size for both generation-3 replacements.')
param vmSize string

@allowed([
  32
])
@description('Fixed managed OS disk size in GiB for both replacement nodes.')
param osDiskSizeGiB int

@allowed([
  'StandardSSD_LRS'
])
@description('Fixed cost-controlled managed OS disk SKU.')
param osDiskSku string

@allowed([
  true
])
@description('Trusted Launch, Secure Boot, and vTPM are mandatory.')
param enableTrustedLaunch bool

@allowed([
  'cpadmin'
])
@description('Fixed Linux administrator account.')
param adminUsername string

@secure()
@description('Approved ED25519 public key. Password authentication remains disabled.')
param sshPublicKey string

@allowed([
  'Debian'
])
@description('Pinned Debian marketplace image publisher.')
param imagePublisher string

@allowed([
  'debian-13'
])
@description('Pinned Debian marketplace image offer.')
param imageOffer string

@allowed([
  '13-gen2'
])
@description('Pinned Debian marketplace image SKU used with Trusted Launch.')
param imageSku string

@allowed([
  '0.20260826.2582'
])
@description('Exact Debian 13 image version already qualified by this POC.')
param imageVersion string

var targetResourceGroup = resourceGroup(targetSubscriptionId, targetResourceGroupName)

resource existingVnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  scope: targetResourceGroup
  name: existingVirtualNetworkName
}

resource existingEdgeSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' existing = {
  parent: existingVnet
  name: existingEdgeSubnetName
}

resource existingEdgeAvailabilitySet 'Microsoft.Compute/availabilitySets@2024-03-01' existing = {
  scope: targetResourceGroup
  name: existingAvailabilitySetName
}

var edgeSubnetPrefix = '10.20.2.0/24'
var azureWireServerIpv4 = '168.63.129.16'
var azureImdsIpv4 = '169.254.169.254'
var fixedNtpServerPrefixes = [
  '162.159.200.1/32'
  '162.159.200.123/32'
]
var microsoftMediaProcessorPortRanges = [
  microsoftMediaIcePortRange
  microsoftMediaHighPortRange
]
var rtpMediaPortEnd = rtpMediaPortStart + rtpMediaPortCount - 1
var rtpMediaDestinationRange = '${rtpMediaPortStart}-${rtpMediaPortEnd}'
var tenantRtpMediaPortEnd = tenantRtpMediaPortStart + tenantRtpMediaPortCount - 1
var tenantRtpMediaDestinationRange = '${tenantRtpMediaPortStart}-${tenantRtpMediaPortEnd}'
var pbxMediaDestinationRange = '${pbxMediaDestinationPortStart}-${pbxMediaDestinationPortEnd}'

var commonTags = {
  workload: 'vivolution-sbc'
  environment: 'poc'
  region: location
  managedBy: 'bicep'
  owner: 'Vivolution Technologies LLC'
  purpose: 'Direct Routing generation-3 replacement Edge'
  costProfile: 'monthly-credit-lab'
  edgeRuntimeProfile: edgeRuntimeProfile
  edgeGeneration: string(edgeGeneration)
  replacementMode: 'parallel-preserve-generation-2'
  parallelAcceptanceWindowHours: '72'
  parallelAcceptanceDeadlineUtc: parallelAcceptanceDeadlineUtc
  predecessorDisposition: 'deallocate-after-final-acceptance'
}

var inboundSecurityRules = [
  {
    name: 'AllowAdminSsh'
    properties: {
      description: 'SSH from the separately approved administrator public IPv4 /32 set only.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 100
      protocol: 'Tcp'
      sourceAddressPrefixes: administratorSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '22'
    }
  }
  {
    name: 'AllowMicrosoftTls5061'
    properties: {
      description: 'Microsoft Direct Routing mutual-TLS signaling from the reviewed current IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 200
      protocol: 'Tcp'
      sourceAddressPrefixes: microsoftSignalingSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(remoteTlsPort)
    }
  }
  {
    name: 'AllowMicrosoftMedia'
    properties: {
      description: 'Microsoft Media Processor UDP from its documented source ports to the bounded local RTPengine pool.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 210
      protocol: 'Udp'
      sourceAddressPrefixes: microsoftMediaSourcePrefixes
      sourcePortRanges: microsoftMediaProcessorPortRanges
      destinationAddressPrefix: edgeSubnetPrefix
      destinationPortRange: rtpMediaDestinationRange
    }
  }
  {
    name: 'AllowCarrierGatewayTls15061'
    properties: {
      description: 'CP1 carrier-gateway mutual-TLS signaling to the isolated local PBX listener.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 300
      protocol: 'Tcp'
      sourceAddressPrefix: cp1PrivatePrefix
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(localPbxTlsListenerPort)
    }
  }
  {
    name: 'AllowCarrierGatewayMediaInbound'
    properties: {
      description: 'CP1 carrier-gateway media from its exact advertised range to the first-tenant Edge allocation.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 310
      protocol: 'Udp'
      sourceAddressPrefix: cp1PrivatePrefix
      sourcePortRange: pbxMediaDestinationRange
      destinationAddressPrefix: '*'
      destinationPortRange: tenantRtpMediaDestinationRange
    }
  }
  {
    name: 'DenyAllInbound'
    properties: {
      description: 'Explicitly deny every other inbound flow before Azure default rules.'
      access: 'Deny'
      direction: 'Inbound'
      priority: 4096
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]

var outboundSecurityRules = [
  {
    name: 'AllowAzureDhcpOutbound'
    properties: {
      description: 'Azure DHCP renewal from the guest client port to WireServer DHCP only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1000
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '68'
      destinationAddressPrefix: azureWireServerIpv4
      destinationPortRange: '67'
    }
  }
  {
    name: 'AllowAzureDnsUdpOutbound'
    properties: {
      description: 'Unicast UDP DNS to Azure platform DNS only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1010
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: azureWireServerIpv4
      destinationPortRange: '53'
    }
  }
  {
    name: 'AllowAzureDnsTcpOutbound'
    properties: {
      description: 'Unicast TCP DNS fallback to Azure platform DNS only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1020
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: azureWireServerIpv4
      destinationPortRange: '53'
    }
  }
  {
    name: 'AllowAzureWireServerOutbound'
    properties: {
      description: 'Azure Linux Agent WireServer channels only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1030
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: azureWireServerIpv4
      destinationPortRanges: [
        '80'
        '32526'
      ]
    }
  }
  {
    name: 'AllowAzureImdsOutbound'
    properties: {
      description: 'Managed-identity and instance metadata requests to IMDS only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1040
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: azureImdsIpv4
      destinationPortRange: '80'
    }
  }
  {
    name: 'AllowNtpOutbound'
    properties: {
      description: 'NTP to the two fixed anycast time sources configured by the Edge role.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1050
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefixes: fixedNtpServerPrefixes
      destinationPortRange: '123'
    }
  }
  {
    name: 'AllowWebOutbound'
    properties: {
      description: 'HTTP and HTTPS for Debian APT, pinned package retrieval, ACME, and Azure DNS APIs.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1060
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: 'Internet'
      destinationPortRanges: [
        '80'
        '443'
      ]
    }
  }
  {
    name: 'AllowControlPlaneOutbound'
    properties: {
      description: 'Private HTTPS to the fixed CP1 control-plane address only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1070
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: cp1PrivatePrefix
      destinationPortRange: '443'
    }
  }
  {
    name: 'AllowMicrosoftSignalingOutbound'
    properties: {
      description: 'Mutual-TLS signaling to the reviewed current Microsoft Direct Routing IPv4 CIDRs only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1100
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefixes: microsoftSignalingSourcePrefixes
      destinationPortRange: string(remoteTlsPort)
    }
  }
  {
    name: 'AllowMicrosoftMediaOutbound'
    properties: {
      description: 'First-tenant RTPengine UDP to documented Microsoft Media Processor ports and IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1110
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: tenantRtpMediaDestinationRange
      destinationAddressPrefixes: microsoftMediaSourcePrefixes
      destinationPortRanges: microsoftMediaProcessorPortRanges
    }
  }
  {
    name: 'AllowCarrierGatewayTls5061'
    properties: {
      description: 'Mutual-TLS signaling over the existing VNet to the exact CP1 private /32 and remote listener only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1120
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: cp1PrivatePrefix
      destinationPortRange: string(remoteTlsPort)
    }
  }
  {
    name: 'AllowCarrierGatewayMediaOutbound'
    properties: {
      description: 'First-tenant RTPengine allocation over the existing VNet to the exact CP1 private /32 and media range only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1130
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: tenantRtpMediaDestinationRange
      destinationAddressPrefix: cp1PrivatePrefix
      destinationPortRange: pbxMediaDestinationRange
    }
  }
  {
    name: 'DenyAllOutbound'
    properties: {
      description: 'Explicitly deny every other outbound flow before Azure default rules.'
      access: 'Deny'
      direction: 'Outbound'
      priority: 4096
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]

var edgeSecurityRules = concat(inboundSecurityRules, outboundSecurityRules)

module sbc1 'modules/linux-node.bicep' = {
  scope: targetResourceGroup
  name: '${sbc1NodeName}-deployment'
  params: {
    location: location
    nodeName: sbc1NodeName
    subnetId: existingEdgeSubnet.id
    privateIpAddress: sbc1PrivateIpAddress
    vmSize: vmSize
    osDiskSizeGiB: osDiskSizeGiB
    osDiskSku: osDiskSku
    enableTrustedLaunch: enableTrustedLaunch
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    imagePublisher: imagePublisher
    imageOffer: imageOffer
    imageSku: imageSku
    imageVersion: imageVersion
    securityRules: edgeSecurityRules
    availabilitySetId: existingEdgeAvailabilitySet.id
    tags: union(commonTags, {
      nodeRole: 'session-border-controller'
      nodeName: 'sbc1'
    })
  }
}

module sbc2 'modules/linux-node.bicep' = {
  scope: targetResourceGroup
  name: '${sbc2NodeName}-deployment'
  params: {
    location: location
    nodeName: sbc2NodeName
    subnetId: existingEdgeSubnet.id
    privateIpAddress: sbc2PrivateIpAddress
    vmSize: vmSize
    osDiskSizeGiB: osDiskSizeGiB
    osDiskSku: osDiskSku
    enableTrustedLaunch: enableTrustedLaunch
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    imagePublisher: imagePublisher
    imageOffer: imageOffer
    imageSku: imageSku
    imageVersion: imageVersion
    securityRules: edgeSecurityRules
    availabilitySetId: existingEdgeAvailabilitySet.id
    tags: union(commonTags, {
      nodeRole: 'session-border-controller'
      nodeName: 'sbc2'
    })
  }
}

output intendedResourceGroup object = {
  subscriptionId: targetSubscriptionId
  name: targetResourceGroupName
}

output preservedExistingResources object = {
  virtualNetwork: existingVnet.name
  edgeSubnet: existingEdgeSubnet.name
  edgeAvailabilitySet: existingEdgeAvailabilitySet.name
  syntheticSbcVmNames: [
    'viv-sbc-poc-sbc1'
    'viv-sbc-poc-sbc2'
  ]
}

output replacementResourceNames object = {
  sbc1: {
    vm: sbc1.outputs.deployedVmName
    nic: sbc1.outputs.deployedNicName
    nsg: sbc1.outputs.deployedNetworkSecurityGroupName
    publicIp: sbc1.outputs.deployedPublicIpName
  }
  sbc2: {
    vm: sbc2.outputs.deployedVmName
    nic: sbc2.outputs.deployedNicName
    nsg: sbc2.outputs.deployedNetworkSecurityGroupName
    publicIp: sbc2.outputs.deployedPublicIpName
  }
}

output replacementPublicIpAddresses object = {
  sbc1: sbc1.outputs.assignedPublicIpAddress
  sbc2: sbc2.outputs.assignedPublicIpAddress
}

output replacementPrivateIpAddresses object = {
  sbc1: sbc1.outputs.assignedPrivateIpAddress
  sbc2: sbc2.outputs.assignedPrivateIpAddress
}

output replacementIdentityPrincipalIds object = {
  sbc1: sbc1.outputs.identityPrincipalId
  sbc2: sbc2.outputs.identityPrincipalId
}

output directRoutingContract object = {
  runtimeProfile: edgeRuntimeProfile
  generation: edgeGeneration
  microsoftTlsPort: remoteTlsPort
  localPbxTlsListenerPort: localPbxTlsListenerPort
  carrierGatewayRemoteTlsPort: remoteTlsPort
  carrierGatewayPrivatePrefix: cp1PrivatePrefix
  carrierGatewayName: 'carrier.vivolution.ae'
  carrierGatewayPath: 'same-vnet-private-no-public-hairpin'
  carrierGatewayMediaDestinationRange: pbxMediaDestinationRange
  tenantRtpMediaRange: tenantRtpMediaDestinationRange
  rtpMediaPoolRange: rtpMediaDestinationRange
}

output boundedParallelCostContract object = {
  monthlyBudgetUsd: 100
  maximumParallelAcceptanceHours: 72
  parallelAcceptanceDeadlineUtc: parallelAcceptanceDeadlineUtc
  maximumIncrementalReplacementCostUsd: '7.80'
  syntheticPredecessorVmNames: [
    'viv-sbc-poc-sbc1'
    'viv-sbc-poc-sbc2'
  ]
  requiredDisposition: 'deallocate-after-final-acceptance-and-no-later-than-plan-deadline'
}
