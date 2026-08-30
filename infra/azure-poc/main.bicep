targetScope = 'resourceGroup'

@allowed([
  'uaenorth'
])
@description('Azure region. This POC is intentionally restricted to UAE North.')
param location string = 'uaenorth'

@allowed([
  'viv-sbc-poc'
])
@description('Fixed lowercase naming prefix used for every POC resource.')
param namePrefix string = 'viv-sbc-poc'

@allowed([
  'poc'
])
@description('Fixed POC environment tag value.')
param environmentName string = 'poc'

@description('Additional resource tags. The workload, environment, region, and managedBy tags are enforced by this template.')
param tags object = {}

@minLength(1)
@description('Public IPv4 CIDRs allowed to SSH to CP1. Use /32 entries for individual administration addresses.')
param administratorSourcePrefixes array

@minLength(1)
@description('Current Microsoft Direct Routing signaling IPv4 CIDRs allowed to reach TCP 5061 on each SBC.')
param microsoftSignalingSourcePrefixes array

@minLength(1)
@description('Current Microsoft Direct Routing media IPv4 CIDRs allowed to reach the bounded UDP media range on each SBC.')
param microsoftMediaSourcePrefixes array

@allowed([
  '3478-3481'
])
@description('Fixed Microsoft Media Processor ICE/STUN UDP source/destination port range.')
param microsoftMediaIcePortRange string = '3478-3481'

@allowed([
  '49152-53247'
])
@description('Fixed Microsoft Media Processor high UDP source/destination port range.')
param microsoftMediaHighPortRange string = '49152-53247'

@allowed([
  'SYNTHETIC_PRIVATE'
  'DIRECT_ROUTING'
])
@description('Edge data-plane profile used to select mutually exclusive inbound and outbound signaling/media policies.')
param edgeRuntimeProfile string = 'SYNTHETIC_PRIVATE'

@description('Optional private IPv4 CIDRs for the isolated no-PSTN Teams-side simulator. Empty disables synthetic ingress.')
param syntheticTeamsSourcePrefixes array = []

@description('Enable CP1 fixture ingress only for SYNTHETIC_PRIVATE. DIRECT_ROUTING preflight requires false.')
param enableSyntheticVoiceFixture bool = true

@description('PBX peer IPv4 CIDRs allowed for SBC1 inbound and, in DIRECT_ROUTING, outbound TLS/media. Empty means no PBX path.')
param sbc1PbxSourcePrefixes array = []

@description('PBX peer IPv4 CIDRs allowed for SBC2 inbound and, in DIRECT_ROUTING, outbound TLS/media. Empty means no PBX path.')
param sbc2PbxSourcePrefixes array = []

@minValue(1024)
@maxValue(65534)
@description('First UDP source/destination port advertised by the SBC1 PBX peer. Must be even; preflight binds it to the signed/local Direct Routing contract or the fixed synthetic fixture range.')
param sbc1PbxMediaDestinationPortStart int

@minValue(1025)
@maxValue(65535)
@description('Last UDP source/destination port advertised by the SBC1 PBX peer. Must be odd and form a bounded range with the start.')
param sbc1PbxMediaDestinationPortEnd int

@minValue(1024)
@maxValue(65534)
@description('First UDP source/destination port advertised by the SBC2 PBX peer. Must be even; preflight binds it to the signed/local Direct Routing contract or the fixed synthetic fixture range.')
param sbc2PbxMediaDestinationPortStart int

@minValue(1025)
@maxValue(65535)
@description('Last UDP source/destination port advertised by the SBC2 PBX peer. Must be odd and form a bounded range with the start.')
param sbc2PbxMediaDestinationPortEnd int

@allowed([
  15061
])
@description('Fixed first-tenant PBX-side TLS listener port. It remains distinct from reserved host ports and the shared Microsoft listener on 5061.')
param pbxTlsListenerPort int = 15061

@allowed([
  'cpadmin'
])
@description('Fixed Linux administrator account provisioned on every VM.')
param adminUsername string = 'cpadmin'

@secure()
@description('SSH public key installed for the administrator on every VM. Password authentication is disabled.')
param sshPublicKey string

@allowed([
  '10.20.0.0/16'
])
@description('Fixed POC virtual network address space.')
param vnetAddressPrefix string = '10.20.0.0/16'

@allowed([
  '10.20.1.0/24'
])
@description('Fixed POC management subnet address prefix for CP1.')
param managementSubnetPrefix string = '10.20.1.0/24'

@allowed([
  '10.20.2.0/24'
])
@description('Fixed POC Edge subnet address prefix for SBC1 and SBC2.')
param edgeSubnetPrefix string = '10.20.2.0/24'

@allowed([
  '10.20.1.4'
])
@description('Fixed POC static private IPv4 address for CP1.')
param cp1PrivateIpAddress string = '10.20.1.4'

@allowed([
  '10.20.2.4'
])
@description('Fixed POC static private IPv4 address for SBC1.')
param sbc1PrivateIpAddress string = '10.20.2.4'

@allowed([
  '10.20.2.5'
])
@description('Fixed POC static private IPv4 address for SBC2.')
param sbc2PrivateIpAddress string = '10.20.2.5'

@allowed([
  'Standard_D2as_v5'
])
@description('Fixed initially qualified CP1 VM size. Resize only through a separately reviewed template revision and requalification.')
param cp1VmSize string = 'Standard_D2as_v5'

@allowed([
  'Standard_B2als_v2'
])
@description('Fixed low-cost two-vCPU SBC1 VM size qualified for this subscription and region.')
param sbc1VmSize string = 'Standard_B2als_v2'

@allowed([
  'Standard_B2als_v2'
])
@description('Fixed low-cost two-vCPU SBC2 VM size qualified for this subscription and region.')
param sbc2VmSize string = 'Standard_B2als_v2'

@allowed([
  64
])
@description('Fixed CP1 managed OS disk size in GiB.')
param cp1OsDiskSizeGiB int = 64

@allowed([
  32
])
@description('Fixed SBC1 managed OS disk size in GiB.')
param sbc1OsDiskSizeGiB int = 32

@allowed([
  32
])
@description('Fixed SBC2 managed OS disk size in GiB.')
param sbc2OsDiskSizeGiB int = 32

@allowed([
  'StandardSSD_LRS'
])
@description('Fixed cost-controlled managed OS disk SKU used by all three nodes.')
param osDiskSku string = 'StandardSSD_LRS'

@allowed([
  true
])
@description('Trusted Launch, Secure Boot, and vTPM are mandatory on all POC nodes.')
param enableTrustedLaunch bool = true

@allowed([
  20000
])
@description('First local UDP port in the fixed POC RTPengine cluster pool. Both Teams and the approved PBX use tenant allocations inside this pool.')
param rtpMediaPortStart int = 20000

@allowed([
  10000
])
@description('Number of local UDP ports in the fixed POC RTPengine cluster pool.')
param rtpMediaPortCount int = 10000

@allowed([
  20000
])
@description('First local UDP port in the fixed first-tenant RTP allocation used by the private fixture and PBX paths.')
param tenantRtpMediaPortStart int = 20000

@allowed([
  256
])
@description('Number of local UDP ports in the fixed first-tenant RTP allocation.')
param tenantRtpMediaPortCount int = 256

@allowed([
  '0.20260826.2582'
])
@description('Fixed Debian marketplace image version qualified by the existing CP1 Azure profile.')
param debianImageVersion string = '0.20260826.2582'

var vnetName = '${namePrefix}-vnet'
var managementSubnetName = 'snet-management'
var edgeSubnetName = 'snet-edge'
var managementSubnetId = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, managementSubnetName)
var edgeSubnetId = resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, edgeSubnetName)

var cp1Name = '${namePrefix}-cp1'
var sbc1Name = '${namePrefix}-sbc1'
var sbc2Name = '${namePrefix}-sbc2'

var rtpMediaPortEnd = rtpMediaPortStart + rtpMediaPortCount - 1
var rtpMediaDestinationRange = '${rtpMediaPortStart}-${rtpMediaPortEnd}'
var tenantRtpMediaPortEnd = tenantRtpMediaPortStart + tenantRtpMediaPortCount - 1
var tenantRtpMediaDestinationRange = '${tenantRtpMediaPortStart}-${tenantRtpMediaPortEnd}'
var sbc1PbxMediaDestinationRange = '${sbc1PbxMediaDestinationPortStart}-${sbc1PbxMediaDestinationPortEnd}'
var sbc2PbxMediaDestinationRange = '${sbc2PbxMediaDestinationPortStart}-${sbc2PbxMediaDestinationPortEnd}'
var microsoftMediaProcessorPortRanges = [
  microsoftMediaIcePortRange
  microsoftMediaHighPortRange
]
var azureWireServerIpv4 = '168.63.129.16'
var azureImdsIpv4 = '169.254.169.254'
var fixedNtpServerPrefixes = [
  '162.159.200.1/32'
  '162.159.200.123/32'
]
var syntheticFixtureSignalingDestinationPorts = [
  '16061'
  '25061'
]
var syntheticFixtureMediaDestinationPorts = [
  '21000-21127'
  '22000-22063'
]

var commonTags = union(tags, {
  workload: 'vivolution-sbc'
  environment: environmentName
  region: location
  managedBy: 'bicep'
})

var cp1SharedSecurityRules = [
  {
    name: 'AllowAdminSsh'
    properties: {
      description: 'SSH to CP1 from explicitly approved administrator IPv4 CIDRs.'
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
    name: 'AllowPublicHttp'
    properties: {
      description: 'Public HTTP for redirect and ACME HTTP challenge where used.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 200
      protocol: 'Tcp'
      sourceAddressPrefix: 'Internet'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '80'
    }
  }
  {
    name: 'AllowPublicHttps'
    properties: {
      description: 'Public CP1 HTTPS ingress.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 210
      protocol: 'Tcp'
      sourceAddressPrefix: 'Internet'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '443'
    }
  }
]

var cp1VoiceFixtureSecurityRules = edgeRuntimeProfile == 'SYNTHETIC_PRIVATE' && enableSyntheticVoiceFixture ? [
  {
    name: 'AllowEdgeToFixtureSignaling'
    properties: {
      description: 'Private SBC-to-CP1 TLS signaling for the isolated PBX and Teams-side fixtures only.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 300
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: cp1PrivateIpAddress
      destinationPortRanges: [
        '16061'
        '25061'
      ]
    }
  }
  {
    name: 'AllowEdgeToFixtureMedia'
    properties: {
      description: 'Private SBC-to-CP1 RTP for the isolated PBX and Teams-side fixtures only.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 310
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: cp1PrivateIpAddress
      destinationPortRanges: [
        '21000-21127'
        '22000-22063'
      ]
    }
  }
] : []

var sbcAdminInboundSecurityRules = [
  {
    name: 'AllowAdminSsh'
    properties: {
      description: 'SSH to the SBC from explicitly approved administrator IPv4 CIDRs.'
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
]

var sbcDirectMicrosoftInboundSecurityRules = edgeRuntimeProfile == 'DIRECT_ROUTING' ? [
  {
    name: 'AllowMicrosoftTls5061'
    properties: {
      description: 'Microsoft Direct Routing TLS signaling from explicitly supplied IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 200
      protocol: 'Tcp'
      sourceAddressPrefixes: microsoftSignalingSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '5061'
    }
  }
  {
    name: 'AllowMicrosoftMedia'
    properties: {
      description: 'Microsoft Media Processor UDP from documented remote source ports to the bounded local RTPengine pool.'
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
] : []

var sbcCommonOutboundSecurityRules = [
  {
    name: 'AllowAzureDhcpOutbound'
    properties: {
      description: 'Azure DHCP renewal from the guest client port to the fixed WireServer DHCP endpoint only.'
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
      description: 'Managed-identity token and instance metadata requests to IMDS only.'
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
      description: 'HTTP/HTTPS for Debian APT, pinned package retrieval, ACME, and Azure DNS APIs.'
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
      destinationAddressPrefix: cp1PrivateIpAddress
      destinationPortRange: '443'
    }
  }
]

var sbcSyntheticOutboundSecurityRules = edgeRuntimeProfile == 'SYNTHETIC_PRIVATE' ? [
  {
    name: 'AllowSyntheticFixtureSignalingOutbound'
    properties: {
      description: 'Synthetic PBX and Teams-side mutual-TLS signaling to the fixed private CP1 fixture only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1100
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefix: cp1PrivateIpAddress
      destinationPortRanges: syntheticFixtureSignalingDestinationPorts
    }
  }
  {
    name: 'AllowSyntheticFixtureMediaOutbound'
    properties: {
      description: 'RTPengine tenant allocation to the two bounded private CP1 fixture media ranges only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1110
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: tenantRtpMediaDestinationRange
      destinationAddressPrefix: cp1PrivateIpAddress
      destinationPortRanges: syntheticFixtureMediaDestinationPorts
    }
  }
] : []

var sbcDirectMicrosoftOutboundSecurityRules = edgeRuntimeProfile == 'DIRECT_ROUTING' ? [
  {
    name: 'AllowMicrosoftSignalingOutbound'
    properties: {
      description: 'Mutual-TLS signaling to the reviewed Microsoft Direct Routing CIDRs only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1100
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefixes: microsoftSignalingSourcePrefixes
      destinationPortRange: '5061'
    }
  }
  {
    name: 'AllowMicrosoftMediaOutbound'
    properties: {
      description: 'Bounded local RTPengine UDP to documented Microsoft Media Processor destination ports and IPv4 CIDRs.'
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
] : []

var sbc1DirectPbxOutboundSecurityRules = edgeRuntimeProfile == 'DIRECT_ROUTING' && length(sbc1PbxSourcePrefixes) > 0 ? [
  {
    name: 'AllowPbxSignalingOutbound'
    properties: {
      description: 'Mutual-TLS signaling to the signed and locally authorized SBC1 PBX CIDRs only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1120
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefixes: sbc1PbxSourcePrefixes
      destinationPortRange: '5061'
    }
  }
  {
    name: 'AllowPbxMediaOutbound'
    properties: {
      description: 'RTPengine tenant allocation to the authorized SBC1 PBX CIDRs and explicit PBX-advertised destination range only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1130
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: tenantRtpMediaDestinationRange
      destinationAddressPrefixes: sbc1PbxSourcePrefixes
      destinationPortRange: sbc1PbxMediaDestinationRange
    }
  }
] : []

var sbc2DirectPbxOutboundSecurityRules = edgeRuntimeProfile == 'DIRECT_ROUTING' && length(sbc2PbxSourcePrefixes) > 0 ? [
  {
    name: 'AllowPbxSignalingOutbound'
    properties: {
      description: 'Mutual-TLS signaling to the signed and locally authorized SBC2 PBX CIDRs only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1120
      protocol: 'Tcp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: '*'
      destinationAddressPrefixes: sbc2PbxSourcePrefixes
      destinationPortRange: '5061'
    }
  }
  {
    name: 'AllowPbxMediaOutbound'
    properties: {
      description: 'RTPengine tenant allocation to the authorized SBC2 PBX CIDRs and explicit PBX-advertised destination range only.'
      access: 'Allow'
      direction: 'Outbound'
      priority: 1130
      protocol: 'Udp'
      sourceAddressPrefix: edgeSubnetPrefix
      sourcePortRange: tenantRtpMediaDestinationRange
      destinationAddressPrefixes: sbc2PbxSourcePrefixes
      destinationPortRange: sbc2PbxMediaDestinationRange
    }
  }
] : []

var sbcSyntheticTeamsSecurityRules = edgeRuntimeProfile == 'SYNTHETIC_PRIVATE' && length(syntheticTeamsSourcePrefixes) > 0 ? [
  {
    name: 'AllowSyntheticTeamsTls5061'
    properties: {
      description: 'Private no-PSTN Teams-side simulator TLS signaling for bounded qualification.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 220
      protocol: 'Tcp'
      sourceAddressPrefixes: syntheticTeamsSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '5061'
    }
  }
  {
    name: 'AllowSyntheticTeamsMedia'
    properties: {
      description: 'Private no-PSTN Teams-side simulator media for bounded qualification.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 230
      protocol: 'Udp'
      sourceAddressPrefixes: syntheticTeamsSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: tenantRtpMediaDestinationRange
    }
  }
] : []

var sbc1PbxSecurityRules = length(sbc1PbxSourcePrefixes) == 0 ? [] : [
  {
    name: 'AllowPbxTls'
    properties: {
      description: 'PBX TLS signaling to the isolated first-tenant listener from explicitly supplied SBC1 PBX IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 300
      protocol: 'Tcp'
      sourceAddressPrefixes: sbc1PbxSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(pbxTlsListenerPort)
    }
  }
  {
    name: 'AllowPbxMedia'
    properties: {
      description: 'PBX-side UDP media from explicitly supplied SBC1 PBX IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 310
      protocol: 'Udp'
      sourceAddressPrefixes: sbc1PbxSourcePrefixes
      sourcePortRange: sbc1PbxMediaDestinationRange
      destinationAddressPrefix: '*'
      destinationPortRange: tenantRtpMediaDestinationRange
    }
  }
]

var sbc2PbxSecurityRules = length(sbc2PbxSourcePrefixes) == 0 ? [] : [
  {
    name: 'AllowPbxTls'
    properties: {
      description: 'PBX TLS signaling to the isolated first-tenant listener from explicitly supplied SBC2 PBX IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 300
      protocol: 'Tcp'
      sourceAddressPrefixes: sbc2PbxSourcePrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(pbxTlsListenerPort)
    }
  }
  {
    name: 'AllowPbxMedia'
    properties: {
      description: 'PBX-side UDP media from explicitly supplied SBC2 PBX IPv4 CIDRs.'
      access: 'Allow'
      direction: 'Inbound'
      priority: 310
      protocol: 'Udp'
      sourceAddressPrefixes: sbc2PbxSourcePrefixes
      sourcePortRange: sbc2PbxMediaDestinationRange
      destinationAddressPrefix: '*'
      destinationPortRange: tenantRtpMediaDestinationRange
    }
  }
]

var denyAllInboundRule = [
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

var denyAllOutboundRule = [
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

var sbc1SecurityRules = concat(sbcAdminInboundSecurityRules, sbcDirectMicrosoftInboundSecurityRules, sbcSyntheticTeamsSecurityRules, sbc1PbxSecurityRules, denyAllInboundRule, sbcCommonOutboundSecurityRules, sbcSyntheticOutboundSecurityRules, sbcDirectMicrosoftOutboundSecurityRules, sbc1DirectPbxOutboundSecurityRules, denyAllOutboundRule)
var sbc2SecurityRules = concat(sbcAdminInboundSecurityRules, sbcDirectMicrosoftInboundSecurityRules, sbcSyntheticTeamsSecurityRules, sbc2PbxSecurityRules, denyAllInboundRule, sbcCommonOutboundSecurityRules, sbcSyntheticOutboundSecurityRules, sbcDirectMicrosoftOutboundSecurityRules, sbc2DirectPbxOutboundSecurityRules, denyAllOutboundRule)
var cp1SecurityRules = concat(cp1SharedSecurityRules, cp1VoiceFixtureSecurityRules, denyAllInboundRule)

resource edgeAvailabilitySet 'Microsoft.Compute/availabilitySets@2024-03-01' = {
  name: '${namePrefix}-edge-as'
  location: location
  tags: commonTags
  sku: {
    name: 'Aligned'
  }
  properties: {
    platformFaultDomainCount: 2
    platformUpdateDomainCount: 5
  }
}

module network 'modules/network.bicep' = {
  name: '${namePrefix}-network-deployment'
  params: {
    location: location
    vnetName: vnetName
    vnetAddressPrefix: vnetAddressPrefix
    managementSubnetName: managementSubnetName
    managementSubnetPrefix: managementSubnetPrefix
    edgeSubnetName: edgeSubnetName
    edgeSubnetPrefix: edgeSubnetPrefix
    tags: commonTags
  }
}

module cp1 'modules/linux-node.bicep' = {
  name: '${cp1Name}-deployment'
  params: {
    location: location
    nodeName: cp1Name
    subnetId: managementSubnetId
    privateIpAddress: cp1PrivateIpAddress
    vmSize: cp1VmSize
    osDiskSizeGiB: cp1OsDiskSizeGiB
    osDiskSku: osDiskSku
    enableTrustedLaunch: enableTrustedLaunch
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    imagePublisher: 'Debian'
    imageOffer: 'debian-13'
    imageSku: '13-gen2'
    imageVersion: debianImageVersion
    securityRules: cp1SecurityRules
    tags: union(commonTags, {
      nodeRole: 'control-plane'
      nodeName: 'cp1'
    })
  }
  dependsOn: [
    network
  ]
}

module sbc1 'modules/linux-node.bicep' = {
  name: '${sbc1Name}-deployment'
  params: {
    location: location
    nodeName: sbc1Name
    subnetId: edgeSubnetId
    privateIpAddress: sbc1PrivateIpAddress
    vmSize: sbc1VmSize
    osDiskSizeGiB: sbc1OsDiskSizeGiB
    osDiskSku: osDiskSku
    enableTrustedLaunch: enableTrustedLaunch
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    imagePublisher: 'Debian'
    imageOffer: 'debian-13'
    imageSku: '13-gen2'
    imageVersion: debianImageVersion
    securityRules: sbc1SecurityRules
    availabilitySetId: edgeAvailabilitySet.id
    tags: union(commonTags, {
      nodeRole: 'session-border-controller'
      nodeName: 'sbc1'
    })
  }
  dependsOn: [
    network
  ]
}

module sbc2 'modules/linux-node.bicep' = {
  name: '${sbc2Name}-deployment'
  params: {
    location: location
    nodeName: sbc2Name
    subnetId: edgeSubnetId
    privateIpAddress: sbc2PrivateIpAddress
    vmSize: sbc2VmSize
    osDiskSizeGiB: sbc2OsDiskSizeGiB
    osDiskSku: osDiskSku
    enableTrustedLaunch: enableTrustedLaunch
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    imagePublisher: 'Debian'
    imageOffer: 'debian-13'
    imageSku: '13-gen2'
    imageVersion: debianImageVersion
    securityRules: sbc2SecurityRules
    availabilitySetId: edgeAvailabilitySet.id
    tags: union(commonTags, {
      nodeRole: 'session-border-controller'
      nodeName: 'sbc2'
    })
  }
  dependsOn: [
    network
  ]
}

output resourceNames object = {
  virtualNetwork: vnetName
  managementSubnet: managementSubnetName
  edgeSubnet: edgeSubnetName
  edgeAvailabilitySet: edgeAvailabilitySet.name
  cp1: {
    vm: cp1.outputs.deployedVmName
    nic: cp1.outputs.deployedNicName
    nsg: cp1.outputs.deployedNetworkSecurityGroupName
    publicIp: cp1.outputs.deployedPublicIpName
  }
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

output publicIpAddresses object = {
  cp1: cp1.outputs.assignedPublicIpAddress
  sbc1: sbc1.outputs.assignedPublicIpAddress
  sbc2: sbc2.outputs.assignedPublicIpAddress
}

output privateIpAddresses object = {
  cp1: cp1.outputs.assignedPrivateIpAddress
  sbc1: sbc1.outputs.assignedPrivateIpAddress
  sbc2: sbc2.outputs.assignedPrivateIpAddress
}

output systemAssignedIdentityPrincipalIds object = {
  cp1: cp1.outputs.identityPrincipalId
  sbc1: sbc1.outputs.identityPrincipalId
  sbc2: sbc2.outputs.identityPrincipalId
}

output pbxMediaDestinationPortRanges object = {
  sbc1: sbc1PbxMediaDestinationRange
  sbc2: sbc2PbxMediaDestinationRange
}
