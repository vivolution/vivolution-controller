using './direct-replacement.bicep'

// This example deliberately cannot pass direct-replacement-preflight.py.
// Replace only the three marked authorities with separately verified values.
param targetSubscriptionId = 'a806949c-240f-4541-8c61-fd97f6d1f953'
param targetResourceGroupName = 'rg-vivolution-sbc-poc-uaenorth'
param location = 'uaenorth'
param existingVirtualNetworkName = 'viv-sbc-poc-vnet'
param existingEdgeSubnetName = 'snet-edge'
param existingAvailabilitySetName = 'viv-sbc-poc-edge-as'

param edgeRuntimeProfile = 'DIRECT_ROUTING_PRIVATE_PBX_POC'
param edgeGeneration = 3
// REPLACE once, immediately before offline admission. It must be canonical UTC,
// future, and no more than 72 hours away; never extend it after create begins.
param parallelAcceptanceDeadlineUtc = '2026-09-03T00:00:00Z'
param sbc1NodeName = 'viv-sbc-dr-sbc1-g3'
param sbc2NodeName = 'viv-sbc-dr-sbc2-g3'
param sbc1PrivateIpAddress = '10.20.2.6'
param sbc2PrivateIpAddress = '10.20.2.7'
param cp1PrivatePrefix = '10.20.1.4/32'

// REPLACE: current approved public administration address(es), /32 only.
param administratorSourcePrefixes = [
  '203.0.113.10/32'
]

// Reviewed Microsoft Direct Routing IPv4 sets, checked 2026-08-31.
param microsoftSignalingSourcePrefixes = [
  '52.112.0.0/14'
  '52.120.0.0/14'
]
param microsoftMediaSourcePrefixes = [
  '52.112.0.0/14'
  '52.120.0.0/14'
]

param microsoftMediaIcePortRange = '3478-3481'
param microsoftMediaHighPortRange = '49152-53247'
param remoteTlsPort = 5061
param localPbxTlsListenerPort = 15061
param pbxMediaDestinationPortStart = 30000
param pbxMediaDestinationPortEnd = 30127
param rtpMediaPortStart = 20000
param rtpMediaPortCount = 10000
param tenantRtpMediaPortStart = 20000
param tenantRtpMediaPortCount = 256

param vmSize = 'Standard_B2als_v2'
param osDiskSizeGiB = 32
param osDiskSku = 'StandardSSD_LRS'
param enableTrustedLaunch = true
param adminUsername = 'cpadmin'

// REPLACE: approved ED25519 public key only. Never put a private key here.
param sshPublicKey = 'REPLACE_WITH_ONE_APPROVED_SSH_ED25519_PUBLIC_KEY'

param imagePublisher = 'Debian'
param imageOffer = 'debian-13'
param imageSku = '13-gen2'
param imageVersion = '0.20260826.2582'
