using './main.bicep'

// This file is deliberately non-deployable as-is. Replace the SSH key and all
// RFC 5737 documentation prefixes with verified current values.
param namePrefix = 'viv-sbc-poc'
param environmentName = 'poc'
param adminUsername = 'cpadmin'
param sshPublicKey = 'REPLACE_WITH_A_VALID_SSH_ED25519_PUBLIC_KEY'

// Replace with Jay's current public administration IPv4 address(es), normally /32.
param administratorSourcePrefixes = [
  '203.0.113.10/32'
]

// Replace with the current Microsoft-published Direct Routing endpoint CIDRs.
param microsoftSignalingSourcePrefixes = [
  '192.0.2.0/24'
]
param microsoftMediaSourcePrefixes = [
  '192.0.2.0/24'
]
param microsoftMediaIcePortRange = '3478-3481'
param microsoftMediaHighPortRange = '49152-53247'
param edgeRuntimeProfile = 'SYNTHETIC_PRIVATE'

// Optional private source for an isolated no-PSTN Teams-side simulator.
param syntheticTeamsSourcePrefixes = []
param enableSyntheticVoiceFixture = true

// Leave empty until the test PBX source addresses are known. Rules are omitted
// when these arrays are empty, so PBX ingress remains denied by default.
param sbc1PbxSourcePrefixes = []
param sbc2PbxSourcePrefixes = []
// Synthetic fixture values. For DIRECT_ROUTING, replace these with the exact
// reviewed real-PBX range (the shared first-tenant POC recommendation is
// 30000-30127) and mirror it into the signed profile/private Edge inventory.
param sbc1PbxMediaDestinationPortStart = 21000
param sbc1PbxMediaDestinationPortEnd = 21127
param sbc2PbxMediaDestinationPortStart = 21000
param sbc2PbxMediaDestinationPortEnd = 21127
param pbxTlsListenerPort = 15061

param cp1VmSize = 'Standard_D2as_v5'
param sbc1VmSize = 'Standard_B2als_v2'
param sbc2VmSize = 'Standard_B2als_v2'
param cp1OsDiskSizeGiB = 64
param sbc1OsDiskSizeGiB = 32
param sbc2OsDiskSizeGiB = 32
param osDiskSku = 'StandardSSD_LRS'
param enableTrustedLaunch = true
param rtpMediaPortStart = 20000
param rtpMediaPortCount = 10000
param tenantRtpMediaPortStart = 20000
param tenantRtpMediaPortCount = 256

param tags = {
  owner: 'Vivolution Technologies LLC'
  purpose: 'SBC proof of concept'
  costProfile: 'monthly-credit-lab'
}
