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

@description('Explicit Twilio authority switch. False emits no Twilio child rule; changing it requires a newly pinned parameter digest and Provider What-If.')
param twilioEnabled bool

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

resource allowCp1AzureDhcpOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1AzureDhcpOutbound'
  properties: {
    description: 'CP1 DHCP renewal from UDP/68 to the fixed Azure WireServer DHCP endpoint only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1000
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '68'
    destinationAddressPrefix: '168.63.129.16'
    destinationPortRange: '67'
  }
}

resource allowCp1AzureDnsUdpOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1AzureDnsUdpOutbound'
  properties: {
    description: 'CP1 unicast UDP DNS to the fixed Azure platform resolver only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1010
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: '168.63.129.16'
    destinationPortRange: '53'
  }
}

resource allowCp1AzureDnsTcpOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1AzureDnsTcpOutbound'
  properties: {
    description: 'CP1 unicast TCP DNS fallback to the fixed Azure platform resolver only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1020
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: '168.63.129.16'
    destinationPortRange: '53'
  }
}

resource allowCp1AzureWireServerOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1AzureWireServerOutbound'
  properties: {
    description: 'CP1 Azure Linux Agent WireServer channels only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1030
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: '168.63.129.16'
    destinationPortRanges: [
      '80'
      '32526'
    ]
  }
}

resource allowCp1AzureImdsOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1AzureImdsOutbound'
  properties: {
    description: 'CP1 managed-identity and instance metadata requests to IMDS only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1040
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: '169.254.169.254'
    destinationPortRange: '80'
  }
}

resource allowCp1NtpOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1NtpOutbound'
  properties: {
    description: 'CP1 resolver-selected network time service on UDP/123 only.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1050
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: 'Internet'
    destinationPortRange: '123'
  }
}

resource allowCp1WebOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowCp1WebOutbound'
  properties: {
    description: 'CP1 HTTP and HTTPS for Debian APT, pinned artifacts, ACME, and Azure DNS APIs.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1060
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefix: 'Internet'
    destinationPortRanges: [
      '80'
      '443'
    ]
  }
}

resource allowGeneration2FixtureSignalingOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration2FixtureSignalingOutbound'
  properties: {
    description: 'Active generation-2 synthetic fixture TLS signaling from CP1 to the two preserved SBCs.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1100
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefixes: [
      '10.20.2.4/32'
      '10.20.2.5/32'
    ]
    destinationPortRange: '15061'
  }
}

resource allowGeneration2FixtureMediaOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration2FixtureMediaOutbound'
  properties: {
    description: 'Active generation-2 synthetic fixture media from both exact CP1 allocations to the preserved SBCs.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1110
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRanges: [
      '21000-21127'
      '22000-22063'
    ]
    destinationAddressPrefixes: [
      '10.20.2.4/32'
      '10.20.2.5/32'
    ]
    destinationPortRange: '20000-20255'
  }
}

resource allowGeneration3CarrierSignalingOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration3CarrierSignalingOutbound'
  properties: {
    description: 'CP1 carrier mutual-TLS signaling to the exact generation-3 private listeners.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1120
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefixes: [
      '10.20.2.6/32'
      '10.20.2.7/32'
    ]
    destinationPortRange: '15061'
  }
}

resource allowGeneration3CarrierMediaOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowGeneration3CarrierMediaOutbound'
  properties: {
    description: 'Exact CP1 carrier media allocation to the generation-3 Edge tenant allocation.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1130
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '30000-30127'
    destinationAddressPrefixes: [
      '10.20.2.6/32'
      '10.20.2.7/32'
    ]
    destinationPortRange: '20000-20255'
  }
}

resource allowTwilioSecureMediaInbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = if (twilioEnabled) {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowTwilioSecureMediaInbound'
  properties: {
    description: 'Twilio global secure-media gateways to the exact CP1 Asterisk RTP allocation; no inbound SIP/DID rule is created.'
    access: 'Allow'
    direction: 'Inbound'
    priority: 340
    protocol: 'Udp'
    sourceAddressPrefix: '168.86.128.0/18'
    sourcePortRange: '10000-60000'
    destinationAddressPrefix: '10.20.1.4/32'
    destinationPortRange: '30000-30127'
  }
}

resource allowTwilioSecureSignalingOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = if (twilioEnabled) {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowTwilioSecureSignalingOutbound'
  properties: {
    description: 'CP1 TLS termination traffic to all current Twilio Elastic SIP Trunking signaling gateway ranges; host policy narrows this to reviewed DNS /32s.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1200
    protocol: 'Tcp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '*'
    destinationAddressPrefixes: [
      '54.172.60.0/30'
      '54.244.51.0/30'
      '54.171.127.192/30'
      '35.156.191.128/30'
      '54.65.63.192/30'
      '54.169.127.128/30'
      '54.252.254.64/30'
      '177.71.206.192/30'
    ]
    destinationPortRange: '5061'
  }
}

resource allowTwilioSecureMediaOutbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = if (twilioEnabled) {
  parent: existingCp1NetworkSecurityGroup
  name: 'AllowTwilioSecureMediaOutbound'
  properties: {
    description: 'Exact CP1 Asterisk RTP allocation to Twilio global secure-media gateway ports.'
    access: 'Allow'
    direction: 'Outbound'
    priority: 1210
    protocol: 'Udp'
    sourceAddressPrefix: '10.20.1.4/32'
    sourcePortRange: '30000-30127'
    destinationAddressPrefix: '168.86.128.0/18'
    destinationPortRange: '10000-60000'
  }
}

resource denyAllCp1Outbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01' = {
  parent: existingCp1NetworkSecurityGroup
  name: 'DenyAllCp1Outbound'
  properties: {
    description: 'Explicitly deny every other CP1 outbound flow before Azure default rules.'
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

output overlayContract object = {
  authority: {
    subscriptionId: targetSubscriptionId
    resourceGroupName: targetResourceGroupName
  }
  existingNetworkSecurityGroupId: existingCp1NetworkSecurityGroup.id
  rules: concat([
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
    {
      id: allowCp1AzureDhcpOutbound.id
      name: allowCp1AzureDhcpOutbound.name
      priority: 1000
    }
    {
      id: allowCp1AzureDnsUdpOutbound.id
      name: allowCp1AzureDnsUdpOutbound.name
      priority: 1010
    }
    {
      id: allowCp1AzureDnsTcpOutbound.id
      name: allowCp1AzureDnsTcpOutbound.name
      priority: 1020
    }
    {
      id: allowCp1AzureWireServerOutbound.id
      name: allowCp1AzureWireServerOutbound.name
      priority: 1030
    }
    {
      id: allowCp1AzureImdsOutbound.id
      name: allowCp1AzureImdsOutbound.name
      priority: 1040
    }
    {
      id: allowCp1NtpOutbound.id
      name: allowCp1NtpOutbound.name
      priority: 1050
    }
    {
      id: allowCp1WebOutbound.id
      name: allowCp1WebOutbound.name
      priority: 1060
    }
    {
      id: allowGeneration2FixtureSignalingOutbound.id
      name: allowGeneration2FixtureSignalingOutbound.name
      priority: 1100
    }
    {
      id: allowGeneration2FixtureMediaOutbound.id
      name: allowGeneration2FixtureMediaOutbound.name
      priority: 1110
    }
    {
      id: allowGeneration3CarrierSignalingOutbound.id
      name: allowGeneration3CarrierSignalingOutbound.name
      priority: 1120
    }
    {
      id: allowGeneration3CarrierMediaOutbound.id
      name: allowGeneration3CarrierMediaOutbound.name
      priority: 1130
    }
    {
      id: denyAllCp1Outbound.id
      name: denyAllCp1Outbound.name
      priority: 4096
    }
  ], twilioEnabled ? [
    {
      id: allowTwilioSecureMediaInbound.id
      name: allowTwilioSecureMediaInbound.name
      priority: 340
    }
    {
      id: allowTwilioSecureSignalingOutbound.id
      name: allowTwilioSecureSignalingOutbound.name
      priority: 1200
    }
    {
      id: allowTwilioSecureMediaOutbound.id
      name: allowTwilioSecureMediaOutbound.name
      priority: 1210
    }
  ] : [])
}
