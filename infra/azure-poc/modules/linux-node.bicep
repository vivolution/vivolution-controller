@description('Azure region for the node resources.')
param location string

@description('Short, DNS-safe node name used for the VM and its dependent resources.')
param nodeName string

@description('Resource ID of the subnet that receives the NIC.')
param subnetId string

@description('Static private IPv4 address assigned to the NIC.')
param privateIpAddress string

@description('Azure VM size. Low-cost POC defaults are supplied by the parent template.')
param vmSize string

@minValue(30)
@maxValue(2048)
@description('Size of the managed OS disk in GiB.')
param osDiskSizeGiB int

@allowed([
  'StandardSSD_LRS'
  'Premium_LRS'
])
@description('Managed OS disk SKU.')
param osDiskSku string

@description('Enable Trusted Launch, Secure Boot, and vTPM. Disable only for a verified unsupported VM SKU.')
param enableTrustedLaunch bool

@description('Linux administrator username.')
param adminUsername string

@secure()
@description('SSH public key for the Linux administrator. Password authentication is always disabled.')
param sshPublicKey string

@description('Marketplace image publisher.')
param imagePublisher string

@description('Marketplace image offer.')
param imageOffer string

@description('Marketplace image SKU.')
param imageSku string

@description('Marketplace image version. Pin an exact version for a reproducible deployment.')
param imageVersion string

@description('Complete NSG security-rule objects for this node.')
param securityRules array

@description('Optional availability-set resource ID. Leave empty for a standalone node.')
param availabilitySetId string = ''

@description('Tags applied to every node resource.')
param tags object

var publicIpName = '${nodeName}-pip'
var nsgName = '${nodeName}-nsg'
var nicName = '${nodeName}-nic'
var osDiskName = '${nodeName}-osdisk'

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: publicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    idleTimeoutInMinutes: 30
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: securityRules
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: nicName
  location: location
  tags: tags
  properties: {
    enableAcceleratedNetworking: false
    enableIPForwarding: false
    networkSecurityGroup: {
      id: nsg.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: privateIpAddress
          privateIPAddressVersion: 'IPv4'
          subnet: {
            id: subnetId
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: nodeName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    availabilitySet: empty(availabilitySetId) ? null : {
      id: availabilitySetId
    }
    securityProfile: enableTrustedLaunch ? {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    } : null
    storageProfile: {
      imageReference: {
        publisher: imagePublisher
        offer: imageOffer
        sku: imageSku
        version: imageVersion
      }
      osDisk: {
        name: osDiskName
        osType: 'Linux'
        createOption: 'FromImage'
        caching: 'ReadWrite'
        diskSizeGB: osDiskSizeGiB
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: osDiskSku
        }
      }
      dataDisks: []
    }
    osProfile: {
      computerName: nodeName
      adminUsername: adminUsername
      allowExtensionOperations: true
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        patchSettings: {
          assessmentMode: 'ImageDefault'
          patchMode: 'ImageDefault'
        }
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output deployedVmName string = vm.name
output deployedNicName string = nic.name
output deployedNetworkSecurityGroupName string = nsg.name
output deployedPublicIpName string = publicIp.name
output assignedPublicIpAddress string = publicIp.properties.ipAddress
output assignedPrivateIpAddress string = privateIpAddress
output identityPrincipalId string = vm.identity.principalId
