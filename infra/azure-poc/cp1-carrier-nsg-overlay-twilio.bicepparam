using './cp1-carrier-nsg-overlay.bicep'

param targetSubscriptionId = 'a806949c-240f-4541-8c61-fd97f6d1f953'
param targetResourceGroupName = 'rg-vivolution-sbc-poc-uaenorth'
param existingCp1NetworkSecurityGroupName = 'viv-sbc-poc-cp1-nsg'
param twilioEnabled = true
