#requires -Version 7.2
[CmdletBinding()]
param(
    [switch] $SkipConnect,
    [switch] $DeviceAuthentication
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$result = Invoke-VivolutionTenantDiscovery `
    -SkipConnect:$SkipConnect `
    -DeviceAuthentication:$DeviceAuthentication
$result | ConvertTo-Json -Depth 12
