#requires -Version 7.2
[CmdletBinding()]
param([switch] $SkipConnect)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$result = Invoke-VivolutionTenantDiscovery -SkipConnect:$SkipConnect
$result | ConvertTo-Json -Depth 12
