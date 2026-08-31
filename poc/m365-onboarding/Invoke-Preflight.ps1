#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ConfigPath,

    [switch] $SkipConnect,

    [switch] $DeviceAuthentication
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$config = Import-VivolutionConfiguration -Path $ConfigPath
$result = Invoke-VivolutionPreflight `
    -Configuration $config `
    -SkipConnect:$SkipConnect `
    -DeviceAuthentication:$DeviceAuthentication
$result | ConvertTo-Json -Depth 12
