#requires -Version 7.2
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $ConfigPath,

    [Parameter(Mandatory)]
    [string] $Acknowledge,

    [string] $StatePath = (Join-Path $PSScriptRoot '.state/apply-state.json'),

    [switch] $SkipConnect
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$config = Import-VivolutionConfiguration -Path $ConfigPath
Invoke-VivolutionApply `
    -Configuration $config `
    -StatePath $StatePath `
    -Acknowledge $Acknowledge `
    -SkipConnect:$SkipConnect `
    -WhatIf:$WhatIfPreference `
    -Confirm:$false
