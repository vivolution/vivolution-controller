#requires -Version 7.2
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $ConfigPath,

    [Parameter(Mandatory)]
    [string] $StatePath,

    [Parameter(Mandatory)]
    [string] $Acknowledge,

    [switch] $SkipConnect
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$config = Import-VivolutionConfiguration -Path $ConfigPath
Invoke-VivolutionRollback `
    -Configuration $config `
    -StatePath $StatePath `
    -Acknowledge $Acknowledge `
    -SkipConnect:$SkipConnect `
    -WhatIf:$WhatIfPreference `
    -Confirm:$false
