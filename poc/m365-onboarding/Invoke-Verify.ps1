#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ConfigPath,

    [switch] $SkipConnect
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Vivolution.DirectRouting.psm1') -Force

$config = Import-VivolutionConfiguration -Path $ConfigPath
$result = Invoke-VivolutionVerification -Configuration $config -SkipConnect:$SkipConnect
$result | ConvertTo-Json -Depth 12
