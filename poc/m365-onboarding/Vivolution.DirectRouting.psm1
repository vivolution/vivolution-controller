Set-StrictMode -Version Latest

$script:ExpectedTenantId = '151cd01a-1e81-40a9-b898-d8646e1a8760'
$script:VerifiedDomain = 'vivolution.ae'
$script:DiscoveryUserUpn = 'jay@vivolution.ae'
$script:Gateways = @(
    'sbc1.vivolution.ae'
    'sbc2.vivolution.ae'
)
$script:SipSignalingPort = 5061
$script:PstnUsage = 'Vivolution-POC-UAE'
$script:VoiceRoute = 'Vivolution-POC-UAE-Plus971'
$script:VoiceRoutingPolicy = 'Vivolution-POC-UAE'
$script:NumberPattern = '^(?:\+971000000200[12]|\+971[1-9][0-9]{7,8})$'
$script:UserNumberPattern = '^\+971[1-9][0-9]{7,8}$'
$script:GatewayDescription = 'Vivolution OpenSIPS non-certified POC; no Microsoft support claim'
$script:ApplyAcknowledgement =
    'APPLY VIVOLUTION DIRECT ROUTING POC TO 151cd01a-1e81-40a9-b898-d8646e1a8760'
$script:RollbackAcknowledgement =
    'ROLL BACK VIVOLUTION DIRECT ROUTING POC FROM 151cd01a-1e81-40a9-b898-d8646e1a8760'

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)] [object] $InputObject,
        [Parameter(Mandatory)] [string[]] $Names
    )

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property) {
            return $property.Value
        }
    }
    return $null
}

function ConvertTo-StringArray {
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) {
        return @()
    }

    return @(
        foreach ($item in @($Value)) {
            if ($null -ne $item) {
                [string] $item
            }
        }
    )
}

function Test-ExactStringSequence {
    param(
        [AllowNull()] [object] $Actual,
        [Parameter(Mandatory)] [string[]] $Expected
    )

    $actualItems = @(ConvertTo-StringArray -Value $Actual)
    if ($actualItems.Count -ne $Expected.Count) {
        return $false
    }

    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if (-not [string]::Equals(
                $actualItems[$index],
                $Expected[$index],
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            return $false
        }
    }
    return $true
}

function Test-StringInArray {
    param(
        [AllowNull()] [object] $Values,
        [Parameter(Mandatory)] [string] $Expected
    )

    foreach ($value in @(ConvertTo-StringArray -Value $Values)) {
        if ([string]::Equals($value, $Expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Normalize-PolicyName {
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) {
        return ''
    }
    return ([string] $Value) -replace '(?i)^tag:', ''
}

function Normalize-LineUri {
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) {
        return ''
    }
    return (([string] $Value) -replace '(?i)^tel:', '')
}

function Assert-InteractiveTeamsUserAccount {
    param(
        [Parameter(Mandatory)] [object] $User,
        [Parameter(Mandatory)] [string] $Upn
    )

    $accountType = [string] (
        Get-PropertyValue -InputObject $User -Names @('AccountType')
    )
    if (-not [string]::Equals(
            $accountType,
            'User',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "User '$Upn' must have exact AccountType 'User'; found '$accountType'."
    }
    $softDeletionTimestamp = Get-PropertyValue `
        -InputObject $User `
        -Names @('SoftDeletionTimestamp')
    if ($null -ne $softDeletionTimestamp) {
        throw "User '$Upn' is soft-deleted and is not eligible for this POC."
    }
    return 'User'
}

function Get-VivolutionConfigurationHash {
    param([Parameter(Mandatory)] [hashtable] $Configuration)

    $canonical = [ordered]@{
        SchemaVersion = [int] $Configuration.SchemaVersion
        ExpectedTenantId = ([string] $Configuration.ExpectedTenantId).ToLowerInvariant()
        VerifiedDomain = ([string] $Configuration.VerifiedDomain).ToLowerInvariant()
        Gateways = @($Configuration.Gateways | ForEach-Object { ([string] $_).ToLowerInvariant() })
        SipSignalingPort = [int] $Configuration.SipSignalingPort
        PstnUsage = [string] $Configuration.PstnUsage
        VoiceRoute = [string] $Configuration.VoiceRoute
        VoiceRoutingPolicy = [string] $Configuration.VoiceRoutingPolicy
        NumberPattern = [string] $Configuration.NumberPattern
        Users = @(
            foreach ($user in @($Configuration.Users)) {
                [ordered]@{
                    Upn = ([string] $user.Upn).ToLowerInvariant()
                    TelephoneNumber = [string] $user.TelephoneNumber
                }
            }
        )
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        ($canonical | ConvertTo-Json -Depth 8 -Compress)
    )
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Assert-VivolutionConfiguration {
    param([Parameter(Mandatory)] [hashtable] $Configuration)

    $requiredKeys = @(
        'SchemaVersion', 'ExpectedTenantId', 'VerifiedDomain', 'Gateways',
        'SipSignalingPort', 'PstnUsage', 'VoiceRoute', 'VoiceRoutingPolicy',
        'NumberPattern', 'Users'
    )
    foreach ($key in $requiredKeys) {
        if (-not $Configuration.ContainsKey($key)) {
            throw "Configuration is missing required key '$key'."
        }
    }

    if ([int] $Configuration.SchemaVersion -ne 1) {
        throw 'Only configuration SchemaVersion 1 is supported.'
    }
    if (-not [string]::Equals(
            [string] $Configuration.ExpectedTenantId,
            $script:ExpectedTenantId,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "ExpectedTenantId must be exactly $script:ExpectedTenantId."
    }
    if (-not [string]::Equals(
            [string] $Configuration.VerifiedDomain,
            $script:VerifiedDomain,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "VerifiedDomain must be exactly $script:VerifiedDomain."
    }
    if (-not (Test-ExactStringSequence -Actual $Configuration.Gateways -Expected $script:Gateways)) {
        throw "Gateways must be exactly '$($script:Gateways -join "', '")' in that order."
    }
    if ([int] $Configuration.SipSignalingPort -ne $script:SipSignalingPort) {
        throw "SipSignalingPort must be exactly $script:SipSignalingPort."
    }

    $lockedStrings = @{
        PstnUsage = $script:PstnUsage
        VoiceRoute = $script:VoiceRoute
        VoiceRoutingPolicy = $script:VoiceRoutingPolicy
        NumberPattern = $script:NumberPattern
    }
    foreach ($key in $lockedStrings.Keys) {
        if (-not [string]::Equals(
                [string] $Configuration[$key],
                [string] $lockedStrings[$key],
                [System.StringComparison]::Ordinal
            )) {
            throw "$key must be exactly '$($lockedStrings[$key])'."
        }
    }

    $users = @($Configuration.Users)
    if ($users.Count -lt 1 -or $users.Count -gt 2) {
        throw 'One or two test users must be supplied.'
    }

    $seenUpns = @{}
    $seenNumbers = @{}
    foreach ($user in $users) {
        if ($user -isnot [hashtable]) {
            throw 'Every Users entry must be a hashtable.'
        }
        if (-not $user.ContainsKey('Upn') -or -not $user.ContainsKey('TelephoneNumber')) {
            throw 'Every Users entry requires Upn and TelephoneNumber.'
        }

        $upn = ([string] $user.Upn).Trim().ToLowerInvariant()
        $number = ([string] $user.TelephoneNumber).Trim()
        if ($upn -match '(?i)replace|example|<|>') {
            throw "User UPN '$upn' is still a placeholder."
        }
        if ($upn -notmatch '^[a-z0-9.!#$%&''*+/=?^_`{|}~-]+@vivolution\.ae$') {
            throw "User UPN '$upn' must be in the verified vivolution.ae domain."
        }
        if ($number -notmatch $script:UserNumberPattern) {
            throw "Telephone number '$number' is not an allowed +971 Direct Routing number."
        }
        if ($seenUpns.ContainsKey($upn)) {
            throw "Duplicate user UPN '$upn'."
        }
        if ($seenNumbers.ContainsKey($number)) {
            throw "Duplicate telephone number '$number'."
        }
        $seenUpns[$upn] = $true
        $seenNumbers[$number] = $true
    }
}

function Import-VivolutionConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if ([System.IO.Path]::GetExtension($resolved.Path) -ne '.psd1') {
        throw 'The configuration must be a PowerShell data file with a .psd1 extension.'
    }
    $configuration = Import-PowerShellDataFile -LiteralPath $resolved.Path
    Assert-VivolutionConfiguration -Configuration $configuration
    return $configuration
}

function Assert-TeamsReadOnlyModuleContract {
    Import-Module MicrosoftTeams -MinimumVersion 7.0.0 -ErrorAction Stop

    $requiredCommands = @(
        'Connect-MicrosoftTeams',
        'Get-CsTenant',
        'Get-CsOnlineUser',
        'Get-CsPhoneNumberAssignment',
        'Get-CsOnlinePSTNGateway',
        'Get-CsOnlinePstnUsage',
        'Get-CsOnlineVoiceRoute',
        'Get-CsOnlineVoiceRoutingPolicy'
    )
    foreach ($command in $requiredCommands) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required MicrosoftTeams read command '$command' is unavailable."
        }
    }
}

function Assert-TeamsModuleContract {
    Assert-TeamsReadOnlyModuleContract

    $requiredCommands = @(
        'Set-CsPhoneNumberAssignment',
        'Remove-CsPhoneNumberAssignment',
        'New-CsOnlinePSTNGateway',
        'Remove-CsOnlinePSTNGateway',
        'Set-CsOnlinePstnUsage',
        'New-CsOnlineVoiceRoute',
        'Remove-CsOnlineVoiceRoute',
        'New-CsOnlineVoiceRoutingPolicy',
        'Grant-CsOnlineVoiceRoutingPolicy',
        'Remove-CsOnlineVoiceRoutingPolicy'
    )
    foreach ($command in $requiredCommands) {
        if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required MicrosoftTeams command '$command' is unavailable."
        }
    }
}

function Get-TenantIdFromObject {
    param([Parameter(Mandatory)] [object] $Tenant)

    foreach ($name in @('TenantId', 'Identity', 'ObjectId', 'Id')) {
        $value = Get-PropertyValue -InputObject $Tenant -Names @($name)
        if ($null -ne $value) {
            $candidate = [string] $value
            $parsed = [guid]::Empty
            if ([guid]::TryParse($candidate, [ref] $parsed)) {
                return $parsed.ToString()
            }
        }
    }
    throw 'Get-CsTenant did not return a parseable tenant ID.'
}

function Get-TenantDomains {
    param([Parameter(Mandatory)] [object] $Tenant)

    $domains = @()
    foreach ($entry in @(Get-PropertyValue -InputObject $Tenant -Names @('Domains'))) {
        if ($null -eq $entry) {
            continue
        }
        if ($entry -is [string]) {
            $domains += ([string] $entry).ToLowerInvariant()
            continue
        }
        $value = Get-PropertyValue -InputObject $entry -Names @(
            'Name', 'DomainName', 'Domain', 'Fqdn'
        )
        if ($null -ne $value) {
            $domains += ([string] $value).ToLowerInvariant()
        }
    }
    return @($domains | Sort-Object -Unique)
}

function Connect-VivolutionMicrosoftTeams {
    param(
        [Parameter(Mandatory)] [string] $TenantId,
        [switch] $DeviceAuthentication
    )

    if (-not $DeviceAuthentication) {
        Connect-MicrosoftTeams -TenantId $TenantId -ErrorAction Stop | Out-Null
        return
    }

    $connectCommand = Get-Command Connect-MicrosoftTeams -ErrorAction Stop
    foreach ($parameterName in @('UseDeviceAuthentication', 'DisableWAM')) {
        if (-not $connectCommand.Parameters.ContainsKey($parameterName)) {
            throw (
                'Device-code MicrosoftTeams authentication requires ' +
                "Connect-MicrosoftTeams parameter '-$parameterName'. " +
                'Install a current MicrosoftTeams module; authentication fallback is refused.'
            )
        }
    }
    Connect-MicrosoftTeams `
        -TenantId $TenantId `
        -UseDeviceAuthentication `
        -DisableWAM `
        -ErrorAction Stop | Out-Null
}

function Connect-VivolutionTenant {
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication,
        [switch] $ReadOnlyContract
    )

    if ($ReadOnlyContract) {
        Assert-TeamsReadOnlyModuleContract
    }
    else {
        Assert-TeamsModuleContract
    }
    if ($SkipConnect -and $DeviceAuthentication) {
        throw '-SkipConnect and -DeviceAuthentication cannot be combined.'
    }
    if (-not $SkipConnect) {
        Connect-VivolutionMicrosoftTeams `
            -TenantId $Configuration.ExpectedTenantId `
            -DeviceAuthentication:$DeviceAuthentication
    }

    $tenants = @(Get-CsTenant -ErrorAction Stop)
    if ($tenants.Count -ne 1) {
        throw "Expected exactly one connected tenant; Get-CsTenant returned $($tenants.Count)."
    }
    $actualTenantId = Get-TenantIdFromObject -Tenant $tenants[0]
    if (-not [string]::Equals(
            $actualTenantId,
            [string] $Configuration.ExpectedTenantId,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Connected tenant '$actualTenantId' is not the expected tenant '$($Configuration.ExpectedTenantId)'."
    }

    $domains = @(Get-TenantDomains -Tenant $tenants[0])
    if (-not (Test-StringInArray -Values $domains -Expected $Configuration.VerifiedDomain)) {
        throw (
            "Domain '$($Configuration.VerifiedDomain)' is not registered in the connected tenant. " +
            'Microsoft requires the exact subdomain used by an SBC FQDN to be registered.'
        )
    }

    return [pscustomobject]@{
        Tenant = $tenants[0]
        TenantId = $actualTenantId
        Domains = $domains
    }
}

function Invoke-VivolutionTenantDiscovery {
    [CmdletBinding()]
    param(
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication
    )

    $discoveryConfiguration = @{
        ExpectedTenantId = $script:ExpectedTenantId
        VerifiedDomain = $script:VerifiedDomain
    }
    $tenantContext = Connect-VivolutionTenant `
        -Configuration $discoveryConfiguration `
        -SkipConnect:$SkipConnect `
        -DeviceAuthentication:$DeviceAuthentication `
        -ReadOnlyContract

    $users = @(Get-CsOnlineUser -Identity $script:DiscoveryUserUpn -ErrorAction Stop)
    if ($users.Count -ne 1) {
        throw (
            "Expected exactly one discovery user '$script:DiscoveryUserUpn'; " +
            "found $($users.Count)."
        )
    }
    $user = $users[0]
    $actualUpn = ([string] (
        Get-PropertyValue -InputObject $user -Names @('UserPrincipalName')
    )).ToLowerInvariant()
    if (-not [string]::Equals(
            $actualUpn,
            $script:DiscoveryUserUpn,
            [System.StringComparison]::Ordinal
        )) {
        throw "Tenant discovery returned '$actualUpn' for the fixed user."
    }
    if ((Get-PropertyValue -InputObject $user -Names @('AccountEnabled')) -ne $true) {
        throw "Discovery user '$actualUpn' is not enabled."
    }
    $accountType = Assert-InteractiveTeamsUserAccount -User $user -Upn $actualUpn

    $featureTypes = @(ConvertTo-StringArray -Value (
        Get-PropertyValue -InputObject $user -Names @('FeatureTypes')
    ))
    foreach ($feature in @('Teams', 'PhoneSystem')) {
        if (-not (Test-StringInArray -Values $featureTypes -Expected $feature)) {
            throw "Discovery user '$actualUpn' is missing the '$feature' license feature."
        }
    }
    $registrarPool = [string] (
        Get-PropertyValue -InputObject $user -Names @('RegistrarPool')
    )
    if ($registrarPool -notmatch '(?i)\.infra\.lync\.com$') {
        throw "Discovery user '$actualUpn' is not homed in an online Teams registrar."
    }
    $onPremLineUri = Normalize-LineUri -Value (
        Get-PropertyValue -InputObject $user -Names @('OnPremLineURI')
    )
    if (-not [string]::IsNullOrWhiteSpace($onPremLineUri)) {
        throw "Discovery user '$actualUpn' has an on-premises LineURI."
    }
    $upgradeMode = [string] (
        Get-PropertyValue -InputObject $user -Names @('TeamsUpgradeEffectiveMode')
    )
    if (-not [string]::Equals(
            $upgradeMode,
            'TeamsOnly',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Discovery user '$actualUpn' must use TeamsOnly mode."
    }

    $lineUri = Normalize-LineUri -Value (
        Get-PropertyValue -InputObject $user -Names @('LineURI')
    )
    $voicePolicy = Normalize-PolicyName -Value (
        Get-PropertyValue -InputObject $user -Names @('OnlineVoiceRoutingPolicy')
    )
    $discoveryStatus = if ([string]::IsNullOrWhiteSpace($lineUri)) {
        'READY_FOR_NUMBER_SELECTION'
    }
    else {
        'EXISTING_NUMBER_REQUIRES_EXACT_REVIEW'
    }
    return [pscustomobject]@{
        Status = $discoveryStatus
        ReadOnly = $true
        TenantId = $tenantContext.TenantId
        RegisteredDomains = @($tenantContext.Domains)
        User = [pscustomobject]@{
            Upn = $actualUpn
            AccountEnabled = $true
            AccountType = $accountType
            SoftDeletionTimestampEmpty = $true
            RequiredFeatureTypes = @('PhoneSystem', 'Teams')
            RegistrarPool = $registrarPool
            TeamsUpgradeEffectiveMode = $upgradeMode
            OnPremLineUriEmpty = $true
            CurrentLineUri = $lineUri
            ExistingVoiceRoutingPolicy = $voicePolicy
            EnterpriseVoiceEnabled = [bool] (
                Get-PropertyValue -InputObject $user -Names @('EnterpriseVoiceEnabled')
            )
        }
        Limitations = @(
            'No Direct Routing number has been selected or assigned by this discovery.',
            'No gateway, route, policy, license, user, or tenant object was changed.',
            'This read-only result is not an evidence-bound CP1 M365 verification receipt.'
        )
    }
}

function Get-ManagedObject {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Objects,
        [Parameter(Mandatory)] [string] $Identity,
        [switch] $PolicyIdentity
    )

    $matches = @(
        foreach ($object in $Objects) {
            $actual = [string] (Get-PropertyValue -InputObject $object -Names @('Identity', 'Fqdn', 'Name'))
            if ($PolicyIdentity) {
                $actual = Normalize-PolicyName -Value $actual
            }
            if ([string]::Equals($actual, $Identity, [System.StringComparison]::OrdinalIgnoreCase)) {
                $object
            }
        }
    )
    if ($matches.Count -gt 1) {
        throw "More than one object matched managed identity '$Identity'."
    }
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    return $null
}

function Assert-GatewayExact {
    param(
        [Parameter(Mandatory)] [object] $Gateway,
        [Parameter(Mandatory)] [string] $Fqdn
    )

    $actualFqdn = [string] (Get-PropertyValue -InputObject $Gateway -Names @('Fqdn', 'Identity'))
    $checks = [ordered]@{
        Fqdn = [string]::Equals($actualFqdn, $Fqdn, [System.StringComparison]::OrdinalIgnoreCase)
        SipSignalingPort = [int] (Get-PropertyValue -InputObject $Gateway -Names @('SipSignalingPort')) -eq 5061
        Enabled = [bool] (Get-PropertyValue -InputObject $Gateway -Names @('Enabled')) -eq $true
        SendSipOptions = [bool] (Get-PropertyValue -InputObject $Gateway -Names @('SendSipOptions')) -eq $true
        MediaBypass = [bool] (Get-PropertyValue -InputObject $Gateway -Names @('MediaBypass')) -eq $false
        ForwardCallHistory = [bool] (Get-PropertyValue -InputObject $Gateway -Names @('ForwardCallHistory')) -eq $false
        ForwardPai = [bool] (Get-PropertyValue -InputObject $Gateway -Names @('ForwardPai')) -eq $true
        FailoverTimeSeconds = [int] (Get-PropertyValue -InputObject $Gateway -Names @('FailoverTimeSeconds')) -eq 10
        FailoverResponseCodes = (([string] (Get-PropertyValue -InputObject $Gateway -Names @('FailoverResponseCodes'))) -replace '\s', '') -eq '408,503,504'
        MaxConcurrentSessions = [int] (Get-PropertyValue -InputObject $Gateway -Names @('MaxConcurrentSessions')) -eq 20
        IPAddressVersion = [string]::Equals(
            [string] (Get-PropertyValue -InputObject $Gateway -Names @('IPAddressVersion')),
            'IPv4',
            [System.StringComparison]::OrdinalIgnoreCase
        )
        Description = [string]::Equals(
            [string] (Get-PropertyValue -InputObject $Gateway -Names @('Description')),
            $script:GatewayDescription,
            [System.StringComparison]::Ordinal
        )
    }
    $failed = @($checks.Keys | Where-Object { -not $checks[$_] })
    if ($failed.Count -gt 0) {
        throw "Existing gateway '$Fqdn' diverges in: $($failed -join ', ')."
    }
}

function Assert-RouteExact {
    param([Parameter(Mandatory)] [object] $Route)

    $failures = @()
    if (-not [string]::Equals(
            [string] (Get-PropertyValue -InputObject $Route -Names @('NumberPattern')),
            $script:NumberPattern,
            [System.StringComparison]::Ordinal
        )) {
        $failures += 'NumberPattern'
    }
    if (-not (Test-ExactStringSequence `
            -Actual (Get-PropertyValue -InputObject $Route -Names @('OnlinePstnGatewayList')) `
            -Expected $script:Gateways)) {
        $failures += 'OnlinePstnGatewayList/order'
    }
    if (-not (Test-ExactStringSequence `
            -Actual (Get-PropertyValue -InputObject $Route -Names @('OnlinePstnUsages')) `
            -Expected @($script:PstnUsage))) {
        $failures += 'OnlinePstnUsages'
    }
    if ($failures.Count -gt 0) {
        throw "Existing route '$script:VoiceRoute' diverges in: $($failures -join ', ')."
    }
}

function Assert-PolicyExact {
    param([Parameter(Mandatory)] [object] $Policy)

    if (-not (Test-ExactStringSequence `
            -Actual (Get-PropertyValue -InputObject $Policy -Names @('OnlinePstnUsages')) `
            -Expected @($script:PstnUsage))) {
        throw "Existing policy '$script:VoiceRoutingPolicy' has divergent OnlinePstnUsages."
    }
}

function Get-UserIdentityCandidates {
    param([Parameter(Mandatory)] [object] $User)

    $values = @()
    foreach ($name in @('Identity', 'ObjectId', 'Id', 'UserPrincipalName')) {
        $value = Get-PropertyValue -InputObject $User -Names @($name)
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string] $value)) {
            $values += [string] $value
        }
    }
    return @($values | Sort-Object -Unique)
}

function Assert-UserReady {
    param(
        [Parameter(Mandatory)] [object] $User,
        [Parameter(Mandatory)] [hashtable] $ExpectedUser,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $PhoneAssignments
    )

    $upn = ([string] $ExpectedUser.Upn).ToLowerInvariant()
    $number = [string] $ExpectedUser.TelephoneNumber
    $actualUpn = ([string] (Get-PropertyValue -InputObject $User -Names @('UserPrincipalName'))).ToLowerInvariant()
    if ($actualUpn -ne $upn) {
        throw "Get-CsOnlineUser returned '$actualUpn' for expected user '$upn'."
    }
    if ((Get-PropertyValue -InputObject $User -Names @('AccountEnabled')) -ne $true) {
        throw "User '$upn' is not enabled."
    }
    $null = Assert-InteractiveTeamsUserAccount -User $User -Upn $upn

    $featureTypes = Get-PropertyValue -InputObject $User -Names @('FeatureTypes')
    foreach ($feature in @('Teams', 'PhoneSystem')) {
        if (-not (Test-StringInArray -Values $featureTypes -Expected $feature)) {
            throw "User '$upn' is missing the '$feature' license feature."
        }
    }

    $registrarPool = [string] (Get-PropertyValue -InputObject $User -Names @('RegistrarPool'))
    if ($registrarPool -notmatch '(?i)\.infra\.lync\.com$') {
        throw "User '$upn' is not homed online in an infra.lync.com registrar pool."
    }
    $onPremLineUri = Normalize-LineUri -Value (
        Get-PropertyValue -InputObject $User -Names @('OnPremLineURI')
    )
    if (-not [string]::IsNullOrWhiteSpace($onPremLineUri)) {
        throw "User '$upn' has an on-premises LineURI and is not safe for online assignment."
    }
    $upgradeMode = [string] (Get-PropertyValue -InputObject $User -Names @('TeamsUpgradeEffectiveMode'))
    if (-not [string]::Equals(
            $upgradeMode,
            'TeamsOnly',
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "User '$upn' must have TeamsUpgradeEffectiveMode TeamsOnly."
    }

    $lineUri = Normalize-LineUri -Value (Get-PropertyValue -InputObject $User -Names @('LineURI'))
    if (-not [string]::IsNullOrWhiteSpace($lineUri) -and $lineUri -ne $number) {
        throw "User '$upn' already has divergent LineURI '$lineUri'."
    }

    if ($PhoneAssignments.Count -gt 1) {
        throw "Number '$number' returned more than one phone-number inventory record."
    }
    if ($PhoneAssignments.Count -eq 1) {
        $assignment = $PhoneAssignments[0]
        $numberType = [string] (Get-PropertyValue -InputObject $assignment -Names @('NumberType'))
        if (-not [string]::Equals(
                $numberType,
                'DirectRouting',
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Number '$number' already exists with divergent NumberType '$numberType'."
        }

        $assignedTarget = [string] (Get-PropertyValue -InputObject $assignment -Names @('AssignedPstnTargetId'))
        $hasTarget = -not [string]::IsNullOrWhiteSpace($assignedTarget)
        if ([string]::IsNullOrWhiteSpace($lineUri) -and $hasTarget) {
            throw "Number '$number' is already assigned to another or inconsistent target '$assignedTarget'."
        }
        if (-not [string]::IsNullOrWhiteSpace($lineUri)) {
            $targetMatches = $false
            foreach ($candidate in @(Get-UserIdentityCandidates -User $User)) {
                if ([string]::Equals(
                        $candidate,
                        $assignedTarget,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )) {
                    $targetMatches = $true
                }
            }
            if (-not $targetMatches) {
                throw "Number '$number' does not point to expected user '$upn'."
            }
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($lineUri)) {
        throw "User '$upn' has LineURI '$lineUri' but no matching number inventory record."
    }

    $policy = Normalize-PolicyName -Value (
        Get-PropertyValue -InputObject $User -Names @('OnlineVoiceRoutingPolicy')
    )
    if (-not [string]::IsNullOrWhiteSpace($policy) -and -not [string]::Equals(
            $policy,
            $script:VoiceRoutingPolicy,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "User '$upn' already has divergent voice routing policy '$policy'."
    }

    return [pscustomobject]@{
        Upn = $upn
        TelephoneNumber = $number
        NumberExact = -not [string]::IsNullOrWhiteSpace($lineUri)
        PolicyExact = -not [string]::IsNullOrWhiteSpace($policy)
        EnterpriseVoiceEnabled = [bool] (Get-PropertyValue -InputObject $User -Names @('EnterpriseVoiceEnabled'))
    }
}

function Assert-NoForeignReferences {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Routes,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
        [Parameter(Mandatory)] [string[]] $ManagedUpns
    )

    foreach ($route in $Routes) {
        $identity = [string] (Get-PropertyValue -InputObject $route -Names @('Identity'))
        $isManaged = [string]::Equals(
            $identity,
            $script:VoiceRoute,
            [System.StringComparison]::OrdinalIgnoreCase
        )
        $usesUsage = Test-StringInArray `
            -Values (Get-PropertyValue -InputObject $route -Names @('OnlinePstnUsages')) `
            -Expected $script:PstnUsage
        $usesGateway = $false
        foreach ($gateway in $script:Gateways) {
            if (Test-StringInArray `
                    -Values (Get-PropertyValue -InputObject $route -Names @('OnlinePstnGatewayList')) `
                    -Expected $gateway) {
                $usesGateway = $true
            }
        }
        if (-not $isManaged -and ($usesUsage -or $usesGateway)) {
            throw "Unmanaged voice route '$identity' references this POC's usage or gateways."
        }
    }

    foreach ($policy in $Policies) {
        $identity = Normalize-PolicyName -Value (
            Get-PropertyValue -InputObject $policy -Names @('Identity')
        )
        $isManaged = [string]::Equals(
            $identity,
            $script:VoiceRoutingPolicy,
            [System.StringComparison]::OrdinalIgnoreCase
        )
        $usesUsage = Test-StringInArray `
            -Values (Get-PropertyValue -InputObject $policy -Names @('OnlinePstnUsages')) `
            -Expected $script:PstnUsage
        if (-not $isManaged -and $usesUsage) {
            throw "Unmanaged voice routing policy '$identity' references this POC's PSTN usage."
        }
    }

    $assignedUsers = @(
        Get-CsOnlineUser `
            -Filter "OnlineVoiceRoutingPolicy -eq '$script:VoiceRoutingPolicy'" `
            -ErrorAction Stop
    )
    foreach ($assignedUser in $assignedUsers) {
        $upn = ([string] (Get-PropertyValue -InputObject $assignedUser -Names @('UserPrincipalName'))).ToLowerInvariant()
        if (-not (Test-StringInArray -Values $ManagedUpns -Expected $upn)) {
            throw "Unmanaged user '$upn' is assigned this POC's voice routing policy."
        }
    }
}

function Get-VivolutionSnapshot {
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [Parameter(Mandatory)] [pscustomobject] $TenantContext
    )

    $gateways = @(Get-CsOnlinePSTNGateway -ErrorAction Stop)
    $routes = @(Get-CsOnlineVoiceRoute -ErrorAction Stop)
    $policies = @(Get-CsOnlineVoiceRoutingPolicy -ErrorAction Stop)
    $usageObject = Get-CsOnlinePstnUsage -Identity Global -ErrorAction Stop
    $globalUsages = @(ConvertTo-StringArray -Value (
        Get-PropertyValue -InputObject $usageObject -Names @('Usage')
    ))

    $gatewayPresence = [ordered]@{}
    foreach ($fqdn in $script:Gateways) {
        $gateway = Get-ManagedObject -Objects $gateways -Identity $fqdn
        if ($null -ne $gateway) {
            Assert-GatewayExact -Gateway $gateway -Fqdn $fqdn
            $gatewayPresence[$fqdn] = $true
        }
        else {
            $gatewayPresence[$fqdn] = $false
        }
    }

    $route = Get-ManagedObject -Objects $routes -Identity $script:VoiceRoute
    if ($null -ne $route) {
        Assert-RouteExact -Route $route
    }
    $policy = Get-ManagedObject `
        -Objects $policies `
        -Identity $script:VoiceRoutingPolicy `
        -PolicyIdentity
    if ($null -ne $policy) {
        Assert-PolicyExact -Policy $policy
    }

    $managedUpns = @($Configuration.Users | ForEach-Object { ([string] $_.Upn).ToLowerInvariant() })
    Assert-NoForeignReferences `
        -Routes $routes `
        -Policies $policies `
        -ManagedUpns $managedUpns

    $userStates = @()
    foreach ($expectedUser in @($Configuration.Users)) {
        $upn = ([string] $expectedUser.Upn).ToLowerInvariant()
        $users = @(Get-CsOnlineUser -Identity $upn -ErrorAction Stop)
        if ($users.Count -ne 1) {
            throw "Expected exactly one Teams user '$upn'; found $($users.Count)."
        }
        $phoneAssignments = @(
            Get-CsPhoneNumberAssignment `
                -TelephoneNumber ([string] $expectedUser.TelephoneNumber) `
                -ErrorAction Stop
        )
        $userStates += Assert-UserReady `
            -User $users[0] `
            -ExpectedUser $expectedUser `
            -PhoneAssignments $phoneAssignments
    }

    return [pscustomobject]@{
        SchemaVersion = 1
        CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
        TenantId = $TenantContext.TenantId
        VerifiedDomain = $script:VerifiedDomain
        PstnUsagePresent = Test-StringInArray -Values $globalUsages -Expected $script:PstnUsage
        GatewaysPresent = [pscustomobject] $gatewayPresence
        VoiceRoutePresent = $null -ne $route
        VoiceRoutingPolicyPresent = $null -ne $policy
        Users = $userStates
    }
}

function Invoke-VivolutionPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication
    )

    Assert-VivolutionConfiguration -Configuration $Configuration
    $tenantContext = Connect-VivolutionTenant `
        -Configuration $Configuration `
        -SkipConnect:$SkipConnect `
        -DeviceAuthentication:$DeviceAuthentication
    $snapshot = Get-VivolutionSnapshot `
        -Configuration $Configuration `
        -TenantContext $tenantContext

    return [pscustomobject]@{
        Status = 'READY_FOR_RECONCILIATION'
        ReadOnly = $true
        ConfigurationSha256 = Get-VivolutionConfigurationHash -Configuration $Configuration
        Snapshot = $snapshot
        Limitations = @(
            'OpenSIPS/RTPengine is not a Microsoft-certified SBC and is not Microsoft-supported.',
            'This package configures one tenant and +971-only test routing; it does not enable PSTN or emergency calling.'
        )
    }
}

function Invoke-VivolutionVerification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication
    )

    $preflight = Invoke-VivolutionPreflight `
        -Configuration $Configuration `
        -SkipConnect:$SkipConnect `
        -DeviceAuthentication:$DeviceAuthentication
    $snapshot = $preflight.Snapshot

    if (-not $snapshot.PstnUsagePresent) {
        throw "Managed PSTN usage '$script:PstnUsage' is absent."
    }
    foreach ($fqdn in $script:Gateways) {
        if (-not [bool] $snapshot.GatewaysPresent.$fqdn) {
            throw "Managed gateway '$fqdn' is absent."
        }
    }
    if (-not $snapshot.VoiceRoutePresent) {
        throw "Managed voice route '$script:VoiceRoute' is absent."
    }
    if (-not $snapshot.VoiceRoutingPolicyPresent) {
        throw "Managed voice routing policy '$script:VoiceRoutingPolicy' is absent."
    }
    foreach ($user in @($snapshot.Users)) {
        if (-not $user.NumberExact) {
            throw "User '$($user.Upn)' does not have the expected Direct Routing number."
        }
        if (-not $user.PolicyExact) {
            throw "User '$($user.Upn)' does not have the expected voice routing policy."
        }
        if (-not $user.EnterpriseVoiceEnabled) {
            throw "User '$($user.Upn)' is not Enterprise Voice enabled."
        }
    }

    return [pscustomobject]@{
        Status = 'EXACT_CONFIGURATION_VERIFIED'
        ReadOnly = $true
        ConfigurationSha256 = $preflight.ConfigurationSha256
        Snapshot = $snapshot
    }
}

function Write-VivolutionState {
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $State,
        [Parameter(Mandatory)] [string] $Path
    )

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = '.'
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $json = $State | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8 -NoNewline
    if (-not $IsWindows) {
        & chmod 600 -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to restrict state file permissions on '$Path'."
        }
    }
}

function Read-VivolutionState {
    param([Parameter(Mandatory)] [string] $Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.LinkType) {
        throw "State path '$Path' must not be a symbolic link."
    }
    $state = Get-Content -LiteralPath $Path -Raw -Encoding utf8 |
        ConvertFrom-Json -AsHashtable -Depth 12
    if ([int] $state.SchemaVersion -ne 1) {
        throw 'Unsupported state journal schema.'
    }
    return $state
}

function New-VivolutionState {
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [Parameter(Mandatory)] [pscustomobject] $Snapshot
    )

    $gatewayState = [ordered]@{}
    foreach ($fqdn in $script:Gateways) {
        $gatewayState[$fqdn] = [bool] $Snapshot.GatewaysPresent.$fqdn
    }
    $userState = [ordered]@{}
    foreach ($user in @($Snapshot.Users)) {
        $userState[$user.Upn] = [ordered]@{
            NumberExact = [bool] $user.NumberExact
            PolicyExact = [bool] $user.PolicyExact
        }
    }

    return [ordered]@{
        SchemaVersion = 1
        OperationId = [guid]::NewGuid().ToString()
        Status = 'Prepared'
        CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
        ExpectedTenantId = $script:ExpectedTenantId
        ConfigurationSha256 = Get-VivolutionConfigurationHash -Configuration $Configuration
        Preexisting = [ordered]@{
            PstnUsage = [bool] $Snapshot.PstnUsagePresent
            Gateways = $gatewayState
            VoiceRoute = [bool] $Snapshot.VoiceRoutePresent
            VoiceRoutingPolicy = [bool] $Snapshot.VoiceRoutingPolicyPresent
            Users = $userState
        }
    }
}

function Assert-StateMatchesConfiguration {
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $State,
        [Parameter(Mandatory)] [hashtable] $Configuration
    )

    if (-not [string]::Equals(
            [string] $State.ExpectedTenantId,
            $script:ExpectedTenantId,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The state journal belongs to a different tenant.'
    }
    $hash = Get-VivolutionConfigurationHash -Configuration $Configuration
    if (-not [string]::Equals(
            [string] $State.ConfigurationSha256,
            $hash,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The state journal does not match this exact configuration.'
    }
}

function Assert-StateCompatibleWithSnapshot {
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $State,
        [Parameter(Mandatory)] [pscustomobject] $Snapshot
    )

    if ([bool] $State.Preexisting.PstnUsage -and -not $Snapshot.PstnUsagePresent) {
        throw 'A PSTN usage that predated this package is now missing.'
    }
    foreach ($fqdn in $script:Gateways) {
        if ([bool] $State.Preexisting.Gateways[$fqdn] -and
            -not [bool] $Snapshot.GatewaysPresent.$fqdn) {
            throw "Gateway '$fqdn' predated this package but is now missing."
        }
    }
    if ([bool] $State.Preexisting.VoiceRoute -and -not $Snapshot.VoiceRoutePresent) {
        throw "Voice route '$script:VoiceRoute' predated this package but is now missing."
    }
    if ([bool] $State.Preexisting.VoiceRoutingPolicy -and
        -not $Snapshot.VoiceRoutingPolicyPresent) {
        throw "Voice routing policy '$script:VoiceRoutingPolicy' predated this package but is now missing."
    }
    foreach ($user in @($Snapshot.Users)) {
        $prior = $State.Preexisting.Users[$user.Upn]
        if ($null -eq $prior) {
            throw "State journal has no entry for '$($user.Upn)'."
        }
        if ([bool] $prior.NumberExact -and -not $user.NumberExact) {
            throw "User '$($user.Upn)' had the exact number before apply but no longer has it."
        }
        if ([bool] $prior.PolicyExact -and -not $user.PolicyExact) {
            throw "User '$($user.Upn)' had the exact policy before apply but no longer has it."
        }
    }
}

function Invoke-VivolutionApply {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $Acknowledge,
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication
    )

    if (-not [string]::Equals(
            $Acknowledge,
            $script:ApplyAcknowledgement,
            [System.StringComparison]::Ordinal
        )) {
        throw "Mutation refused. Acknowledge must be exactly: $script:ApplyAcknowledgement"
    }

    $preflight = Invoke-VivolutionPreflight `
        -Configuration $Configuration `
        -SkipConnect:$SkipConnect `
        -DeviceAuthentication:$DeviceAuthentication
    $snapshot = $preflight.Snapshot

    if (-not $PSCmdlet.ShouldProcess(
            $script:ExpectedTenantId,
            'Reconcile the exact Vivolution Direct Routing POC objects and two users'
        )) {
        return [pscustomobject]@{
            Status = 'WHATIF_ONLY'
            TenantId = $script:ExpectedTenantId
            ConfigurationSha256 = $preflight.ConfigurationSha256
        }
    }

    if (Test-Path -LiteralPath $StatePath) {
        $state = Read-VivolutionState -Path $StatePath
        Assert-StateMatchesConfiguration -State $state -Configuration $Configuration
        if ([string] $state.Status -eq 'RolledBack') {
            throw 'This state journal is already rolled back. Use a new state path for a new apply.'
        }
    }
    else {
        $state = New-VivolutionState `
            -Configuration $Configuration `
            -Snapshot $snapshot
        Write-VivolutionState -State $state -Path $StatePath
    }
    Assert-StateCompatibleWithSnapshot -State $state -Snapshot $snapshot

    if (-not $snapshot.PstnUsagePresent) {
        Set-CsOnlinePstnUsage `
            -Identity Global `
            -Usage @{ Add = $script:PstnUsage } `
            -ErrorAction Stop
    }

    foreach ($fqdn in $script:Gateways) {
        if (-not [bool] $snapshot.GatewaysPresent.$fqdn) {
            New-CsOnlinePSTNGateway `
                -Fqdn $fqdn `
                -SipSignalingPort $script:SipSignalingPort `
                -Enabled $true `
                -SendSipOptions $true `
                -MediaBypass $false `
                -ForwardCallHistory $false `
                -ForwardPai $true `
                -FailoverTimeSeconds 10 `
                -FailoverResponseCodes '408,503,504' `
                -MaxConcurrentSessions 20 `
                -IPAddressVersion IPv4 `
                -Description $script:GatewayDescription `
                -ErrorAction Stop | Out-Null
        }
    }

    if (-not $snapshot.VoiceRoutePresent) {
        New-CsOnlineVoiceRoute `
            -Identity $script:VoiceRoute `
            -NumberPattern $script:NumberPattern `
            -OnlinePstnGatewayList $script:Gateways `
            -OnlinePstnUsages @($script:PstnUsage) `
            -ErrorAction Stop | Out-Null
    }
    if (-not $snapshot.VoiceRoutingPolicyPresent) {
        New-CsOnlineVoiceRoutingPolicy `
            -Identity $script:VoiceRoutingPolicy `
            -OnlinePstnUsages @($script:PstnUsage) `
            -ErrorAction Stop | Out-Null
    }

    foreach ($user in @($snapshot.Users)) {
        if (-not $user.NumberExact) {
            Set-CsPhoneNumberAssignment `
                -Identity $user.Upn `
                -TelephoneNumber $user.TelephoneNumber `
                -NumberType DirectRouting `
                -ErrorAction Stop | Out-Null
        }
        if (-not $user.PolicyExact) {
            Grant-CsOnlineVoiceRoutingPolicy `
                -Identity $user.Upn `
                -PolicyName $script:VoiceRoutingPolicy `
                -ErrorAction Stop | Out-Null
        }
    }

    $verification = $null
    $verificationError = $null
    for ($attempt = 1; $attempt -le 7; $attempt++) {
        try {
            $verification = Invoke-VivolutionVerification `
                -Configuration $Configuration `
                -SkipConnect
            break
        }
        catch {
            $verificationError = $_
            if ($attempt -lt 7) {
                Start-Sleep -Seconds 10
            }
        }
    }
    if ($null -eq $verification) {
        throw "Apply finished but exact verification did not converge: $verificationError"
    }

    $state.Status = 'Applied'
    $state.AppliedAtUtc = [DateTime]::UtcNow.ToString('o')
    Write-VivolutionState -State $state -Path $StatePath

    return [pscustomobject]@{
        Status = 'APPLIED_AND_VERIFIED'
        OperationId = $state.OperationId
        StatePath = (Resolve-Path -LiteralPath $StatePath).Path
        Verification = $verification
    }
}

function Assert-RollbackSnapshot {
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $State,
        [Parameter(Mandatory)] [pscustomobject] $Snapshot
    )

    Assert-StateCompatibleWithSnapshot -State $State -Snapshot $Snapshot

    foreach ($fqdn in $script:Gateways) {
        $wasPresent = [bool] $State.Preexisting.Gateways[$fqdn]
        $isPresent = [bool] $Snapshot.GatewaysPresent.$fqdn
        if ($wasPresent -ne $isPresent) {
            throw "Rollback verification failed for gateway '$fqdn'."
        }
    }
    if ([bool] $State.Preexisting.PstnUsage -ne [bool] $Snapshot.PstnUsagePresent) {
        throw 'Rollback verification failed for the global PSTN usage.'
    }
    if ([bool] $State.Preexisting.VoiceRoute -ne [bool] $Snapshot.VoiceRoutePresent) {
        throw 'Rollback verification failed for the managed voice route.'
    }
    if ([bool] $State.Preexisting.VoiceRoutingPolicy -ne
        [bool] $Snapshot.VoiceRoutingPolicyPresent) {
        throw 'Rollback verification failed for the managed voice routing policy.'
    }
    foreach ($user in @($Snapshot.Users)) {
        $prior = $State.Preexisting.Users[$user.Upn]
        if ([bool] $prior.NumberExact -ne [bool] $user.NumberExact) {
            throw "Rollback verification failed for '$($user.Upn)' number assignment."
        }
        if ([bool] $prior.PolicyExact -ne [bool] $user.PolicyExact) {
            throw "Rollback verification failed for '$($user.Upn)' policy assignment."
        }
    }
}

function Invoke-VivolutionRollback {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [hashtable] $Configuration,
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $Acknowledge,
        [switch] $SkipConnect,
        [switch] $DeviceAuthentication
    )

    if (-not [string]::Equals(
            $Acknowledge,
            $script:RollbackAcknowledgement,
            [System.StringComparison]::Ordinal
        )) {
        throw "Mutation refused. Acknowledge must be exactly: $script:RollbackAcknowledgement"
    }
    $state = Read-VivolutionState -Path $StatePath
    Assert-StateMatchesConfiguration -State $state -Configuration $Configuration

    $preflight = Invoke-VivolutionPreflight `
        -Configuration $Configuration `
        -SkipConnect:$SkipConnect `
        -DeviceAuthentication:$DeviceAuthentication
    $snapshot = $preflight.Snapshot

    if ([string] $state.Status -eq 'RolledBack') {
        Assert-RollbackSnapshot -State $state -Snapshot $snapshot
        return [pscustomobject]@{
            Status = 'ALREADY_ROLLED_BACK_AND_VERIFIED'
            OperationId = $state.OperationId
        }
    }
    Assert-StateCompatibleWithSnapshot -State $state -Snapshot $snapshot

    if (-not $PSCmdlet.ShouldProcess(
            $script:ExpectedTenantId,
            "Roll back only changes journaled by operation $($state.OperationId)"
        )) {
        return [pscustomobject]@{
            Status = 'WHATIF_ONLY'
            OperationId = $state.OperationId
        }
    }

    foreach ($user in @($snapshot.Users)) {
        $prior = $state.Preexisting.Users[$user.Upn]
        if (-not [bool] $prior.PolicyExact -and $user.PolicyExact) {
            Grant-CsOnlineVoiceRoutingPolicy `
                -Identity $user.Upn `
                -PolicyName $null `
                -ErrorAction Stop | Out-Null
        }
        if (-not [bool] $prior.NumberExact -and $user.NumberExact) {
            Remove-CsPhoneNumberAssignment `
                -Identity $user.Upn `
                -TelephoneNumber $user.TelephoneNumber `
                -NumberType DirectRouting `
                -ErrorAction Stop | Out-Null
        }
    }

    if (-not [bool] $state.Preexisting.VoiceRoutingPolicy -and
        $snapshot.VoiceRoutingPolicyPresent) {
        Remove-CsOnlineVoiceRoutingPolicy `
            -Identity $script:VoiceRoutingPolicy `
            -Confirm:$false `
            -ErrorAction Stop
    }
    if (-not [bool] $state.Preexisting.VoiceRoute -and $snapshot.VoiceRoutePresent) {
        Remove-CsOnlineVoiceRoute `
            -Identity $script:VoiceRoute `
            -Confirm:$false `
            -ErrorAction Stop
    }
    for ($gatewayIndex = $script:Gateways.Count - 1; $gatewayIndex -ge 0; $gatewayIndex--) {
        $fqdn = $script:Gateways[$gatewayIndex]
        if (-not [bool] $state.Preexisting.Gateways[$fqdn] -and
            [bool] $snapshot.GatewaysPresent.$fqdn) {
            Remove-CsOnlinePSTNGateway `
                -Identity $fqdn `
                -Confirm:$false `
                -ErrorAction Stop
        }
    }
    if (-not [bool] $state.Preexisting.PstnUsage -and $snapshot.PstnUsagePresent) {
        Set-CsOnlinePstnUsage `
            -Identity Global `
            -Usage @{ Remove = $script:PstnUsage } `
            -ErrorAction Stop
    }

    $finalPreflight = Invoke-VivolutionPreflight `
        -Configuration $Configuration `
        -SkipConnect
    Assert-RollbackSnapshot -State $state -Snapshot $finalPreflight.Snapshot

    $state.Status = 'RolledBack'
    $state.RolledBackAtUtc = [DateTime]::UtcNow.ToString('o')
    Write-VivolutionState -State $state -Path $StatePath

    return [pscustomobject]@{
        Status = 'EXACT_ROLLBACK_VERIFIED'
        OperationId = $state.OperationId
        StatePath = (Resolve-Path -LiteralPath $StatePath).Path
    }
}

Export-ModuleMember -Function @(
    'Import-VivolutionConfiguration',
    'Invoke-VivolutionTenantDiscovery',
    'Invoke-VivolutionPreflight',
    'Invoke-VivolutionVerification',
    'Invoke-VivolutionApply',
    'Invoke-VivolutionRollback'
)
