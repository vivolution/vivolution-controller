import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("pwsh")


@unittest.skipUnless(POWERSHELL, "PowerShell is required for behavioral discovery tests")
class Microsoft365DiscoveryBehaviorTests(unittest.TestCase):
    def test_discovery_and_preflight_require_exact_active_user_account(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            # Use a deliberately newer fake so module auto-discovery cannot
            # select an installed real MicrosoftTeams module.
            module_directory = temporary_root / "MicrosoftTeams" / "99.0.0"
            module_directory.mkdir(parents=True)
            (module_directory / "MicrosoftTeams.psd1").write_text(
                textwrap.dedent(
                    """
                    @{
                        RootModule = 'MicrosoftTeams.psm1'
                        ModuleVersion = '99.0.0'
                        GUID = '7ec47861-0f88-4772-8f4b-66f7f70fdceb'
                        FunctionsToExport = @(
                            'Connect-MicrosoftTeams',
                            'Get-CsTenant',
                            'Get-CsOnlineUser',
                            'Get-CsPhoneNumberAssignment',
                            'Get-CsOnlinePSTNGateway',
                            'Get-CsOnlinePstnUsage',
                            'Get-CsOnlineVoiceRoute',
                            'Get-CsOnlineVoiceRoutingPolicy'
                        )
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (module_directory / "MicrosoftTeams.psm1").write_text(
                textwrap.dedent(
                    """
                    function Connect-MicrosoftTeams {
                        [CmdletBinding()]
                        param([string] $TenantId)
                    }

                    function Get-CsTenant {
                        [CmdletBinding()]
                        param()
                        [pscustomobject]@{
                            TenantId = '151cd01a-1e81-40a9-b898-d8646e1a8760'
                            Domains = @('vivolution.ae')
                        }
                    }

                    function Get-CsOnlineUser {
                        [CmdletBinding()]
                        param([string] $Identity, [string] $Filter)
                        $softDeletionTimestamp = if (
                            $env:VIVO_TEST_SOFT_DELETED -eq 'true'
                        ) {
                            [datetime]'2026-08-30T00:00:00Z'
                        }
                        else {
                            $null
                        }
                        [pscustomobject]@{
                            UserPrincipalName = 'jay@vivolution.ae'
                            AccountEnabled = $true
                            AccountType = $env:VIVO_TEST_ACCOUNT_TYPE
                            SoftDeletionTimestamp = $softDeletionTimestamp
                            FeatureTypes = @('Teams', 'PhoneSystem')
                            RegistrarPool = 'sippool-ae1.infra.lync.com'
                            OnPremLineURI = $null
                            TeamsUpgradeEffectiveMode = 'TeamsOnly'
                            LineURI = $null
                            OnlineVoiceRoutingPolicy = $null
                            EnterpriseVoiceEnabled = $false
                        }
                    }

                    function Get-CsPhoneNumberAssignment {
                        [CmdletBinding()]
                        param()
                    }
                    function Get-CsOnlinePSTNGateway {
                        [CmdletBinding()]
                        param()
                    }
                    function Get-CsOnlinePstnUsage {
                        [CmdletBinding()]
                        param()
                    }
                    function Get-CsOnlineVoiceRoute {
                        [CmdletBinding()]
                        param()
                    }
                    function Get-CsOnlineVoiceRoutingPolicy {
                        [CmdletBinding()]
                        param()
                    }

                    Export-ModuleMember -Function @(
                        'Connect-MicrosoftTeams',
                        'Get-CsTenant',
                        'Get-CsOnlineUser',
                        'Get-CsPhoneNumberAssignment',
                        'Get-CsOnlinePSTNGateway',
                        'Get-CsOnlinePstnUsage',
                        'Get-CsOnlineVoiceRoute',
                        'Get-CsOnlineVoiceRoutingPolicy'
                    )
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            module_path = str(ROOT / "Vivolution.DirectRouting.psm1").replace(
                "'", "''"
            )
            fake_module_path = str(
                module_directory / "MicrosoftTeams.psd1"
            ).replace("'", "''")
            runner = temporary_root / "test-discovery.ps1"
            runner.write_text(
                textwrap.dedent(
                    f"""
                    $ErrorActionPreference = 'Stop'
                    Import-Module '{fake_module_path}' -Force
                    Import-Module '{module_path}' -Force
                    $vivolutionModule = Get-Module Vivolution.DirectRouting
                    $mockedDiscovery = {{
                        function Get-CsTenant {{
                            [CmdletBinding()]
                            param()
                            [pscustomobject]@{{
                                TenantId = '151cd01a-1e81-40a9-b898-d8646e1a8760'
                                Domains = @('vivolution.ae')
                            }}
                        }}
                        function Get-CsOnlineUser {{
                            [CmdletBinding()]
                            param([string] $Identity, [string] $Filter)
                            $softDeletionTimestamp = if (
                                $env:VIVO_TEST_SOFT_DELETED -eq 'true'
                            ) {{
                                [datetime]'2026-08-30T00:00:00Z'
                            }}
                            else {{
                                $null
                            }}
                            [pscustomobject]@{{
                                UserPrincipalName = 'jay@vivolution.ae'
                                AccountEnabled = $true
                                AccountType = $env:VIVO_TEST_ACCOUNT_TYPE
                                SoftDeletionTimestamp = $softDeletionTimestamp
                                FeatureTypes = @('Teams', 'PhoneSystem')
                                RegistrarPool = 'sippool-ae1.infra.lync.com'
                                OnPremLineURI = $null
                                TeamsUpgradeEffectiveMode = 'TeamsOnly'
                                LineURI = $null
                                OnlineVoiceRoutingPolicy = $null
                                EnterpriseVoiceEnabled = $false
                            }}
                        }}
                        Invoke-VivolutionTenantDiscovery -SkipConnect
                    }}
                    $mockedUserReadiness = {{
                        $softDeletionTimestamp = if (
                            $env:VIVO_TEST_SOFT_DELETED -eq 'true'
                        ) {{
                            [datetime]'2026-08-30T00:00:00Z'
                        }}
                        else {{
                            $null
                        }}
                        $user = [pscustomobject]@{{
                            UserPrincipalName = 'jay@vivolution.ae'
                            AccountEnabled = $true
                            AccountType = $env:VIVO_TEST_ACCOUNT_TYPE
                            SoftDeletionTimestamp = $softDeletionTimestamp
                            FeatureTypes = @('Teams', 'PhoneSystem')
                            RegistrarPool = 'sippool-ae1.infra.lync.com'
                            OnPremLineURI = $null
                            TeamsUpgradeEffectiveMode = 'TeamsOnly'
                            LineURI = $null
                            OnlineVoiceRoutingPolicy = $null
                            EnterpriseVoiceEnabled = $false
                        }}
                        $expected = @{{
                            Upn = 'jay@vivolution.ae'
                            TelephoneNumber = '+971501234567'
                        }}
                        Assert-UserReady `
                            -User $user `
                            -ExpectedUser $expected `
                            -PhoneAssignments @()
                    }}

                    $cases = @(
                        [pscustomobject]@{{
                            Name = 'User'
                            AccountType = 'User'
                            SoftDeleted = 'false'
                            Expected = $true
                        }},
                        [pscustomobject]@{{
                            Name = 'case-insensitive user'
                            AccountType = 'user'
                            SoftDeleted = 'false'
                            Expected = $true
                        }},
                        [pscustomobject]@{{
                            Name = 'resource account'
                            AccountType = 'ResourceAccount'
                            SoftDeleted = 'false'
                            Expected = $false
                        }},
                        [pscustomobject]@{{
                            Name = 'on-premises user'
                            AccountType = 'SfBOnPremUser'
                            SoftDeleted = 'false'
                            Expected = $false
                        }},
                        [pscustomobject]@{{
                            Name = 'guest'
                            AccountType = 'Guest'
                            SoftDeleted = 'false'
                            Expected = $false
                        }},
                        [pscustomobject]@{{
                            Name = 'ineligible'
                            AccountType = 'IneligibleUser'
                            SoftDeleted = 'false'
                            Expected = $false
                        }},
                        [pscustomobject]@{{
                            Name = 'missing account type'
                            AccountType = ''
                            SoftDeleted = 'false'
                            Expected = $false
                        }},
                        [pscustomobject]@{{
                            Name = 'soft deleted user'
                            AccountType = 'User'
                            SoftDeleted = 'true'
                            Expected = $false
                        }}
                    )

                    foreach ($case in $cases) {{
                        $env:VIVO_TEST_ACCOUNT_TYPE = $case.AccountType
                        $env:VIVO_TEST_SOFT_DELETED = $case.SoftDeleted
                        $succeeded = $false
                        $failure = ''
                        try {{
                            $result = & $vivolutionModule $mockedDiscovery
                            if ($result.Status -ne 'READY_FOR_NUMBER_SELECTION') {{
                                throw "Unexpected discovery status '$($result.Status)'."
                            }}
                            if ($result.ReadOnly -ne $true) {{
                                throw 'Discovery did not identify itself as read-only.'
                            }}
                            $succeeded = $true
                        }}
                        catch {{
                            $failure = ($_ | Out-String).Trim()
                        }}
                        if ($succeeded -ne $case.Expected) {{
                            throw (
                                "Case '$($case.Name)' expected success=$($case.Expected), " +
                                "observed success=$succeeded; failure='$failure'."
                            )
                        }}

                        $readinessSucceeded = $false
                        $readinessFailure = ''
                        try {{
                            $null = & $vivolutionModule $mockedUserReadiness
                            $readinessSucceeded = $true
                        }}
                        catch {{
                            $readinessFailure = ($_ | Out-String).Trim()
                        }}
                        if ($readinessSucceeded -ne $case.Expected) {{
                            throw (
                                "Assert-UserReady case '$($case.Name)' expected " +
                                "success=$($case.Expected), observed " +
                                "success=$readinessSucceeded; " +
                                "failure='$readinessFailure'."
                            )
                        }}
                    }}
                    'M365_DISCOVERY_ACCOUNT_GATES_OK'
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PSModulePath"] = str(temporary_root)
            completed = subprocess.run(
                [POWERSHELL, "-NoLogo", "-NoProfile", "-File", str(runner)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertIn("M365_DISCOVERY_ACCOUNT_GATES_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
