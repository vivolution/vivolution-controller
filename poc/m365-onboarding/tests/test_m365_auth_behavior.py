import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("pwsh")
EXPECTED_TENANT_ID = "151cd01a-1e81-40a9-b898-d8646e1a8760"


def _run_authentication(
    root: Path,
    marker: Path,
    *,
    device_parameters: bool,
    request_device_authentication: bool,
) -> subprocess.CompletedProcess[str]:
    module_path = str(ROOT / "Vivolution.DirectRouting.psm1").replace("'", "''")
    authentication_parameters = (
        ", [switch] $UseDeviceAuthentication, [switch] $DisableWAM"
        if device_parameters
        else ""
    )
    authentication_record = (
        "UseDeviceAuthentication = [bool] $UseDeviceAuthentication\n"
        "                    DisableWAM = [bool] $DisableWAM"
        if device_parameters
        else "UseDeviceAuthentication = $false\n"
        "                    DisableWAM = $false"
    )
    runner = root / "invoke-authentication.ps1"
    runner.write_text(
        textwrap.dedent(
            f"""
            $ErrorActionPreference = 'Stop'
            Import-Module '{module_path}' -Force
            $vivolutionModule = Get-Module Vivolution.DirectRouting
            $authentication = {{
                function Connect-MicrosoftTeams {{
                    [CmdletBinding()]
                    param([string] $TenantId{authentication_parameters})
                    [ordered]@{{
                        TenantId = $TenantId
                        {authentication_record}
                    }} | ConvertTo-Json -Compress |
                        Set-Content -LiteralPath $env:VIVO_AUTH_MARKER -NoNewline
                }}
                Connect-VivolutionMicrosoftTeams `
                    -TenantId '{EXPECTED_TENANT_ID}' `
                    -DeviceAuthentication:${str(request_device_authentication).lower()}
            }}
            & $vivolutionModule $authentication
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["VIVO_AUTH_MARKER"] = str(marker)
    return subprocess.run(
        [POWERSHELL, "-NoLogo", "-NoProfile", "-File", str(runner)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )


@unittest.skipUnless(POWERSHELL, "PowerShell is required for authentication tests")
class Microsoft365AuthenticationBehaviorTests(unittest.TestCase):
    def test_every_operator_flow_exposes_device_authentication(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            module_path = str(ROOT / "Vivolution.DirectRouting.psm1").replace(
                "'", "''"
            )
            runner = root / "inspect-parameters.ps1"
            runner.write_text(
                textwrap.dedent(
                    f"""
                    $ErrorActionPreference = 'Stop'
                    Import-Module '{module_path}' -Force
                    foreach ($name in @(
                        'Invoke-VivolutionTenantDiscovery',
                        'Invoke-VivolutionPreflight',
                        'Invoke-VivolutionApply',
                        'Invoke-VivolutionVerification',
                        'Invoke-VivolutionRollback'
                    )) {{
                        $command = Get-Command $name -ErrorAction Stop
                        if (-not $command.Parameters.ContainsKey('DeviceAuthentication')) {{
                            throw "$name has no DeviceAuthentication parameter."
                        }}
                    }}
                    'M365_DEVICE_AUTHENTICATION_INTERFACE_OK'
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [POWERSHELL, "-NoLogo", "-NoProfile", "-File", str(runner)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertIn(
                "M365_DEVICE_AUTHENTICATION_INTERFACE_OK",
                completed.stdout,
            )

    def test_explicit_device_authentication_preserves_tenant_binding(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "authentication.json"
            completed = _run_authentication(
                root,
                marker,
                device_parameters=True,
                request_device_authentication=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            record = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(record["TenantId"], EXPECTED_TENANT_ID)
            self.assertTrue(record["UseDeviceAuthentication"])
            self.assertTrue(record["DisableWAM"])

    def test_default_authentication_does_not_force_device_or_disable_wam(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "authentication.json"
            completed = _run_authentication(
                root,
                marker,
                device_parameters=True,
                request_device_authentication=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            record = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(record["TenantId"], EXPECTED_TENANT_ID)
            self.assertFalse(record["UseDeviceAuthentication"])
            self.assertFalse(record["DisableWAM"])

    def test_device_mode_refuses_module_without_device_parameters(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "authentication.json"
            completed = _run_authentication(
                root,
                marker,
                device_parameters=False,
                request_device_authentication=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "Device-code MicrosoftTeams authentication requires",
                completed.stdout + completed.stderr,
            )
            self.assertIn("authentication fallback is refused", completed.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
