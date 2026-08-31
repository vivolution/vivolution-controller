from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = (ROOT / "Vivolution.DirectRouting.psm1").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
CONFIG = (ROOT / "config.example.psd1").read_text(encoding="utf-8")


class Microsoft365OnboardingStaticTests(unittest.TestCase):
    def test_contract_is_locked_to_expected_tenant_fqdns_and_uae_route(self):
        for value in (
            "151cd01a-1e81-40a9-b898-d8646e1a8760",
            "vivolution.ae",
            "sbc1.vivolution.ae",
            "sbc2.vivolution.ae",
            "SipSignalingPort = 5061",
            "^(?:\\+971000000200[12]|\\+971[1-9][0-9]{7,8})$",
            "^\\+971[1-9][0-9]{7,8}$",
        ):
            self.assertIn(value, MODULE + CONFIG)
        self.assertIn("One or two test users must be supplied", MODULE)
        self.assertIn("$users.Count -lt 1 -or $users.Count -gt 2", MODULE)
        self.assertIn("must be in the verified vivolution.ae domain", MODULE)
        self.assertIn("$number -notmatch $script:UserNumberPattern", MODULE)
        self.assertIn("+9710000002001", README)
        self.assertIn("+9710000002002", README)
        self.assertNotIn("@voice\\.vivolution\\.ae", MODULE)

    def test_preflight_checks_tenant_domain_and_user_readiness(self):
        for value in (
            "Connect-MicrosoftTeams -TenantId",
            "Get-CsTenant",
            "Get-TenantDomains",
            "Get-CsOnlineUser -Identity",
            "Get-CsPhoneNumberAssignment",
            "@('Teams', 'PhoneSystem')",
            "TeamsUpgradeEffectiveMode",
            "infra\\.lync\\.com",
            "OnPremLineURI",
            "Assert-NoForeignReferences",
        ):
            self.assertIn(value, MODULE)

    def test_explicit_device_authentication_is_without_wam_and_fail_closed(self):
        authentication_body = MODULE.split(
            "function Connect-VivolutionMicrosoftTeams", 1
        )[
            1
        ].split("function Connect-VivolutionTenant", 1)[0]
        connection_body = MODULE.split("function Connect-VivolutionTenant", 1)[
            1
        ].split("function Invoke-VivolutionTenantDiscovery", 1)[0]
        for value in (
            "if (-not $DeviceAuthentication)",
            "Connect-MicrosoftTeams -TenantId",
            "@('UseDeviceAuthentication', 'DisableWAM')",
            "-UseDeviceAuthentication",
            "-DisableWAM",
            "authentication fallback is refused",
        ):
            self.assertIn(value, authentication_body)
        self.assertLess(
            authentication_body.index("$connectCommand.Parameters.ContainsKey"),
            authentication_body.index("-UseDeviceAuthentication"),
        )
        self.assertIn(
            "-DeviceAuthentication:$DeviceAuthentication",
            connection_body,
        )
        self.assertIn(
            "-SkipConnect and -DeviceAuthentication cannot be combined",
            connection_body,
        )
        for value in (
            "On macOS and Linux, select the explicit `-DeviceAuthentication` mode",
            "ordinary browser",
            "extension, debugging mode, or WAM",
            "including on Windows",
            "pwsh -NoLogo -NoProfile -File ./Invoke-Discovery.ps1 -DeviceAuthentication",
        ):
            self.assertIn(value, README)

        for name in (
            "Invoke-Discovery.ps1",
            "Invoke-Preflight.ps1",
            "Invoke-Apply.ps1",
            "Invoke-Verify.ps1",
            "Invoke-Rollback.ps1",
        ):
            wrapper = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("[switch] $DeviceAuthentication", wrapper, name)
            self.assertIn("-DeviceAuthentication:$DeviceAuthentication", wrapper, name)

    def test_discovery_is_number_independent_and_read_only(self):
        discovery = (ROOT / "Invoke-Discovery.ps1").read_text(encoding="utf-8")
        discovery_body = MODULE.split(
            "function Invoke-VivolutionTenantDiscovery", 1
        )[1].split("function Get-ManagedObject", 1)[0]
        connection_body = MODULE.split("function Connect-VivolutionTenant", 1)[
            1
        ].split("function Invoke-VivolutionTenantDiscovery", 1)[0]
        read_only_contract_body = MODULE.split(
            "function Assert-TeamsReadOnlyModuleContract", 1
        )[1].split("function Assert-TeamsModuleContract", 1)[0]
        tenant_domains_body = MODULE.split("function Get-TenantDomains", 1)[1].split(
            "function Connect-VivolutionTenant", 1
        )[0]
        account_gate_body = MODULE.split(
            "function Assert-InteractiveTeamsUserAccount", 1
        )[1].split("function Get-VivolutionConfigurationHash", 1)[0]
        user_ready_body = MODULE.split("function Assert-UserReady", 1)[1].split(
            "function Assert-NoForeignReferences", 1
        )[0]
        for value in (
            "Invoke-VivolutionTenantDiscovery",
            "jay@vivolution.ae",
            "READY_FOR_NUMBER_SELECTION",
            "EXISTING_NUMBER_REQUIRES_EXACT_REVIEW",
            "RequiredFeatureTypes = @('PhoneSystem', 'Teams')",
            "No Direct Routing number has been selected or assigned",
            "not an evidence-bound CP1 M365 verification receipt",
        ):
            self.assertIn(value, MODULE + discovery)
        self.assertNotIn("TelephoneNumber", discovery)
        mutation_pattern = re.compile(
            r"(?:New|Set|Remove|Grant)-Cs(?:Online|Phone)", re.IGNORECASE
        )
        for name, body in (
            ("wrapper", discovery),
            ("discovery", discovery_body),
            ("connection", connection_body),
            ("read-only module contract", read_only_contract_body),
            ("tenant domains", tenant_domains_body),
            ("account gate", account_gate_body),
        ):
            self.assertNotRegex(body, mutation_pattern, name)
        self.assertIn("-ReadOnlyContract", discovery_body)
        self.assertIn("Assert-InteractiveTeamsUserAccount", discovery_body)
        self.assertIn("Assert-InteractiveTeamsUserAccount", user_ready_body)
        self.assertIn("'User'", account_gate_body)
        self.assertIn("SoftDeletionTimestamp", account_gate_body)

    def test_mutations_require_exact_acknowledgements(self):
        apply_ack = (
            "APPLY VIVOLUTION DIRECT ROUTING POC TO "
            "151cd01a-1e81-40a9-b898-d8646e1a8760"
        )
        rollback_ack = (
            "ROLL BACK VIVOLUTION DIRECT ROUTING POC FROM "
            "151cd01a-1e81-40a9-b898-d8646e1a8760"
        )
        self.assertIn(apply_ack, MODULE)
        self.assertIn(rollback_ack, MODULE)
        self.assertGreaterEqual(MODULE.count("[System.StringComparison]::Ordinal"), 2)

    def test_global_pstn_usage_is_add_remove_only(self):
        self.assertRegex(
            MODULE,
            r"Set-CsOnlinePstnUsage\s+`\s+-Identity Global\s+`\s+"
            r"-Usage @\{ Add = \$script:PstnUsage \}",
        )
        self.assertRegex(
            MODULE,
            r"Set-CsOnlinePstnUsage\s+`\s+-Identity Global\s+`\s+"
            r"-Usage @\{ Remove = \$script:PstnUsage \}",
        )
        self.assertNotRegex(MODULE, r"(?i)@\{\s*replace\s*=")

    def test_state_is_written_before_first_cloud_mutation(self):
        apply_body = MODULE.split("function Invoke-VivolutionApply", 1)[1]
        apply_body = apply_body.split("function Assert-RollbackSnapshot", 1)[0]
        self.assertLess(
            apply_body.index("Write-VivolutionState -State $state -Path $StatePath"),
            apply_body.index("Set-CsOnlinePstnUsage"),
        )
        self.assertIn("ConfigurationSha256", apply_body)
        self.assertIn("Assert-StateCompatibleWithSnapshot", apply_body)

    def test_current_phone_assignment_cmdlet_parameters_are_used(self):
        self.assertIn("Set-CsPhoneNumberAssignment", MODULE)
        self.assertIn("Remove-CsPhoneNumberAssignment", MODULE)
        self.assertGreaterEqual(MODULE.count("-TelephoneNumber"), 3)
        self.assertGreaterEqual(MODULE.count("-NumberType DirectRouting"), 2)
        self.assertNotIn("-PhoneNumberType DirectRouting", MODULE)

    def test_rollback_is_reverse_order_and_journal_scoped(self):
        rollback = MODULE.split("function Invoke-VivolutionRollback", 1)[1]
        positions = [
            rollback.index("Grant-CsOnlineVoiceRoutingPolicy"),
            rollback.index("Remove-CsPhoneNumberAssignment"),
            rollback.index("Remove-CsOnlineVoiceRoutingPolicy"),
            rollback.index("Remove-CsOnlineVoiceRoute"),
            rollback.index("Remove-CsOnlinePSTNGateway"),
            rollback.index("Set-CsOnlinePstnUsage"),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("State.Preexisting", MODULE)
        self.assertIn("Assert-RollbackSnapshot", rollback)

    def test_read_only_wrappers_contain_no_mutation_cmdlets(self):
        mutation_pattern = re.compile(
            r"(?:New|Set|Remove|Grant)-Cs(?:Online|Phone)", re.IGNORECASE
        )
        for name in (
            "Invoke-Discovery.ps1",
            "Invoke-Preflight.ps1",
            "Invoke-Verify.ps1",
        ):
            content = (ROOT / name).read_text(encoding="utf-8")
            self.assertIsNone(mutation_pattern.search(content), name)

    def test_documentation_records_support_and_live_blocks(self):
        for value in (
            "guest directory",
            "registered-domain, SKU, user-license, Teams-homing, and number state remain",
            "jay@vivolution.ae",
            "PENDING_EVIDENCE_BOUND_CP1_VERIFICATION",
            "Checked against Microsoft Learn on 2026-08-30",
            "-WhatIf",
        ):
            self.assertIn(value, README)
        self.assertRegex(
            README,
            r"(?s)not a Microsoft-certified\s+SBC and is not supported by Microsoft",
        )


if __name__ == "__main__":
    unittest.main()
