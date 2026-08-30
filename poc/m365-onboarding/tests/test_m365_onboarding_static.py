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
            "voice.vivolution.ae",
            "sbc1.voice.vivolution.ae",
            "sbc2.voice.vivolution.ae",
            "SipSignalingPort = 5061",
            "^\\+971[1-9][0-9]{7,8}$",
        ):
            self.assertIn(value, MODULE + CONFIG)
        self.assertIn("Exactly two test users must be supplied", MODULE)
        self.assertIn("must be in the verified voice.vivolution.ae domain", MODULE)

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
        for name in ("Invoke-Preflight.ps1", "Invoke-Verify.ps1"):
            content = (ROOT / name).read_text(encoding="utf-8")
            self.assertIsNone(mutation_pattern.search(content), name)

    def test_documentation_records_support_and_live_blocks(self):
        for value in (
            "guest directory",
            "registered-domain, SKU, user-license, Teams-homing, and number state remain",
            "jay@vivolution.ae",
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
