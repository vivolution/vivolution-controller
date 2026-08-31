from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RootDirectDnsAcmeStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entrypoint = (ROOT / "root-direct-dns-acme.bicep").read_text()
        self.module = (
            ROOT / "modules" / "root-direct-dns-acme-zone.bicep"
        ).read_text()
        self.wrapper = (ROOT / "deploy_root_direct_dns_acme.py").read_text()
        self.contract = (ROOT / "root_direct_dns_acme_contract.py").read_text()
        self.teardown = (ROOT / "teardown_root_direct_dns_acme.py").read_text()
        self.readme = (ROOT / "root-direct-dns-acme-README.md").read_text()

    def test_root_authority_is_additive_exact_and_has_no_wildcard(self) -> None:
        self.assertIn("'vivolution.ae'", self.entrypoint)
        for value in ("'sbc1'", "'sbc2'", "'carrier'"):
            self.assertIn(value, self.module)
        self.assertEqual(self.module.count("'Microsoft.Network/dnsZones/A@"), 3)
        self.assertEqual(self.module.count("'Microsoft.Network/dnsZones/NS@"), 3)
        self.assertEqual(self.module.count("'Microsoft.Network/dnsZones/CNAME@"), 3)
        self.assertNotIn("wildcard", self.module.lower())
        self.assertNotIn("name: 'voice.vivolution.ae'", self.module)
        self.assertNotIn("controller", self.module)

    def test_three_child_zones_have_txt_only_identity_authority(self) -> None:
        for value in (
            "acme-sbc1.${dnsZoneName}",
            "acme-sbc2.${dnsZoneName}",
            "acme-carrier.${dnsZoneName}",
        ):
            self.assertIn(value, self.module)
        self.assertIn("DIRECT_ROUTING_PRIVATE_PBX_POC", self.module)
        self.assertIn("direct-routing-private-pbx-poc-acme-dns01", self.module)
        self.assertNotIn("Microsoft.Authorization/locks", self.module)
        self.assertNotIn("Microsoft.Network/dnsZones/TXT@", self.module)
        self.assertEqual(self.module.count("principalType: 'ServicePrincipal'"), 3)
        self.assertIn("scope: sbc1AcmeZone", self.module)
        self.assertIn("scope: sbc2AcmeZone", self.module)
        self.assertIn("scope: carrierAcmeZone", self.module)
        for action in (
            "Microsoft.Network/dnszones/read",
            "Microsoft.Network/dnszones/TXT/read",
            "Microsoft.Network/dnszones/TXT/write",
            "Microsoft.Network/dnszones/TXT/delete",
            "Microsoft.ResourceGraph/resources/read",
        ):
            self.assertEqual(self.entrypoint.count(action), 1)
        self.assertNotIn("Microsoft.Network/dnszones/write", self.entrypoint)
        self.assertNotIn("Microsoft.Network/dnszones/delete", self.entrypoint)

    def test_example_is_bound_to_the_separate_entrypoint(self) -> None:
        example = (ROOT / "root-direct-dns-acme.example.bicepparam").read_text()
        self.assertIn("using './root-direct-dns-acme.bicep'", example)
        self.assertEqual(example.count("192.0.2."), 3)
        self.assertEqual(example.count("00000000-0000-0000-0000-00000000000"), 3)

    def test_create_is_only_reachable_through_fresh_plan_bound_wrapper(self) -> None:
        for value in (
            "root-direct-dns-acme.bicepparam",
            "root-direct-dns-acme-create-plan.json",
            "compiledParametersSha256",
            "compiledTemplateSha256",
            "parameterFileSha256",
            "provider What-If",
            "--validation-level", "Provider",
            "PLAN_MAX_AGE_MINUTES = 10",
            "APPLY-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY",
            "observationSha256",
            "reserved root names/resources were not vacant",
            "len(changes) != 16",
            "Azure authority changed after create planning",
        ):
            self.assertIn(value, self.wrapper)
        self.assertNotIn("az deployment sub create", self.readme)
        self.assertIn("deploy_root_direct_dns_acme.py plan", self.readme)
        self.assertIn("deploy_root_direct_dns_acme.py execute", self.readme)

    def test_partial_create_and_rbac_descendants_are_fail_closed(self) -> None:
        self.assertIn("PARTIAL_EXACT", self.wrapper)
        self.assertIn("Every exact partial create/teardown state", self.teardown)
        self.assertIn("--include-groups", self.contract)
        self.assertIn("subscription-wide direct RBAC assignments", self.contract)
        self.assertIn('scope_lower.startswith(owned + "/")', self.contract)
        self.assertIn("principalType", self.contract)


if __name__ == "__main__":
    unittest.main()
