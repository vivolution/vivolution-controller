from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import preflight  # noqa: E402


KEY_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"k" * 32
KEY = "ssh-ed25519 " + base64.b64encode(KEY_BLOB).decode("ascii") + " test"
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).decode("ascii").rstrip("=")
ADMINS = ["8.8.8.8/32"]


def document():
    values = dict(preflight.FIXED_VALUES)
    values.update(
        {
            "administratorSourcePrefixes": ADMINS,
            "edgeRuntimeProfile": "SYNTHETIC_PRIVATE",
            "enableSyntheticVoiceFixture": True,
            "microsoftSignalingSourcePrefixes": sorted(preflight.MICROSOFT_DIRECT_ROUTING_CIDRS),
            "microsoftMediaSourcePrefixes": sorted(preflight.MICROSOFT_DIRECT_ROUTING_CIDRS),
            "syntheticTeamsSourcePrefixes": ["10.20.1.4/32"],
            "sbc1PbxSourcePrefixes": ["10.20.1.4/32"],
            "sbc2PbxSourcePrefixes": ["10.20.1.4/32"],
            "sbc1PbxMediaDestinationPortStart": 21000,
            "sbc1PbxMediaDestinationPortEnd": 21127,
            "sbc2PbxMediaDestinationPortStart": 21000,
            "sbc2PbxMediaDestinationPortEnd": 21127,
            "sshPublicKey": KEY,
        }
    )
    return {"parameters": {name: {"value": value} for name, value in values.items()}}


class PreflightTests(unittest.TestCase):
    def validate(self, value):
        return preflight.validate_parameters(
            value,
            approved_admin_cidrs=ADMINS,
            expected_ssh_fingerprint=FINGERPRINT,
        )

    def test_reviewed_parameters_pass(self):
        evidence = self.validate(document())
        self.assertEqual(evidence["status"], "POC_DEPLOYMENT_INPUTS_VALID")
        self.assertEqual(
            evidence["microsoftMediaProcessorUdpPortRanges"],
            ["3478-3481", "49152-53247"],
        )
        self.assertEqual(evidence["edgeRuntimeProfile"], "SYNTHETIC_PRIVATE")
        self.assertEqual(
            evidence["fixedNtpServerPrefixes"],
            ["162.159.200.1/32", "162.159.200.123/32"],
        )

    def test_wildcard_admin_is_rejected(self):
        value = document()
        value["parameters"]["administratorSourcePrefixes"]["value"] = ["0.0.0.0/0"]
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

    def test_unapproved_admin_is_rejected(self):
        value = document()
        value["parameters"]["administratorSourcePrefixes"]["value"] = ["1.1.1.1/32"]
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

    def test_broad_or_stale_microsoft_ranges_are_rejected(self):
        for candidate in (["0.0.0.0/0"], ["52.112.0.0/14"]):
            with self.subTest(candidate=candidate):
                value = document()
                value["parameters"]["microsoftMediaSourcePrefixes"]["value"] = candidate
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)

    def test_reviewed_signaling_supernets_contain_current_52_114_hubs(self):
        signaling = [
            ipaddress.ip_network(cidr)
            for cidr in preflight.MICROSOFT_DIRECT_ROUTING_CIDRS
        ]
        for current_hub_example in (
            "52.114.14.70",
            "52.114.75.24",
            "52.114.132.46",
        ):
            address = ipaddress.ip_address(current_hub_example)
            self.assertTrue(any(address in network for network in signaling))

    def test_source_prefix_arrays_require_canonical_network_order(self):
        value = document()
        value["parameters"]["microsoftMediaSourcePrefixes"]["value"] = [
            "52.120.0.0/14",
            "52.112.0.0/14",
        ]
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

    def test_external_pbx_cannot_be_smuggled_into_fixture_profile(self):
        value = document()
        value["parameters"]["sbc1PbxSourcePrefixes"]["value"] = ["203.0.113.1/32"]
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

    def test_direct_profile_requires_external_pbx_and_removes_fixture(self):
        value = document()
        value["parameters"]["edgeRuntimeProfile"]["value"] = "DIRECT_ROUTING"
        value["parameters"]["enableSyntheticVoiceFixture"]["value"] = False
        value["parameters"]["syntheticTeamsSourcePrefixes"]["value"] = []
        value["parameters"]["sbc1PbxSourcePrefixes"]["value"] = ["8.8.8.8/32"]
        value["parameters"]["sbc2PbxSourcePrefixes"]["value"] = ["1.1.1.1/32"]
        value["parameters"]["sbc1PbxMediaDestinationPortStart"]["value"] = 30000
        value["parameters"]["sbc1PbxMediaDestinationPortEnd"]["value"] = 30127
        value["parameters"]["sbc2PbxMediaDestinationPortStart"]["value"] = 30000
        value["parameters"]["sbc2PbxMediaDestinationPortEnd"]["value"] = 30127
        evidence = self.validate(value)
        self.assertEqual(evidence["edgeRuntimeProfile"], "DIRECT_ROUTING")
        self.assertEqual(
            evidence["pbxMediaDestinationPortRanges"]["sbc1"],
            {"end": 30127, "start": 30000},
        )

        for name, candidate in (
            ("enableSyntheticVoiceFixture", True),
            ("syntheticTeamsSourcePrefixes", ["10.20.1.4/32"]),
            ("sbc1PbxSourcePrefixes", []),
            ("sbc2PbxSourcePrefixes", ["10.20.1.4/32"]),
        ):
            with self.subTest(name=name):
                broken = copy.deepcopy(value)
                broken["parameters"][name]["value"] = candidate
                with self.assertRaises(preflight.PreflightError):
                    self.validate(broken)

    def test_pbx_media_destination_range_is_exact_bounded_and_profile_bound(self):
        for start, end in (
            (30001, 30127),
            (30000, 30126),
            (30000, 35001),
            (5000, 5071),
        ):
            with self.subTest(start=start, end=end):
                value = document()
                value["parameters"]["sbc1PbxMediaDestinationPortStart"]["value"] = start
                value["parameters"]["sbc1PbxMediaDestinationPortEnd"]["value"] = end
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)

    def test_sku_disk_and_security_profile_are_fixed(self):
        for name, candidate in (
            ("cp1VmSize", "Standard_D64s_v5"),
            ("sbc1OsDiskSizeGiB", 2048),
            ("enableTrustedLaunch", False),
            ("enableSyntheticVoiceFixture", False),
            ("tenantRtpMediaPortCount", 10000),
            ("microsoftMediaIcePortRange", "3478-3479"),
            ("microsoftMediaHighPortRange", "49152-65535"),
            ("edgeRuntimeProfile", "UNSAFE_PROFILE"),
        ):
            with self.subTest(name=name):
                value = document()
                value["parameters"][name]["value"] = candidate
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)

    def test_private_key_and_wrong_public_fingerprint_are_rejected(self):
        value = document()
        value["parameters"]["sshPublicKey"]["value"] = "-----BEGIN OPENSSH PRIVATE KEY-----"
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

        value = copy.deepcopy(document())
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_parameters(
                value,
                approved_admin_cidrs=ADMINS,
                expected_ssh_fingerprint="SHA256:" + "x" * 43,
            )

    def test_template_models_microsoft_media_ports_directionally(self):
        source = (ROOT / "main.bicep").read_text(encoding="utf-8")
        self.assertIn("microsoftMediaIcePortRange string = '3478-3481'", source)
        self.assertIn("microsoftMediaHighPortRange string = '49152-53247'", source)
        self.assertEqual(
            source.count("sourcePortRanges: microsoftMediaProcessorPortRanges"),
            1,
        )
        self.assertEqual(
            source.count("destinationPortRanges: microsoftMediaProcessorPortRanges"),
            1,
        )
        self.assertEqual(source.count("destinationPortRange: rtpMediaDestinationRange"), 1)
        self.assertEqual(source.count("sourcePortRange: tenantRtpMediaDestinationRange"), 4)
        self.assertIn("name: 'AllowMicrosoftMediaOutbound'", source)
        self.assertIn("edgeRuntimeProfile == 'DIRECT_ROUTING'", source)
        self.assertIn("name: 'DenyAllOutbound'", source)
        self.assertIn("destinationAddressPrefixes: microsoftMediaSourcePrefixes", source)
        self.assertNotIn(
            "sourceAddressPrefixes: microsoftMediaSourcePrefixes\n      sourcePortRange: '*'",
            source,
        )

    def test_template_egress_is_profile_specific_and_default_denied(self):
        source = (ROOT / "main.bicep").read_text(encoding="utf-8")
        network_source = (ROOT / "modules" / "network.bicep").read_text(
            encoding="utf-8"
        )
        synthetic_start = source.index("var sbcSyntheticOutboundSecurityRules")
        direct_start = source.index("var sbcDirectMicrosoftOutboundSecurityRules")
        pbx_start = source.index("var sbc1DirectPbxOutboundSecurityRules")
        synthetic = source[synthetic_start:direct_start]
        microsoft = source[direct_start:pbx_start]

        self.assertIn("edgeRuntimeProfile == 'SYNTHETIC_PRIVATE'", synthetic)
        self.assertIn("destinationAddressPrefix: cp1PrivateIpAddress", synthetic)
        self.assertIn("sourcePortRange: tenantRtpMediaDestinationRange", synthetic)
        self.assertNotIn("microsoftMediaSourcePrefixes", synthetic)

        self.assertIn("edgeRuntimeProfile == 'DIRECT_ROUTING'", microsoft)
        self.assertIn("destinationAddressPrefixes: microsoftMediaSourcePrefixes", microsoft)
        self.assertIn("destinationPortRanges: microsoftMediaProcessorPortRanges", microsoft)
        self.assertIn("sourcePortRange: tenantRtpMediaDestinationRange", microsoft)

        self.assertIn("destinationAddressPrefixes: fixedNtpServerPrefixes", source)
        self.assertIn("destinationAddressPrefix: azureWireServerIpv4", source)
        self.assertIn("destinationAddressPrefix: azureImdsIpv4", source)
        self.assertNotIn("destinationAddressPrefix: 'AzurePlatformDNS'", source)
        self.assertNotIn("destinationAddressPrefix: 'AzurePlatformIMDS'", source)
        self.assertIn("name: 'DenyAllOutbound'", source)
        self.assertIn("direction: 'Outbound'", source)
        self.assertEqual(network_source.count("defaultOutboundAccess: false"), 2)

    def test_template_ingress_is_mutually_exclusive_by_profile(self):
        source = (ROOT / "main.bicep").read_text(encoding="utf-8")
        admin_start = source.index("var sbcAdminInboundSecurityRules")
        direct_start = source.index("var sbcDirectMicrosoftInboundSecurityRules")
        common_outbound_start = source.index("var sbcCommonOutboundSecurityRules")
        synthetic_start = source.index("var sbcSyntheticTeamsSecurityRules")
        pbx_start = source.index("var sbc1PbxSecurityRules")

        admin = source[admin_start:direct_start]
        direct = source[direct_start:common_outbound_start]
        synthetic = source[synthetic_start:pbx_start]

        self.assertIn("name: 'AllowAdminSsh'", admin)
        self.assertNotIn("AllowMicrosoft", admin)
        self.assertIn("edgeRuntimeProfile == 'DIRECT_ROUTING'", direct)
        self.assertIn("name: 'AllowMicrosoftTls5061'", direct)
        self.assertIn("name: 'AllowMicrosoftMedia'", direct)
        self.assertNotIn("AllowSynthetic", direct)
        self.assertIn("edgeRuntimeProfile == 'SYNTHETIC_PRIVATE'", synthetic)
        self.assertIn("name: 'AllowSyntheticTeamsTls5061'", synthetic)
        self.assertNotIn("AllowMicrosoft", synthetic)
        self.assertIn(
            "edgeRuntimeProfile == 'SYNTHETIC_PRIVATE' && enableSyntheticVoiceFixture",
            source,
        )


if __name__ == "__main__":
    unittest.main()
