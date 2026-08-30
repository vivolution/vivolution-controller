from __future__ import annotations

import pathlib
import re
import unittest


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
PLAYBOOK = PROJECT_ROOT / "deploy" / "playbooks" / "qualify-azure-infrastructure.yml"
DISK_LOCKDOWN = PROJECT_ROOT / "infra" / "azure-poc" / "lockdown_os_disks.py"


class AzureInfrastructureQualificationStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = PLAYBOOK.read_text(encoding="utf-8")
        self.disk_lockdown_text = DISK_LOCKDOWN.read_text(encoding="utf-8")

    def test_legacy_contract_remains_default_and_poc_is_explicit(self) -> None:
        self.assertIn("default('legacy-single-node', true)", self.text)
        self.assertIn("['legacy-single-node', 'poc-three-node']", self.text)
        self.assertIn("cp_azure_resources | length == 6", self.text)
        self.assertIn("cp_azure_os_disk_sku == 'Premium_LRS'", self.text)
        self.assertIn("cp_azure_vm.osDiskDeleteOption == 'Detach'", self.text)
        self.assertIn("cp_azure_vm.networkInterfaces[0].deleteOption == 'Detach'", self.text)

    def test_poc_resource_group_is_exact_and_rejects_extra_resources(self) -> None:
        self.assertIn("cp_azure_poc_declared_resources | length == 14", self.text)
        self.assertIn("cp_azure_poc_disk_resources | length == 3", self.text)
        self.assertIn("cp_azure_resources | length == 17", self.text)
        self.assertIn("cp_azure_poc_expected_declared_resources", self.text)
        self.assertIn("cp_azure_poc_expected_disk_resources", self.text)
        self.assertEqual(
            self.text.count("type: Microsoft.Compute/virtualMachines"), 4
        )
        self.assertEqual(
            self.text.count("type: Microsoft.Network/networkInterfaces"), 4
        )
        self.assertEqual(
            self.text.count("type: Microsoft.Network/networkSecurityGroups"), 4
        )
        self.assertEqual(
            self.text.count("type: Microsoft.Network/publicIPAddresses"), 4
        )
        self.assertIn("type: Microsoft.Compute/availabilitySets", self.text)
        self.assertIn("type: Microsoft.Network/virtualNetworks", self.text)

    def test_poc_nodes_network_and_nsg_contracts_are_fail_closed(self) -> None:
        for value in (
            "Standard_B2als_v2",
            "StandardSSD_LRS",
            "snet-management",
            "snet-edge",
            "10.20.2.4",
            "10.20.2.5",
            "20000-29999",
            "20000-20255",
            "pbx_media_destination_port_start",
            "pbx_media_destination_port_end",
            "AllowMicrosoftTls5061",
            "AllowSyntheticFixtureMediaOutbound",
            "DenyAllOutbound",
            "AllowSyntheticTeamsTls5061",
            "AllowPbxTls",
            "DenyAllInbound",
            "(17 if cp_azure_poc_edge_runtime_profile == 'SYNTHETIC_PRIVATE' else 19)",
            "(6 if cp_azure_poc_edge_runtime_profile == 'SYNTHETIC_PRIVATE' else 4)",
            "disk.publicNetworkAccess == 'Disabled'",
            "disk.networkAccessPolicy == 'DenyAll'",
            "'PowerState/running' in states",
        ):
            self.assertIn(value, self.text)

        self.assertIn("cp_azure_poc_edge_subnet.ipConfigurationIds | length == 2", self.text)
        self.assertIn("cp_azure_poc_availability_set.vmIds | length == 2", self.text)
        self.assertIn("cp_azure_poc_availability_set.faultDomains | int == 2", self.text)
        self.assertNotIn(
            "cp_azure_poc_availability_set.provisioningState", self.text
        )

    def test_poc_microsoft_media_rules_are_exact_and_directional(self) -> None:
        self.assertIn("sort_by([],&name)[].{name:name,priority:priority", self.text)
        self.assertEqual(self.text.count("- name: AllowMicrosoftMedia\n"), 1)
        self.assertEqual(self.text.count("- name: AllowMicrosoftMediaOutbound\n"), 1)
        self.assertIn(
            "cp_azure_poc_microsoft_media_source_prefixes | sort ==\n"
            "                ['52.112.0.0/14', '52.120.0.0/14']",
            self.text,
        )

        media_start = self.text.index("              - name: AllowMicrosoftMedia\n")
        signaling_start = self.text.index("              - name: AllowMicrosoftTls5061\n")
        inbound = self.text[media_start:signaling_start]

        for value in (
            "direction: Inbound",
            "sourcePrefixes: \"{{ cp_azure_poc_microsoft_media_source_prefixes }}\"",
            "sourcePortRange: null",
            "sourcePortRanges:\n                  - '3478-3481'\n                  - '49152-53247'",
            "destinationPrefix: \"{{ cp_azure_poc_edge_subnet_address_prefix }}\"",
            "destinationPortRange: \"{{ cp_azure_poc_rtp_media_port_range }}\"",
        ):
            self.assertIn(value, inbound)

        outbound_start = self.text.index(
            "              - name: AllowMicrosoftMediaOutbound\n"
        )
        outbound_end = self.text.index(
            "              - name: AllowMicrosoftSignalingOutbound\n"
        )
        outbound = self.text[outbound_start:outbound_end]
        for value in (
            "direction: Outbound",
            "sourcePortRange: \"{{ cp_azure_poc_tenant_media_port_range }}\"",
            "destinationPrefixes: \"{{ cp_azure_poc_microsoft_media_source_prefixes }}\"",
            "destinationPortRange: null",
            "destinationPortRanges:\n                  - '3478-3481'\n                  - '49152-53247'",
        ):
            self.assertIn(value, outbound)

        for value in (
            "AllowSyntheticFixtureMediaOutbound",
            "sourcePortRange: \"{{ cp_azure_poc_tenant_media_port_range }}\"",
            "destinationPrefix: \"{{ cp_azure_private_ip }}\"",
            "AllowAzureDnsUdpOutbound",
            "destinationPrefix: 168.63.129.16",
            "AllowAzureImdsOutbound",
            "destinationPrefix: 169.254.169.254",
            "AllowNtpOutbound",
            "162.159.200.123/32",
            "DenyAllOutbound",
        ):
            self.assertIn(value, self.text)

    def test_both_profiles_are_qualified_and_wrong_profile_rules_are_removed(self) -> None:
        for value in (
            "['SYNTHETIC_PRIVATE', 'DIRECT_ROUTING']",
            "rejectattr('name', 'equalto', 'AllowMicrosoftMedia')",
            "rejectattr('name', 'equalto', 'AllowMicrosoftTls5061')",
            "rejectattr('name', 'equalto', 'AllowSyntheticFixtureMediaOutbound')",
            "rejectattr('name', 'equalto', 'AllowSyntheticFixtureSignalingOutbound')",
            "rejectattr('name', 'equalto', 'AllowSyntheticTeamsMedia')",
            "rejectattr('name', 'equalto', 'AllowSyntheticTeamsTls5061')",
            "direct_profile_outbound_rules",
            "AllowPbxMediaOutbound",
            "AllowPbxSignalingOutbound",
            "network.prefixlen >= 24",
            "network.network_address.is_global",
        ):
            self.assertIn(value, self.text)

        self.assertIn(
            "cp_azure_poc_synthetic_teams_source_prefixes | length == 0",
            self.text,
        )
        self.assertIn("'10.20.1.4/32' not in item.pbx_source_prefixes", self.text)
        self.assertIn(
            "item.pbx_media_destination_port_end | int -\n"
            "                 item.pbx_media_destination_port_start | int + 1 >= 100",
            self.text,
        )
        self.assertIn(
            "node.pbx_media_destination_port_start | string", self.text
        )

        superset_text = self.text[
            self.text.index("            expected_rule_superset:\n") :
            self.text.index("            direct_profile_outbound_rules:\n")
        ]
        direct_text = self.text[
            self.text.index("            direct_profile_outbound_rules:\n") :
            self.text.index("            expected_rules: >-\n")
        ]
        superset = set(
            re.findall(r"^              - name: (\S+)$", superset_text, re.MULTILINE)
        )
        direct_outbound = set(
            re.findall(r"^              - name: (\S+)$", direct_text, re.MULTILINE)
        )
        synthetic = superset - {"AllowMicrosoftMedia", "AllowMicrosoftTls5061"}
        direct = (
            superset
            - {
                "AllowSyntheticFixtureMediaOutbound",
                "AllowSyntheticFixtureSignalingOutbound",
                "AllowSyntheticTeamsMedia",
                "AllowSyntheticTeamsTls5061",
            }
        ) | direct_outbound
        self.assertEqual(len(synthetic), 17)
        self.assertEqual(len(direct), 19)
        self.assertNotIn("AllowMicrosoftMedia", synthetic)
        self.assertFalse(any(name.startswith("AllowSynthetic") for name in direct))

    def test_all_three_implicit_os_disks_have_network_lockdown_proof(self) -> None:
        expected_disks = {
            "viv-sbc-poc-cp1-osdisk": "viv-sbc-poc-cp1",
            "viv-sbc-poc-sbc1-osdisk": "viv-sbc-poc-sbc1",
            "viv-sbc-poc-sbc2-osdisk": "viv-sbc-poc-sbc2",
        }
        for disk, vm in expected_disks.items():
            self.assertIn(disk, self.disk_lockdown_text)
            self.assertIn(vm, self.disk_lockdown_text)

        self.assertIn("cp_azure_os_disk_name == 'viv-sbc-poc-cp1-osdisk'", self.text)
        self.assertIn("['sbc1', 'sbc2']", self.text)
        self.assertIn("item.vm_name == 'viv-sbc-poc-' ~ item.role", self.text)
        self.assertIn("item.os_disk_name == item.vm_name ~ '-osdisk'", self.text)

        for value in (
            "cp_azure_disk.publicNetworkAccess == 'Disabled'",
            "cp_azure_disk.networkAccessPolicy == 'DenyAll'",
            "cp_azure_poc_os_disk_lockdown_evidence",
            "cp_azure_poc_os_disk_lockdown_evidence | length == 3",
            "map(attribute='publicNetworkAccess') | unique | list ==",
            "['Disabled']",
            "map(attribute='networkAccessPolicy') | unique | list ==",
            "['DenyAll']",
            "map(attribute='os_disk_name') | list",
            "cp1-sbc1-sbc2-disabled-deny-all",
        ):
            self.assertIn(value, self.text)

        for value in (
            'actual["publicNetworkAccess"] != "Disabled"',
            'actual["networkAccessPolicy"] != "DenyAll"',
        ):
            self.assertIn(value, self.disk_lockdown_text)

    def test_poc_acme_authority_is_qualified_read_only_and_fail_closed(self) -> None:
        for value in (
            "identityPrincipalId:identity.principalId",
            "reconcile_dns_acme_authority.py",
            "POC_DNS_ACME_AUTHORITY_RECONCILED",
            "['ABSENT', 'ABSENT']",
            "map(attribute='legacyLockCount') | list == [0, 0]",
            "map(attribute='legacyRoleAssignments') | list == [[], []]",
            "map(attribute='roleAssignmentCount') | list == [1, 1]",
            "no zone locks, only one exact TXT-only custom-role",
        ):
            self.assertIn(value, self.text)
        task = self.text[
            self.text.index(
                "        - name: Read the exact reconciled POC ACME DNS authority contract\n"
            ) : self.text.index(
                "        - name: Parse the sanitized POC ACME DNS authority evidence\n"
            )
        ]
        self.assertNotIn("--mode", task)
        self.assertNotIn("--confirmation", task)
        self.assertIn("changed_when: false", task)
        self.assertIn("check_mode: false", task)

    def test_every_azure_cli_operation_is_read_only(self) -> None:
        task_sections = self.text.split("\n        - name: ")
        azure_tasks = [section for section in task_sections if "\n              - az\n" in section]
        self.assertGreaterEqual(len(azure_tasks), 15)

        forbidden = re.compile(
            r"^\s+- (?:create|delete|update|set|add|remove)\s*$", re.MULTILINE
        )
        for section in azure_tasks:
            task_name = section.splitlines()[0]
            self.assertIn("\n          changed_when: false\n", section, task_name)
            self.assertIn("\n          check_mode: false\n", section, task_name)
            argv = section.split("\n          environment:", maxsplit=1)[0]
            self.assertIsNone(
                forbidden.search(argv),
                f"mutating Azure CLI verb in qualification task: {task_name}",
            )


if __name__ == "__main__":
    unittest.main()
