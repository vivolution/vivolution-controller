from __future__ import annotations

import pathlib
import re
import unittest


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
PLAYBOOK = PROJECT_ROOT / "deploy" / "playbooks" / "qualify-azure-infrastructure.yml"
DISK_LOCKDOWN = PROJECT_ROOT / "infra" / "azure-poc" / "lockdown_os_disks.py"
LIFECYCLE_CONTRACT = (
    PROJECT_ROOT / "infra" / "azure-poc" / "azure_lifecycle_contract.py"
)


class AzureInfrastructureQualificationStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = PLAYBOOK.read_text(encoding="utf-8")
        self.disk_lockdown_text = DISK_LOCKDOWN.read_text(encoding="utf-8")
        self.lifecycle_text = LIFECYCLE_CONTRACT.read_text(encoding="utf-8")

    def test_legacy_contract_remains_default_and_poc_is_explicit(self) -> None:
        self.assertIn("default('legacy-single-node', true)", self.text)
        self.assertIn("['legacy-single-node', 'poc-three-node']", self.text)
        self.assertIn("cp_azure_resources | length == 6", self.text)
        self.assertIn("cp_azure_os_disk_sku == 'Premium_LRS'", self.text)
        self.assertIn("cp_azure_vm.osDiskDeleteOption == 'Detach'", self.text)
        self.assertIn("cp_azure_vm.networkInterfaces[0].deleteOption == 'Detach'", self.text)

    def test_poc_resource_group_is_exact_and_rejects_extra_resources(self) -> None:
        self.assertIn(
            "14 + (cp_azure_poc_expected_direct_replacement_declared_resources | length)",
            self.text,
        )
        self.assertIn(
            "3 + (cp_azure_poc_expected_direct_replacement_disk_resources | length)",
            self.text,
        )
        self.assertIn(
            "17 + (cp_azure_poc_expected_direct_replacement_declared_resources | length) +",
            self.text,
        )
        self.assertIn("cp_azure_poc_expected_declared_resources", self.text)
        self.assertIn("cp_azure_poc_expected_disk_resources", self.text)
        self.assertIn("cp_azure_poc_expected_direct_replacement_declared_resources", self.text)
        self.assertIn("cp_azure_poc_expected_direct_replacement_disk_resources", self.text)
        self.assertIn("cp_azure_poc_direct_replacement_vm_names[0] ~ '-osdisk'", self.text)
        self.assertIn(
            'name: "{{ cp_azure_poc_os_disk_audit.disks[1].name }}"',
            self.text,
        )
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
            "AllowSyntheticFixtureMediaOutbound",
            "AllowGeneration3CarrierSignaling",
            "AllowGeneration3CarrierMedia",
            "DIRECT_ROUTING_PRIVATE_PBX_POC",
            "30000-30127",
            "DenyAllOutbound",
            "AllowSyntheticTeamsTls5061",
            "AllowPbxTls",
            "DenyAllInbound",
            "rules | length == 17",
            "20 if cp_azure_poc_cp1_carrier_overlay_mode_selected ==",
            "else 23",
            "g3-edge-19-rule-exact-contracts",
            "Read each complete generation-3 Direct Routing NSG rule set",
            "validate-g3-rules",
            "evidence.ruleCount | int == 19",
            "GENERATION3_DIRECT_ROUTING_NSG_VALID",
            "disk.publicNetworkAccess == 'Disabled'",
            "disk.networkAccessPolicy == 'DenyAll'",
            "'PowerState/running' in states",
        ):
            self.assertIn(value, self.text)

        self.assertIn(
            "cp_azure_poc_edge_subnet.ipConfigurationIds | length ==\n"
            "                (4 if cp_azure_poc_direct_replacement_runtime_profile ==",
            self.text,
        )
        self.assertIn(
            "cp_azure_poc_availability_set.vmIds | length ==\n"
            "                (4 if cp_azure_poc_direct_replacement_runtime_profile ==",
            self.text,
        )
        self.assertIn("cp_azure_poc_availability_set.faultDomains | int == 2", self.text)
        self.assertNotIn(
            "cp_azure_poc_availability_set.provisioningState", self.text
        )

    def test_g2_stays_synthetic_and_cp1_overlay_is_exact(self) -> None:
        self.assertIn("sort_by([],&name)[].{name:name,priority:priority", self.text)
        self.assertNotIn("- name: AllowMicrosoftMedia\n", self.text)
        self.assertNotIn("- name: AllowMicrosoftMediaOutbound\n", self.text)
        self.assertNotIn("- name: AllowMicrosoftTls5061\n", self.text)
        self.assertIn(
            "cp_azure_poc_microsoft_media_source_prefixes | sort ==\n"
            "                ['52.112.0.0/14', '52.120.0.0/14']",
            self.text,
        )

        overlay_start = self.text.index(
            "              - name: AllowGeneration3CarrierSignaling\n"
        )
        overlay_end = self.text.index(
            "              - name: DenyAllInbound\n", overlay_start
        )
        overlay = self.text[overlay_start:overlay_end]
        for value in (
            "priority: 320",
            "priority: 330",
            "sourcePrefixes:\n                  - 10.20.2.6/32\n                  - 10.20.2.7/32",
            "destinationPrefix: 10.20.1.4/32",
            "destinationPortRange: '5061'",
            "sourcePortRange: \"{{ cp_azure_poc_tenant_media_port_range }}\"",
            "destinationPortRange: '30000-30127'",
        ):
            self.assertIn(value, overlay)

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

        controller_start = self.text.index(
            "            cp_azure_poc_controller_nsg_rule_superset:\n"
        )
        controller_end = self.text.index(
            "        - name: Define the exact independently selected CP1 carrier rule sets\n",
            controller_start,
        )
        controller = self.text[controller_start:controller_end]
        self.assertEqual(controller.count("              - name: "), 23)
        for name in (
            "AllowCp1AzureDhcpOutbound",
            "AllowCp1AzureDnsUdpOutbound",
            "AllowCp1AzureDnsTcpOutbound",
            "AllowCp1AzureWireServerOutbound",
            "AllowCp1AzureImdsOutbound",
            "AllowCp1NtpOutbound",
            "AllowCp1WebOutbound",
            "AllowGeneration2FixtureSignalingOutbound",
            "AllowGeneration2FixtureMediaOutbound",
            "AllowGeneration3CarrierSignalingOutbound",
            "AllowGeneration3CarrierMediaOutbound",
            "AllowTwilioSecureMediaInbound",
            "AllowTwilioSecureSignalingOutbound",
            "AllowTwilioSecureMediaOutbound",
            "DenyAllCp1Outbound",
        ):
            self.assertIn("- name: " + name, controller)
        self.assertIn("'ABSENT' else", self.text)
        self.assertIn("'TWILIO_DISABLED' else 23", self.text)

    def test_base_synthetic_and_g3_direct_profiles_are_independent(self) -> None:
        for value in (
            "cp_azure_poc_edge_runtime_profile == 'SYNTHETIC_PRIVATE'",
            "cp_azure_poc_direct_replacement_runtime_profile in",
            "['NOT_DEPLOYED', 'DIRECT_ROUTING_PRIVATE_PBX_POC']",
            "cp_azure_poc_direct_replacement_runtime_profile ==",
            "cp_azure_poc_cp1_carrier_overlay_mode_selected",
            "['TWILIO_DISABLED', 'TWILIO_ENABLED']",
            "cp_azure_poc_controller_carrier_overlay_rule_names",
            "cp_azure_poc_controller_twilio_overlay_rule_names",
            "cp_azure_poc_synthetic_teams_source_prefixes == ['10.20.1.4/32']",
            "reconcile_dns_acme_authority.py",
            "reconcile_root_direct_dns_acme_authority.py",
        ):
            self.assertIn(value, self.text)
        self.assertNotIn(
            "cp_azure_poc_edge_runtime_profile == 'DIRECT_ROUTING", self.text
        )

    def test_all_three_implicit_os_disks_have_network_lockdown_proof(self) -> None:
        expected_disks = {
            "viv-sbc-poc-cp1-osdisk": "viv-sbc-poc-cp1",
            "viv-sbc-poc-sbc1-osdisk": "viv-sbc-poc-sbc1",
            "viv-sbc-poc-sbc2-osdisk": "viv-sbc-poc-sbc2",
        }
        for disk, vm in expected_disks.items():
            self.assertIn(disk, self.lifecycle_text)
            self.assertIn(vm, self.lifecycle_text)

        self.assertIn("cp_azure_os_disk_name == 'viv-sbc-poc-cp1-osdisk'", self.text)
        self.assertIn("['sbc1', 'sbc2']", self.text)
        self.assertIn("item.vm_name == 'viv-sbc-poc-' ~ item.role", self.text)
        self.assertIn("item.os_disk_name == item.vm_name ~ '-osdisk'", self.text)

        for value in (
            "cp_azure_disk.publicNetworkAccess == 'Disabled'",
            "cp_azure_disk.networkAccessPolicy == 'DenyAll'",
            "cp_azure_poc_os_disk_lockdown_evidence",
            "cp_azure_poc_os_disk_lockdown_evidence | length == 3",
            "POC_OS_DISKS_AUDIT_PASSED",
            "--mode\n              - audit",
            "osDiskId:storageProfile.osDisk.managedDisk.id",
            "vm.osDiskId | lower == resolved_disk.id | lower",
            "cp_azure_poc_os_disk_final_audit_raw.stdout | from_json ==",
            "map(attribute='publicNetworkAccess') | unique | list ==",
            "['Disabled']",
            "map(attribute='networkAccessPolicy') | unique | list ==",
            "['DenyAll']",
            "map(attribute='name') | list | sort",
            "cp1-sbc1-sbc2-disabled-deny-all",
        ):
            self.assertIn(value, self.text)

        for value in (
            'actual["publicNetworkAccess"] != "Disabled"',
            'actual["networkAccessPolicy"] != "DenyAll"',
            "lifecycle.resolve_vm_os_disks",
            "lifecycle.validate_os_disk_inventory",
        ):
            self.assertIn(value, self.disk_lockdown_text)

        self.assertEqual(
            self.text.count("              - --mode\n              - audit\n"), 2
        )
        final_audit = self.text.index(
            "        - name: Reaudit the exact POC OS-disk attachments after all "
            "qualification reads\n"
        )
        final_race_assertion = self.text.index(
            "        - name: Prove the POC OS-disk identity did not race qualification\n"
        )
        last_prior_read = self.text.index(
            "        - name: Require public DNS to resolve solely to the static public IP\n"
        )
        report = self.text.index(
            "        - name: Report sanitized Azure infrastructure qualification evidence\n"
        )
        self.assertLess(last_prior_read, final_audit)
        self.assertLess(final_audit, final_race_assertion)
        self.assertLess(final_race_assertion, report)

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
                "        - name: Read the exact reconciled legacy voice POC ACME DNS authority contract\n"
            ) : self.text.index(
                "        - name: Parse the sanitized legacy voice POC ACME DNS authority evidence\n"
            )
        ]
        self.assertNotIn("--mode", task)
        self.assertNotIn("--confirmation", task)
        self.assertIn("changed_when: false", task)
        self.assertIn("check_mode: false", task)

    def test_private_pbx_profile_uses_separate_root_dns_authority(self) -> None:
        for value in (
            "cp_azure_poc_direct_dns_resource_group == 'DNS_Zones'",
            "cp_azure_poc_direct_dns_parent_zone == 'vivolution.ae'",
            "cp_azure_poc_direct_replacement_runtime_profile",
            "cp_azure_poc_direct_certificate_fqdns",
            "['sbc1.vivolution.ae', 'sbc2.vivolution.ae',",
            "['acme-sbc1.vivolution.ae', 'acme-sbc2.vivolution.ae',",
            "['viv-sbc-dr-sbc1-g3', 'viv-sbc-dr-sbc2-g3']",
            "['viv-sbc-dr-sbc1-g3-pip', 'viv-sbc-dr-sbc2-g3-pip']",
            "c5498bfb-a31f-40dd-b636-0f53e530ed53",
            "reconcile_root_direct_dns_acme_authority.py",
            "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILED",
            "[none, none, none]",
            "[true, true, true]",
            "['carrier', 'sbc1', 'sbc2']",
            "voiceAuthorityZones",
            "acme-sbc1.voice.vivolution.ae",
            "customRoleDefinition.actions",
            "identityPrincipalId:identity.principalId",
            "viv-sbc-dr-sbc1-g3",
            "viv-sbc-dr-sbc2-g3",
        ):
            self.assertIn(value, self.text)
        legacy_task = self.text[
            self.text.index(
                "        - name: Read the exact reconciled legacy voice POC ACME DNS authority contract\n"
            ) : self.text.index(
                "        - name: Parse the sanitized legacy voice POC ACME DNS authority evidence\n"
            )
        ]
        self.assertNotIn("cp_azure_poc_direct_replacement_runtime_profile", legacy_task)
        self.assertIn(
            "cp_azure_infrastructure_topology_selected == 'poc-three-node'",
            legacy_task,
        )
        root_task = self.text[
            self.text.index(
                "        - name: Read the exact root Direct DNS and ACME authority contract\n"
            ) : self.text.index(
                "        - name: Parse sanitized root Direct DNS and ACME authority evidence\n"
            )
        ]
        self.assertNotIn("--mode", root_task)
        self.assertNotIn("--confirmation", root_task)
        self.assertIn("changed_when: false", root_task)
        self.assertIn("check_mode: false", root_task)
        self.assertIn(
            "cp_azure_poc_direct_replacement_runtime_profile ==\n"
            "              'DIRECT_ROUTING_PRIVATE_PBX_POC'",
            root_task,
        )

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
