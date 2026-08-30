from __future__ import annotations

import json
import os
import pathlib
import subprocess
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
INVENTORIES = PROJECT_ROOT / "deploy" / "inventories"


def load_inventory(path: pathlib.Path) -> dict:
    result = subprocess.run(
        ["ansible-inventory", "--inventory", str(path), "--list"],
        check=True,
        capture_output=True,
        encoding="utf-8",
    )
    document = json.loads(result.stdout)
    if not isinstance(document, dict):
        raise TypeError(f"Expected an inventory mapping from {path}")
    return document


class DeploymentProfileTests(unittest.TestCase):
    def profile(self, name: str) -> dict:
        inventory_dir = INVENTORIES / name
        inventory_path = inventory_dir / "hosts.yml"
        if not inventory_path.exists():
            inventory_path = inventory_dir / "hosts.example.yml"
        inventory = load_inventory(inventory_path)
        hostvars = inventory.get("_meta", {}).get("hostvars", {})
        self.assertEqual(len(hostvars), 1)
        return next(iter(hostvars.values()))

    def test_database_and_tls_profile_matrix(self) -> None:
        lab = self.profile("lab")
        rebuild = self.profile("rebuild")
        azure = self.profile("azure")
        azure_single = self.profile("azure-single")

        for local_profile in (lab, rebuild, azure_single):
            self.assertTrue(local_profile["cp_install_local_postgres"])
            self.assertEqual(local_profile["cp_db_upstream_host"], "127.0.0.1")
            self.assertEqual(local_profile["cp_db_server_tls_sslmode"], "disable")

        self.assertFalse(azure["cp_install_local_postgres"])
        self.assertNotIn(
            azure["cp_db_upstream_host"], {"127.0.0.1", "localhost", "::1"}
        )
        self.assertEqual(azure["cp_db_server_tls_sslmode"], "verify-full")

        self.assertTrue(lab["cp_ingress_local_tls"])
        self.assertTrue(rebuild["cp_ingress_local_tls"])
        self.assertFalse(azure["cp_ingress_local_tls"])
        self.assertFalse(azure_single["cp_ingress_local_tls"])
        self.assertEqual(lab["cp_controller_hsts_seconds"], 0)
        self.assertEqual(rebuild["cp_controller_hsts_seconds"], 0)
        self.assertGreaterEqual(azure["cp_controller_hsts_seconds"], 3600)
        self.assertGreaterEqual(azure_single["cp_controller_hsts_seconds"], 3600)

    def test_azure_single_exposes_only_ingress_and_restricted_ssh(self) -> None:
        profile = self.profile("azure-single")
        public_ports = set(profile["cp_firewall_public_tcp_ports"])
        self.assertEqual(public_ports, {80, 443})
        self.assertTrue(public_ports.isdisjoint({22, 5432, 6432, 8000}))
        self.assertEqual(
            profile["cp_firewall_ssh_source_ipv4_cidrs"],
            ["83.110.90.136/32", "83.110.90.142/32"],
        )
        self.assertEqual(profile["cp_firewall_dhcp_server_ipv4"], "168.63.129.16")
        self.assertEqual(
            profile["cp_resolved_expected_dns_server_ipv4"], "168.63.129.16"
        )
        self.assertEqual(profile["cp_resolved_unicast_probe_name"], "one.one.one.one")
        self.assertEqual(profile["cp_resolved_unicast_probe_ipv4"], "1.1.1.1")
        self.assertEqual(profile["cp_ingress_server_name"], "controller.voice.vivolution.ae")
        self.assertEqual(profile["cp_ingress_https_port"], 443)
        self.assertEqual(profile["cp_ingress_guest_connect_address"], "127.0.0.1")
        self.assertEqual(profile["cp_ingress_external_connect_address"], "20.74.155.71")

    def test_azure_single_inventory_uses_strict_pinned_ssh(self) -> None:
        inventory = load_inventory(INVENTORIES / "azure-single" / "hosts.yml")
        host = inventory["_meta"]["hostvars"]["cp1"]
        self.assertEqual(host["ansible_host"], "controller.voice.vivolution.ae")
        self.assertEqual(host["ansible_port"], 22)
        self.assertEqual(host["ansible_user"], "cpadmin")
        common_args = host["ansible_ssh_common_args"]
        self.assertIn("IdentitiesOnly=yes", common_args)
        self.assertIn("StrictHostKeyChecking=yes", common_args)
        self.assertIn("generated/known_hosts", common_args)
        self.assertIn("GlobalKnownHostsFile=/dev/null", common_args)

    def test_azure_single_uses_dedicated_secrets_contract(self) -> None:
        cpctl = (PROJECT_ROOT / "bin" / "cpctl").read_text(encoding="utf-8")
        self.assertIn("VIVO_CP_SECRETS", cpctl)
        self.assertIn("azure-single-secrets.yml", cpctl)
        self.assertIn("require_profile_secrets", cpctl)
        self.assertIn("selected_inventory_profile", cpctl)
        self.assertNotIn('case "$inventory_relative"', cpctl)

        environment = os.environ.copy()
        environment.update(
            {
                "VIVO_CP_INVENTORY": "deploy/inventories/azure-single/hosts.yml",
                "VIVO_CP_SECRETS": "deploy/.state/lab-secrets.yml",
            }
        )
        result = subprocess.run(
            [str(PROJECT_ROOT / "bin" / "cpctl"), "init"],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("azure-single profile requires", result.stderr)

    def test_azure_single_qualification_records_infrastructure_gate(self) -> None:
        cpctl = (PROJECT_ROOT / "bin" / "cpctl").read_text(encoding="utf-8")
        self.assertEqual(cpctl.count("qualify-azure-infrastructure.yml"), 2)
        self.assertIn("azure-infrastructure-before.log", cpctl)
        self.assertIn("azure-infrastructure-after.log", cpctl)
        self.assertIn("azure_infrastructure=passed", cpctl)

    def test_azure_single_preflight_binds_hostname_to_topology(self) -> None:
        preflight = (
            PROJECT_ROOT / "deploy" / "roles" / "preflight" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("cp_expected_hostname == 'controller'", preflight)
        self.assertIn("cp_expected_hostname == 'viv-sbc-poc-cp1'", preflight)
        self.assertIn("'legacy-single-node'", preflight)
        self.assertIn("'poc-three-node'", preflight)

    def test_host_disables_llmnr_without_installing_resolved(self) -> None:
        policy = (
            PROJECT_ROOT
            / "deploy"
            / "roles"
            / "base_os"
            / "templates"
            / "99-vivolution-hardening.conf.j2"
        ).read_text(encoding="utf-8")
        base_tasks = (
            PROJECT_ROOT / "deploy" / "roles" / "base_os" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        verify = (PROJECT_ROOT / "deploy" / "playbooks" / "verify.yml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(policy, "[Resolve]\nLLMNR=no\n")
        self.assertNotIn("      - systemd-resolved\n", base_tasks)
        self.assertIn("cp_systemd_resolved_active", base_tasks)
        self.assertIn("cp_systemd_resolved_hardening.changed", base_tasks)
        self.assertIn("cp_systemd_resolved_protocols_before", base_tasks)
        self.assertIn("systemd-analyze, cat-config", base_tasks)
        self.assertIn("Data from: network", base_tasks)
        self.assertIn("':5355'", base_tasks)
        self.assertIn("cp_verify_expected_resolved_hardening_content", verify)
        self.assertIn("cp_verify_systemd_resolved_merged_config", verify)
        self.assertIn("'+LLMNR' not in", verify)
        self.assertIn("'-LLMNR' in", verify)
        self.assertIn("Data from: network", verify)
        self.assertIn("':5355'", verify)


if __name__ == "__main__":
    unittest.main()
