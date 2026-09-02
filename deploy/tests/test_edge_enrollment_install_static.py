from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EdgeEnrollmentInstallStaticTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_playbook_targets_existing_edges_and_only_enrollment_role(self) -> None:
        playbook = self.read("playbooks/install-edge-enrollment.yml")
        self.assertIn("hosts: edge_nodes", playbook)
        self.assertIn("become: true", playbook)
        self.assertIn("role: edge_enrollment_install", playbook)
        self.assertNotIn("role: controller", playbook)

    def test_role_installs_protected_identity_and_environment_scrubbed_cli(self) -> None:
        tasks = self.read("roles/edge_enrollment_install/tasks/main.yml")
        wrapper = self.read(
            "roles/edge_enrollment_install/templates/vivolution-edge-join.j2"
        )
        self.assertIn("python3-cryptography", tasks)
        self.assertIn("calculate_release_digest", tasks)
        self.assertIn("edge_enrollment_release_digest", tasks)
        self.assertIn("enrollment-release-digest", tasks)
        self.assertIn("name: vivolution-edge-agent", tasks)
        self.assertIn("path: /var/lib/vivolution-edge/enrollment", tasks)
        self.assertIn("mode: '0700'", tasks)
        self.assertIn("/usr/bin/env -i", wrapper)
        self.assertNotIn("TOKEN", wrapper.upper())

    def test_role_fails_closed_to_the_qualified_host_baseline(self) -> None:
        tasks = self.read("roles/edge_enrollment_install/tasks/main.yml")
        self.assertIn("ansible_facts['distribution'] == 'Ubuntu'", tasks)
        self.assertIn("ansible_facts['distribution_version'] == '24.04'", tasks)
        self.assertIn("ansible_facts['pkg_mgr'] == 'apt'", tasks)
        self.assertIn("ansible_facts['service_mgr'] == 'systemd'", tasks)
        self.assertIn("ansible_facts['python']['version']['minor'] | int >= 10", tasks)
        self.assertNotIn("distribution'] in ['Ubuntu', 'Debian']", tasks)

    def test_service_is_unprivileged_outbound_only_and_hardened(self) -> None:
        service = self.read(
            "roles/edge_enrollment_install/templates/vivolution-edge-enrollment.service.j2"
        )
        for required in (
            "User=vivolution-edge-agent",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "PrivateDevices=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "CapabilityBoundingSet=",
            "MemoryDenyWriteExecute=true",
            "ReadWritePaths=/var/lib/vivolution-edge/enrollment",
        ):
            self.assertIn(required, service)
        self.assertNotIn("Listen", service)
        self.assertNotIn("Environment=", service)
        self.assertNotIn("ProcSubset=pid", service)

    def test_role_verifies_systemd_and_boot_id_inside_hardened_service_context(self) -> None:
        tasks = self.read("roles/edge_enrollment_install/tasks/main.yml")
        self.assertIn("/usr/bin/systemd-analyze", tasks)
        self.assertIn("- verify", tasks)
        self.assertIn("- security", tasks)
        self.assertIn("/usr/bin/systemd-run", tasks)
        self.assertIn("--property=ProtectProc=invisible", tasks)
        self.assertIn("/proc/sys/kernel/random/boot_id", tasks)

    def test_cli_has_no_token_value_argument_or_environment_source(self) -> None:
        cli = self.read("../edge/enrollment/cli.py")
        self.assertNotIn('add_argument("--token"', cli)
        self.assertNotIn("os.environ", cli)
        self.assertIn('"--token-stdin"', cli)
        self.assertIn('"--token-file"', cli)
        self.assertIn("read_token_tty", cli)


if __name__ == "__main__":
    unittest.main()
