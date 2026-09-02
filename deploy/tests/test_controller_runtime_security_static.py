from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def read(relative_path):
    return (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")


class ControllerRuntimeSecurityStaticTests(unittest.TestCase):
    def test_quadlet_pins_runc_and_preserves_all_container_controls(self):
        quadlet = read(
            "deploy/roles/controller_services/templates/"
            "vivolution-cp-web.container.j2"
        )

        for contract in (
            "Network=host",
            "ReadOnly=true",
            "DropCapability=all",
            "PodmanArgs=--runtime=/usr/sbin/runc",
            "NoNewPrivileges=true",
        ):
            self.assertIn(contract, quadlet)
        self.assertNotIn("apparmor=unconfined", quadlet)
        self.assertNotIn("SecurityLabelDisable=true", quadlet)

    def test_ubuntu_installer_installs_and_proves_runc_before_activation(self):
        base = read("installer/ansible/roles/ubuntu_base_os/tasks/main.yml")
        playbook = read("installer/ansible/install-controller.yml")

        self.assertRegex(base, r"(?m)^\s+- runc$")
        self.assertIn("argv: [/usr/sbin/runc, --version]", base)
        self.assertIn("cp_runc_version.rc == 0", base)
        self.assertLess(
            playbook.index("name: ubuntu_base_os"),
            playbook.index("name: controller_services"),
        )

    def test_ubuntu_installer_pins_current_caddy_for_trusted_https(self):
        defaults = read("installer/ansible/roles/ubuntu_base_os/defaults/main.yml")
        base = read("installer/ansible/roles/ubuntu_base_os/tasks/main.yml")

        self.assertIn("cp_caddy_package_version: '2.11.4'", defaults)
        self.assertIn("65760C51EDEA2017CEA2CA15155B6D79CA56EA34", defaults)
        self.assertIn("caddy-stable.sources", base)
        self.assertIn("vivolution-caddy", base)
        self.assertIn("Pin-Priority: 1001", base)
        self.assertIn('name: "caddy={{ cp_caddy_package_version }}"', base)
        self.assertIn("argv: [/usr/bin/caddy, version]", base)


if __name__ == "__main__":
    unittest.main()
