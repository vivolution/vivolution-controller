from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "installer" / "install-edge.sh"


class EdgeInstallerStaticTests(unittest.TestCase):
    def test_script_is_valid_posix_shell(self) -> None:
        result = subprocess.run(
            ["/bin/sh", "-n", str(SCRIPT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("CDPATH='' cd", script)
        self.assertNotIn("CDPATH= cd", script)

    def test_grant_is_never_an_argument_or_environment_input(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("--token", script)
        self.assertNotIn("TOKEN=", script.upper())
        self.assertNotIn("environ", script.lower())
        self.assertIn("/usr/local/bin/vivolution-edge-join enroll", script)
        self.assertNotIn("enroll --", script)

    def test_verifies_release_before_any_apt_or_ansible_mutation(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        comparison = '[ "$vivo_edge_actual_digest" = "$vivo_edge_expected_digest" ]'
        self.assertLess(script.index(comparison), script.index("/usr/bin/apt-get update"))
        self.assertLess(
            script.index(comparison), script.index("/usr/bin/ansible-playbook")
        )
        self.assertIn("--verify-only", script)
        self.assertIn("--check-host-os", script)
        self.assertIn("--dry-run", script)

    def test_accepts_only_the_canonical_ubuntu_os_release_symlink(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('os.readlink(source) != "../usr/lib/os-release"', script)
        self.assertIn('read_path = "/usr/lib/os-release"', script)
        self.assertIn('os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK', script)
        self.assertIn('not stat.S_ISREG(opened_metadata.st_mode)', script)
        self.assertIn('opened_metadata.st_uid != 0', script)
        self.assertIn('opened_metadata.st_mode & 0o022', script)
        self.assertIn('os.open(read_path, flags)', script)

    def test_local_playbook_uses_only_the_enrollment_role(self) -> None:
        playbook = (
            ROOT / "deploy" / "playbooks" / "install-edge-enrollment-local.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("hosts: localhost", playbook)
        self.assertIn("connection: local", playbook)
        self.assertIn("role: edge_enrollment_install", playbook)
        self.assertNotIn("role: controller", playbook)

    def test_installer_pins_ansible_config_with_deploy_role_resolution(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        config = (ROOT / "installer" / "ansible" / "ansible.cfg").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'vivo_edge_ansible_config="$vivo_edge_repo_root/installer/ansible/ansible.cfg"',
            script,
        )
        self.assertIn('ANSIBLE_CONFIG="$vivo_edge_ansible_config"', script)
        self.assertIn("roles_path = roles:../../deploy/roles", config)


if __name__ == "__main__":
    unittest.main()
