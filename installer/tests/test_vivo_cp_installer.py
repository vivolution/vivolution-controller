import hashlib
import importlib.util
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "vivo_cp_installer.py"
SPEC = importlib.util.spec_from_file_location("vivo_cp_installer", MODULE_PATH)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def valid_answers():
    return {
        "deployment_mode": "standalone",
        "node_fqdn": "cp1.voice.example.com",
        "shared_fqdn": "controller.voice.example.com",
        "public_ipv4": "1.1.1.1",
        "ssh_source_cidrs": ["8.8.8.8/32"],
        "admin_username": "cpadmin",
        "admin_email": "admin@example.com",
        "acme_email": "certificates@example.com",
        "ssh_allowed_user": "ubuntu",
        "firewall_mode": "installer",
        "timezone": "Etc/UTC",
        "ntp_mode": "automatic",
        "ntp_servers": [],
    }


class InstallerFixture:
    def __init__(self, base):
        self.base = Path(base)
        self.fake_root = self.base / "target"
        self.source_root = self.base / "source"
        (self.fake_root / "etc").mkdir(parents=True)
        (self.fake_root / "etc" / "os-release").write_text(
            'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8"
        )
        controller = self.source_root / "controller"
        (controller / "core").mkdir(parents=True)
        (controller / "cp1").mkdir(parents=True)
        for relative in installer.CONTROLLER_REQUIRED_FILES:
            (controller / relative).write_text("content for %s\n" % relative, encoding="utf-8")
        (controller / "Containerfile").write_text(
            "# syntax=docker/dockerfile:1\n"
            "FROM docker.io/library/python@sha256:%s\n" % ("a" * 64),
            encoding="utf-8",
        )
        (controller / "core" / "app.py").write_text("CORE = True\n", encoding="utf-8")
        (controller / "cp1" / "settings.py").write_text("SETTINGS = True\n", encoding="utf-8")
        self.playbook = self.source_root / installer.DEFAULT_PLAYBOOK
        self.playbook.parent.mkdir(parents=True)
        self.playbook.write_text("---\n- hosts: controllers\n", encoding="utf-8")
        self.ansible_config = self.source_root / installer.DEFAULT_ANSIBLE_CONFIG
        self.ansible_config.write_text("[defaults]\n", encoding="utf-8")
        self.answer_file = self.base / "answers.json"
        self.answer_file.write_text(json.dumps(valid_answers()), encoding="utf-8")
        self.real_paths = installer.InstallerPaths(root=str(self.fake_root), dry_run=False)
        self.dry_paths = installer.InstallerPaths(root=str(self.fake_root), dry_run=True)
        self.paths = self.dry_paths

    def engine(self, **overrides):
        dry_run = overrides.get("dry_run", True)
        values = {
            "paths": self.dry_paths if dry_run else self.real_paths,
            "source_root": self.source_root,
            "answer_file": self.answer_file,
            "accept_configuration": True,
            "dry_run": True,
            "ansible_playbook": "/usr/bin/true",
            "output_stream": io.StringIO(),
            "dns_resolver": lambda host, port, family, socket_type: (
                [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))]
                if family == socket.AF_INET
                else []
            ),
        }
        values.update(overrides)
        return installer.InstallerEngine(**values)


class ValidationTests(unittest.TestCase):
    def test_valid_answers_are_normalized(self):
        answers = valid_answers()
        answers["node_fqdn"] = "CP1.Voice.Example.COM."
        answers["ssh_source_cidrs"] = "8.8.4.4/32, 8.8.8.8/32"
        normalized = installer.validate_answers(answers)
        self.assertEqual(normalized["node_fqdn"], "cp1.voice.example.com")
        self.assertEqual(
            normalized["ssh_source_cidrs"], ["8.8.4.4/32", "8.8.8.8/32"]
        )
        self.assertEqual(normalized["acme_email"], "certificates@example.com")

    def test_legacy_answers_default_acme_contact_to_admin_email(self):
        answers = valid_answers()
        del answers["acme_email"]
        answers["admin_email"] = "Admin@Example.COM"
        normalized = installer.validate_answers(answers)
        self.assertEqual(normalized["acme_email"], "Admin@example.com")

    def test_interactive_prompt_asks_for_acme_email_with_admin_default(self):
        responses = iter(
            (
                "cp1.voice.example.com",
                "controller.voice.example.com",
                "",
                "1",
                "cpadmin",
                "admin@example.com",
                "",
                "ubuntu",
                "1",
            )
        )
        prompts = []

        def answer(prompt):
            prompts.append(prompt)
            return next(responses)

        answers = installer.prompt_answers(
            input_function=answer,
            environment={},
            public_ip_discoverer=lambda: {
                "address": "1.1.1.1",
                "confirmed_by": 2,
                "disagreement": False,
            },
            timezone_selector=lambda **kwargs: "Etc/UTC",
        )
        self.assertEqual(answers["acme_email"], "admin@example.com")
        self.assertEqual(answers["firewall_mode"], "infrastructure")
        self.assertEqual(answers["ssh_source_cidrs"], [])
        self.assertTrue(any("Let's Encrypt ACME contact email" in item for item in prompts))

    def test_interactive_prompt_defaults_to_detected_active_ssh_client(self):
        responses = iter(
            (
                "cp1.voice.example.com",
                "controller.voice.example.com",
                "",
                "2",
                "",
                "cpadmin",
                "admin@example.com",
                "",
                "",
                "1",
            )
        )
        prompts = []

        def answer(prompt):
            prompts.append(prompt)
            return next(responses)

        answers = installer.prompt_answers(
            input_function=answer,
            environment={
                "SSH_CONNECTION": "198.51.100.23 53122 203.0.113.10 22",
                "SUDO_USER": "ubuntu",
            },
            public_ip_discoverer=lambda: {
                "address": "1.1.1.1",
                "confirmed_by": 3,
                "disagreement": False,
            },
            timezone_selector=lambda **kwargs: "Etc/UTC",
        )
        self.assertEqual(answers["ssh_source_cidrs"], ["198.51.100.23/32"])
        self.assertTrue(any("[198.51.100.23/32]" in item for item in prompts))

    def test_interactive_prompt_retries_only_missing_or_invalid_ssh_source(self):
        responses = iter(
            (
                "cp1.voice.example.com",
                "controller.voice.example.com",
                "",
                "2",
                "0.0.0.0/0",
                "198.51.100.23/32",
                "cpadmin",
                "admin@example.com",
                "",
                "ubuntu",
                "1",
            )
        )
        prompts = []
        messages = []

        def answer(prompt):
            prompts.append(prompt)
            return next(responses)

        answers = installer.prompt_answers(
            input_function=answer,
            output_function=messages.append,
            environment={},
            public_ip_discoverer=lambda: {
                "address": "1.1.1.1",
                "confirmed_by": 2,
                "disagreement": False,
            },
            timezone_selector=lambda **kwargs: "Etc/UTC",
        )
        self.assertEqual(answers["ssh_source_cidrs"], ["198.51.100.23/32"])
        self.assertEqual(
            sum("Allowed administrator SSH" in item for item in prompts), 2
        )
        self.assertTrue(any("intentionally refused" in item for item in messages))
        self.assertFalse(
            any("This controller's public FQDN" in item for item in prompts[2:])
        )

    def test_world_open_ssh_source_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerError, "exact IPv4 /32"):
            installer.validate_ssh_cidrs("0.0.0.0/0")

    def test_configuration_summary_names_fixed_letsencrypt_directory(self):
        rendered = "\n".join(installer.configuration_summary_lines(valid_answers()))
        self.assertIn("Let's Encrypt ACME email: certificates@example.com", rendered)
        self.assertIn(installer.LETS_ENCRYPT_PRODUCTION_DIRECTORY, rendered)

    def test_join_modes_are_explicitly_refused(self):
        for mode in ("join-cp2", "join-cp3", "witness", "ha"):
            answers = valid_answers()
            answers["deployment_mode"] = mode
            with self.assertRaisesRegex(installer.InstallerError, "Only Create"):
                installer.validate_answers(answers)

    def test_unknown_answer_keys_are_refused(self):
        answers = valid_answers()
        answers["cp_db_owner_password"] = "attacker-selected"
        with self.assertRaisesRegex(installer.InstallerError, "Unknown answer keys"):
            installer.validate_answers(answers)

    def test_node_and_shared_fqdn_must_be_distinct(self):
        answers = valid_answers()
        answers["shared_fqdn"] = answers["node_fqdn"]
        with self.assertRaisesRegex(installer.InstallerError, "must be different"):
            installer.validate_answers(answers)

    def test_up_to_sixteen_exact_ssh_sources_are_supported(self):
        answers = valid_answers()
        answers["ssh_source_cidrs"] = ["10.0.0.%d/32" % value for value in range(1, 17)]
        self.assertEqual(len(installer.validate_answers(answers)["ssh_source_cidrs"]), 16)
        answers["ssh_source_cidrs"].append("10.0.0.17/32")
        with self.assertRaisesRegex(installer.InstallerError, "At most sixteen"):
            installer.validate_answers(answers)

    def test_node_and_shared_dns_must_exclusively_match_declared_ipv4(self):
        answers = valid_answers()

        def matching_resolver(host, port, family, socket_type):
            if family == socket.AF_INET6:
                return []
            return [(family, socket_type, 6, "", ("1.1.1.1", port))]

        resolved = installer.validate_answer_dns(answers, resolver=matching_resolver)
        self.assertEqual(set(resolved), {answers["node_fqdn"], answers["shared_fqdn"]})

        def mismatching_resolver(host, port, family, socket_type):
            if family == socket.AF_INET6:
                return []
            address = "1.1.1.1" if host == answers["node_fqdn"] else "8.8.8.8"
            return [(family, socket_type, 6, "", (address, port))]

        with self.assertRaisesRegex(installer.InstallerError, "must resolve exclusively"):
            installer.validate_answer_dns(answers, resolver=mismatching_resolver)

    def test_published_aaaa_records_are_refused(self):
        answers = valid_answers()

        def dual_stack_resolver(host, port, family, socket_type):
            if family == socket.AF_INET6:
                return [
                    (family, socket_type, 6, "", ("2001:4860:4860::8888", port, 0, 0))
                ]
            return [(family, socket_type, 6, "", ("1.1.1.1", port))]

        with self.assertRaisesRegex(installer.InstallerError, "must not publish IPv6 AAAA"):
            installer.validate_answer_dns(answers, resolver=dual_stack_resolver)

    def test_unsafe_network_and_identity_values_are_refused(self):
        cases = (
            ("node_fqdn", "*.example.com"),
            ("public_ipv4", "10.0.0.1"),
            ("ssh_source_cidrs", ["8.8.8.0/24"]),
            ("admin_username", "root"),
            ("admin_email", "Name <admin@example.com>"),
            ("acme_email", "Name <certificates@example.com>"),
            ("ssh_allowed_user", "root"),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                answers = valid_answers()
                answers[key] = value
                with self.assertRaises(installer.InstallerError):
                    installer.validate_answers(answers)

    def test_private_management_cidr_and_active_ssh_client_are_allowed(self):
        answers = valid_answers()
        answers["ssh_source_cidrs"] = ["10.20.30.40/32"]
        environment = {
            "SSH_CONNECTION": "192.168.50.25 53122 203.0.113.10 22",
            "SUDO_USER": "ubuntu",
        }
        normalized = installer.validate_answers(answers, environment=environment)
        self.assertEqual(
            normalized["ssh_source_cidrs"], ["10.20.30.40/32", "192.168.50.25/32"]
        )

    def test_sudo_user_supplies_missing_ssh_user(self):
        answers = valid_answers()
        del answers["ssh_allowed_user"]
        normalized = installer.validate_answers(answers, environment={"SUDO_USER": "cloudadmin"})
        self.assertEqual(normalized["ssh_allowed_user"], "cloudadmin")

    def test_state_path_cannot_escape_root(self):
        with self.assertRaisesRegex(installer.InstallerError, "must not contain"):
            installer.InstallerPaths(root="/tmp/safe", state_dir="/../../escape")

    def test_live_host_state_and_log_overrides_are_refused(self):
        for state_dir, log_dir in (
            ("/", None),
            ("/etc", None),
            ("/var/lib", None),
            (None, "/"),
            (None, "/etc"),
            (None, "/var/log"),
        ):
            with self.subTest(state_dir=state_dir, log_dir=log_dir):
                with self.assertRaisesRegex(installer.InstallerError, "overrides are refused"):
                    installer.InstallerPaths(
                        root="/", state_dir=state_dir, log_dir=log_dir
                    )

    def test_rc2_ledger_schema_is_refused_by_letsencrypt_only_rc3(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.json"
            ledger = installer.PhaseLedger.create(path)
            value = dict(ledger.value)
            value["schema_version"] = 3
            installer.atomic_write_json(path, value)
            with self.assertRaisesRegex(installer.InstallerError, "unsupported schema"):
                installer.PhaseLedger.load(path)

    def test_dry_run_defaults_are_isolated_and_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            real = installer.InstallerPaths(root=temporary, dry_run=False)
            dry = installer.InstallerPaths(root=temporary, dry_run=True)
            self.assertNotEqual(real.state_dir, dry.state_dir)
            self.assertNotEqual(real.log_dir, dry.log_dir)
            self.assertTrue(str(real.state_dir).endswith(installer.DEFAULT_STATE_DIR))
            self.assertTrue(str(dry.state_dir).endswith(installer.DEFAULT_DRY_RUN_STATE_DIR))
            self.assertTrue(str(dry.log_dir).endswith(installer.DEFAULT_DRY_RUN_LOG_DIR))

    def test_critical_paths_refuse_symlink_ancestors_without_touching_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fake_root = base / "target"
            outside = base / "outside"
            (fake_root / "var").mkdir(parents=True)
            outside.mkdir(mode=0o750)
            original_mode = stat.S_IMODE(outside.stat().st_mode)
            os.symlink(
                str(outside),
                str(fake_root / "var" / "lib"),
                target_is_directory=True,
            )
            paths = installer.InstallerPaths(root=str(fake_root))

            with self.assertRaisesRegex(installer.InstallerError, "symbolic link"):
                paths.ensure_state_log_directories()

            self.assertFalse((outside / "vivolution").exists())
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), original_mode)
            self.assertFalse((fake_root / "run").exists())

    def test_critical_paths_refuse_unsafe_existing_fake_root_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_root = Path(temporary) / "target"
            unsafe = fake_root / "var"
            unsafe.mkdir(parents=True)
            unsafe.chmod(0o777)
            paths = installer.InstallerPaths(root=str(fake_root))

            with self.assertRaisesRegex(installer.InstallerError, "group/world writable"):
                paths.ensure_lock_directory()

            self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o777)
            self.assertFalse((fake_root / "run").exists())

    def test_stock_rsyslog_group_writable_var_log_anchor_is_contained(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_root = Path(temporary) / "target"
            (fake_root / "var").mkdir(parents=True)
            log_anchor = fake_root / "var" / "log"
            log_anchor.mkdir(mode=0o775)
            log_anchor.chmod(0o775)
            paths = installer.InstallerPaths(root=str(fake_root))

            paths.ensure_lock_directory()
            paths.ensure_state_log_directories()

            self.assertEqual(stat.S_IMODE(log_anchor.stat().st_mode), 0o775)
            self.assertEqual(stat.S_IMODE(paths.log_dir.stat().st_mode), 0o700)
            self.assertEqual(paths.log_dir.stat().st_uid, os.geteuid())

    def test_secure_chain_rejects_unexpected_owner_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            boundary = Path(temporary)
            target = boundary / "state"
            target.mkdir()
            with self.assertRaisesRegex(installer.InstallerError, "owned by UID"):
                installer._validate_secure_directory_chain(
                    target, boundary, os.geteuid() + 1
                )


class ReleaseIdentityTests(unittest.TestCase):
    def test_release_id_is_deterministic_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            controller = fixture.source_root / "controller"
            first = installer.calculate_controller_release_id(controller)
            second = installer.calculate_controller_release_id(controller)
            self.assertEqual(first, second)
            self.assertRegex(first, r"^cp1-[0-9a-f]{64}$")
            (controller / "core" / "app.py").write_text("CORE = False\n", encoding="utf-8")
            self.assertNotEqual(first, installer.calculate_controller_release_id(controller))

    def test_release_manifest_matches_documented_hash_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            manifest = installer.controller_source_manifest(fixture.source_root / "controller")
            expected = "cp1-%s" % hashlib.sha256(manifest).hexdigest()
            self.assertEqual(
                installer.calculate_controller_release_id(fixture.source_root / "controller"),
                expected,
            )
            self.assertTrue(manifest.endswith(b"\n"))

    def test_symlink_in_controller_code_is_refused(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            controller = fixture.source_root / "controller"
            os.symlink(str(controller / "core" / "app.py"), str(controller / "core" / "alias.py"))
            with self.assertRaisesRegex(installer.InstallerError, "symbolic links"):
                installer.controller_source_manifest(controller)

    def test_base_image_is_read_from_first_from_and_must_be_digest_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            controller = fixture.source_root / "controller"
            expected = "docker.io/library/python@sha256:%s" % ("a" * 64)
            self.assertEqual(installer.parse_controller_base_image(controller), expected)
            (controller / "Containerfile").write_text(
                "FROM docker.io/library/python:latest\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(installer.InstallerError, "immutable sha256"):
                installer.parse_controller_base_image(controller)


class PreflightAndLoggingTests(unittest.TestCase):
    def test_mutating_bootstrap_follows_answers_and_explicit_confirmation(self):
        self.assertLess(installer.PHASES.index("answers"), installer.PHASES.index("bootstrap"))
        self.assertLess(
            installer.PHASES.index("confirmation"), installer.PHASES.index("bootstrap")
        )
        self.assertLess(installer.PHASES.index("release"), installer.PHASES.index("bootstrap"))

    def test_preflight_accepts_fake_ubuntu_and_rejects_existing_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            result = installer.run_preflight(fixture.paths)
            self.assertEqual(result["os_id"], "ubuntu")
            marker = fixture.fake_root / "etc" / "vivolution" / "installation-owner"
            marker.parent.mkdir()
            marker.write_text("owned\n", encoding="utf-8")
            with self.assertRaisesRegex(installer.InstallerError, "existing Vivolution"):
                installer.run_preflight(fixture.paths)

    def test_preflight_accepts_ubuntu_canonical_os_release_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            usr_os_release = fixture.fake_root / "usr" / "lib" / "os-release"
            usr_os_release.parent.mkdir(parents=True)
            usr_os_release.write_bytes(etc_os_release.read_bytes())
            etc_os_release.unlink()
            os.symlink("../usr/lib/os-release", etc_os_release)

            result = installer.run_preflight(fixture.paths)

            self.assertEqual(result["os_id"], "ubuntu")
            self.assertEqual(result["os_version"], "24.04")

    def test_host_os_check_accepts_canonical_link_without_installer_state(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            usr_os_release = fixture.fake_root / "usr" / "lib" / "os-release"
            usr_os_release.parent.mkdir(parents=True)
            usr_os_release.write_bytes(etc_os_release.read_bytes())
            etc_os_release.unlink()
            os.symlink("../usr/lib/os-release", etc_os_release)

            identity = installer.validate_host_os(fixture.paths)

            self.assertEqual(identity, {"os_id": "ubuntu", "os_version": "24.04"})
            self.assertFalse(fixture.paths.ledger.exists())

    def test_preflight_rejects_noncanonical_os_release_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            alternate = fixture.fake_root / "var" / "tmp" / "os-release"
            alternate.parent.mkdir(parents=True)
            alternate.write_bytes(etc_os_release.read_bytes())
            etc_os_release.unlink()
            os.symlink("../var/tmp/os-release", etc_os_release)

            with self.assertRaisesRegex(installer.InstallerError, "missing or unsafe"):
                installer.run_preflight(fixture.paths)

    def test_preflight_rejects_canonical_link_to_symlink_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            usr_os_release = fixture.fake_root / "usr" / "lib" / "os-release"
            alternate = fixture.fake_root / "var" / "tmp" / "os-release"
            usr_os_release.parent.mkdir(parents=True)
            alternate.parent.mkdir(parents=True)
            alternate.write_bytes(etc_os_release.read_bytes())
            etc_os_release.unlink()
            os.symlink("../usr/lib/os-release", etc_os_release)
            os.symlink("../../../var/tmp/os-release", usr_os_release)

            with self.assertRaisesRegex(installer.InstallerError, "Could not read"):
                installer.run_preflight(fixture.paths)

    def test_preflight_rejects_canonical_link_with_missing_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            etc_os_release.unlink()
            os.symlink("../usr/lib/os-release", etc_os_release)

            with self.assertRaisesRegex(installer.InstallerError, "Could not read"):
                installer.run_preflight(fixture.paths)

    def test_preflight_rejects_canonical_link_to_nonregular_target(self):
        if not hasattr(os, "symlink") or not hasattr(os, "mkfifo"):
            self.skipTest("required filesystem primitives are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            etc_os_release = fixture.fake_root / "etc" / "os-release"
            usr_os_release = fixture.fake_root / "usr" / "lib" / "os-release"
            usr_os_release.parent.mkdir(parents=True)
            etc_os_release.unlink()
            os.symlink("../usr/lib/os-release", etc_os_release)
            os.mkfifo(usr_os_release)

            with self.assertRaisesRegex(installer.InstallerError, "missing or unsafe"):
                installer.run_preflight(fixture.paths)

    def test_preflight_rejects_duplicate_os_identity_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            os_release = fixture.fake_root / "etc" / "os-release"
            os_release.write_text(
                'ID=ubuntu\nID=debian\nVERSION_ID="24.04"\n', encoding="utf-8"
            )

            with self.assertRaisesRegex(installer.InstallerError, "duplicate key: ID"):
                installer.run_preflight(fixture.paths)

    def test_preflight_rejects_oversized_os_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            os_release = fixture.fake_root / "etc" / "os-release"
            os_release.write_bytes(
                b"ID=ubuntu\nVERSION_ID=24.04\n" + (b"X" * 65536)
            )

            with self.assertRaisesRegex(installer.InstallerError, "missing or unsafe"):
                installer.run_preflight(fixture.paths)

    def test_logs_redact_values_and_sensitive_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret = "very-secret-value"
            redactor = installer.Redactor([secret])
            log = installer.InstallerLog(
                Path(temporary) / "human.log", Path(temporary) / "events.jsonl", redactor
            )
            log.info("output included %s" % secret)
            log.event("probe", password="another-value", output=secret)
            combined = (Path(temporary) / "human.log").read_text(encoding="utf-8")
            combined += (Path(temporary) / "events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret, combined)
            self.assertNotIn("another-value", combined)
            self.assertIn("[REDACTED]", combined)

    def test_bootstrap_uses_bounded_idempotent_apt_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            log = installer.InstallerLog(
                Path(temporary) / "human.log", Path(temporary) / "events.jsonl"
            )

            def runner(command, **kwargs):
                calls.append((list(command), kwargs))
                return subprocess.CompletedProcess(command, 0, stdout="apt completed\n")

            result = installer.run_bootstrap(log, runner=runner, apt_get="/usr/bin/true")
            self.assertEqual(result["packages"], list(installer.BOOTSTRAP_PACKAGES))
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], ["/usr/bin/true", "update"])
            self.assertEqual(calls[1][0][1:4], ["install", "--yes", "--no-install-recommends"])
            self.assertEqual(tuple(calls[1][0][4:]), installer.BOOTSTRAP_PACKAGES)
            self.assertIn("ufw", installer.BOOTSTRAP_PACKAGES)
            self.assertEqual(calls[0][1]["env"]["DEBIAN_FRONTEND"], "noninteractive")
            self.assertIn("apt completed", (Path(temporary) / "human.log").read_text())

    def test_streamed_command_redacts_and_fsyncs_each_line_before_wait(self):
        with tempfile.TemporaryDirectory() as temporary:
            secret = "protected-stream-value"
            human_log = Path(temporary) / "human.log"
            log = installer.InstallerLog(
                human_log,
                Path(temporary) / "events.jsonl",
                installer.Redactor([secret]),
            )
            log.bind(
                correlation_id="correlation-123",
                phase="ansible",
                attempt=2,
            )
            console = io.StringIO()

            class StreamingProcess:
                def __init__(self):
                    self.stdout = iter(["first line\n", "%s\n" % secret])

                def wait(self):
                    durable = human_log.read_text(encoding="utf-8")
                    self.assertions(durable)
                    return 0

                @staticmethod
                def assertions(durable):
                    if "first line" not in durable or "[REDACTED]" not in durable:
                        raise AssertionError("stream output was not durably logged before wait")
                    if secret in durable:
                        raise AssertionError("secret reached durable output")

            return_code = installer.run_streamed_command(
                ["/usr/bin/example"],
                log,
                "example",
                runner=lambda command, **kwargs: StreamingProcess(),
                console_stream=console,
            )
            self.assertEqual(return_code, 0)
            self.assertIn("example: first line", console.getvalue())
            self.assertIn("example: [REDACTED]", console.getvalue())
            self.assertNotIn(secret, console.getvalue())

    def test_bootstrap_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = installer.InstallerLog(
                Path(temporary) / "human.log", Path(temporary) / "events.jsonl"
            )

            def runner(command, **kwargs):
                return subprocess.CompletedProcess(command, 100, stdout="repository unavailable")

            with self.assertRaisesRegex(installer.InstallerError, "exit code 100"):
                installer.run_bootstrap(log, runner=runner, apt_get="/usr/bin/true")


class RuntimePreflightTests(unittest.TestCase):
    @staticmethod
    def command_finder(name):
        return "/usr/bin/%s" % name

    @staticmethod
    def runner(clock_output, listener_output):
        def run(command, **kwargs):
            if command[0].endswith("timedatectl"):
                output = clock_output
            else:
                output = listener_output
            return subprocess.CompletedProcess(command, 0, stdout=output)

        return run

    def test_clock_and_listener_preflight_accepts_clean_sshd_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary, dry_run=True)
            result = installer.run_runtime_preflight(
                paths,
                runner=self.runner(
                    "NTP=yes\nNTPSynchronized=yes\n",
                    'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=20,fd=3))\n',
                ),
                command_finder=self.command_finder,
            )
            self.assertTrue(result["clock_synchronized"])
            self.assertTrue(result["ssh_listener_verified"])

    def test_pending_reboot_unsynchronized_clock_and_foreign_ports_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary, dry_run=True)
            reboot_marker = paths.host_path("/var/run/reboot-required")
            reboot_marker.parent.mkdir(parents=True)
            reboot_marker.write_text("restart required\n", encoding="utf-8")
            with self.assertRaisesRegex(installer.InstallerError, "pending reboot"):
                installer.run_runtime_preflight(
                    paths,
                    runner=self.runner("NTP=yes\nNTPSynchronized=yes\n", ""),
                    command_finder=self.command_finder,
                )
            reboot_marker.unlink()
            result = installer.run_runtime_preflight(
                paths,
                runner=self.runner("NTP=yes\nNTPSynchronized=no\n", ""),
                command_finder=self.command_finder,
            )
            self.assertFalse(result["clock_synchronized"])
            with self.assertRaisesRegex(installer.InstallerError, "reserved ports: 443"):
                installer.run_runtime_preflight(
                    paths,
                    runner=self.runner(
                        "NTP=yes\nNTPSynchronized=yes\n",
                        'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=21,fd=3))\n',
                    ),
                    command_finder=self.command_finder,
                )

    def test_port_22_must_be_exclusively_owned_by_sshd(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary, dry_run=True)
            with self.assertRaisesRegex(installer.InstallerError, "exclusively owned by sshd"):
                installer.run_runtime_preflight(
                    paths,
                    runner=self.runner(
                        "NTP=yes\nNTPSynchronized=yes\n",
                        'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("other",pid=22,fd=3))\n',
                    ),
                    command_finder=self.command_finder,
                )


class BootstrapScriptTests(unittest.TestCase):
    def test_shell_bootstrap_falls_back_to_python3_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            marker = temporary_path / "python-calls.txt"
            fake_python = temporary_path / "python3"
            fake_python.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = -c ]; then exit 0; fi\n"
                "printf '%s\\n' \"$*\" >> \"$PYTHON_CALL_MARKER\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            environment = os.environ.copy()
            environment.pop("VIVO_INSTALLER_PYTHON", None)
            environment["PYTHON_CALL_MARKER"] = str(marker)
            environment["PATH"] = "%s:%s" % (temporary, environment.get("PATH", ""))
            script = MODULE_PATH.parent / "install.sh"
            completed = subprocess.run(
                ["/bin/sh", str(script), "status", "--root", "/tmp/target"],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            invocation = marker.read_text(encoding="utf-8")
            self.assertIn("vivo_cp_installer.py status --root /tmp/target", invocation)

    def test_shell_bootstrap_defaults_to_turnkey_menu(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            marker = temporary_path / "python-calls.txt"
            fake_python = temporary_path / "python3"
            fake_python.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = -c ]; then exit 0; fi\n"
                "printf '%s\\n' \"$*\" >> \"$PYTHON_CALL_MARKER\"\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            environment = os.environ.copy()
            environment.pop("VIVO_INSTALLER_PYTHON", None)
            environment["PYTHON_CALL_MARKER"] = str(marker)
            environment["PATH"] = "%s:%s" % (temporary, environment.get("PATH", ""))
            completed = subprocess.run(
                ["/bin/sh", str(MODULE_PATH.parent / "install.sh")],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(
                "vivo_cp_installer.py menu", marker.read_text(encoding="utf-8")
            )


class EngineTests(unittest.TestCase):
    def test_answer_file_requires_explicit_acceptance_before_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            with self.assertRaisesRegex(
                installer.InstallerError, "requires --accept-configuration"
            ):
                fixture.engine(accept_configuration=False).run()
            ledger = installer.read_json_file(fixture.paths.ledger)
            self.assertEqual(ledger["phases"]["answers"]["status"], "completed")
            self.assertEqual(ledger["phases"]["confirmation"]["status"], "failed")
            self.assertEqual(ledger["phases"]["bootstrap"]["status"], "pending")
            self.assertFalse(fixture.paths.secrets.exists())

    def test_interactive_install_requires_exact_confirmation_token(self):
        answers = valid_answers()
        output = io.StringIO()
        responses = iter(["yes"])
        with self.assertRaisesRegex(installer.InstallerError, "was not confirmed"):
            installer.confirm_configuration(
                answers,
                input_function=lambda prompt: next(responses),
                output_stream=output,
            )
        self.assertIn("Node FQDN: cp1.voice.example.com", output.getvalue())
        accepted = installer.confirm_configuration(
            answers,
            input_function=lambda prompt: "INSTALL",
            output_stream=io.StringIO(),
        )
        self.assertEqual(accepted["method"], "interactive-token")

    def test_dry_run_completes_with_private_state_and_no_ephemeral_vars(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            summary = fixture.engine().run()
            ledger = installer.read_json_file(fixture.paths.ledger)
            protected = installer.read_json_file(fixture.paths.secrets)
            self.assertEqual(ledger["status"], "dry-run-complete")
            self.assertTrue(all(item["status"] == "completed" for item in ledger["phases"].values()))
            self.assertTrue(summary["dry_run"])
            self.assertEqual(
                summary["console_url"], "https://controller.voice.example.com/admin/"
            )
            self.assertEqual(
                summary["documentation_url"], "https://controller.voice.example.com/docs/"
            )
            self.assertEqual(
                summary["recovery_url"], "https://controller.voice.example.com/recovery/"
            )
            self.assertEqual(ledger["phases"]["bootstrap"]["status"], "completed")
            self.assertEqual(stat.S_IMODE(fixture.paths.secrets.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(fixture.paths.credentials.stat().st_mode), 0o600)
            self.assertFalse(list(fixture.paths.state_dir.glob("ansible-vars-*.json")))
            logs = fixture.paths.human_log.read_text(encoding="utf-8")
            for value in protected.values():
                self.assertNotIn(value, logs)
            credentials = fixture.paths.credentials.read_text(encoding="utf-8")
            self.assertIn("Console URL: https://controller.voice.example.com/admin/", credentials)
            self.assertIn(
                "Documentation URL: https://controller.voice.example.com/docs/", credentials
            )
            self.assertIn(
                "Recovery URL: https://controller.voice.example.com/recovery/", credentials
            )

    def test_dry_run_does_not_require_ansible_executable_to_be_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            missing = "ansible-playbook-vivolution-definitely-unavailable"
            self.assertIsNone(installer.shutil.which(missing))
            summary = fixture.engine(ansible_playbook=missing).run()
            ledger = installer.read_json_file(fixture.paths.ledger)
            self.assertTrue(summary["dry_run"])
            self.assertEqual(
                ledger["phases"]["ansible"]["details"],
                {"reason": "dry-run", "result": "not-executed"},
            )
            self.assertIn(
                "Ansible command: %s" % missing,
                fixture.paths.human_log.read_text(encoding="utf-8"),
            )

    def test_failure_is_resumable_and_secrets_never_appear_on_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            real_paths = fixture.real_paths
            observed = {"calls": 0, "argv": [], "vars": []}

            def failing_runner(command, **kwargs):
                observed["calls"] += 1
                observed["argv"].append(list(command))
                vars_path = Path(command[command.index("--extra-vars") + 1][1:])
                values = json.loads(vars_path.read_text(encoding="utf-8"))
                observed["vars"].append(values)
                return subprocess.CompletedProcess(command, 19, stdout=values["cp_db_owner_password"])

            first = fixture.engine(dry_run=False, runner=failing_runner)
            with self.assertRaisesRegex(installer.InstallerError, "exit code 19"):
                first.run()
            secrets_before = installer.read_json_file(real_paths.secrets)
            failed_ledger = installer.read_json_file(real_paths.ledger)
            self.assertEqual(failed_ledger["phases"]["ansible"]["status"], "failed")
            flat_argv = "\0".join(observed["argv"][0])
            for value in secrets_before.values():
                self.assertNotIn(value, flat_argv)
            self.assertEqual(observed["vars"][0]["cp_db_owner_password"], secrets_before["cp_db_owner_password"])
            self.assertEqual(observed["vars"][0]["cp_ssh_allowed_user"], "ubuntu")
            self.assertEqual(
                observed["vars"][0]["cp_ingress_server_name"], "controller.voice.example.com"
            )
            self.assertEqual(
                observed["vars"][0]["cp_acme_email"], "certificates@example.com"
            )
            self.assertEqual(
                observed["vars"][0]["cp_controller_allowed_hosts"],
                "127.0.0.1,localhost,cp1.voice.example.com,controller.voice.example.com",
            )
            self.assertEqual(
                observed["vars"][0]["cp_controller_csrf_origins"],
                "https://cp1.voice.example.com,https://controller.voice.example.com",
            )
            self.assertRegex(
                observed["vars"][0]["cp_controller_base_image"], r"@sha256:[0-9a-f]{64}$"
            )
            self.assertNotIn(
                secrets_before["cp_db_owner_password"],
                real_paths.human_log.read_text(encoding="utf-8"),
            )
            self.assertFalse(list(real_paths.state_dir.glob("ansible-vars-*.json")))

            def successful_runner(command, **kwargs):
                observed["calls"] += 1
                return subprocess.CompletedProcess(command, 0, stdout="ok")

            resumed = fixture.engine(dry_run=False, runner=successful_runner)
            with self.assertRaisesRegex(installer.InstallerError, "use resume"):
                resumed.run(reconcile=True)
            summary = resumed.run(resume=True)
            self.assertEqual(observed["calls"], 2)
            self.assertFalse(summary["dry_run"])
            self.assertEqual(installer.read_json_file(real_paths.secrets), secrets_before)
            final_ledger = installer.read_json_file(real_paths.ledger)
            self.assertEqual(final_ledger["status"], "complete")
            self.assertEqual(final_ledger["run_count"], 1)
            self.assertEqual(len(final_ledger["runs"][0]["resumed_at"]), 1)
            self.assertEqual(len(final_ledger["runs"][0]["failures"]), 1)

    def test_existing_ledger_requires_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            fixture.engine().run()
            with self.assertRaisesRegex(installer.InstallerError, "use status or resume"):
                fixture.engine().run()
            with self.assertRaisesRegex(installer.InstallerError, "already complete"):
                fixture.engine().run(resume=True)

    def test_non_dry_filesystem_override_cannot_invoke_real_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            engine = fixture.engine(dry_run=False, runner=subprocess.run)
            with self.assertRaisesRegex(installer.InstallerError, "require --dry-run"):
                engine.run()

    def test_completed_dry_run_does_not_block_real_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            fixture.engine().run()
            self.assertTrue(fixture.dry_paths.ledger.exists())
            self.assertFalse(fixture.real_paths.ledger.exists())

            def successful_runner(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, stdout="ok")

            real_summary = fixture.engine(dry_run=False, runner=successful_runner).run()
            self.assertFalse(real_summary["dry_run"])
            self.assertEqual(
                installer.read_json_file(fixture.real_paths.ledger)["status"], "complete"
            )
            self.assertEqual(
                installer.read_json_file(fixture.dry_paths.ledger)["status"],
                "dry-run-complete",
            )

    def test_reconcile_reuses_identity_and_resets_only_mutable_phases(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            calls = []

            def successful_runner(command, **kwargs):
                calls.append(list(command))
                return subprocess.CompletedProcess(command, 0, stdout="ok")

            first_summary = fixture.engine(dry_run=False, runner=successful_runner).run()
            first_ledger = installer.read_json_file(fixture.real_paths.ledger)
            first_secrets = installer.read_json_file(fixture.real_paths.secrets)
            immutable_phase_records = {
                phase: json.loads(json.dumps(first_ledger["phases"][phase]))
                for phase in (
                    "preflight",
                    "answers",
                    "confirmation",
                    "bootstrap",
                    "secrets",
                )
            }
            (fixture.source_root / "controller" / "core" / "app.py").write_text(
                "CORE = 'reconciled'\n", encoding="utf-8"
            )
            second_summary = fixture.engine(dry_run=False, runner=successful_runner).run(
                reconcile=True
            )
            second_ledger = installer.read_json_file(fixture.real_paths.ledger)
            self.assertEqual(len(calls), 2)
            self.assertNotEqual(
                first_summary["controller_release_id"], second_summary["controller_release_id"]
            )
            self.assertEqual(first_summary["operation"], "install")
            self.assertEqual(second_summary["operation"], "reconcile")
            self.assertEqual(installer.read_json_file(fixture.real_paths.secrets), first_secrets)
            self.assertEqual(second_ledger["run_count"], 2)
            self.assertEqual(second_ledger["reconcile_count"], 1)
            self.assertEqual([run["kind"] for run in second_ledger["runs"]], ["install", "reconcile"])
            self.assertIn("started_at", second_ledger["runs"][1])
            self.assertIn("completed_at", second_ledger["runs"][1])
            self.assertIn("last_reconcile_started_at", second_ledger)
            self.assertIn("last_reconcile_completed_at", second_ledger)
            for phase, record in immutable_phase_records.items():
                self.assertEqual(second_ledger["phases"][phase], record)
            for phase in ("release", "ansible", "summary"):
                self.assertEqual(second_ledger["phases"][phase]["status"], "completed")

    def test_reconcile_rejects_dry_run_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            fixture.engine().run()
            with self.assertRaisesRegex(installer.InstallerError, "completed real installation"):
                fixture.engine().run(reconcile=True)

    def test_support_bundle_is_allowlisted_and_secret_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            fixture.engine().run()
            protected = installer.read_json_file(fixture.paths.secrets)
            secret = next(iter(protected.values()))
            external_markers = {
                "auth": "EXTERNAL_AUTH_SECRET_12345",
                "proxy": "PROXY_AUTH_SECRET_23456",
                "password": "PASSWORD_ASSIGNMENT_SECRET_34567",
                "token": "TOKEN_ASSIGNMENT_SECRET_45678",
                "api_key": "API_KEY_ASSIGNMENT_SECRET_56789",
                "client_secret": "CLIENT_SECRET_ASSIGNMENT_67890",
                "url": "URL_PASSWORD_SECRET_78901",
                "pem": "PEM_PRIVATE_MATERIAL_89012",
                "argv": "BUNDLED_ARGV_SECRET_90123",
            }
            ledger = installer.read_json_file(fixture.paths.ledger)
            ledger["support_note"] = "unsafe-control:\x1b secret:%s" % secret
            ledger["pattern_note"] = (
                "Authorization: Bearer {auth}\n"
                "password={password}\n"
                "token: {token}\n"
                '"api_key": "{api_key}"\n'
                "client_secret={client_secret}\n"
                "https://operator:{url}@voice.example.com/path\n"
                "-----BEGIN PRIVATE KEY-----\n"
                "{pem}\n"
                "-----END PRIVATE KEY-----"
            ).format(**external_markers)
            ledger["safe_note"] = "ordinary diagnostic text remains intact"
            installer.atomic_write_json(fixture.paths.ledger, ledger)
            installer.append_private_line(
                fixture.paths.event_log,
                json.dumps(
                    {
                        "event": "support-test",
                        "fields": {
                            "token": secret,
                            "message": (
                                "Proxy-Authorization: Basic %s\n"
                                "passwd: %s\n"
                                "safe event text"
                            )
                            % (
                                external_markers["proxy"],
                                external_markers["password"],
                            ),
                        },
                    }
                ),
            )
            installer.append_private_line(
                fixture.paths.event_log,
                json.dumps(
                    {
                        "event": "raw-command-test",
                        "fields": {
                            "command": [
                                "/usr/bin/example",
                                "--token",
                                external_markers["argv"],
                            ]
                        },
                    }
                ),
            )
            installer.append_private_line(
                fixture.paths.human_log,
                (
                    "unsafe-control:\x1b secret:%s\n"
                    "Authorization: Bearer %s\n"
                    "-----BEGIN RSA PRIVATE KEY-----\n"
                    "%s\n"
                    "-----END RSA PRIVATE KEY-----\n"
                    "safe human text"
                )
                % (secret, external_markers["auth"], external_markers["pem"]),
            )
            output = Path(temporary) / "bundle.tar.gz"
            installer.create_support_bundle(fixture.paths, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertNotIn("installer/secrets.json", names)
                self.assertNotIn("installer/credentials.txt", names)
                self.assertIn("installer/ledger.json", names)
                payloads = {
                    member.name: archive.extractfile(member).read().decode("utf-8")
                    for member in archive.getmembers()
                    if member.isfile()
                }
                combined = "".join(payloads.values())
            for value in protected.values():
                self.assertNotIn(value, combined)
            for marker in external_markers.values():
                self.assertNotIn(marker, combined)
            parsed_ledger = json.loads(payloads["installer/ledger.json"])
            self.assertIn("[REDACTED]", parsed_ledger["support_note"])
            self.assertIn("[REDACTED]", parsed_ledger["pattern_note"])
            self.assertIn("[REDACTED PRIVATE KEY]", parsed_ledger["pattern_note"])
            self.assertEqual(
                parsed_ledger["safe_note"], "ordinary diagnostic text remains intact"
            )
            event_records = [
                json.loads(line)
                for line in payloads["logs/events.jsonl"].splitlines()
                if line
            ]
            self.assertTrue(any(record["event"] == "support-test" for record in event_records))
            self.assertGreater(payloads["installer/ledger.json"].count("\n"), 1)
            self.assertGreater(payloads["logs/events.jsonl"].count("\n"), 1)
            self.assertNotIn("\x1b", combined)
            self.assertIn("\\x1b", payloads["logs/install.log"])
            self.assertIn("safe event text", payloads["logs/events.jsonl"])
            self.assertIn("safe human text", payloads["logs/install.log"])
            self.assertNotIn("BEGIN RSA PRIVATE KEY", payloads["logs/install.log"])

    def test_status_uses_phase_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)
            self.assertEqual(installer.installer_status(fixture.paths)["status"], "not-installed")
            fixture.engine().run()
            status = installer.installer_status(fixture.paths)
            self.assertEqual(status["status"], "dry-run-complete")
            self.assertTrue(all(value == "completed" for value in status["phases"].values()))

    def test_generated_security_keys_are_exact_lowercase_hex_and_independent(self):
        generated = installer.generate_secrets()
        self.assertRegex(generated["cp_rls_context_key"], r"^[0-9a-f]{64}$")
        self.assertRegex(
            generated["cp_edge_enrollment_token_pepper"],
            r"^[0-9a-f]{64}$",
        )
        self.assertNotEqual(
            generated["cp_rls_context_key"],
            generated["cp_edge_enrollment_token_pepper"],
        )
        installer.validate_secrets(generated)
        generated["cp_rls_context_key"] = "A" * 64
        with self.assertRaisesRegex(installer.InstallerError, "64 lowercase hexadecimal"):
            installer.validate_secrets(generated)

        generated = installer.generate_secrets()
        generated["cp_edge_enrollment_token_pepper"] = generated["cp_rls_context_key"]
        with self.assertRaisesRegex(installer.InstallerError, "must be independent"):
            installer.validate_secrets(generated)


class UniversalInstallerFoundationTests(unittest.TestCase):
    def test_no_argument_menu_dispatch_does_not_require_path_attributes(self):
        original_version = installer.sys.version_info
        original_selector = installer.select_installer_action
        original_diagnostics = installer.diagnostics_report
        original_stdout = installer.sys.stdout
        try:
            installer.sys.version_info = (3, 12)
            installer.select_installer_action = lambda: "diagnostics"
            installer.diagnostics_report = lambda *args, **kwargs: {"ready": True}
            installer.sys.stdout = io.StringIO()
            self.assertEqual(installer.main([]), 0)
            self.assertIn('"ready": true', installer.sys.stdout.getvalue().lower())
        finally:
            installer.sys.version_info = original_version
            installer.select_installer_action = original_selector
            installer.diagnostics_report = original_diagnostics
            installer.sys.stdout = original_stdout

    def test_numbered_menu_shows_but_cannot_execute_unavailable_roles(self):
        responses = iter(("2", "3", "1"))
        messages = []
        selected = installer.select_installer_action(
            input_function=lambda prompt: next(responses),
            output_function=messages.append,
        )
        self.assertEqual(selected, "create-controller")
        rendered = "\n".join(messages)
        self.assertIn("Join an existing Controller Plane (not yet available)", rendered)
        self.assertIn("Deploy an Edge Appliance (SBC) (not yet available)", rendered)
        self.assertGreaterEqual(rendered.count("no action was taken"), 2)

    def test_arrow_menu_movement_skips_disabled_roles(self):
        self.assertEqual(
            installer._next_enabled_index(installer.MENU_OPTIONS, 0, 1), 3
        )
        self.assertEqual(
            installer._next_enabled_index(installer.MENU_OPTIONS, 0, -1), 4
        )

    def test_public_ipv4_discovery_requires_consensus_and_reports_disagreement(self):
        values = {
            "https://one.example/ip": "1.1.1.1",
            "https://two.example/ip": "1.1.1.1",
            "https://three.example/ip": "8.8.8.8",
        }
        result = installer.discover_public_ipv4(
            fetcher=lambda source: values[source], sources=tuple(values)
        )
        self.assertEqual(result["address"], "1.1.1.1")
        self.assertEqual(result["confirmed_by"], 2)
        self.assertTrue(result["disagreement"])
        tied = installer.discover_public_ipv4(
            fetcher=lambda source: values[source],
            sources=("https://one.example/ip", "https://three.example/ip"),
        )
        self.assertIsNone(tied["address"])

    def test_majority_public_ipv4_disagreement_is_always_warned(self):
        responses = iter(
            (
                "node.voice.example.com",
                "controller.voice.example.com",
                "",
                "1",
                "cpadmin",
                "admin@example.com",
                "",
                "ubuntu",
                "1",
            )
        )
        messages = []
        answers = installer.prompt_answers(
            input_function=lambda prompt: next(responses),
            output_function=messages.append,
            environment={},
            public_ip_discoverer=lambda: {
                "address": "1.1.1.1",
                "confirmed_by": 2,
                "observations": [
                    {"source": "one", "address": "1.1.1.1"},
                    {"source": "two", "address": "1.1.1.1"},
                    {"source": "three", "address": "8.8.8.8"},
                ],
                "errors": [],
                "disagreement": True,
            },
            timezone_selector=lambda **kwargs: "Etc/UTC",
        )
        self.assertEqual(answers["public_ipv4"], "1.1.1.1")
        self.assertTrue(
            any("services disagreed" in message for message in messages)
        )

    def test_infrastructure_firewall_and_time_contract_are_validated(self):
        answers = valid_answers()
        answers.update(
            firewall_mode="infrastructure",
            ssh_source_cidrs=[],
            timezone="Asia/Dubai",
            ntp_mode="custom",
            ntp_servers=["time.cloudflare.com", "1.1.1.1"],
        )
        normalized = installer.validate_answers(answers)
        self.assertEqual(normalized["ssh_source_cidrs"], [])
        self.assertEqual(normalized["timezone"], "Asia/Dubai")
        self.assertNotIn(
            "ufw", installer.bootstrap_packages_for_answers(normalized)
        )
        values = installer.build_ansible_vars(
            normalized,
            installer.generate_secrets(),
            "cp1-%s" % ("a" * 64),
            "docker.io/library/python@sha256:%s" % ("b" * 64),
        )
        self.assertEqual(values["cp_firewall_mode"], "infrastructure")
        self.assertEqual(values["cp_timezone"], "Asia/Dubai")
        self.assertEqual(values["cp_ntp_mode"], "custom")
        self.assertEqual(values["cp_ntp_servers"], ["time.cloudflare.com", "1.1.1.1"])

    def test_dns_wait_retry_is_interactive_and_unattended_retry_is_bounded(self):
        answers = valid_answers()
        calls = {"count": 0}

        def eventually_ready(host, port, family, socket_type):
            calls["count"] += 1
            if calls["count"] <= 1:
                raise socket.gaierror(socket.EAI_NONAME, "missing")
            if family == socket.AF_INET6:
                return []
            return [(family, socket_type, 6, "", ("1.1.1.1", port))]

        interactive_flushes = []
        updated, resolved = installer.wait_for_answer_dns(
            answers,
            resolver=eventually_ready,
            input_function=lambda prompt: "1",
            output_function=lambda message: None,
            auto_retry_delays=(0,),
            cache_flusher=lambda: (
                interactive_flushes.append(True)
                or {"attempted": True, "success": True}
            ),
        )
        self.assertEqual(updated["shared_fqdn"], answers["shared_fqdn"])
        self.assertEqual(len(resolved), 2)
        self.assertEqual(interactive_flushes, [True])

        unattended_calls = []

        def never_ready(*args):
            unattended_calls.append(args)
            raise socket.gaierror(socket.EAI_NONAME, "missing")

        sleeps = []
        unattended_flushes = []
        with self.assertRaisesRegex(installer.InstallerError, "3 bounded attempts"):
            installer.wait_for_answer_dns(
                answers,
                resolver=never_ready,
                interactive=False,
                auto_retry_delays=(0, 1, 2),
                sleep_function=sleeps.append,
                cache_flusher=lambda: (
                    unattended_flushes.append(True)
                    or {"attempted": True, "success": True}
                ),
            )
        self.assertEqual(len(unattended_calls), 3)
        self.assertEqual(sleeps, [1, 2])
        self.assertEqual(unattended_flushes, [True, True])

    def test_changed_dns_answers_are_persisted_before_safe_exit(self):
        answers = valid_answers()
        responses = iter(
            (
                "3",
                "new-node.voice.example.com",
                "new-controller.voice.example.com",
                "2.2.2.2",
                "4",
            )
        )
        persisted = []

        with self.assertRaisesRegex(installer.InstallerError, "deferred"):
            installer.wait_for_answer_dns(
                answers,
                resolver=lambda *args: (_ for _ in ()).throw(
                    socket.gaierror(socket.EAI_NONAME, "missing")
                ),
                input_function=lambda prompt: next(responses),
                output_function=lambda message: None,
                cache_flusher=lambda: {"attempted": False, "success": False},
                answers_changed=lambda updated: persisted.append(updated),
            )

        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["node_fqdn"], "new-node.voice.example.com")
        self.assertEqual(
            persisted[0]["shared_fqdn"], "new-controller.voice.example.com"
        )
        self.assertEqual(persisted[0]["public_ipv4"], "2.2.2.2")

    def test_local_dns_cache_flush_is_bounded_and_argument_safe(self):
        commands = []

        def runner(command, **kwargs):
            commands.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout="")

        result = installer.flush_local_dns_cache(
            command_finder=lambda name: "/usr/bin/resolvectl",
            runner=runner,
        )
        self.assertTrue(result["success"])
        self.assertEqual(commands[0][0], ["/usr/bin/resolvectl", "flush-caches"])
        self.assertEqual(commands[0][1]["timeout"], 10)

    def test_diagnostics_is_read_only_and_reports_initial_unsynchronized_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InstallerFixture(temporary)

            def runner(command, **kwargs):
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout="NTP=yes\nNTPSynchronized=no\nTimezone=Etc/UTC\n",
                )

            report = installer.diagnostics_report(
                fixture.real_paths,
                public_ip_discoverer=lambda: {
                    "address": "1.1.1.1",
                    "confirmed_by": 2,
                    "observations": [],
                    "errors": [],
                    "disagreement": False,
                },
                runner=runner,
                command_finder=lambda name: "/usr/bin/%s" % name,
            )
            self.assertTrue(report["host_os"]["ready"])
            self.assertFalse(report["time"]["synchronized"])
            self.assertFalse(fixture.real_paths.state_dir.exists())
            self.assertFalse(fixture.real_paths.log_dir.exists())

    def test_discard_incomplete_requires_proof_plan_and_exact_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            installer.ensure_private_directory(paths.state_dir)
            installer.ensure_private_directory(paths.log_dir)
            ledger = installer.PhaseLedger.create(paths.ledger)
            installer.initialize_ownership_manifest(paths, ledger)
            installer.atomic_write_json(paths.answers, valid_answers())
            installer.append_private_line(paths.human_log, "safe log")
            installer.append_private_line(paths.event_log, "{}")

            plan = installer.discard_incomplete(paths, dry_run=True)
            self.assertTrue(plan["pre_mutation_proven"])
            self.assertTrue(paths.ledger.exists())
            with self.assertRaisesRegex(installer.InstallerError, "did not match"):
                installer.discard_incomplete(
                    paths,
                    confirmation_token="DELETE",
                    output_stream=io.StringIO(),
                )
            completed = installer.discard_incomplete(
                paths,
                confirmation_token=installer.DISCARD_CONFIRMATION_TOKEN,
                output_stream=io.StringIO(),
            )
            self.assertIn("discarded_at", completed)
            self.assertFalse(paths.state_dir.exists())
            self.assertFalse(paths.log_dir.exists())
            self.assertTrue(paths.lock.exists())
            self.assertNotIn(str(paths.state_dir), str(paths.lock))

    def test_discard_refuses_any_started_mutation_phase_or_unknown_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            installer.ensure_private_directory(paths.state_dir)
            installer.ensure_private_directory(paths.log_dir)
            ledger = installer.PhaseLedger.create(paths.ledger)
            installer.initialize_ownership_manifest(paths, ledger)
            ledger.start_phase("bootstrap")
            with self.assertRaisesRegex(installer.InstallerError, "phase bootstrap"):
                installer.discard_incomplete(paths, dry_run=True)

        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            installer.ensure_private_directory(paths.state_dir)
            installer.ensure_private_directory(paths.log_dir)
            ledger = installer.PhaseLedger.create(paths.ledger)
            installer.initialize_ownership_manifest(paths, ledger)
            (paths.state_dir / "unexpected.bin").write_bytes(b"unknown")
            with self.assertRaisesRegex(installer.InstallerError, "unexpected state object"):
                installer.discard_incomplete(paths, dry_run=True)

    def test_discard_refuses_corrupt_or_unlinked_ownership_manifests(self):
        def variants(valid, paths, ledger):
            cases = {"empty": {}}

            wrong_schema = json.loads(json.dumps(valid))
            wrong_schema["schema_version"] = 2
            cases["wrong-schema"] = wrong_schema

            wrong_id = json.loads(json.dumps(valid))
            wrong_id["installation_id"] = "not-%s" % ledger.value["installation_id"]
            cases["wrong-installation-id"] = wrong_id

            wrong_state = json.loads(json.dumps(valid))
            wrong_state["state"] = "installed"
            cases["wrong-state"] = wrong_state

            wrong_roots = json.loads(json.dumps(valid))
            wrong_roots["namespace_roots"][0] = "/var/lib/not-vivolution"
            cases["wrong-roots"] = wrong_roots

            wrong_tombstone = json.loads(json.dumps(valid))
            wrong_tombstone["tombstone_path"] = str(paths.state_dir / "other.json")
            cases["wrong-tombstone"] = wrong_tombstone

            integrations = json.loads(json.dumps(valid))
            integrations["system_integrations"] = ["/etc/unsafe"]
            cases["integration-evidence"] = integrations

            requested = json.loads(json.dumps(valid))
            requested["packages"]["requested"] = ["ansible-core"]
            cases["requested-packages"] = requested

            installed = json.loads(json.dumps(valid))
            installed["packages"]["installed_by_installer"] = ["ansible-core"]
            cases["installed-packages"] = installed

            preexisting = json.loads(json.dumps(valid))
            preexisting["packages"]["preexisting"] = ["ca-certificates"]
            cases["preexisting-packages"] = preexisting

            wrong_package_type = json.loads(json.dumps(valid))
            wrong_package_type["packages"]["requested"] = "ansible-core"
            cases["wrong-package-type"] = wrong_package_type

            missing_package_key = json.loads(json.dumps(valid))
            del missing_package_key["packages"]["preexisting"]
            cases["missing-package-key"] = missing_package_key

            extra_package_key = json.loads(json.dumps(valid))
            extra_package_key["packages"]["unexpected"] = []
            cases["extra-package-key"] = extra_package_key

            extra_top_key = json.loads(json.dumps(valid))
            extra_top_key["unexpected"] = True
            cases["extra-top-key"] = extra_top_key

            wrong_created_at = json.loads(json.dumps(valid))
            wrong_created_at["created_at"] = []
            cases["wrong-created-at-type"] = wrong_created_at
            return cases

        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            paths.ensure_state_log_directories()
            ledger = installer.PhaseLedger.create(paths.ledger)
            valid = installer.initialize_ownership_manifest(paths, ledger)
            installer.atomic_write_json(paths.answers, valid_answers())
            installer.append_private_line(paths.human_log, "safe log")
            installer.append_private_line(paths.event_log, "{}")

            for name, corrupt in variants(valid, paths, ledger).items():
                with self.subTest(name=name):
                    installer.atomic_write_json(paths.ownership, corrupt)
                    with self.assertRaisesRegex(
                        installer.InstallerError, "ownership"
                    ):
                        installer.discard_incomplete(paths, dry_run=True)

            installer.atomic_write_json(paths.ownership, valid)
            self.assertTrue(
                installer.discard_incomplete(paths, dry_run=True)[
                    "pre_mutation_proven"
                ]
            )

    def test_discard_holds_lock_and_aborts_if_plan_changes_during_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            paths.ensure_state_log_directories()
            ledger = installer.PhaseLedger.create(paths.ledger)
            installer.initialize_ownership_manifest(paths, ledger)
            installer.atomic_write_json(paths.answers, valid_answers())
            installer.append_private_line(paths.human_log, "safe log")
            installer.append_private_line(paths.event_log, "{}")
            displayed = io.StringIO()

            def mutate_while_prompted(_prompt):
                with self.assertRaisesRegex(
                    installer.InstallerError, "Another Vivolution installer process"
                ):
                    with paths.exclusive_lock():
                        pass
                installer.atomic_write_json(paths.tombstone, {"late": True})
                return installer.DISCARD_CONFIRMATION_TOKEN

            with self.assertRaisesRegex(installer.InstallerError, "state changed"):
                installer.discard_incomplete(
                    paths,
                    input_function=mutate_while_prompted,
                    output_stream=displayed,
                )

            self.assertTrue(paths.ledger.exists())
            self.assertTrue(paths.answers.exists())
            self.assertTrue(paths.tombstone.exists())
            self.assertNotIn(str(paths.tombstone), displayed.getvalue())

    def test_legacy_schema4_pre_mutation_state_is_detected_but_execution_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = installer.InstallerPaths(root=temporary)
            installer.ensure_private_directory(paths.legacy_state_dir)
            installer.ensure_private_directory(paths.legacy_log_dir)
            ledger = installer.PhaseLedger.create(paths.legacy_ledger)
            value = ledger.value
            value["schema_version"] = 4
            installer.atomic_write_json(paths.legacy_ledger, value)
            installer.atomic_write_json(paths.legacy_state_dir / "answers.json", valid_answers())
            installer.append_private_line(paths.legacy_log_dir / "install.log", "legacy")
            detected = installer.detect_legacy_state(paths)
            self.assertEqual(detected["schema_version"], 4)
            self.assertEqual(installer.installer_status(paths)["status"], "legacy-state-detected")
            plan = installer.discard_incomplete(paths, dry_run=True)
            self.assertEqual(plan["source"], "legacy-schema-4")
            self.assertEqual(
                installer.select_manage_action(
                    paths,
                    input_function=lambda prompt: "6",
                    output_function=lambda message: None,
                ),
                "preview-legacy-cleanup",
            )
            with self.assertRaisesRegex(installer.InstallerError, "plan-only"):
                installer.discard_incomplete(
                    paths,
                    confirmation_token=installer.DISCARD_CONFIRMATION_TOKEN,
                    output_stream=io.StringIO(),
                )
            self.assertTrue(paths.legacy_state_dir.exists())
            self.assertTrue(paths.legacy_log_dir.exists())

    def test_public_ip_fetch_forces_ipv4_and_https_only_redirects(self):
        original_run = installer.subprocess.run
        original_which = installer.shutil.which
        observed = {}
        try:
            installer.shutil.which = lambda name: "/usr/bin/curl"

            def fake_run(command, **kwargs):
                observed["command"] = command
                return subprocess.CompletedProcess(command, 0, stdout=b"1.1.1.1\n", stderr=b"")

            installer.subprocess.run = fake_run
            self.assertEqual(
                installer._https_ipv4_fetch("https://ifconfig.me/ip"), "1.1.1.1"
            )
        finally:
            installer.subprocess.run = original_run
            installer.shutil.which = original_which
        command = observed["command"]
        self.assertIn("--ipv4", command)
        self.assertEqual(command[command.index("--proto") + 1], "=https")
        self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
        self.assertIn("--tlsv1.2", command)

    def test_structured_logging_redacts_and_caps_command_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "super-secret-token-value"
            log = installer.InstallerLog(
                root / "install.log",
                root / "events.jsonl",
                installer.Redactor([secret]),
            )
            log.bind(
                correlation_id="correlation-123",
                phase="ansible",
                attempt=2,
            )
            result = installer.run_streamed_command(
                ["/usr/bin/example", "--token", secret],
                log,
                "example",
                runner=lambda command, **kwargs: subprocess.CompletedProcess(
                    command, 0, stdout="\x1b[31m%s\x1b[0m\nsecond line\n" % secret
                ),
                console_stream=io.StringIO(),
                show_output=False,
                max_output_lines=1,
                max_output_bytes=1024,
            )
            self.assertEqual(result, 0)
            combined = (root / "install.log").read_text(encoding="utf-8") + (
                root / "events.jsonl"
            ).read_text(encoding="utf-8")
            self.assertNotIn(secret, combined)
            self.assertNotIn("\x1b", combined)
            self.assertIn("\\x1b", combined)
            self.assertIn("command_output_truncated", combined)
            records = [
                json.loads(line)
                for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(any(record.get("category") == "command" for record in records))
            started = next(record for record in records if record["event"] == "command_started")
            self.assertEqual(started["fields"]["correlation_id"], "correlation-123")
            self.assertEqual(started["fields"]["phase"], "ansible")
            self.assertEqual(started["fields"]["attempt"], 2)
            self.assertEqual(started["fields"]["step"], "example")
            self.assertEqual(started["fields"]["effective_uid"], os.geteuid())
            self.assertEqual(
                started["fields"]["effective_user"],
                installer.pwd.getpwuid(os.geteuid()).pw_name,
            )

    def test_streaming_command_pattern_redaction_in_console_human_and_jsonl(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            human = root / "install.log"
            events = root / "events.jsonl"
            console = io.StringIO()
            log = installer.InstallerLog(human, events)
            markers = (
                "EXTERNAL_AUTH_SECRET_12345",
                "PROXY_AUTH_SECRET_23456",
                "PASSWORD_ASSIGNMENT_34567",
                "TOKEN_ASSIGNMENT_45678",
                "URL_CREDENTIAL_56789",
                "PEM_PRIVATE_MATERIAL_67890",
            )
            output = (
                "Authorization: Bearer %s\n"
                "pRoXy-AuThOrIzAtIoN: Basic %s\n"
                "password=%s\n"
                '"token": "%s"\n'
                "https://operator:%s@example.com/path\n"
                "-----BEGIN PRIVATE KEY-----\n"
                "%s\n"
                "-----END PRIVATE KEY-----\n"
                "safe streamed text\n"
            ) % markers

            result = installer.run_streamed_command(
                ["/usr/bin/example"],
                log,
                "example",
                runner=lambda command, **kwargs: subprocess.CompletedProcess(
                    command, 0, stdout=output
                ),
                console_stream=console,
            )

            self.assertEqual(result, 0)
            combined = (
                human.read_text(encoding="utf-8")
                + events.read_text(encoding="utf-8")
                + console.getvalue()
            )
            for marker in markers:
                self.assertNotIn(marker, combined)
            self.assertIn("[REDACTED]", combined)
            self.assertIn("[REDACTED PRIVATE KEY]", combined)
            self.assertIn("safe streamed text", combined)
            for line in events.read_text(encoding="utf-8").splitlines():
                json.loads(line)

    def test_command_argv_semantics_redact_separate_secret_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            human = root / "install.log"
            events = root / "events.jsonl"
            log = installer.InstallerLog(human, events)
            markers = (
                "ARGV_TOKEN_SECRET_12345",
                "ARGV_PASSWORD_SECRET_23456",
                "ARGV_API_KEY_SECRET_34567",
                "ARGV_CLIENT_SECRET_45678",
                "ARGV_AUTH_HEADER_SECRET_56789",
            )
            raw_command = [
                "/usr/bin/example",
                "--token",
                markers[0],
                "--password",
                markers[1],
                "--api-key",
                markers[2],
                "--client-secret",
                markers[3],
                "-H",
                "Authorization: Bearer %s" % markers[4],
                "--header",
                "User-Agent: Vivolution-safe-client",
                "--ordinary",
                "safe-argument",
            ]
            observed = []

            def runner(command, **kwargs):
                observed.append(list(command))
                return subprocess.CompletedProcess(command, 0, stdout="safe output\n")

            self.assertEqual(
                installer.run_streamed_command(
                    raw_command,
                    log,
                    "example",
                    runner=runner,
                    show_output=False,
                ),
                0,
            )
            self.assertEqual(observed, [raw_command])
            combined = human.read_text(encoding="utf-8") + events.read_text(
                encoding="utf-8"
            )
            for marker in markers:
                self.assertNotIn(marker, combined)
            self.assertIn("Vivolution-safe-client", combined)
            self.assertIn("safe-argument", combined)
            records = [
                json.loads(line)
                for line in events.read_text(encoding="utf-8").splitlines()
            ]
            for event_name in ("command_started", "command_completed"):
                record = next(record for record in records if record["event"] == event_name)
                self.assertEqual(
                    sum(
                        "[REDACTED]" in argument
                        for argument in record["fields"]["command"]
                    ),
                    5,
                )

    def test_effective_identity_uses_kernel_uid_and_account_database(self):
        original_geteuid = installer.os.geteuid
        original_getpwuid = installer.pwd.getpwuid
        try:
            installer.os.geteuid = lambda: 4242

            class Entry:
                pw_name = "effective-service-user"

            installer.pwd.getpwuid = lambda uid: Entry()
            self.assertEqual(
                installer.effective_process_identity(),
                (4242, "effective-service-user"),
            )
        finally:
            installer.os.geteuid = original_geteuid
            installer.pwd.getpwuid = original_getpwuid


if __name__ == "__main__":
    unittest.main()
