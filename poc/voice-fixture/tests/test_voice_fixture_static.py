#!/usr/bin/env python3
"""Offline security and contract checks for the isolated voice fixture."""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


class VoiceFixtureStaticTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_all_expected_artifacts_exist(self) -> None:
        required = [
            "README.md",
            "install.yml",
            "teardown.yml",
            "roles/voice_fixture/tasks/main.yml",
            "roles/voice_fixture/handlers/main.yml",
            "roles/voice_fixture/files/asterisk/Containerfile",
            "roles/voice_fixture/files/sipp/Containerfile",
            "roles/voice_fixture/files/sipp/bin/fixture_sipp.py",
            "roles/voice_fixture/files/bin/synthetic_cdr_evidence.py",
            "roles/voice_fixture/files/sipp/scenarios/teams-uac.xml",
            "roles/voice_fixture/files/sipp/scenarios/teams-uas.xml",
            "roles/voice_fixture/templates/vivolution-voice-fixture-asterisk.container.j2",
            "roles/voice_fixture/templates/vivolution-voice-fixture-sipp.container.j2",
            "roles/voice_fixture/templates/vivolution-voice-fixture-tmpfiles.conf.j2",
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2",
            "roles/voice_fixture/templates/vivolution-voice-fixture-test.j2",
            "roles/voice_fixture_teardown/tasks/main.yml",
        ]
        for relative in required:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).is_file())

    def test_fixed_private_contract(self) -> None:
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        for expected in [
            "voice_fixture_controller_ipv4: 10.20.1.4",
            "voice_fixture_edge_subnet_ipv4: 10.20.2.0/24",
            "voice_fixture_sbc1_ipv4: 10.20.2.4",
            "voice_fixture_sbc2_ipv4: 10.20.2.5",
            "voice_fixture_edge_teams_tls_port: 5061",
            "voice_fixture_edge_pbx_mtls_port: 15061",
            "voice_fixture_edge_rtp_start: 20000",
            "voice_fixture_edge_rtp_end: 20255",
            "voice_fixture_asterisk_tls_port: 16061",
            "voice_fixture_asterisk_rtp_start: 21000",
            "voice_fixture_asterisk_rtp_end: 21127",
            "voice_fixture_sipp_uas_tls_port: 25061",
            "voice_fixture_sipp_uac_tls_port: 25062",
            "voice_fixture_sipp_probe_tls_port: 25063",
            "voice_fixture_sipp_rtp_start: 22000",
            "voice_fixture_sipp_rtp_end: 22063",
        ]:
            self.assertIn(expected, defaults)

    def test_runtime_services_are_private_and_egress_denied(self) -> None:
        for name in ("asterisk", "sipp"):
            quadlet = self.read(
                f"roles/voice_fixture/templates/vivolution-voice-fixture-{name}.container.j2"
            )
            self.assertIn("Network=host", quadlet)
            self.assertIn("ReadOnly=true", quadlet)
            self.assertIn("DropCapability=all", quadlet)
            self.assertIn("NoNewPrivileges=true", quadlet)
            self.assertIn("IPAddressDeny=any", quadlet)
            self.assertIn("IPAddressAllow={{ voice_fixture_controller_ipv4 }}/32", quadlet)
            self.assertIn("IPAddressAllow={{ voice_fixture_edge_subnet_ipv4 }}", quadlet)
            self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET", quadlet)
            self.assertNotIn("AF_INET6", quadlet)
            self.assertIn("SocketBindDeny=any", quadlet)
            self.assertIn("Pull=never", quadlet)
            self.assertRegex(quadlet, r"Image=\{\{ voice_fixture_\w+_image_id \}\}")

        asterisk = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-asterisk.container.j2"
        )
        for directory in ("lib", "run", "spool"):
            self.assertIn(
                "Volume={{ voice_fixture_runtime_root }}/asterisk/"
                f"{directory}:/var/{directory if directory != 'run' else 'run'}/asterisk:rw",
                asterisk,
            )
        self.assertNotRegex(asterisk, r"Tmpfs=/var/(?:lib|run|spool)/asterisk")
        self.assertNotIn("uid=10001", asterisk)
        self.assertNotIn("gid=10001", asterisk)

    def test_asterisk_writable_paths_use_protected_ephemeral_bind_sources(self) -> None:
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        tmpfiles = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-tmpfiles.conf.j2"
        )
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        teardown = self.read("roles/voice_fixture_teardown/tasks/main.yml")
        self.assertIn("voice_fixture_runtime_root: /run/vivolution-voice-fixture", defaults)
        self.assertEqual(tasks.count("owner: '10001'"), 5)
        self.assertIn(
            "voice_fixture_runtime_root == '/run/vivolution-voice-fixture'",
            tasks,
        )
        for directory in ("asterisk", "asterisk/lib", "asterisk/run", "asterisk/spool"):
            self.assertIn(f"{{{{ voice_fixture_runtime_root }}}}/{directory}", tasks)
            self.assertIn(f"{{{{ voice_fixture_runtime_root }}}}/{directory}", tmpfiles)
        self.assertIn("mode: '0700'", tasks)
        self.assertIn("systemd-tmpfiles", tasks)
        self.assertIn("10001 10001", tmpfiles)
        self.assertIn("stat --format='%u:%g:%a'", readiness)
        self.assertIn("'10001:10001:700'", readiness)
        for option in ("nosuid", "nodev", "noexec"):
            self.assertIn(option, readiness)
        self.assertIn("/etc/tmpfiles.d/vivolution-voice-fixture.conf", teardown)
        self.assertIn('"{{ voice_fixture_runtime_root }}"', teardown)

    def test_asterisk_has_no_carrier_registration_or_command_execution(self) -> None:
        configs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "roles/voice_fixture/templates").glob("*.conf.j2")
        ).lower()
        self.assertNotRegex(configs, r"(?m)^\s*register\s*=>")
        self.assertNotIn("system(", configs)
        self.assertNotIn("shell(", configs)
        self.assertIn("noload=app_system.so", configs)
        self.assertIn("noload=func_shell.so", configs)
        self.assertIn("+9710000001001", configs)
        self.assertIn("exten => +9710000001001,1,noop", configs)
        self.assertIn("exten => 911,1,hangup(21)", configs)
        self.assertIn("exten => 112,1,hangup(21)", configs)
        self.assertIn("exten => 999,1,hangup(21)", configs)
        self.assertEqual(configs.count("dial(pjsip/"), 2)
        self.assertNotRegex(configs, r"(?i)(pstn|carrier).*@")

    def test_public_edge_server_and_private_client_trust_are_separated(self) -> None:
        pjsip = self.read("roles/voice_fixture/templates/pjsip.conf.j2")
        leaf_profile = self.read("roles/voice_fixture/templates/leaf-extensions.cnf.j2")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("[fixture-mtls-server]", pjsip)
        self.assertIn("ca_list_file=/run/fixture-pki/ca.crt", pjsip)
        self.assertIn("[fixture-public-client]", pjsip)
        self.assertIn("ca_list_file=/run/fixture-pki/public-ca.crt", pjsip)
        self.assertIn("contact=sips:{{ voice_fixture_sbc1_server_name }}", pjsip)
        self.assertIn("contact=sips:{{ voice_fixture_sbc2_server_name }}", pjsip)
        self.assertIn("extendedKeyUsage={{ item.extended_key_usage }}", leaf_profile)
        self.assertEqual(tasks.count("extended_key_usage: clientAuth\n"), 2)
        self.assertEqual(tasks.count("extended_key_usage: serverAuth,clientAuth\n"), 2)
        self.assertIn("Reject Edge client identities as fixture server certificates", tasks)

    def test_fixture_pki_rotation_is_expiry_aware_and_atomic(self) -> None:
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("voice_fixture_leaf_renewal_seconds: 259200", defaults)
        self.assertIn("voice_fixture_ca_renewal_seconds: 1209600", defaults)
        self.assertIn("pki-generations", defaults)
        self.assertIn("-checkend", tasks)
        self.assertIn("voice_fixture_pki_rotation_required", tasks)
        self.assertIn("Reuse current private keys without exposing them", tasks)
        self.assertIn("generation-[0-9a-f]{32}", tasks)
        self.assertIn("Atomically select the complete PKI generation", tasks)
        self.assertIn("--no-target-directory", tasks)
        self.assertIn("ca.srl", tasks)
        self.assertIn("-CAserial", tasks)
        self.assertIn("Prove renewed serials are unique", tasks)
        self.assertNotIn("-set_serial", tasks)
        for reused in ("0x1001", "0x1002", "0x2001", "0x2002"):
            self.assertNotIn(reused, tasks)
        self.assertNotRegex(
            tasks,
            r"creates:\s+\"\{\{ voice_fixture_pki_root \}\}/[^\n]+\.(?:crt|csr|key)\"",
        )

    def test_sipp_scenarios_are_bounded_tls_only(self) -> None:
        for scenario_name in ("teams-uac.xml", "teams-uas.xml"):
            path = ROOT / "roles/voice_fixture/files/sipp/scenarios" / scenario_name
            ET.parse(path)
            scenario = path.read_text(encoding="utf-8")
            self.assertIn("transport=tls", scenario)
            self.assertIn("RTP/AVP 0 8", scenario)
            self.assertNotIn("REGISTER", scenario)
            self.assertNotRegex(scenario, r"(?i)(tel:|911|999@|emergency|carrier)")
        self.assertIn("m=audio 22032", self.read(
            "roles/voice_fixture/files/sipp/scenarios/teams-uac.xml"
        ))
        self.assertIn("m=audio 22000", self.read(
            "roles/voice_fixture/files/sipp/scenarios/teams-uas.xml"
        ))
        self.assertIn("^INVITE sips?:\\+9710000001001@", self.read(
            "roles/voice_fixture/files/sipp/scenarios/teams-uas.xml"
        ))
        self.assertIn("INVITE sip:+9710000001001@", self.read(
            "roles/voice_fixture/files/sipp/scenarios/teams-uac.xml"
        ))

    def test_runner_has_exact_target_allowlist_and_rtp_evidence(self) -> None:
        runner = self.read("roles/voice_fixture/files/sipp/bin/fixture_sipp.py")
        self.assertIn('EDGE_IPS = {ipaddress.ip_address("10.20.2.4"), ipaddress.ip_address("10.20.2.5")}', runner)
        self.assertIn("if target not in EDGE_IPS", runner)
        self.assertIn("if args.target_port != 5061", runner)
        self.assertIn('packet[0] >> 6 == 2', runner)
        self.assertIn('summary["packets_received"] < 1', runner)
        self.assertIn("ssl.create_default_context", runner)
        self.assertIn('cafile="/run/fixture-pki/public-ca.crt"', runner)
        self.assertIn("resolved != {expected_ip}", runner)
        self.assertIn('"-bind_local"', runner)
        self.assertIn('"-ci",\n        "127.0.0.1"', runner)
        self.assertIn('"-nostdin"', runner)
        self.assertNotIn("shell=True", runner)
        self.assertNotIn("os.system", runner)

    def test_test_driver_is_serialized_and_content_addressed(self) -> None:
        script = self.read("roles/voice_fixture/templates/vivolution-voice-fixture-test.j2")
        self.assertIn("flock --exclusive --nonblock", script)
        self.assertIn("case \"$node\" in", script)
        self.assertIn("^sha256:[0-9a-f]{64}$", script)
        self.assertIn("systemd-run --quiet --wait --collect --pipe", script)
        self.assertIn("--property=IPAddressDeny=any", script)
        self.assertIn("--security-opt=no-new-privileges", script)
        self.assertIn("MANIFEST.sha256", script)
        self.assertIn("asterisk-cdr-delta.csv", script)
        self.assertIn("fixture-cdr.json", script)
        self.assertIn("vivolution-synthetic-cdr-evidence normalize-fixture", script)
        self.assertIn("SYNTHETIC_PRIVATE_NO_PSTN", script)
        self.assertIn("liveM365Interoperability == \"NOT_ASSERTED\"", script)
        self.assertNotIn("eval ", script)

    def test_fixture_cdr_contract_is_directional_bounded_and_offline(self) -> None:
        extensions = self.read("roles/voice_fixture/templates/extensions.conf.j2")
        cdr = self.read("roles/voice_fixture/files/bin/synthetic_cdr_evidence.py")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("vivo-synth-t2p", extensions)
        self.assertEqual(extensions.count("vivo-synth-p2t"), 2)
        self.assertIn("MAX_CDR_RECORDS = 32", cdr)
        self.assertIn("SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED", cdr)
        self.assertIn('LIVE_M365_STATUS = "NOT_ASSERTED"', cdr)
        self.assertIn("compile_fixture_cdr", cdr)
        self.assertIn("compile_reconciliation", cdr)
        self.assertNotIn("requests", cdr)
        self.assertNotIn("urllib", cdr)
        self.assertIn("mode: '0550'", tasks)

    def test_readiness_rejects_wildcard_listeners_and_checks_mtls(self) -> None:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        self.assertIn("0\\.0\\.0\\.0", readiness)
        self.assertIn("-verify_ip", readiness)
        self.assertIn("-verify_return_error", readiness)
        self.assertIn("Verification: OK", readiness)
        self.assertIn("SocketBindDeny --value) == any", readiness)
        self.assertIn("accepted a TLS client without its fixture certificate", readiness)
        self.assertIn("nft list ruleset", readiness)
        self.assertIn("IPAddressDeny=any", readiness)

    def test_build_inputs_are_pinned(self) -> None:
        asterisk = self.read("roles/voice_fixture/files/asterisk/Containerfile")
        sipp = self.read("roles/voice_fixture/files/sipp/Containerfile")
        for containerfile in (asterisk, sipp):
            self.assertRegex(containerfile, r"ARG BASE_IMAGE=.*@sha256:[0-9a-f]{64}")
            self.assertNotRegex(containerfile, r"(?m)^FROM\s+[^\n]*:(latest|main|master)(\s|$)")
        self.assertIn("ASTERISK_VERSION=22.10.1", asterisk)
        self.assertIn("373c98f4d4a1b923b42def0aee03f4e36aca9d1c244a8eeda646da8a97f89663", asterisk)
        self.assertIn("PJPROJECT_VERSION=2.17", asterisk)
        self.assertIn("04b2eb1f0f01aa0ad1945b167171843448a51aa6b7c3e806496d434f13a112b7", asterisk)
        self.assertIn("sha256sum --check --strict", asterisk)
        self.assertIn("SIPP_DEBIAN_VERSION=1:3.7.3-2", sipp)
        self.assertIn('"sip-tester=${SIPP_DEBIAN_VERSION}"', sipp)

    def test_build_network_bypasses_only_the_blocked_bridge_path(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        build_network = (
            "--network=slirp4netns:allow_host_loopback=false,enable_ipv6=false"
        )
        self.assertIn("      - slirp4netns\n", tasks)
        self.assertEqual(tasks.count(build_network), 2)
        for block in re.findall(
            r"- name: Build the .+? fixture image .+?(?=\n- name:|\Z)",
            tasks,
            flags=re.DOTALL,
        ):
            self.assertIn(build_network, block)
            self.assertNotIn("--network=host", block)
        self.assertIn("--network=none", tasks)

    def test_podman_image_ids_are_strictly_normalized(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("Remember raw immutable fixture image IDs", tasks)
        self.assertEqual(tasks.count("is match('^(sha256:)?[0-9a-f]{64}$')"), 2)
        self.assertIn("voice_fixture_asterisk_image_id_raw | regex_replace", tasks)
        self.assertIn("voice_fixture_sipp_image_id_raw | regex_replace", tasks)
        self.assertEqual(tasks.count("regex_replace('^sha256:', '')"), 2)
        self.assertIn("Remember canonical immutable fixture image IDs", tasks)
        self.assertIn("sha256:{{ voice_fixture_asterisk_image_id_raw", tasks)
        self.assertIn("sha256:{{ voice_fixture_sipp_image_id_raw", tasks)

    def test_sipp_version_probe_accepts_only_its_documented_no_call_exit(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        expected = "SIPp v3.7.3-TLS-SCTP-PCAP-SHA256."
        self.assertIn("failed_when: voice_fixture_sipp_version_output.rc != 99", tasks)
        self.assertIn("voice_fixture_sipp_version_output.rc == 99", tasks)
        self.assertIn("voice_fixture_sipp_version_output.stderr | trim == ''", tasks)
        self.assertIn("map('trim') | reject('equalto', '') | list", tasks)
        self.assertEqual(tasks.count(expected), 2)
        self.assertIn("select('match', '^SIPp v') | list", tasks)
        self.assertNotIn(
            "'v3.7.3' in (voice_fixture_sipp_version_output.stdout",
            tasks,
        )

    def test_install_is_fail_closed_and_does_not_use_shell_module(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("NO_PSTN_SYNTHETIC_ONLY", tasks)
        self.assertIn("voice_fixture_firewall_contract_acknowledged | bool", tasks)
        self.assertIn("ansible_facts['distribution'] == 'Debian'", tasks)
        self.assertIn("ansible_facts['distribution_major_version'] == '13'", tasks)
        self.assertIn("ansible_facts['architecture'] == 'x86_64'", tasks)
        self.assertIn("ansible_facts['service_mgr'] == 'systemd'", tasks)
        self.assertIn("ansible_facts['all_ipv4_addresses']", tasks)
        self.assertNotIn("ansible.builtin.shell:", tasks)
        self.assertNotRegex(tasks, r"(?m)^\s*shell:")
        self.assertIn("podman, pull", tasks)
        self.assertIn("      - slirp4netns\n", tasks)
        self.assertIn("--pull=never", tasks)
        self.assertIn("Prove systemd cgroup socket-bind denial is enforced", tasks)
        self.assertIn("Prove systemd cgroup IP egress denial is enforced", tasks)
        self.assertGreaterEqual(tasks.count("errno.EACCES, errno.EPERM"), 2)

    def test_teardown_preserves_evidence_and_pki_by_default(self) -> None:
        defaults = self.read("roles/voice_fixture_teardown/defaults/main.yml")
        tasks = self.read("roles/voice_fixture_teardown/tasks/main.yml")
        self.assertIn("voice_fixture_remove_results: false", defaults)
        self.assertIn("voice_fixture_remove_pki: false", defaults)
        self.assertIn("DELETE_SYNTHETIC_RESULTS_AND_CDRS", tasks)
        self.assertIn("DELETE_SYNTHETIC_PKI_AND_EDGE_KEYS", tasks)
        self.assertNotRegex(tasks, r"\brm\s+-rf\b")

    def test_repository_contains_no_embedded_private_key(self) -> None:
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix in {".pyc", ".pyo"}:
                continue
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertNotIn("BEGIN " + "PRIVATE KEY", content)
                self.assertNotIn("BEGIN " + "EC PRIVATE KEY", content)

    def test_documented_firewall_and_limitations_are_explicit(self) -> None:
        readme = self.read("README.md")
        for token in [
            "10.20.2.0/24",
            "10.20.1.4/32",
            "16061",
            "25061",
            "21000-21127",
            "22000-22063",
            "20000-20255",
            "not Microsoft Teams",
            "not the PSTN",
            "does not edit the project IaC",
            "always present their public ACME",
            "must never be installed as an Edge",
        ]:
            self.assertIn(token, readme)


if __name__ == "__main__":
    unittest.main()
