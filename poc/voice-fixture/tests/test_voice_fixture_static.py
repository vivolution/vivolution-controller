#!/usr/bin/env python3
"""Offline security and contract checks for the isolated voice fixture."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


class VoiceFixtureStaticTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def run_systemd_policy_helper(
        self, call: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        helpers = readiness.split("# BEGIN SYSTEMD POLICY HELPERS\n", 1)[1].split(
            "# END SYSTEMD POLICY HELPERS\n", 1
        )[0]
        return subprocess.run(
            ["bash", "-c", f"set -euo pipefail\n{helpers}\n{call}", "policy-test", *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def run_podman_image_id_helper(
        self, value: str
    ) -> subprocess.CompletedProcess[str]:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        helper = readiness.split("# BEGIN PODMAN IMAGE ID HELPER\n", 1)[1].split(
            "# END PODMAN IMAGE ID HELPER\n", 1
        )[0]
        return subprocess.run(
            [
                "bash",
                "-c",
                f"set -euo pipefail\n{helper}\ncanonicalize_podman_image_id \"$1\"",
                "image-id-test",
                value,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def run_runtime_image_helper(
        self, *, output: str, status: int, expected: str
    ) -> subprocess.CompletedProcess[str]:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        helper = readiness.split("# BEGIN PODMAN IMAGE ID HELPER\n", 1)[1].split(
            "# END PODMAN IMAGE ID HELPER\n", 1
        )[0]
        helper = helper.replace("{{ '{{' }}.Image{{ '}}' }}", "{{.Image}}")
        return subprocess.run(
            [
                "bash",
                "-c",
                (
                    "set -euo pipefail\n"
                    f"{helper}\n"
                    "podman() { printf '%s' \"$PODMAN_OUTPUT\"; "
                    "return \"$PODMAN_STATUS\"; }\n"
                    "require_runtime_image vivolution-voice-fixture-asterisk \"$1\""
                ),
                "runtime-image-test",
                expected,
            ],
            check=False,
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin",
                "PODMAN_OUTPUT": output,
                "PODMAN_STATUS": str(status),
            },
        )

    def run_sipp_uas_recovery_helper(
        self, *, mode: str
    ) -> subprocess.CompletedProcess[str]:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        helpers = readiness.split("# BEGIN SIPP UAS RECOVERY HELPERS\n", 1)[
            1
        ].split("# END SIPP UAS RECOVERY HELPERS\n", 1)[0]
        helpers = helpers.replace(
            "{{ voice_fixture_sipp_uas_tls_port }}", "25061"
        ).replace("{{ voice_fixture_sipp_uas_rtp_port }}", "22000")
        command = f"""
set -euo pipefail
controller_ip=10.20.1.4
pki_root=/run/fixture-pki
{helpers}
systemctl() {{
    if [[ $1 == is-active ]]; then
        [[ $RECOVERY_MODE != inactive ]]
        return
    fi
    if [[ $1 == show ]]; then
        if [[ $RECOVERY_MODE == changing-pid ]]; then
            counter=$(<"$RECOVERY_COUNTER")
            printf '%d\n' "$((counter + 1))" >"$RECOVERY_COUNTER"
            printf '%d\n' "$((counter + 100))"
        else
            printf '123\n'
        fi
        return
    fi
    return 2
}}
ss() {{
    if [[ $* == *-lnt4* ]]; then
        printf 'LISTEN 0 128 10.20.1.4:25061 0.0.0.0:*\n'
    elif [[ $RECOVERY_MODE != missing-rtp ]]; then
        printf 'UNCONN 0 0 10.20.1.4:22000 0.0.0.0:*\n'
    fi
}}
timeout() {{ shift; "$@"; }}
openssl() {{
    [[ $RECOVERY_MODE != bad-tls ]] || return 1
    printf 'Verification: OK\n'
}}
sleep() {{ :; }}
wait_for_sipp_uas_recovery
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            counter = Path(temporary_directory) / "counter"
            counter.write_text("1\n", encoding="utf-8")
            return subprocess.run(
                ["bash", "-c", command],
                check=False,
                capture_output=True,
                text=True,
                env={
                    "PATH": "/usr/bin:/bin",
                    "RECOVERY_MODE": mode,
                    "RECOVERY_COUNTER": str(counter),
                },
            )

    def test_all_expected_artifacts_exist(self) -> None:
        required = [
            "README.md",
            "install.yml",
            "teardown.yml",
            "roles/voice_fixture/tasks/main.yml",
            "roles/voice_fixture/handlers/main.yml",
            "roles/voice_fixture/files/asterisk/Containerfile",
            "roles/voice_fixture/files/asterisk/private-edge-dns-probe.c",
            "roles/voice_fixture/files/asterisk/pjproject-dns-kernel-autobind.patch",
            "roles/voice_fixture/files/bin/verify_private_edge_dns.py",
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
            "voice_fixture_controller_interface: eth0",
            "voice_fixture_controller_gateway_ipv4: 10.20.1.1",
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
        asterisk_quadlet = self.read(
            "roles/voice_fixture/templates/"
            "vivolution-voice-fixture-asterisk.container.j2"
        )
        test_driver = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-test.j2"
        )
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        teardown = self.read("roles/voice_fixture_teardown/tasks/main.yml")
        self.assertIn("voice_fixture_runtime_root: /run/vivolution-voice-fixture", defaults)
        self.assertEqual(tasks.count("owner: '10001'"), 6)
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
        self.assertIn("asterisk-log/cdr-custom", tasks)
        self.assertIn("asterisk-log/cdr-custom", readiness)
        self.assertIn("'10001:10001:750'", readiness)
        self.assertIn("Inspect the fixture CDR path without following links", tasks)
        self.assertIn("Reject non-directory or symlinked fixture CDR paths", tasks)
        self.assertIn("follow: false", tasks)
        self.assertIn("(not item.stat.exists) or", tasks)
        self.assertIn("not (item.stat.islnk | default(false))", tasks)
        self.assertIn("! -L $asterisk_log_directory", readiness)
        self.assertIn("! -L $asterisk_cdr_directory", readiness)
        self.assertIn(
            "Volume={{ voice_fixture_state_root }}/asterisk-log:"
            "/var/log/asterisk:rw",
            asterisk_quadlet,
        )
        self.assertIn(
            'cdr_file="$state_root/asterisk-log/cdr-custom/'
            'VivolutionFixture.csv"',
            test_driver,
        )
        self.assertLess(
            tasks.index("Inspect the fixture CDR path without following links"),
            tasks.index("Create fixture directories"),
        )
        self.assertLess(
            tasks.index("Create fixture directories"),
            tasks.index("Install the isolated fixture Quadlets"),
        )
        for option in ("nosuid", "nodev", "noexec"):
            self.assertIn(option, readiness)
        self.assertIn("/etc/tmpfiles.d/vivolution-voice-fixture.conf", teardown)
        self.assertIn('"{{ voice_fixture_runtime_root }}"', teardown)

    def test_asterisk_has_no_carrier_registration_or_command_execution(self) -> None:
        modules = self.read(
            "roles/voice_fixture/templates/modules.conf.j2"
        ).lower()
        configs = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "roles/voice_fixture/templates").glob("*.conf.j2")
        ).lower()
        self.assertNotRegex(configs, r"(?m)^\s*register\s*=>")
        self.assertNotIn("system(", configs)
        self.assertNotIn("shell(", configs)
        self.assertIn("autoload=no", modules)
        self.assertNotRegex(
            modules, r"(?m)^require=(?:app_system|func_shell)\.so$"
        )
        self.assertIn("+9710000001001", configs)
        self.assertIn("exten => +9710000001001,1,noop", configs)
        self.assertIn("exten => 911,1,hangup(21)", configs)
        self.assertIn("exten => 112,1,hangup(21)", configs)
        self.assertIn("exten => 999,1,hangup(21)", configs)
        self.assertEqual(configs.count("dial(pjsip/"), 2)
        self.assertNotRegex(configs, r"(?i)(pstn|carrier).*@")

    def test_asterisk_stasis_documentation_is_immutable_and_verified(self) -> None:
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        teardown_defaults = self.read(
            "roles/voice_fixture_teardown/defaults/main.yml"
        )
        containerfile = self.read("roles/voice_fixture/files/asterisk/Containerfile")
        config = self.read("roles/voice_fixture/templates/asterisk.conf.j2")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        image_tag = (
            "voice-fixture-asterisk:22.10.1-xmldoc1-nosounds1-tlsbind4-dns1"
        )
        self.assertIn(image_tag, defaults)
        self.assertIn(image_tag, teardown_defaults)
        self.assertIn(
            "/out/var/lib/asterisk/documentation/core-en_US.xml",
            containerfile,
        )
        self.assertIn('<configObject name="declined_message_types">', containerfile)
        self.assertIn(
            "COPY --from=builder /out/var/lib/asterisk/documentation/ "
            "/usr/share/asterisk/documentation/",
            containerfile,
        )
        self.assertIn("astdatadir => /usr/share/asterisk", config)
        self.assertNotIn("astdatadir => /var/lib/asterisk", config)
        self.assertIn("Verify immutable Asterisk Stasis XML documentation", tasks)
        self.assertIn("/usr/share/asterisk/documentation/core-en_US.xml", tasks)
        self.assertIn("--security-opt=no-new-privileges", tasks)
        self.assertIn("      - '10001:10001'", tasks)

    def test_single_supported_transport_uses_exact_combined_trust(self) -> None:
        pjsip = self.read("roles/voice_fixture/templates/pjsip.conf.j2")
        leaf_profile = self.read("roles/voice_fixture/templates/leaf-extensions.cnf.j2")
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        self.assertIn("[fixture-mutual-tls]", pjsip)
        self.assertEqual(pjsip.count("type=transport\n"), 1)
        self.assertEqual(pjsip.count("transport=fixture-mutual-tls\n"), 3)
        self.assertIn("ca_list_file=/run/fixture-pki/combined-ca.crt", pjsip)
        self.assertIn("verify_client=yes", pjsip)
        self.assertIn("require_client_cert=yes", pjsip)
        self.assertIn("verify_server=yes", pjsip)
        self.assertIn("Stage the exact combined public and fixture TLS trust bundle", tasks)
        self.assertIn("voice_fixture_generation_combined_ca.stat.checksum", tasks)
        self.assertIn("combined-ca.crt", tasks)
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

    def test_sipp_uac_binds_every_response_to_its_started_transaction(self) -> None:
        path = ROOT / "roles/voice_fixture/files/sipp/scenarios/teams-uac.xml"
        root = ET.parse(path).getroot()
        self.assertEqual(
            [send.get("start_txn") for send in root.findall("send")],
            ["invite", None, "bye"],
        )
        self.assertEqual(
            [
                (
                    recv.get("response"),
                    recv.get("optional"),
                    recv.get("response_txn"),
                )
                for recv in root.findall("recv")
            ],
            [
                ("100", "true", "invite"),
                ("180", "true", "invite"),
                ("183", "true", "invite"),
                ("200", None, "invite"),
                ("200", None, "bye"),
            ],
        )

    def test_runner_has_exact_target_allowlist_and_rtp_evidence(self) -> None:
        runner = self.read("roles/voice_fixture/files/sipp/bin/fixture_sipp.py")
        self.assertIn('EDGE_IPS = {ipaddress.ip_address("10.20.2.4"), ipaddress.ip_address("10.20.2.5")}', runner)
        self.assertIn(
            'ipaddress.ip_address("10.20.2.4"): "sbc1.voice.vivolution.ae"',
            runner,
        )
        self.assertIn(
            'ipaddress.ip_address("10.20.2.5"): "sbc2.voice.vivolution.ae"',
            runner,
        )
        self.assertIn("if target not in EDGE_IPS", runner)
        self.assertIn("if args.target_port != 5061", runner)
        self.assertIn('packet[0] >> 6 == 2', runner)
        self.assertIn('summary["packets_received"] < 1', runner)
        self.assertIn("ssl.create_default_context", runner)
        self.assertIn('cafile="/run/fixture-pki/public-ca.crt"', runner)
        self.assertIn("resolved != {expected_ip}", runner)
        self.assertIn("server_name = EDGE_SERVER_NAMES[target]", runner)
        self.assertIn(
            'command.insert(1, f"{server_name}:{args.target_port}")', runner
        )
        self.assertIn("server_hostname=server_name", runner)
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
        self.assertIn("socket_bind_deny == any", readiness)
        self.assertIn("accepted a TLS client without its fixture certificate", readiness)
        self.assertIn("nft list ruleset", readiness)
        self.assertIn("'::/0' '0.0.0.0/0'", readiness)
        self.assertIn("normalize_socket_bind", readiness)
        self.assertIn("require_exact_word_set", readiness)
        self.assertNotIn("grep -Fq 'IPAddressDeny=any'", readiness)
        self.assertIn('ip -j -4 route get "$edge_ip" uid 10001', readiness)
        self.assertIn(
            'keys == ["cache", "dev", "dst", "flags", "gateway", '
            '"prefsrc", "uid"]',
            readiness,
        )
        self.assertIn(".uid == 10001", readiness)
        self.assertIn(".flags == [] and .cache == []", readiness)
        self.assertIn("fixture kernel-autobind route identity is not exact", readiness)
        self.assertIn(
            "podman exec vivolution-voice-fixture-asterisk cat /etc/resolv.conf",
            readiness,
        )
        self.assertIn(
            "$'nameserver 127.0.0.53\\noptions edns0 trust-ad'", readiness
        )
        self.assertIn("exact loopback-only stub", readiness)

    def test_private_edge_dns_is_exact_atomic_and_tls_name_preserving(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        teardown = self.read("roles/voice_fixture_teardown/tasks/main.yml")
        quadlet = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-asterisk.container.j2"
        )
        pjsip = self.read("roles/voice_fixture/templates/pjsip.conf.j2")
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        containerfile = self.read("roles/voice_fixture/files/asterisk/Containerfile")
        probe = self.read(
            "roles/voice_fixture/files/asterisk/private-edge-dns-probe.c"
        )
        verifier = self.read(
            "roles/voice_fixture/files/bin/verify_private_edge_dns.py"
        )

        self.assertIn(
            "# {mark} VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS", tasks
        )
        self.assertIn("10.20.2.4 sbc1.voice.vivolution.ae", tasks)
        self.assertIn("10.20.2.5 sbc2.voice.vivolution.ae", tasks)
        self.assertEqual(tasks.count("ReadEtcHosts=yes"), 1)
        self.assertIn("voice_fixture_hosts_file.stat.nlink | int == 1", tasks)
        self.assertIn("voice_fixture_hosts_file.stat.mode == '0644'", tasks)
        self.assertIn("validate: /usr/local/libexec/vivolution-verify-private-edge-dns hosts-post %s", tasks)
        self.assertLess(
            tasks.index("Reject conflicting partial or unmanaged Edge host mappings"),
            tasks.index("Atomically install the two exact private Edge host mappings"),
        )
        self.assertIn("state: restarted", tasks)
        self.assertIn("when: voice_fixture_private_edge_hosts.changed | bool", tasks)
        self.assertIn("resolvectl", tasks)
        self.assertIn("hosts-post", tasks)
        self.assertIn("resolved-effective", tasks)
        self.assertIn(
            "Require reboot-persistent active systemd-resolved authority", tasks
        )
        self.assertIn("- is-enabled\n      - systemd-resolved.service", tasks)
        self.assertIn("voice_fixture_resolved_enabled.stdout == 'enabled'", tasks)

        self.assertIn("AddHost={{ voice_fixture_sbc1_server_name }}", quadlet)
        self.assertIn("AddHost={{ voice_fixture_sbc2_server_name }}", quadlet)
        self.assertIn(
            "contact=sips:{{ voice_fixture_sbc1_server_name }}:", pjsip
        )
        self.assertIn(
            "contact=sips:{{ voice_fixture_sbc2_server_name }}:", pjsip
        )
        self.assertNotIn("maddr=", pjsip)
        self.assertNotIn("outbound_proxy=", pjsip)

        self.assertIn("private-edge-dns-probe.c", containerfile)
        self.assertIn("vivolution-private-edge-dns-probe", containerfile)
        self.assertIn('"127.0.0.53"', probe)
        self.assertIn("DNS_TYPE_AAAA", probe)
        self.assertIn("query_type == DNS_TYPE_AAAA && answers != 0", probe)
        self.assertIn("PRIVATE_EDGE_STUB_DNS_OK", probe)
        self.assertIn("podman exec vivolution-voice-fixture-asterisk", readiness)
        self.assertIn("vivolution-private-edge-dns-probe", readiness)
        self.assertIn("PRIVATE_EDGE_STUB_DNS_OK", readiness)

        self.assertIn("MARKER_BEGIN", verifier)
        self.assertIn("private_edge_mapping_not_exclusive", verifier)
        self.assertIn("resolved_read_etc_hosts_not_enabled", verifier)
        self.assertIn("hosts-absent", teardown)
        self.assertIn("state: absent", teardown)
        self.assertIn("Inspect the trusted private Edge DNS verifier source", teardown)
        self.assertIn("checksum_algorithm: sha256", teardown)
        self.assertIn(
            "Restore the exact verifier solely for bounded cleanup when absent",
            teardown,
        )
        self.assertIn(
            "Require exact fixture resolved authority content before deletion",
            teardown,
        )
        self.assertIn("'[Resolve]\\nReadEtcHosts=yes\\n'", teardown)
        self.assertIn(
            "/etc/systemd/resolved.conf.d/99-vivolution-voice-fixture-private-edge.conf",
            teardown,
        )

    def test_private_edge_hosts_verifier_rejects_drift(self) -> None:
        verifier = ROOT / "roles/voice_fixture/files/bin/verify_private_edge_dns.py"

        def run(mode: str, content: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as temporary_directory:
                hosts = Path(temporary_directory) / "hosts"
                hosts.write_text(content, encoding="utf-8")
                return subprocess.run(
                    [sys.executable, str(verifier), mode, str(hosts)],
                    check=False,
                    capture_output=True,
                    text=True,
                )

        absent = "127.0.0.1 localhost\n"
        exact = (
            absent
            + "# BEGIN VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS\n"
            + "10.20.2.4 sbc1.voice.vivolution.ae\n"
            + "10.20.2.5 sbc2.voice.vivolution.ae\n"
            + "# END VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS\n"
        )
        self.assertEqual(run("hosts-pre", absent).returncode, 0)
        self.assertEqual(run("hosts-post", exact).returncode, 0)
        self.assertEqual(run("hosts-absent", absent).returncode, 0)
        for drift in (
            "20.46.45.96 sbc1.voice.vivolution.ae\n",
            exact + "10.20.2.4 sbc1.voice.vivolution.ae\n",
            exact.replace("10.20.2.5", "20.216.14.173"),
            exact.replace("# END VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS\n", ""),
        ):
            with self.subTest(drift=drift):
                rejected = run("hosts-pre", drift)
                self.assertNotEqual(rejected.returncode, 0)

    def test_readiness_waits_for_stable_sipp_uas_after_negative_mtls(self) -> None:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        negative_probe = readiness.index(
            "SIPp fixture accepted a TLS client without its fixture certificate"
        )
        recovery = readiness.index("wait_for_sipp_uas_recovery", negative_probe)
        ready = readiness.index("printf 'READY no-pstn", recovery)
        self.assertLess(negative_probe, recovery)
        self.assertLess(recovery, ready)
        self.assertIn("for attempt in {1..12}", readiness)
        self.assertIn("stable_samples >= 3", readiness)
        self.assertIn("--property=MainPID --value", readiness)

        recovered = self.run_sipp_uas_recovery_helper(mode="stable")
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        for mode in ("inactive", "changing-pid", "missing-rtp", "bad-tls"):
            with self.subTest(mode=mode):
                rejected = self.run_sipp_uas_recovery_helper(mode=mode)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("did not recover stably", rejected.stderr)

    def test_readiness_accepts_only_equivalent_systemd_policy_renderings(self) -> None:
        socket_renderings = {
            "ipv4:tcp:16061": "ipv4:tcp:16061",
            "ipv4:tcp16061": "ipv4:tcp:16061",
            "ipv4:tcp:16061-16061": "ipv4:tcp:16061",
            "ipv4:udp:21000-21127": "ipv4:udp:21000-21127",
            "ipv4:udp21000-21127": "ipv4:udp:21000-21127",
        }
        for rendered, canonical in socket_renderings.items():
            with self.subTest(rendered=rendered):
                result = self.run_systemd_policy_helper(
                    'normalize_socket_bind "$1"', rendered
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), canonical)

        for rejected in (
            "any",
            "ipv6:tcp16061",
            "ipv4:sctp16061",
            "ipv4:tcp0",
            "ipv4:tcp65536",
            "ipv4:udp21127-21000",
            "ipv4:tcp16061:extra",
        ):
            with self.subTest(rejected=rejected):
                result = self.run_systemd_policy_helper(
                    'normalize_socket_bind "$1"', rejected
                )
                self.assertNotEqual(result.returncode, 0)

        scalar_call = 'require_scalar_property_value fixture "$1"'
        scalar_result = self.run_systemd_policy_helper(scalar_call, "AF_INET")
        self.assertEqual(scalar_result.returncode, 0, scalar_result.stderr)
        for rejected_scalar in ("", "AF_INET\nAF_UNIX", "AF_INET\rAF_UNIX"):
            with self.subTest(rejected_scalar=rejected_scalar):
                scalar_result = self.run_systemd_policy_helper(
                    scalar_call, rejected_scalar
                )
                self.assertNotEqual(scalar_result.returncode, 0)

        scalar_reader_call = """
rendered=$1
systemctl() { printf '%s' "$rendered"; }
read_systemd_property fixture.service RestrictAddressFamilies
"""
        scalar_reader_result = self.run_systemd_policy_helper(
            scalar_reader_call, "AF_INET\n"
        )
        self.assertEqual(
            scalar_reader_result.returncode, 0, scalar_reader_result.stderr
        )
        self.assertEqual(scalar_reader_result.stdout, "AF_INET")
        for rejected_rendering in (
            "AF_INET",
            "AF_INET\n\n",
            "AF_INET\nAF_UNIX\n",
            "AF_INET\r\n",
        ):
            with self.subTest(rejected_rendering=rejected_rendering):
                scalar_reader_result = self.run_systemd_policy_helper(
                    scalar_reader_call, rejected_rendering
                )
                self.assertNotEqual(scalar_reader_result.returncode, 0)

        current_socket_list = (
            "ipv4:udp21000-21127\n"
            "ipv4:tcp16061"
        )
        legacy_socket_list = (
            "ipv4:udp21000-21127 ipv4:tcp16061"
        )
        list_reader_call = """
rendered=$1
systemctl() { printf '%s\n' "$rendered"; }
read_systemd_socket_bind_list fixture.service SocketBindAllow 2
"""
        expected_socket_list = (
            "ipv4:udp:21000-21127\n"
            "ipv4:tcp:16061"
        )
        for rendered_list in (current_socket_list, legacy_socket_list):
            with self.subTest(rendered_list=rendered_list):
                list_result = self.run_systemd_policy_helper(
                    list_reader_call, rendered_list
                )
                self.assertEqual(list_result.returncode, 0, list_result.stderr)
                self.assertEqual(list_result.stdout.strip(), expected_socket_list)

        exact_socket_list_call = """
rendered=$1
systemctl() { printf '%s\n' "$rendered"; }
normalized=$(read_systemd_socket_bind_list fixture.service SocketBindAllow 2)
normalized_words=${normalized//$'\n'/ }
require_exact_word_set 'fixture SocketBindAllow' "$normalized_words" \
    ipv4:udp:21000-21127 ipv4:tcp:16061
"""
        for rendered_list in (current_socket_list, legacy_socket_list):
            exact_result = self.run_systemd_policy_helper(
                exact_socket_list_call, rendered_list
            )
            self.assertEqual(exact_result.returncode, 0, exact_result.stderr)

        rejected_lists = {
            "duplicate": (
                "ipv4:udp21000-21127\n"
                "ipv4:udp21000-21127"
            ),
            "extra": (
                f"{current_socket_list}\nipv4:tcp16063"
            ),
            "missing": "ipv4:tcp16061",
            "blank-internal": (
                "ipv4:udp21000-21127\n\nipv4:tcp16061"
            ),
            "blank-trailing": f"{current_socket_list}\n",
            "malformed": (
                "ipv4:udp21000-21127\n"
                "ipv4:sctp16061"
            ),
            "ambiguous-spaces": (
                "ipv4:udp21000-21127  ipv4:tcp16061"
            ),
        }
        for reason, rendered_list in rejected_lists.items():
            with self.subTest(reason=reason):
                exact_result = self.run_systemd_policy_helper(
                    exact_socket_list_call, rendered_list
                )
                self.assertNotEqual(exact_result.returncode, 0)

        for rendered_deny in (
            "any",
            "::/0 0.0.0.0/0",
            "0.0.0.0/0 ::/0",
        ):
            with self.subTest(rendered_deny=rendered_deny):
                result = self.run_systemd_policy_helper(
                    'require_ip_address_deny_any fixture.service "$1"',
                    rendered_deny,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

        for rejected_deny in (
            "::/0",
            "0.0.0.0/0",
            "::/0 0.0.0.0/0 10.0.0.0/8",
        ):
            with self.subTest(rejected_deny=rejected_deny):
                result = self.run_systemd_policy_helper(
                    'require_ip_address_deny_any fixture.service "$1"',
                    rejected_deny,
                )
                self.assertNotEqual(result.returncode, 0)

        exact_set_call = 'require_exact_word_set fixture "$1" one two three'
        for accepted_set in ("one two three", "three one two"):
            result = self.run_systemd_policy_helper(exact_set_call, accepted_set)
            self.assertEqual(result.returncode, 0, result.stderr)
        for rejected_set in ("one two", "one two three four", "one two two"):
            result = self.run_systemd_policy_helper(exact_set_call, rejected_set)
            self.assertNotEqual(result.returncode, 0)

    def test_build_inputs_are_pinned(self) -> None:
        asterisk = self.read("roles/voice_fixture/files/asterisk/Containerfile")
        sipp = self.read("roles/voice_fixture/files/sipp/Containerfile")
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        teardown_defaults = self.read(
            "roles/voice_fixture_teardown/defaults/main.yml"
        )
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        for containerfile in (asterisk, sipp):
            self.assertRegex(containerfile, r"ARG BASE_IMAGE=.*@sha256:[0-9a-f]{64}")
            self.assertNotRegex(containerfile, r"(?m)^FROM\s+[^\n]*:(latest|main|master)(\s|$)")
        self.assertIn("ASTERISK_VERSION=22.10.1", asterisk)
        self.assertIn("373c98f4d4a1b923b42def0aee03f4e36aca9d1c244a8eeda646da8a97f89663", asterisk)
        self.assertIn("PJPROJECT_VERSION=2.17", asterisk)
        self.assertIn("04b2eb1f0f01aa0ad1945b167171843448a51aa6b7c3e806496d434f13a112b7", asterisk)
        self.assertIn("sha256sum --check --strict", asterisk)
        self.assertIn("declined_message_types", asterisk)
        for category in (
            "MENUSELECT_CORE_SOUNDS",
            "MENUSELECT_MOH",
            "MENUSELECT_EXTRA_SOUNDS",
        ):
            self.assertIn(f"--disable-category {category}", asterisk)
            self.assertIn(f"grep -qx '{category}=' menuselect.makeopts", asterisk)
        self.assertIn("make --jobs=2 DOWNLOAD=:", asterisk)
        self.assertIn("make DESTDIR=/out DOWNLOAD=: install", asterisk)
        self.assertNotIn("make DESTDIR=/out install", asterisk)
        self.assertIn("SIPP_VERSION=3.7.7", sipp)
        self.assertIn(
            "SIPP_SOURCE_SHA256="
            "e55b15f567760e9febeef366a1ab51a5239d197a132ce931b78c826d22d31e69",
            sipp,
        )
        self.assertIn(
            'https://github.com/SIPp/sipp/releases/download/v${SIPP_VERSION}/'
            'sipp-${SIPP_VERSION}.tar.gz',
            sipp,
        )
        self.assertNotIn("archive/refs/tags", sipp)
        self.assertIn("sha256sum --check --strict", sipp)
        self.assertIn("SSL_set_tlsext_host_name(ssl, remote_host);", sipp)
        self.assertIn("test \"$(grep --fixed-strings --count", sipp)
        self.assertIn("-DUSE_GSL=1", sipp)
        self.assertIn("-DUSE_PCAP=1", sipp)
        self.assertIn("-DUSE_SCTP=1", sipp)
        self.assertIn("-DUSE_SSL=1", sipp)
        self.assertNotIn("TLS_KEY_LOGGING", sipp)
        self.assertNotIn("USE_SYSTEM_PUGIXML", sipp)
        self.assertNotIn("libpugixml-dev", sipp)
        self.assertIn("COPY --from=builder /runtime-libs/ /", sipp)
        self.assertNotIn("sip-tester", sipp)
        self.assertNotIn("SIPP_DEBIAN_VERSION", sipp)
        self.assertIn("voice_fixture_sipp_version: 3.7.7", defaults)
        self.assertIn(
            "voice_fixture_sipp_source_sha256: "
            "e55b15f567760e9febeef366a1ab51a5239d197a132ce931b78c826d22d31e69",
            defaults,
        )
        image_tag = "voice-fixture-sipp:3.7.7-sni1-txn1"
        self.assertIn(image_tag, defaults)
        self.assertIn(image_tag, teardown_defaults)
        self.assertIn(
            '"SIPP_VERSION={{ voice_fixture_sipp_version }}"', tasks
        )
        self.assertIn(
            '"SIPP_SOURCE_SHA256={{ voice_fixture_sipp_source_sha256 }}"',
            tasks,
        )

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
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        self.assertIn("Remember raw immutable fixture image IDs", tasks)
        self.assertEqual(tasks.count("is match('^(sha256:)?[0-9a-f]{64}$')"), 2)
        self.assertIn("voice_fixture_asterisk_image_id_raw | regex_replace", tasks)
        self.assertIn("voice_fixture_sipp_image_id_raw | regex_replace", tasks)
        self.assertEqual(tasks.count("regex_replace('^sha256:', '')"), 2)
        self.assertIn("Remember canonical immutable fixture image IDs", tasks)
        self.assertIn("sha256:{{ voice_fixture_asterisk_image_id_raw", tasks)
        self.assertIn("sha256:{{ voice_fixture_sipp_image_id_raw", tasks)
        digest = "a" * 64
        for representation in (digest, f"sha256:{digest}"):
            with self.subTest(representation=representation):
                result = self.run_podman_image_id_helper(representation)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"sha256:{digest}\n")
        for invalid in (
            "",
            "a" * 63,
            "A" * 64,
            f"sha512:{digest}",
            f"sha256:{digest}extra",
        ):
            with self.subTest(invalid=invalid):
                result = self.run_podman_image_id_helper(invalid)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        self.assertIn("fixture runtime image does not match", readiness)
        self.assertIn("fixture runtime image inspection failed", readiness)

        for representation in (digest, f"sha256:{digest}"):
            with self.subTest(runtime_representation=representation):
                result = self.run_runtime_image_helper(
                    output=representation,
                    status=0,
                    expected=f"sha256:{digest}",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")

        fail_closed_cases = (
            (digest, 42, f"sha256:{digest}"),
            ("malformed", 0, f"sha256:{digest}"),
            ("b" * 64, 0, f"sha256:{digest}"),
        )
        for output, status, expected in fail_closed_cases:
            with self.subTest(output=output, status=status, expected=expected):
                result = self.run_runtime_image_helper(
                    output=output,
                    status=status,
                    expected=expected,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_rtp_config_disables_ice_without_triggering_empty_stun_dns(self) -> None:
        rtp = self.read("roles/voice_fixture/templates/rtp.conf.j2")
        self.assertIn("icesupport=no", rtp)
        self.assertNotIn("stunaddr", rtp)

    def test_sipp_version_probe_accepts_only_its_documented_no_call_exit(self) -> None:
        tasks = self.read("roles/voice_fixture/tasks/main.yml")
        containerfile = self.read(
            "roles/voice_fixture/files/sipp/Containerfile"
        )
        expected = "SIPp v3.7.7-TLS-SCTP-PCAP-SHA256."
        self.assertIn("failed_when: voice_fixture_sipp_version_output.rc != 99", tasks)
        self.assertIn("voice_fixture_sipp_version_output.rc == 99", tasks)
        self.assertIn("voice_fixture_sipp_version_output.stderr | trim == ''", tasks)
        self.assertIn("map('trim') | reject('equalto', '') | list", tasks)
        self.assertEqual(tasks.count(expected), 2)
        self.assertEqual(containerfile.count(expected), 1)
        self.assertIn('test "${sipp_version_rc}" -eq 99', containerfile)
        self.assertIn("test ! -s /tmp/sipp-version.stderr", containerfile)
        self.assertIn("select('match', '^SIPp v') | list", tasks)
        self.assertNotIn(
            "'v3.7.7' in (voice_fixture_sipp_version_output.stdout",
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
            "SSL_set_tlsext_host_name(ssl, remote_host)",
            "no wildcard or no-SNI TLS domain",
            "SIPp v3.7.7-TLS-SCTP-PCAP-SHA256.",
        ]:
            self.assertIn(token, readme)


if __name__ == "__main__":
    unittest.main()
