#!/usr/bin/env python3

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_MODULES = (
    "app_dial.so",
    "app_milliwatt.so",
    "app_stack.so",
    "bridge_builtin_features.so",
    "bridge_native_rtp.so",
    "bridge_simple.so",
    "cdr_custom.so",
    "chan_pjsip.so",
    "codec_a_mu.so",
    "codec_alaw.so",
    "codec_ulaw.so",
    "func_cdr.so",
    "pbx_config.so",
    "res_cdrel_custom.so",
    "res_clioriginate.so",
    "res_pjproject.so",
    "res_pjsip.so",
    "res_pjsip_caller_id.so",
    "res_pjsip_endpoint_identifier_ip.so",
    "res_pjsip_header_funcs.so",
    "res_pjsip_pubsub.so",
    "res_pjsip_rfc3326.so",
    "res_pjsip_sdp_rtp.so",
    "res_pjsip_session.so",
    "res_pjsip_sips_contact.so",
    "res_rtp_asterisk.so",
    "res_sorcery_astdb.so",
    "res_sorcery_config.so",
    "res_sorcery_memory.so",
    "res_timing_timerfd.so",
)


class AsteriskRuntimeContractStaticTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def run_asterisk_contract_helper(
        self, call: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        helpers = readiness.split("# BEGIN ASTERISK CONTRACT HELPERS\n", 1)[
            1
        ].split("# END ASTERISK CONTRACT HELPERS\n", 1)[0]
        return subprocess.run(
            [
                "bash",
                "-c",
                f"set -euo pipefail\n{helpers}\n{call}",
                "asterisk-contract-test",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_dynamic_module_allowlist_is_exact_and_fail_closed(self) -> None:
        modules = self.read("roles/voice_fixture/templates/modules.conf.j2")
        directives = [
            line.strip()
            for line in modules.splitlines()
            if line.strip() and not line.lstrip().startswith((";", "["))
        ]
        self.assertEqual(directives[0], "autoload=no")
        self.assertFalse(any(line.startswith("load=") for line in directives))
        self.assertFalse(any(line.startswith("noload=") for line in directives))

        required = {
            line.removeprefix("require=")
            for line in directives[1:]
            if line.startswith("require=")
        }
        self.assertEqual(len(required), len(directives) - 1)
        self.assertEqual(
            required,
            set(EXPECTED_MODULES),
        )
        for forbidden in (
            "app_system.so",
            "func_shell.so",
            "func_curl.so",
            "res_config_curl.so",
            "res_ari.so",
            "res_http_websocket.so",
            "res_pjsip_config_wizard.so",
        ):
            self.assertNotIn(forbidden, required)

    def test_custom_cdr_uses_native_asterisk_22_advanced_mapping(self) -> None:
        cdr = self.read("roles/voice_fixture/templates/cdr_custom.conf.j2")
        self.assertEqual(
            [line.strip() for line in cdr.splitlines() if line.strip()],
            [
                "[VivolutionFixture.csv]",
                "format=dsv",
                "separator_character=,",
                'quote_character="',
                'quote_escape_character="',
                "quoting_method=all",
                "fields=start,answer,end,duration,billsec,disposition,src,dst,channel,dstchannel,uniqueid,linkedid,accountcode,userfield",
            ],
        )
        self.assertNotIn("[mappings]", cdr)
        self.assertNotIn("${CDR(", cdr)

    def test_pjproject_tls_listener_patch_is_scoped_and_applied(self) -> None:
        patch = self.read(
            "roles/voice_fixture/files/asterisk/"
            "pjsip-tls-listener-bind-fail-closed.patch"
        )
        containerfile = self.read("roles/voice_fixture/files/asterisk/Containerfile")
        defaults = self.read("roles/voice_fixture/defaults/main.yml")
        teardown_defaults = self.read(
            "roles/voice_fixture_teardown/defaults/main.yml"
        )

        self.assertEqual(
            patch.count("--- a/"),
            1,
        )
        self.assertIn(
            "--- a/pjsip/src/pjsip/sip_transport_tls.c\n"
            "+++ b/pjsip/src/pjsip/sip_transport_tls.c\n",
            patch,
        )
        self.assertIn(
            "if (status != PJ_SUCCESS && status != PJ_EPENDING)",
            patch,
        )
        self.assertIn("if (status != PJ_SUCCESS)", patch)
        self.assertNotIn(
            "+    if (status == PJ_SUCCESS || status == PJ_EPENDING)",
            patch,
        )
        self.assertIn(
            "COPY pjsip-tls-listener-bind-fail-closed.patch ",
            containerfile,
        )
        self.assertIn(
            "--directory=third-party/pjproject/source",
            containerfile,
        )
        self.assertIn(
            "< /tmp/pjsip-tls-listener-bind-fail-closed.patch",
            containerfile,
        )
        self.assertIn(
            "third-party/pjproject/source/pjsip/src/pjsip/sip_transport_tls.c",
            containerfile,
        )
        tag = "voice-fixture-asterisk:22.10.1-xmldoc1-nosounds1-tlsbind4"
        self.assertIn(tag, defaults)
        self.assertIn(tag, teardown_defaults)

        repeated_mkdir = "    mkdir --parents \\\n    mkdir --parents \\"
        self.assertNotIn(repeated_mkdir, containerfile)
        self.assertEqual(containerfile.count("    mkdir --parents \\\n"), 1)

    def test_pjproject_tls_client_uses_kernel_autobind_for_zero_port(self) -> None:
        patch = self.read(
            "roles/voice_fixture/files/asterisk/"
            "pjproject-tls-kernel-autobind.patch"
        )
        containerfile = self.read("roles/voice_fixture/files/asterisk/Containerfile")

        self.assertEqual(patch.count("--- a/"), 1)
        self.assertIn(
            "--- a/pjlib/src/pj/ssl_sock_imp_common.c\n"
            "+++ b/pjlib/src/pj/ssl_sock_imp_common.c\n",
            patch,
        )
        self.assertIn(
            "if (!port_range && pj_sockaddr_get_port(localaddr) == 0)",
            patch,
        )
        self.assertIn(
            "+#if defined(VIVOLUTION_PJ_TLS_KERNEL_AUTOBIND_ZERO_PORT) && \\\n"
            "+    VIVOLUTION_PJ_TLS_KERNEL_AUTOBIND_ZERO_PORT == 1",
            patch,
        )
        self.assertIn("status = PJ_SUCCESS", patch)
        self.assertEqual(
            [
                line
                for line in patch.splitlines()
                if line.startswith("-") and not line.startswith("---")
            ],
            ["-    /* Bind socket */", "-    if (port_range) {"],
        )
        self.assertIn("+    if (port_range) {", patch)
        self.assertIn(
            "CFLAGS='-DVIVOLUTION_PJ_TLS_KERNEL_AUTOBIND_ZERO_PORT=1 "
            "-DVIVOLUTION_PJ_DNS_KERNEL_AUTOBIND_ZERO_PORT=1' "
            "./configure",
            containerfile,
        )
        self.assertIn(
            "'-DVIVOLUTION_PJ_TLS_KERNEL_AUTOBIND_ZERO_PORT=1' \\\n"
            "        third-party/pjproject/source/build.mak",
            containerfile,
        )
        self.assertIn(
            "COPY pjproject-tls-kernel-autobind.patch ", containerfile
        )
        self.assertIn(
            "< /tmp/pjproject-tls-kernel-autobind.patch", containerfile
        )
        self.assertIn(
            "third-party/pjproject/source/pjlib/src/pj/ssl_sock_imp_common.c",
            containerfile,
        )

    def test_pjproject_dns_uses_kernel_autobind_and_safe_socket_sentinels(self) -> None:
        patch = self.read(
            "roles/voice_fixture/files/asterisk/"
            "pjproject-dns-kernel-autobind.patch"
        )
        containerfile = self.read("roles/voice_fixture/files/asterisk/Containerfile")

        self.assertEqual(patch.count("--- a/"), 1)
        self.assertIn(
            "--- a/pjlib-util/src/pjlib-util/resolver.c\n"
            "+++ b/pjlib-util/src/pjlib-util/resolver.c\n",
            patch,
        )
        self.assertIn(
            "+#if defined(VIVOLUTION_PJ_DNS_KERNEL_AUTOBIND_ZERO_PORT) && \\\n"
            "+    VIVOLUTION_PJ_DNS_KERNEL_AUTOBIND_ZERO_PORT == 1",
            patch,
        )
        self.assertIn(
            "+    /* Bind upstream, or defer the zero-port bind to the first sendto(). */",
            patch,
        )
        self.assertIn("+    resv->udp6_sock = PJ_INVALID_SOCKET;", patch)
        self.assertEqual(
            [
                line
                for line in patch.splitlines()
                if line.startswith("-") and not line.startswith("---")
            ],
            [
                "-",
                "-    /* Bind to any address/port */",
                "-    status = pj_sock_bind_in(resv->udp_sock, 0, 0);",
            ],
        )
        self.assertIn(
            "COPY pjproject-dns-kernel-autobind.patch ", containerfile
        )
        self.assertIn(
            "< /tmp/pjproject-dns-kernel-autobind.patch", containerfile
        )
        self.assertIn(
            "'-DVIVOLUTION_PJ_DNS_KERNEL_AUTOBIND_ZERO_PORT=1' \\\n"
            "        third-party/pjproject/source/build.mak",
            containerfile,
        )
        self.assertIn(
            "third-party/pjproject/source/pjlib-util/src/pjlib-util/resolver.c",
            containerfile,
        )

    def test_readiness_executes_exact_asterisk_contract(self) -> None:
        readiness = self.read(
            "roles/voice_fixture/templates/vivolution-voice-fixture-readiness.j2"
        )
        module_block = readiness.split("expected_asterisk_modules=(\n", 1)[1].split(
            ")\nasterisk_module_status=", 1
        )[0]
        readiness_modules = tuple(
            line.strip() for line in module_block.splitlines() if line.strip()
        )
        self.assertEqual(readiness_modules, EXPECTED_MODULES)
        for command in (
            "asterisk_cli 'module show'",
            "asterisk_cli 'cdr show status'",
            "asterisk_cli 'pjsip show transports'",
            "asterisk_cli 'pjsip show transport fixture-mutual-tls'",
        ):
            self.assertIn(command, readiness)
        self.assertIn("require_exact_asterisk_modules", readiness)
        self.assertIn("require_asterisk_cdr_contract", readiness)
        self.assertIn("require_exact_pjsip_transport_table", readiness)
        self.assertEqual(
            readiness.count("require_exact_pjsip_transport_detail \\"),
            1,
        )

    def test_readiness_renders_with_ansible_and_is_valid_bash(self) -> None:
        template = ROOT / (
            "roles/voice_fixture/templates/"
            "vivolution-voice-fixture-readiness.j2"
        )
        defaults = ROOT / "roles/voice_fixture/defaults/main.yml"
        repository = ROOT.parents[1]
        environment = dict(os.environ)
        environment["ANSIBLE_CONFIG"] = str(repository / "deploy/ansible.cfg")

        with tempfile.TemporaryDirectory() as temporary_directory:
            rendered = Path(temporary_directory) / "readiness"
            render = subprocess.run(
                [
                    "ansible",
                    "localhost",
                    "-i",
                    "localhost,",
                    "-c",
                    "local",
                    "-m",
                    "ansible.builtin.template",
                    "-a",
                    json.dumps(
                        {
                            "src": str(template),
                            "dest": str(rendered),
                            "mode": "0600",
                        }
                    ),
                    "-e",
                    f"@{defaults}",
                ],
                cwd=repository,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(render.returncode, 0, render.stderr or render.stdout)
            self.assertTrue(rendered.is_file())
            syntax = subprocess.run(
                ["bash", "-n", str(rendered)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            self.assertNotIn("{#", template.read_text(encoding="utf-8"))

    def test_dynamic_module_readiness_rejects_drift_and_not_running(self) -> None:
        rows = [
            f"{module:<39} Fixture module 0 Running core"
            for module in EXPECTED_MODULES
        ]
        valid = "\n".join(
            [
                "Module Description Use Count Status Support Level",
                *rows,
                f"{len(rows)} modules loaded",
            ]
        )
        call = """
output=$1
shift
require_exact_asterisk_modules "$output" "$@"
"""
        result = self.run_asterisk_contract_helper(call, valid, *EXPECTED_MODULES)
        self.assertEqual(result.returncode, 0, result.stderr)

        invalid_outputs = {
            "missing": "\n".join(valid.splitlines()[:-2] + [valid.splitlines()[-1]]),
            "extra": valid.replace(
                f"{len(rows)} modules loaded",
                "unexpected-module.so Fixture module 0 Running core\n"
                f"{len(rows) + 1} modules loaded",
            ),
            "duplicate": valid.replace(rows[0], f"{rows[0]}\n{rows[0]}", 1),
            "not-running": valid.replace(
                rows[0],
                f"{EXPECTED_MODULES[0]:<39} Fixture module 0 Not Running core",
                1,
            ),
            "malformed": valid.replace(rows[0], EXPECTED_MODULES[0], 1),
        }
        for reason, invalid in invalid_outputs.items():
            with self.subTest(reason=reason):
                result = self.run_asterisk_contract_helper(
                    call, invalid, *EXPECTED_MODULES
                )
                self.assertNotEqual(result.returncode, 0)

    def test_cdr_readiness_requires_exact_running_custom_backend(self) -> None:
        valid = """Call Detail Record (CDR) settings
----------------------------------
  Logging:                    Enabled
  Mode:                       Simple
  Log unanswered calls:       Yes

* Registered Backends
  -------------------
    CDR File custom bac
"""
        call = 'require_asterisk_cdr_contract "$1"'
        result = self.run_asterisk_contract_helper(call, valid)
        self.assertEqual(result.returncode, 0, result.stderr)

        invalid_outputs = {
            "disabled": valid.replace("Logging:                    Enabled", "Logging:                    Disabled"),
            "batch-mode": valid.replace("Mode:                       Simple", "Mode:                       Batch"),
            "missing": valid.replace("    CDR File custom bac\n", ""),
            "extra": valid.replace(
                "    CDR File custom bac\n",
                "    CDR File custom bac\n    CDR SQL backend\n",
            ),
            "duplicate": valid.replace(
                "    CDR File custom bac\n",
                "    CDR File custom bac\n    CDR File custom bac\n",
            ),
        }
        for reason, invalid in invalid_outputs.items():
            with self.subTest(reason=reason):
                result = self.run_asterisk_contract_helper(call, invalid)
                self.assertNotEqual(result.returncode, 0)

    def test_pjsip_transport_table_is_exact_tls_contract(self) -> None:
        valid = """Transport:  <TransportId........>  <Type>  <cos>  <tos>  <BindAddress....................>
==========================================================================================
Transport:  fixture-mutual-tls      tls      0      0  10.20.1.4:16061

Objects found: 1
"""
        call = 'require_exact_pjsip_transport_table "$1" "$2" "$3"'
        result = self.run_asterisk_contract_helper(
            call, valid, "10.20.1.4", "16061"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        invalid_outputs = {
            "wrong-protocol": valid.replace("fixture-mutual-tls      tls", "fixture-mutual-tls      udp"),
            "wrong-port": valid.replace("10.20.1.4:16061", "10.20.1.4:5061"),
            "missing": valid.replace(
                "Transport:  fixture-mutual-tls      tls      0      0  10.20.1.4:16061\n",
                "",
            ).replace("Objects found: 1", "Objects found: 0"),
            "extra": valid.replace(
                "Objects found: 1",
                "Transport:  fixture-extra            tls      0      0  10.20.1.4:16063\n\nObjects found: 2",
            ),
            "count-mismatch": valid.replace("Objects found: 1", "Objects found: 2"),
        }
        for reason, invalid in invalid_outputs.items():
            with self.subTest(reason=reason):
                result = self.run_asterisk_contract_helper(
                    call, invalid, "10.20.1.4", "16061"
                )
                self.assertNotEqual(result.returncode, 0)

    def test_pjsip_transport_details_enforce_mutual_tls_and_combined_trust(self) -> None:
        valid = """Transport:  <TransportId........>  <Type>  <cos>  <tos>  <BindAddress....................>
==========================================================================================
Transport:  fixture-mutual-tls      tls      0      0  10.20.1.4:16061

 ParameterName                              : ParameterValue
 ================================================================
 allow_reload                               : false
 bind                                       : 10.20.1.4:16061
 ca_list_file                               : /run/fixture-pki/combined-ca.crt
 cert_file                                  : /run/fixture-pki/asterisk.crt
 local_net                                  : 10.20.0.0/255.255.0.0
 method                                     : tlsv1_2
 priv_key_file                              : /run/fixture-pki/asterisk.key
 protocol                                   : tls
 require_client_cert                        : Yes
 verify_client                              : Yes
 verify_server                              : Yes
"""
        call = """
require_exact_pjsip_transport_detail "$1" fixture-mutual-tls \
    10.20.1.4:16061 \
    protocol tls \
    bind 10.20.1.4:16061 \
    method tlsv1_2 \
    cert_file /run/fixture-pki/asterisk.crt \
    priv_key_file /run/fixture-pki/asterisk.key \
    ca_list_file /run/fixture-pki/combined-ca.crt \
    local_net 10.20.0.0/255.255.0.0 \
    verify_client Yes \
    require_client_cert Yes \
    verify_server Yes \
    allow_reload false
"""
        result = self.run_asterisk_contract_helper(call, valid)
        self.assertEqual(result.returncode, 0, result.stderr)

        invalid_outputs = {
            "wrong-bind": valid.replace("10.20.1.4:16061", "0.0.0.0:16061"),
            "wrong-ca": valid.replace("/run/fixture-pki/combined-ca.crt", "/run/fixture-pki/ca.crt"),
            "wrong-local-net": valid.replace("10.20.0.0/255.255.0.0", "10.20.0.0/24"),
            "no-client-verification": valid.replace("verify_client                              : Yes", "verify_client                              : No"),
            "no-client-certificate": valid.replace("require_client_cert                        : Yes", "require_client_cert                        : No"),
            "no-server-verification": valid.replace("verify_server                              : Yes", "verify_server                              : No"),
            "missing-parameter": valid.replace(" allow_reload                               : false\n", ""),
            "duplicate-parameter": valid.replace(
                " allow_reload                               : false\n",
                " allow_reload                               : false\n allow_reload                               : false\n",
            ),
        }
        for reason, invalid in invalid_outputs.items():
            with self.subTest(reason=reason):
                result = self.run_asterisk_contract_helper(call, invalid)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
