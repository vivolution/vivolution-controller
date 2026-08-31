from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class CarrierGatewayStaticTests(unittest.TestCase):
    def test_image_is_pinned_multistage_and_proves_srtp(self) -> None:
        source = read("roles/carrier_gateway/files/asterisk/Containerfile")
        self.assertIn("ASTERISK_VERSION=22.10.1", source)
        self.assertIn("373c98f4d4a1b923b42def0aee03f4e36aca9d1c244a8eeda646da8a97f89663", source)
        self.assertIn("PJPROJECT_VERSION=2.17", source)
        self.assertIn("04b2eb1f0f01aa0ad1945b167171843448a51aa6b7c3e806496d434f13a112b7", source)
        self.assertIn("libsrtp2-dev", source)
        self.assertIn("--with-srtp", source)
        self.assertIn("--enable res_srtp", source)
        self.assertIn("res_srtp.so", source)
        self.assertRegex(source, r"libsrtp2\?\\\.so|libsrtp2\?\\\\\.so|libsrtp2")
        self.assertEqual(source.count("FROM ${BASE_IMAGE}"), 2)
        self.assertIn("USER 10003:10003", source)

    def test_pjproject_patches_remain_fail_closed(self) -> None:
        tls = read("roles/carrier_gateway/files/asterisk/pjproject-tls-kernel-autobind.patch")
        dns = read("roles/carrier_gateway/files/asterisk/pjproject-dns-kernel-autobind.patch")
        listener = read("roles/carrier_gateway/files/asterisk/pjsip-tls-listener-bind-fail-closed.patch")
        self.assertIn("!port_range && pj_sockaddr_get_port(localaddr) == 0", tls)
        self.assertIn("VIVOLUTION_PJ_DNS_KERNEL_AUTOBIND_ZERO_PORT == 1", dns)
        self.assertIn("udp6_sock = PJ_INVALID_SOCKET", dns)
        self.assertIn("status != PJ_SUCCESS && status != PJ_EPENDING", listener)

    def test_exact_private_generation_three_contract(self) -> None:
        defaults = read("roles/carrier_gateway/defaults/main.yml")
        pjsip = read("roles/carrier_gateway/templates/pjsip.conf.j2")
        self.assertIn("carrier_gateway_controller_ipv4: 10.20.1.4", defaults)
        self.assertIn("carrier_gateway_sbc1_ipv4: 10.20.2.6", defaults)
        self.assertIn("carrier_gateway_sbc2_ipv4: 10.20.2.7", defaults)
        self.assertIn("carrier_gateway_sbc1_server_name: sbc1.vivolution.ae", defaults)
        self.assertIn("carrier_gateway_sbc2_server_name: sbc2.vivolution.ae", defaults)
        self.assertIn("carrier_gateway_server_name: carrier.vivolution.ae", defaults)
        self.assertIn("carrier_gateway_tls_port: 5061", defaults)
        self.assertIn("carrier_gateway_rtp_start: 30000", defaults)
        self.assertIn("carrier_gateway_rtp_end: 30127", defaults)
        self.assertIn("carrier_gateway_edge_listener_port: 15061", defaults)
        self.assertIn("method=tlsv1_2", pjsip)
        self.assertIn("verify_client=yes", pjsip)
        self.assertIn("require_client_cert=yes", pjsip)
        self.assertIn("verify_server=yes", pjsip)
        # Edge ingress, both generation-three Edge peers, and the disabled-by-
        # default Twilio endpoint each require SDES when their branch exists.
        self.assertEqual(pjsip.count("media_encryption=sdes"), 4)
        self.assertNotIn("fixture-pki", pjsip)
        self.assertNotIn("pbx-fixture.invalid", pjsip)

    def test_nonbillable_tests_blocks_and_ordered_failover(self) -> None:
        dialplan = read("roles/carrier_gateway/templates/extensions.conf.j2")
        self.assertIn("Milliwatt()", dialplan)
        self.assertIn("Echo()", dialplan)
        for emergency in ("112", "911", "999", "998", "997"):
            self.assertIn(f"'{emergency}'", dialplan)
        self.assertIn("sbc1-then-sbc2", dialplan)
        self.assertLess(dialplan.index("@sbc1,5"), dialplan.index("@sbc2,5"))
        runner = read("roles/carrier_gateway/templates/vivolution-carrier-gateway-test.j2")
        self.assertIn("NON_BILLABLE_EDGE_SIGNALING_ONLY", runner)
        self.assertNotIn("@twilio", runner.lower())
        self.assertNotIn("PJSIP/twilio", runner)

    def test_twilio_is_absent_by_default_and_one_shot_when_enabled(self) -> None:
        defaults = read("roles/carrier_gateway/defaults/main.yml")
        tasks = read("roles/carrier_gateway/tasks/main.yml")
        pjsip = read("roles/carrier_gateway/templates/pjsip.conf.j2")
        dialplan = read("roles/carrier_gateway/templates/extensions.conf.j2")
        authorize = read("roles/carrier_gateway_authorize/tasks/main.yml")
        agi = read("roles/carrier_gateway/templates/vivolution-twilio-authorize.agi.j2")
        self.assertIn("carrier_gateway_twilio_enabled: false", defaults)
        self.assertIn("carrier_gateway_twilio_secrets: {}", defaults)
        self.assertIn("ENABLE_ONE_SHOT_TWILIO_OUTBOUND_POC", tasks)
        self.assertIn("{% if carrier_gateway_twilio_enabled | bool %}", pjsip)
        self.assertIn("media_encryption=sdes", pjsip)
        self.assertIn("AUTHORIZE_EXACTLY_ONE_BILLABLE_PSTN_CALL", authorize)
        self.assertIn("force: false", authorize)
        self.assertIn("maximum_calls=1", authorize)
        self.assertIn("AGI(vivolution-twilio-authorize.agi,${EXTEN})", dialplan)
        self.assertIn('mv "$pending"', agi)
        self.assertIn(".claimed", agi)
        self.assertGreaterEqual(tasks.count("no_log: true"), 6)

    def test_runtime_is_true_rootless_read_only_and_capability_free(self) -> None:
        defaults = read("roles/carrier_gateway/defaults/main.yml")
        quadlet = read("roles/carrier_gateway/templates/vivolution-carrier-gateway.container.j2")
        tasks = read("roles/carrier_gateway/tasks/main.yml")
        policy = read("roles/carrier_gateway/templates/10-vivolution-carrier-gateway-policy.conf.j2")
        self.assertIn("rootless-home/.config/containers/systemd", defaults)
        self.assertIn("carrier_gateway_rootless_quadlet_root", tasks)
        self.assertIn("become_user: \"{{ carrier_gateway_runtime_user }}\"", tasks)
        self.assertIn("loginctl, enable-linger", tasks)
        self.assertIn("UserNS=keep-id", quadlet)
        self.assertIn("User=10003:10003", quadlet)
        self.assertIn("ReadOnly=true", quadlet)
        self.assertIn("DropCapability=all", quadlet)
        self.assertIn("NoNewPrivileges=true", quadlet)
        self.assertIn("AddHost={{ carrier_gateway_twilio_termination_fqdn }}", quadlet)
        self.assertIn("SocketBindDeny=any", policy)
        self.assertIn("SocketBindAllow=ipv4:tcp:{{ carrier_gateway_tls_port }}", policy)
        self.assertIn("IPAddressDeny=any", policy)

        readiness = read("roles/carrier_gateway/templates/vivolution-carrier-gateway-readiness.j2")
        self.assertIn("--property=IPAddressDeny", readiness)
        self.assertIn("actual_twilio_hosts", readiness)

    def test_host_firewall_is_separate_from_synthetic_fixture(self) -> None:
        defaults = (PROJECT / "deploy/roles/host_firewall/defaults/main.yml").read_text()
        policy = (PROJECT / "deploy/roles/host_firewall/templates/nftables.conf.j2").read_text()
        self.assertIn("cp_carrier_gateway_enabled: false", defaults)
        self.assertIn('comment "vivolution-carrier-tls"', policy)
        self.assertIn('comment "vivolution-carrier-media"', policy)
        fixture_block = policy[policy.index("{% if cp_effective_voice_fixture_enabled %}") :]
        fixture_block = fixture_block[: fixture_block.index("{% endif %}")]
        self.assertNotIn("cp_carrier_gateway", fixture_block)

    def test_install_is_idempotent_and_rollback_is_crash_visible(self) -> None:
        tasks = read("roles/carrier_gateway/tasks/main.yml")
        rollback = read("roles/carrier_gateway_rollback/tasks/main.yml")
        teardown = read("roles/carrier_gateway_teardown/tasks/main.yml")
        self.assertIn("podman, image, exists", tasks)
        self.assertIn("pending-config.tar", tasks)
        self.assertIn("Refuse to overwrite an interrupted rollback authority", tasks)
        self.assertIn("previous-config.tar", tasks)
        self.assertIn("ROLLBACK_CARRIER_GATEWAY_TO_PROTECTED_PREVIOUS_CONFIG", rollback)
        self.assertIn("Validate bounded archive members before extraction", rollback)
        self.assertIn("rescue:", rollback)
        self.assertIn("Remove any unconsumed billable-call authority", teardown)
        self.assertIn("HOST_FIREWALL_CARRIER_RULES_REMOVED", teardown)

    def test_no_inbound_did_or_production_claim(self) -> None:
        all_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in ROOT.rglob("*")
            if path.is_file()
            and path.suffix not in {".pyc"}
            and "tests" not in path.parts
        )
        self.assertNotIn("inbound DID supported", all_source)
        self.assertNotIn("production ready", all_source.lower())


if __name__ == "__main__":
    unittest.main()
