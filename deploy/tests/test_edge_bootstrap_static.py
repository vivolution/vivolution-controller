import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


DEPLOY = Path(__file__).resolve().parents[1]


class EdgeBootstrapStaticTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (DEPLOY / relative_path).read_text(encoding="utf-8")

    def folded_assertion(self, relative_path: str, needle: str) -> str:
        lines = self.read(relative_path).splitlines()
        matches = [index for index, line in enumerate(lines) if needle in line]
        self.assertEqual(
            len(matches),
            1,
            f"expected one {needle!r} assertion in {relative_path}",
        )
        start = next(
            index
            for index in range(matches[0], -1, -1)
            if lines[index] == "      - >-"
        )
        end = next(
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("      - ")
            or lines[index].startswith("    fail_msg:")
        )
        return " ".join(line.strip() for line in lines[start + 1 : end])

    def run_local_assertions(
        self, assertions: list[str], variables: dict[str, object]
    ) -> subprocess.CompletedProcess[str]:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        playbook = [
            {
                "name": "Exercise the Edge bootstrap identity boundary",
                "hosts": "all",
                "gather_facts": False,
                "vars": variables,
                "tasks": [
                    {
                        "name": "Evaluate the production preflight assertions",
                        "ansible.builtin.assert": {"that": assertions},
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.yml"
            path.write_text(json.dumps(playbook), encoding="utf-8")
            return subprocess.run(
                [
                    executable,
                    "--inventory",
                    "sbc1,",
                    "--connection",
                    "local",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_preflight_keeps_logical_os_and_acme_identities_distinct(self) -> None:
        assertions = [
            "inventory_hostname in ['sbc1', 'sbc2']",
            "edge_expected_hostname is match('^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')",
            "edge_acme_node_fqdn is match('^' ~ inventory_hostname ~ '\\\\.[a-z0-9.-]+$')",
            "edge_acme_wildcard_fqdn == '*.' ~ edge_acme_node_fqdn",
        ]
        preflight = self.read("roles/edge_preflight/tasks/main.yml")
        for expression in assertions:
            self.assertIn(f"- {expression}", preflight)
        self.assertNotIn(
            "edge_acme_node_fqdn is match('^' ~ edge_expected_hostname ~ '\\\\.[a-z0-9.-]+$')",
            preflight,
        )

        variables = {
            "edge_expected_hostname": "viv-sbc-poc-sbc1",
            "edge_acme_node_fqdn": "sbc1.voice.vivolution.ae",
            "edge_acme_wildcard_fqdn": "*.sbc1.voice.vivolution.ae",
        }
        accepted = self.run_local_assertions(assertions, variables)
        self.assertEqual(
            accepted.returncode,
            0,
            msg=f"{accepted.stdout}\n{accepted.stderr}",
        )

        conflated = self.run_local_assertions(
            assertions,
            {
                **variables,
                "edge_acme_node_fqdn": "viv-sbc-poc-sbc1.voice.vivolution.ae",
                "edge_acme_wildcard_fqdn": "*.viv-sbc-poc-sbc1.voice.vivolution.ae",
            },
        )
        self.assertNotEqual(conflated.returncode, 0)

    def test_playbook_is_edge_only_except_shared_ssh_hardening(self) -> None:
        playbook = self.read("playbooks/install-edge.yml")
        expected_roles = {
            "edge_preflight",
            "edge_base_os",
            "ssh_hardening",
            "edge_firewall",
            "edge_repositories",
            "edge_certificate",
            "edge_opensips",
            "edge_rtpengine",
            "edge_verify",
        }
        for role in expected_roles:
            self.assertIn(f"role: {role}", playbook)
        self.assertNotIn("role: base_os", playbook)
        self.assertNotIn("role: host_firewall", playbook)
        self.assertNotIn("role: podman", playbook)
        self.assertNotIn("role: controller_services", playbook)

    def test_exact_signed_repository_and_package_contract(self) -> None:
        playbook = self.read("playbooks/install-edge.yml")
        repositories = self.read("roles/edge_repositories/tasks/main.yml")
        opensips_source = self.read(
            "roles/edge_repositories/templates/opensips.sources.j2"
        )
        rtpengine_source = self.read(
            "roles/edge_repositories/templates/rtpengine.sources.j2"
        )

        self.assertIn("edge_opensips_version_required: 3.6.8-1", playbook)
        self.assertIn(
            "edge_opensips_binary_sha256: "
            "bdab0bf76361369a46a5e4763533a555a91a6ccc92a4b9a5a6e0c223792675d1",
            playbook,
        )
        self.assertIn(
            "edge_rtpengine_version_required: 26.0.1.22-1~bpo13+1", playbook
        )
        for package in (
            "opensips-tls-module",
            "opensips-tls-openssl-module",
            "opensips-tlsmgm-module",
        ):
            self.assertIn(package, repositories)
        self.assertIn("Components: 3.6-releases", opensips_source)
        self.assertIn("Signed-By:", opensips_source)
        self.assertIn("URIs: https://rtpengine.dfx.at/26.0", rtpengine_source)
        self.assertIn("Signed-By:", rtpengine_source)
        self.assertIn("policy_rc_d: 101", repositories)
        self.assertIn("install_recommends: false", repositories)
        self.assertIn("edge_native_debs:", playbook)
        self.assertIn("checksum: \"sha256:{{ item.sha256 }}\"", repositories)
        self.assertIn("dpkg-deb", repositories)
        self.assertIn("opensips: /usr/sbin/opensips", repositories)
        self.assertIn("VIVO_XLOG_CORE_PROBE", repositories)
        self.assertNotIn("xlog.so", repositories)
        self.assertNotIn("name:\n      - \"opensips=", repositories)
        for digest in (
            "29a2be1811bb70d9ab759fa1ec3e787207054558ed4c58646fdfa31923bc0f72",
            "164c9fbb25dd0271362658b4b0d626f511ee9ff88cf5c4b1a937b408ce6a296e",
            "275ab8f8eb2167a6ce74186760d0cdaf866dca2f5da64150089fefe7417cd772",
            "5fa6147a65389af44d73aafdcf731c023ff5b1645622d23a2d8360e0dddbd9d2",
            "feeaaf78fc2b7581b914cb6051c3bebf3c80ac92ad0a20256b40516438bf70ca",
        ):
            self.assertIn(digest, playbook)

    def test_edge_certificate_uses_pinned_lego_and_managed_identity_dns(self) -> None:
        playbook = self.read("playbooks/install-edge.yml")
        tasks = self.read("roles/edge_certificate/tasks/main.yml")
        environment = self.read("roles/edge_certificate/templates/acme-azure.env.j2")
        helper = self.read(
            "roles/edge_certificate/templates/renew-edge-certificate.sh.j2"
        )
        service = self.read(
            "roles/edge_certificate/templates/vivolution-edge-certificate.service.j2"
        )

        self.assertIn("edge_lego_version_required: 5.4.0", playbook)
        self.assertIn(
            "d3adf89392d606ce84d485c1cc20832edd42ace6ff9ced9dd3670d9d8b8aca38",
            playbook,
        )
        self.assertIn("checksum: \"sha256:{{ edge_lego_linux_amd64_archive_sha256 }}\"", tasks)
        self.assertIn("AZURE_AUTH_METHOD=msi", environment)
        self.assertNotIn("CLIENT_SECRET", environment)
        self.assertIn("--dns azuredns", helper)
        self.assertIn("--domains '{{ edge_acme_wildcard_fqdn }}'", helper)
        self.assertIn("--key-type '{{ edge_acme_certificate_key_type }}'", helper)
        self.assertIn("edge_acme_certificate_key_type: rsa2048", playbook)
        self.assertIn(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
            playbook,
        )
        self.assertNotIn("--http", helper)
        self.assertIn("validate-edge-certificate", helper)
        self.assertIn('-m 0400 "$key_source"', helper)
        self.assertIn("/bin/chmod 0400", helper)
        self.assertIn("/var/lib/vivolution-edge/certificate-rotation", helper)
        self.assertIn("/usr/local/libexec/vivolution-edge/rotate-edge-certificate", helper)
        self.assertNotIn('"/etc/vivolution-edge/tls/teams-fullchain.pem"', helper)
        self.assertIn(
            "ReadWritePaths=/var/lib/vivolution-edge/acme /var/lib/vivolution-edge/certificate-rotation /var/lib/vivolution-edge/runtime /etc/vivolution-edge/tls -/etc/vivolution-edge/runtime-authority.json",
            service,
        )

    def test_rtpengine_is_one_unprivileged_userspace_instance(self) -> None:
        config = self.read("roles/edge_rtpengine/templates/rtpengine.conf.j2")
        unit = self.read(
            "roles/edge_rtpengine/templates/10-vivolution-userspace.conf.j2"
        )
        repositories = self.read("roles/edge_repositories/tasks/main.yml")

        self.assertIn("table = -1", config)
        self.assertEqual(config.count("port-min ="), 1)
        self.assertEqual(config.count("port-max ="), 1)
        self.assertIn("listen-ng = 127.0.0.1:", config)
        self.assertIn("listen-cli = 127.0.0.1:", config)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertIn("AmbientCapabilities=\n", unit)
        self.assertNotIn("rtpengine-kernel-dkms=", repositories)
        self.assertNotIn("name: rtpengine\n", repositories)

    def test_firewall_owns_only_one_table_and_splits_signaling(self) -> None:
        firewall = self.read("roles/edge_firewall/templates/nftables.conf.j2")
        tasks = self.read("roles/edge_firewall/tasks/main.yml")
        systemd = self.read(
            "roles/edge_firewall/templates/10-vivolution-edge.conf.j2"
        )
        handler = self.read("roles/edge_firewall/handlers/main.yml")

        self.assertNotIn("flush ruleset", firewall)
        self.assertIn("destroy table inet vivolution_edge_filter", firewall)
        self.assertIn("policy drop", firewall)
        self.assertIn("hook output priority filter; policy drop;", firewall)
        self.assertIn("edge_tls_signaling_port", firewall)
        self.assertIn("edge_pbx_tls_signaling_port", firewall)
        self.assertNotIn("dport 5060", firewall)
        self.assertNotIn("dport 2223", firewall)
        self.assertNotIn("dport 2224", firewall)
        self.assertIn("synthetic_teams_source_ipv4", firewall)
        self.assertIn("edge_microsoft_media_processor_remote_port_ranges", firewall)
        self.assertIn("udp sport", firewall)
        self.assertIn("edge_runtime_profile == 'SYNTHETIC_PRIVATE'", firewall)
        self.assertIn("edge_runtime_profile == 'DIRECT_ROUTING'", firewall)
        direct_input = (
            "{% if edge_runtime_profile == 'DIRECT_ROUTING' %}\n"
            "        ip saddr @microsoft_signaling_source_ipv4"
        )
        synthetic_input = (
            "{% elif edge_synthetic_teams_source_ipv4_cidrs | length > 0 %}\n"
            "        ip saddr @synthetic_teams_source_ipv4"
        )
        self.assertIn(direct_input, firewall)
        self.assertIn(synthetic_input, firewall)
        self.assertIn("ip daddr @control_plane_ipv4", firewall)
        self.assertIn("ip daddr @microsoft_media_source_ipv4", firewall)
        self.assertIn("ip daddr @pbx_source_ipv4", firewall)
        self.assertIn("ip daddr @ntp_server_ipv4 udp dport 123 accept", firewall)
        self.assertIn("ip daddr {{ edge_azure_imds_ipv4 }} tcp dport 80", firewall)
        self.assertIn("meta nfproto ipv4 tcp dport { 80, 443 }", firewall)
        self.assertNotIn("hook output priority filter; policy accept;", firewall)
        self.assertIn("'3478-3481'", self.read("playbooks/install-edge.yml"))
        self.assertIn("'49152-53247'", self.read("playbooks/install-edge.yml"))
        self.assertIn("vivolution_edge_preservation_probe", tasks)
        self.assertIn(
            "ip saddr @microsoft_(signaling|media)_source_ipv4", tasks
        )
        self.assertIn(
            "ip daddr @(microsoft_(signaling|media)_source_ipv4|pbx_source_ipv4)",
            tasks,
        )
        self.assertNotIn("flush ruleset", systemd)
        self.assertIn("destroy table inet vivolution_edge_filter", systemd)
        self.assertNotIn("state: restarted", handler)
        self.assertIn("--file, /etc/nftables.conf", handler)

    def test_live_firewall_tls_port_assertion_is_profile_exact(self) -> None:
        assertions = [
            self.folded_assertion(
                "roles/edge_firewall/tasks/main.yml",
                "edge_active_firewall.stdout is search('tcp dport 5061",
            ),
            self.folded_assertion(
                "roles/edge_verify/tasks/main.yml",
                "edge_verify_firewall.stdout is search('tcp dport 5061",
            ),
        ]
        azure_synthetic_nft = """table inet vivolution_edge_filter {
        set pbx_source_ipv4 {
                type ipv4_addr
                flags interval
                auto-merge
                elements = { 10.20.1.4 }
        }

        chain input {
                type filter hook input priority filter; policy drop;
                ip saddr @pbx_source_ipv4 tcp dport 15061 ct state new accept
                ip saddr @pbx_source_ipv4 udp sport 21000-21127 udp dport 20000-20255 accept
        }
}"""
        azure_teams_tls_rule = (
            "ip saddr @microsoft_signaling_source_ipv4 "
            "tcp dport 5061 ct state new accept"
        )
        azure_direct_nft = azure_synthetic_nft.replace(
            "ip saddr @pbx_source_ipv4 tcp dport 15061",
            azure_teams_tls_rule
            + "\n                ip saddr @pbx_source_ipv4 tcp dport 15061",
        )
        azure_synthetic_source_nft = azure_synthetic_nft.replace(
            "ip saddr @pbx_source_ipv4 tcp dport 15061",
            "ip saddr @synthetic_teams_source_ipv4 "
            "tcp dport 5061 ct state new accept"
            "\n                ip saddr @pbx_source_ipv4 tcp dport 15061",
        )

        cases = (
            (
                "synthetic-empty-accepted",
                "SYNTHETIC_PRIVATE",
                [],
                azure_synthetic_nft,
                True,
            ),
            (
                "synthetic-empty-rejects-5061",
                "SYNTHETIC_PRIVATE",
                [],
                azure_synthetic_source_nft,
                False,
            ),
            (
                "direct-requires-5061",
                "DIRECT_ROUTING",
                [],
                azure_direct_nft,
                True,
            ),
            (
                "direct-rejects-missing-5061",
                "DIRECT_ROUTING",
                [],
                azure_synthetic_nft,
                False,
            ),
            (
                "synthetic-source-requires-5061",
                "SYNTHETIC_PRIVATE",
                ["10.20.1.4/32"],
                azure_synthetic_source_nft,
                True,
            ),
            (
                "synthetic-source-rejects-missing-5061",
                "SYNTHETIC_PRIVATE",
                ["10.20.1.4/32"],
                azure_synthetic_nft,
                False,
            ),
        )
        for name, profile, synthetic_sources, nft_output, accepted in cases:
            with self.subTest(name=name):
                completed = self.run_local_assertions(
                    assertions,
                    {
                        "edge_runtime_profile": profile,
                        "edge_synthetic_teams_source_ipv4_cidrs": synthetic_sources,
                        "edge_active_firewall": {"stdout": nft_output},
                        "edge_verify_firewall": {"stdout": nft_output},
                    },
                )
                if accepted:
                    self.assertEqual(
                        completed.returncode,
                        0,
                        msg=f"{completed.stdout}\n{completed.stderr}",
                    )
                else:
                    self.assertNotEqual(completed.returncode, 0)

    def test_template_inventory_contains_no_fabricated_ingress_cidrs(self) -> None:
        variables = self.read("inventories/poc-edge-template/group_vars/all.yml")
        hosts = self.read("inventories/poc-edge-template/hosts.yml")

        for variable in (
            "edge_admin_source_ipv4_cidrs",
            "edge_microsoft_signaling_source_ipv4_cidrs",
            "edge_microsoft_media_source_ipv4_cidrs",
            "edge_synthetic_teams_source_ipv4_cidrs",
            "edge_pbx_source_ipv4_cidrs",
        ):
            self.assertIn(f"{variable}: []", variables)
        self.assertIn("edge_pbx_tls_signaling_port: 15061", variables)
        self.assertIn("edge_rtp_port_start: 20000", variables)
        self.assertIn("edge_rtp_port_end: 20255", variables)
        self.assertIn("edge_control_plane_ipv4_cidrs:\n  - 10.20.1.4/32", variables)
        self.assertIn(
            "edge_ntp_server_ipv4_cidrs:\n"
            "  - 162.159.200.1/32\n"
            "  - 162.159.200.123/32",
            variables,
        )
        self.assertIn("example.invalid", hosts)

    def test_time_and_single_nic_network_invariants_are_verified(self) -> None:
        base = self.read("roles/edge_base_os/tasks/main.yml")
        sysctl = self.read(
            "roles/edge_base_os/templates/99-vivolution-edge-network.conf.j2"
        )
        verify = self.read("roles/edge_verify/tasks/main.yml")

        self.assertIn("net.ipv4.ip_forward = 0", sysctl)
        self.assertIn("net.ipv6.conf.all.forwarding = 0", sysctl)
        self.assertIn("accept_redirects = 0", sysctl)
        self.assertIn("send_redirects = 0", sysctl)
        self.assertIn("accept_source_route = 0", sysctl)
        self.assertIn("rp_filter = 1", sysctl)
        self.assertIn("--load=/etc/sysctl.d/99-vivolution-edge-network.conf", base)
        self.assertIn("NTPSynchronized", verify)
        self.assertIn("retries: 10", verify)
        self.assertIn("edge_verify_network_sysctls", verify)
        self.assertIn("python3-cryptography", base)
        self.assertIn("python3-jsonschema", base)
        self.assertIn("openssl", base)
        self.assertIn("ntpsec", base)
        self.assertIn("util-linux", base)
        ntp = self.read("roles/edge_base_os/templates/ntpsec.conf.j2")
        self.assertIn("edge_ntp_server_ipv4_cidrs", ntp)
        self.assertNotIn("pool ", ntp)


if __name__ == "__main__":
    unittest.main()
