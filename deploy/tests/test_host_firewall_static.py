from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
ROLE = PROJECT_ROOT / "deploy" / "roles" / "host_firewall"
SEMANTIC_GUARD = ROLE / "files" / "nftables_semantic_guard.py"

SPEC = importlib.util.spec_from_file_location("nftables_semantic_guard", SEMANTIC_GUARD)
assert SPEC is not None and SPEC.loader is not None
semantic_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(semantic_guard)


class HostFirewallStaticTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROLE / relative_path).read_text(encoding="utf-8")

    def test_voice_fixture_contract_is_disabled_and_exact_by_default(self) -> None:
        defaults = self.read("defaults/main.yml")

        self.assertIn("cp_voice_fixture_enabled: false", defaults)
        self.assertIn(
            "cp_voice_fixture_source_ipv4_cidr: 10.20.2.0/24", defaults
        )
        self.assertIn("cp_voice_fixture_tcp_ports:\n  - 16061\n  - 25061", defaults)
        self.assertIn(
            "cp_voice_fixture_udp_port_ranges:\n"
            "  - 21000-21127\n"
            "  - 22000-22063",
            defaults,
        )

    def test_voice_fixture_rules_are_conditional_and_source_scoped(self) -> None:
        policy = self.read("templates/nftables.conf.j2")
        condition = "{% if cp_effective_voice_fixture_enabled %}"
        condition_start = policy.index(condition)
        condition_end = policy.index("{% endif %}", condition_start)
        conditional_rules = policy[condition_start:condition_end]

        self.assertIn("cp_voice_fixture_enabled | default(false) | bool", policy)
        self.assertIn("ip saddr {{ cp_voice_fixture_source_ipv4_cidr }}", conditional_rules)
        self.assertIn("tcp dport { {{ cp_voice_fixture_tcp_ports", conditional_rules)
        self.assertIn(
            "udp dport { {{ cp_voice_fixture_udp_port_ranges", conditional_rules
        )
        self.assertNotIn("cp_voice_fixture_tcp_ports", policy[:condition_start])
        self.assertNotIn("cp_voice_fixture_udp_port_ranges", policy[:condition_start])

    def test_enabled_fixture_cannot_override_fixed_contract(self) -> None:
        tasks = self.read("tasks/main.yml")

        self.assertIn("when: cp_voice_fixture_enabled | bool", tasks)
        self.assertIn(
            "cp_voice_fixture_source_ipv4_cidr == '10.20.2.0/24'", tasks
        )
        self.assertIn("cp_voice_fixture_tcp_ports == [16061, 25061]", tasks)
        self.assertIn(
            "cp_voice_fixture_udp_port_ranges == ['21000-21127', '22000-22063']",
            tasks,
        )

    def test_carrier_gateway_contract_is_separate_fixed_and_opt_in(self) -> None:
        defaults = self.read("defaults/main.yml")
        tasks = self.read("tasks/main.yml")
        policy = self.read("templates/nftables.conf.j2")

        self.assertIn("cp_carrier_gateway_enabled: false", defaults)
        self.assertIn("  - 10.20.2.6/32\n  - 10.20.2.7/32", defaults)
        self.assertIn("cp_carrier_gateway_tcp_port: 5061", defaults)
        self.assertIn("20000-20255", defaults)
        self.assertIn("cp_carrier_gateway_ingress_rtp_port_range: 30000-30063", defaults)
        self.assertIn("cp_carrier_gateway_egress_rtp_port_range: 30064-30127", defaults)
        self.assertNotIn("cp_carrier_gateway_udp_destination_port_range", defaults)
        self.assertIn("when: cp_carrier_gateway_enabled | bool", tasks)
        self.assertIn(
            "cp_carrier_gateway_source_ipv4_cidrs == "
            "['10.20.2.6/32', '10.20.2.7/32']",
            tasks,
        )
        condition = "{% if cp_effective_carrier_gateway_enabled %}"
        condition_start = policy.index(condition)
        condition_end = policy.index("{% endif %}", condition_start)
        rules = policy[condition_start:condition_end]
        self.assertIn('comment "vivolution-carrier-tls"', rules)
        self.assertIn('comment "vivolution-carrier-media"', rules)
        self.assertIn("udp sport {{ cp_carrier_gateway_edge_media_source_port_range }}", rules)
        self.assertIn("udp dport {{ cp_carrier_gateway_ingress_rtp_port_range }}", rules)

    def test_provider_trunk_media_and_egress_are_exact_and_opt_in(self) -> None:
        defaults = self.read("defaults/main.yml")
        tasks = self.read("tasks/main.yml")
        policy = self.read("templates/nftables.conf.j2")

        self.assertIn("cp_carrier_gateway_provider_enabled: false", defaults)
        self.assertIn("cp_carrier_gateway_provider_destination_ipv4_cidrs: []", defaults)
        self.assertIn(
            "cp_carrier_gateway_provider_remote_media_port_range: ''",
            defaults,
        )
        self.assertNotIn("twilio", defaults.lower())
        self.assertIn("Reject retained network authority while the provider is disabled", tasks)
        self.assertIn("value.prefixlen == 32", tasks)
        self.assertIn("value.subnet_of(authority)", tasks)
        self.assertIn("cp_carrier_gateway_provider_media_ipv4_cidrs", tasks)
        self.assertIn("cp_carrier_gateway_provider_remote_media_port_range", tasks)

        self.assertGreaterEqual(
            policy.count("{% if cp_carrier_gateway_provider_enabled | bool %}"),
            2,
        )
        self.assertIn('comment "vivolution-carrier-provider-media-in"', policy)
        self.assertIn('comment "vivolution-carrier-provider-tls-out"', policy)
        self.assertIn('comment "vivolution-carrier-provider-media-out"', policy)
        self.assertIn("udp sport {{ cp_carrier_gateway_provider_remote_media_port_range }}", policy)
        self.assertIn("udp dport {{ cp_carrier_gateway_provider_remote_media_port_range }}", policy)
        self.assertIn("udp dport {{ cp_carrier_gateway_egress_rtp_port_range }}", policy)
        self.assertIn("udp sport {{ cp_carrier_gateway_egress_rtp_port_range }}", policy)
        self.assertNotIn("cp_carrier_gateway_udp_destination_port_range", policy)
        self.assertIn("meta skuid {{ cp_carrier_gateway_runtime_uid }}", policy)
        self.assertIn('comment "vivolution-carrier-user-egress-deny"', policy)

    def test_carrier_activation_requires_and_reproves_generation2_profile(self) -> None:
        tasks = self.read("tasks/main.yml")

        carrier_validation = tasks[
            tasks.index("- name: Validate bounded carrier-gateway firewall contract") :
            tasks.index("- name: Reject provider authority while the carrier firewall is disabled")
        ]
        self.assertIn("- cp_voice_fixture_enabled | bool", carrier_validation)
        self.assertIn(
            "Prove the recorded generation-2 profile before carrier activation", tasks
        )
        self.assertIn(
            "Prove the unrecorded generation-2 baseline before first carrier activation",
            tasks,
        )
        self.assertIn("--fixture-enabled\n      - 'true'", tasks)
        self.assertIn("Apply pending controller firewall changes", tasks)
        self.assertIn(
            "Prove the complete rendered policy equals the live ruleset", tasks
        )
        self.assertIn("Reprove the digest-bound active firewall profile", tasks)
        self.assertGreaterEqual(tasks.count("compare-live"), 2)
        self.assertNotIn("carrier_gateway_nft_input.stdout is search", tasks)

    def test_enabled_and_disabled_provider_profiles_render_distinct_exact_policies(self) -> None:
        policy = self.read("templates/nftables.conf.j2")

        def conditional_profile(provider_enabled: bool) -> str:
            conditions = {
                "cp_effective_ssh_source_ipv4_cidrs | length > 0": True,
                "cp_effective_dhcp_server_ipv4 | length > 0": True,
                "cp_effective_voice_fixture_enabled": True,
                "cp_effective_carrier_gateway_enabled": True,
                "cp_carrier_gateway_provider_enabled | bool": provider_enabled,
            }
            active = [True]
            output = []
            for line in policy.splitlines():
                stripped = line.strip()
                if stripped.startswith("{% set "):
                    continue
                if stripped.startswith("{% if ") and stripped.endswith(" %}"):
                    expression = stripped[len("{% if ") : -len(" %}")]
                    active.append(active[-1] and conditions[expression])
                    continue
                if stripped == "{% endif %}":
                    active.pop()
                    continue
                if active[-1]:
                    output.append(line)
            self.assertEqual(active, [True])
            return "\n".join(output)

        disabled = conditional_profile(False)
        enabled = conditional_profile(True)

        for rendered in (disabled, enabled):
            self.assertIn("cp_voice_fixture_tcp_ports", rendered)
            self.assertIn("cp_voice_fixture_udp_port_ranges", rendered)
            self.assertIn('comment "vivolution-carrier-tls"', rendered)
            self.assertIn('comment "vivolution-carrier-user-egress-deny"', rendered)
        self.assertNotIn("vivolution-carrier-provider-", disabled)
        self.assertIn("vivolution-carrier-provider-media-in", enabled)
        self.assertIn("vivolution-carrier-provider-tls-out", enabled)
        self.assertIn("cp_carrier_gateway_provider_destination_ipv4_cidrs", enabled)

    def test_semantic_guard_normalizes_only_runtime_nftables_identity(self) -> None:
        first = {
            "nftables": [
                {"metainfo": {"version": "1.0.9"}},
                {"table": {"family": "inet", "handle": 1, "name": "vivolution_filter"}},
                {
                    "rule": {
                        "chain": "input",
                        "comment": "fixture",
                        "expr": [{"accept": None}],
                        "family": "inet",
                        "handle": 9,
                        "table": "vivolution_filter",
                    }
                },
            ]
        }
        second = json.loads(json.dumps(first))
        second["nftables"][0]["metainfo"]["version"] = "1.1.0"
        second["nftables"][1]["table"]["handle"] = 50
        second["nftables"][2]["rule"]["handle"] = 70
        canonical_first = semantic_guard._canonical_ruleset(
            json.dumps(first), "first"
        )
        canonical_second = semantic_guard._canonical_ruleset(
            json.dumps(second), "second"
        )
        self.assertEqual(canonical_first, canonical_second)

        second["nftables"][2]["rule"]["comment"] = "widened"
        self.assertNotEqual(
            canonical_first,
            semantic_guard._canonical_ruleset(json.dumps(second), "changed"),
        )

    def test_existing_controller_profiles_do_not_enable_fixture(self) -> None:
        inventories = PROJECT_ROOT / "deploy" / "inventories"
        for profile in ("lab", "rebuild", "azure", "azure-single"):
            variables = (
                inventories / profile / "group_vars" / "all.yml"
            ).read_text(
                encoding="utf-8"
            )
            self.assertNotIn(
                "cp_voice_fixture_enabled: true",
                variables,
                f"{profile} unexpectedly enables the isolated voice fixture",
            )


if __name__ == "__main__":
    unittest.main()
