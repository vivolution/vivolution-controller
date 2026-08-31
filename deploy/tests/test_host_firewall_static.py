from __future__ import annotations

import pathlib
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
ROLE = PROJECT_ROOT / "deploy" / "roles" / "host_firewall"


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
        self.assertIn("30000-30127", defaults)
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
        self.assertIn("udp dport {{ cp_carrier_gateway_udp_destination_port_range }}", rules)

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
