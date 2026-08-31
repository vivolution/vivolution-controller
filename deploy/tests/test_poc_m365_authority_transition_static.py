import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PocM365AuthorityTransitionStaticTests(unittest.TestCase):
    def test_controller_activation_keeps_transition_exact_and_secret_safe(self) -> None:
        defaults = (
            PROJECT_ROOT
            / "deploy"
            / "roles"
            / "controller_services"
            / "defaults"
            / "main.yml"
        ).read_text(encoding="utf-8")
        activation = (
            PROJECT_ROOT
            / "deploy"
            / "roles"
            / "controller_services"
            / "tasks"
            / "activate.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "cp_controller_transition_vivolution_poc_m365_authority: false",
            defaults,
        )
        self.assertIn(
            "cp_controller_vivolution_previous_entra_tenant_id: ''", defaults
        )
        self.assertIn(
            "cp_controller_vivolution_m365_transition_acknowledgement: ''", defaults
        )
        self.assertIn(
            "cp_controller_vivolution_previous_entra_tenant_id == "
            "'efc3bcaa-8879-4366-a452-2b8efa76b16a'",
            activation,
        )
        self.assertIn(
            "cp_controller_vivolution_entra_tenant_id == "
            "'151cd01a-1e81-40a9-b898-d8646e1a8760'",
            activation,
        )
        self.assertIn(
            "cp_controller_vivolution_primary_domain == 'vivolution.ae'",
            activation,
        )
        self.assertIn(
            "transition_vivolution_poc_m365_authority", activation
        )
        self.assertIn("--from-entra-tenant-id", activation)
        self.assertIn("--to-entra-tenant-id", activation)
        self.assertIn("--to-primary-domain", activation)
        self.assertIn("--acknowledge", activation)

        transition_start = activation.index(
            "Transition bounded POC to preflight-confirmed Vivolution M365 authority"
        )
        reconcile_start = activation.index(
            "Reconcile the bounded Vivolution first-tenant POC inventory"
        )
        self.assertLess(transition_start, reconcile_start)
        transition_block = activation[transition_start:reconcile_start]
        self.assertIn("no_log: true", transition_block)
        self.assertNotIn("password", transition_block.lower())
        self.assertNotIn("private key", transition_block.lower())


if __name__ == "__main__":
    unittest.main()
