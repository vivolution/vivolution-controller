from __future__ import annotations

import copy
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "cp1_carrier_nsg_overlay.py"
BICEP = ROOT / "cp1-carrier-nsg-overlay.bicep"
PARAMETERS = ROOT / "cp1-carrier-nsg-overlay.bicepparam"
TWILIO_PARAMETERS = ROOT / "cp1-carrier-nsg-overlay-twilio.bicepparam"
MAIN_BICEP = ROOT / "main.bicep"

SPEC = importlib.util.spec_from_file_location("cp1_carrier_nsg_overlay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)

NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)


def stat_mode(path: Path | None) -> int:
    assert path is not None
    return stat.S_IMODE(path.stat().st_mode)


def rid(resource_type: str, name: str) -> str:
    return (
        "/subscriptions/{}/resourceGroups/{}/providers/{}/{}".format(
            overlay.EXPECTED_SUBSCRIPTION_ID,
            overlay.EXPECTED_RESOURCE_GROUP,
            resource_type,
            name,
        )
    )


def tags(node: str) -> dict[str, str]:
    return overlay._replacement_tags(node, "2026-09-03T00:00:00Z")


def node_observation(node: str, action: str) -> dict:
    private_ip, subnet = overlay.NODE_SPECS[node]
    nic_id = rid("Microsoft.Network/networkInterfaces", node + "-nic")
    nsg_id = rid("Microsoft.Network/networkSecurityGroups", node + "-nsg")
    node_tags = tags(node) if node in overlay.G3_NODES else {"base": "test"}
    return {
        "name": node,
        "nic": {
            "enableAcceleratedNetworking": False,
            "enableIPForwarding": False,
            "id": nic_id,
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "primary": True,
                    "privateIPAddress": private_ip,
                    "privateIPAddressVersion": "IPv4",
                    "privateIPAllocationMethod": "Static",
                    "publicIpId": rid(
                        "Microsoft.Network/publicIPAddresses", node + "-pip"
                    ),
                    "subnetId": rid(
                        "Microsoft.Network/virtualNetworks", "viv-sbc-poc-vnet"
                    )
                    + "/subnets/"
                    + subnet,
                }
            ],
            "location": "uaenorth",
            "name": node + "-nic",
            "networkSecurityGroupId": nsg_id,
            "provisioningState": "Succeeded",
            "tags": node_tags,
        },
        "nsg": {
            "id": nsg_id,
            "location": "uaenorth",
            "name": node + "-nsg",
            "networkInterfaceIds": [nic_id],
            "provisioningState": "Succeeded",
            "subnetIds": [],
            "tags": node_tags,
        },
        "powerState": (
            "PowerState/deallocated"
            if action == "teardown" and node in overlay.G3_NODES
            else "PowerState/running"
        ),
        "vm": {
            "id": rid("Microsoft.Compute/virtualMachines", node),
            "location": "uaenorth",
            "name": node,
            "nicIds": [nic_id],
            "provisioningState": "Succeeded",
            "tags": node_tags,
        },
    }


def with_etags(rules: list[dict]) -> list[dict]:
    return [{**copy.deepcopy(rule), "etag": 'W/"{}"'.format(index)} for index, rule in enumerate(rules)]


def budget() -> dict:
    notifications = {
        str(value): {
            "contactEmails": ["jaydevupadhyay@gmail.com"],
            "contactGroups": [],
            "contactRoles": [],
            "enabled": True,
            "operator": "GreaterThanOrEqualTo",
            "threshold": value,
            "thresholdType": "Actual",
        }
        for value in (75, 90, 100)
    }
    return {
        "id": rid(
            "Microsoft.Consumption/budgets", overlay.EXPECTED_BUDGET_NAME
        ),
        "name": overlay.EXPECTED_BUDGET_NAME,
        "properties": {
            "amount": 100,
            "category": "Cost",
            "currentSpend": {"amount": 20.25, "unit": "USD"},
            "notifications": notifications,
            "timePeriod": {
                "endDate": "2027-08-01T00:00:00Z",
                "startDate": "2026-08-01T00:00:00Z",
            },
            "timeGrain": "Monthly",
        },
        "type": "Microsoft.Consumption/budgets",
    }


def generation3_authority(action: str) -> dict:
    return {
        "compiledParametersSha256": "a" * 64,
        "compiledTemplateSha256": "b" * 64,
        "deadlineUtc": "2026-09-03T00:00:00Z",
        "deadmanJobId": "12345678-1234-4234-8234-123456789abc",
        "deadmanReceiptSha256": "c" * 64,
        "directReplacementPlanSha256": "d" * 64,
        "liveDeadmanJobSha256": "e" * 64 if action == "apply" else None,
        "schedulerAuthoritySha256": "f" * 64 if action == "apply" else None,
        "schedulerLive": action == "apply",
    }


def observations(action: str, state: str, *, target_twilio_enabled: bool = False) -> dict:
    target_rules = overlay._target_overlay_rules(target_twilio_enabled)
    target_by_name = {rule["name"]: rule for rule in target_rules}
    cp1 = list(overlay.CP1_BASE_RULES)
    if state == "EXACT":
        cp1 += list(target_rules)
    elif state == "DISABLED":
        cp1 += list(overlay.ALWAYS_OVERLAY_RULES)
    elif state == "PARTIAL":
        cp1 += [target_rules[0]]
    present = {rule["name"] for rule in cp1} & set(target_by_name)
    return {
        "account": {
            "id": overlay.EXPECTED_SUBSCRIPTION_ID,
            "state": "Enabled",
            "tenantId": overlay.EXPECTED_TENANT_ID,
        },
        "action": action,
        "budget": budget(),
        "cp1Rules": with_etags(cp1),
        "g2Rules": {
            node: with_etags(rules)
            for node, rules in overlay.G2_RULES_BY_NODE.items()
        },
        "g3Rules": {
            node: with_etags(rules)
            for node, rules in overlay.G3_RULES_BY_NODE.items()
        },
        "generation3Authority": generation3_authority(action),
        "nodes": [node_observation(node, action) for node in overlay.NODE_SPECS],
        "overlayDeploymentState": "ABSENT",
        "resourceGroup": {
            "id": "/subscriptions/{}/resourceGroups/{}".format(
                overlay.EXPECTED_SUBSCRIPTION_ID, overlay.EXPECTED_RESOURCE_GROUP
            ),
            "location": "uaenorth",
            "name": overlay.EXPECTED_RESOURCE_GROUP,
            "properties": {"provisioningState": "Succeeded"},
        },
        "whatIf": (
            {
                "changes": [
                    {
                        "changeType": "NoChange" if name in present else "Create",
                        "resourceId": overlay._rule_id(name),
                    }
                    for name in sorted(target_by_name)
                ],
                "status": "Succeeded",
            }
            if action == "apply"
            else None
        ),
    }


class OverlayTests(unittest.TestCase):
    def test_compiled_package_and_bicep_are_exact(self):
        self.assertEqual(
            overlay.compile_package(),
            {
                "bicepCompilerVersion": "0.46.1.21595",
                "compiledParametersSha256": overlay.EXPECTED_COMPILED_PARAMETERS_SHA256[False],
                "compiledTemplateSha256": overlay.EXPECTED_COMPILED_TEMPLATE_SHA256,
                "twilioEnabled": False,
            },
        )
        self.assertEqual(
            overlay.compile_package(True),
            {
                "bicepCompilerVersion": "0.46.1.21595",
                "compiledParametersSha256": overlay.EXPECTED_COMPILED_PARAMETERS_SHA256[True],
                "compiledTemplateSha256": overlay.EXPECTED_COMPILED_TEMPLATE_SHA256,
                "twilioEnabled": True,
            },
        )
        source = BICEP.read_text(encoding="utf-8")
        self.assertEqual(source.count("Microsoft.Network/networkSecurityGroups/securityRules@2023-11-01"), 17)
        self.assertEqual(source.count("= if (twilioEnabled)"), 3)
        self.assertIn("param twilioEnabled bool", source)
        self.assertIn("param twilioEnabled = false", PARAMETERS.read_text(encoding="utf-8"))
        self.assertIn(
            "param twilioEnabled = true",
            TWILIO_PARAMETERS.read_text(encoding="utf-8"),
        )
        self.assertIn("priority: 320", source)
        self.assertIn("priority: 330", source)
        self.assertIn("priority: 340", source)
        self.assertIn("priority: 1200", source)
        self.assertIn("priority: 1210", source)
        self.assertIn("'10.20.2.6/32'", source)
        self.assertIn("'10.20.2.7/32'", source)
        self.assertIn("sourcePortRange: '20000-20255'", source)
        self.assertIn("destinationPortRange: '30000-30127'", source)
        self.assertIn("sourceAddressPrefix: '168.86.128.0/18'", source)
        self.assertIn("destinationAddressPrefix: '168.86.128.0/18'", source)
        self.assertIn("sourcePortRange: '10000-60000'", source)
        self.assertIn("destinationPortRange: '10000-60000'", source)
        self.assertIn("sourcePortRange: '30000-30127'", source)
        self.assertIn("direction: 'Outbound'", source)
        self.assertIn("name: 'DenyAllCp1Outbound'", source)
        self.assertIn("priority: 4096", source)
        for dependency in (
            "AllowCp1AzureDhcpOutbound",
            "AllowCp1AzureDnsUdpOutbound",
            "AllowCp1AzureDnsTcpOutbound",
            "AllowCp1AzureWireServerOutbound",
            "AllowCp1AzureImdsOutbound",
            "AllowCp1NtpOutbound",
            "AllowCp1WebOutbound",
            "AllowGeneration2FixtureSignalingOutbound",
            "AllowGeneration2FixtureMediaOutbound",
            "AllowGeneration3CarrierSignalingOutbound",
            "AllowGeneration3CarrierMediaOutbound",
        ):
            self.assertIn(dependency, source)
        for signaling_range in (
            "54.172.60.0/30",
            "54.244.51.0/30",
            "54.171.127.192/30",
            "35.156.191.128/30",
            "54.65.63.192/30",
            "54.169.127.128/30",
            "54.252.254.64/30",
            "177.71.206.192/30",
        ):
            self.assertIn(signaling_range, source)
        self.assertNotIn("0.0.0.0/0", source)
        self.assertTrue(PARAMETERS.exists())

    def test_main_template_remains_two_profile_and_has_no_overlay(self):
        source = MAIN_BICEP.read_text(encoding="utf-8")
        self.assertNotIn("DIRECT_ROUTING_PRIVATE_PBX_POC", source)
        self.assertNotIn("AllowGeneration3Carrier", source)
        allowed = source[source.index("@allowed([") : source.index("])\n@description('Edge data-plane")]
        self.assertIn("'SYNTHETIC_PRIVATE'", allowed)
        self.assertIn("'DIRECT_ROUTING'", allowed)

    def test_apply_plan_binds_every_node_base_rules_g2_rules_budget_and_what_if(self):
        package = overlay.compile_package()
        plan = overlay.create_plan("apply", observations("apply", "ABSENT"), package, now=NOW)
        self.assertEqual(plan["overlayState"], "ABSENT")
        self.assertFalse(plan["targetTwilioEnabled"])
        self.assertEqual(len(plan["nodeBindings"]), 5)
        self.assertEqual(
            len(plan["providerWhatIf"]["changes"]), len(overlay.OVERLAY_RULES)
        )
        self.assertTrue(all(item["changeType"] == "Create" for item in plan["providerWhatIf"]["changes"]))
        self.assertEqual(plan["budget"]["incrementalOverlayCostUsd"], "0.00")
        self.assertEqual(plan["budget"]["budgetScope"], overlay._resource_group_id())
        self.assertEqual(
            plan["generation3Authority"]["directReplacementPlanSha256"], "d" * 64
        )
        body = {key: value for key, value in plan.items() if key not in {"planSha256", "status"}}
        self.assertEqual(plan["planSha256"], overlay._digest(body))

    def test_tampering_and_unapproved_what_if_fail_closed(self):
        cases = []
        bad = observations("apply", "ABSENT")
        bad["nodes"][0]["nic"]["ipConfigurations"][0]["privateIPAddress"] = "10.20.1.5"
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["g2Rules"][overlay.G2_NODES[0]][0]["priority"] = 999
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["g3Rules"][overlay.G3_NODES[0]][0]["destinationPortRange"] = "*"
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["whatIf"]["changes"][0]["changeType"] = "Modify"
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["amount"] = 101
        cases.append(bad)
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(overlay.OverlayError):
                overlay.create_plan("apply", value, overlay.compile_package(), now=NOW)

    def test_generation3_rule_inventory_validator_is_exact_and_bounded(self):
        node = overlay.G3_NODES[0]
        raw = json.dumps(overlay.G3_RULES_BY_NODE[node])
        evidence = overlay.validate_generation3_rule_inventory(node, raw)
        self.assertEqual(evidence["ruleCount"], 19)
        self.assertEqual(
            evidence["status"], "GENERATION3_DIRECT_ROUTING_NSG_VALID"
        )

        drifted = copy.deepcopy(overlay.G3_RULES_BY_NODE[node])
        drifted[0]["destinationPortRange"] = "*"
        with self.assertRaises(overlay.OverlayError):
            overlay.validate_generation3_rule_inventory(node, json.dumps(drifted))
        with self.assertRaises(overlay.OverlayError):
            overlay.validate_generation3_rule_inventory(node, "[" + " " * (256 * 1024))

    def test_partial_overlay_has_mixed_apply_recovery_and_fresh_teardown(self):
        package = overlay.compile_package()
        apply_plan = overlay.create_plan(
            "apply", observations("apply", "PARTIAL"), package, now=NOW
        )
        self.assertEqual(apply_plan["overlayState"], "PARTIAL")
        self.assertEqual(
            {item["changeType"] for item in apply_plan["providerWhatIf"]["changes"]},
            {"Create", "NoChange"},
        )
        teardown_plan = overlay.create_plan(
            "teardown", observations("teardown", "PARTIAL"), package, now=NOW
        )
        self.assertEqual(teardown_plan["overlayState"], "PARTIAL")
        self.assertEqual(len(teardown_plan["overlayRules"]), 1)

    def test_disabled_target_plans_etag_removal_and_teardown_accepts_superset(self):
        value = observations("apply", "EXACT")
        value["cp1Rules"] = with_etags(
            list(overlay.CP1_BASE_RULES) + list(overlay.ALL_OVERLAY_RULES)
        )
        disabled = overlay.create_plan(
            "apply", value, overlay.compile_package(False), now=NOW
        )
        self.assertEqual(disabled["overlayState"], "SUPERSET")
        self.assertEqual(len(disabled["conditionalDeletes"]), 3)

        teardown = observations("teardown", "EXACT")
        teardown["cp1Rules"] = with_etags(
            list(overlay.CP1_BASE_RULES) + list(overlay.ALL_OVERLAY_RULES)
        )
        plan = overlay.create_plan(
            "teardown", teardown, overlay.compile_package(), now=NOW
        )
        self.assertEqual(plan["overlayState"], "SUPERSET")
        self.assertEqual(len(plan["overlayRules"]), len(overlay.ALL_OVERLAY_RULES))

    def test_later_twilio_enable_is_separately_digest_and_what_if_bound(self):
        package = overlay.compile_package(True)
        before = observations(
            "apply", "DISABLED", target_twilio_enabled=True
        )
        plan = overlay.create_plan("apply", before, package, now=NOW)
        self.assertTrue(plan["targetTwilioEnabled"])
        self.assertEqual(plan["conditionalDeletes"], [])
        self.assertEqual(plan["overlayState"], "PARTIAL")
        changes = {
            item["resourceId"].rsplit("/", 1)[-1].lower(): item["changeType"]
            for item in plan["providerWhatIf"]["changes"]
        }
        self.assertEqual(
            {
                changes[rule["name"].lower()]
                for rule in overlay.TWILIO_OVERLAY_RULES
            },
            {"Create"},
        )
        self.assertEqual(
            {
                changes[rule["name"].lower()]
                for rule in overlay.ALWAYS_OVERLAY_RULES
            },
            {"NoChange"},
        )

    def test_budget_uses_exact_active_rg_current_spend_and_no_filter(self):
        package = overlay.compile_package()
        exact = observations("apply", "ABSENT")
        exact["budget"]["properties"]["currentSpend"]["amount"] = 100
        plan = overlay.create_plan("apply", exact, package, now=NOW)
        self.assertEqual(plan["budget"]["currentSpendUsd"], "100.00")
        self.assertEqual(plan["budget"]["remainingBudgetUsd"], "0.00")

        cases = []
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["timePeriod"]["endDate"] = "2026-08-30T00:00:00Z"
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["filter"] = {"dimensions": {}}
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["currentSpend"] = {"amount": 101, "unit": "USD"}
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["currentSpend"] = {"amount": 1, "unit": "EUR"}
        cases.append(bad)
        bad = observations("apply", "ABSENT")
        bad["budget"]["properties"]["currentSpend"] = {"amount": "NaN", "unit": "USD"}
        cases.append(bad)
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(overlay.OverlayError):
                overlay.create_plan("apply", value, package, now=NOW)

    def test_generation3_deadline_must_equal_reviewed_plan_and_live_deadman(self):
        value = observations("apply", "ABSENT")
        value["generation3Authority"]["deadlineUtc"] = "2030-01-01T00:00:00Z"
        with self.assertRaises(overlay.OverlayError):
            overlay.create_plan("apply", value, overlay.compile_package(), now=NOW)
        value = observations("apply", "ABSENT")
        value["generation3Authority"]["schedulerLive"] = False
        with self.assertRaises(overlay.OverlayError):
            overlay.create_plan("apply", value, overlay.compile_package(), now=NOW)

    def test_compiled_artifacts_are_0400_and_shared_by_what_if_and_create(self):
        bundle = overlay.compile_package_bundle()
        with overlay.CompiledArtifacts(bundle) as artifacts:
            artifacts.verify(bundle.evidence)
            self.assertEqual(stat_mode(artifacts.template_path), 0o400)
            self.assertEqual(stat_mode(artifacts.parameters_path), 0o400)
            arguments = artifacts.deployment_arguments()
            self.assertIn("--template-file", arguments)
            self.assertTrue(any(value.startswith("@") for value in arguments))

    def test_mutation_refuses_expiry_and_fresh_package_drift(self):
        before = observations("apply", "ABSENT")
        plan = overlay.create_plan("apply", before, overlay.compile_package(), now=NOW)
        with mock.patch.object(overlay, "collect_observations", return_value=before):
            with self.assertRaises(overlay.OverlayError):
                overlay.apply_plan(plan, runner=lambda argv: "", now=NOW + timedelta(minutes=11))

        commands = []
        with overlay.CompiledArtifacts(overlay.compile_package_bundle()) as artifacts:
            with mock.patch.object(overlay, "collect_observations", return_value=before), mock.patch.object(
                overlay, "compile_package", return_value={"drift": "yes"}
            ):
                with self.assertRaises(overlay.OverlayError):
                    overlay.apply_plan(
                        plan,
                        runner=lambda argv: commands.append(list(argv)) or "",
                        artifacts=artifacts,
                        now=NOW + timedelta(minutes=1),
                    )
        self.assertEqual(commands, [])

    def test_timed_out_deployment_is_cancelled_and_settled(self):
        plan = overlay.create_plan(
            "apply", observations("apply", "ABSENT"), overlay.compile_package(), now=NOW
        )
        calls = []

        def command_result(argv, timeout):
            calls.append(list(argv))
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(argv, timeout)
            if len(calls) == 2:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, '"Canceled"', "")

        with mock.patch.object(overlay, "_command_result", side_effect=command_result):
            with self.assertRaises(overlay.OverlayError):
                overlay._run_deployment_with_deadline(
                    ["az", "deployment", "group", "create"],
                    plan,
                    runner=overlay._run,
                    now=NOW + timedelta(minutes=1),
                )
        self.assertEqual(calls[1][0:4], ["az", "deployment", "group", "cancel"])
        self.assertEqual(calls[2][0:4], ["az", "deployment", "group", "show"])

    def test_teardown_requires_both_g3_nodes_deallocated(self):
        value = observations("teardown", "EXACT")
        value["nodes"][-1]["powerState"] = "PowerState/running"
        with self.assertRaises(overlay.OverlayError):
            overlay.create_plan("teardown", value, overlay.compile_package(), now=NOW)
        plan = overlay.create_plan(
            "teardown", observations("teardown", "EXACT"), overlay.compile_package(), now=NOW
        )
        self.assertEqual(plan["overlayState"], "EXACT")
        self.assertIsNone(plan["providerWhatIf"])

    def test_saved_plan_requires_exact_path_mode_digest_phrase_and_freshness(self):
        plan = overlay.create_plan(
            "apply", observations("apply", "ABSENT"), overlay.compile_package(), now=NOW
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.object(overlay, "EXPECTED_PLAN_PATH", path):
                loaded = overlay.read_plan(
                    path,
                    supplied_sha256=plan["planSha256"],
                    confirmation=overlay.APPLY_CONFIRMATION,
                    now=NOW + timedelta(minutes=5),
                )
                self.assertEqual(loaded, plan)
                for sha, phrase, current in (
                    ("0" * 64, overlay.APPLY_CONFIRMATION, NOW + timedelta(minutes=5)),
                    (plan["planSha256"], "wrong", NOW + timedelta(minutes=5)),
                    (plan["planSha256"], overlay.APPLY_CONFIRMATION, NOW + timedelta(minutes=11)),
                ):
                    with self.assertRaises(overlay.OverlayError):
                        overlay.read_plan(path, supplied_sha256=sha, confirmation=phrase, now=current)

    def test_apply_reobserves_then_deploys_and_proves_exact_postcondition(self):
        package = overlay.compile_package()
        before = observations("apply", "ABSENT")
        after = observations("apply", "EXACT")
        plan = overlay.create_plan("apply", before, package, now=NOW)
        commands = []

        def runner(argv):
            commands.append(list(argv))
            return json.dumps(
                {
                    "id": rid("Microsoft.Resources/deployments", overlay.DEPLOYMENT_NAME),
                    "name": overlay.DEPLOYMENT_NAME,
                    "provisioningState": "Succeeded",
                }
            )

        with mock.patch.object(overlay, "collect_observations", side_effect=[before, after]):
            result = overlay.apply_plan(plan, runner=runner, now=NOW + timedelta(minutes=1))
        self.assertEqual(result["status"], "CP1_CARRIER_NSG_OVERLAY_APPLIED")
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0:4], ["az", "deployment", "group", "create"])

    def test_apply_disabled_mode_etag_removes_only_conditional_twilio_rules(self):
        package = overlay.compile_package(False)
        before = observations("apply", "EXACT")
        before["cp1Rules"] = with_etags(
            list(overlay.CP1_BASE_RULES) + list(overlay.ALL_OVERLAY_RULES)
        )
        after = observations("apply", "EXACT")
        plan = overlay.create_plan("apply", before, package, now=NOW)
        commands = []

        def runner(argv):
            commands.append(list(argv))
            if argv[0:4] == ["az", "deployment", "group", "create"]:
                return json.dumps(
                    {
                        "id": rid(
                            "Microsoft.Resources/deployments", overlay.DEPLOYMENT_NAME
                        ),
                        "name": overlay.DEPLOYMENT_NAME,
                        "provisioningState": "Succeeded",
                    }
                )
            return ""

        with mock.patch.object(
            overlay, "collect_observations", side_effect=[before, after]
        ):
            result = overlay.apply_plan(
                plan, runner=runner, now=NOW + timedelta(minutes=1)
            )
        self.assertFalse(result["twilioEnabled"])
        self.assertEqual(commands[0][0:4], ["az", "deployment", "group", "create"])
        self.assertEqual(len(commands[1:]), 3)
        self.assertTrue(
            all(command[0:4] == ["az", "rest", "--method", "delete"] for command in commands[1:])
        )
        self.assertTrue(
            all(any(value.startswith("If-Match=") for value in command) for command in commands[1:])
        )

    def test_teardown_uses_etag_deletes_and_proves_absence(self):
        package = overlay.compile_package()
        before = observations("teardown", "EXACT")
        after = observations("teardown", "ABSENT")
        plan = overlay.create_plan("teardown", before, package, now=NOW)
        commands = []

        def runner(argv):
            commands.append(list(argv))
            return ""

        with mock.patch.object(overlay, "collect_observations", side_effect=[before, after]):
            result = overlay.apply_plan(plan, runner=runner, now=NOW + timedelta(minutes=1))
        self.assertEqual(result["status"], "CP1_CARRIER_NSG_OVERLAY_REMOVED")
        self.assertEqual(len(commands), len(overlay.OVERLAY_RULES))
        self.assertTrue(all(command[0:4] == ["az", "rest", "--method", "delete"] for command in commands))
        self.assertTrue(all(any(value.startswith("If-Match=") for value in command) for command in commands))

    def test_exact_teardown_plan_resumes_from_one_remaining_rule(self):
        plan = overlay.create_plan(
            "teardown", observations("teardown", "EXACT"), overlay.compile_package(), now=NOW
        )
        partial = observations("teardown", "PARTIAL")
        absent = observations("teardown", "ABSENT")
        commands = []

        def runner(argv):
            commands.append(list(argv))
            return ""

        with mock.patch.object(overlay, "collect_observations", side_effect=[partial, absent]):
            result = overlay.apply_plan(
                plan, runner=runner, now=NOW + timedelta(minutes=1)
            )
        self.assertEqual(result["deletedRuleNames"], [partial["cp1Rules"][-1]["name"]])
        self.assertEqual(len(commands), 1)


if __name__ == "__main__":
    unittest.main()
