from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reconcile_root_direct_dns_acme_authority as reconcile  # noqa: E402
import deploy_root_direct_dns_acme as deploy_authority  # noqa: E402
import root_direct_dns_acme_contract as contract  # noqa: E402
import teardown_root_direct_dns_acme as teardown  # noqa: E402


SUB = contract.EXPECTED_SUBSCRIPTION_ID
TENANT = contract.EXPECTED_TENANT_ID
PRINCIPALS = {
    "carrier": "10000000-0000-4000-8000-000000000001",
    "sbc1": "10000000-0000-4000-8000-000000000002",
    "sbc2": "10000000-0000-4000-8000-000000000003",
}


def inputs() -> contract.ExpectedInputs:
    return contract.ExpectedInputs(
        subscription_id=SUB,
        tenant_id=TENANT,
        carrier_public_ipv4="1.1.1.1",
        sbc1_public_ipv4="8.8.8.8",
        sbc2_public_ipv4="9.9.9.9",
        cp1_principal_id=PRINCIPALS["carrier"],
        sbc1_principal_id=PRINCIPALS["sbc1"],
        sbc2_principal_id=PRINCIPALS["sbc2"],
    )


def child_map() -> dict[str, dict[str, object]]:
    return {
        zone: {
            "nameServers": [
                f"ns1-{endpoint}.azure-dns.com",
                f"ns2-{endpoint}.azure-dns.net",
                f"ns3-{endpoint}.azure-dns.org",
                f"ns4-{endpoint}.azure-dns.info",
            ]
        }
        for endpoint, zone in zip(contract.ENDPOINTS, contract.CHILD_ZONES)
    }


def root_records() -> list[dict[str, object]]:
    result: list[dict[str, object]] = [
        {
            "etag": "unrelated-etag",
            "id": contract.record_id(SUB, contract.ROOT_ZONE, "TXT", "unrelated"),
            "name": "unrelated",
            "type": "Microsoft.Network/dnsZones/TXT",
            "ttl": 300,
        }
    ]
    children = child_map()
    for endpoint in contract.ENDPOINTS:
        zone = f"acme-{endpoint}.{contract.ROOT_ZONE}"
        result.extend(
            [
                {
                    "ARecords": [{"ipv4Address": inputs().addresses[endpoint]}],
                    "etag": f"a-{endpoint}",
                    "id": contract.record_id(SUB, contract.ROOT_ZONE, "A", endpoint),
                    "name": endpoint,
                    "ttl": 60,
                    "type": "Microsoft.Network/dnsZones/A",
                },
                {
                    "CNAMERecord": {
                        "cname": f"_acme-challenge.acme-{endpoint}.{contract.ROOT_ZONE}."
                    },
                    "etag": f"cname-{endpoint}",
                    "id": contract.record_id(
                        SUB, contract.ROOT_ZONE, "CNAME", f"_acme-challenge.{endpoint}"
                    ),
                    "name": f"_acme-challenge.{endpoint}",
                    "ttl": 60,
                    "type": "Microsoft.Network/dnsZones/CNAME",
                },
                {
                    "NSRecords": [
                        {"nsdname": f"{server}."}
                        for server in children[zone]["nameServers"]
                    ],
                    "etag": f"ns-{endpoint}",
                    "id": contract.record_id(
                        SUB, contract.ROOT_ZONE, "NS", f"acme-{endpoint}"
                    ),
                    "name": f"acme-{endpoint}",
                    "ttl": 3600,
                    "type": "Microsoft.Network/dnsZones/NS",
                },
            ]
        )
    return result


def assignment(endpoint: str) -> dict[str, str]:
    zone = f"acme-{endpoint}.{contract.ROOT_ZONE}"
    scope = contract.zone_id(SUB, zone)
    suffix = {"sbc1": "1", "sbc2": "2", "carrier": "3"}[endpoint]
    return {
        "id": (
            f"{scope}/providers/Microsoft.Authorization/roleAssignments/"
            f"20000000-0000-4000-8000-00000000000{suffix}"
        ),
        "principalId": PRINCIPALS[endpoint],
        "principalType": "ServicePrincipal",
        "roleDefinitionId": contract.role_definition_id(SUB),
        "scope": scope,
    }


def role() -> dict[str, object]:
    return {
        "assignableScopes": [f"/subscriptions/{SUB}"],
        "description": contract.ROLE_DESCRIPTION,
        "id": contract.role_definition_id(SUB),
        "name": contract.ROLE_GUID,
        "permissions": [
            {
                "actions": sorted(contract.ROLE_ACTIONS),
                "notActions": [],
                "dataActions": [],
                "notDataActions": [],
            }
        ],
        "roleName": contract.ROLE_NAME,
        "roleType": "CustomRole",
    }


def discovery(with_challenges: bool = False) -> dict[str, object]:
    children = []
    observed = []
    for endpoint, zone in zip(contract.ENDPOINTS, contract.CHILD_ZONES):
        direct_assignment = assignment(endpoint)
        children.append(
            {
                "assignment": {
                    "id": direct_assignment["id"],
                    "principalId": direct_assignment["principalId"],
                    "scope": direct_assignment["scope"],
                },
                "etag": f"zone-{endpoint}",
                "id": contract.zone_id(SUB, zone),
                "name": zone,
            }
        )
        challenge = None
        if with_challenges:
            challenge = {
                "etag": f"txt-{endpoint}",
                "id": contract.record_id(SUB, zone, "TXT", "_acme-challenge"),
                "name": "_acme-challenge",
            }
        observed.append(
            {
                "challenge": challenge,
                "exists": True,
                "name": zone,
                "roleAssignmentPresent": True,
            }
        )
    return {
        "authority": {
            "childZones": children,
            "customRoleDefinition": {
                "id": contract.role_definition_id(SUB),
                "name": contract.ROLE_GUID,
            },
            "parentRecords": contract._validate_parent_records(
                root_records(), inputs(), child_map(), require_all=True
            )[0],
            "virtualMachines": [
                {
                    "ipAddress": inputs().addresses[endpoint],
                    "name": contract.VM_NAMES[endpoint],
                    "powerState": "PowerState/deallocated",
                    "principalId": inputs().principals[endpoint],
                }
                for endpoint in contract.ENDPOINTS
            ],
        },
        "observed": {"childZones": observed},
        "preserved": {
            "rootUnrelatedRecordInventorySha256": "a" * 64,
            "rootZone": {
                "etag": "root-1",
                "id": "root-id",
                "name": contract.ROOT_ZONE,
                "nameServers": ["ns1", "ns2", "ns3", "ns4"],
                "tags": None,
            },
            "voiceAuthorityZones": [{"name": name} for name in contract.PRESERVED_ZONES],
        },
        "scope": {
            "childZones": list(contract.CHILD_ZONES),
            "dnsResourceGroup": contract.DNS_RESOURCE_GROUP,
            "parentZone": contract.ROOT_ZONE,
            "pocResourceGroup": contract.POC_RESOURCE_GROUP,
            "preservedZones": list(contract.PRESERVED_ZONES),
            "profile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
            "subscriptionId": SUB,
            "tenantId": TENANT,
        },
    }


def absent_discovery() -> dict[str, object]:
    value = discovery()
    value["authority"]["childZones"] = []
    value["authority"]["customRoleDefinition"] = None
    value["authority"]["parentRecords"] = []
    for child in value["observed"]["childZones"]:
        child["exists"] = False
        child["roleAssignmentPresent"] = False
    return value


def provider_what_if(value: dict[str, object]) -> dict[str, object]:
    state = deploy_authority._resource_state(value)
    changes = [
        {
            "changeType": "NoChange" if present else "Create",
            "resourceId": resource_id,
        }
        for resource_id, present in state["presence"].items()
    ]
    for endpoint in contract.ENDPOINTS:
        observed = state["assignmentIds"][endpoint]
        changes.append(
            {
                "changeType": "NoChange" if observed is not None else "Create",
                "resourceId": observed or assignment(endpoint)["id"],
            }
        )
    return {"changes": changes, "status": "Succeeded"}


class RootDirectDnsContractTests(unittest.TestCase):
    def test_inputs_are_exact_public_and_distinct(self) -> None:
        contract.validate_inputs(inputs())
        with self.assertRaisesRegex(contract.RootDirectDnsError, "globally routable"):
            contract.validate_inputs(
                contract.ExpectedInputs(**{**inputs().__dict__, "carrier_public_ipv4": "10.0.0.1"})
            )
        with self.assertRaisesRegex(contract.RootDirectDnsError, "must be distinct"):
            contract.validate_inputs(
                contract.ExpectedInputs(**{**inputs().__dict__, "sbc2_public_ipv4": "8.8.8.8"})
            )

    def test_root_records_are_exact_but_unrelated_records_are_preserved(self) -> None:
        evidence, unrelated = contract._validate_parent_records(
            root_records(), inputs(), child_map(), require_all=True
        )
        self.assertEqual(len(evidence), 9)
        self.assertEqual(
            [(item["name"], contract.record_kind(item)) for item in unrelated],
            [("unrelated", "TXT")],
        )
        self.assertFalse(any("*" in item["name"] for item in evidence))

    def test_reserved_name_with_another_type_is_rejected(self) -> None:
        records = root_records()
        records.append(
            {
                "etag": "wrong-type",
                "id": contract.record_id(SUB, contract.ROOT_ZONE, "TXT", "sbc1"),
                "name": "sbc1",
                "type": "Microsoft.Network/dnsZones/TXT",
            }
        )
        with self.assertRaisesRegex(contract.RootDirectDnsError, "unexpected record type"):
            contract._validate_parent_records(records, inputs(), child_map(), require_all=True)

    def test_child_zones_accept_only_apex_and_optional_challenge(self) -> None:
        zone = contract.CHILD_ZONES[0]
        base = [
            {"etag": "ns", "id": contract.record_id(SUB, zone, "NS", "@"), "name": "@", "type": "dnsZones/NS"},
            {"etag": "soa", "id": contract.record_id(SUB, zone, "SOA", "@"), "name": "@", "type": "dnsZones/SOA"},
        ]
        self.assertIsNone(contract._validate_child_records(base, SUB, zone))
        bad = base + [
            {"etag": "bad", "id": contract.record_id(SUB, zone, "A", "bad"), "name": "bad", "type": "dnsZones/A"}
        ]
        with self.assertRaisesRegex(contract.RootDirectDnsError, "unexpected record"):
            contract._validate_child_records(bad, SUB, zone)

    def test_role_and_assignments_are_exact_and_zone_scoped(self) -> None:
        validated = contract._validate_role([role()], SUB, required=True)
        self.assertEqual(validated["actions"], sorted(contract.ROLE_ACTIONS))
        children = {zone: child_map()[zone] for zone in contract.CHILD_ZONES}
        found = contract._validate_assignments(
            [assignment(endpoint) for endpoint in contract.ENDPOINTS],
            inputs(),
            children,
            role_present=True,
            require_all=True,
        )
        self.assertEqual(set(found), set(contract.ENDPOINTS))
        drift = assignment("sbc1")
        drift["scope"] = f"/subscriptions/{SUB}"
        with self.assertRaises(contract.RootDirectDnsError):
            contract._validate_assignments(
                [drift, assignment("sbc2"), assignment("carrier")],
                inputs(), children, role_present=True, require_all=True
            )

    def test_group_or_other_role_at_record_descendant_is_inventoried_and_rejected(self) -> None:
        exact = [assignment(endpoint) for endpoint in contract.ENDPOINTS]
        descendant = {
            "id": (
                contract.record_id(SUB, contract.CHILD_ZONES[0], "TXT", "_acme-challenge")
                + "/providers/Microsoft.Authorization/roleAssignments/"
                + "30000000-0000-4000-8000-000000000001"
            ),
            "principalId": "30000000-0000-4000-8000-000000000002",
            "principalType": "Group",
            "roleDefinitionId": (
                f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/"
                "30000000-0000-4000-8000-000000000003"
            ),
            "scope": contract.record_id(
                SUB, contract.CHILD_ZONES[0], "TXT", "_acme-challenge"
            ),
        }
        owned = contract._owned_assignment_inventory([*exact, descendant], inputs())
        self.assertIn(descendant, owned)
        with self.assertRaisesRegex(contract.RootDirectDnsError, "outside its exact node zone"):
            contract._validate_assignments(
                owned,
                inputs(),
                {zone: child_map()[zone] for zone in contract.CHILD_ZONES},
                role_present=True,
                require_all=True,
            )

    def test_public_ip_is_bound_through_exact_vm_nic_and_ipconfiguration(self) -> None:
        endpoint = "sbc1"
        vm_id = (
            f"{contract.resource_group_id(SUB, contract.POC_RESOURCE_GROUP)}/providers/"
            f"Microsoft.Compute/virtualMachines/{contract.VM_NAMES[endpoint]}"
        )
        nic_id = (
            f"{contract.resource_group_id(SUB, contract.POC_RESOURCE_GROUP)}/providers/"
            f"Microsoft.Network/networkInterfaces/{contract.NIC_NAMES[endpoint]}"
        )
        pip_id = (
            f"{contract.resource_group_id(SUB, contract.POC_RESOURCE_GROUP)}/providers/"
            f"Microsoft.Network/publicIPAddresses/{contract.PIP_NAMES[endpoint]}"
        )
        ipconfig_id = f"{nic_id}/ipConfigurations/ipconfig1"
        nic = {
            "id": nic_id,
            "name": contract.NIC_NAMES[endpoint],
            "provisioningState": "Succeeded",
            "virtualMachineId": vm_id,
            "ipConfigurations": [
                {
                    "id": ipconfig_id,
                    "name": "ipconfig1",
                    "primary": True,
                    "privateIpAddress": contract.PRIVATE_IPV4[endpoint],
                    "privateIpAllocationMethod": "Static",
                    "publicIpAddressId": pip_id,
                }
            ],
        }
        pip = {
            "id": pip_id,
            "ipAddress": inputs().sbc1_public_ipv4,
            "ipConfigurationId": ipconfig_id,
            "name": contract.PIP_NAMES[endpoint],
            "provisioningState": "Succeeded",
            "publicIPAllocationMethod": "Static",
            "publicIPAddressVersion": "IPv4",
            "skuName": "Standard",
            "skuTier": "Regional",
        }
        evidence = contract._validate_vm_network(nic, pip, inputs(), endpoint)
        self.assertEqual(evidence["ipAddress"], inputs().sbc1_public_ipv4)
        pip["ipAddress"] = "8.8.4.4"
        with self.assertRaisesRegex(contract.RootDirectDnsError, "public IPv4"):
            contract._validate_vm_network(nic, pip, inputs(), endpoint)

    def test_mutation_primitives_have_exact_etag_bound_targets(self) -> None:
        commands: list[list[str]] = []

        def runner(argv):
            commands.append(list(argv))
            return ""

        contract.delete_txt(
            {
                "etag": "txt-etag",
                "name": "_acme-challenge",
                "zone": contract.CHILD_ZONES[0],
            },
            SUB,
            runner,
        )
        contract.delete_parent_record(
            {"etag": "a-etag", "name": "sbc1", "recordType": "A"}, SUB, runner
        )
        contract.delete_zone(
            {
                "etag": "zone-etag",
                "id": contract.zone_id(SUB, contract.CHILD_ZONES[0]),
                "name": contract.CHILD_ZONES[0],
            },
            SUB,
            runner,
        )
        self.assertIn("--if-match", commands[0])
        self.assertIn("txt-etag", commands[0])
        self.assertIn("--if-match", commands[1])
        self.assertIn("If-Match=zone-etag", commands[2])
        for command in commands:
            self.assertNotIn(contract.ROOT_ZONE, command[:3])

    def test_shared_and_voice_zones_are_never_valid_zone_deletion_targets(self) -> None:
        for zone in (contract.ROOT_ZONE, *contract.PRESERVED_ZONES):
            with self.assertRaisesRegex(contract.RootDirectDnsError, "unauthorized"):
                contract.delete_zone(
                    {"etag": "x", "id": contract.zone_id(SUB, zone), "name": zone},
                    SUB,
                    lambda argv: "",
                )


class RootDirectDnsCreatePlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.package = {
            "bicepCompilerVersion": deploy_authority.EXPECTED_BICEP_VERSION,
            "compiledParametersSha256": "1" * 64,
            "compiledTemplateSha256": deploy_authority.EXPECTED_TEMPLATE_SHA256,
            "parameterFileSha256": "2" * 64,
        }

    def test_compiled_template_and_parameters_are_both_bound(self) -> None:
        parameter_document = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                name: {"value": value}
                for name, value in deploy_authority._expected_parameter_values(inputs()).items()
            },
        }
        template = {
            "metadata": {
                "_generator": {
                    "name": "bicep",
                    "version": deploy_authority.EXPECTED_BICEP_VERSION,
                }
            }
        }
        envelope = json.dumps(
            {
                "parametersJson": json.dumps(parameter_document),
                "templateJson": json.dumps(template),
                "templateSpecId": None,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "root-direct-dns-acme.bicepparam"
            path.write_text("using './root-direct-dns-acme.bicep'\n", encoding="utf-8")
            os.chmod(path, 0o600)
            with mock.patch.object(deploy_authority, "EXPECTED_PARAMETER_PATH", path), mock.patch.object(
                deploy_authority,
                "EXPECTED_TEMPLATE_SHA256",
                deploy_authority._digest(template),
            ):
                package = deploy_authority.compile_package(
                    inputs(), path=path, runner=lambda argv: envelope
                )
        self.assertEqual(
            package["compiledParametersSha256"],
            deploy_authority._digest(parameter_document),
        )
        self.assertEqual(package["compiledTemplateSha256"], deploy_authority._digest(template))

    def test_initial_names_must_be_vacant_but_exact_prior_partial_is_resumable(self) -> None:
        vacant = absent_discovery()
        plan = deploy_authority.build_plan(
            inputs(), vacant, [], self.package, provider_what_if(vacant), now=self.now
        )
        self.assertEqual(plan["resourceState"]["state"], "ABSENT")
        partial = discovery()
        partial["authority"]["parentRecords"] = partial["authority"]["parentRecords"][:1]
        with self.assertRaisesRegex(deploy_authority.RootDirectDnsDeployError, "no exact prior"):
            deploy_authority.build_plan(
                inputs(), partial, [], self.package, provider_what_if(partial), now=self.now
            )
        history = [{"name": deploy_authority.DEPLOYMENT_NAME, "parametersSha256": "3" * 64}]
        resumed = deploy_authority.build_plan(
            inputs(), partial, history, self.package, provider_what_if(partial), now=self.now
        )
        self.assertEqual(resumed["resourceState"]["state"], "PARTIAL_EXACT")
        self.assertEqual(resumed["preserved"]["rootZone"]["etag"], "root-1")

    def test_provider_what_if_is_exact_for_all_sixteen_resources(self) -> None:
        value = absent_discovery()
        state = deploy_authority._resource_state(value)
        validated = deploy_authority._validate_what_if(
            provider_what_if(value), state, inputs()
        )
        self.assertEqual(len(validated["changes"]), 16)
        bad = provider_what_if(value)
        bad["changes"][0]["resourceId"] = f"/subscriptions/{SUB}/resourceGroups/other"
        with self.assertRaisesRegex(deploy_authority.RootDirectDnsDeployError, "unowned"):
            deploy_authority._validate_what_if(bad, state, inputs())

    def test_saved_plan_requires_owner_only_digest_confirmation_and_freshness(self) -> None:
        value = absent_discovery()
        plan = deploy_authority.build_plan(
            inputs(), value, [], self.package, provider_what_if(value), now=self.now
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "root-direct-dns-acme-create-plan.json"
            with mock.patch.object(deploy_authority, "EXPECTED_PLAN_PATH", path):
                deploy_authority.write_plan(plan, path)
                read = deploy_authority.read_plan(
                    supplied_sha256=plan["planSha256"],
                    confirmation=deploy_authority.CONFIRMATION,
                    path=path,
                    now=self.now + timedelta(minutes=1),
                )
                self.assertEqual(read["planSha256"], plan["planSha256"])
                with self.assertRaisesRegex(deploy_authority.RootDirectDnsDeployError, "ten-minute"):
                    deploy_authority.read_plan(
                        supplied_sha256=plan["planSha256"],
                        confirmation=deploy_authority.CONFIRMATION,
                        path=path,
                        now=self.now + timedelta(minutes=11),
                    )
                with self.assertRaisesRegex(deploy_authority.RootDirectDnsDeployError, "confirmation"):
                    deploy_authority.read_plan(
                        supplied_sha256=plan["planSha256"],
                        confirmation="WRONG",
                        path=path,
                        now=self.now + timedelta(minutes=1),
                    )

    def test_apply_reobserves_package_state_what_if_then_requires_exact_postcondition(self) -> None:
        before = absent_discovery()
        after = discovery()
        raw_what_if = provider_what_if(before)
        plan = deploy_authority.build_plan(
            inputs(), before, [], self.package, raw_what_if, now=self.now
        )
        commands: list[list[str]] = []

        def runner(argv):
            commands.append(list(argv))
            return json.dumps(
                {
                    "id": (
                        f"/subscriptions/{SUB}/providers/Microsoft.Resources/deployments/"
                        f"{deploy_authority.DEPLOYMENT_NAME}"
                    ),
                    "name": deploy_authority.DEPLOYMENT_NAME,
                    "provisioningState": "Succeeded",
                }
            )

        with mock.patch.object(
            deploy_authority, "compile_package", return_value=self.package
        ), mock.patch.object(
            deploy_authority.contract, "discover", side_effect=[before, after]
        ), mock.patch.object(
            deploy_authority, "_deployment_history", return_value=[]
        ), mock.patch.object(
            deploy_authority, "_what_if", return_value=raw_what_if
        ):
            result = deploy_authority.apply_plan(plan, runner=runner)
        self.assertEqual(result["status"], "ROOT_DIRECT_DNS_ACME_AUTHORITY_DEPLOYED")
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][1:4], ["deployment", "sub", "create"])

    def test_changed_preservation_etag_refuses_before_mutation(self) -> None:
        before = absent_discovery()
        plan = deploy_authority.build_plan(
            inputs(), before, [], self.package, provider_what_if(before), now=self.now
        )
        changed = copy.deepcopy(before)
        changed["preserved"]["rootZone"]["etag"] = "raced"
        runner = mock.Mock()
        with mock.patch.object(
            deploy_authority, "compile_package", return_value=self.package
        ), mock.patch.object(
            deploy_authority.contract, "discover", return_value=changed
        ), mock.patch.object(
            deploy_authority, "_deployment_history", return_value=[]
        ), mock.patch.object(
            deploy_authority, "_what_if", return_value=provider_what_if(changed)
        ):
            with self.assertRaisesRegex(deploy_authority.RootDirectDnsDeployError, "changed"):
                deploy_authority.apply_plan(plan, runner=runner)
        runner.assert_not_called()


class RootDirectDnsWorkflowTests(unittest.TestCase):
    def test_reconciliation_actions_only_stale_txt(self) -> None:
        value = discovery(with_challenges=True)
        actions = reconcile._actions(value)
        self.assertEqual(len(actions), 3)
        self.assertEqual({item["kind"] for item in actions}, {"DELETE_STALE_ACME_CHALLENGE_TXT"})
        self.assertEqual({item["zone"] for item in actions}, set(contract.CHILD_ZONES))

    def test_teardown_action_order_is_fail_closed(self) -> None:
        actions = teardown._actions(discovery(with_challenges=True), inputs())
        kinds = [item["kind"] for item in actions]
        self.assertEqual(kinds[:3], ["DELETE_ACME_CHALLENGE_TXT"] * 3)
        self.assertEqual(kinds[3:6], ["DELETE_ROOT_RECORD_SET"] * 3)
        self.assertEqual([actions[index]["recordType"] for index in range(3, 6)], ["CNAME"] * 3)
        self.assertEqual(kinds[-1], "DELETE_DIRECT_ACME_CUSTOM_ROLE")
        self.assertEqual(kinds.count("DELETE_ROOT_RECORD_SET"), 9)
        self.assertEqual(kinds.count("DELETE_DIRECT_ACME_CHILD_ZONE"), 3)

    def test_teardown_accepts_exact_partial_create_states(self) -> None:
        value = discovery()
        value["authority"]["childZones"][0]["assignment"] = None
        value["observed"]["childZones"][0]["roleAssignmentPresent"] = False
        actions = teardown._actions(value, inputs())
        self.assertEqual(
            sum(item["kind"] == "DELETE_DIRECT_ACME_ROLE_ASSIGNMENT" for item in actions),
            2,
        )
        value = discovery()
        value["authority"]["customRoleDefinition"] = None
        actions = teardown._actions(value, inputs())
        self.assertNotIn("DELETE_DIRECT_ACME_CUSTOM_ROLE", [item["kind"] for item in actions])
        value = discovery(with_challenges=True)
        value["authority"]["parentRecords"] = value["authority"]["parentRecords"][1:]
        actions = teardown._actions(value, inputs())
        self.assertEqual(actions[0]["kind"], "DELETE_ACME_CHALLENGE_TXT")

    def test_teardown_apply_requires_exact_fresh_digest_and_suffix(self) -> None:
        first = discovery()
        actions = teardown._actions(first, inputs())[:2]
        base = {
            "actions": actions,
            "authority": first["authority"],
            "observed": first["observed"],
            "preserved": first["preserved"],
            "scope": first["scope"],
            "status": "ROOT_DIRECT_DNS_ACME_TEARDOWN_PLAN_READY",
        }
        base["planSha256"] = "b" * 64
        suffix = copy.deepcopy(base)
        suffix["actions"] = actions[1:]
        suffix["preserved"]["rootZone"]["etag"] = "root-2"
        final = copy.deepcopy(base)
        final["actions"] = []
        final["status"] = "ROOT_DIRECT_DNS_ACME_AUTHORITY_ABSENT"
        final["preserved"]["rootZone"]["etag"] = "root-3"
        with mock.patch.object(
            teardown, "plan", side_effect=[base, base, suffix, final]
        ), mock.patch.object(teardown, "_apply_action") as mutate:
            result = teardown.apply(
                inputs(),
                approved_plan_sha256="b" * 64,
                confirmation=teardown.CONFIRMATION,
            )
        self.assertEqual(mutate.call_count, 2)
        self.assertEqual(result["appliedActions"], 2)

    def test_teardown_apply_rejects_wrong_confirmation_without_mutation(self) -> None:
        with self.assertRaisesRegex(contract.RootDirectDnsError, "confirmation"):
            teardown.apply(
                inputs(), approved_plan_sha256="b" * 64, confirmation="WRONG"
            )

    def test_scripts_never_name_shared_objects_as_deletion_actions(self) -> None:
        source = (ROOT / "teardown_root_direct_dns_acme.py").read_text()
        self.assertNotIn("group delete", source)
        self.assertNotIn("zone delete", source)
        self.assertNotIn("DELETE_ROOT_ZONE", source)
        self.assertNotIn("DELETE_VOICE", source)
        self.assertIn("approved_plan_sha256", source)
        self.assertIn("boundary[\"actions\"] != approved[\"actions\"][index:]", source)

    def test_contract_inventories_global_direct_and_inherited_rbac(self) -> None:
        source = (ROOT / "root_direct_dns_acme_contract.py").read_text()
        self.assertIn("--assignee-object-id", source)
        self.assertIn("--include-inherited", source)
        self.assertIn("--include-groups", source)
        self.assertIn("direct child-zone RBAC inventory drifted", source)
        self.assertIn("managed identity has broader RBAC", source)
        self.assertIn("_owned_assignment_inventory(assignments_raw, inputs)", source)
        self.assertIn("scope_lower.startswith(owned + \"/\")", source)


if __name__ == "__main__":
    unittest.main()
