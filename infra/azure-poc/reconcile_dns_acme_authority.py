#!/usr/bin/env python3
"""Plan or apply the exact live ACME DNS-authority reconciliation.

The updated Bicep contract creates a TXT-only custom role and one assignment
per node, but an incremental deployment does not remove the previous zone
locks, broad Reader/DNS Zone Contributor assignments, or stale Lego TXT record
sets.  Planning is read-only.  Applying requires the digest of a freshly
revalidated plan plus the exact confirmation phrase, and can remove only those
validated legacy objects.  It never creates, updates, or deletes a DNS zone,
parent-zone record, resource group, VM, or custom role.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

import teardown_dns_acme as contract


EXPECTED_SUBSCRIPTION_ID = contract.EXPECTED_SUBSCRIPTION_ID
EXPECTED_TENANT_ID = contract.EXPECTED_TENANT_ID
POC_RESOURCE_GROUP = contract.POC_RESOURCE_GROUP
DNS_RESOURCE_GROUP = contract.DNS_RESOURCE_GROUP
PARENT_ZONE = contract.PARENT_ZONE
CHILD_ZONES = contract.CHILD_ZONES
EDGE_VMS = {
    CHILD_ZONES[0]: "viv-sbc-poc-sbc1",
    CHILD_ZONES[1]: "viv-sbc-poc-sbc2",
}
ZONE_TAGS = contract.ZONE_TAGS
EDGE_ACME_TXT_ROLE_ID = contract.EDGE_ACME_TXT_ROLE_ID
EDGE_ACME_TXT_ROLE_NAME = contract.EDGE_ACME_TXT_ROLE_NAME
EDGE_ACME_TXT_ROLE_DESCRIPTION = contract.EDGE_ACME_TXT_ROLE_DESCRIPTION
EDGE_ACME_TXT_ROLE_ACTIONS = contract.EDGE_ACME_TXT_ROLE_ACTIONS

LEGACY_READER_ROLE_ID = contract.LEGACY_READER_ROLE_ID
LEGACY_DNS_ZONE_CONTRIBUTOR_ROLE_ID = contract.LEGACY_DNS_ZONE_CONTRIBUTOR_ROLE_ID
LEGACY_LOCK_NAME = "prevent-edge-acme-zone-deletion"
LEGACY_LOCK_LEVEL = "CanNotDelete"
LEGACY_LOCK_NOTES = {
    CHILD_ZONES[0]: (
        "Preserve the durable SBC1 ACME RBAC boundary while allowing TXT record updates."
    ),
    CHILD_ZONES[1]: (
        "Preserve the durable SBC2 ACME RBAC boundary while allowing TXT record updates."
    ),
}
CONFIRMATION = "RECONCILE-VIVOLUTION-SBC-POC-ACME-AUTHORITY"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class AuthorityReconciliationError(RuntimeError):
    """Raised when authority discovery, validation, or reconciliation rejects."""


Runner = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class ExpectedInputs:
    subscription_id: str
    tenant_id: str
    sbc1_principal_id: str
    sbc2_principal_id: str


def _run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise AuthorityReconciliationError(f"Azure CLI command failed: {detail}")
    return result.stdout


def _json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthorityReconciliationError(
            f"Azure CLI returned malformed {label} JSON"
        ) from exc


def _contract_call(
    callback: Callable[..., Any], *args: Any, **kwargs: Any
) -> Any:
    try:
        return callback(*args, **kwargs)
    except contract.DnsTeardownError as exc:
        raise AuthorityReconciliationError(str(exc)) from exc


def _validate_inputs(inputs: ExpectedInputs) -> None:
    subscription_id = _contract_call(
        contract._canonical_uuid, inputs.subscription_id, "expected subscription ID"
    )
    tenant_id = _contract_call(
        contract._canonical_uuid, inputs.tenant_id, "expected tenant ID"
    )
    if subscription_id != EXPECTED_SUBSCRIPTION_ID:
        raise AuthorityReconciliationError(
            "subscription ID is outside this reviewed POC reconciliation contract"
        )
    if tenant_id != EXPECTED_TENANT_ID:
        raise AuthorityReconciliationError(
            "tenant ID is outside this reviewed POC reconciliation contract"
        )
    principals = (
        _contract_call(
            contract._canonical_uuid, inputs.sbc1_principal_id, "SBC1 principal ID"
        ),
        _contract_call(
            contract._canonical_uuid, inputs.sbc2_principal_id, "SBC2 principal ID"
        ),
    )
    if principals[0] == principals[1]:
        raise AuthorityReconciliationError(
            "SBC1 and SBC2 principal IDs must be distinct"
        )


def _base_command(subscription_id: str, *parts: str) -> list[str]:
    return contract._base_command(subscription_id, *parts)


def _validate_custom_role(records: Any, subscription_id: str) -> dict[str, str]:
    role = _contract_call(contract._validate_role_definition, records, subscription_id)
    if role is None:
        raise AuthorityReconciliationError(
            "the exact ACME TXT custom role must exist before legacy authority is removed"
        )
    return role


def _validate_assignments(
    records: Any,
    *,
    zone: str,
    zone_id: str,
    principal_id: str,
    subscription_id: str,
) -> tuple[dict[str, str], list[dict[str, str]]]:
    found = _contract_call(
        contract._validate_node_principal_assignments,
        records,
        zone=zone,
        zone_id=zone_id,
        principal_id=principal_id,
        subscription_id=subscription_id,
        allow_legacy=True,
        require_custom=True,
    )
    custom = found["CUSTOM_ACME_TXT"]
    legacy = sorted(
        (value for key, value in found.items() if key != "CUSTOM_ACME_TXT"),
        key=lambda value: value["roleKind"],
    )
    return custom, legacy


def _validate_lock(records: Any, zone: str, zone_id: str) -> dict[str, str] | None:
    if not isinstance(records, list) or len(records) > 1:
        raise AuthorityReconciliationError(
            f"child zone {zone} has unexpected management locks"
        )
    if not records:
        return None
    record = records[0]
    expected_id = (
        f"{zone_id}/providers/Microsoft.Authorization/locks/{LEGACY_LOCK_NAME}"
    )
    if (
        not isinstance(record, dict)
        or record.get("name") != LEGACY_LOCK_NAME
        or record.get("level") != LEGACY_LOCK_LEVEL
        or record.get("notes") != LEGACY_LOCK_NOTES[zone]
        or not contract._same_id(record.get("id"), expected_id)
    ):
        raise AuthorityReconciliationError(
            f"management-lock identity drifted for child zone {zone}"
        )
    return {"id": expected_id, "name": LEGACY_LOCK_NAME}


def _validate_child_records(
    records: Any, zone: str, subscription_id: str
) -> dict[str, str] | None:
    if not isinstance(records, list):
        raise AuthorityReconciliationError(
            f"record inventory for {zone} is not a list"
        )
    allowed = {("@", "NS"), ("@", "SOA"), ("_acme-challenge", "TXT")}
    required = {("@", "NS"), ("@", "SOA")}
    found: set[tuple[str, str]] = set()
    challenge: dict[str, str] | None = None
    for record in records:
        if not isinstance(record, dict):
            raise AuthorityReconciliationError(
                f"record inventory for {zone} contains a non-object"
            )
        kind = _contract_call(contract._record_type, record.get("type"))
        name = record.get("name")
        key = (name, kind)
        expected_id = contract._record_id(subscription_id, zone, kind, str(name))
        if (
            key not in allowed
            or key in found
            or not contract._same_id(record.get("id"), expected_id)
        ):
            raise AuthorityReconciliationError(
                f"child zone {zone} contains an unexpected record set"
            )
        found.add(key)
        if key == ("_acme-challenge", "TXT"):
            etag = record.get("etag")
            if not isinstance(etag, str) or not etag:
                raise AuthorityReconciliationError(
                    f"ACME challenge record in {zone} has no concurrency ETag"
                )
            challenge = {"etag": etag, "id": expected_id, "name": str(name)}
    if not required.issubset(found):
        raise AuthorityReconciliationError(
            f"child zone {zone} is missing its Azure NS/SOA records"
        )
    return challenge


def _parent_authority_specs() -> tuple[dict[str, Any], ...]:
    return (
        {
            "name": "_acme-challenge.sbc1",
            "type": "CNAME",
            "ttl": 60,
            "cname": "_acme-challenge.acme-sbc1.voice.vivolution.ae",
        },
        {
            "name": "_acme-challenge.sbc2",
            "type": "CNAME",
            "ttl": 60,
            "cname": "_acme-challenge.acme-sbc2.voice.vivolution.ae",
        },
        {"name": "acme-sbc1", "type": "NS", "ttl": 3600, "child": CHILD_ZONES[0]},
        {"name": "acme-sbc2", "type": "NS", "ttl": 3600, "child": CHILD_ZONES[1]},
    )


def _validate_edge_vm(
    record: Any,
    statuses: Any,
    *,
    subscription_id: str,
    vm_name: str,
    principal_id: str,
) -> dict[str, str]:
    expected_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{POC_RESOURCE_GROUP}/"
        f"providers/Microsoft.Compute/virtualMachines/{vm_name}"
    )
    if (
        not isinstance(record, dict)
        or record.get("name") != vm_name
        or not contract._same_id(record.get("id"), expected_id)
        or record.get("identityType") != "SystemAssigned"
        or record.get("principalId") != principal_id
        or record.get("provisioningState") != "Succeeded"
    ):
        raise AuthorityReconciliationError(
            f"Edge VM identity or managed principal drifted for {vm_name}"
        )
    if not isinstance(statuses, list) or any(
        not isinstance(value, str) for value in statuses
    ):
        raise AuthorityReconciliationError(
            f"Edge VM instance state is malformed for {vm_name}"
        )
    power_states = [value for value in statuses if value.startswith("PowerState/")]
    if "ProvisioningState/succeeded" not in statuses or len(power_states) != 1:
        raise AuthorityReconciliationError(
            f"Edge VM instance state is incomplete for {vm_name}"
        )
    return {
        "id": expected_id,
        "name": vm_name,
        "powerState": power_states[0],
        "principalId": principal_id,
    }


def _discover(inputs: ExpectedInputs, runner: Runner) -> dict[str, Any]:
    _validate_inputs(inputs)
    subscription_id = inputs.subscription_id

    account = _json(
        runner(
            [
                "az",
                "account",
                "show",
                "--subscription",
                subscription_id,
                "--query",
                "{id:id,tenantId:tenantId}",
                "--output",
                "json",
                "--only-show-errors",
            ]
        ),
        "account",
    )
    if account != {"id": subscription_id, "tenantId": inputs.tenant_id}:
        raise AuthorityReconciliationError(
            "selected Azure subscription or tenant does not match the reviewed IDs"
        )

    for group_name in (POC_RESOURCE_GROUP, DNS_RESOURCE_GROUP):
        group = _json(
            runner(
                _base_command(
                    subscription_id,
                    "group",
                    "show",
                    "--name",
                    group_name,
                    "--query",
                    "{id:id,name:name,location:location}",
                )
            ),
            f"resource group {group_name}",
        )
        _contract_call(contract._validate_group, group, subscription_id, group_name)

    parent = _json(
        runner(
            _base_command(
                subscription_id,
                "network",
                "dns",
                "zone",
                "show",
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--name",
                PARENT_ZONE,
                "--query",
                "{id:id,name:name,zoneType:zoneType}",
            )
        ),
        "parent DNS zone",
    )
    _contract_call(contract._validate_parent_zone, parent, subscription_id)

    role_records = _json(
        runner(
            _base_command(
                subscription_id,
                "role",
                "definition",
                "list",
                "--name",
                EDGE_ACME_TXT_ROLE_ID,
                "--custom-role-only",
                "true",
                "--query",
                (
                    "[].{assignableScopes:assignableScopes,description:description,id:id,"
                    "name:name,permissions:permissions,roleName:roleName,roleType:roleType}"
                ),
            )
        ),
        "ACME custom-role definition inventory",
    )
    role = _validate_custom_role(role_records, subscription_id)

    principals = {
        CHILD_ZONES[0]: inputs.sbc1_principal_id,
        CHILD_ZONES[1]: inputs.sbc2_principal_id,
    }
    raw_global_custom_assignments = _json(
        runner(
            _base_command(
                subscription_id,
                "role",
                "assignment",
                "list",
                "--all",
                "--role",
                EDGE_ACME_TXT_ROLE_ID,
                "--fill-principal-name",
                "false",
                "--fill-role-definition-name",
                "false",
                "--query",
                (
                    "[].{id:id,principalId:principalId,principalType:principalType,"
                    "roleDefinitionId:roleDefinitionId,scope:scope}"
                ),
            )
        ),
        "global ACME custom-role assignments",
    )
    global_custom_assignments = _contract_call(
        contract._validate_global_custom_role_assignments,
        raw_global_custom_assignments,
        subscription_id,
        principals,
        require_all=True,
    )
    principal_assignment_inventory: dict[str, dict[str, dict[str, str]]] = {}
    for zone in CHILD_ZONES:
        direct_principal_assignments = _json(
            runner(
                _base_command(
                    subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--all",
                    "--assignee-object-id",
                    principals[zone],
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    (
                        "[].{id:id,principalId:principalId,principalType:principalType,"
                        "roleDefinitionId:roleDefinitionId,scope:scope}"
                    ),
                )
            ),
            f"direct subscription RBAC assignments for Edge principal {zone}",
        )
        inherited_principal_assignments = _json(
            runner(
                _base_command(
                    subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--scope",
                    f"/subscriptions/{subscription_id}",
                    "--assignee-object-id",
                    principals[zone],
                    "--include-inherited",
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    (
                        "[].{id:id,principalId:principalId,principalType:principalType,"
                        "roleDefinitionId:roleDefinitionId,scope:scope}"
                    ),
                )
            ),
            f"inherited RBAC assignments for Edge principal {zone}",
        )
        complete_principal_assignments = _contract_call(
            contract._merge_assignment_inventories,
            direct_principal_assignments,
            inherited_principal_assignments,
        )
        principal_assignment_inventory[zone] = _contract_call(
            contract._validate_node_principal_assignments,
            complete_principal_assignments,
            zone=zone,
            zone_id=contract._zone_id(subscription_id, zone),
            principal_id=principals[zone],
            subscription_id=subscription_id,
            allow_legacy=True,
            require_custom=True,
        )

    edge_vms: dict[str, dict[str, str]] = {}
    for zone in CHILD_ZONES:
        vm_name = EDGE_VMS[zone]
        raw_vm = _json(
            runner(
                _base_command(
                    subscription_id,
                    "vm",
                    "show",
                    "--resource-group",
                    POC_RESOURCE_GROUP,
                    "--name",
                    vm_name,
                    "--query",
                    (
                        "{id:id,name:name,identityType:identity.type,"
                        "principalId:identity.principalId,"
                        "provisioningState:provisioningState}"
                    ),
                )
            ),
            f"Edge VM identity {vm_name}",
        )
        raw_statuses = _json(
            runner(
                _base_command(
                    subscription_id,
                    "vm",
                    "get-instance-view",
                    "--resource-group",
                    POC_RESOURCE_GROUP,
                    "--name",
                    vm_name,
                    "--query",
                    "instanceView.statuses[].code",
                )
            ),
            f"Edge VM instance state {vm_name}",
        )
        edge_vms[zone] = _validate_edge_vm(
            raw_vm,
            raw_statuses,
            subscription_id=subscription_id,
            vm_name=vm_name,
            principal_id=principals[zone],
        )

    children: dict[str, dict[str, Any]] = {}
    for zone in CHILD_ZONES:
        matches = _json(
            runner(
                _base_command(
                    subscription_id,
                    "resource",
                    "list",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--name",
                    zone,
                    "--resource-type",
                    "Microsoft.Network/dnsZones",
                    "--query",
                    "[].{id:id,name:name,type:type}",
                )
            ),
            f"resource identity lookup for {zone}",
        )
        if not isinstance(matches, list) or len(matches) != 1:
            raise AuthorityReconciliationError(
                f"exact child DNS zone {zone} must exist once"
            )
        match = matches[0]
        if (
            not isinstance(match, dict)
            or match.get("name") != zone
            or str(match.get("type", "")).lower() != "microsoft.network/dnszones"
            or not contract._same_id(
                match.get("id"), contract._zone_id(subscription_id, zone)
            )
        ):
            raise AuthorityReconciliationError(
                f"resource identity lookup drifted for {zone}"
            )
        raw_child = _json(
            runner(
                _base_command(
                    subscription_id,
                    "network",
                    "dns",
                    "zone",
                    "show",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--name",
                    zone,
                    "--query",
                    (
                        "{etag:etag,id:id,name:name,zoneType:zoneType,tags:tags,"
                        "nameServers:nameServers}"
                    ),
                )
            ),
            f"child DNS zone {zone}",
        )
        child = _contract_call(contract._validate_child_zone, raw_child, subscription_id)
        children[zone] = child

    raw_parent_records = _json(
        runner(
            _base_command(
                subscription_id,
                "network",
                "dns",
                "record-set",
                "list",
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--zone-name",
                PARENT_ZONE,
                "--query",
                (
                    "[].{etag:etag,id:id,name:name,type:type,ttl:TTL,"
                    "cnameRecord:CNAMERecord,nsRecords:NSRecords}"
                ),
            )
        ),
        "parent DNS-record inventory",
    )
    parent_index = _contract_call(contract._index_parent_records, raw_parent_records)
    parent_evidence = []
    for spec in _parent_authority_specs():
        key = (str(spec["name"]), str(spec["type"]))
        record = parent_index.get(key)
        if record is None:
            raise AuthorityReconciliationError(
                f"required parent {key[1]} record {key[0]} is absent"
            )
        parent_evidence.append(
            _contract_call(
                contract._validate_parent_record,
                record,
                spec,
                subscription_id,
                children,
            )
        )

    actions: list[dict[str, str]] = []
    authority_children = []
    observed_children = []
    for zone in CHILD_ZONES:
        child = children[zone]
        zone_id = child["id"]
        child_records = _json(
            runner(
                _base_command(
                    subscription_id,
                    "network",
                    "dns",
                    "record-set",
                    "list",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--zone-name",
                    zone,
                    "--query",
                    "[].{etag:etag,id:id,name:name,type:type}",
                )
            ),
            f"DNS records for {zone}",
        )
        challenge = _validate_child_records(child_records, zone, subscription_id)

        assignments = _json(
            runner(
                _base_command(
                    subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--scope",
                    zone_id,
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    (
                        "[].{id:id,principalId:principalId,principalType:principalType,"
                        "roleDefinitionId:roleDefinitionId,scope:scope}"
                    ),
                )
            ),
            f"RBAC assignments for {zone}",
        )
        custom_assignment, legacy_assignments = _validate_assignments(
            assignments,
            zone=zone,
            zone_id=zone_id,
            principal_id=principals[zone],
            subscription_id=subscription_id,
        )
        direct_assignment_inventory = {
            custom_assignment["roleKind"]: custom_assignment,
            **{
                assignment["roleKind"]: assignment
                for assignment in legacy_assignments
            },
        }
        principal_wide = principal_assignment_inventory[zone]
        if set(direct_assignment_inventory) != set(principal_wide) or any(
            not contract._same_id(
                direct_assignment_inventory[kind]["id"], principal_wide[kind]["id"]
            )
            for kind in direct_assignment_inventory
        ):
            raise AuthorityReconciliationError(
                f"direct child-zone assignments disagree with the complete Edge-principal inventory for {zone}"
            )
        if not contract._same_id(
            custom_assignment["id"], global_custom_assignments[zone]["id"]
        ):
            raise AuthorityReconciliationError(
                f"direct child-zone assignment disagrees with global inventory for {zone}"
            )

        locks = _json(
            runner(
                _base_command(
                    subscription_id,
                    "lock",
                    "list",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--resource-name",
                    zone,
                    "--resource-type",
                    "dnsZones",
                    "--namespace",
                    "Microsoft.Network",
                    "--query",
                    "[].{id:id,name:name,level:level,notes:notes}",
                )
            ),
            f"management locks for {zone}",
        )
        legacy_lock = _validate_lock(locks, zone, zone_id)

        if legacy_lock is not None:
            actions.append(
                {
                    "id": legacy_lock["id"],
                    "kind": "DELETE_LEGACY_ZONE_LOCK",
                    "zone": zone,
                }
            )
        legacy_by_kind = {
            assignment["roleKind"]: assignment
            for assignment in legacy_assignments
        }
        for role_kind in (
            "LEGACY_DNS_ZONE_CONTRIBUTOR",
            "LEGACY_READER",
        ):
            legacy = legacy_by_kind.get(role_kind)
            if legacy is None:
                continue
            actions.append(
                {
                    "id": legacy["id"],
                    "kind": "DELETE_LEGACY_ROLE_ASSIGNMENT",
                    "roleKind": legacy["roleKind"],
                    "zone": zone,
                }
            )
        if challenge is not None:
            actions.append(
                {
                    "etag": challenge["etag"],
                    "id": challenge["id"],
                    "kind": "DELETE_STALE_ACME_CHALLENGE_TXT",
                    "name": challenge["name"],
                    "zone": zone,
                }
            )

        authority_children.append(
            {
                "customAssignmentId": custom_assignment["id"],
                "id": zone_id,
                "name": zone,
                "nameServers": sorted(child["nameServers"]),
                "principalId": principals[zone],
                "tags": ZONE_TAGS,
            }
        )
        observed_children.append(
            {
                "challengeRecordStatus": (
                    "PRESENT_STALE" if challenge is not None else "ABSENT"
                ),
                "legacyLockCount": 1 if legacy_lock is not None else 0,
                "legacyRoleAssignments": [
                    value["roleKind"] for value in legacy_assignments
                ],
                "name": zone,
                "roleAssignmentCount": 1 + len(legacy_assignments),
            }
        )

    if actions and any(
        record["powerState"] != "PowerState/deallocated"
        for record in edge_vms.values()
    ):
        raise AuthorityReconciliationError(
            "both Edge VMs must be Azure-deallocated while legacy ACME authority remains"
        )

    authority = {
        "childZones": authority_children,
        "customRoleDefinition": {
            "actions": sorted(EDGE_ACME_TXT_ROLE_ACTIONS),
            "description": EDGE_ACME_TXT_ROLE_DESCRIPTION,
            "id": role["id"],
            "name": role["name"],
            "roleName": EDGE_ACME_TXT_ROLE_NAME,
        },
        "edgeVirtualMachines": [
            {
                "id": edge_vms[zone]["id"],
                "name": edge_vms[zone]["name"],
                "principalId": edge_vms[zone]["principalId"],
            }
            for zone in CHILD_ZONES
        ],
        "parentAuthorityRecords": parent_evidence,
    }
    scope = {
        "childZones": list(CHILD_ZONES),
        "dnsResourceGroup": DNS_RESOURCE_GROUP,
        "parentZone": PARENT_ZONE,
        "pocResourceGroup": POC_RESOURCE_GROUP,
        "subscriptionId": subscription_id,
        "tenantId": inputs.tenant_id,
    }
    return {
        "actions": actions,
        "authority": authority,
        "observed": {
            "childZones": observed_children,
            "edgeVirtualMachines": [edge_vms[zone] for zone in CHILD_ZONES],
        },
        "scope": scope,
    }


def _with_digest(discovery: Mapping[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(discovery, sort_keys=True, separators=(",", ":")).encode()
    result = dict(discovery)
    result["planSha256"] = hashlib.sha256(canonical).hexdigest()
    result["status"] = (
        "POC_DNS_ACME_AUTHORITY_RECONCILIATION_PLAN_READY"
        if discovery["actions"]
        else "POC_DNS_ACME_AUTHORITY_RECONCILED"
    )
    return result


def plan_reconciliation(
    inputs: ExpectedInputs, *, runner: Runner = _run
) -> dict[str, Any]:
    """Return a read-only exact reconciliation or qualified-final-state plan."""
    return _with_digest(_discover(inputs, runner))


def _apply_action(
    action: Mapping[str, str], subscription_id: str, runner: Runner
) -> None:
    kind = action.get("kind")
    if kind == "DELETE_LEGACY_ZONE_LOCK":
        if action.get("id", "").rsplit("/", 1)[-1] != LEGACY_LOCK_NAME:
            raise AuthorityReconciliationError(
                "plan contains an unexpected management-lock identity"
            )
        runner(
            [
                "az",
                "lock",
                "delete",
                "--subscription",
                subscription_id,
                "--ids",
                action["id"],
                "--only-show-errors",
            ]
        )
    elif kind == "DELETE_STALE_ACME_CHALLENGE_TXT":
        if action.get("zone") not in CHILD_ZONES or action.get("name") != "_acme-challenge":
            raise AuthorityReconciliationError(
                "plan contains an unexpected ACME challenge record"
            )
        runner(
            [
                "az",
                "network",
                "dns",
                "record-set",
                "txt",
                "delete",
                "--subscription",
                subscription_id,
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--zone-name",
                action["zone"],
                "--name",
                "_acme-challenge",
                "--if-match",
                action["etag"],
                "--yes",
                "--only-show-errors",
            ]
        )
    elif kind == "DELETE_LEGACY_ROLE_ASSIGNMENT":
        if action.get("roleKind") not in {
            "LEGACY_READER",
            "LEGACY_DNS_ZONE_CONTRIBUTOR",
        }:
            raise AuthorityReconciliationError(
                "plan contains an unexpected legacy role kind"
            )
        runner(
            [
                "az",
                "role",
                "assignment",
                "delete",
                "--subscription",
                subscription_id,
                "--ids",
                action["id"],
                "--only-show-errors",
            ]
        )
    else:  # pragma: no cover - internal plan invariant
        raise AuthorityReconciliationError(
            f"plan contains unsupported action {kind!r}"
        )


def apply_reconciliation(
    inputs: ExpectedInputs,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    runner: Runner = _run,
) -> dict[str, Any]:
    """Apply only the exact remaining suffix of a freshly approved plan."""
    if DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise AuthorityReconciliationError(
            "approved plan SHA-256 must be 64 lowercase hexadecimal characters"
        )
    if confirmation != CONFIRMATION:
        raise AuthorityReconciliationError(
            "exact reconciliation confirmation phrase was not supplied"
        )

    plan = plan_reconciliation(inputs, runner=runner)
    if plan["planSha256"] != approved_plan_sha256:
        raise AuthorityReconciliationError(
            "approved plan digest does not match freshly validated Azure state"
        )

    for index, action in enumerate(plan["actions"]):
        boundary = plan_reconciliation(inputs, runner=runner)
        if (
            boundary["scope"] != plan["scope"]
            or boundary["authority"] != plan["authority"]
            or boundary["actions"] != plan["actions"][index:]
        ):
            raise AuthorityReconciliationError(
                "validated authority changed during reconciliation; generate a new plan"
            )
        _apply_action(action, inputs.subscription_id, runner)

    postcondition = plan_reconciliation(inputs, runner=runner)
    if (
        postcondition["status"] != "POC_DNS_ACME_AUTHORITY_RECONCILED"
        or postcondition["actions"]
        or postcondition["authority"] != plan["authority"]
    ):
        raise AuthorityReconciliationError(
            "reconciliation postcondition failed: legacy ACME authority remains"
        )
    return {
        "appliedActions": len(plan["actions"]),
        "appliedPlanSha256": approved_plan_sha256,
        "postconditionPlanSha256": postcondition["planSha256"],
        "scope": plan["scope"],
        "status": "POC_DNS_ACME_AUTHORITY_RECONCILIATION_APPLIED",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-sbc1-principal-id", required=True)
    parser.add_argument("--expected-sbc2-principal-id", required=True)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--confirmation")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    inputs = ExpectedInputs(
        subscription_id=args.expected_subscription_id,
        tenant_id=args.expected_tenant_id,
        sbc1_principal_id=args.expected_sbc1_principal_id,
        sbc2_principal_id=args.expected_sbc2_principal_id,
    )
    try:
        if args.mode == "plan":
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise AuthorityReconciliationError(
                    "plan mode refuses apply-only approval arguments"
                )
            evidence = plan_reconciliation(inputs)
        else:
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise AuthorityReconciliationError(
                    "apply mode requires a plan digest and confirmation phrase"
                )
            evidence = apply_reconciliation(
                inputs,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
    except AuthorityReconciliationError as exc:
        print(f"POC_DNS_ACME_AUTHORITY_RECONCILIATION_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
