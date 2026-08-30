#!/usr/bin/env python3
"""Plan or apply the bounded Vivolution SBC POC public-DNS teardown.

Planning is the default and is read-only. Applying requires the digest emitted
by an immediately preceding plan plus an exact confirmation phrase. The helper
never deletes the shared DNS resource group or parent zone: it can delete only
the exact POC record sets, per-SBC child-zone RBAC, the POC custom role, and
tagged child zones defined below.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


EXPECTED_SUBSCRIPTION_ID = "a806949c-240f-4541-8c61-fd97f6d1f953"
EXPECTED_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
POC_RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
POC_LOCATION = "uaenorth"
DNS_RESOURCE_GROUP = "DNS_Zones"
PARENT_ZONE = "voice.vivolution.ae"
CHILD_ZONES = (
    "acme-sbc1.voice.vivolution.ae",
    "acme-sbc2.voice.vivolution.ae",
)
ZONE_TAGS = {
    "environment": "poc",
    "managedBy": "bicep",
    "purpose": "edge-acme-dns01",
    "workload": "vivolution-sbc",
}
EDGE_ACME_TXT_ROLE_ID = "c502c211-fd81-49aa-8ec3-45854ecd5e23"
EDGE_ACME_TXT_ROLE_NAME = "Vivolution Edge ACME TXT Record Operator"
EDGE_ACME_TXT_ROLE_DESCRIPTION = (
    "Discover one assigned public DNS child zone and manage only its TXT record sets "
    "for ACME DNS-01."
)
EDGE_ACME_TXT_ROLE_ACTIONS = {
    "Microsoft.Network/dnszones/read",
    "Microsoft.Network/dnszones/TXT/delete",
    "Microsoft.Network/dnszones/TXT/read",
    "Microsoft.Network/dnszones/TXT/write",
    "Microsoft.ResourceGraph/resources/read",
}
LEGACY_READER_ROLE_ID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
LEGACY_DNS_ZONE_CONTRIBUTOR_ROLE_ID = "befefa01-2a29-4197-83a8-272ff33ce314"
CONFIRMATION = "DELETE-VIVOLUTION-SBC-POC-ACME-DNS"
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class DnsTeardownError(RuntimeError):
    """Raised when discovery, ownership validation, or teardown fails closed."""


Runner = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class ExpectedInputs:
    subscription_id: str
    tenant_id: str
    cp1_public_ipv4: str
    sbc1_public_ipv4: str
    sbc2_public_ipv4: str
    sbc1_principal_id: str
    sbc2_principal_id: str


def _run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise DnsTeardownError(f"Azure CLI command failed: {detail}")
    return result.stdout


def _json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DnsTeardownError(f"Azure CLI returned malformed {label} JSON") from exc


def _canonical_uuid(value: str, label: str) -> str:
    if UUID_RE.fullmatch(value) is None:
        raise DnsTeardownError(f"{label} must be a canonical lowercase UUID")
    return value


def _public_ipv4(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DnsTeardownError(f"{label} must be one public IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise DnsTeardownError(f"{label} must be one globally routable IPv4 address")
    return str(address)


def _validate_inputs(inputs: ExpectedInputs) -> None:
    _canonical_uuid(inputs.subscription_id, "expected subscription ID")
    _canonical_uuid(inputs.tenant_id, "expected tenant ID")
    if inputs.subscription_id != EXPECTED_SUBSCRIPTION_ID:
        raise DnsTeardownError("subscription ID is outside this reviewed POC teardown contract")
    if inputs.tenant_id != EXPECTED_TENANT_ID:
        raise DnsTeardownError("tenant ID is outside this reviewed POC teardown contract")

    addresses = (
        _public_ipv4(inputs.cp1_public_ipv4, "CP1 public IPv4"),
        _public_ipv4(inputs.sbc1_public_ipv4, "SBC1 public IPv4"),
        _public_ipv4(inputs.sbc2_public_ipv4, "SBC2 public IPv4"),
    )
    if len(set(addresses)) != 3:
        raise DnsTeardownError("the three expected public IPv4 addresses must be distinct")

    principals = (
        _canonical_uuid(inputs.sbc1_principal_id, "SBC1 principal ID"),
        _canonical_uuid(inputs.sbc2_principal_id, "SBC2 principal ID"),
    )
    if principals[0] == principals[1]:
        raise DnsTeardownError("SBC1 and SBC2 principal IDs must be distinct")


def _resource_group_id(subscription_id: str, name: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{name}"


def _zone_id(subscription_id: str, name: str) -> str:
    return (
        f"{_resource_group_id(subscription_id, DNS_RESOURCE_GROUP)}"
        f"/providers/Microsoft.Network/dnsZones/{name}"
    )


def _record_id(subscription_id: str, zone: str, record_type: str, name: str) -> str:
    return f"{_zone_id(subscription_id, zone)}/{record_type}/{name}"


def _same_id(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual.lower() == expected.lower()


def _record_type(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DnsTeardownError("DNS record has no resource type")
    return value.rsplit("/", 1)[-1].upper()


def _dns_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DnsTeardownError("DNS target contains an empty name")
    return value.rstrip(".").lower()


def _role_definition_id(subscription_id: str, role_id: str) -> str:
    return (
        f"/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Authorization/roleDefinitions/{role_id}"
    )


def _base_command(subscription_id: str, *parts: str) -> list[str]:
    return [
        "az",
        *parts,
        "--subscription",
        subscription_id,
        "--output",
        "json",
        "--only-show-errors",
    ]


def _validate_group(record: Any, subscription_id: str, name: str) -> None:
    if not isinstance(record, dict):
        raise DnsTeardownError(f"resource group {name} is not an object")
    if record.get("name") != name or not _same_id(
        record.get("id"), _resource_group_id(subscription_id, name)
    ):
        raise DnsTeardownError(f"resource-group identity drifted for {name}")
    if name == POC_RESOURCE_GROUP and str(record.get("location", "")).lower() != POC_LOCATION:
        raise DnsTeardownError("POC resource-group location drifted")


def _validate_parent_zone(record: Any, subscription_id: str) -> None:
    if not isinstance(record, dict):
        raise DnsTeardownError("parent DNS zone is not an object")
    if (
        record.get("name") != PARENT_ZONE
        or not _same_id(record.get("id"), _zone_id(subscription_id, PARENT_ZONE))
        or record.get("zoneType") != "Public"
    ):
        raise DnsTeardownError("shared parent DNS-zone identity drifted")


def _validate_child_zone(record: Any, subscription_id: str) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("name") not in CHILD_ZONES:
        raise DnsTeardownError("child-zone inventory contains an unexpected object")
    name = str(record["name"])
    if (
        not _same_id(record.get("id"), _zone_id(subscription_id, name))
        or record.get("zoneType") != "Public"
        or record.get("tags") != ZONE_TAGS
        or not isinstance(record.get("etag"), str)
        or not record["etag"]
    ):
        raise DnsTeardownError(f"identity or ownership tags drifted for child zone {name}")
    raw_servers = record.get("nameServers")
    if not isinstance(raw_servers, list) or len(raw_servers) != 4:
        raise DnsTeardownError(f"child zone {name} must have exactly four authoritative servers")
    servers = [_dns_name(value) for value in raw_servers]
    if len(set(servers)) != 4:
        raise DnsTeardownError(f"child zone {name} has duplicate authoritative servers")
    return {
        "etag": record["etag"],
        "id": _zone_id(subscription_id, name),
        "name": name,
        "nameServers": servers,
    }


def _parent_specs(inputs: ExpectedInputs) -> tuple[dict[str, Any], ...]:
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
        {"name": "cp1-poc", "type": "A", "ttl": 60, "ipv4": inputs.cp1_public_ipv4},
        {"name": "sbc1", "type": "A", "ttl": 60, "ipv4": inputs.sbc1_public_ipv4},
        {"name": "*.sbc1", "type": "A", "ttl": 60, "ipv4": inputs.sbc1_public_ipv4},
        {"name": "sbc2", "type": "A", "ttl": 60, "ipv4": inputs.sbc2_public_ipv4},
        {"name": "*.sbc2", "type": "A", "ttl": 60, "ipv4": inputs.sbc2_public_ipv4},
    )


def _index_parent_records(records: Any) -> dict[tuple[str, str], Mapping[str, Any]]:
    if not isinstance(records, list):
        raise DnsTeardownError("parent DNS record inventory is not a list")
    indexed: dict[tuple[str, str], Mapping[str, Any]] = {}
    targets = {(spec["name"], spec["type"]) for spec in _parent_specs_placeholder()}
    for record in records:
        if not isinstance(record, dict):
            raise DnsTeardownError("parent DNS record inventory contains a non-object")
        name = record.get("name")
        kind = _record_type(record.get("type"))
        key = (name, kind)
        if key not in targets:
            continue
        if key in indexed:
            raise DnsTeardownError(f"duplicate parent record inventory entry for {kind} {name}")
        indexed[key] = record
    return indexed


def _parent_specs_placeholder() -> tuple[dict[str, str], ...]:
    """Return only record keys without accepting unvalidated runtime inputs."""
    return (
        {"name": "_acme-challenge.sbc1", "type": "CNAME"},
        {"name": "_acme-challenge.sbc2", "type": "CNAME"},
        {"name": "acme-sbc1", "type": "NS"},
        {"name": "acme-sbc2", "type": "NS"},
        {"name": "cp1-poc", "type": "A"},
        {"name": "sbc1", "type": "A"},
        {"name": "*.sbc1", "type": "A"},
        {"name": "sbc2", "type": "A"},
        {"name": "*.sbc2", "type": "A"},
    )


def _validate_parent_record(
    record: Mapping[str, Any],
    spec: Mapping[str, Any],
    subscription_id: str,
    child_zones: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    name = str(spec["name"])
    kind = str(spec["type"])
    expected_id = _record_id(subscription_id, PARENT_ZONE, kind, name)
    if (
        record.get("name") != name
        or _record_type(record.get("type")) != kind
        or record.get("ttl") != spec["ttl"]
        or not _same_id(record.get("id"), expected_id)
        or not isinstance(record.get("etag"), str)
        or not record["etag"]
    ):
        raise DnsTeardownError(f"identity or TTL drifted for parent {kind} record {name}")

    if kind == "A":
        values = record.get("aRecords")
        if values != [{"ipv4Address": spec["ipv4"]}]:
            raise DnsTeardownError(f"address drifted for parent A record {name}")
    elif kind == "CNAME":
        value = record.get("cnameRecord")
        if not isinstance(value, dict) or _dns_name(value.get("cname")) != spec["cname"]:
            raise DnsTeardownError(f"target drifted for parent CNAME record {name}")
    elif kind == "NS":
        child_name = str(spec["child"])
        if child_name not in child_zones:
            raise DnsTeardownError(
                f"cannot prove ownership of delegation {name} after its child zone disappeared"
            )
        raw_values = record.get("nsRecords")
        if not isinstance(raw_values, list):
            raise DnsTeardownError(f"delegation {name} has malformed NS records")
        values = sorted(
            _dns_name(value.get("nsdname"))
            for value in raw_values
            if isinstance(value, dict)
        )
        expected_servers = sorted(child_zones[child_name]["nameServers"])
        if len(values) != len(raw_values) or values != expected_servers:
            raise DnsTeardownError(f"authoritative servers drifted for delegation {name}")
    else:  # pragma: no cover - internal specification invariant
        raise DnsTeardownError(f"unsupported parent record type {kind}")
    return {"etag": record["etag"], "id": expected_id, "kind": kind, "name": name}


def _validate_child_records(records: Any, zone: str, subscription_id: str) -> None:
    if not isinstance(records, list):
        raise DnsTeardownError(f"record inventory for {zone} is not a list")
    allowed = {("@", "NS"), ("@", "SOA"), ("_acme-challenge", "TXT")}
    required = {("@", "NS"), ("@", "SOA")}
    found: set[tuple[str, str]] = set()
    zone_prefix = f"{_zone_id(subscription_id, zone)}/".lower()
    for record in records:
        if not isinstance(record, dict):
            raise DnsTeardownError(f"record inventory for {zone} contains a non-object")
        key = (record.get("name"), _record_type(record.get("type")))
        if key not in allowed or key in found:
            raise DnsTeardownError(f"child zone {zone} contains an unexpected record set")
        if not isinstance(record.get("id"), str) or not record["id"].lower().startswith(
            zone_prefix
        ):
            raise DnsTeardownError(f"record identity escaped child zone {zone}")
        found.add(key)
    if not required.issubset(found):
        raise DnsTeardownError(f"child zone {zone} is missing its Azure NS/SOA records")


def _validate_role_definition(records: Any, subscription_id: str) -> dict[str, str] | None:
    if not isinstance(records, list) or len(records) > 1:
        raise DnsTeardownError("ACME custom-role definition inventory drifted")
    if not records:
        return None
    record = records[0]
    expected_id = _role_definition_id(subscription_id, EDGE_ACME_TXT_ROLE_ID)
    expected_scope = f"/subscriptions/{subscription_id}"
    if not isinstance(record, dict):
        raise DnsTeardownError("ACME custom-role definition is not an object")
    permissions = record.get("permissions")
    if not isinstance(permissions, list) or len(permissions) != 1:
        raise DnsTeardownError("ACME custom-role permissions drifted")
    permission = permissions[0]
    if not isinstance(permission, dict):
        raise DnsTeardownError("ACME custom-role permission is not an object")
    actions = permission.get("actions")
    if (
        record.get("name") != EDGE_ACME_TXT_ROLE_ID
        or not _same_id(record.get("id"), expected_id)
        or record.get("roleName") != EDGE_ACME_TXT_ROLE_NAME
        or record.get("description") != EDGE_ACME_TXT_ROLE_DESCRIPTION
        or record.get("roleType") != "CustomRole"
        or record.get("assignableScopes") != [expected_scope]
        or not isinstance(actions, list)
        or len(actions) != len(set(actions))
        or set(actions) != EDGE_ACME_TXT_ROLE_ACTIONS
        or permission.get("notActions") != []
        or permission.get("dataActions") != []
        or permission.get("notDataActions") != []
    ):
        raise DnsTeardownError("ACME custom-role definition drifted")
    return {"id": expected_id, "name": EDGE_ACME_TXT_ROLE_ID}


def _validate_assignments(
    assignments: Any,
    zone: str,
    zone_id: str,
    principal_id: str,
    subscription_id: str,
) -> list[dict[str, str]]:
    validated = _validate_node_principal_assignments(
        assignments,
        zone=zone,
        zone_id=zone_id,
        principal_id=principal_id,
        subscription_id=subscription_id,
        allow_legacy=False,
        require_custom=False,
    )
    return sorted(validated.values(), key=lambda value: value["roleDefinitionId"])


def _validate_node_principal_assignments(
    assignments: Any,
    *,
    zone: str,
    zone_id: str,
    principal_id: str,
    subscription_id: str,
    allow_legacy: bool,
    require_custom: bool,
) -> dict[str, dict[str, str]]:
    """Validate every visible assignment for one Edge managed identity."""
    if not isinstance(assignments, list):
        raise DnsTeardownError(f"RBAC inventory for {zone} is not a list")
    expected_roles = {
        _role_definition_id(subscription_id, EDGE_ACME_TXT_ROLE_ID).lower(): (
            "CUSTOM_ACME_TXT"
        )
    }
    if allow_legacy:
        expected_roles.update(
            {
                _role_definition_id(subscription_id, LEGACY_READER_ROLE_ID).lower(): (
                    "LEGACY_READER"
                ),
                _role_definition_id(
                    subscription_id, LEGACY_DNS_ZONE_CONTRIBUTOR_ROLE_ID
                ).lower(): "LEGACY_DNS_ZONE_CONTRIBUTOR",
            }
        )
    validated: dict[str, dict[str, str]] = {}
    assignment_prefix = f"{zone_id}/providers/Microsoft.Authorization/roleAssignments/".lower()
    for record in assignments:
        if not isinstance(record, dict):
            raise DnsTeardownError(f"RBAC inventory for {zone} contains a non-object")
        role_id = str(record.get("roleDefinitionId", "")).lower()
        role_kind = expected_roles.get(role_id)
        assignment_id = record.get("id")
        if (
            record.get("principalId") != principal_id
            or record.get("principalType") != "ServicePrincipal"
            or not _same_id(record.get("scope"), zone_id)
            or role_kind is None
            or role_kind in validated
            or not isinstance(assignment_id, str)
            or not assignment_id.lower().startswith(assignment_prefix)
            or UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1].lower()) is None
        ):
            raise DnsTeardownError(
                f"Edge principal for {zone} has an unexpected Azure RBAC assignment"
            )
        validated[role_kind] = {
            "id": assignment_id,
            "roleDefinitionId": role_id,
            "roleKind": role_kind,
        }
    if require_custom and "CUSTOM_ACME_TXT" not in validated:
        raise DnsTeardownError(
            f"Edge principal for {zone} lacks its exact ACME TXT assignment"
        )
    return validated


def _validate_global_custom_role_assignments(
    assignments: Any,
    subscription_id: str,
    principals: Mapping[str, str],
    *,
    require_all: bool,
) -> dict[str, dict[str, str]]:
    """Prove the custom role is assigned only to each node's own child zone."""
    if not isinstance(assignments, list):
        raise DnsTeardownError("global ACME custom-role assignment inventory is not a list")
    expected_role = _role_definition_id(
        subscription_id, EDGE_ACME_TXT_ROLE_ID
    ).lower()
    expected_scopes = {
        _zone_id(subscription_id, zone).lower(): zone for zone in CHILD_ZONES
    }
    validated: dict[str, dict[str, str]] = {}
    for record in assignments:
        if not isinstance(record, dict):
            raise DnsTeardownError(
                "global ACME custom-role assignment inventory contains a non-object"
            )
        scope = str(record.get("scope", "")).lower()
        zone = expected_scopes.get(scope)
        assignment_id = record.get("id")
        assignment_prefix = ""
        if zone is not None:
            assignment_prefix = (
                f"{_zone_id(subscription_id, zone)}/providers/"
                "Microsoft.Authorization/roleAssignments/"
            ).lower()
        if (
            zone is None
            or zone in validated
            or record.get("principalId") != principals[zone]
            or record.get("principalType") != "ServicePrincipal"
            or str(record.get("roleDefinitionId", "")).lower() != expected_role
            or not isinstance(assignment_id, str)
            or not assignment_id.lower().startswith(assignment_prefix)
            or UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1].lower()) is None
        ):
            raise DnsTeardownError(
                "ACME custom role has an unexpected subscription assignment"
            )
        validated[zone] = {"id": assignment_id, "scope": record["scope"]}
    if require_all and set(validated) != set(CHILD_ZONES):
        raise DnsTeardownError(
            "ACME custom role must have exactly one scoped assignment per node"
        )
    return validated


def _merge_assignment_inventories(*inventories: Any) -> list[dict[str, Any]]:
    """Union overlapping Azure assignment queries without hiding disagreement."""
    merged: dict[str, dict[str, Any]] = {}
    for inventory in inventories:
        if not isinstance(inventory, list):
            raise DnsTeardownError("Edge-principal RBAC inventory is not a list")
        for record in inventory:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise DnsTeardownError(
                    "Edge-principal RBAC inventory contains an invalid assignment"
                )
            identity = record["id"].lower()
            signature = (
                identity,
                record.get("principalId"),
                record.get("principalType"),
                str(record.get("roleDefinitionId", "")).lower(),
                str(record.get("scope", "")).lower(),
            )
            existing = merged.get(identity)
            if existing is not None:
                existing_signature = (
                    str(existing.get("id", "")).lower(),
                    existing.get("principalId"),
                    existing.get("principalType"),
                    str(existing.get("roleDefinitionId", "")).lower(),
                    str(existing.get("scope", "")).lower(),
                )
                if signature != existing_signature:
                    raise DnsTeardownError(
                        "overlapping Edge-principal RBAC inventories disagree"
                    )
                continue
            merged[identity] = record
    return [merged[key] for key in sorted(merged)]


def _validate_no_locks(locks: Any, zone: str) -> None:
    if not isinstance(locks, list):
        raise DnsTeardownError(f"lock inventory for {zone} is not a list")
    if locks:
        raise DnsTeardownError(
            f"child zone {zone} has a management lock that would block ACME cleanup"
        )


def _discover(inputs: ExpectedInputs, runner: Runner) -> dict[str, Any]:
    _validate_inputs(inputs)
    subscription_id = inputs.subscription_id

    account = _json(
        runner(
            [
                "az",
                "account",
                "show",
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
        raise DnsTeardownError(
            "active Azure subscription or tenant does not match the reviewed IDs"
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
        _validate_group(group, subscription_id, group_name)

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
    _validate_parent_zone(parent, subscription_id)

    role_definitions = _json(
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
    role_definition = _validate_role_definition(role_definitions, subscription_id)

    principals = {
        CHILD_ZONES[0]: inputs.sbc1_principal_id,
        CHILD_ZONES[1]: inputs.sbc2_principal_id,
    }
    if role_definition is None:
        global_custom_assignments: dict[str, dict[str, str]] = {}
    else:
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
        global_custom_assignments = _validate_global_custom_role_assignments(
            raw_global_custom_assignments,
            subscription_id,
            principals,
            require_all=False,
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
        complete_principal_assignments = _merge_assignment_inventories(
            direct_principal_assignments, inherited_principal_assignments
        )
        principal_assignment_inventory[zone] = _validate_node_principal_assignments(
            complete_principal_assignments,
            zone=zone,
            zone_id=_zone_id(subscription_id, zone),
            principal_id=principals[zone],
            subscription_id=subscription_id,
            allow_legacy=False,
            require_custom=False,
        )

    child_zones: dict[str, dict[str, Any]] = {}
    for child_name in CHILD_ZONES:
        child_matches = _json(
            runner(
                _base_command(
                    subscription_id,
                    "resource",
                    "list",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--name",
                    child_name,
                    "--resource-type",
                    "Microsoft.Network/dnsZones",
                    "--query",
                    "[].{id:id,name:name,type:type}",
                )
            ),
            f"resource identity lookup for {child_name}",
        )
        if not isinstance(child_matches, list) or len(child_matches) > 1:
            raise DnsTeardownError(f"resource identity lookup drifted for {child_name}")
        if not child_matches:
            continue
        match = child_matches[0]
        if (
            not isinstance(match, dict)
            or match.get("name") != child_name
            or str(match.get("type", "")).lower() != "microsoft.network/dnszones"
            or not _same_id(match.get("id"), _zone_id(subscription_id, child_name))
        ):
            raise DnsTeardownError(f"resource identity lookup drifted for {child_name}")
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
                    child_name,
                    "--query",
                    (
                        "{etag:etag,id:id,name:name,zoneType:zoneType,tags:tags,"
                        "nameServers:nameServers}"
                    ),
                )
            ),
            f"child DNS zone {child_name}",
        )
        child = _validate_child_zone(raw_child, subscription_id)
        child_zones[child["name"]] = child

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
                    "[].{etag:etag,id:id,name:name,type:type,ttl:TTL,aRecords:ARecords,"
                    "cnameRecord:CNAMERecord,nsRecords:NSRecords}"
                ),
            )
        ),
        "parent DNS-record inventory",
    )
    parent_records = _index_parent_records(raw_parent_records)

    actions: list[dict[str, str]] = []
    validated_parent = []
    for spec in _parent_specs(inputs):
        key = (str(spec["name"]), str(spec["type"]))
        record = parent_records.get(key)
        if record is None:
            continue
        validated = _validate_parent_record(record, spec, subscription_id, child_zones)
        validated_parent.append(validated)
        actions.append(
            {
                "id": validated["id"],
                "kind": "DELETE_PARENT_RECORD",
                "name": validated["name"],
                "recordType": validated["kind"],
                "etag": validated["etag"],
            }
        )

    child_evidence = []
    child_actions: list[dict[str, str]] = []
    direct_custom_assignment_ids: dict[str, str] = {}
    direct_assignment_inventory: dict[str, dict[str, dict[str, str]]] = {}
    for zone in CHILD_ZONES:
        child = child_zones.get(zone)
        if child is None:
            continue
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
                    "[].{id:id,name:name,type:type}",
                )
            ),
            f"DNS records for {zone}",
        )
        _validate_child_records(child_records, zone, subscription_id)

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
        validated_assignments = _validate_assignments(
            assignments, zone, zone_id, principals[zone], subscription_id
        )
        direct_assignment_inventory[zone] = {
            assignment["roleKind"]: assignment
            for assignment in validated_assignments
        }
        if validated_assignments:
            direct_custom_assignment_ids[zone] = validated_assignments[0]["id"]

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
        _validate_no_locks(locks, zone)

        # Parent records are already earlier in the plan, so an interrupted
        # run cannot leave live DNS pointing into a child zone whose narrow
        # identity assignment has been removed.
        for assignment in validated_assignments:
            child_actions.append(
                {
                    "id": assignment["id"],
                    "kind": "DELETE_CHILD_ZONE_ROLE_ASSIGNMENT",
                    "zone": zone,
                }
            )
        child_actions.append(
            {
                "etag": child["etag"],
                "id": zone_id,
                "kind": "DELETE_CHILD_ZONE",
                "zone": zone,
            }
        )
        child_evidence.append(
            {
                "id": zone_id,
                "locks": 0,
                "name": zone,
                "roleAssignments": len(validated_assignments),
                "tags": ZONE_TAGS,
            }
        )

    if role_definition is None and child_zones:
        raise DnsTeardownError(
            "ACME custom role disappeared before its child zones were removed"
        )
    if set(global_custom_assignments) != set(direct_custom_assignment_ids) or any(
        not _same_id(
            global_custom_assignments[zone]["id"], direct_custom_assignment_ids[zone]
        )
        for zone in global_custom_assignments
    ):
        raise DnsTeardownError(
            "direct child-zone assignments do not match the global custom-role inventory"
        )
    for zone in CHILD_ZONES:
        direct = direct_assignment_inventory.get(zone, {})
        principal_wide = principal_assignment_inventory[zone]
        if set(direct) != set(principal_wide) or any(
            not _same_id(direct[kind]["id"], principal_wide[kind]["id"])
            for kind in direct
        ):
            raise DnsTeardownError(
                "direct child-zone assignments do not match the complete Edge-principal inventory"
            )

    actions.extend(child_actions)
    if role_definition is not None:
        actions.append(
            {
                "id": role_definition["id"],
                "kind": "DELETE_ACME_ROLE_DEFINITION",
                "name": role_definition["name"],
            }
        )
    scope = {
        "childZones": list(CHILD_ZONES),
        "dnsResourceGroup": DNS_RESOURCE_GROUP,
        "parentZone": PARENT_ZONE,
        "pocResourceGroup": POC_RESOURCE_GROUP,
        "subscriptionId": subscription_id,
        "tenantId": inputs.tenant_id,
        "roleDefinitionId": _role_definition_id(
            subscription_id, EDGE_ACME_TXT_ROLE_ID
        ),
    }
    return {
        "actions": actions,
        "scope": scope,
        "validated": {
            "childZones": child_evidence,
            "parentRecords": validated_parent,
        },
    }


def _with_digest(discovery: Mapping[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(discovery, sort_keys=True, separators=(",", ":")).encode()
    result = dict(discovery)
    result["planSha256"] = hashlib.sha256(canonical).hexdigest()
    result["status"] = (
        "POC_DNS_ACME_TEARDOWN_PLAN_READY"
        if discovery["actions"]
        else "POC_DNS_ACME_ALREADY_ABSENT"
    )
    return result


def plan_teardown(inputs: ExpectedInputs, *, runner: Runner = _run) -> dict[str, Any]:
    """Discover, validate, and return a non-mutating teardown plan."""
    return _with_digest(_discover(inputs, runner))


def _apply_action(action: Mapping[str, str], subscription_id: str, runner: Runner) -> None:
    kind = action.get("kind")
    if kind == "DELETE_PARENT_RECORD":
        record_type = action.get("recordType", "").lower()
        if record_type not in {"a", "cname", "ns"}:
            raise DnsTeardownError("plan contains an unsupported parent record type")
        runner(
            [
                "az",
                "network",
                "dns",
                "record-set",
                record_type,
                "delete",
                "--subscription",
                subscription_id,
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--zone-name",
                PARENT_ZONE,
                "--name",
                action["name"],
                "--if-match",
                action["etag"],
                "--yes",
                "--only-show-errors",
            ]
        )
    elif kind == "DELETE_CHILD_ZONE_ROLE_ASSIGNMENT":
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
    elif kind == "DELETE_CHILD_ZONE":
        runner(
            [
                "az",
                "network",
                "dns",
                "zone",
                "delete",
                "--subscription",
                subscription_id,
                "--ids",
                action["id"],
                "--if-match",
                action["etag"],
                "--yes",
                "--only-show-errors",
            ]
        )
    elif kind == "DELETE_ACME_ROLE_DEFINITION":
        if action.get("name") != EDGE_ACME_TXT_ROLE_ID:
            raise DnsTeardownError("plan contains an unexpected custom-role identity")
        runner(
            [
                "az",
                "role",
                "definition",
                "delete",
                "--subscription",
                subscription_id,
                "--name",
                EDGE_ACME_TXT_ROLE_ID,
                "--only-show-errors",
            ]
        )
    else:  # pragma: no cover - internal plan invariant
        raise DnsTeardownError(f"plan contains unsupported action {kind!r}")


def apply_teardown(
    inputs: ExpectedInputs,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    runner: Runner = _run,
) -> dict[str, Any]:
    """Apply only a freshly revalidated and explicitly approved plan."""
    if DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise DnsTeardownError("approved plan SHA-256 must be 64 lowercase hexadecimal characters")
    if confirmation != CONFIRMATION:
        raise DnsTeardownError("exact destructive confirmation phrase was not supplied")

    plan = plan_teardown(inputs, runner=runner)
    if plan["planSha256"] != approved_plan_sha256:
        raise DnsTeardownError("approved plan digest does not match freshly validated Azure state")

    for index, action in enumerate(plan["actions"]):
        if action["kind"] in {"DELETE_CHILD_ZONE", "DELETE_ACME_ROLE_DEFINITION"}:
            # Zone and role-definition deletion are wider than leaf cleanup.
            # Re-read the complete bounded state after prior removals and
            # require the exact remaining suffix before either wider delete.
            boundary = plan_teardown(inputs, runner=runner)
            if boundary["actions"] != plan["actions"][index:]:
                raise DnsTeardownError(
                    "validated state changed before a wide DNS-authority deletion; generate a new plan"
                )
        _apply_action(action, inputs.subscription_id, runner)

    postcondition = plan_teardown(inputs, runner=runner)
    if postcondition["actions"]:
        raise DnsTeardownError("teardown postcondition failed: POC DNS resources remain")
    return {
        "appliedPlanSha256": approved_plan_sha256,
        "deletedActions": len(plan["actions"]),
        "postconditionPlanSha256": postcondition["planSha256"],
        "scope": plan["scope"],
        "status": "POC_DNS_ACME_TEARDOWN_APPLIED",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-cp1-public-ipv4", required=True)
    parser.add_argument("--expected-sbc1-public-ipv4", required=True)
    parser.add_argument("--expected-sbc2-public-ipv4", required=True)
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
        cp1_public_ipv4=args.expected_cp1_public_ipv4,
        sbc1_public_ipv4=args.expected_sbc1_public_ipv4,
        sbc2_public_ipv4=args.expected_sbc2_public_ipv4,
        sbc1_principal_id=args.expected_sbc1_principal_id,
        sbc2_principal_id=args.expected_sbc2_principal_id,
    )
    try:
        if args.mode == "plan":
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise DnsTeardownError("plan mode refuses apply-only approval arguments")
            evidence = plan_teardown(inputs)
        else:
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise DnsTeardownError("apply mode requires a plan digest and confirmation phrase")
            evidence = apply_teardown(
                inputs,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
    except DnsTeardownError as exc:
        print(f"POC_DNS_ACME_TEARDOWN_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
