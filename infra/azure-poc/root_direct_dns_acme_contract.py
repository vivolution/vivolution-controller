#!/usr/bin/env python3
"""Exact Azure contract for the additive root Direct Routing DNS authority.

This module is intentionally separate from the synthetic
``voice.vivolution.ae`` DNS/ACME authority.  It supplies read-only discovery
and narrow mutation primitives to the reconciliation and teardown CLIs; it is
not itself an operator entry point.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


EXPECTED_SUBSCRIPTION_ID = "a806949c-240f-4541-8c61-fd97f6d1f953"
EXPECTED_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
POC_RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
POC_LOCATION = "uaenorth"
DNS_RESOURCE_GROUP = "DNS_Zones"
ROOT_ZONE = "vivolution.ae"
PRESERVED_ZONES = (
    "voice.vivolution.ae",
    "acme-sbc1.voice.vivolution.ae",
    "acme-sbc2.voice.vivolution.ae",
)
ENDPOINTS = ("sbc1", "sbc2", "carrier")
CHILD_ZONES = tuple(f"acme-{endpoint}.{ROOT_ZONE}" for endpoint in ENDPOINTS)
VM_NAMES = {
    "sbc1": "viv-sbc-dr-sbc1-g3",
    "sbc2": "viv-sbc-dr-sbc2-g3",
    "carrier": "viv-sbc-poc-cp1",
}
NIC_NAMES = {endpoint: f"{name}-nic" for endpoint, name in VM_NAMES.items()}
PIP_NAMES = {endpoint: f"{name}-pip" for endpoint, name in VM_NAMES.items()}
PRIVATE_IPV4 = {
    "sbc1": "10.20.2.6",
    "sbc2": "10.20.2.7",
    "carrier": "10.20.1.4",
}
ZONE_TAGS = {
    "environment": "poc",
    "managedBy": "bicep",
    "profile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
    "purpose": "direct-routing-private-pbx-poc-acme-dns01",
    "workload": "vivolution-sbc",
}
ROLE_GUID = "c5498bfb-a31f-40dd-b636-0f53e530ed53"
ROLE_NAME = "Vivolution Direct POC ACME TXT Record Operator"
ROLE_DESCRIPTION = (
    "Discover one assigned direct-routing public DNS child zone and manage only "
    "its TXT record sets for ACME DNS-01."
)
ROLE_ACTIONS = {
    "Microsoft.Network/dnszones/read",
    "Microsoft.Network/dnszones/TXT/read",
    "Microsoft.Network/dnszones/TXT/write",
    "Microsoft.Network/dnszones/TXT/delete",
    "Microsoft.ResourceGraph/resources/read",
}
PARENT_RECORD_KEYS = {
    (endpoint, "A") for endpoint in ENDPOINTS
} | {
    (f"_acme-challenge.{endpoint}", "CNAME") for endpoint in ENDPOINTS
} | {
    (f"acme-{endpoint}", "NS") for endpoint in ENDPOINTS
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class RootDirectDnsError(RuntimeError):
    """Fail-closed contract rejection."""


Runner = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class ExpectedInputs:
    subscription_id: str
    tenant_id: str
    carrier_public_ipv4: str
    sbc1_public_ipv4: str
    sbc2_public_ipv4: str
    cp1_principal_id: str
    sbc1_principal_id: str
    sbc2_principal_id: str

    @property
    def addresses(self) -> dict[str, str]:
        return {
            "sbc1": self.sbc1_public_ipv4,
            "sbc2": self.sbc2_public_ipv4,
            "carrier": self.carrier_public_ipv4,
        }

    @property
    def principals(self) -> dict[str, str]:
        return {
            "sbc1": self.sbc1_principal_id,
            "sbc2": self.sbc2_principal_id,
            "carrier": self.cp1_principal_id,
        }


def run(argv: Sequence[str]) -> str:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Azure CLI error"
        raise RootDirectDnsError(f"Azure CLI command failed: {detail}")
    return completed.stdout


def parse_json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RootDirectDnsError(f"Azure CLI returned malformed {label} JSON") from exc


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def canonical_uuid(value: str, label: str) -> str:
    if UUID_RE.fullmatch(value) is None:
        raise RootDirectDnsError(f"{label} must be a canonical lowercase UUID")
    return value


def public_ipv4(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RootDirectDnsError(f"{label} must be one public IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise RootDirectDnsError(f"{label} must be one globally routable IPv4 address")
    return str(address)


def validate_inputs(inputs: ExpectedInputs) -> None:
    if canonical_uuid(inputs.subscription_id, "expected subscription ID") != EXPECTED_SUBSCRIPTION_ID:
        raise RootDirectDnsError("subscription is outside the reviewed root DNS contract")
    if canonical_uuid(inputs.tenant_id, "expected tenant ID") != EXPECTED_TENANT_ID:
        raise RootDirectDnsError("tenant is outside the reviewed root DNS contract")
    addresses = [
        public_ipv4(value, f"{endpoint} public IPv4")
        for endpoint, value in inputs.addresses.items()
    ]
    if len(set(addresses)) != 3:
        raise RootDirectDnsError("carrier, SBC1, and SBC2 public IPv4 addresses must be distinct")
    principals = [
        canonical_uuid(value, f"{endpoint} principal ID")
        for endpoint, value in inputs.principals.items()
    ]
    if len(set(principals)) != 3:
        raise RootDirectDnsError("CP1, SBC1, and SBC2 managed identities must be distinct")


def resource_group_id(subscription_id: str, name: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{name}"


def zone_id(subscription_id: str, name: str) -> str:
    return (
        f"{resource_group_id(subscription_id, DNS_RESOURCE_GROUP)}"
        f"/providers/Microsoft.Network/dnsZones/{name}"
    )


def record_id(subscription_id: str, zone: str, kind: str, name: str) -> str:
    return f"{zone_id(subscription_id, zone)}/{kind}/{name}"


def role_definition_id(subscription_id: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ROLE_GUID}"
    )


def same_id(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual.lower() == expected.lower()


def dns_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RootDirectDnsError("DNS target contains an empty name")
    return value.rstrip(".").lower()


def record_kind(record: Mapping[str, Any]) -> str:
    value = record.get("type")
    if not isinstance(value, str) or not value:
        raise RootDirectDnsError("DNS record has no resource type")
    return value.rsplit("/", 1)[-1].upper()


def base_command(subscription_id: str, *parts: str) -> list[str]:
    return [
        "az",
        *parts,
        "--subscription",
        subscription_id,
        "--output",
        "json",
        "--only-show-errors",
    ]


def _show_group(runner: Runner, subscription_id: str, name: str) -> dict[str, Any]:
    raw = parse_json(
        runner(
            base_command(
                subscription_id,
                "group",
                "show",
                "--name",
                name,
                "--query",
                "{id:id,name:name,location:location}",
            )
        ),
        f"resource group {name}",
    )
    expected = resource_group_id(subscription_id, name)
    if (
        not isinstance(raw, dict)
        or raw.get("name") != name
        or not same_id(raw.get("id"), expected)
        or (name == POC_RESOURCE_GROUP and str(raw.get("location", "")).lower() != POC_LOCATION)
    ):
        raise RootDirectDnsError(f"resource-group identity drifted for {name}")
    return raw


def _show_zone(runner: Runner, subscription_id: str, name: str) -> dict[str, Any]:
    raw = parse_json(
        runner(
            base_command(
                subscription_id,
                "network",
                "dns",
                "zone",
                "show",
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--name",
                name,
                "--query",
                "{etag:etag,id:id,name:name,zoneType:zoneType,tags:tags,nameServers:nameServers}",
            )
        ),
        f"DNS zone {name}",
    )
    if (
        not isinstance(raw, dict)
        or raw.get("name") != name
        or not same_id(raw.get("id"), zone_id(subscription_id, name))
        or raw.get("zoneType") != "Public"
        or not isinstance(raw.get("etag"), str)
        or not raw["etag"]
    ):
        raise RootDirectDnsError(f"DNS-zone identity drifted for {name}")
    servers = raw.get("nameServers")
    if not isinstance(servers, list) or len(servers) != 4:
        raise RootDirectDnsError(f"DNS zone {name} must have four authoritative servers")
    canonical_servers = sorted(dns_name(value) for value in servers)
    if len(set(canonical_servers)) != 4:
        raise RootDirectDnsError(f"DNS zone {name} has duplicate authoritative servers")
    result = dict(raw)
    result["nameServers"] = canonical_servers
    return result


def _list_records(runner: Runner, subscription_id: str, zone: str) -> list[dict[str, Any]]:
    raw = parse_json(
        runner(
            base_command(
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
                (
                    "[].{etag:etag,id:id,name:name,type:type,ttl:TTL,ARecords:ARecords,"
                    "CNAMERecord:CNAMERecord,NSRecords:NSRecords}"
                ),
            )
        ),
        f"record inventory for {zone}",
    )
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        raise RootDirectDnsError(f"record inventory for {zone} is not a list of objects")
    return raw


def _record_metadata_digest(
    records: Sequence[Mapping[str, Any]],
    *,
    subscription_id: str | None = None,
    zone: str | None = None,
) -> str:
    if (subscription_id is None) != (zone is None):
        raise RootDirectDnsError("record metadata validation needs both subscription and zone")
    seen: set[tuple[str, str]] = set()
    for record in records:
        kind = record_kind(record)
        name = record.get("name")
        etag = record.get("etag")
        key = (str(name), kind)
        if (
            not isinstance(name, str)
            or not name
            or key in seen
            or not isinstance(etag, str)
            or not etag
            or (
                subscription_id is not None
                and not same_id(record.get("id"), record_id(subscription_id, str(zone), kind, name))
            )
        ):
            raise RootDirectDnsError(f"record metadata drifted in {zone or 'inventory'}")
        seen.add(key)
    metadata = sorted(
        (
            {
                "etag": record.get("etag"),
                "id": record.get("id"),
                "name": record.get("name"),
                "type": record_kind(record),
            }
            for record in records
        ),
        key=lambda item: (str(item["name"]), str(item["type"])),
    )
    return canonical_json_sha256(metadata)


def _validate_child_records(
    records: Sequence[Mapping[str, Any]], subscription_id: str, zone: str
) -> dict[str, str] | None:
    found: set[tuple[str, str]] = set()
    challenge: dict[str, str] | None = None
    for record in records:
        kind = record_kind(record)
        name = record.get("name")
        key = (str(name), kind)
        if key not in {("@", "NS"), ("@", "SOA"), ("_acme-challenge", "TXT")} or key in found:
            raise RootDirectDnsError(f"child zone {zone} contains an unexpected record set")
        expected_id = record_id(subscription_id, zone, kind, str(name))
        etag = record.get("etag")
        if (
            not same_id(record.get("id"), expected_id)
            or not isinstance(etag, str)
            or not etag
        ):
            raise RootDirectDnsError(f"child record identity drifted in {zone}")
        found.add(key)
        if key == ("_acme-challenge", "TXT"):
            challenge = {"etag": etag, "id": expected_id, "name": str(name)}
    if not {("@", "NS"), ("@", "SOA")}.issubset(found):
        raise RootDirectDnsError(f"child zone {zone} lacks Azure NS/SOA authority")
    return challenge


def _expected_parent_specs(inputs: ExpectedInputs) -> tuple[dict[str, Any], ...]:
    specs: list[dict[str, Any]] = []
    for endpoint in ENDPOINTS:
        specs.extend(
            (
                {"name": endpoint, "type": "A", "ttl": 60, "ipv4": inputs.addresses[endpoint]},
                {
                    "name": f"_acme-challenge.{endpoint}",
                    "type": "CNAME",
                    "ttl": 60,
                    "cname": f"_acme-challenge.acme-{endpoint}.{ROOT_ZONE}",
                },
                {
                    "name": f"acme-{endpoint}",
                    "type": "NS",
                    "ttl": 3600,
                    "child": f"acme-{endpoint}.{ROOT_ZONE}",
                },
            )
        )
    return tuple(specs)


def _validate_parent_records(
    records: Sequence[Mapping[str, Any]],
    inputs: ExpectedInputs,
    children: Mapping[str, Mapping[str, Any] | None],
    *,
    require_all: bool,
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    expected_specs = {(spec["name"], spec["type"]): spec for spec in _expected_parent_specs(inputs)}
    reserved_names = {str(spec["name"]) for spec in expected_specs.values()}
    found: dict[tuple[str, str], Mapping[str, Any]] = {}
    unrelated: list[Mapping[str, Any]] = []
    all_keys: set[tuple[str, str]] = set()
    for record in records:
        kind = record_kind(record)
        name = record.get("name")
        if not isinstance(name, str) or not name:
            raise RootDirectDnsError("root DNS inventory contains an unnamed record")
        key = (name, kind)
        etag = record.get("etag")
        expected_id = record_id(inputs.subscription_id, ROOT_ZONE, kind, name)
        if (
            key in all_keys
            or not isinstance(etag, str)
            or not etag
            or not same_id(record.get("id"), expected_id)
        ):
            raise RootDirectDnsError(f"root DNS record metadata drifted for {name}")
        all_keys.add(key)
        if name not in reserved_names:
            unrelated.append(record)
            continue
        if key not in expected_specs or key in found:
            raise RootDirectDnsError(f"reserved root DNS name {name} has an unexpected record type")
        found[key] = record

    evidence: list[dict[str, Any]] = []
    for key, spec in expected_specs.items():
        record = found.get(key)
        if record is None:
            if require_all:
                raise RootDirectDnsError(f"required root {key[1]} record {key[0]} is absent")
            continue
        expected_id = record_id(inputs.subscription_id, ROOT_ZONE, key[1], key[0])
        etag = record.get("etag")
        if (
            not same_id(record.get("id"), expected_id)
            or record.get("ttl") != spec["ttl"]
            or not isinstance(etag, str)
            or not etag
        ):
            raise RootDirectDnsError(f"root {key[1]} record {key[0]} drifted")
        item: dict[str, Any] = {
            "etag": etag,
            "id": expected_id,
            "name": key[0],
            "type": key[1],
        }
        if key[1] == "A":
            addresses = record.get("ARecords")
            if addresses != [{"ipv4Address": spec["ipv4"]}]:
                raise RootDirectDnsError(f"root A record {key[0]} has the wrong address")
            item["ipv4"] = spec["ipv4"]
        elif key[1] == "CNAME":
            target = record.get("CNAMERecord")
            value = target.get("cname") if isinstance(target, dict) else None
            if (
                not isinstance(target, dict)
                or set(target) != {"cname"}
                or dns_name(value) != spec["cname"]
            ):
                raise RootDirectDnsError(f"root CNAME record {key[0]} has the wrong target")
            item["target"] = spec["cname"]
        else:
            child = children.get(str(spec["child"]))
            if child is None:
                raise RootDirectDnsError(
                    f"root delegation {key[0]} remains while its child zone is absent"
                )
            values = record.get("NSRecords")
            if (
                not isinstance(values, list)
                or len(values) != 4
                or any(not isinstance(value, dict) or set(value) != {"nsdname"} for value in values)
            ):
                raise RootDirectDnsError(f"root NS record {key[0]} is malformed")
            servers = sorted(
                dns_name(value.get("nsdname")) for value in values
            )
            if servers != child["nameServers"]:
                raise RootDirectDnsError(f"root NS delegation {key[0]} drifted")
            item["nameServers"] = servers
        evidence.append(item)
    return sorted(evidence, key=lambda item: (item["name"], item["type"])), unrelated


def _validate_role(records: Any, subscription_id: str, *, required: bool) -> dict[str, Any] | None:
    if not isinstance(records, list) or len(records) > 1:
        raise RootDirectDnsError("direct ACME custom-role inventory is ambiguous")
    if not records:
        if required:
            raise RootDirectDnsError("direct ACME TXT custom role is absent")
        return None
    role = records[0]
    expected_id = role_definition_id(subscription_id)
    permissions = role.get("permissions") if isinstance(role, dict) else None
    if not isinstance(permissions, list) or len(permissions) != 1:
        raise RootDirectDnsError("direct ACME custom-role permissions drifted")
    permission = permissions[0]
    if (
        not isinstance(role, dict)
        or role.get("name") != ROLE_GUID
        or not same_id(role.get("id"), expected_id)
        or role.get("roleName") != ROLE_NAME
        or role.get("description") != ROLE_DESCRIPTION
        or role.get("roleType") != "CustomRole"
        or role.get("assignableScopes") != [f"/subscriptions/{subscription_id}"]
        or not isinstance(permission, dict)
        or set(permission.get("actions", [])) != ROLE_ACTIONS
        or permission.get("notActions") != []
        or permission.get("dataActions") != []
        or permission.get("notDataActions") != []
    ):
        raise RootDirectDnsError("direct ACME TXT custom-role contract drifted")
    return {
        "actions": sorted(ROLE_ACTIONS),
        "description": ROLE_DESCRIPTION,
        "id": expected_id,
        "name": ROLE_GUID,
        "roleName": ROLE_NAME,
    }


def _validate_assignments(
    records: Any,
    inputs: ExpectedInputs,
    children: Mapping[str, Mapping[str, Any] | None],
    *,
    role_present: bool,
    require_all: bool,
) -> dict[str, dict[str, str]]:
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise RootDirectDnsError("direct ACME role-assignment inventory is malformed")
    if records and not role_present:
        raise RootDirectDnsError("direct ACME assignments remain without their role")
    expected_role = role_definition_id(inputs.subscription_id)
    expected: dict[tuple[str, str], str] = {}
    for endpoint in ENDPOINTS:
        zone = f"acme-{endpoint}.{ROOT_ZONE}"
        if children.get(zone) is not None:
            expected[(zone_id(inputs.subscription_id, zone).lower(), inputs.principals[endpoint])] = endpoint
    found: dict[str, dict[str, str]] = {}
    for record in records:
        scope = record.get("scope")
        principal = record.get("principalId")
        key = (str(scope).lower(), str(principal))
        endpoint = expected.get(key)
        assignment_id = record.get("id")
        if (
            endpoint is None
            or endpoint in found
            or record.get("principalType") != "ServicePrincipal"
            or not same_id(record.get("roleDefinitionId"), expected_role)
            or not isinstance(assignment_id, str)
            or not assignment_id.lower().startswith(str(scope).lower() + "/providers/microsoft.authorization/roleassignments/")
            or UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1]) is None
        ):
            raise RootDirectDnsError("direct ACME role is assigned outside its exact node zone")
        found[endpoint] = {
            "id": assignment_id,
            "principalId": str(principal),
            "scope": str(scope),
        }
    if require_all and set(found) != set(ENDPOINTS):
        raise RootDirectDnsError("one exact direct ACME assignment per endpoint is required")
    return found


def _owned_assignment_inventory(
    records: Any, inputs: ExpectedInputs
) -> list[dict[str, Any]]:
    """Select every assignment that can affect or escape the owned boundary.

    The subscription-wide unfiltered inventory is intentional.  It includes
    direct Group assignments and record-set descendant scopes that a
    zone-scoped query can omit.  We retain both every use of the dedicated
    custom role (at any scope) and every assignment of any role at an owned
    child-zone or record descendant.  The exact assignment validator then
    permits only one ServicePrincipal assignment at each child-zone apex.
    """
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise RootDirectDnsError("subscription RBAC inventory is malformed")
    expected_role = role_definition_id(inputs.subscription_id)
    owned_scopes = [zone_id(inputs.subscription_id, zone).lower() for zone in CHILD_ZONES]
    selected: dict[str, dict[str, Any]] = {}
    for item in records:
        assignment_id = item.get("id")
        scope = item.get("scope")
        role_id = item.get("roleDefinitionId")
        if not all(isinstance(value, str) and value for value in (assignment_id, scope, role_id)):
            raise RootDirectDnsError("subscription RBAC inventory is malformed")
        scope_lower = scope.rstrip("/").lower()
        affects_owned = any(
            scope_lower == owned or scope_lower.startswith(owned + "/")
            for owned in owned_scopes
        )
        if affects_owned or same_id(role_id, expected_role):
            key = assignment_id.lower()
            if key in selected and selected[key] != item:
                raise RootDirectDnsError("subscription RBAC inventory contains conflicting duplicates")
            selected[key] = dict(item)
    return list(selected.values())


def _validate_vm(
    record: Any,
    statuses: Any,
    inputs: ExpectedInputs,
    endpoint: str,
) -> dict[str, str]:
    vm_name = VM_NAMES[endpoint]
    expected_id = (
        f"{resource_group_id(inputs.subscription_id, POC_RESOURCE_GROUP)}/providers/"
        f"Microsoft.Compute/virtualMachines/{vm_name}"
    )
    expected_nic_id = (
        f"{resource_group_id(inputs.subscription_id, POC_RESOURCE_GROUP)}/providers/"
        f"Microsoft.Network/networkInterfaces/{NIC_NAMES[endpoint]}"
    )
    if (
        not isinstance(record, dict)
        or record.get("name") != vm_name
        or not same_id(record.get("id"), expected_id)
        or record.get("identityType") != "SystemAssigned"
        or record.get("principalId") != inputs.principals[endpoint]
        or record.get("provisioningState") != "Succeeded"
        or record.get("networkInterfaceIds") != [expected_nic_id]
    ):
        raise RootDirectDnsError(f"VM managed identity drifted for {endpoint}")
    if not isinstance(statuses, list) or any(not isinstance(value, str) for value in statuses):
        raise RootDirectDnsError(f"VM status inventory is malformed for {endpoint}")
    power = [value for value in statuses if value.startswith("PowerState/")]
    if "ProvisioningState/succeeded" not in statuses or len(power) != 1:
        raise RootDirectDnsError(f"VM status inventory is incomplete for {endpoint}")
    return {
        "id": expected_id,
        "name": vm_name,
        "powerState": power[0],
        "principalId": inputs.principals[endpoint],
    }


def _validate_vm_network(
    nic: Any,
    pip: Any,
    inputs: ExpectedInputs,
    endpoint: str,
) -> dict[str, str]:
    vm_id = (
        f"{resource_group_id(inputs.subscription_id, POC_RESOURCE_GROUP)}/providers/"
        f"Microsoft.Compute/virtualMachines/{VM_NAMES[endpoint]}"
    )
    nic_id = (
        f"{resource_group_id(inputs.subscription_id, POC_RESOURCE_GROUP)}/providers/"
        f"Microsoft.Network/networkInterfaces/{NIC_NAMES[endpoint]}"
    )
    pip_id = (
        f"{resource_group_id(inputs.subscription_id, POC_RESOURCE_GROUP)}/providers/"
        f"Microsoft.Network/publicIPAddresses/{PIP_NAMES[endpoint]}"
    )
    ipconfig_id = f"{nic_id}/ipConfigurations/ipconfig1"
    expected_ip = inputs.addresses[endpoint]
    if (
        not isinstance(nic, dict)
        or nic.get("name") != NIC_NAMES[endpoint]
        or not same_id(nic.get("id"), nic_id)
        or not same_id(nic.get("virtualMachineId"), vm_id)
        or nic.get("provisioningState") != "Succeeded"
        or nic.get("ipConfigurations")
        != [
            {
                "id": ipconfig_id,
                "name": "ipconfig1",
                "primary": True,
                "privateIpAddress": PRIVATE_IPV4[endpoint],
                "privateIpAllocationMethod": "Static",
                "publicIpAddressId": pip_id,
            }
        ]
    ):
        raise RootDirectDnsError(f"NIC or public-IP attachment drifted for {endpoint}")
    if (
        not isinstance(pip, dict)
        or pip.get("name") != PIP_NAMES[endpoint]
        or not same_id(pip.get("id"), pip_id)
        or pip.get("ipAddress") != expected_ip
        or pip.get("publicIPAllocationMethod") != "Static"
        or pip.get("publicIPAddressVersion") != "IPv4"
        or pip.get("skuName") != "Standard"
        or pip.get("skuTier") != "Regional"
        or pip.get("provisioningState") != "Succeeded"
        or not same_id(pip.get("ipConfigurationId"), ipconfig_id)
    ):
        raise RootDirectDnsError(f"static public IPv4 binding drifted for {endpoint}")
    return {
        "ipAddress": expected_ip,
        "nicId": nic_id,
        "publicIpId": pip_id,
    }


def discover(
    inputs: ExpectedInputs,
    *,
    runner: Runner = run,
    require_complete: bool,
    include_vms: bool,
) -> dict[str, Any]:
    """Discover and validate the complete or exact partial recovery authority."""
    validate_inputs(inputs)
    account = parse_json(
        runner(
            [
                "az",
                "account",
                "show",
                "--subscription",
                inputs.subscription_id,
                "--query",
                "{id:id,tenantId:tenantId}",
                "--output",
                "json",
                "--only-show-errors",
            ]
        ),
        "Azure account",
    )
    if account != {"id": inputs.subscription_id, "tenantId": inputs.tenant_id}:
        raise RootDirectDnsError("selected Azure subscription or tenant drifted")
    _show_group(runner, inputs.subscription_id, POC_RESOURCE_GROUP)
    _show_group(runner, inputs.subscription_id, DNS_RESOURCE_GROUP)

    root = _show_zone(runner, inputs.subscription_id, ROOT_ZONE)
    preserved_zones: list[dict[str, Any]] = []
    for name in PRESERVED_ZONES:
        zone = _show_zone(runner, inputs.subscription_id, name)
        records = _list_records(runner, inputs.subscription_id, name)
        preserved_zones.append(
            {
                "etag": zone["etag"],
                "id": zone["id"],
                "name": name,
                "recordInventorySha256": _record_metadata_digest(
                    records, subscription_id=inputs.subscription_id, zone=name
                ),
            }
        )

    children: dict[str, dict[str, Any] | None] = {}
    child_records: dict[str, list[dict[str, Any]]] = {}
    for zone in CHILD_ZONES:
        try:
            child = _show_zone(runner, inputs.subscription_id, zone)
        except RootDirectDnsError as exc:
            # Create/teardown recovery accepts an Azure not-found sentinel only
            # through the explicit existence query below.
            if require_complete:
                raise
            exists = parse_json(
                runner(
                    base_command(
                        inputs.subscription_id,
                        "resource",
                        "list",
                        "--resource-group",
                        DNS_RESOURCE_GROUP,
                        "--name",
                        zone,
                        "--resource-type",
                        "Microsoft.Network/dnsZones",
                        "--query",
                        "[].{id:id,name:name}",
                    )
                ),
                f"existence lookup for {zone}",
            )
            if exists != []:
                raise exc
            children[zone] = None
            child_records[zone] = []
            continue
        if child.get("tags") != ZONE_TAGS:
            raise RootDirectDnsError(f"ownership tags drifted for child zone {zone}")
        locks = parse_json(
            runner(
                base_command(
                    inputs.subscription_id,
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
                    "[].{id:id,name:name,level:level}",
                )
            ),
            f"locks for {zone}",
        )
        if locks != []:
            raise RootDirectDnsError(f"child zone {zone} must have no management lock")
        records = _list_records(runner, inputs.subscription_id, zone)
        _validate_child_records(records, inputs.subscription_id, zone)
        children[zone] = child
        child_records[zone] = records

    root_records = _list_records(runner, inputs.subscription_id, ROOT_ZONE)
    parent_records, unrelated_root = _validate_parent_records(
        root_records, inputs, children, require_all=require_complete
    )

    roles = parse_json(
        runner(
            base_command(
                inputs.subscription_id,
                "role",
                "definition",
                "list",
                "--name",
                ROLE_GUID,
                "--custom-role-only",
                "true",
                "--query",
                (
                    "[].{assignableScopes:assignableScopes,description:description,id:id,"
                    "name:name,permissions:permissions,roleName:roleName,roleType:roleType}"
                ),
            )
        ),
        "direct ACME role definition",
    )
    role = _validate_role(roles, inputs.subscription_id, required=require_complete)
    assignments_raw = parse_json(
        runner(
            base_command(
                inputs.subscription_id,
                "role",
                "assignment",
                "list",
                "--all",
                "--fill-principal-name",
                "false",
                "--fill-role-definition-name",
                "false",
                "--query",
                "[].{id:id,principalId:principalId,principalType:principalType,roleDefinitionId:roleDefinitionId,scope:scope}",
            )
        ),
        "subscription-wide direct RBAC assignments",
    )
    assignments = _validate_assignments(
        _owned_assignment_inventory(assignments_raw, inputs),
        inputs,
        children,
        role_present=role is not None,
        require_all=require_complete,
    )
    for endpoint, zone in zip(ENDPOINTS, CHILD_ZONES):
        child = children[zone]
        if child is None:
            continue
        scope_records = parse_json(
            runner(
                base_command(
                    inputs.subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--scope",
                    zone_id(inputs.subscription_id, zone),
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    "[].{id:id,principalId:principalId,principalType:principalType,roleDefinitionId:roleDefinitionId,scope:scope}",
                )
            ),
            f"direct RBAC assignments on {zone}",
        )
        scoped = _validate_assignments(
            scope_records,
            inputs,
            children,
            role_present=role is not None,
            require_all=False,
        )
        if set(scoped) != ({endpoint} if endpoint in assignments else set()):
            raise RootDirectDnsError(f"direct child-zone RBAC inventory drifted for {zone}")

        principal_direct = parse_json(
            runner(
                base_command(
                    inputs.subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--all",
                    "--assignee-object-id",
                    inputs.principals[endpoint],
                    "--include-groups",
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    "[].{id:id,principalId:principalId,principalType:principalType,roleDefinitionId:roleDefinitionId,scope:scope}",
                )
            ),
            f"subscription RBAC for {endpoint}",
        )
        principal_inherited = parse_json(
            runner(
                base_command(
                    inputs.subscription_id,
                    "role",
                    "assignment",
                    "list",
                    "--scope",
                    f"/subscriptions/{inputs.subscription_id}",
                    "--assignee-object-id",
                    inputs.principals[endpoint],
                    "--include-inherited",
                    "--include-groups",
                    "--fill-principal-name",
                    "false",
                    "--fill-role-definition-name",
                    "false",
                    "--query",
                    "[].{id:id,principalId:principalId,principalType:principalType,roleDefinitionId:roleDefinitionId,scope:scope}",
                )
            ),
            f"inherited RBAC for {endpoint}",
        )
        if not isinstance(principal_direct, list) or not isinstance(principal_inherited, list):
            raise RootDirectDnsError(f"principal RBAC inventory is malformed for {endpoint}")
        merged_by_id: dict[str, Mapping[str, Any]] = {}
        for item in [*principal_direct, *principal_inherited]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise RootDirectDnsError(f"principal RBAC inventory is malformed for {endpoint}")
            key = item["id"].lower()
            if key in merged_by_id and merged_by_id[key] != item:
                raise RootDirectDnsError(f"principal RBAC inventories disagree for {endpoint}")
            merged_by_id[key] = item
        principal_found = _validate_assignments(
            list(merged_by_id.values()),
            inputs,
            children,
            role_present=role is not None,
            require_all=False,
        )
        if set(principal_found) != ({endpoint} if endpoint in assignments else set()):
            raise RootDirectDnsError(f"managed identity has broader RBAC for {endpoint}")

    vms: list[dict[str, str]] = []
    if include_vms:
        for endpoint in ENDPOINTS:
            vm = parse_json(
                runner(
                    base_command(
                        inputs.subscription_id,
                        "vm",
                        "show",
                        "--resource-group",
                        POC_RESOURCE_GROUP,
                        "--name",
                        VM_NAMES[endpoint],
                        "--query",
                        "{id:id,name:name,identityType:identity.type,principalId:identity.principalId,provisioningState:provisioningState,networkInterfaceIds:networkProfile.networkInterfaces[].id}",
                    )
                ),
                f"VM identity for {endpoint}",
            )
            statuses = parse_json(
                runner(
                    base_command(
                        inputs.subscription_id,
                        "vm",
                        "get-instance-view",
                        "--resource-group",
                        POC_RESOURCE_GROUP,
                        "--name",
                        VM_NAMES[endpoint],
                        "--query",
                        "instanceView.statuses[].code",
                    )
                ),
                f"VM state for {endpoint}",
            )
            validated_vm = _validate_vm(vm, statuses, inputs, endpoint)
            nic = parse_json(
                runner(
                    base_command(
                        inputs.subscription_id,
                        "network",
                        "nic",
                        "show",
                        "--resource-group",
                        POC_RESOURCE_GROUP,
                        "--name",
                        NIC_NAMES[endpoint],
                        "--query",
                        "{id:id,name:name,provisioningState:provisioningState,virtualMachineId:virtualMachine.id,ipConfigurations:ipConfigurations[].{id:id,name:name,primary:primary,privateIpAddress:privateIPAddress,privateIpAllocationMethod:privateIPAllocationMethod,publicIpAddressId:publicIPAddress.id}}",
                    )
                ),
                f"NIC binding for {endpoint}",
            )
            pip = parse_json(
                runner(
                    base_command(
                        inputs.subscription_id,
                        "network",
                        "public-ip",
                        "show",
                        "--resource-group",
                        POC_RESOURCE_GROUP,
                        "--name",
                        PIP_NAMES[endpoint],
                        "--query",
                        "{id:id,name:name,ipAddress:ipAddress,publicIPAllocationMethod:publicIPAllocationMethod,publicIPAddressVersion:publicIPAddressVersion,skuName:sku.name,skuTier:sku.tier,provisioningState:provisioningState,ipConfigurationId:ipConfiguration.id}",
                    )
                ),
                f"public IPv4 binding for {endpoint}",
            )
            network = _validate_vm_network(nic, pip, inputs, endpoint)
            vms.append({**validated_vm, **network})

    authority_children: list[dict[str, Any]] = []
    observed_children: list[dict[str, Any]] = []
    for endpoint, zone in zip(ENDPOINTS, CHILD_ZONES):
        child = children[zone]
        challenge = (
            _validate_child_records(child_records[zone], inputs.subscription_id, zone)
            if child is not None
            else None
        )
        if child is not None:
            authority_children.append(
                {
                    "assignment": assignments.get(endpoint),
                    "etag": child["etag"],
                    "id": child["id"],
                    "name": zone,
                    "nameServers": child["nameServers"],
                    "principalId": inputs.principals[endpoint],
                    "tags": ZONE_TAGS,
                }
            )
        observed_children.append(
            {
                "challenge": challenge,
                "exists": child is not None,
                "name": zone,
                "roleAssignmentPresent": endpoint in assignments,
            }
        )

    preserved = {
        "rootUnrelatedRecordInventorySha256": _record_metadata_digest(
            unrelated_root,
            subscription_id=inputs.subscription_id,
            zone=ROOT_ZONE,
        ),
        "rootZone": {
            "etag": root["etag"],
            "id": root["id"],
            "name": ROOT_ZONE,
            "nameServers": root["nameServers"],
            "tags": root.get("tags"),
        },
        "voiceAuthorityZones": preserved_zones,
    }
    scope = {
        "childZones": list(CHILD_ZONES),
        "dnsResourceGroup": DNS_RESOURCE_GROUP,
        "parentZone": ROOT_ZONE,
        "pocResourceGroup": POC_RESOURCE_GROUP,
        "preservedZones": list(PRESERVED_ZONES),
        "profile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
        "subscriptionId": inputs.subscription_id,
        "tenantId": inputs.tenant_id,
    }
    return {
        "authority": {
            "childZones": authority_children,
            "customRoleDefinition": role,
            "parentRecords": parent_records,
            "virtualMachines": vms,
        },
        "observed": {"childZones": observed_children},
        "preserved": preserved,
        "scope": scope,
    }


def delete_txt(action: Mapping[str, str], subscription_id: str, runner: Runner) -> None:
    zone = action.get("zone")
    if zone not in CHILD_ZONES or action.get("name") != "_acme-challenge":
        raise RootDirectDnsError("plan contains an unauthorized TXT deletion")
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
            str(zone),
            "--name",
            "_acme-challenge",
            "--if-match",
            action["etag"],
            "--yes",
            "--only-show-errors",
        ]
    )


def delete_parent_record(action: Mapping[str, str], subscription_id: str, runner: Runner) -> None:
    kind = action.get("recordType")
    name = action.get("name")
    if (name, kind) not in PARENT_RECORD_KEYS or kind not in {"A", "CNAME", "NS"}:
        raise RootDirectDnsError("plan contains an unauthorized root record deletion")
    runner(
        [
            "az",
            "network",
            "dns",
            "record-set",
            str(kind).lower(),
            "delete",
            "--subscription",
            subscription_id,
            "--resource-group",
            DNS_RESOURCE_GROUP,
            "--zone-name",
            ROOT_ZONE,
            "--name",
            str(name),
            "--if-match",
            action["etag"],
            "--yes",
            "--only-show-errors",
        ]
    )


def delete_assignment(
    action: Mapping[str, str], inputs: ExpectedInputs, runner: Runner
) -> None:
    subscription_id = inputs.subscription_id
    assignment_id = action.get("id", "")
    zone = action.get("zone")
    endpoint = ENDPOINTS[CHILD_ZONES.index(str(zone))] if zone in CHILD_ZONES else None
    expected_scope = zone_id(subscription_id, str(zone)) if endpoint is not None else ""
    if (
        endpoint is None
        or action.get("principalId") != inputs.principals[endpoint]
        or not same_id(action.get("scope"), expected_scope)
        or not same_id(action.get("roleDefinitionId"), role_definition_id(subscription_id))
        or not isinstance(assignment_id, str)
        or not assignment_id.lower().startswith(
            expected_scope.lower() + "/providers/microsoft.authorization/roleassignments/"
        )
        or UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1]) is None
    ):
        raise RootDirectDnsError("plan contains an unauthorized role-assignment deletion")
    runner(
        [
            "az",
            "role",
            "assignment",
            "delete",
            "--subscription",
            subscription_id,
            "--ids",
            assignment_id,
            "--only-show-errors",
        ]
    )


def delete_zone(action: Mapping[str, str], subscription_id: str, runner: Runner) -> None:
    zone = action.get("name")
    expected_id = zone_id(subscription_id, str(zone)) if zone in CHILD_ZONES else ""
    if not expected_id or not same_id(action.get("id"), expected_id):
        raise RootDirectDnsError("plan contains an unauthorized child-zone deletion")
    runner(
        [
            "az",
            "rest",
            "--method",
            "delete",
            "--url",
            f"https://management.azure.com{expected_id}?api-version=2018-05-01",
            "--headers",
            f"If-Match={action['etag']}",
            "--subscription",
            subscription_id,
            "--only-show-errors",
        ]
    )


def delete_role(action: Mapping[str, str], subscription_id: str, runner: Runner) -> None:
    expected_id = role_definition_id(subscription_id)
    if not same_id(action.get("id"), expected_id):
        raise RootDirectDnsError("plan contains an unauthorized role-definition deletion")
    runner(
        [
            "az",
            "role",
            "definition",
            "delete",
            "--subscription",
            subscription_id,
            "--name",
            ROLE_GUID,
            "--only-show-errors",
        ]
    )
