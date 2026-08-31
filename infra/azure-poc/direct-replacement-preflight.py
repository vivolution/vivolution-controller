#!/usr/bin/env python3
"""Offline, fail-closed admission guard for Direct Routing replacement IaC."""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Sequence


PARAMETER_SCHEMA = (
    "https://schema.management.azure.com/schemas/2019-04-01/"
    "deploymentParameters.json#"
)
TEMPLATE_SCHEMA = (
    "https://schema.management.azure.com/schemas/2018-05-01/"
    "subscriptionDeploymentTemplate.json#"
)
MICROSOFT_DIRECT_ROUTING_CIDRS = [
    "52.112.0.0/14",
    "52.120.0.0/14",
]
MAX_ADMIN_CIDRS = 4
EXPECTED_SUBSCRIPTION_ID = "a806949c-240f-4541-8c61-fd97f6d1f953"
EXPECTED_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
EXPECTED_RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
EXPECTED_LOCATION = "uaenorth"
EXPECTED_VNET_NAME = "viv-sbc-poc-vnet"
EXPECTED_VNET_PREFIX = "10.20.0.0/16"
EXPECTED_MANAGEMENT_SUBNET_NAME = "snet-management"
EXPECTED_MANAGEMENT_SUBNET_PREFIX = "10.20.1.0/24"
EXPECTED_EDGE_SUBNET_NAME = "snet-edge"
EXPECTED_EDGE_SUBNET_PREFIX = "10.20.2.0/24"
EXPECTED_AVAILABILITY_SET_NAME = "viv-sbc-poc-edge-as"
EXPECTED_PROVIDER_NAMESPACES = ("Microsoft.Compute", "Microsoft.Network")
EXPECTED_BICEP_VERSION = "0.46.1.21595"
EXPECTED_SYNTHETIC_VM_NAMES = ("viv-sbc-poc-sbc1", "viv-sbc-poc-sbc2")
EXPECTED_REPLACEMENT_VM_NAMES = ("viv-sbc-dr-sbc1-g3", "viv-sbc-dr-sbc2-g3")
EXPECTED_NODE_PRIVATE_IPS = {
    "viv-sbc-poc-cp1": "10.20.1.4",
    "viv-sbc-poc-sbc1": "10.20.2.4",
    "viv-sbc-poc-sbc2": "10.20.2.5",
    "viv-sbc-dr-sbc1-g3": "10.20.2.6",
    "viv-sbc-dr-sbc2-g3": "10.20.2.7",
}
EXPECTED_BUDGET_NAME = "viv-sbc-poc-monthly-usd100"
EXPECTED_BUDGET_AMOUNT_USD = Decimal("100")
EXPECTED_BUDGET_THRESHOLDS = {Decimal("75"), Decimal("90"), Decimal("100")}
MAXIMUM_PARALLEL_ACCEPTANCE_HOURS = 72
MAXIMUM_INCREMENTAL_REPLACEMENT_COST_USD = Decimal("7.80")
LIVE_PLAN_MAX_AGE_MINUTES = 15
SCHEDULER_RECEIPT_MAX_AGE_MINUTES = 5
MINIMUM_CREATE_BUFFER_MINUTES = 60
CREATE_AUTHORIZATION_SAFETY_SECONDS = 120
DEPLOYMENT_CANCEL_TIMEOUT_SECONDS = 60
DEPLOYMENT_SETTLE_TIMEOUT_SECONDS = 300
DEPLOYMENT_NAME = "viv-sbc-direct-replacement-g3"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PARAMETER_PATH = (
    PROJECT_ROOT / "infra/azure-poc/direct-replacement.local.bicepparam"
)
EXPECTED_LIVE_PLAN_PATH = (
    PROJECT_ROOT / "deploy/.state/direct-replacement-live-plan.json"
)
EXPECTED_DEADMAN_BUNDLE_PATH = (
    PROJECT_ROOT / "deploy/.state/direct-replacement-deadman-sealed.py"
)
EXPECTED_SCHEDULER_RECEIPT_PATH = (
    PROJECT_ROOT / "deploy/.state/direct-replacement-deadman-scheduler-receipt.json"
)
EXPECTED_DEADMAN_PYTHON = Path("/opt/homebrew/bin/python3.13")
EXPECTED_OPENCLAW_CLI = Path("/opt/homebrew/bin/openclaw")
EXPECTED_AZ_CLI = Path("/opt/homebrew/bin/az")
OPENCLAW_AGENT_ID = "main"
OPENCLAW_COMMAND_TIMEOUT_SECONDS = 900
OPENCLAW_NO_OUTPUT_TIMEOUT_SECONDS = 300
OPENCLAW_OUTPUT_MAX_BYTES = 65536
OPENCLAW_NOTIFICATION_CHANNEL = "telegram"
OPENCLAW_NOTIFICATION_TARGET = "telegram:-1004364314662"
OPENCLAW_NOTIFICATION_ACCOUNT = "default"

# This binds admission to the reviewed ARM JSON emitted by Bicep CLI 0.46.1.
# A source or compiler change must be reviewed and deliberately re-pinned.
EXPECTED_COMPILED_TEMPLATE_SHA256 = (
    "a80c5771331be86d5aa2cd8abea05a127e3cd7982ba9cc89308595e6e819a5b9"
)

FIXED_VALUES: Dict[str, Any] = {
    "targetSubscriptionId": EXPECTED_SUBSCRIPTION_ID,
    "targetResourceGroupName": EXPECTED_RESOURCE_GROUP,
    "location": EXPECTED_LOCATION,
    "existingVirtualNetworkName": EXPECTED_VNET_NAME,
    "existingEdgeSubnetName": EXPECTED_EDGE_SUBNET_NAME,
    "existingAvailabilitySetName": EXPECTED_AVAILABILITY_SET_NAME,
    "edgeRuntimeProfile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
    "edgeGeneration": 3,
    "sbc1NodeName": "viv-sbc-dr-sbc1-g3",
    "sbc2NodeName": "viv-sbc-dr-sbc2-g3",
    "sbc1PrivateIpAddress": "10.20.2.6",
    "sbc2PrivateIpAddress": "10.20.2.7",
    "cp1PrivatePrefix": "10.20.1.4/32",
    "microsoftSignalingSourcePrefixes": MICROSOFT_DIRECT_ROUTING_CIDRS,
    "microsoftMediaSourcePrefixes": MICROSOFT_DIRECT_ROUTING_CIDRS,
    "microsoftMediaIcePortRange": "3478-3481",
    "microsoftMediaHighPortRange": "49152-53247",
    "remoteTlsPort": 5061,
    "localPbxTlsListenerPort": 15061,
    "pbxMediaDestinationPortStart": 30000,
    "pbxMediaDestinationPortEnd": 30127,
    "rtpMediaPortStart": 20000,
    "rtpMediaPortCount": 10000,
    "tenantRtpMediaPortStart": 20000,
    "tenantRtpMediaPortCount": 256,
    "vmSize": "Standard_B2als_v2",
    "osDiskSizeGiB": 32,
    "osDiskSku": "StandardSSD_LRS",
    "enableTrustedLaunch": True,
    "adminUsername": "cpadmin",
    "imagePublisher": "Debian",
    "imageOffer": "debian-13",
    "imageSku": "13-gen2",
    "imageVersion": "0.20260826.2582",
}

DYNAMIC_PARAMETER_NAMES = {
    "administratorSourcePrefixes",
    "parallelAcceptanceDeadlineUtc",
    "sshPublicKey",
}
EXACT_PARAMETER_NAMES = set(FIXED_VALUES) | DYNAMIC_PARAMETER_NAMES


class PreflightError(ValueError):
    """The compiled package is outside the reviewed replacement boundary."""


def _canonical_digest(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _values(document: Mapping[str, Any]) -> Dict[str, Any]:
    if set(document) != {"$schema", "contentVersion", "parameters"}:
        raise PreflightError("compiled parameter document has unexpected top-level fields")
    if document.get("$schema") != PARAMETER_SCHEMA:
        raise PreflightError("compiled parameter document schema is not the reviewed schema")
    if document.get("contentVersion") != "1.0.0.0":
        raise PreflightError("compiled parameter contentVersion must equal 1.0.0.0")
    parameters = document.get("parameters")
    if not isinstance(parameters, dict):
        raise PreflightError("compiled deployment parameters are missing")
    if set(parameters) != EXACT_PARAMETER_NAMES:
        missing = sorted(EXACT_PARAMETER_NAMES - set(parameters))
        extra = sorted(set(parameters) - EXACT_PARAMETER_NAMES)
        raise PreflightError(
            "compiled parameter names are not exact (missing={}, extra={})".format(
                missing, extra
            )
        )

    values: Dict[str, Any] = {}
    for name, wrapped in parameters.items():
        if not isinstance(wrapped, dict) or set(wrapped) != {"value"}:
            raise PreflightError(
                "compiled parameter {!r} is not one explicit value".format(name)
            )
        values[name] = wrapped["value"]
    return values


def _canonical_ipv4_32(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise PreflightError("{} must be one IPv4 /32 string".format(name))
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PreflightError("{} must be one canonical IPv4 /32".format(name)) from exc
    if (
        network.version != 4
        or network.prefixlen != 32
        or str(network) != value
        or not network.network_address.is_global
    ):
        raise PreflightError("{} must be one globally routable canonical IPv4 /32".format(name))
    return str(network)


def _admin_prefixes(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PreflightError("administratorSourcePrefixes must be a nonempty array")
    if len(value) > MAX_ADMIN_CIDRS:
        raise PreflightError("administratorSourcePrefixes exceeds the four-address limit")
    if any(not isinstance(item, str) for item in value):
        raise PreflightError("administratorSourcePrefixes must contain strings only")
    if len(value) != len(set(value)):
        raise PreflightError("administratorSourcePrefixes contains a duplicate")
    normalized = [
        _canonical_ipv4_32(item, "administratorSourcePrefixes") for item in value
    ]
    expected_order = sorted(
        normalized,
        key=lambda item: int(ipaddress.ip_network(item).network_address),
    )
    if normalized != expected_order:
        raise PreflightError("administratorSourcePrefixes is not in canonical network order")
    return normalized


def _ssh_fingerprint(public_key: Any) -> str:
    if (
        not isinstance(public_key, str)
        or "PRIVATE KEY" in public_key
        or "\n" in public_key
    ):
        raise PreflightError("sshPublicKey must be one single-line public key")
    parts = public_key.split()
    if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
        raise PreflightError("sshPublicKey must use the reviewed ED25519 key type")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PreflightError("sshPublicKey has invalid base64") from exc
    if base64.b64encode(blob).decode("ascii") != parts[1]:
        raise PreflightError("sshPublicKey base64 is not canonical")
    if (
        len(blob) != 51
        or blob[:15] != b"\x00\x00\x00\x0bssh-ed25519"
        or blob[15:19] != b"\x00\x00\x00\x20"
    ):
        raise PreflightError("sshPublicKey is not a canonical 32-byte ED25519 blob")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return "SHA256:" + digest.rstrip("=")


def _canonical_deadline(
    value: Any, *, now: datetime, require_future: bool = True
) -> tuple[str, datetime]:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PreflightError("parallelAcceptanceDeadlineUtc must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise PreflightError("parallelAcceptanceDeadlineUtc must be canonical UTC") from exc
    current = now.astimezone(timezone.utc).replace(microsecond=0)
    if require_future and parsed <= current:
        raise PreflightError("parallel acceptance deadline has expired")
    if parsed > current + timedelta(hours=MAXIMUM_PARALLEL_ACCEPTANCE_HOURS):
        raise PreflightError("parallel acceptance deadline exceeds the 72-hour cost boundary")
    return value, parsed


def validate_parameters(
    document: Mapping[str, Any],
    *,
    approved_admin_cidrs: Iterable[str],
    expected_ssh_fingerprint: str,
    now: datetime | None = None,
    allow_expired_deadline: bool = False,
) -> Dict[str, Any]:
    values = _values(document)
    errors = []

    for name, expected in FIXED_VALUES.items():
        if values.get(name) != expected:
            errors.append("{} does not equal the reviewed fixed value".format(name))

    try:
        actual_admin = _admin_prefixes(values.get("administratorSourcePrefixes"))
        approved_admin = _admin_prefixes(list(approved_admin_cidrs))
        if actual_admin != approved_admin:
            errors.append(
                "administratorSourcePrefixes does not equal the separately approved set"
            )
    except PreflightError as exc:
        errors.append(str(exc))
        actual_admin = []

    try:
        fingerprint = _ssh_fingerprint(values.get("sshPublicKey"))
        if fingerprint != expected_ssh_fingerprint:
            errors.append(
                "sshPublicKey fingerprint does not match the separately approved key"
            )
    except PreflightError as exc:
        errors.append(str(exc))
        fingerprint = "INVALID"

    try:
        deadline, _ = _canonical_deadline(
            values.get("parallelAcceptanceDeadlineUtc"),
            now=now or datetime.now(timezone.utc),
            require_future=not allow_expired_deadline,
        )
    except PreflightError as exc:
        errors.append(str(exc))
        deadline = "INVALID"

    if errors:
        raise PreflightError("; ".join(errors))

    return {
        "administratorCidrCount": len(actual_admin),
        "carrierGatewayPrivatePrefix": values["cp1PrivatePrefix"],
        "carrierGatewayPath": "same-vnet-private-no-public-hairpin",
        "compiledParametersSha256": _canonical_digest(document),
        "edgeGeneration": values["edgeGeneration"],
        "edgeRuntimeProfile": values["edgeRuntimeProfile"],
        "microsoftDirectRoutingCidrVersion": (
            "learn.microsoft.com reviewed 2026-08-31"
        ),
        "microsoftMediaProcessorUdpPortRanges": [
            values["microsoftMediaIcePortRange"],
            values["microsoftMediaHighPortRange"],
        ],
        "parallelAcceptanceDeadlineUtc": deadline,
        "replacementPrivateIpAddresses": {
            "sbc1": values["sbc1PrivateIpAddress"],
            "sbc2": values["sbc2PrivateIpAddress"],
        },
        "replacementVmNames": {
            "sbc1": values["sbc1NodeName"],
            "sbc2": values["sbc2NodeName"],
        },
        "sshPublicKeyFingerprint": fingerprint,
        "status": "DIRECT_REPLACEMENT_PARAMETERS_VALID",
        "targetResourceGroup": {
            "name": values["targetResourceGroupName"],
            "subscriptionId": values["targetSubscriptionId"],
        },
    }


def validate_compiled_template(template: Mapping[str, Any]) -> str:
    if template.get("$schema") != TEMPLATE_SCHEMA:
        raise PreflightError("compiled template is not subscription scoped")
    metadata = template.get("metadata")
    generator = metadata.get("_generator") if isinstance(metadata, dict) else None
    if not isinstance(generator, dict):
        raise PreflightError("compiled template lacks Bicep generator metadata")
    if generator.get("name") != "bicep" or generator.get("version") != EXPECTED_BICEP_VERSION:
        raise PreflightError("compiled template was not produced by reviewed Bicep 0.46.1")
    digest = _canonical_digest(template)
    if digest != EXPECTED_COMPILED_TEMPLATE_SHA256:
        raise PreflightError("compiled template digest does not match reviewed IaC")
    return digest


def validate_compiled_package(
    parameters: Mapping[str, Any],
    template: Mapping[str, Any],
    *,
    approved_admin_cidrs: Iterable[str],
    expected_ssh_fingerprint: str,
    now: datetime | None = None,
    allow_expired_deadline: bool = False,
) -> Dict[str, Any]:
    template_digest = validate_compiled_template(template)
    evidence = validate_parameters(
        parameters,
        approved_admin_cidrs=approved_admin_cidrs,
        expected_ssh_fingerprint=expected_ssh_fingerprint,
        now=now,
        allow_expired_deadline=allow_expired_deadline,
    )
    return {
        **evidence,
        "bicepCompilerVersion": EXPECTED_BICEP_VERSION,
        "compiledTemplateSha256": template_digest,
        "status": "DIRECT_REPLACEMENT_COMPILED_PACKAGE_VALID",
    }


def compile_bicep_package(path: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    result = subprocess.run(
        ["az", "bicep", "build-params", "--file", str(path), "--stdout"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PreflightError(
            "Bicep parameter compilation failed: {}".format(result.stderr.strip())
        )
    try:
        outer = json.loads(result.stdout)
        if set(outer) != {"parametersJson", "templateJson", "templateSpecId"}:
            raise PreflightError("Bicep returned an unexpected package envelope")
        if outer["templateSpecId"] is not None:
            raise PreflightError("template-spec parameters are not accepted")
        parameters = json.loads(outer["parametersJson"])
        template = json.loads(outer["templateJson"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PreflightError("Bicep returned a malformed compiled package") from exc
    if not isinstance(parameters, dict) or not isinstance(template, dict):
        raise PreflightError("compiled parameters and template must be objects")
    return parameters, template


Runner = Callable[[Sequence[str]], str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise PreflightError("Azure CLI command failed: {}".format(detail))
    return result.stdout


def _json_from_runner(argv: Sequence[str], label: str, runner: Runner) -> Any:
    try:
        raw = runner(argv)
    except PreflightError as exc:
        raise PreflightError("{} query failed: {}".format(label, exc)) from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PreflightError("Azure CLI returned malformed {} JSON".format(label)) from exc


def _same_id(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual.rstrip("/").lower() == expected.rstrip("/").lower()


def _resource_group_id() -> str:
    return "/subscriptions/{}/resourceGroups/{}".format(
        EXPECTED_SUBSCRIPTION_ID, EXPECTED_RESOURCE_GROUP
    )


def _resource_id(resource_type: str, name: str) -> str:
    return "{}/providers/{}/{}".format(_resource_group_id(), resource_type, name)


def _replacement_declared_resources() -> Dict[str, tuple[str, str]]:
    result: Dict[str, tuple[str, str]] = {}
    for node in EXPECTED_REPLACEMENT_VM_NAMES:
        for suffix, resource_type in (
            ("", "Microsoft.Compute/virtualMachines"),
            ("-nic", "Microsoft.Network/networkInterfaces"),
            ("-nsg", "Microsoft.Network/networkSecurityGroups"),
            ("-pip", "Microsoft.Network/publicIPAddresses"),
        ):
            name = node + suffix
            result[_resource_id(resource_type, name).lower()] = (name, resource_type)
    return result


def _replacement_disk_resources() -> Dict[str, tuple[str, str]]:
    return {
        _resource_id("Microsoft.Compute/disks", node + "-osdisk").lower(): (
            node + "-osdisk",
            node,
        )
        for node in EXPECTED_REPLACEMENT_VM_NAMES
    }


def validate_local_parameter_path(path: Path) -> Path:
    """Require the secret-bearing operator file beside its relative `using` target."""
    if path.is_symlink():
        raise PreflightError("local parameter file must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise PreflightError("local parameter file is not a readable regular file") from exc
    expected_parent = Path(__file__).resolve().parent
    if (
        resolved.parent != expected_parent
        or resolved.name != "direct-replacement.local.bicepparam"
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise PreflightError(
            "use the adjacent ignored infra/azure-poc/direct-replacement.local.bicepparam"
        )
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
        raise PreflightError("local parameter file must be owner-only mode 0400 or 0600")
    return resolved


def _required_common_tags() -> Dict[str, str]:
    return {
        "costProfile": "monthly-credit-lab",
        "environment": "poc",
        "managedBy": "bicep",
        "owner": "Vivolution Technologies LLC",
        "purpose": "SBC proof of concept",
        "region": EXPECTED_LOCATION,
        "workload": "vivolution-sbc",
    }


def _replacement_tags(node: str, deadline: str) -> Dict[str, str]:
    return {
        "costProfile": "monthly-credit-lab",
        "edgeGeneration": "3",
        "edgeRuntimeProfile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
        "environment": "poc",
        "managedBy": "bicep",
        "nodeName": "sbc1" if node.endswith("sbc1-g3") else "sbc2",
        "nodeRole": "session-border-controller",
        "owner": "Vivolution Technologies LLC",
        "parallelAcceptanceWindowHours": "72",
        "parallelAcceptanceDeadlineUtc": deadline,
        "predecessorDisposition": "deallocate-after-final-acceptance",
        "purpose": "Direct Routing generation-3 replacement Edge",
        "region": EXPECTED_LOCATION,
        "replacementMode": "parallel-preserve-generation-2",
        "workload": "vivolution-sbc",
    }


def _validate_budget_and_headroom(
    budget: Any, *, observed_at: datetime
) -> Dict[str, Any]:
    if not isinstance(budget, dict) or budget.get("name") != EXPECTED_BUDGET_NAME:
        raise PreflightError("the exact USD 100 POC budget is absent")
    expected_budget_id = (
        "/subscriptions/{}/resourceGroups/{}/providers/"
        "Microsoft.Consumption/budgets/{}".format(
            EXPECTED_SUBSCRIPTION_ID,
            EXPECTED_RESOURCE_GROUP,
            EXPECTED_BUDGET_NAME,
        )
    )
    if (
        not _same_id(budget.get("id"), expected_budget_id)
        or str(budget.get("type", "")).lower()
        != "microsoft.consumption/budgets"
    ):
        raise PreflightError("POC budget identity drifted")
    properties = budget.get("properties")
    if not isinstance(properties, dict):
        raise PreflightError("POC budget properties are missing")
    try:
        amount = Decimal(str(properties.get("amount")))
    except InvalidOperation as exc:
        raise PreflightError("POC budget amount is malformed") from exc
    if (
        amount != EXPECTED_BUDGET_AMOUNT_USD
        or not amount.is_finite()
        or properties.get("category") != "Cost"
        or properties.get("timeGrain") != "Monthly"
        or properties.get("filter") not in (None, {})
    ):
        raise PreflightError(
            "POC budget amount/category/time grain or unfiltered scope drifted"
        )

    period = properties.get("timePeriod")
    if not isinstance(period, dict) or set(period) != {"startDate", "endDate"}:
        raise PreflightError("POC budget time period is malformed")
    start = _parse_canonical_utc(period.get("startDate"), "POC budget startDate")
    end = _parse_canonical_utc(period.get("endDate"), "POC budget endDate")
    observed_date = observed_at.astimezone(timezone.utc).date()
    if (
        start.day != 1
        or (start.hour, start.minute, start.second, start.microsecond) != (0, 0, 0, 0)
        or (end.hour, end.minute, end.second, end.microsecond) != (0, 0, 0, 0)
        or start > observed_at.astimezone(timezone.utc)
        or end.date() < observed_date
        or end <= start
    ):
        raise PreflightError("POC budget is not active on a first-of-month boundary")
    notifications = properties.get("notifications")
    if not isinstance(notifications, dict) or len(notifications) != 3:
        raise PreflightError("POC budget must retain exactly three notifications")
    found: set[Decimal] = set()
    for notification in notifications.values():
        if not isinstance(notification, dict):
            raise PreflightError("POC budget notification is malformed")
        try:
            threshold = Decimal(str(notification.get("threshold")))
        except InvalidOperation as exc:
            raise PreflightError("POC budget threshold is malformed") from exc
        if (
            threshold not in EXPECTED_BUDGET_THRESHOLDS
            or threshold in found
            or notification.get("enabled") is not True
            or notification.get("operator") != "GreaterThanOrEqualTo"
            or notification.get("thresholdType") != "Actual"
            or notification.get("contactEmails") != ["jaydevupadhyay@gmail.com"]
            or notification.get("contactGroups") not in (None, [])
            or notification.get("contactRoles") not in (None, [])
        ):
            raise PreflightError("POC budget notification contract drifted")
        found.add(threshold)
    if found != EXPECTED_BUDGET_THRESHOLDS:
        raise PreflightError("POC budget thresholds are not exactly 75/90/100")

    current_spend = properties.get("currentSpend")
    if (
        not isinstance(current_spend, dict)
        or set(current_spend) != {"amount", "unit"}
        or current_spend.get("unit") != "USD"
    ):
        raise PreflightError("POC resource-group budget currentSpend is malformed")
    try:
        actual = Decimal(str(current_spend.get("amount")))
    except InvalidOperation as exc:
        raise PreflightError("POC resource-group budget currentSpend is malformed") from exc
    if not actual.is_finite() or actual < 0 or actual > amount:
        raise PreflightError(
            "POC resource-group budget currentSpend is outside the bounded USD budget"
        )
    remaining = amount - actual
    if remaining < MAXIMUM_INCREMENTAL_REPLACEMENT_COST_USD:
        raise PreflightError("insufficient USD budget headroom for the 72-hour parallel window")
    return {
        "budgetAmountUsd": str(amount.quantize(Decimal("0.01"))),
        "budgetScope": _resource_group_id(),
        "currentSpendUsd": str(actual.quantize(Decimal("0.01"))),
        "remainingBudgetUsd": str(remaining.quantize(Decimal("0.01"))),
        "maximumIncrementalReplacementCostUsd": str(
            MAXIMUM_INCREMENTAL_REPLACEMENT_COST_USD
        ),
        "thresholds": [75, 90, 100],
    }


def _subnet_by_name(vnet: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    subnets = vnet.get("subnets")
    if not isinstance(subnets, list):
        raise PreflightError("VNet subnet inventory is missing")
    selected = [item for item in subnets if isinstance(item, dict) and item.get("name") == name]
    if len(selected) != 1:
        raise PreflightError("VNet does not contain the exact {} subnet".format(name))
    return selected[0]


def _validate_subnet_policy(subnet: Mapping[str, Any], expected_prefix: str) -> None:
    empty_fields = (
        "delegations",
        "privateEndpointIds",
        "serviceEndpoints",
        "serviceEndpointPolicyIds",
    )
    if (
        subnet.get("addressPrefix") != expected_prefix
        or subnet.get("addressPrefixes") not in (None, [])
        or subnet.get("defaultOutboundAccess") is not False
        or subnet.get("networkSecurityGroupId") is not None
        or subnet.get("natGatewayId") is not None
        or subnet.get("routeTableId") is not None
        or subnet.get("privateEndpointNetworkPolicies") != "Enabled"
        or subnet.get("privateLinkServiceNetworkPolicies") != "Enabled"
        or subnet.get("provisioningState") != "Succeeded"
        or any(subnet.get(field) not in (None, []) for field in empty_fields)
    ):
        raise PreflightError(
            "subnet drifted from the exact no-NSG/no-route/no-NAT/no-delegation/default-outbound-disabled contract"
        )


def _validate_resource_inventory(
    resources: Any, *, deadline: str
) -> tuple[set[str], set[str]]:
    if not isinstance(resources, list):
        raise PreflightError("resource-group inventory is missing")
    declared = _replacement_declared_resources()
    disks = _replacement_disk_resources()
    present_declared: set[str] = set()
    present_nodes: set[str] = set()
    present_disks: set[str] = set()
    replacement_prefixes = tuple(name.lower() for name in EXPECTED_REPLACEMENT_VM_NAMES)
    for record in resources:
        if not isinstance(record, dict):
            raise PreflightError("resource-group inventory contains a malformed record")
        name = str(record.get("name", ""))
        if not name.lower().startswith(replacement_prefixes):
            continue
        resource_id = str(record.get("id", "")).lower()
        resource_type = str(record.get("type", ""))
        if resource_id in declared:
            expected_name, expected_type = declared[resource_id]
            node = next(node for node in EXPECTED_REPLACEMENT_VM_NAMES if expected_name.startswith(node))
            if (
                name != expected_name
                or resource_type.lower() != expected_type.lower()
                or str(record.get("location", "")).lower() != EXPECTED_LOCATION
                or record.get("tags") != _replacement_tags(node, deadline)
            ):
                raise PreflightError("an existing replacement resource drifted from the exact contract")
            present_declared.add(resource_id)
            if expected_type == "Microsoft.Compute/virtualMachines":
                present_nodes.add(node)
        elif resource_id in disks:
            expected_name, node = disks[resource_id]
            if (
                name != expected_name
                or resource_type.lower() != "microsoft.compute/disks"
                or str(record.get("location", "")).lower() != EXPECTED_LOCATION
                or record.get("tags") not in (None, _replacement_tags(node, deadline))
            ):
                raise PreflightError("an existing replacement OS disk drifted from the exact VM attachment")
            present_disks.add(resource_id)
        else:
            raise PreflightError("a colliding replacement-prefixed Azure resource already exists")
    for node in EXPECTED_REPLACEMENT_VM_NAMES:
        expected_declared = {
            resource_id
            for resource_id, (name, _) in declared.items()
            if name == node or name.startswith(node + "-")
        }
        expected_disk_id = _resource_id(
            "Microsoft.Compute/disks", node + "-osdisk"
        ).lower()
        observed = (present_declared & expected_declared) | (
            {expected_disk_id} if expected_disk_id in present_disks else set()
        )
        if observed and observed != expected_declared | {expected_disk_id}:
            raise PreflightError(
                "replacement node is a fragmented partial resource set and cannot be resumed"
            )
        if observed:
            present_nodes.add(node)
    return present_declared, present_nodes


def _expected_subnet_id(node: str) -> str:
    subnet = (
        EXPECTED_MANAGEMENT_SUBNET_NAME
        if node == "viv-sbc-poc-cp1"
        else EXPECTED_EDGE_SUBNET_NAME
    )
    return (
        _resource_id("Microsoft.Network/virtualNetworks", EXPECTED_VNET_NAME)
        + "/subnets/"
        + subnet
    )


def _validate_node_bindings(
    nodes: Any,
    present_nodes: set[str],
    *,
    deadline: str,
    allow_replacement_deallocated: bool = False,
) -> Dict[str, list[str]]:
    if not isinstance(nodes, list):
        raise PreflightError("exact VM/NIC binding observations are missing")
    required = {
        "viv-sbc-poc-cp1",
        *EXPECTED_SYNTHETIC_VM_NAMES,
        *present_nodes,
    }
    by_name = {
        item.get("name"): item
        for item in nodes
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if set(by_name) != required or len(nodes) != len(required):
        raise PreflightError(
            "CP1, predecessor and admitted replacement node observations are not exact"
        )
    locked: list[str] = []
    pending: list[str] = []
    for node in sorted(required):
        record = by_name[node]
        vm = record.get("vm")
        nic = record.get("nic")
        nsg = record.get("nsg")
        public_ip = record.get("publicIp")
        expected_vm_id = _resource_id("Microsoft.Compute/virtualMachines", node)
        expected_nic_id = _resource_id(
            "Microsoft.Network/networkInterfaces", node + "-nic"
        )
        expected_nsg_id = _resource_id(
            "Microsoft.Network/networkSecurityGroups", node + "-nsg"
        )
        expected_pip_id = _resource_id(
            "Microsoft.Network/publicIPAddresses", node + "-pip"
        )
        if (
            not isinstance(vm, dict)
            or not _same_id(vm.get("id"), expected_vm_id)
            or vm.get("name") != node
            or str(vm.get("location", "")).lower() != EXPECTED_LOCATION
            or vm.get("provisioningState") != "Succeeded"
            or not isinstance(vm.get("nicIds"), list)
            or len(vm["nicIds"]) != 1
            or not _same_id(vm["nicIds"][0], expected_nic_id)
            or record.get("powerState")
            not in (
                {"PowerState/running", "PowerState/deallocated"}
                if allow_replacement_deallocated
                and node in EXPECTED_REPLACEMENT_VM_NAMES
                else {"PowerState/running"}
            )
        ):
            raise PreflightError("VM is not the exact healthy running node: {}".format(node))
        os_disk_name = vm.get("osDiskName")
        os_disk_id = vm.get("osDiskId")
        expected_os_disk_name = node + "-osdisk"
        physical_os_disk_name = (
            os_disk_id.rsplit("/", 1)[-1]
            if isinstance(os_disk_id, str)
            else None
        )
        expected_physical_os_disk_pattern = (
            re.escape(node + "-osdisk")
            if node == "viv-sbc-poc-cp1" or node in EXPECTED_REPLACEMENT_VM_NAMES
            else re.escape(node + "-osdisk") + r"(?:_[0-9a-f]{32})?"
        )
        if (
            os_disk_name != expected_os_disk_name
            or not isinstance(physical_os_disk_name, str)
            or re.fullmatch(
                expected_physical_os_disk_pattern,
                physical_os_disk_name,
            )
            is None
            or not _same_id(
                os_disk_id,
                _resource_id("Microsoft.Compute/disks", physical_os_disk_name),
            )
        ):
            raise PreflightError("VM OS-disk identity drifted for {}".format(node))
        if not isinstance(nic, dict) or (
            not _same_id(nic.get("id"), expected_nic_id)
            or nic.get("name") != node + "-nic"
            or str(nic.get("location", "")).lower() != EXPECTED_LOCATION
            or nic.get("provisioningState") != "Succeeded"
            or nic.get("enableIPForwarding") is not False
            or nic.get("enableAcceleratedNetworking") is not False
            or not _same_id(nic.get("networkSecurityGroupId"), expected_nsg_id)
        ):
            raise PreflightError("NIC identity or policy drifted for {}".format(node))
        ip_configs = nic.get("ipConfigurations")
        if not isinstance(ip_configs, list) or len(ip_configs) != 1:
            raise PreflightError("NIC does not have exactly one IP configuration for {}".format(node))
        ip_config = ip_configs[0]
        if (
            not isinstance(ip_config, dict)
            or ip_config.get("name") != "ipconfig1"
            or ip_config.get("primary") is not True
            or ip_config.get("privateIPAddress") != EXPECTED_NODE_PRIVATE_IPS[node]
            or ip_config.get("privateIPAllocationMethod") != "Static"
            or ip_config.get("privateIPAddressVersion") != "IPv4"
            or not _same_id(ip_config.get("subnetId"), _expected_subnet_id(node))
            or not _same_id(ip_config.get("publicIpId"), expected_pip_id)
        ):
            raise PreflightError("NIC private-IP/allocation binding drifted for {}".format(node))
        expected_ip_configuration_id = (
            expected_nic_id + "/ipConfigurations/ipconfig1"
        )
        if not isinstance(nsg, dict) or (
            not _same_id(nsg.get("id"), expected_nsg_id)
            or nsg.get("name") != node + "-nsg"
            or str(nsg.get("location", "")).lower() != EXPECTED_LOCATION
            or nsg.get("provisioningState") != "Succeeded"
            or not isinstance(nsg.get("networkInterfaceIds"), list)
            or len(nsg["networkInterfaceIds"]) != 1
            or not _same_id(nsg["networkInterfaceIds"][0], expected_nic_id)
            or nsg.get("subnetIds") not in (None, [])
        ):
            raise PreflightError("NSG identity/provisioning/attachment drifted for {}".format(node))
        try:
            assigned_public_ip = ipaddress.ip_address(
                public_ip.get("ipAddress") if isinstance(public_ip, dict) else ""
            )
        except ValueError as exc:
            raise PreflightError(
                "public IP allocation is missing or malformed for {}".format(node)
            ) from exc
        if not isinstance(public_ip, dict) or (
            not _same_id(public_ip.get("id"), expected_pip_id)
            or public_ip.get("name") != node + "-pip"
            or str(public_ip.get("location", "")).lower() != EXPECTED_LOCATION
            or public_ip.get("provisioningState") != "Succeeded"
            or public_ip.get("publicIPAllocationMethod") != "Static"
            or public_ip.get("publicIPAddressVersion") != "IPv4"
            or public_ip.get("skuName") != "Standard"
            or public_ip.get("skuTier") != "Regional"
            or not isinstance(assigned_public_ip, ipaddress.IPv4Address)
            or not assigned_public_ip.is_global
            or not _same_id(
                public_ip.get("ipConfigurationId"), expected_ip_configuration_id
            )
        ):
            raise PreflightError(
                "public IP identity/provisioning/allocation/attachment drifted for {}".format(
                    node
                )
            )
        if node in present_nodes:
            expected_tags = _replacement_tags(node, deadline)
            if nsg.get("tags") != expected_tags or public_ip.get("tags") != expected_tags:
                raise PreflightError(
                    "replacement NSG/public-IP tags drifted for {}".format(node)
                )
        if node not in present_nodes:
            continue
        disk = record.get("disk")
        expected_disk_id = _resource_id("Microsoft.Compute/disks", node + "-osdisk")
        if (
            not isinstance(disk, dict)
            or not _same_id(disk.get("id"), expected_disk_id)
            or disk.get("name") != node + "-osdisk"
            or not _same_id(disk.get("managedBy"), expected_vm_id)
            or disk.get("provisioningState") != "Succeeded"
            or not _same_id(vm.get("osDiskId"), expected_disk_id)
            or vm.get("osDiskName") != node + "-osdisk"
        ):
            raise PreflightError("replacement OS disk identity/attachment drifted for {}".format(node))
        expected_tags = _replacement_tags(node, deadline)
        policy = (disk.get("publicNetworkAccess"), disk.get("networkAccessPolicy"))
        if policy == ("Disabled", "DenyAll") and disk.get("tags") == expected_tags:
            locked.append(node)
        elif (
            policy in {("Enabled", "AllowAll"), (None, None)}
            and disk.get("tags") in (None, expected_tags)
        ) or (policy == ("Disabled", "DenyAll") and disk.get("tags") is None):
            pending.append(node)
        else:
            raise PreflightError("replacement OS disk lockdown state drifted for {}".format(node))
    return {
        "lockedVmNames": locked,
        "pendingVmNames": pending,
    }


def _validate_what_if(
    what_if: Any,
    present_declared: set[str],
    validated_existing_ids: set[str],
) -> Dict[str, Any]:
    if not isinstance(what_if, dict) or what_if.get("status") != "Succeeded":
        raise PreflightError("provider-level subscription what-if did not succeed")
    changes = what_if.get("changes")
    if not isinstance(changes, list):
        raise PreflightError("provider-level what-if change inventory is missing")
    declared = _replacement_declared_resources()
    existing_refs = {
        _resource_id("Microsoft.Network/virtualNetworks", EXPECTED_VNET_NAME).lower(),
        (
            _resource_id("Microsoft.Network/virtualNetworks", EXPECTED_VNET_NAME)
            + "/subnets/"
            + EXPECTED_EDGE_SUBNET_NAME
        ).lower(),
        _resource_id(
            "Microsoft.Compute/availabilitySets", EXPECTED_AVAILABILITY_SET_NAME
        ).lower(),
    } | {value.lower() for value in validated_existing_ids}
    nested_deployments = {
        (
            "/subscriptions/{}/providers/Microsoft.Resources/deployments/{}".format(
                EXPECTED_SUBSCRIPTION_ID, DEPLOYMENT_NAME
            )
        ).lower(),
        _resource_id(
            "Microsoft.Resources/deployments",
            EXPECTED_REPLACEMENT_VM_NAMES[0] + "-deployment",
        ).lower(),
        _resource_id(
            "Microsoft.Resources/deployments",
            EXPECTED_REPLACEMENT_VM_NAMES[1] + "-deployment",
        ).lower(),
    }
    summarized: list[Dict[str, str]] = []
    create_ids: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            raise PreflightError("provider-level what-if contains a malformed change")
        resource_id = str(change.get("resourceId", "")).lower()
        change_type = str(change.get("changeType", ""))
        if resource_id in declared:
            if change_type not in {"Create", "NoChange", "Ignore"}:
                raise PreflightError("what-if would modify or remove a replacement resource")
            if change_type == "Create":
                create_ids.add(resource_id)
        elif resource_id in nested_deployments:
            if change_type not in {"Create", "Deploy", "Modify", "NoChange", "Ignore"}:
                raise PreflightError("what-if contains an unsafe nested-deployment change")
        elif resource_id in existing_refs:
            if change_type not in {"NoChange", "Ignore"}:
                raise PreflightError("what-if would change an existing topology authority")
        else:
            raise PreflightError("what-if targets a resource outside the two replacement node sets")
        summarized.append({"changeType": change_type, "resourceId": resource_id})
    missing = set(declared) - present_declared
    if not missing.issubset(create_ids):
        raise PreflightError("what-if does not create every absent replacement resource")
    if create_ids & present_declared:
        raise PreflightError("what-if would recreate an already admitted partial resource")
    return {
        "changes": sorted(summarized, key=lambda item: (item["resourceId"], item["changeType"])),
        "sha256": _canonical_digest(what_if),
    }


def _validated_existing_what_if_ids(nodes: Any) -> set[str]:
    """Return only identities already proven exact by node binding validation."""
    if not isinstance(nodes, list):
        raise PreflightError("exact VM/NIC binding observations are missing")
    result = {_resource_group_id().lower()}
    for record in nodes:
        if not isinstance(record, dict):
            raise PreflightError("exact VM/NIC binding observations are malformed")
        vm = record.get("vm")
        components = (
            vm,
            record.get("nic"),
            record.get("nsg"),
            record.get("publicIp"),
        )
        if any(not isinstance(component, dict) for component in components):
            raise PreflightError("exact VM/NIC binding observations are incomplete")
        for component in components:
            resource_id = component.get("id")
            if not isinstance(resource_id, str) or not resource_id:
                raise PreflightError("validated node component lacks one resource ID")
            result.add(resource_id.lower())
        os_disk_id = vm.get("osDiskId")
        if not isinstance(os_disk_id, str) or not os_disk_id:
            raise PreflightError("validated VM lacks one OS-disk resource ID")
        result.add(os_disk_id.lower())
    return result


def validate_live_plan(
    observations: Mapping[str, Any],
    package_evidence: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    allow_expired_deadline: bool = False,
    allow_replacement_deallocated: bool = False,
) -> Dict[str, Any]:
    if (
        package_evidence.get("edgeGeneration") != FIXED_VALUES["edgeGeneration"]
        or package_evidence.get("edgeRuntimeProfile")
        != FIXED_VALUES["edgeRuntimeProfile"]
    ):
        raise PreflightError("compiled package runtime authority is not exact")
    account = observations.get("account")
    if (
        not isinstance(account, dict)
        or account.get("id") != EXPECTED_SUBSCRIPTION_ID
        or account.get("tenantId") != EXPECTED_TENANT_ID
        or account.get("state") != "Enabled"
    ):
        raise PreflightError("authenticated Azure account is not the exact enabled POC authority")
    providers = observations.get("providers")
    if not isinstance(providers, list) or {
        item.get("namespace")
        for item in providers
        if isinstance(item, dict) and item.get("registrationState") == "Registered"
    } != set(EXPECTED_PROVIDER_NAMESPACES):
        raise PreflightError("Microsoft.Compute and Microsoft.Network providers must be exactly registered")
    group = observations.get("resourceGroup")
    group_properties = group.get("properties") if isinstance(group, dict) else None
    if (
        not isinstance(group, dict)
        or not _same_id(group.get("id"), _resource_group_id())
        or group.get("name") != EXPECTED_RESOURCE_GROUP
        or str(group.get("location", "")).lower() != EXPECTED_LOCATION
        or not isinstance(group_properties, dict)
        or group_properties.get("provisioningState") != "Succeeded"
        or group.get("tags") != _required_common_tags()
    ):
        raise PreflightError("target resource group drifted from its exact POC authority")

    deadline = package_evidence.get("parallelAcceptanceDeadlineUtc")
    if not isinstance(deadline, str):
        raise PreflightError("compiled package evidence lacks the immutable cost deadline")
    _, deadline_value = _canonical_deadline(
        deadline,
        now=observed_at or datetime.now(timezone.utc),
        require_future=not allow_expired_deadline,
    )
    plan_time = (observed_at or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    ).replace(microsecond=0)
    if (
        not allow_expired_deadline
        and deadline_value - plan_time
        < timedelta(minutes=MINIMUM_CREATE_BUFFER_MINUTES)
    ):
        raise PreflightError(
            "parallel deadline is inside the mandatory create safety buffer"
        )
    present_declared, present_nodes = _validate_resource_inventory(
        observations.get("resources"), deadline=deadline
    )
    vnet = observations.get("vnet")
    expected_vnet_id = _resource_id("Microsoft.Network/virtualNetworks", EXPECTED_VNET_NAME)
    if (
        not isinstance(vnet, dict)
        or not _same_id(vnet.get("id"), expected_vnet_id)
        or vnet.get("name") != EXPECTED_VNET_NAME
        or str(vnet.get("location", "")).lower() != EXPECTED_LOCATION
        or vnet.get("addressPrefixes") != [EXPECTED_VNET_PREFIX]
        or vnet.get("dnsServers") not in (None, [])
        or vnet.get("ddosProtection") is not False
        or vnet.get("peerings") not in (None, [])
        or vnet.get("provisioningState") != "Succeeded"
        or vnet.get("tags") != _required_common_tags()
        or not isinstance(vnet.get("subnets"), list)
        or len(vnet["subnets"]) != 2
    ):
        raise PreflightError("existing VNet drifted from the exact isolated /16 topology")
    management = _subnet_by_name(vnet, EXPECTED_MANAGEMENT_SUBNET_NAME)
    edge = _subnet_by_name(vnet, EXPECTED_EDGE_SUBNET_NAME)
    _validate_subnet_policy(management, EXPECTED_MANAGEMENT_SUBNET_PREFIX)
    _validate_subnet_policy(edge, EXPECTED_EDGE_SUBNET_PREFIX)
    expected_management_ipconfigs = {
        (_resource_id("Microsoft.Network/networkInterfaces", "viv-sbc-poc-cp1-nic") + "/ipConfigurations/ipconfig1").lower()
    }
    expected_edge_ipconfigs = {
        (_resource_id("Microsoft.Network/networkInterfaces", name + "-nic") + "/ipConfigurations/ipconfig1").lower()
        for name in EXPECTED_SYNTHETIC_VM_NAMES
    } | {
        (_resource_id("Microsoft.Network/networkInterfaces", name + "-nic") + "/ipConfigurations/ipconfig1").lower()
        for name in present_nodes
    }
    if {str(value).lower() for value in (management.get("ipConfigurationIds") or [])} != expected_management_ipconfigs:
        raise PreflightError("management subnet is not bound only to the exact CP1 NIC")
    if {str(value).lower() for value in (edge.get("ipConfigurationIds") or [])} != expected_edge_ipconfigs:
        raise PreflightError("Edge subnet NIC membership is outside the exact safe-resume set")

    node_observations = observations.get("nodes")
    disk_lockdown = _validate_node_bindings(
        node_observations,
        present_nodes,
        deadline=deadline,
        allow_replacement_deallocated=allow_replacement_deallocated,
    )
    validated_existing_ids = _validated_existing_what_if_ids(node_observations)

    availability_set = observations.get("availabilitySet")
    expected_as_id = _resource_id(
        "Microsoft.Compute/availabilitySets", EXPECTED_AVAILABILITY_SET_NAME
    )
    expected_vm_ids = {
        _resource_id("Microsoft.Compute/virtualMachines", name).lower()
        for name in EXPECTED_SYNTHETIC_VM_NAMES
    } | {
        _resource_id("Microsoft.Compute/virtualMachines", name).lower()
        for name in present_nodes
    }
    expected_availability_set_keys = {
        "faultDomains",
        "id",
        "location",
        "name",
        "sku",
        "tags",
        "updateDomains",
        "vmIds",
    }
    if (
        not isinstance(availability_set, dict)
        or set(availability_set) != expected_availability_set_keys
        or not _same_id(availability_set.get("id"), expected_as_id)
        or availability_set.get("name") != EXPECTED_AVAILABILITY_SET_NAME
        or str(availability_set.get("location", "")).lower() != EXPECTED_LOCATION
        or availability_set.get("sku") != "Aligned"
        or availability_set.get("faultDomains") != 2
        or availability_set.get("updateDomains") != 5
        or availability_set.get("tags") != _required_common_tags()
        or {str(value).lower() for value in (availability_set.get("vmIds") or [])} != expected_vm_ids
    ):
        raise PreflightError("availability set drifted from Aligned UAE North FD2/UD5 exact membership")

    budget = _validate_budget_and_headroom(
        observations.get("budget"), observed_at=plan_time
    )
    what_if = _validate_what_if(
        observations.get("whatIf"),
        present_declared,
        validated_existing_ids,
    )
    now = observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise PreflightError("live plan timestamp must be timezone aware")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    body: Dict[str, Any] = {
        "authority": {
            "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
            "tenantId": EXPECTED_TENANT_ID,
            "resourceGroup": EXPECTED_RESOURCE_GROUP,
            "providerValidationLevel": "Provider",
        },
        "budget": budget,
        "bicepCompilerVersion": package_evidence["bicepCompilerVersion"],
        "compiledParametersSha256": package_evidence["compiledParametersSha256"],
        "compiledTemplateSha256": package_evidence["compiledTemplateSha256"],
        "deploymentName": DEPLOYMENT_NAME,
        "observedAtUtc": now.isoformat().replace("+00:00", "Z"),
        "authorizationExpiresUtc": min(
            deadline_value, now + timedelta(minutes=LIVE_PLAN_MAX_AGE_MINUTES)
        ).isoformat().replace("+00:00", "Z"),
        "parallelAcceptance": {
            "deadlineUtc": deadline,
            "maximumHours": MAXIMUM_PARALLEL_ACCEPTANCE_HOURS,
            "syntheticPredecessorVmNames": list(EXPECTED_SYNTHETIC_VM_NAMES),
            "requiredDisposition": "deallocate-after-final-acceptance-and-no-later-than-deadline",
        },
        "runtimeAuthority": {
            "generation": package_evidence["edgeGeneration"],
            "profile": package_evidence["edgeRuntimeProfile"],
        },
        "partialDeploymentResume": {
            "diskLockdown": disk_lockdown,
            "presentDeclaredResourceIds": sorted(present_declared),
            "presentReplacementVmNames": sorted(present_nodes),
            "resumeWithSameDeploymentNameAndParameterDigest": True,
        },
        "topology": {
            "availabilitySet": "Aligned/FD2/UD5",
            "edgeSubnet": EXPECTED_EDGE_SUBNET_PREFIX,
            "edgeSubnetDefaultOutboundAccess": False,
            "edgeSubnetDelegations": [],
            "edgeSubnetNetworkSecurityGroup": None,
            "edgeSubnetNatGateway": None,
            "edgeSubnetRouteTable": None,
            "vnet": EXPECTED_VNET_PREFIX,
        },
        "whatIf": what_if,
    }
    return {
        **body,
        "planSha256": _canonical_digest(body),
        "status": "DIRECT_REPLACEMENT_LIVE_PLAN_VALID",
    }


def _read_node_observation(
    node: str, *, include_disk: bool, runner: Runner
) -> Dict[str, Any]:
    common = [
        "--subscription",
        EXPECTED_SUBSCRIPTION_ID,
        "--output",
        "json",
        "--only-show-errors",
    ]
    vm = _json_from_runner(
        [
            "az", "vm", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", node, *common, "--query",
            "{id:id,name:name,location:location,provisioningState:provisioningState,nicIds:networkProfile.networkInterfaces[].id,osDiskId:storageProfile.osDisk.managedDisk.id,osDiskName:storageProfile.osDisk.name}",
        ],
        "{} VM".format(node),
        runner,
    )
    power = _json_from_runner(
        [
            "az", "vm", "get-instance-view", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", node, *common, "--query",
            "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]",
        ],
        "{} power state".format(node),
        runner,
    )
    nic = _json_from_runner(
        [
            "az", "network", "nic", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", node + "-nic", *common, "--query",
            "{id:id,name:name,location:location,provisioningState:provisioningState,enableIPForwarding:enableIPForwarding,enableAcceleratedNetworking:enableAcceleratedNetworking,networkSecurityGroupId:networkSecurityGroup.id,ipConfigurations:ipConfigurations[].{name:name,primary:primary,privateIPAddress:privateIPAddress,privateIPAllocationMethod:privateIPAllocationMethod,privateIPAddressVersion:privateIPAddressVersion,subnetId:subnet.id,publicIpId:publicIPAddress.id}}",
        ],
        "{} NIC".format(node),
        runner,
    )
    nsg = _json_from_runner(
        [
            "az", "network", "nsg", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", node + "-nsg", *common, "--query",
            "{id:id,name:name,location:location,provisioningState:provisioningState,tags:tags,networkInterfaceIds:networkInterfaces[].id,subnetIds:subnets[].id}",
        ],
        "{} NSG".format(node),
        runner,
    )
    public_ip = _json_from_runner(
        [
            "az", "network", "public-ip", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", node + "-pip", *common, "--query",
            "{id:id,name:name,location:location,provisioningState:provisioningState,tags:tags,ipAddress:ipAddress,publicIPAllocationMethod:publicIPAllocationMethod,publicIPAddressVersion:publicIPAddressVersion,skuName:sku.name,skuTier:sku.tier,ipConfigurationId:ipConfiguration.id}",
        ],
        "{} public IP".format(node),
        runner,
    )
    result: Dict[str, Any] = {
        "name": node,
        "nic": nic,
        "nsg": nsg,
        "powerState": power,
        "publicIp": public_ip,
        "vm": vm,
    }
    if include_disk:
        result["disk"] = _json_from_runner(
            [
                "az", "disk", "show", "--ids",
                _resource_id("Microsoft.Compute/disks", node + "-osdisk"),
                *common, "--query",
                "{id:id,name:name,managedBy:managedBy,provisioningState:provisioningState,publicNetworkAccess:publicNetworkAccess,networkAccessPolicy:networkAccessPolicy,tags:tags}",
            ],
            "{} OS disk".format(node),
            runner,
        )
    return result


def collect_live_observations(path: Path, *, runner: Runner = _run) -> Dict[str, Any]:
    common = ["--subscription", EXPECTED_SUBSCRIPTION_ID, "--output", "json", "--only-show-errors"]
    account = _json_from_runner(
        ["az", "account", "show", *common, "--query", "{id:id,tenantId:tenantId,state:state}"],
        "account",
        runner,
    )
    providers = [
        _json_from_runner(
            [
                "az", "provider", "show", "--namespace", namespace, *common,
                "--query", "{namespace:namespace,registrationState:registrationState}",
            ],
            namespace,
            runner,
        )
        for namespace in EXPECTED_PROVIDER_NAMESPACES
    ]
    group = _json_from_runner(
        ["az", "group", "show", "--name", EXPECTED_RESOURCE_GROUP, *common],
        "resource group",
        runner,
    )
    resources = _json_from_runner(
        ["az", "resource", "list", "--resource-group", EXPECTED_RESOURCE_GROUP, *common],
        "resource inventory",
        runner,
    )
    replacement_vm_ids = {
        _resource_id("Microsoft.Compute/virtualMachines", node).lower(): node
        for node in EXPECTED_REPLACEMENT_VM_NAMES
    }
    present_replacement_nodes = {
        replacement_vm_ids[str(item.get("id", "")).lower()]
        for item in resources
        if isinstance(item, dict)
        and str(item.get("id", "")).lower() in replacement_vm_ids
    }
    nodes = [
        _read_node_observation(node, include_disk=False, runner=runner)
        for node in ("viv-sbc-poc-cp1", *EXPECTED_SYNTHETIC_VM_NAMES)
    ] + [
        _read_node_observation(node, include_disk=True, runner=runner)
        for node in sorted(present_replacement_nodes)
    ]
    vnet = _json_from_runner(
        [
            "az", "network", "vnet", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", EXPECTED_VNET_NAME, *common, "--query",
            "{id:id,name:name,location:location,tags:tags,addressPrefixes:addressSpace.addressPrefixes,dnsServers:dhcpOptions.dnsServers,ddosProtection:enableDdosProtection,peerings:virtualNetworkPeerings[].id,subnets:subnets[].{id:id,name:name,addressPrefix:addressPrefix,addressPrefixes:addressPrefixes,defaultOutboundAccess:defaultOutboundAccess,delegations:delegations[].id,ipConfigurationIds:ipConfigurations[].id,networkSecurityGroupId:networkSecurityGroup.id,natGatewayId:natGateway.id,routeTableId:routeTable.id,privateEndpointNetworkPolicies:privateEndpointNetworkPolicies,privateLinkServiceNetworkPolicies:privateLinkServiceNetworkPolicies,privateEndpointIds:privateEndpoints[].id,serviceEndpoints:serviceEndpoints[].service,serviceEndpointPolicyIds:serviceEndpointPolicies[].id,provisioningState:provisioningState},provisioningState:provisioningState}",
        ],
        "VNet topology",
        runner,
    )
    availability_set = _json_from_runner(
        [
            "az", "vm", "availability-set", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
            "--name", EXPECTED_AVAILABILITY_SET_NAME, *common, "--query",
            "{id:id,name:name,location:location,tags:tags,sku:sku.name,faultDomains:platformFaultDomainCount,updateDomains:platformUpdateDomainCount,vmIds:virtualMachines[].id}",
        ],
        "availability set",
        runner,
    )
    budget_url = (
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/"
        "Microsoft.Consumption/budgets/{}?api-version=2023-11-01"
    ).format(
        EXPECTED_SUBSCRIPTION_ID,
        EXPECTED_RESOURCE_GROUP,
        EXPECTED_BUDGET_NAME,
    )
    budget = _json_from_runner(
        ["az", "rest", "--method", "get", "--url", budget_url, *common],
        "budget",
        runner,
    )
    what_if = _json_from_runner(
        [
            "az", "deployment", "sub", "what-if", "--name", DEPLOYMENT_NAME,
            "--location", EXPECTED_LOCATION, "--parameters", str(path),
            "--result-format", "ResourceIdOnly", "--no-pretty-print",
            "--validation-level", "Provider", *common,
        ],
        "provider-level what-if",
        runner,
    )
    return {
        "account": account,
        "availabilitySet": availability_set,
        "budget": budget,
        "providers": providers,
        "resourceGroup": group,
        "resources": resources,
        "nodes": nodes,
        "vnet": vnet,
        "whatIf": what_if,
    }


def _parse_canonical_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PreflightError("{} must be canonical UTC".format(label))
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise PreflightError("{} must be canonical UTC".format(label)) from exc


def _read_protected_json(
    path: Path, *, label: str, expected_path: Path | None = None
) -> Dict[str, Any]:
    if path.is_symlink():
        raise PreflightError("{} must not be a symbolic link".format(label))
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise PreflightError("{} is not a readable regular file".format(label)) from exc
    if (
        (expected_path is not None and resolved != expected_path.resolve())
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        or metadata.st_nlink != 1
    ):
        raise PreflightError(
            "{} must be the exact owner-only 0400/0600 file".format(label)
        )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PreflightError("{} is malformed JSON".format(label)) from exc
    if not isinstance(value, dict):
        raise PreflightError("{} must contain one JSON object".format(label))
    return value


def _read_saved_plan(path: Path) -> Dict[str, Any]:
    return _read_protected_json(
        path, label="live plan file", expected_path=EXPECTED_LIVE_PLAN_PATH
    )


def _read_protected_bytes(path: Path, *, label: str, expected_path: Path) -> bytes:
    if path.is_symlink():
        raise PreflightError("{} must not be a symbolic link".format(label))
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        content = resolved.read_bytes()
    except OSError as exc:
        raise PreflightError("{} is not a readable regular file".format(label)) from exc
    if (
        resolved != expected_path.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o500}
        or metadata.st_nlink != 1
    ):
        raise PreflightError(
            "{} must be the exact owner-only single-link 0400/0500 file".format(label)
        )
    return content


def _write_protected_bytes(
    path: Path, content: bytes, *, label: str, expected_path: Path
) -> None:
    if path != expected_path or path.parent.resolve() != expected_path.parent.resolve():
        raise PreflightError("{} output path is not exact".format(label))
    if path.is_symlink():
        raise PreflightError("{} output must not be a symbolic link".format(label))
    if path.exists():
        if _read_protected_bytes(path, label=label, expected_path=expected_path) != content:
            raise PreflightError("existing {} bytes differ from the approved contract".format(label))
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise PreflightError("could not create protected {}".format(label)) from exc


def _replacement_vm_ids() -> list[str]:
    return [
        _resource_id("Microsoft.Compute/virtualMachines", node)
        for node in EXPECTED_REPLACEMENT_VM_NAMES
    ]


def _predecessor_vm_ids() -> list[str]:
    return [
        _resource_id("Microsoft.Compute/virtualMachines", node)
        for node in EXPECTED_SYNTHETIC_VM_NAMES
    ]


def _runtime_executable_identity(path: Path, *, label: str) -> Dict[str, str]:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        content = resolved.read_bytes()
    except OSError as exc:
        raise PreflightError("{} runtime executable is unavailable".format(label)) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise PreflightError("{} runtime executable is not a regular executable".format(label))
    return {
        "path": str(path),
        "resolvedPath": str(resolved),
        "sha256": _sha256_bytes(content),
    }


def _deadman_bundle_contract(plan: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "apiVersion": "vivolution.ae/direct-replacement-deadman/v0.1",
        "deadlineUtc": plan["parallelAcceptance"]["deadlineUtc"],
        "planSha256": plan["planSha256"],
        "protectedPredecessorVmIds": _predecessor_vm_ids(),
        "replacementVmIds": _replacement_vm_ids(),
        "resourceGroup": EXPECTED_RESOURCE_GROUP,
        "runtimeExecutables": {
            "azureCli": _runtime_executable_identity(
                EXPECTED_AZ_CLI, label="Azure CLI"
            ),
            "openclaw": _runtime_executable_identity(
                EXPECTED_OPENCLAW_CLI, label="OpenClaw CLI"
            ),
            "python": _runtime_executable_identity(
                EXPECTED_DEADMAN_PYTHON, label="Python"
            ),
        },
        "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
        "tenantId": EXPECTED_TENANT_ID,
    }


def _deadman_bundle_source(plan: Mapping[str, Any]) -> bytes:
    contract_json = json.dumps(
        _deadman_bundle_contract(plan), sort_keys=True, separators=(",", ":")
    )
    source = '''#!/opt/homebrew/bin/python3.13
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

CONTRACT = json.loads(__CONTRACT_JSON__)
RUN_BUDGET_SECONDS = 840
COMMAND_TIMEOUT_SECONDS = 45
RETRY_DELAY_SECONDS = 10
STARTED_MONOTONIC = time.monotonic()

def remaining_seconds():
    return RUN_BUDGET_SECONDS - (time.monotonic() - STARTED_MONOTONIC)

def run_once(argv):
    remaining = remaining_seconds()
    if remaining <= 1:
        raise RuntimeError("deadman retry budget exhausted")
    try:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, min(COMMAND_TIMEOUT_SECONDS, int(remaining))),
        )
    except subprocess.TimeoutExpired:
        return None

def retry_json(argv, *, maximum_attempts=3):
    for attempt in range(maximum_attempts):
        print(
            "DIRECT_REPLACEMENT_DEADMAN_PROGRESS: bounded query attempt {}/{}".format(
                attempt + 1, maximum_attempts
            ),
            file=sys.stderr,
            flush=True,
        )
        result = run_once(argv)
        if result is not None and result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except (TypeError, ValueError):
                pass
        if attempt + 1 < maximum_attempts:
            delay = min(RETRY_DELAY_SECONDS, max(0, remaining_seconds() - 1))
            if delay > 0:
                time.sleep(delay)
    raise RuntimeError("bounded Azure query failed after retries")

def verify_executable(identity):
    if os.path.realpath(identity["path"]) != identity["resolvedPath"]:
        raise RuntimeError("deadman runtime executable target drifted")
    with open(identity["resolvedPath"], "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if digest != identity["sha256"]:
        raise RuntimeError("deadman runtime executable bytes drifted")

def normalize_inventory(inventory):
    if not isinstance(inventory, list):
        raise RuntimeError("replacement VM inventory is malformed")
    expected = {value.lower(): value for value in CONTRACT["replacementVmIds"]}
    present = {}
    for item in inventory:
        if not isinstance(item, dict):
            raise RuntimeError("replacement VM inventory contains malformed data")
        resource_id = str(item.get("id", "")).lower()
        if resource_id in expected:
            if resource_id in present or item.get("name") != expected[resource_id].rsplit("/", 1)[-1]:
                raise RuntimeError("replacement VM identity is ambiguous")
            present[resource_id] = expected[resource_id]
    return present

def main():
    deadline = datetime.strptime(CONTRACT["deadlineUtc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) < deadline:
        raise RuntimeError("replacement deadman refuses to run before its immutable deadline")
    verify_executable(CONTRACT["runtimeExecutables"]["azureCli"])
    verify_executable(CONTRACT["runtimeExecutables"]["openclaw"])
    verify_executable(CONTRACT["runtimeExecutables"]["python"])
    azure_cli = CONTRACT["runtimeExecutables"]["azureCli"]["path"]
    common = ["--subscription", CONTRACT["subscriptionId"], "--output", "json", "--only-show-errors"]
    account = retry_json([azure_cli, "account", "show", *common, "--query", "{id:id,tenantId:tenantId,state:state}"])
    if account != {"id": CONTRACT["subscriptionId"], "state": "Enabled", "tenantId": CONTRACT["tenantId"]}:
        raise RuntimeError("replacement deadman Azure authority drifted")
    inventory = retry_json([azure_cli, "vm", "list", "--resource-group", CONTRACT["resourceGroup"], *common, "--query", "[].{id:id,name:name}"])
    present = normalize_inventory(inventory)
    changed = set()
    verified = set()
    pending = list(CONTRACT["replacementVmIds"])
    while pending and remaining_seconds() > (COMMAND_TIMEOUT_SECONDS * 3) + 1:
        print(
            "DIRECT_REPLACEMENT_DEADMAN_PROGRESS: {} replacement VM(s) pending".format(
                len(pending)
            ),
            file=sys.stderr,
            flush=True,
        )
        inventory_result = run_once([azure_cli, "vm", "list", "--resource-group", CONTRACT["resourceGroup"], *common, "--query", "[].{id:id,name:name}"])
        if inventory_result is not None and inventory_result.returncode == 0:
            try:
                present = normalize_inventory(json.loads(inventory_result.stdout))
            except (TypeError, ValueError):
                pass
        next_pending = []
        for resource_id in CONTRACT["replacementVmIds"]:
            if resource_id.lower() not in present:
                next_pending.append(resource_id)
                continue
            power_result = run_once([azure_cli, "vm", "get-instance-view", "--ids", resource_id, *common, "--query", "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]"])
            power = None
            if power_result is not None and power_result.returncode == 0:
                try:
                    power = json.loads(power_result.stdout)
                except (TypeError, ValueError):
                    pass
            if power == "PowerState/deallocated":
                verified.add(resource_id)
                continue
            deallocate_result = run_once([azure_cli, "vm", "deallocate", "--ids", resource_id, "--subscription", CONTRACT["subscriptionId"], "--only-show-errors"])
            if deallocate_result is not None and deallocate_result.returncode == 0:
                changed.add(resource_id)
            next_pending.append(resource_id)
        pending = next_pending
        if pending:
            delay = min(RETRY_DELAY_SECONDS, max(0, remaining_seconds() - 1))
            if delay > 0:
                time.sleep(delay)
    final_pending = []
    final_inventory_result = run_once([azure_cli, "vm", "list", "--resource-group", CONTRACT["resourceGroup"], *common, "--query", "[].{id:id,name:name}"])
    if final_inventory_result is not None and final_inventory_result.returncode == 0:
        try:
            present = normalize_inventory(json.loads(final_inventory_result.stdout))
        except (TypeError, ValueError):
            pass
    absent = []
    for resource_id in CONTRACT["replacementVmIds"]:
        if resource_id.lower() not in present:
            absent.append(resource_id)
            continue
        power_result = run_once([azure_cli, "vm", "get-instance-view", "--ids", resource_id, *common, "--query", "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]"])
        power = None
        if power_result is not None and power_result.returncode == 0:
            try:
                power = json.loads(power_result.stdout)
            except (TypeError, ValueError):
                pass
        if power == "PowerState/deallocated":
            verified.add(resource_id)
        else:
            final_pending.append(resource_id)
    if final_pending:
        raise RuntimeError("one or more exact replacement VMs could not be deallocated")
    print(json.dumps({"absentReplacementVmIds": sorted(absent), "changedReplacementVmIds": sorted(changed), "deadlineUtc": CONTRACT["deadlineUtc"], "planSha256": CONTRACT["planSha256"], "protectedPredecessorVmIds": CONTRACT["protectedPredecessorVmIds"], "status": "DIRECT_REPLACEMENT_DEADMAN_ENFORCED", "verifiedDeallocatedReplacementVmIds": sorted(verified)}, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("DIRECT_REPLACEMENT_DEADMAN_FAILED: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)
'''.replace("__CONTRACT_JSON__", repr(contract_json))
    return source.encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _deadman_job_name(plan: Mapping[str, Any]) -> str:
    return "viv-sbc-g3-deadman-{}".format(plan["planSha256"][:12])


def _deadman_job_description(plan: Mapping[str, Any]) -> str:
    return "planSha256={};deadlineUtc={};replacementVmIds={}".format(
        plan["planSha256"],
        plan["parallelAcceptance"]["deadlineUtc"],
        ",".join(_replacement_vm_ids()),
    )


def _deadman_command_contract(plan: Mapping[str, Any]) -> Dict[str, Any]:
    embedded_source = _deadman_bundle_source(plan).decode("utf-8")
    argv = [str(EXPECTED_DEADMAN_PYTHON), "-c", embedded_source]
    return {
        "argv": argv,
        "cwd": str(PROJECT_ROOT),
        "embeddedProgramSha256": _sha256_bytes(embedded_source.encode("utf-8")),
        "sha256": _canonical_digest({"argv": argv, "cwd": str(PROJECT_ROOT)}),
    }


def _deadman_cron_add_argv(plan: Mapping[str, Any]) -> list[str]:
    command = _deadman_command_contract(plan)
    return [
        str(EXPECTED_OPENCLAW_CLI),
        "cron",
        "add",
        "--name",
        _deadman_job_name(plan),
        "--declaration-key",
        "vivolution-direct-replacement-deadman:{}".format(plan["planSha256"]),
        "--display-name",
        "Vivolution g3 replacement budget deadman",
        "--description",
        _deadman_job_description(plan),
        "--agent",
        OPENCLAW_AGENT_ID,
        "--session",
        "isolated",
        "--wake",
        "now",
        "--at",
        plan["parallelAcceptance"]["deadlineUtc"],
        "--exact",
        "--delete-after-run",
        "--command-argv",
        json.dumps(command["argv"], separators=(",", ":")),
        "--command-cwd",
        command["cwd"],
        "--timeout-seconds",
        str(OPENCLAW_COMMAND_TIMEOUT_SECONDS),
        "--no-output-timeout-seconds",
        str(OPENCLAW_NO_OUTPUT_TIMEOUT_SECONDS),
        "--output-max-bytes",
        str(OPENCLAW_OUTPUT_MAX_BYTES),
        "--announce",
        "--channel",
        OPENCLAW_NOTIFICATION_CHANNEL,
        "--to",
        OPENCLAW_NOTIFICATION_TARGET,
        "--account",
        OPENCLAW_NOTIFICATION_ACCOUNT,
        "--json",
    ]


def _expected_deadman_payload(plan: Mapping[str, Any]) -> Dict[str, Any]:
    command = _deadman_command_contract(plan)
    return {
        "argv": command["argv"],
        "cwd": command["cwd"],
        "kind": "command",
        "noOutputTimeoutSeconds": OPENCLAW_NO_OUTPUT_TIMEOUT_SECONDS,
        "outputMaxBytes": OPENCLAW_OUTPUT_MAX_BYTES,
        "timeoutSeconds": OPENCLAW_COMMAND_TIMEOUT_SECONDS,
    }


def _expected_deadman_delivery() -> Dict[str, str]:
    return {
        "accountId": OPENCLAW_NOTIFICATION_ACCOUNT,
        "channel": OPENCLAW_NOTIFICATION_CHANNEL,
        "mode": "announce",
        "to": OPENCLAW_NOTIFICATION_TARGET,
    }


def _canonical_millisecond(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _normalize_live_deadman_job(
    job: Any,
    plan: Mapping[str, Any],
    *,
    job_id: str,
    now: datetime,
) -> Dict[str, Any]:
    try:
        if str(uuid.UUID(job_id)) != job_id:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise PreflightError("OpenClaw deadman job ID is not one canonical UUID") from exc
    observed = _parse_canonical_utc(plan["observedAtUtc"], "observedAtUtc")
    authorization_expiry = _parse_canonical_utc(
        plan["authorizationExpiresUtc"], "authorizationExpiresUtc"
    )
    deadline = _parse_canonical_utc(
        plan["parallelAcceptance"]["deadlineUtc"], "parallel deadline"
    )
    if not isinstance(job, dict):
        raise PreflightError("OpenClaw cron get returned malformed job data")
    created_at_ms = job.get("createdAtMs")
    updated_at_ms = job.get("updatedAtMs")
    state = job.get("state")
    if (
        job.get("id") != job_id
        or job.get("declarationKey")
        != "vivolution-direct-replacement-deadman:{}".format(plan["planSha256"])
        or job.get("displayName") != "Vivolution g3 replacement budget deadman"
        or job.get("name") != _deadman_job_name(plan)
        or job.get("description") != _deadman_job_description(plan)
        or job.get("enabled") is not True
        or job.get("deleteAfterRun") is not True
        or job.get("agentId") != OPENCLAW_AGENT_ID
        or job.get("sessionTarget") != "isolated"
        or job.get("wakeMode") != "now"
        or job.get("schedule")
        != {
            "at": plan["parallelAcceptance"]["deadlineUtc"],
            "kind": "at",
        }
        or job.get("payload") != _expected_deadman_payload(plan)
        or job.get("delivery") != _expected_deadman_delivery()
        or not isinstance(created_at_ms, int)
        or isinstance(created_at_ms, bool)
        or not isinstance(updated_at_ms, int)
        or isinstance(updated_at_ms, bool)
        or created_at_ms < _canonical_millisecond(observed)
        or created_at_ms > _canonical_millisecond(authorization_expiry)
        or updated_at_ms < created_at_ms
        # issuedAtUtc is canonical to seconds; a live job update within that same
        # observed second is not future state.
        or updated_at_ms > _canonical_millisecond(now) + 999
        or not isinstance(state, dict)
        or state.get("nextRunAtMs") != _canonical_millisecond(deadline)
        or state.get("runningAtMs") is not None
        or state.get("lastRunAtMs") is not None
    ):
        raise PreflightError("live OpenClaw deadman job drifted from the exact one-shot command")
    return {
        "agentId": OPENCLAW_AGENT_ID,
        "createdAtMs": created_at_ms,
        "declarationKey": job["declarationKey"],
        "deleteAfterRun": True,
        "delivery": _expected_deadman_delivery(),
        "description": job["description"],
        "displayName": job["displayName"],
        "enabled": True,
        "id": job_id,
        "name": job["name"],
        "payload": job["payload"],
        "schedule": job["schedule"],
        "sessionTarget": "isolated",
        "state": {"nextRunAtMs": state["nextRunAtMs"]},
        "updatedAtMs": updated_at_ms,
        "wakeMode": "now",
    }


def _query_live_deadman_job(
    job_id: str, *, scheduler_runner: Runner
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    status = _json_from_runner(
        [str(EXPECTED_OPENCLAW_CLI), "cron", "status"],
        "OpenClaw cron scheduler status",
        scheduler_runner,
    )
    job = _json_from_runner(
        [str(EXPECTED_OPENCLAW_CLI), "cron", "get", job_id],
        "OpenClaw deadman job",
        scheduler_runner,
    )
    return status, job


def _validate_scheduler_status(
    status: Any, *, now: datetime, deadline: datetime
) -> Dict[str, Any]:
    if (
        not isinstance(status, dict)
        or status.get("enabled") is not True
        or status.get("storage") != "sqlite"
        or not isinstance(status.get("jobs"), int)
        or isinstance(status.get("jobs"), bool)
        or status["jobs"] < 1
        or not isinstance(status.get("nextWakeAtMs"), int)
        or isinstance(status.get("nextWakeAtMs"), bool)
        or status["nextWakeAtMs"] < _canonical_millisecond(now)
        or status["nextWakeAtMs"] > _canonical_millisecond(deadline)
    ):
        raise PreflightError("OpenClaw cron scheduler is not healthy and durably armed")
    return {
        "enabled": True,
        "nextWakeAtMs": status["nextWakeAtMs"],
        "storage": "sqlite",
    }


def prepare_deadman_bundle(
    plan: Mapping[str, Any], *, output_path: Path
) -> Dict[str, Any]:
    _runtime_executable_identity(EXPECTED_DEADMAN_PYTHON, label="Python")
    _runtime_executable_identity(EXPECTED_AZ_CLI, label="Azure CLI")
    content = _deadman_bundle_source(plan)
    _write_protected_bytes(
        output_path,
        content,
        label="sealed deadman bundle",
        expected_path=EXPECTED_DEADMAN_BUNDLE_PATH,
    )
    command = _deadman_command_contract(plan)
    return {
        "bundlePath": str(EXPECTED_DEADMAN_BUNDLE_PATH),
        "bundleSha256": _sha256_bytes(content),
        "command": command,
        "deadlineUtc": plan["parallelAcceptance"]["deadlineUtc"],
        "planSha256": plan["planSha256"],
        "scheduleCommandArgv": _deadman_cron_add_argv(plan),
        "status": "DIRECT_REPLACEMENT_DEADMAN_EVIDENCE_PREPARED",
    }


def _scheduler_host_name() -> str:
    host_name = socket.gethostname()
    if (
        not isinstance(host_name, str)
        or not host_name
        or host_name in EXPECTED_REPLACEMENT_VM_NAMES
        or host_name.split(".", 1)[0] in EXPECTED_REPLACEMENT_VM_NAMES
    ):
        raise PreflightError("scheduler host is not an external OpenClaw gateway")
    return host_name


def build_deadman_scheduler_receipt(
    plan: Mapping[str, Any],
    *,
    job_id: str,
    now: datetime,
    scheduler_runner: Runner,
    host_name: str | None = None,
) -> Dict[str, Any]:
    observed_current = now.astimezone(timezone.utc)
    current = observed_current.replace(microsecond=0)
    authorization_expiry = _parse_canonical_utc(
        plan["authorizationExpiresUtc"], "authorizationExpiresUtc"
    )
    observed = _parse_canonical_utc(plan["observedAtUtc"], "observedAtUtc")
    if observed_current < observed or observed_current > authorization_expiry:
        raise PreflightError("scheduler receipt is outside the live create authorization")
    embedded_program = _deadman_bundle_source(plan)
    status, job = _query_live_deadman_job(job_id, scheduler_runner=scheduler_runner)
    normalized_job = _normalize_live_deadman_job(
        job, plan, job_id=job_id, now=current
    )
    deadline = _parse_canonical_utc(
        plan["parallelAcceptance"]["deadlineUtc"], "parallel deadline"
    )
    normalized_status = _validate_scheduler_status(
        status, now=current, deadline=deadline
    )
    gateway_host = host_name or _scheduler_host_name()
    if (
        not isinstance(gateway_host, str)
        or not gateway_host
        or gateway_host.split(".", 1)[0] in EXPECTED_REPLACEMENT_VM_NAMES
    ):
        raise PreflightError("deadman scheduler cannot run on a replacement VM")
    body: Dict[str, Any] = {
        "apiVersion": "vivolution.ae/direct-replacement-scheduler-receipt/v0.1",
        "embeddedProgram": {
            "bytes": len(embedded_program),
            "runtimeExecutables": _deadman_bundle_contract(plan)[
                "runtimeExecutables"
            ],
            "sha256": _sha256_bytes(embedded_program),
        },
        "command": _deadman_command_contract(plan),
        "issuedAtUtc": current.isoformat().replace("+00:00", "Z"),
        "job": {
            "contractSha256": _canonical_digest(normalized_job),
            "createdAtMs": normalized_job["createdAtMs"],
            "id": job_id,
            "scheduledAtUtc": plan["parallelAcceptance"]["deadlineUtc"],
            "updatedAtMs": normalized_job["updatedAtMs"],
        },
        "plan": {
            "authorizationExpiresUtc": plan["authorizationExpiresUtc"],
            "deadlineUtc": plan["parallelAcceptance"]["deadlineUtc"],
            "observedAtUtc": plan["observedAtUtc"],
            "planSha256": plan["planSha256"],
            "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
            "tenantId": EXPECTED_TENANT_ID,
        },
        "protectedPredecessorVmIds": _predecessor_vm_ids(),
        "replacementVmIds": _replacement_vm_ids(),
        "scheduler": {
            "agentId": OPENCLAW_AGENT_ID,
            "gatewayHost": gateway_host,
            "gatewayHostSha256": hashlib.sha256(
                gateway_host.encode("utf-8")
            ).hexdigest(),
            "sessionTarget": "isolated",
            **normalized_status,
        },
        "status": "DIRECT_REPLACEMENT_DEADMAN_SCHEDULER_RECEIPT_VALID",
    }
    return {**body, "receiptSha256": _canonical_digest(body)}


def validate_deadman_scheduler_receipt(
    receipt: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    now: datetime,
    scheduler_runner: Runner,
    host_name: str | None = None,
) -> Dict[str, Any]:
    exact_keys = {
        "apiVersion",
        "command",
        "embeddedProgram",
        "issuedAtUtc",
        "job",
        "plan",
        "protectedPredecessorVmIds",
        "receiptSha256",
        "replacementVmIds",
        "scheduler",
        "status",
    }
    if set(receipt) != exact_keys:
        raise PreflightError("scheduler receipt shape is not exact")
    body = {key: receipt[key] for key in sorted(receipt) if key != "receiptSha256"}
    if receipt.get("receiptSha256") != _canonical_digest(body):
        raise PreflightError("scheduler receipt digest does not match its canonical body")
    current = now.astimezone(timezone.utc)
    issued = _parse_canonical_utc(receipt.get("issuedAtUtc"), "receipt issuedAtUtc")
    if (
        issued > current
        or current - issued > timedelta(minutes=SCHEDULER_RECEIPT_MAX_AGE_MINUTES)
        or issued
        > _parse_canonical_utc(
            plan["authorizationExpiresUtc"], "authorizationExpiresUtc"
        )
    ):
        raise PreflightError("scheduler receipt is stale or post-authorization")
    job = receipt.get("job")
    if not isinstance(job, dict) or not isinstance(job.get("id"), str):
        raise PreflightError("scheduler receipt lacks one exact live job ID")
    rebuilt = build_deadman_scheduler_receipt(
        plan,
        job_id=job["id"],
        now=issued,
        scheduler_runner=scheduler_runner,
        host_name=host_name,
    )
    if receipt != rebuilt:
        raise PreflightError("scheduler receipt differs from the current live OpenClaw job")
    return dict(receipt)


def issue_deadman_scheduler_receipt(
    plan: Mapping[str, Any],
    *,
    job_id: str,
    output_path: Path,
    now: datetime,
    scheduler_runner: Runner,
    host_name: str | None = None,
) -> Dict[str, Any]:
    receipt = build_deadman_scheduler_receipt(
        plan,
        job_id=job_id,
        now=now,
        scheduler_runner=scheduler_runner,
        host_name=host_name,
    )
    _write_protected_bytes(
        output_path,
        (
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8"),
        label="deadman scheduler receipt",
        expected_path=EXPECTED_SCHEDULER_RECEIPT_PATH,
    )
    return receipt


def _read_scheduler_receipt(path: Path) -> Dict[str, Any]:
    return _read_protected_json(
        path,
        label="deadman scheduler receipt",
        expected_path=EXPECTED_SCHEDULER_RECEIPT_PATH,
    )


def validate_saved_plan(
    plan: Mapping[str, Any],
    package_evidence: Mapping[str, Any],
    *,
    approved_plan_sha256: str,
    expected_compiled_parameters_sha256: str,
    expected_compiled_template_sha256: str,
    expected_bicep_version: str,
    expected_subscription_id: str,
    expected_tenant_id: str,
    now: datetime | None = None,
    require_create_authorization: bool = True,
) -> Dict[str, Any]:
    exact_keys = {
        "authority",
        "authorizationExpiresUtc",
        "bicepCompilerVersion",
        "budget",
        "compiledParametersSha256",
        "compiledTemplateSha256",
        "deploymentName",
        "observedAtUtc",
        "parallelAcceptance",
        "partialDeploymentResume",
        "planSha256",
        "runtimeAuthority",
        "status",
        "topology",
        "whatIf",
    }
    if set(plan) != exact_keys or plan.get("status") != "DIRECT_REPLACEMENT_LIVE_PLAN_VALID":
        raise PreflightError("saved live plan shape or status is not exact")
    body = {key: plan[key] for key in sorted(plan) if key not in {"planSha256", "status"}}
    actual_plan_sha256 = _canonical_digest(body)
    if (
        not isinstance(approved_plan_sha256, str)
        or actual_plan_sha256 != approved_plan_sha256
        or plan.get("planSha256") != approved_plan_sha256
    ):
        raise PreflightError("saved live plan digest is not the separately approved digest")
    authority = plan.get("authority")
    if (
        expected_subscription_id != EXPECTED_SUBSCRIPTION_ID
        or expected_tenant_id != EXPECTED_TENANT_ID
        or not isinstance(authority, dict)
        or authority.get("subscriptionId") != expected_subscription_id
        or authority.get("tenantId") != expected_tenant_id
        or authority.get("providerValidationLevel") != "Provider"
        or authority.get("resourceGroup") != EXPECTED_RESOURCE_GROUP
        or plan.get("deploymentName") != DEPLOYMENT_NAME
    ):
        raise PreflightError("saved plan subscription/tenant/provider authority drifted")
    digest_contract = {
        "bicepCompilerVersion": expected_bicep_version,
        "compiledParametersSha256": expected_compiled_parameters_sha256,
        "compiledTemplateSha256": expected_compiled_template_sha256,
    }
    if (
        expected_bicep_version != EXPECTED_BICEP_VERSION
        or expected_compiled_template_sha256 != EXPECTED_COMPILED_TEMPLATE_SHA256
        or any(plan.get(key) != value for key, value in digest_contract.items())
        or any(package_evidence.get(key) != value for key, value in digest_contract.items())
    ):
        raise PreflightError("compiler/template/parameter digest authority drifted")
    if plan.get("runtimeAuthority") != {
        "generation": FIXED_VALUES["edgeGeneration"],
        "profile": FIXED_VALUES["edgeRuntimeProfile"],
    } or plan.get("runtimeAuthority") != {
        "generation": package_evidence.get("edgeGeneration"),
        "profile": package_evidence.get("edgeRuntimeProfile"),
    }:
        raise PreflightError("saved plan runtime authority drifted")
    current = (now or _utc_now()).astimezone(timezone.utc).replace(
        microsecond=0
    )
    authorization_expiry = _parse_canonical_utc(
        plan.get("authorizationExpiresUtc"), "authorizationExpiresUtc"
    )
    parallel = plan.get("parallelAcceptance")
    deadline = (
        _parse_canonical_utc(parallel.get("deadlineUtc"), "parallel deadline")
        if isinstance(parallel, dict)
        else None
    )
    observed = (
        _parse_canonical_utc(plan["observedAtUtc"], "observedAtUtc")
        if plan.get("observedAtUtc") is not None
        else None
    )
    if (
        deadline is None
        or observed is None
        or observed > current
        or observed >= authorization_expiry
        or deadline <= observed
        or deadline > observed + timedelta(hours=MAXIMUM_PARALLEL_ACCEPTANCE_HOURS)
        or authorization_expiry
        != min(deadline, observed + timedelta(minutes=LIVE_PLAN_MAX_AGE_MINUTES))
    ):
        raise PreflightError(
            "saved live plan observation/create-authorization interval is invalid"
        )
    if require_create_authorization and deadline <= current:
        raise PreflightError("immutable parallel acceptance deadline has expired")
    if require_create_authorization and authorization_expiry <= current:
        raise PreflightError("live create authorization has expired")
    if package_evidence.get("parallelAcceptanceDeadlineUtc") != parallel.get(
        "deadlineUtc"
    ):
        raise PreflightError("compiled parameter deadline differs from the saved plan")
    if parallel != {
        "deadlineUtc": package_evidence["parallelAcceptanceDeadlineUtc"],
        "maximumHours": MAXIMUM_PARALLEL_ACCEPTANCE_HOURS,
        "requiredDisposition": "deallocate-after-final-acceptance-and-no-later-than-deadline",
        "syntheticPredecessorVmNames": list(EXPECTED_SYNTHETIC_VM_NAMES),
    }:
        raise PreflightError("saved plan parallel/deallocation authority drifted")
    return dict(plan)


def _require_same_fresh_authority(
    saved: Mapping[str, Any], fresh: Mapping[str, Any]
) -> None:
    exact_fields = (
        "authority",
        "bicepCompilerVersion",
        "compiledParametersSha256",
        "compiledTemplateSha256",
        "deploymentName",
        "parallelAcceptance",
        "partialDeploymentResume",
        "runtimeAuthority",
        "topology",
        "whatIf",
    )
    if any(saved.get(field) != fresh.get(field) for field in exact_fields):
        raise PreflightError(
            "fresh provider what-if/topology no longer equals the approved live plan"
        )


def _explicit_deployment_not_found(stderr: str) -> bool:
    lines = {line.strip() for line in stderr.splitlines() if line.strip()}
    return "Code: DeploymentNotFound" in lines and any(
        line.startswith("ERROR: (DeploymentNotFound)")
        or line.startswith("(DeploymentNotFound)")
        for line in lines
    )


def _deployment_terminal_state_after_cancel() -> str:
    cancel_argv = [
        str(EXPECTED_AZ_CLI),
        "deployment",
        "sub",
        "cancel",
        "--name",
        DEPLOYMENT_NAME,
        "--subscription",
        EXPECTED_SUBSCRIPTION_ID,
        "--output",
        "none",
        "--only-show-errors",
    ]
    try:
        subprocess.run(
            cancel_argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=DEPLOYMENT_CANCEL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pass
    terminal = {"Absent", "Canceled", "Cancelled", "Failed", "Succeeded"}
    deadline = time.monotonic() + DEPLOYMENT_SETTLE_TIMEOUT_SECONDS
    show_argv = [
        str(EXPECTED_AZ_CLI),
        "deployment",
        "sub",
        "show",
        "--name",
        DEPLOYMENT_NAME,
        "--subscription",
        EXPECTED_SUBSCRIPTION_ID,
        "--query",
        "properties.provisioningState",
        "--output",
        "tsv",
        "--only-show-errors",
    ]
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        try:
            result = subprocess.run(
                show_argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=min(30, remaining),
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            state = result.stdout.strip()
        elif _explicit_deployment_not_found(result.stderr):
            state = "Absent"
        else:
            time.sleep(min(5, max(0, deadline - time.monotonic())))
            continue
        if state in terminal:
            return state
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    raise PreflightError(
        "timed-out Azure deployment did not reach a terminal state after cancellation"
    )


def _run_interactive(
    argv: Sequence[str], *, timeout_seconds: int = DEPLOYMENT_SETTLE_TIMEOUT_SECONDS
) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        if list(argv)[1:4] == ["deployment", "sub", "create"]:
            terminal_state = _deployment_terminal_state_after_cancel()
            raise PreflightError(
                "interactive Azure deployment exceeded its authorization and was bounded in state {}".format(
                    terminal_state
                )
            ) from exc
        raise PreflightError("bounded interactive Azure mutation timed out") from exc
    if result.returncode != 0:
        raise PreflightError("interactive Azure deployment command failed")
    return ""


@contextmanager
def _materialize_exact_compiled_package(
    parameter_path: Path,
    *,
    expected_parameters_sha256: str,
    expected_template_sha256: str,
    compiler: Callable[[Path], tuple[Dict[str, Any], Dict[str, Any]]] = compile_bicep_package,
):
    """Yield owner-only ARM JSON whose bytes are bound to the reviewed package."""
    parameters, template = compiler(parameter_path)
    if (
        _canonical_digest(parameters) != expected_parameters_sha256
        or _canonical_digest(template) != expected_template_sha256
    ):
        raise PreflightError(
            "compiled template or parameter bytes drifted at the mutation boundary"
        )
    with tempfile.TemporaryDirectory(prefix="viv-sbc-direct-replacement-") as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        paths: Dict[str, Path] = {}
        for label, document in (("parameters", parameters), ("template", template)):
            path = root / (label + ".json")
            content = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o400)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            metadata = path.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1
                or hashlib.sha256(path.read_bytes()).hexdigest()
                != hashlib.sha256(content).hexdigest()
            ):
                raise PreflightError(
                    "compiled {} artifact lost its owner-only byte identity".format(label)
                )
            paths[label] = path
        yield paths


def _lock_down_replacement_disks(
    observations: Mapping[str, Any],
    *,
    deadline: str,
    mutation_runner: Runner,
) -> list[str]:
    nodes = observations.get("nodes")
    if not isinstance(nodes, list):
        raise PreflightError("post-create node observations are missing")
    by_name = {
        item.get("name"): item
        for item in nodes
        if isinstance(item, dict) and item.get("name") in EXPECTED_REPLACEMENT_VM_NAMES
    }
    if set(by_name) != set(EXPECTED_REPLACEMENT_VM_NAMES):
        raise PreflightError("both exact replacement VMs must exist before disk lockdown")
    changed: list[str] = []
    for node in EXPECTED_REPLACEMENT_VM_NAMES:
        disk = by_name[node].get("disk")
        expected_disk_id = _resource_id("Microsoft.Compute/disks", node + "-osdisk")
        if not isinstance(disk, dict) or not _same_id(disk.get("id"), expected_disk_id):
            raise PreflightError("post-create disk identity drifted before lockdown")
        expected_tags = _replacement_tags(node, deadline)
        if (
            disk.get("publicNetworkAccess") == "Disabled"
            and disk.get("networkAccessPolicy") == "DenyAll"
            and disk.get("tags") == expected_tags
        ):
            continue
        mutation_runner(
            [
                "az", "disk", "update", "--ids", expected_disk_id,
                "--subscription", EXPECTED_SUBSCRIPTION_ID,
                "--public-network-access", "Disabled",
                "--network-access-policy", "DenyAll",
                "--output", "none", "--only-show-errors",
            ]
        )
        mutation_runner(
            [
                "az", "tag", "create", "--resource-id", expected_disk_id,
                "--subscription", EXPECTED_SUBSCRIPTION_ID, "--tags",
                *[
                    "{}={}".format(key, value)
                    for key, value in sorted(expected_tags.items())
                ],
                "--output", "none", "--only-show-errors",
            ]
        )
        changed.append(node)
    return changed


def apply_saved_plan(
    parameter_path: Path,
    package_evidence: Mapping[str, Any],
    saved_plan: Mapping[str, Any],
    scheduler_receipt: Mapping[str, Any],
    *,
    approved_plan_sha256: str,
    expected_compiled_parameters_sha256: str,
    expected_compiled_template_sha256: str,
    expected_bicep_version: str,
    expected_subscription_id: str,
    expected_tenant_id: str,
    now: datetime | None = None,
    runner: Runner = _run,
    mutation_runner: Runner = _run_interactive,
    scheduler_runner: Runner = _run,
    scheduler_host_name: str | None = None,
) -> Dict[str, Any]:
    current = (now or _utc_now()).astimezone(timezone.utc).replace(
        microsecond=0
    )
    approved = validate_saved_plan(
        saved_plan,
        package_evidence,
        approved_plan_sha256=approved_plan_sha256,
        expected_compiled_parameters_sha256=expected_compiled_parameters_sha256,
        expected_compiled_template_sha256=expected_compiled_template_sha256,
        expected_bicep_version=expected_bicep_version,
        expected_subscription_id=expected_subscription_id,
        expected_tenant_id=expected_tenant_id,
        now=current,
    )
    deadline = _parse_canonical_utc(
        approved["parallelAcceptance"]["deadlineUtc"], "parallel deadline"
    )
    if deadline - current < timedelta(minutes=MINIMUM_CREATE_BUFFER_MINUTES):
        raise PreflightError(
            "create authorization is inside the mandatory deadline safety buffer"
        )
    approved_receipt = validate_deadman_scheduler_receipt(
        scheduler_receipt,
        approved,
        now=current,
        scheduler_runner=scheduler_runner,
        host_name=scheduler_host_name,
    )
    fresh_observations = collect_live_observations(parameter_path, runner=runner)
    fresh_plan = validate_live_plan(
        fresh_observations, package_evidence, observed_at=current
    )
    _require_same_fresh_authority(approved, fresh_plan)
    creates = [
        item
        for item in approved["whatIf"]["changes"]
        if item.get("changeType") == "Create"
    ]
    create_executed = bool(creates)
    create_completed_within_authorization = True
    if create_executed:
        boundary_current = (
            current
            if now is not None
            else _utc_now().replace(microsecond=0)
        )
        approved = validate_saved_plan(
            saved_plan,
            package_evidence,
            approved_plan_sha256=approved_plan_sha256,
            expected_compiled_parameters_sha256=expected_compiled_parameters_sha256,
            expected_compiled_template_sha256=expected_compiled_template_sha256,
            expected_bicep_version=expected_bicep_version,
            expected_subscription_id=expected_subscription_id,
            expected_tenant_id=expected_tenant_id,
            now=boundary_current,
        )
        boundary_deadline = _parse_canonical_utc(
            approved["parallelAcceptance"]["deadlineUtc"], "parallel deadline"
        )
        if boundary_deadline - boundary_current < timedelta(
            minutes=MINIMUM_CREATE_BUFFER_MINUTES
        ):
            raise PreflightError(
                "create mutation boundary is inside the deadline safety buffer"
            )
        approved_receipt = validate_deadman_scheduler_receipt(
            scheduler_receipt,
            approved,
            now=boundary_current,
            scheduler_runner=scheduler_runner,
            host_name=scheduler_host_name,
        )
        authorization_expiry = _parse_canonical_utc(
            approved["authorizationExpiresUtc"], "authorizationExpiresUtc"
        )
        mutation_cutoff = min(authorization_expiry, boundary_deadline) - timedelta(
            seconds=CREATE_AUTHORIZATION_SAFETY_SECONDS
        )
        mutation_timeout_seconds = int(
            (mutation_cutoff - boundary_current).total_seconds()
        )
        if mutation_timeout_seconds < 1:
            raise PreflightError(
                "interactive create lacks a bounded authorization completion window"
            )
        with _materialize_exact_compiled_package(
            parameter_path,
            expected_parameters_sha256=expected_compiled_parameters_sha256,
            expected_template_sha256=expected_compiled_template_sha256,
        ) as artifacts:
            submission_current = (
                boundary_current
                if now is not None
                else _utc_now().replace(microsecond=0)
            )
            approved = validate_saved_plan(
                saved_plan,
                package_evidence,
                approved_plan_sha256=approved_plan_sha256,
                expected_compiled_parameters_sha256=expected_compiled_parameters_sha256,
                expected_compiled_template_sha256=expected_compiled_template_sha256,
                expected_bicep_version=expected_bicep_version,
                expected_subscription_id=expected_subscription_id,
                expected_tenant_id=expected_tenant_id,
                now=submission_current,
            )
            boundary_deadline = _parse_canonical_utc(
                approved["parallelAcceptance"]["deadlineUtc"],
                "parallel deadline",
            )
            if boundary_deadline - submission_current < timedelta(
                minutes=MINIMUM_CREATE_BUFFER_MINUTES
            ):
                raise PreflightError(
                    "create submission is inside the deadline safety buffer"
                )
            approved_receipt = validate_deadman_scheduler_receipt(
                scheduler_receipt,
                approved,
                now=submission_current,
                scheduler_runner=scheduler_runner,
                host_name=scheduler_host_name,
            )
            authorization_expiry = _parse_canonical_utc(
                approved["authorizationExpiresUtc"],
                "authorizationExpiresUtc",
            )
            mutation_cutoff = min(
                authorization_expiry,
                boundary_deadline,
            ) - timedelta(seconds=CREATE_AUTHORIZATION_SAFETY_SECONDS)
            mutation_timeout_seconds = int(
                (mutation_cutoff - submission_current).total_seconds()
            )
            if mutation_timeout_seconds < 1:
                raise PreflightError(
                    "compiled create lacks a bounded authorization completion window"
                )
            create_argv = [
                "az", "deployment", "sub", "create",
                "--name", DEPLOYMENT_NAME,
                "--location", EXPECTED_LOCATION,
                "--template-file", str(artifacts["template"]),
                "--parameters", "@" + str(artifacts["parameters"]),
                "--subscription", expected_subscription_id,
                "--confirm-with-what-if",
                "--what-if-result-format", "ResourceIdOnly",
                "--validation-level", "Provider",
                "--output", "none",
                "--only-show-errors",
            ]
            if mutation_runner is _run_interactive:
                _run_interactive(
                    create_argv, timeout_seconds=mutation_timeout_seconds
                )
            else:
                mutation_runner(create_argv)
        completion_current = (
            boundary_current
            if now is not None
            else _utc_now().replace(microsecond=0)
        )
        create_completed_within_authorization = (
            completion_current <= mutation_cutoff
        )
    post_create_observations = collect_live_observations(parameter_path, runner=runner)
    post_create_plan = validate_live_plan(
        post_create_observations,
        package_evidence,
        observed_at=current,
        allow_expired_deadline=True,
        allow_replacement_deallocated=True,
    )
    if set(post_create_plan["partialDeploymentResume"]["presentReplacementVmNames"]) != set(
        EXPECTED_REPLACEMENT_VM_NAMES
    ):
        raise PreflightError("provider deployment did not produce both exact replacement nodes")
    changed_disks = _lock_down_replacement_disks(
        post_create_observations,
        deadline=package_evidence["parallelAcceptanceDeadlineUtc"],
        mutation_runner=mutation_runner,
    )
    final_observations = collect_live_observations(parameter_path, runner=runner)
    final_plan = validate_live_plan(
        final_observations,
        package_evidence,
        observed_at=current,
        allow_expired_deadline=True,
        allow_replacement_deallocated=True,
    )
    lockdown = final_plan["partialDeploymentResume"]["diskLockdown"]
    if (
        lockdown["pendingVmNames"]
        or set(lockdown["lockedVmNames"]) != set(EXPECTED_REPLACEMENT_VM_NAMES)
    ):
        raise PreflightError("replacement OS disks did not reach the exact locked postcondition")
    if not create_completed_within_authorization:
        raise PreflightError(
            "provider deployment completed outside its bounded create authorization"
        )
    return {
        "approvedPlanSha256": approved_plan_sha256,
        "bicepCompilerVersion": expected_bicep_version,
        "compiledParametersSha256": expected_compiled_parameters_sha256,
        "compiledTemplateSha256": expected_compiled_template_sha256,
        "createExecuted": create_executed,
        "diskLockdownChangedVmNames": changed_disks,
        "parallelAcceptanceDeadlineUtc": package_evidence[
            "parallelAcceptanceDeadlineUtc"
        ],
        "schedulerJobId": approved_receipt["job"]["id"],
        "schedulerReceiptSha256": approved_receipt["receiptSha256"],
        "status": "DIRECT_REPLACEMENT_CREATE_AND_DISK_LOCKDOWN_COMPLETE",
        "subscriptionId": expected_subscription_id,
        "tenantId": expected_tenant_id,
    }


def recover_disk_lockdown(
    parameter_path: Path,
    package_evidence: Mapping[str, Any],
    saved_plan: Mapping[str, Any],
    *,
    approved_plan_sha256: str,
    expected_compiled_parameters_sha256: str,
    expected_compiled_template_sha256: str,
    expected_bicep_version: str,
    expected_subscription_id: str,
    expected_tenant_id: str,
    now: datetime | None = None,
    runner: Runner = _run,
    mutation_runner: Runner = _run_interactive,
) -> Dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    approved = validate_saved_plan(
        saved_plan,
        package_evidence,
        approved_plan_sha256=approved_plan_sha256,
        expected_compiled_parameters_sha256=expected_compiled_parameters_sha256,
        expected_compiled_template_sha256=expected_compiled_template_sha256,
        expected_bicep_version=expected_bicep_version,
        expected_subscription_id=expected_subscription_id,
        expected_tenant_id=expected_tenant_id,
        now=current,
        require_create_authorization=False,
    )
    deadline = _parse_canonical_utc(
        approved["parallelAcceptance"]["deadlineUtc"], "parallel deadline"
    )
    if current < deadline:
        raise PreflightError("disk-lockdown recovery is authorized only after the deadline")
    observations = collect_live_observations(parameter_path, runner=runner)
    plan = validate_live_plan(
        observations,
        package_evidence,
        observed_at=current,
        allow_expired_deadline=True,
        allow_replacement_deallocated=True,
    )
    if (
        set(plan["partialDeploymentResume"]["presentReplacementVmNames"])
        != set(EXPECTED_REPLACEMENT_VM_NAMES)
        or any(
            item.get("changeType") == "Create"
            for item in plan["whatIf"]["changes"]
        )
    ):
        raise PreflightError(
            "disk-lockdown recovery refuses absent replacement resources and can never create"
        )
    changed = _lock_down_replacement_disks(
        observations,
        deadline=approved["parallelAcceptance"]["deadlineUtc"],
        mutation_runner=mutation_runner,
    )
    final_observations = collect_live_observations(parameter_path, runner=runner)
    final = validate_live_plan(
        final_observations,
        package_evidence,
        observed_at=current,
        allow_expired_deadline=True,
        allow_replacement_deallocated=True,
    )
    lockdown = final["partialDeploymentResume"]["diskLockdown"]
    if (
        lockdown["pendingVmNames"]
        or set(lockdown["lockedVmNames"]) != set(EXPECTED_REPLACEMENT_VM_NAMES)
    ):
        raise PreflightError("post-deadline recovery did not lock both replacement disks")
    return {
        "approvedPlanSha256": approved_plan_sha256,
        "diskLockdownChangedVmNames": changed,
        "parallelAcceptanceDeadlineUtc": approved["parallelAcceptance"][
            "deadlineUtc"
        ],
        "status": "DIRECT_REPLACEMENT_POST_DEADLINE_DISK_LOCKDOWN_COMPLETE",
        "subscriptionId": expected_subscription_id,
        "tenantId": expected_tenant_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parameters", type=Path)
    parser.add_argument("--approved-admin-cidr", action="append", required=True)
    parser.add_argument("--expected-ssh-fingerprint", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--live-plan",
        action="store_true",
        help="query the exact Azure topology, budget and provider-level what-if read-only",
    )
    mode.add_argument(
        "--apply-plan",
        type=Path,
        help="guarded create/resume wrapper consuming one fresh owner-only live-plan JSON",
    )
    mode.add_argument(
        "--prepare-deadman-bundle-plan",
        type=Path,
        help="write the exact sealed owner-only replacement-deadman bundle",
    )
    mode.add_argument(
        "--issue-deadman-scheduler-receipt-plan",
        type=Path,
        help="query one live OpenClaw one-shot job and write its protected receipt",
    )
    mode.add_argument(
        "--recover-disk-lockdown-plan",
        type=Path,
        help="post-deadline no-create recovery for replacement OS-disk lockdown only",
    )
    parser.add_argument(
        "--expected-compiled-parameters-sha256",
        help="required in live-plan/apply mode; copy from reviewed offline evidence",
    )
    parser.add_argument("--expected-compiled-template-sha256")
    parser.add_argument("--expected-bicep-version")
    parser.add_argument("--expected-subscription-id")
    parser.add_argument("--expected-tenant-id")
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--deadman-bundle-output", type=Path)
    parser.add_argument("--openclaw-cron-job-id")
    parser.add_argument("--deadman-scheduler-receipt-output", type=Path)
    parser.add_argument("--deadman-scheduler-receipt", type=Path)
    parser.add_argument(
        "--confirm-with-what-if",
        action="store_true",
        help="required in apply mode and passed through to Azure's interactive provider what-if",
    )
    parser.add_argument("--confirm-disk-lockdown-recovery", action="store_true")
    return parser


def _validate_mode_specific_options(args: argparse.Namespace) -> None:
    selected = (
        "live"
        if args.live_plan
        else "apply"
        if args.apply_plan is not None
        else "prepare"
        if args.prepare_deadman_bundle_plan is not None
        else "issue"
        if args.issue_deadman_scheduler_receipt_plan is not None
        else "recover"
        if args.recover_disk_lockdown_plan is not None
        else "offline"
    )
    actual = {
        "approvedPlan": args.approved_plan_sha256 is not None,
        "bundleOutput": args.deadman_bundle_output is not None,
        "confirmRecovery": args.confirm_disk_lockdown_recovery,
        "confirmWhatIf": args.confirm_with_what_if,
        "cronJobId": args.openclaw_cron_job_id is not None,
        "receiptInput": args.deadman_scheduler_receipt is not None,
        "receiptOutput": args.deadman_scheduler_receipt_output is not None,
    }
    expected = {
        "offline": set(),
        "live": set(),
        "apply": {"approvedPlan", "confirmWhatIf", "receiptInput"},
        "prepare": {"approvedPlan", "bundleOutput"},
        "issue": {"approvedPlan", "cronJobId", "receiptOutput"},
        "recover": {"approvedPlan", "confirmRecovery"},
    }[selected]
    enabled = {name for name, value in actual.items() if value}
    if enabled != expected:
        raise PreflightError(
            "{} mode-specific option set is not exact".format(selected)
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _validate_mode_specific_options(args)
        parameter_path = validate_local_parameter_path(args.parameters)
        parameters, template = compile_bicep_package(parameter_path)
        evidence = validate_compiled_package(
            parameters,
            template,
            approved_admin_cidrs=args.approved_admin_cidr,
            expected_ssh_fingerprint=args.expected_ssh_fingerprint,
            allow_expired_deadline=args.recover_disk_lockdown_plan is not None,
        )
        expected_authority = {
            "bicep": args.expected_bicep_version,
            "parameters": args.expected_compiled_parameters_sha256,
            "subscription": args.expected_subscription_id,
            "template": args.expected_compiled_template_sha256,
            "tenant": args.expected_tenant_id,
        }
        authority_mode = any(
            value is not None
            for value in (
                args.apply_plan,
                args.prepare_deadman_bundle_plan,
                args.issue_deadman_scheduler_receipt_plan,
                args.recover_disk_lockdown_plan,
            )
        )
        if args.live_plan or authority_mode:
            if expected_authority != {
                "bicep": evidence["bicepCompilerVersion"],
                "parameters": evidence["compiledParametersSha256"],
                "subscription": EXPECTED_SUBSCRIPTION_ID,
                "template": evidence["compiledTemplateSha256"],
                "tenant": EXPECTED_TENANT_ID,
            }:
                raise PreflightError(
                    "live/apply mode requires exact compiler/template/parameter/subscription/tenant authority"
                )
        if args.live_plan:
            if (
                args.approved_plan_sha256 is not None
                or args.confirm_with_what_if
                or args.confirm_disk_lockdown_recovery
                or args.deadman_bundle_output is not None
                or args.openclaw_cron_job_id is not None
                or args.deadman_scheduler_receipt_output is not None
                or args.deadman_scheduler_receipt is not None
            ):
                raise PreflightError("live plan mode cannot consume apply authority")
            evidence = validate_live_plan(
                collect_live_observations(parameter_path), evidence
            )
        elif args.apply_plan is not None:
            if (
                args.approved_plan_sha256 is None
                or not args.confirm_with_what_if
                or args.confirm_disk_lockdown_recovery
                or args.deadman_scheduler_receipt is None
            ):
                raise PreflightError(
                    "apply mode requires the approved plan, live scheduler receipt and --confirm-with-what-if"
                )
            evidence = apply_saved_plan(
                parameter_path,
                evidence,
                _read_saved_plan(args.apply_plan),
                _read_scheduler_receipt(args.deadman_scheduler_receipt),
                approved_plan_sha256=args.approved_plan_sha256,
                expected_compiled_parameters_sha256=args.expected_compiled_parameters_sha256,
                expected_compiled_template_sha256=args.expected_compiled_template_sha256,
                expected_bicep_version=args.expected_bicep_version,
                expected_subscription_id=args.expected_subscription_id,
                expected_tenant_id=args.expected_tenant_id,
            )
        elif args.prepare_deadman_bundle_plan is not None:
            if (
                args.approved_plan_sha256 is None
                or args.confirm_with_what_if
                or args.confirm_disk_lockdown_recovery
                or args.deadman_bundle_output is None
            ):
                raise PreflightError(
                    "bundle preparation requires the approved plan and exact output path"
                )
            plan = _read_saved_plan(args.prepare_deadman_bundle_plan)
            validate_saved_plan(
                plan,
                evidence,
                approved_plan_sha256=args.approved_plan_sha256,
                expected_compiled_parameters_sha256=args.expected_compiled_parameters_sha256,
                expected_compiled_template_sha256=args.expected_compiled_template_sha256,
                expected_bicep_version=args.expected_bicep_version,
                expected_subscription_id=args.expected_subscription_id,
                expected_tenant_id=args.expected_tenant_id,
            )
            evidence = prepare_deadman_bundle(
                plan, output_path=args.deadman_bundle_output
            )
        elif args.issue_deadman_scheduler_receipt_plan is not None:
            if (
                args.approved_plan_sha256 is None
                or args.confirm_with_what_if
                or args.confirm_disk_lockdown_recovery
                or args.openclaw_cron_job_id is None
                or args.deadman_scheduler_receipt_output is None
            ):
                raise PreflightError(
                    "receipt issuance requires the approved plan, live job ID and exact output path"
                )
            plan = _read_saved_plan(args.issue_deadman_scheduler_receipt_plan)
            validate_saved_plan(
                plan,
                evidence,
                approved_plan_sha256=args.approved_plan_sha256,
                expected_compiled_parameters_sha256=args.expected_compiled_parameters_sha256,
                expected_compiled_template_sha256=args.expected_compiled_template_sha256,
                expected_bicep_version=args.expected_bicep_version,
                expected_subscription_id=args.expected_subscription_id,
                expected_tenant_id=args.expected_tenant_id,
            )
            evidence = issue_deadman_scheduler_receipt(
                plan,
                job_id=args.openclaw_cron_job_id,
                output_path=args.deadman_scheduler_receipt_output,
                now=datetime.now(timezone.utc),
                scheduler_runner=_run,
            )
        elif args.recover_disk_lockdown_plan is not None:
            if (
                args.approved_plan_sha256 is None
                or args.confirm_with_what_if
                or not args.confirm_disk_lockdown_recovery
            ):
                raise PreflightError(
                    "recovery requires the approved plan and --confirm-disk-lockdown-recovery"
                )
            evidence = recover_disk_lockdown(
                parameter_path,
                evidence,
                _read_saved_plan(args.recover_disk_lockdown_plan),
                approved_plan_sha256=args.approved_plan_sha256,
                expected_compiled_parameters_sha256=args.expected_compiled_parameters_sha256,
                expected_compiled_template_sha256=args.expected_compiled_template_sha256,
                expected_bicep_version=args.expected_bicep_version,
                expected_subscription_id=args.expected_subscription_id,
                expected_tenant_id=args.expected_tenant_id,
            )
        elif any(value is not None for value in expected_authority.values()) or (
            args.approved_plan_sha256 is not None
            or args.confirm_with_what_if
            or args.confirm_disk_lockdown_recovery
            or args.deadman_bundle_output is not None
            or args.openclaw_cron_job_id is not None
            or args.deadman_scheduler_receipt_output is not None
            or args.deadman_scheduler_receipt is not None
        ):
            raise PreflightError(
                "live/apply authority options are invalid in offline mode"
            )
    except PreflightError as exc:
        print("DIRECT_REPLACEMENT_PREFLIGHT_REJECTED: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
