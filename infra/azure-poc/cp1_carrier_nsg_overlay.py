#!/opt/homebrew/bin/python3.13
"""Guard the temporary CP1 carrier NSG overlay for generation-3 Edge nodes.

Planning is read-only. Applying requires a fresh, protected, self-digested
plan and an exact confirmation phrase. The ordinary three-node template is
deliberately not involved: it remains the immutable SYNTHETIC_PRIVATE /
DIRECT_ROUTING base authority while this narrow child-rule overlay exists.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


EXPECTED_SUBSCRIPTION_ID = "a806949c-240f-4541-8c61-fd97f6d1f953"
EXPECTED_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
EXPECTED_RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
EXPECTED_LOCATION = "uaenorth"
EXPECTED_CP1_NSG = "viv-sbc-poc-cp1-nsg"
EXPECTED_BICEP_VERSION = "0.46.1.21595"
EXPECTED_COMPILED_TEMPLATE_SHA256 = (
    "2ef32a468c60c849551ab2a63d3c8f827ed7919c4c0252742c01b6a22c47fc58"
)
EXPECTED_COMPILED_PARAMETERS_SHA256 = (
    "d17eb0b8af0de79eba8a053beabac4e83a523f89bf572fda2d11149d766dc6ab"
)
DEPLOYMENT_NAME = "viv-sbc-cp1-carrier-nsg-overlay"
API_VERSION = "infra.vivolution.ae/cp1-carrier-nsg-overlay-plan/v0.1"
PLAN_KIND = "Cp1CarrierNsgOverlayPlan"
PLAN_MAX_AGE_MINUTES = 10
DEPLOYMENT_COMPLETION_RESERVE_SECONDS = 15
DEPLOYMENT_CANCEL_TIMEOUT_SECONDS = 30
DEPLOYMENT_SETTLE_TIMEOUT_SECONDS = 90
APPLY_CONFIRMATION = "APPLY-VIVOLUTION-CP1-CARRIER-NSG-OVERLAY"
TEARDOWN_CONFIRMATION = "TEARDOWN-VIVOLUTION-CP1-CARRIER-NSG-OVERLAY"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PARAMETER_PATH = (
    PROJECT_ROOT / "infra/azure-poc/cp1-carrier-nsg-overlay.bicepparam"
)
EXPECTED_TEMPLATE_PATH = (
    PROJECT_ROOT / "infra/azure-poc/cp1-carrier-nsg-overlay.bicep"
)
EXPECTED_PLAN_PATH = PROJECT_ROOT / "deploy/.state/cp1-carrier-nsg-overlay-plan.json"
EXPECTED_DIRECT_REPLACEMENT_PLAN_PATH = (
    PROJECT_ROOT / "deploy/.state/direct-replacement-live-plan.json"
)
EXPECTED_DIRECT_REPLACEMENT_RECEIPT_PATH = (
    PROJECT_ROOT / "deploy/.state/direct-replacement-deadman-scheduler-receipt.json"
)
DIRECT_REPLACEMENT_GUARD_PATH = (
    PROJECT_ROOT / "infra/azure-poc/direct-replacement-preflight.py"
)
EXPECTED_ADMIN_PREFIXES = ["83.110.90.136/32", "83.110.90.142/32"]
EXPECTED_BUDGET_NAME = "viv-sbc-poc-monthly-usd100"
EXPECTED_BUDGET_AMOUNT = Decimal("100")
EXPECTED_BUDGET_THRESHOLDS = {Decimal("75"), Decimal("90"), Decimal("100")}

NODE_SPECS = {
    "viv-sbc-poc-cp1": ("10.20.1.4", "snet-management"),
    "viv-sbc-poc-sbc1": ("10.20.2.4", "snet-edge"),
    "viv-sbc-poc-sbc2": ("10.20.2.5", "snet-edge"),
    "viv-sbc-dr-sbc1-g3": ("10.20.2.6", "snet-edge"),
    "viv-sbc-dr-sbc2-g3": ("10.20.2.7", "snet-edge"),
}
G2_NODES = ("viv-sbc-poc-sbc1", "viv-sbc-poc-sbc2")
G3_NODES = ("viv-sbc-dr-sbc1-g3", "viv-sbc-dr-sbc2-g3")


class OverlayError(RuntimeError):
    """The exact overlay authority or observed Azure state could not be proved."""


Runner = Callable[[Sequence[str]], str]


class CompiledPackage:
    """Canonical reviewed ARM documents and their digest evidence."""

    def __init__(
        self,
        *,
        evidence: dict[str, str],
        parameters: dict[str, Any],
        template: dict[str, Any],
    ) -> None:
        self.evidence = evidence
        self.parameters = parameters
        self.template = template


class CompiledArtifacts:
    """One protected compiled artifact set shared by What-If and create."""

    def __init__(self, package: CompiledPackage):
        self.package = package
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.parameters_path: Path | None = None
        self.template_path: Path | None = None

    def __enter__(self) -> "CompiledArtifacts":
        self._temporary = tempfile.TemporaryDirectory(
            prefix="viv-cp1-carrier-overlay-"
        )
        directory = Path(self._temporary.name)
        directory.chmod(0o700)
        self.parameters_path = directory / "parameters.json"
        self.template_path = directory / "template.json"
        self._write_exact(self.parameters_path, _canonical_bytes(self.package.parameters))
        self._write_exact(self.template_path, _canonical_bytes(self.package.template))
        self.verify(self.package.evidence)
        return self

    @staticmethod
    def _write_exact(path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o400)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read_exact(path: Path, label: str) -> dict[str, Any]:
        if path.is_symlink():
            raise OverlayError("compiled {} artifact became a symlink".format(label))
        try:
            metadata = path.stat()
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OverlayError("compiled {} artifact is unavailable".format(label)) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            raise OverlayError("compiled {} artifact protection drifted".format(label))
        value = _strict_json(raw, "compiled {} artifact".format(label))
        if not isinstance(value, dict):
            raise OverlayError("compiled {} artifact is not one object".format(label))
        return value

    def verify(self, expected: Mapping[str, str]) -> None:
        if self.parameters_path is None or self.template_path is None:
            raise OverlayError("compiled artifact set is not materialized")
        evidence = _validate_package(
            self._read_exact(self.parameters_path, "parameter"),
            self._read_exact(self.template_path, "template"),
        )
        if evidence != dict(expected) or evidence != self.package.evidence:
            raise OverlayError("compiled artifact digest authority drifted")

    def deployment_arguments(self) -> list[str]:
        if self.parameters_path is None or self.template_path is None:
            raise OverlayError("compiled artifact set is not materialized")
        return [
            "--template-file", str(self.template_path),
            "--parameters", "@" + str(self.parameters_path),
        ]

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


def _run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise OverlayError("Azure/Bicep command failed: {}".format(detail))
    return result.stdout


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _strict_json(raw: str, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OverlayError("{} contains a duplicate JSON key".format(label))
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise OverlayError("{} is malformed JSON".format(label)) from exc


def _json(argv: Sequence[str], label: str, runner: Runner) -> Any:
    return _strict_json(runner(argv), label)


def _same_id(actual: Any, expected: str) -> bool:
    return (
        isinstance(actual, str)
        and actual.rstrip("/").lower() == expected.rstrip("/").lower()
    )


def _resource_group_id() -> str:
    return "/subscriptions/{}/resourceGroups/{}".format(
        EXPECTED_SUBSCRIPTION_ID, EXPECTED_RESOURCE_GROUP
    )


def _resource_id(resource_type: str, name: str) -> str:
    return "{}/providers/{}/{}".format(_resource_group_id(), resource_type, name)


def _subnet_id(name: str) -> str:
    return _resource_id("Microsoft.Network/virtualNetworks", "viv-sbc-poc-vnet") + (
        "/subnets/" + name
    )


def _replacement_tags(node: str, deadline: str) -> dict[str, str]:
    return {
        "costProfile": "monthly-credit-lab",
        "edgeGeneration": "3",
        "edgeRuntimeProfile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
        "environment": "poc",
        "managedBy": "bicep",
        "nodeName": "sbc1" if node.endswith("sbc1-g3") else "sbc2",
        "nodeRole": "session-border-controller",
        "owner": "Vivolution Technologies LLC",
        "parallelAcceptanceDeadlineUtc": deadline,
        "parallelAcceptanceWindowHours": "72",
        "predecessorDisposition": "deallocate-after-final-acceptance",
        "purpose": "Direct Routing generation-3 replacement Edge",
        "region": EXPECTED_LOCATION,
        "replacementMode": "parallel-preserve-generation-2",
        "workload": "vivolution-sbc",
    }


def _rule_id(name: str) -> str:
    return _resource_id(
        "Microsoft.Network/networkSecurityGroups", EXPECTED_CP1_NSG
    ) + "/securityRules/" + name


def _rule(
    name: str,
    description: str,
    priority: int,
    protocol: str,
    direction: str,
    *,
    source_prefix: str | None = None,
    source_prefixes: Sequence[str] = (),
    source_port_range: str | None = None,
    source_port_ranges: Sequence[str] = (),
    destination_prefix: str | None = None,
    destination_prefixes: Sequence[str] = (),
    destination_port_range: str | None = None,
    destination_port_ranges: Sequence[str] = (),
    access: str = "Allow",
) -> dict[str, Any]:
    return {
        "access": access,
        "description": description,
        "destinationPortRange": destination_port_range,
        "destinationPortRanges": list(destination_port_ranges),
        "destinationPrefix": destination_prefix,
        "destinationPrefixes": list(destination_prefixes),
        "direction": direction,
        "name": name,
        "priority": priority,
        "protocol": protocol,
        "provisioningState": "Succeeded",
        "sourcePortRange": source_port_range,
        "sourcePortRanges": list(source_port_ranges),
        "sourcePrefix": source_prefix,
        "sourcePrefixes": list(source_prefixes),
    }


CP1_BASE_RULES = sorted(
    [
        _rule(
            "AllowAdminSsh",
            "SSH to CP1 from explicitly approved administrator IPv4 CIDRs.",
            100,
            "Tcp",
            "Inbound",
            source_prefixes=EXPECTED_ADMIN_PREFIXES,
            source_port_range="*",
            destination_prefix="*",
            destination_port_range="22",
        ),
        _rule(
            "AllowPublicHttp",
            "Public HTTP for redirect and ACME HTTP challenge where used.",
            200,
            "Tcp",
            "Inbound",
            source_prefix="Internet",
            source_port_range="*",
            destination_prefix="*",
            destination_port_range="80",
        ),
        _rule(
            "AllowPublicHttps",
            "Public CP1 HTTPS ingress.",
            210,
            "Tcp",
            "Inbound",
            source_prefix="Internet",
            source_port_range="*",
            destination_prefix="*",
            destination_port_range="443",
        ),
        _rule(
            "AllowEdgeToFixtureSignaling",
            "Private SBC-to-CP1 TLS signaling for the isolated PBX and Teams-side fixtures only.",
            300,
            "Tcp",
            "Inbound",
            source_prefix="10.20.2.0/24",
            source_port_range="*",
            destination_prefix="10.20.1.4",
            destination_port_ranges=("16061", "25061"),
        ),
        _rule(
            "AllowEdgeToFixtureMedia",
            "Private SBC-to-CP1 RTP for the isolated PBX and Teams-side fixtures only.",
            310,
            "Udp",
            "Inbound",
            source_prefix="10.20.2.0/24",
            source_port_range="*",
            destination_prefix="10.20.1.4",
            destination_port_ranges=("21000-21127", "22000-22063"),
        ),
        _rule(
            "DenyAllInbound",
            "Explicitly deny every other inbound flow before Azure default rules.",
            4096,
            "*",
            "Inbound",
            source_prefix="*",
            source_port_range="*",
            destination_prefix="*",
            destination_port_range="*",
            access="Deny",
        ),
    ],
    key=lambda item: item["name"],
)

OVERLAY_RULES = sorted(
    [
        _rule(
            "AllowGeneration3CarrierSignaling",
            "POC generation-3 SBC mutual-TLS signaling to the exact private CP1 carrier listener.",
            320,
            "Tcp",
            "Inbound",
            source_prefixes=("10.20.2.6/32", "10.20.2.7/32"),
            source_port_range="*",
            destination_prefix="10.20.1.4/32",
            destination_port_range="5061",
        ),
        _rule(
            "AllowGeneration3CarrierMedia",
            "POC generation-3 tenant RTP allocation to the exact private CP1 carrier media allocation.",
            330,
            "Udp",
            "Inbound",
            source_prefixes=("10.20.2.6/32", "10.20.2.7/32"),
            source_port_range="20000-20255",
            destination_prefix="10.20.1.4/32",
            destination_port_range="30000-30127",
        ),
    ],
    key=lambda item: item["name"],
)
OVERLAY_BY_NAME = {item["name"]: item for item in OVERLAY_RULES}


def _g2_rules() -> list[dict[str, Any]]:
    edge = "10.20.2.0/24"
    cp1 = "10.20.1.4"
    cp1_32 = ["10.20.1.4/32"]
    values = [
        _rule("AllowAdminSsh", "SSH to the SBC from explicitly approved administrator IPv4 CIDRs.", 100, "Tcp", "Inbound", source_prefixes=EXPECTED_ADMIN_PREFIXES, source_port_range="*", destination_prefix="*", destination_port_range="22"),
        _rule("AllowSyntheticTeamsTls5061", "Private no-PSTN Teams-side simulator TLS signaling for bounded qualification.", 220, "Tcp", "Inbound", source_prefixes=cp1_32, source_port_range="*", destination_prefix="*", destination_port_range="5061"),
        _rule("AllowSyntheticTeamsMedia", "Private no-PSTN Teams-side simulator media for bounded qualification.", 230, "Udp", "Inbound", source_prefixes=cp1_32, source_port_range="*", destination_prefix="*", destination_port_range="20000-20255"),
        _rule("AllowPbxTls", "PBX TLS signaling to the isolated first-tenant listener from explicitly supplied SBC1 PBX IPv4 CIDRs.", 300, "Tcp", "Inbound", source_prefixes=cp1_32, source_port_range="*", destination_prefix="*", destination_port_range="15061"),
        _rule("AllowPbxMedia", "PBX-side UDP media from explicitly supplied SBC1 PBX IPv4 CIDRs.", 310, "Udp", "Inbound", source_prefixes=cp1_32, source_port_range="21000-21127", destination_prefix="*", destination_port_range="20000-20255"),
        _rule("DenyAllInbound", "Explicitly deny every other inbound flow before Azure default rules.", 4096, "*", "Inbound", source_prefix="*", source_port_range="*", destination_prefix="*", destination_port_range="*", access="Deny"),
        _rule("AllowAzureDhcpOutbound", "Azure DHCP renewal from the guest client port to the fixed WireServer DHCP endpoint only.", 1000, "Udp", "Outbound", source_prefix=edge, source_port_range="68", destination_prefix="168.63.129.16", destination_port_range="67"),
        _rule("AllowAzureDnsUdpOutbound", "Unicast UDP DNS to Azure platform DNS only.", 1010, "Udp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix="168.63.129.16", destination_port_range="53"),
        _rule("AllowAzureDnsTcpOutbound", "Unicast TCP DNS fallback to Azure platform DNS only.", 1020, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix="168.63.129.16", destination_port_range="53"),
        _rule("AllowAzureWireServerOutbound", "Azure Linux Agent WireServer channels only.", 1030, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix="168.63.129.16", destination_port_ranges=("80", "32526")),
        _rule("AllowAzureImdsOutbound", "Managed-identity token and instance metadata requests to IMDS only.", 1040, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix="169.254.169.254", destination_port_range="80"),
        _rule("AllowNtpOutbound", "NTP to the two fixed anycast time sources configured by the Edge role.", 1050, "Udp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefixes=("162.159.200.1/32", "162.159.200.123/32"), destination_port_range="123"),
        _rule("AllowWebOutbound", "HTTP/HTTPS for Debian APT, pinned package retrieval, ACME, and Azure DNS APIs.", 1060, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix="Internet", destination_port_ranges=("80", "443")),
        _rule("AllowControlPlaneOutbound", "Private HTTPS to the fixed CP1 control-plane address only.", 1070, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix=cp1, destination_port_range="443"),
        _rule("AllowSyntheticFixtureSignalingOutbound", "Synthetic PBX and Teams-side mutual-TLS signaling to the fixed private CP1 fixture only.", 1100, "Tcp", "Outbound", source_prefix=edge, source_port_range="*", destination_prefix=cp1, destination_port_ranges=("16061", "25061")),
        _rule("AllowSyntheticFixtureMediaOutbound", "RTPengine tenant allocation to the two bounded private CP1 fixture media ranges only.", 1110, "Udp", "Outbound", source_prefix=edge, source_port_range="20000-20255", destination_prefix=cp1, destination_port_ranges=("21000-21127", "22000-22063")),
        _rule("DenyAllOutbound", "Explicitly deny every other outbound flow before Azure default rules.", 4096, "*", "Outbound", source_prefix="*", source_port_range="*", destination_prefix="*", destination_port_range="*", access="Deny"),
    ]
    return sorted(values, key=lambda item: item["name"])


G2_RULES_BY_NODE = {
    node: [
        {
            **rule,
            "description": rule["description"].replace("SBC1", "SBC2")
            if node.endswith("sbc2")
            else rule["description"],
        }
        for rule in _g2_rules()
    ]
    for node in G2_NODES
}


def _contract_rule(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = set(CP1_BASE_RULES[0])
    if not isinstance(value, Mapping) or not keys.issubset(value):
        raise OverlayError("NSG rule observation is malformed")
    return {key: value.get(key) for key in sorted(keys)}


def _validate_package(parameters: Mapping[str, Any], template: Mapping[str, Any]) -> dict[str, str]:
    if set(parameters) != {"$schema", "contentVersion", "parameters"}:
        raise OverlayError("compiled parameter document shape drifted")
    wrapped = parameters.get("parameters")
    expected_values = {
        "existingCp1NetworkSecurityGroupName": EXPECTED_CP1_NSG,
        "targetResourceGroupName": EXPECTED_RESOURCE_GROUP,
        "targetSubscriptionId": EXPECTED_SUBSCRIPTION_ID,
    }
    if not isinstance(wrapped, dict) or set(wrapped) != set(expected_values):
        raise OverlayError("compiled overlay parameters are not exact")
    actual_values: dict[str, Any] = {}
    for name, value in wrapped.items():
        if not isinstance(value, dict) or set(value) != {"value"}:
            raise OverlayError("compiled overlay parameter wrapper drifted")
        actual_values[name] = value["value"]
    if actual_values != expected_values:
        raise OverlayError("compiled overlay parameter values drifted")
    parameter_digest = _digest(parameters)
    if parameter_digest != EXPECTED_COMPILED_PARAMETERS_SHA256:
        raise OverlayError("compiled parameter digest differs from the reviewed package")
    metadata = template.get("metadata") if isinstance(template, Mapping) else None
    generator = metadata.get("_generator") if isinstance(metadata, Mapping) else None
    if (
        not isinstance(generator, Mapping)
        or generator.get("name") != "bicep"
        or generator.get("version") != EXPECTED_BICEP_VERSION
    ):
        raise OverlayError("compiled template Bicep compiler identity drifted")
    template_digest = _digest(template)
    if template_digest != EXPECTED_COMPILED_TEMPLATE_SHA256:
        raise OverlayError("compiled template digest differs from the reviewed overlay")
    return {
        "bicepCompilerVersion": EXPECTED_BICEP_VERSION,
        "compiledParametersSha256": parameter_digest,
        "compiledTemplateSha256": template_digest,
    }


def compile_package_bundle(path: Path = EXPECTED_PARAMETER_PATH) -> CompiledPackage:
    if path.is_symlink():
        raise OverlayError("overlay parameter file must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise OverlayError("overlay parameter file is unavailable") from exc
    if (
        resolved != EXPECTED_PARAMETER_PATH.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise OverlayError("use the exact owned, non-writable tracked overlay parameter file")
    raw = _run(["az", "bicep", "build-params", "--file", str(resolved), "--stdout"])
    envelope = _strict_json(raw, "Bicep package envelope")
    if not isinstance(envelope, dict) or set(envelope) != {
        "parametersJson", "templateJson", "templateSpecId"
    } or envelope.get("templateSpecId") is not None:
        raise OverlayError("Bicep package envelope drifted")
    parameters = _strict_json(envelope.get("parametersJson", ""), "compiled parameters")
    template = _strict_json(envelope.get("templateJson", ""), "compiled template")
    if not isinstance(parameters, dict) or not isinstance(template, dict):
        raise OverlayError("compiled overlay package is not two JSON objects")
    return CompiledPackage(
        evidence=_validate_package(parameters, template),
        parameters=parameters,
        template=template,
    )


def compile_package(path: Path = EXPECTED_PARAMETER_PATH) -> dict[str, str]:
    """Return the reviewed digest evidence while retaining the legacy API."""

    return compile_package_bundle(path).evidence


def _read_protected_json(path: Path, expected: Path, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise OverlayError("{} must not be a symlink".format(label))
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise OverlayError("{} is unavailable".format(label)) from exc
    if (
        resolved != expected.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
    ):
        raise OverlayError("{} must be the exact owner-only protected file".format(label))
    value = _strict_json(raw, label)
    if not isinstance(value, dict):
        raise OverlayError("{} must contain one JSON object".format(label))
    return value


def _load_direct_replacement_guard() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vivolution_direct_replacement_guard", DIRECT_REPLACEMENT_GUARD_PATH
    )
    if spec is None or spec.loader is None:
        raise OverlayError("direct-replacement guard cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - import failure is environment-specific
        raise OverlayError("direct-replacement guard failed to load") from exc
    return module


def collect_generation3_authority(
    approved_plan_sha256: str,
    *,
    action: str,
    runner: Runner = _run,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind G3 tags to the reviewed replacement plan and exact live deadman."""

    if (
        not isinstance(approved_plan_sha256, str)
        or len(approved_plan_sha256) != 64
        or any(value not in "0123456789abcdef" for value in approved_plan_sha256)
    ):
        raise OverlayError("direct-replacement plan SHA-256 is not canonical")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    direct = _load_direct_replacement_guard()
    plan = _read_protected_json(
        EXPECTED_DIRECT_REPLACEMENT_PLAN_PATH,
        EXPECTED_DIRECT_REPLACEMENT_PLAN_PATH,
        "direct-replacement live plan",
    )
    parallel = plan.get("parallelAcceptance")
    runtime = plan.get("runtimeAuthority")
    package_evidence = {
        "bicepCompilerVersion": plan.get("bicepCompilerVersion"),
        "compiledParametersSha256": plan.get("compiledParametersSha256"),
        "compiledTemplateSha256": plan.get("compiledTemplateSha256"),
        "edgeGeneration": runtime.get("generation") if isinstance(runtime, dict) else None,
        "edgeRuntimeProfile": runtime.get("profile") if isinstance(runtime, dict) else None,
        "parallelAcceptanceDeadlineUtc": parallel.get("deadlineUtc")
        if isinstance(parallel, dict)
        else None,
    }
    try:
        validated_plan = direct.validate_saved_plan(
            plan,
            package_evidence,
            approved_plan_sha256=approved_plan_sha256,
            expected_compiled_parameters_sha256=plan.get(
                "compiledParametersSha256"
            ),
            expected_compiled_template_sha256=direct.EXPECTED_COMPILED_TEMPLATE_SHA256,
            expected_bicep_version=direct.EXPECTED_BICEP_VERSION,
            expected_subscription_id=EXPECTED_SUBSCRIPTION_ID,
            expected_tenant_id=EXPECTED_TENANT_ID,
            now=current,
            require_create_authorization=False,
        )
    except Exception as exc:
        raise OverlayError("reviewed direct-replacement plan authority is invalid") from exc
    receipt = _read_protected_json(
        EXPECTED_DIRECT_REPLACEMENT_RECEIPT_PATH,
        EXPECTED_DIRECT_REPLACEMENT_RECEIPT_PATH,
        "direct-replacement deadman receipt",
    )
    receipt_body = {
        key: receipt[key] for key in sorted(receipt) if key != "receiptSha256"
    }
    if (
        set(receipt)
        != {
            "apiVersion", "command", "embeddedProgram", "issuedAtUtc", "job",
            "plan", "protectedPredecessorVmIds", "receiptSha256",
            "replacementVmIds", "scheduler", "status",
        }
        or receipt.get("receiptSha256") != _digest(receipt_body)
        or receipt.get("status")
        != "DIRECT_REPLACEMENT_DEADMAN_SCHEDULER_RECEIPT_VALID"
    ):
        raise OverlayError("direct-replacement deadman receipt is invalid")
    receipt_plan = receipt.get("plan")
    receipt_job = receipt.get("job")
    if (
        not isinstance(receipt_plan, dict)
        or receipt_plan.get("planSha256") != approved_plan_sha256
        or receipt_plan.get("deadlineUtc")
        != validated_plan["parallelAcceptance"]["deadlineUtc"]
        or receipt_plan.get("subscriptionId") != EXPECTED_SUBSCRIPTION_ID
        or receipt_plan.get("tenantId") != EXPECTED_TENANT_ID
        or not isinstance(receipt_job, dict)
        or not isinstance(receipt_job.get("id"), str)
    ):
        raise OverlayError("deadman receipt does not bind the reviewed replacement plan")
    try:
        if str(uuid.UUID(receipt_job["id"])) != receipt_job["id"]:
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise OverlayError("deadman receipt job ID is not canonical") from exc

    deadline = _parse_utc(
        validated_plan["parallelAcceptance"]["deadlineUtc"],
        "generation-3 parallel acceptance deadline",
    )
    live_job_sha256 = None
    scheduler_sha256 = None
    scheduler_live = False
    if action == "apply":
        if deadline <= current:
            raise OverlayError("generation-3 parallel acceptance deadline has expired")
        try:
            status, job = direct._query_live_deadman_job(
                receipt_job["id"], scheduler_runner=runner
            )
            normalized_job = direct._normalize_live_deadman_job(
                job,
                validated_plan,
                job_id=receipt_job["id"],
                now=current,
            )
            normalized_status = direct._validate_scheduler_status(
                status, now=current, deadline=deadline
            )
        except Exception as exc:
            raise OverlayError("generation-3 deadman is not durably armed") from exc
        if receipt_job.get("contractSha256") != _digest(normalized_job):
            raise OverlayError("live deadman differs from its reviewed receipt")
        live_job_sha256 = _digest(normalized_job)
        scheduler_sha256 = _digest(normalized_status)
        scheduler_live = True

    return {
        "compiledParametersSha256": validated_plan["compiledParametersSha256"],
        "compiledTemplateSha256": validated_plan["compiledTemplateSha256"],
        "deadlineUtc": validated_plan["parallelAcceptance"]["deadlineUtc"],
        "deadmanJobId": receipt_job["id"],
        "deadmanReceiptSha256": receipt["receiptSha256"],
        "directReplacementPlanSha256": approved_plan_sha256,
        "liveDeadmanJobSha256": live_job_sha256,
        "schedulerAuthoritySha256": scheduler_sha256,
        "schedulerLive": scheduler_live,
    }


def _common() -> list[str]:
    return [
        "--subscription", EXPECTED_SUBSCRIPTION_ID,
        "--output", "json",
        "--only-show-errors",
    ]


def _read_node(node: str, *, runner: Runner) -> dict[str, Any]:
    common = _common()
    vm = _json([
        "az", "vm", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
        "--name", node, *common, "--query",
        "{id:id,name:name,location:location,provisioningState:provisioningState,tags:tags,nicIds:networkProfile.networkInterfaces[].id}",
    ], node + " VM", runner)
    power = _json([
        "az", "vm", "get-instance-view", "--resource-group", EXPECTED_RESOURCE_GROUP,
        "--name", node, *common, "--query",
        "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]",
    ], node + " power state", runner)
    nic = _json([
        "az", "network", "nic", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
        "--name", node + "-nic", *common, "--query",
        "{id:id,name:name,location:location,provisioningState:provisioningState,tags:tags,enableIPForwarding:enableIPForwarding,enableAcceleratedNetworking:enableAcceleratedNetworking,networkSecurityGroupId:networkSecurityGroup.id,ipConfigurations:ipConfigurations[].{name:name,primary:primary,privateIPAddress:privateIPAddress,privateIPAllocationMethod:privateIPAllocationMethod,privateIPAddressVersion:privateIPAddressVersion,subnetId:subnet.id,publicIpId:publicIPAddress.id}}",
    ], node + " NIC", runner)
    nsg = _json([
        "az", "network", "nsg", "show", "--resource-group", EXPECTED_RESOURCE_GROUP,
        "--name", node + "-nsg", *common, "--query",
        "{id:id,name:name,location:location,provisioningState:provisioningState,tags:tags,networkInterfaceIds:networkInterfaces[].id,subnetIds:subnets[].id}",
    ], node + " NSG", runner)
    return {"name": node, "nic": nic, "nsg": nsg, "powerState": power, "vm": vm}


def _read_rules(nsg: str, *, runner: Runner) -> list[dict[str, Any]]:
    result = _json([
        "az", "network", "nsg", "rule", "list",
        "--resource-group", EXPECTED_RESOURCE_GROUP,
        "--nsg-name", nsg,
        *_common(),
        "--query",
        "sort_by([],&name)[].{name:name,description:description,priority:priority,protocol:protocol,access:access,direction:direction,sourcePrefix:sourceAddressPrefix,sourcePrefixes:sourceAddressPrefixes,sourcePortRange:sourcePortRange,sourcePortRanges:sourcePortRanges,destinationPrefix:destinationAddressPrefix,destinationPrefixes:destinationAddressPrefixes,destinationPortRange:destinationPortRange,destinationPortRanges:destinationPortRanges,provisioningState:provisioningState,etag:etag}",
    ], nsg + " custom rules", runner)
    if not isinstance(result, list):
        raise OverlayError("{} rule inventory is not a list".format(nsg))
    return result


def _read_overlay_deployment_state(*, runner: Runner) -> str:
    try:
        state = _json(
            [
                "az", "deployment", "group", "show",
                "--name", DEPLOYMENT_NAME,
                "--resource-group", EXPECTED_RESOURCE_GROUP,
                *_common(),
                "--query", "properties.provisioningState",
            ],
            "overlay deployment state",
            runner,
        )
    except OverlayError as exc:
        detail = str(exc)
        if any(
            marker in detail
            for marker in ("DeploymentNotFound", "ResourceNotFound", "could not be found")
        ):
            return "ABSENT"
        raise
    if state not in {"Canceled", "Failed", "Succeeded"}:
        raise OverlayError("overlay deployment is not absent or terminal")
    return state


def collect_observations(
    action: str,
    *,
    approved_direct_plan_sha256: str,
    runner: Runner = _run,
    include_what_if: bool = True,
    artifacts: CompiledArtifacts | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    common = _common()
    account = _json([
        "az", "account", "show", *common,
        "--query", "{id:id,tenantId:tenantId,state:state}",
    ], "Azure account", runner)
    group = _json([
        "az", "group", "show", "--name", EXPECTED_RESOURCE_GROUP, *common,
        "--query", "{id:id,name:name,location:location,properties:properties}",
    ], "resource group", runner)
    nodes = [_read_node(node, runner=runner) for node in NODE_SPECS]
    cp1_rules = _read_rules(EXPECTED_CP1_NSG, runner=runner)
    g2_rules = {
        node: _read_rules(node + "-nsg", runner=runner) for node in G2_NODES
    }
    budget_url = (
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/"
        "Microsoft.Consumption/budgets/{}?api-version=2023-11-01"
    ).format(EXPECTED_SUBSCRIPTION_ID, EXPECTED_RESOURCE_GROUP, EXPECTED_BUDGET_NAME)
    budget = _json([
        "az", "rest", "--method", "get", "--url", budget_url, *common,
    ], "POC budget", runner)
    generation3_authority = collect_generation3_authority(
        approved_direct_plan_sha256,
        action=action,
        runner=runner,
        now=now,
    )
    overlay_deployment_state = _read_overlay_deployment_state(runner=runner)
    what_if = None
    if action == "apply" and include_what_if:
        if artifacts is None:
            raise OverlayError("apply What-If requires protected compiled artifacts")
        artifacts.verify(artifacts.package.evidence)
        what_if = _json([
            "az", "deployment", "group", "what-if",
            "--name", DEPLOYMENT_NAME,
            "--resource-group", EXPECTED_RESOURCE_GROUP,
            *artifacts.deployment_arguments(),
            "--result-format", "ResourceIdOnly",
            "--no-pretty-print",
            "--validation-level", "Provider",
            *common,
        ], "provider what-if", runner)
    return {
        "account": account,
        "action": action,
        "budget": budget,
        "cp1Rules": cp1_rules,
        "g2Rules": g2_rules,
        "generation3Authority": generation3_authority,
        "nodes": nodes,
        "overlayDeploymentState": overlay_deployment_state,
        "resourceGroup": group,
        "whatIf": what_if,
    }


def _validate_node(record: Any, *, expected_power: str) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("name") not in NODE_SPECS:
        raise OverlayError("node observation is malformed or unexpected")
    node = record["name"]
    private_ip, subnet = NODE_SPECS[node]
    vm, nic, nsg = record.get("vm"), record.get("nic"), record.get("nsg")
    expected_vm_id = _resource_id("Microsoft.Compute/virtualMachines", node)
    expected_nic_id = _resource_id("Microsoft.Network/networkInterfaces", node + "-nic")
    expected_nsg_id = _resource_id("Microsoft.Network/networkSecurityGroups", node + "-nsg")
    expected_pip_id = _resource_id("Microsoft.Network/publicIPAddresses", node + "-pip")
    if (
        not isinstance(vm, dict)
        or not _same_id(vm.get("id"), expected_vm_id)
        or vm.get("name") != node
        or str(vm.get("location", "")).lower() != EXPECTED_LOCATION
        or vm.get("provisioningState") != "Succeeded"
        or not isinstance(vm.get("nicIds"), list)
        or len(vm["nicIds"]) != 1
        or not _same_id(vm["nicIds"][0], expected_nic_id)
        or record.get("powerState") != expected_power
    ):
        raise OverlayError("VM identity/power drifted for {}".format(node))
    if (
        not isinstance(nic, dict)
        or not _same_id(nic.get("id"), expected_nic_id)
        or nic.get("name") != node + "-nic"
        or str(nic.get("location", "")).lower() != EXPECTED_LOCATION
        or nic.get("provisioningState") != "Succeeded"
        or nic.get("enableIPForwarding") is not False
        or nic.get("enableAcceleratedNetworking") is not False
        or not _same_id(nic.get("networkSecurityGroupId"), expected_nsg_id)
    ):
        raise OverlayError("NIC identity/policy drifted for {}".format(node))
    configs = nic.get("ipConfigurations")
    if not isinstance(configs, list) or len(configs) != 1:
        raise OverlayError("NIC IP configuration cardinality drifted for {}".format(node))
    config = configs[0]
    if (
        not isinstance(config, dict)
        or config.get("name") != "ipconfig1"
        or config.get("primary") is not True
        or config.get("privateIPAddress") != private_ip
        or config.get("privateIPAllocationMethod") != "Static"
        or config.get("privateIPAddressVersion") != "IPv4"
        or not _same_id(config.get("subnetId"), _subnet_id(subnet))
        or not _same_id(config.get("publicIpId"), expected_pip_id)
    ):
        raise OverlayError("static private-IP binding drifted for {}".format(node))
    if (
        not isinstance(nsg, dict)
        or not _same_id(nsg.get("id"), expected_nsg_id)
        or nsg.get("name") != node + "-nsg"
        or str(nsg.get("location", "")).lower() != EXPECTED_LOCATION
        or nsg.get("provisioningState") != "Succeeded"
        or not isinstance(nsg.get("networkInterfaceIds"), list)
        or len(nsg["networkInterfaceIds"]) != 1
        or not _same_id(nsg["networkInterfaceIds"][0], expected_nic_id)
        or nsg.get("subnetIds") not in (None, [])
    ):
        raise OverlayError("NSG attachment drifted for {}".format(node))
    deadline = None
    if node in G3_NODES:
        tags = vm.get("tags")
        deadline = tags.get("parallelAcceptanceDeadlineUtc") if isinstance(tags, dict) else None
        _parse_utc(deadline, "generation-3 parallel acceptance deadline")
        expected_tags = _replacement_tags(node, deadline)
        if tags != expected_tags or nsg.get("tags") != expected_tags or nic.get(
            "tags"
        ) != expected_tags:
            raise OverlayError("generation-3 runtime identity tags drifted for {}".format(node))
    return {
        "nicId": expected_nic_id,
        "node": node,
        "nsgId": expected_nsg_id,
        "powerState": expected_power,
        "privateIpv4": private_ip,
        "runtimeTagsSha256": _digest(vm.get("tags")) if node in G3_NODES else None,
        "parallelAcceptanceDeadlineUtc": deadline,
        "subnetId": _subnet_id(subnet),
        "vmId": expected_vm_id,
    }


def _validate_budget(
    budget: Any, *, observed_at: datetime
) -> dict[str, Any]:
    expected_id = (
        _resource_group_id()
        + "/providers/Microsoft.Consumption/budgets/"
        + EXPECTED_BUDGET_NAME
    )
    properties = budget.get("properties") if isinstance(budget, dict) else None
    if (
        not isinstance(budget, dict)
        or budget.get("name") != EXPECTED_BUDGET_NAME
        or not _same_id(budget.get("id"), expected_id)
        or str(budget.get("type", "")).lower() != "microsoft.consumption/budgets"
        or not isinstance(properties, dict)
        or _decimal(properties.get("amount"), "POC budget amount") != EXPECTED_BUDGET_AMOUNT
        or properties.get("category") != "Cost"
        or properties.get("timeGrain") != "Monthly"
        or properties.get("filter") not in (None, {})
    ):
        raise OverlayError("exact USD 100 POC budget drifted")
    period = properties.get("timePeriod")
    if not isinstance(period, dict) or set(period) != {"startDate", "endDate"}:
        raise OverlayError("POC budget time period is malformed")
    start = _parse_utc(period.get("startDate"), "POC budget startDate")
    end = _parse_utc(period.get("endDate"), "POC budget endDate")
    current = observed_at.astimezone(timezone.utc)
    if (
        start.day != 1
        or (start.hour, start.minute, start.second, start.microsecond) != (0, 0, 0, 0)
        or (end.hour, end.minute, end.second, end.microsecond) != (0, 0, 0, 0)
        or start > current
        or end.date() < current.date()
        or end <= start
    ):
        raise OverlayError("POC budget is not active on an exact monthly boundary")
    notifications = properties.get("notifications")
    if not isinstance(notifications, dict) or len(notifications) != 3:
        raise OverlayError("POC budget notification cardinality drifted")
    found: set[Decimal] = set()
    for notification in notifications.values():
        if not isinstance(notification, dict):
            raise OverlayError("POC budget notification is malformed")
        threshold = _decimal(notification.get("threshold"), "POC budget threshold")
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
            raise OverlayError("POC budget notification drifted")
        found.add(threshold)
    if found != EXPECTED_BUDGET_THRESHOLDS:
        raise OverlayError("POC budget thresholds are not exactly 75/90/100")
    current_spend = properties.get("currentSpend")
    if (
        not isinstance(current_spend, dict)
        or set(current_spend) != {"amount", "unit"}
        or current_spend.get("unit") != "USD"
    ):
        raise OverlayError("POC resource-group budget currentSpend is malformed")
    amount = _decimal(current_spend.get("amount"), "POC budget currentSpend")
    if amount < 0 or amount > EXPECTED_BUDGET_AMOUNT:
        raise OverlayError("POC resource-group spend is outside the USD 100 budget")
    amount = amount.quantize(Decimal("0.01"))
    contract = {
        "budgetId": expected_id.lower(),
        "endDate": period["endDate"],
        "startDate": period["startDate"],
        "thresholds": [75, 90, 100],
    }
    return {
        "budgetAmountUsd": "100.00",
        "budgetContractSha256": _digest(contract),
        "budgetScope": _resource_group_id(),
        "currentSpendUsd": str(amount),
        "incrementalOverlayCostUsd": "0.00",
        "remainingBudgetUsd": str(EXPECTED_BUDGET_AMOUNT - amount),
        "thresholds": [75, 90, 100],
    }


def _decimal(value: Any, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise OverlayError("{} is malformed".format(label)) from exc
    if not result.is_finite():
        raise OverlayError("{} must be finite".format(label))
    return result


def _validate_cp1_rules(rules: Any) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(rules, list):
        raise OverlayError("CP1 rule inventory is malformed")
    contracts = sorted([_contract_rule(item) for item in rules], key=lambda item: item["name"])
    base_by_name = {item["name"]: item for item in CP1_BASE_RULES}
    observed_by_name = {item["name"]: item for item in contracts}
    if len(observed_by_name) != len(contracts):
        raise OverlayError("CP1 NSG contains duplicate custom rule names")
    for name, expected in base_by_name.items():
        if observed_by_name.get(name) != expected:
            raise OverlayError("CP1 synthetic base NSG rule drifted: {}".format(name))
    extras = set(observed_by_name) - set(base_by_name)
    if not extras.issubset(OVERLAY_BY_NAME):
        raise OverlayError("CP1 NSG contains an unapproved extra custom rule")
    overlays: list[dict[str, Any]] = []
    raw_by_name = {item.get("name"): item for item in rules if isinstance(item, dict)}
    for name in sorted(extras):
        if observed_by_name[name] != OVERLAY_BY_NAME[name]:
            raise OverlayError("CP1 carrier overlay rule drifted: {}".format(name))
        etag = raw_by_name[name].get("etag")
        if not isinstance(etag, str) or not etag:
            raise OverlayError("CP1 carrier overlay rule lacks an ETag")
        overlays.append({
            "etag": etag,
            "id": _rule_id(name),
            "name": name,
            "rule": observed_by_name[name],
        })
    state = (
        "ABSENT"
        if not extras
        else "EXACT"
        if extras == set(OVERLAY_BY_NAME)
        else "PARTIAL"
    )
    return state, overlays


def _validate_what_if(
    value: Any, overlay_rules: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") != "Succeeded":
        raise OverlayError("provider-level group what-if did not succeed")
    changes = value.get("changes")
    if not isinstance(changes, list) or len(changes) != 2:
        raise OverlayError("provider what-if must contain exactly two child-rule changes")
    expected_ids = {_rule_id(name).lower() for name in OVERLAY_BY_NAME}
    present = {str(item.get("name")) for item in overlay_rules}
    if not present.issubset(OVERLAY_BY_NAME):
        raise OverlayError("provider what-if overlay presence is malformed")
    expected_by_id = {
        _rule_id(name).lower(): "NoChange" if name in present else "Create"
        for name in OVERLAY_BY_NAME
    }
    normalized = []
    for change in changes:
        if not isinstance(change, dict):
            raise OverlayError("provider what-if contains a malformed change")
        resource_id = str(change.get("resourceId", "")).lower()
        change_type = change.get("changeType")
        if resource_id not in expected_ids or change_type != expected_by_id[resource_id]:
            raise OverlayError(
                "provider what-if does not match exact missing/present child rules"
            )
        normalized.append({"changeType": change_type, "resourceId": resource_id})
    if {item["resourceId"] for item in normalized} != expected_ids:
        raise OverlayError("provider what-if omits or duplicates an overlay rule")
    return {"changes": sorted(normalized, key=lambda item: item["resourceId"]), "sha256": _digest(value)}


def validate_observations(
    observations: Mapping[str, Any],
    *,
    action: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if action not in {"apply", "teardown"} or observations.get("action") != action:
        raise OverlayError("observation action is not exact")
    if observations.get("overlayDeploymentState") not in {
        "ABSENT", "Canceled", "Failed", "Succeeded"
    }:
        raise OverlayError("overlay deployment must be absent or terminal")
    if observations.get("account") != {
        "id": EXPECTED_SUBSCRIPTION_ID,
        "state": "Enabled",
        "tenantId": EXPECTED_TENANT_ID,
    }:
        raise OverlayError("authenticated Azure subscription/tenant authority drifted")
    group = observations.get("resourceGroup")
    properties = group.get("properties") if isinstance(group, dict) else None
    if (
        not isinstance(group, dict)
        or not _same_id(group.get("id"), _resource_group_id())
        or group.get("name") != EXPECTED_RESOURCE_GROUP
        or str(group.get("location", "")).lower() != EXPECTED_LOCATION
        or not isinstance(properties, dict)
        or properties.get("provisioningState") != "Succeeded"
    ):
        raise OverlayError("POC resource-group identity drifted")
    nodes = observations.get("nodes")
    by_name = {
        item.get("name"): item
        for item in nodes if isinstance(nodes, list) and isinstance(item, dict)
    } if isinstance(nodes, list) else {}
    if set(by_name) != set(NODE_SPECS) or len(nodes or []) != len(NODE_SPECS):
        raise OverlayError("CP1/g2/g3 node inventory is not exact")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    bindings = []
    for node in sorted(NODE_SPECS):
        power = (
            "PowerState/deallocated"
            if action == "teardown" and node in G3_NODES
            else "PowerState/running"
        )
        bindings.append(_validate_node(by_name[node], expected_power=power))
    deadlines = {
        item["parallelAcceptanceDeadlineUtc"]
        for item in bindings
        if item["node"] in G3_NODES
    }
    if len(deadlines) != 1:
        raise OverlayError("generation-3 nodes do not share one immutable acceptance deadline")
    deadline = _parse_utc(next(iter(deadlines)), "generation-3 parallel acceptance deadline")
    if action == "apply" and deadline <= current:
        raise OverlayError("generation-3 parallel acceptance deadline has expired")
    generation3_authority = observations.get("generation3Authority")
    expected_authority_keys = {
        "compiledParametersSha256", "compiledTemplateSha256", "deadlineUtc",
        "deadmanJobId", "deadmanReceiptSha256", "directReplacementPlanSha256",
        "liveDeadmanJobSha256", "schedulerAuthoritySha256", "schedulerLive",
    }
    if (
        not isinstance(generation3_authority, dict)
        or set(generation3_authority) != expected_authority_keys
        or generation3_authority.get("deadlineUtc") != _utc(deadline)
        or not all(
            isinstance(generation3_authority.get(name), str)
            and len(generation3_authority[name]) == 64
            for name in (
                "compiledParametersSha256", "compiledTemplateSha256",
                "deadmanReceiptSha256", "directReplacementPlanSha256",
            )
        )
        or (
            action == "apply"
            and (
                generation3_authority.get("schedulerLive") is not True
                or not isinstance(
                    generation3_authority.get("liveDeadmanJobSha256"), str
                )
                or not isinstance(
                    generation3_authority.get("schedulerAuthoritySha256"), str
                )
            )
        )
        or (
            action == "teardown"
            and (
                generation3_authority.get("schedulerLive") is not False
                or generation3_authority.get("liveDeadmanJobSha256") is not None
                or generation3_authority.get("schedulerAuthoritySha256") is not None
            )
        )
    ):
        raise OverlayError("generation-3 reviewed plan/deadman authority drifted")
    g2 = observations.get("g2Rules")
    if not isinstance(g2, dict) or set(g2) != set(G2_NODES):
        raise OverlayError("generation-2 NSG observations are incomplete")
    for node in G2_NODES:
        actual = sorted([_contract_rule(item) for item in g2[node]], key=lambda item: item["name"])
        if actual != G2_RULES_BY_NODE[node]:
            raise OverlayError("generation-2 synthetic NSG drifted for {}".format(node))
    overlay_state, overlay_rules = _validate_cp1_rules(observations.get("cp1Rules"))
    budget = _validate_budget(observations.get("budget"), observed_at=current)
    core = {
        "account": observations["account"],
        "cp1BaseRules": CP1_BASE_RULES,
        "g2SyntheticRules": G2_RULES_BY_NODE,
        "generation3Authority": generation3_authority,
        "nodeBindings": bindings,
        "resourceGroup": {
            "id": _resource_group_id(),
            "location": EXPECTED_LOCATION,
            "name": EXPECTED_RESOURCE_GROUP,
            "provisioningState": "Succeeded",
        },
    }
    what_if = None
    if action == "apply" and observations.get("whatIf") is not None:
        what_if = _validate_what_if(observations["whatIf"], overlay_rules)
    return {
        "budget": budget,
        "coreStateSha256": _digest(core),
        "generation3Authority": generation3_authority,
        "nodeBindings": bindings,
        "overlayRules": overlay_rules,
        "overlayState": overlay_state,
        "providerWhatIf": what_if,
    }


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_plan(
    action: str,
    observations: Mapping[str, Any],
    package: Mapping[str, str],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if action not in {"apply", "teardown"}:
        raise OverlayError("plan action must be apply or teardown")
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    evidence = validate_observations(observations, action=action, now=observed_at)
    if action == "apply" and evidence["providerWhatIf"] is None:
        raise OverlayError("apply plan requires provider-level what-if")
    expires = observed_at + timedelta(minutes=PLAN_MAX_AGE_MINUTES)
    body = {
        "action": action,
        "apiVersion": API_VERSION,
        "authority": {
            "resourceGroup": EXPECTED_RESOURCE_GROUP,
            "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
            "tenantId": EXPECTED_TENANT_ID,
        },
        "budget": evidence["budget"],
        "confirmationPhrase": APPLY_CONFIRMATION if action == "apply" else TEARDOWN_CONFIRMATION,
        "coreStateSha256": evidence["coreStateSha256"],
        "deploymentName": DEPLOYMENT_NAME,
        "expiresAtUtc": _utc(expires),
        "generatedAtUtc": _utc(observed_at),
        "generation3Authority": evidence["generation3Authority"],
        "kind": PLAN_KIND,
        "nodeBindings": evidence["nodeBindings"],
        "overlayRules": evidence["overlayRules"],
        "overlayState": evidence["overlayState"],
        "package": dict(package),
        "providerWhatIf": evidence["providerWhatIf"],
    }
    return {**body, "planSha256": _digest(body), "status": "CP1_CARRIER_NSG_OVERLAY_PLAN_VALID"}


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OverlayError("{} must be canonical UTC".format(label))
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise OverlayError("{} must be canonical UTC".format(label)) from exc


def read_plan(path: Path, *, supplied_sha256: str, confirmation: str, now: datetime | None = None) -> dict[str, Any]:
    if path.is_symlink():
        raise OverlayError("plan file must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise OverlayError("plan file is unavailable") from exc
    if (
        resolved != EXPECTED_PLAN_PATH.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
    ):
        raise OverlayError("plan must be the exact owner-only protected plan file")
    value = _strict_json(raw, "saved plan")
    if not isinstance(value, dict):
        raise OverlayError("saved plan must be one object")
    expected_keys = {
        "action", "apiVersion", "authority", "budget", "confirmationPhrase",
        "coreStateSha256", "deploymentName", "expiresAtUtc", "generatedAtUtc",
        "generation3Authority", "kind", "nodeBindings", "overlayRules",
        "overlayState", "package",
        "planSha256", "providerWhatIf", "status",
    }
    if set(value) != expected_keys:
        raise OverlayError("saved plan fields are not exact")
    body = {key: item for key, item in value.items() if key not in {"planSha256", "status"}}
    digest = _digest(body)
    if value.get("planSha256") != digest or supplied_sha256 != digest:
        raise OverlayError("saved plan SHA-256 does not match exact supplied authority")
    if value.get("confirmationPhrase") != confirmation or confirmation not in {
        APPLY_CONFIRMATION, TEARDOWN_CONFIRMATION
    }:
        raise OverlayError("exact confirmation phrase is missing")
    expected_phrase = (
        APPLY_CONFIRMATION if value.get("action") == "apply" else TEARDOWN_CONFIRMATION
        if value.get("action") == "teardown" else None
    )
    if confirmation != expected_phrase:
        raise OverlayError("confirmation phrase does not match the saved plan action")
    if value.get("authority") != {
        "resourceGroup": EXPECTED_RESOURCE_GROUP,
        "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
        "tenantId": EXPECTED_TENANT_ID,
    } or value.get("deploymentName") != DEPLOYMENT_NAME:
        raise OverlayError("saved plan Azure authority/deployment identity drifted")
    if value.get("apiVersion") != API_VERSION or value.get("kind") != PLAN_KIND or value.get(
        "status"
    ) != "CP1_CARRIER_NSG_OVERLAY_PLAN_VALID":
        raise OverlayError("saved plan contract identity drifted")
    _require_plan_fresh(value, now=now)
    if value.get("package") != {
        "bicepCompilerVersion": EXPECTED_BICEP_VERSION,
        "compiledParametersSha256": EXPECTED_COMPILED_PARAMETERS_SHA256,
        "compiledTemplateSha256": EXPECTED_COMPILED_TEMPLATE_SHA256,
    }:
        raise OverlayError("saved plan package digests drifted")
    return value


def _require_reobserved(plan: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    if evidence.get("coreStateSha256") != plan.get("coreStateSha256"):
        raise OverlayError("Azure topology changed after planning")
    if evidence.get("overlayState") != plan.get("overlayState") or evidence.get(
        "overlayRules"
    ) != plan.get("overlayRules"):
        raise OverlayError("CP1 overlay state/ETag changed after planning")
    if plan.get("action") == "apply" and evidence.get("providerWhatIf") != plan.get(
        "providerWhatIf"
    ):
        raise OverlayError("provider what-if changed after planning")
    planned_budget = plan.get("budget")
    current_budget = evidence.get("budget")
    if (
        not isinstance(planned_budget, dict)
        or not isinstance(current_budget, dict)
        or planned_budget.get("budgetContractSha256")
        != current_budget.get("budgetContractSha256")
    ):
        raise OverlayError("resource-group budget contract changed after planning")
    if evidence.get("generation3Authority") != plan.get("generation3Authority"):
        raise OverlayError("generation-3 reviewed plan/deadman authority changed")


def _require_plan_fresh(
    plan: Mapping[str, Any], *, now: datetime | None = None, reserve_seconds: int = 0
) -> datetime:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated = _parse_utc(plan.get("generatedAtUtc"), "generatedAtUtc")
    expires = _parse_utc(plan.get("expiresAtUtc"), "expiresAtUtc")
    if (
        expires - generated != timedelta(minutes=PLAN_MAX_AGE_MINUTES)
        or current < generated
        or current + timedelta(seconds=reserve_seconds) >= expires
    ):
        raise OverlayError("saved plan is outside its mutation authorization window")
    return expires


def _require_package_at_mutation(
    plan: Mapping[str, Any], artifacts: CompiledArtifacts
) -> None:
    fresh = compile_package()
    if fresh != plan.get("package"):
        raise OverlayError("fresh compiled package differs at the mutation boundary")
    artifacts.verify(fresh)


def _command_result(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=max(1.0, timeout),
    )


def _cancel_and_settle_deployment() -> None:
    cancel = _command_result(
        [
            "az", "deployment", "group", "cancel",
            "--name", DEPLOYMENT_NAME,
            "--resource-group", EXPECTED_RESOURCE_GROUP,
            *_common(),
        ],
        DEPLOYMENT_CANCEL_TIMEOUT_SECONDS,
    )
    cancel_detail = cancel.stderr.strip() or cancel.stdout.strip()
    if cancel.returncode != 0 and not any(
        marker in cancel_detail
        for marker in ("DeploymentNotFound", "ResourceNotFound", "could not be found")
    ):
        raise OverlayError("timed-out overlay deployment could not be cancelled")
    deadline = time.monotonic() + DEPLOYMENT_SETTLE_TIMEOUT_SECONDS
    terminal = {"Canceled", "Failed", "Succeeded"}
    while time.monotonic() < deadline:
        shown = _command_result(
            [
                "az", "deployment", "group", "show",
                "--name", DEPLOYMENT_NAME,
                "--resource-group", EXPECTED_RESOURCE_GROUP,
                *_common(),
                "--query", "properties.provisioningState",
            ],
            DEPLOYMENT_CANCEL_TIMEOUT_SECONDS,
        )
        detail = shown.stderr.strip() or shown.stdout.strip()
        if shown.returncode != 0:
            if any(
                marker in detail
                for marker in (
                    "DeploymentNotFound", "ResourceNotFound", "could not be found"
                )
            ):
                return
            raise OverlayError("timed-out deployment terminal state is unreadable")
        state = _strict_json(shown.stdout, "deployment terminal state")
        if state in terminal:
            return
        time.sleep(2)
    raise OverlayError("timed-out overlay deployment did not reach a terminal state")


def _run_deployment_with_deadline(
    argv: Sequence[str],
    plan: Mapping[str, Any],
    *,
    runner: Runner,
    now: datetime | None = None,
) -> str:
    expires = _require_plan_fresh(
        plan,
        now=now,
        reserve_seconds=DEPLOYMENT_COMPLETION_RESERVE_SECONDS,
    )
    if runner is not _run:
        return runner(argv)
    timeout = (
        expires - (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    ).total_seconds() - DEPLOYMENT_COMPLETION_RESERVE_SECONDS
    if timeout <= 0:
        raise OverlayError("insufficient plan lifetime for overlay deployment")
    try:
        result = _command_result(argv, timeout)
    except subprocess.TimeoutExpired as exc:
        _cancel_and_settle_deployment()
        raise OverlayError(
            "overlay deployment crossed authorization and was cancelled"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise OverlayError("Azure/Bicep command failed: {}".format(detail))
    return result.stdout


def apply_plan(
    plan: Mapping[str, Any],
    *,
    runner: Runner = _run,
    artifacts: CompiledArtifacts | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if artifacts is None:
        with CompiledArtifacts(compile_package_bundle()) as materialized:
            return apply_plan(
                plan,
                runner=runner,
                artifacts=materialized,
                now=now,
            )
    action = plan.get("action")
    approved_direct_plan_sha256 = plan.get("generation3Authority", {}).get(
        "directReplacementPlanSha256"
    )
    if action == "apply":
        observations = collect_observations(
            "apply",
            approved_direct_plan_sha256=approved_direct_plan_sha256,
            runner=runner,
            include_what_if=True,
            artifacts=artifacts,
            now=now,
        )
        evidence = validate_observations(observations, action="apply", now=now)
        _require_reobserved(plan, evidence)
        _require_package_at_mutation(plan, artifacts)
        _require_plan_fresh(
            plan,
            now=now,
            reserve_seconds=DEPLOYMENT_COMPLETION_RESERVE_SECONDS,
        )
        deployment_command = [
            "az", "deployment", "group", "create",
            "--name", DEPLOYMENT_NAME,
            "--resource-group", EXPECTED_RESOURCE_GROUP,
            *artifacts.deployment_arguments(),
            "--mode", "Incremental",
            *_common(),
            "--query", "{id:id,name:name,provisioningState:properties.provisioningState}",
        ]
        result = _strict_json(
            _run_deployment_with_deadline(
                deployment_command, plan, runner=runner, now=now
            ),
            "overlay deployment",
        )
        if not isinstance(result, dict) or not _same_id(
            result.get("id"),
            _resource_id("Microsoft.Resources/deployments", DEPLOYMENT_NAME),
        ) or result.get("name") != DEPLOYMENT_NAME or result.get(
            "provisioningState"
        ) != "Succeeded":
            raise OverlayError("provider deployment did not complete exactly")
        post = validate_observations(
            collect_observations(
                "apply",
                approved_direct_plan_sha256=approved_direct_plan_sha256,
                runner=runner,
                include_what_if=False,
                artifacts=artifacts,
            ),
            action="apply",
        )
        if post["coreStateSha256"] != plan["coreStateSha256"] or post[
            "overlayState"
        ] != "EXACT":
            raise OverlayError("overlay postcondition failed")
        return {
            "action": "apply",
            "deploymentName": DEPLOYMENT_NAME,
            "overlayState": "EXACT",
            "planSha256": plan["planSha256"],
            "status": "CP1_CARRIER_NSG_OVERLAY_APPLIED",
        }

    if action != "teardown":
        raise OverlayError("saved plan action is invalid")
    observations = collect_observations(
        "teardown",
        approved_direct_plan_sha256=approved_direct_plan_sha256,
        runner=runner,
        include_what_if=False,
        artifacts=artifacts,
        now=now,
    )
    evidence = validate_observations(observations, action="teardown", now=now)
    if evidence["coreStateSha256"] != plan.get("coreStateSha256"):
        raise OverlayError("Azure topology changed after teardown planning")
    planned = {item["name"]: item for item in plan.get("overlayRules", [])}
    current = {item["name"]: item for item in evidence["overlayRules"]}
    if not set(current).issubset(planned):
        raise OverlayError("teardown observation is outside the planned overlay")
    for name, item in current.items():
        if item != planned[name]:
            raise OverlayError("overlay rule/ETag changed after teardown planning")
    _require_package_at_mutation(plan, artifacts)
    for name in sorted(current):
        item = current[name]
        _require_plan_fresh(plan, now=now)
        runner([
            "az", "rest", "--method", "delete",
            "--url", "https://management.azure.com{}?api-version=2023-11-01".format(item["id"]),
            "--headers", "If-Match={}".format(item["etag"]),
            *_common(),
        ])
    post = validate_observations(
        collect_observations(
            "teardown",
            approved_direct_plan_sha256=approved_direct_plan_sha256,
            runner=runner,
            include_what_if=False,
            artifacts=artifacts,
        ),
        action="teardown",
    )
    if post["coreStateSha256"] != plan["coreStateSha256"] or post[
        "overlayState"
    ] != "ABSENT":
        raise OverlayError("teardown postcondition failed")
    return {
        "action": "teardown",
        "deletedRuleNames": sorted(current),
        "overlayState": "ABSENT",
        "planSha256": plan["planSha256"],
        "status": "CP1_CARRIER_NSG_OVERLAY_REMOVED",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="read-only exact live plan")
    plan_parser.add_argument("--action", choices=("apply", "teardown"), required=True)
    plan_parser.add_argument("--direct-replacement-plan-sha256", required=True)
    execute_parser = subparsers.add_parser("execute", help="execute one protected fresh plan")
    execute_parser.add_argument("--plan", type=Path, required=True)
    execute_parser.add_argument("--plan-sha256", required=True)
    execute_parser.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    try:
        package = compile_package_bundle()
        with CompiledArtifacts(package) as artifacts:
            if args.command == "plan":
                observations = collect_observations(
                    args.action,
                    approved_direct_plan_sha256=args.direct_replacement_plan_sha256,
                    artifacts=artifacts,
                )
                print(
                    json.dumps(
                        create_plan(
                            args.action, observations, package.evidence
                        ),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            else:
                plan = read_plan(
                    args.plan,
                    supplied_sha256=args.plan_sha256,
                    confirmation=args.confirm,
                )
                print(
                    json.dumps(
                        apply_plan(plan, artifacts=artifacts),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
    except (OverlayError, OSError, InvalidOperation) as exc:
        print("CP1_CARRIER_NSG_OVERLAY_REFUSED: {}".format(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
