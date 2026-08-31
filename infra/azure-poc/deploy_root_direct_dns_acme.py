#!/usr/bin/env python3
"""Plan and apply the exact additive root Direct DNS/ACME deployment.

Planning is read-only and writes one owner-only, self-digested plan.  Apply
recompiles the reviewed Bicep package, re-observes every DNS/RBAC/VM boundary
and provider What-If, then executes only the exact subscription deployment.
An interrupted deployment is resumable only when every extant owned resource
is exact and the prior deployment record is bound to the same parameters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import root_direct_dns_acme_contract as contract


API_VERSION = "infra.vivolution.ae/root-direct-dns-acme-create-plan/v0.1"
KIND = "RootDirectDnsAcmeCreatePlan"
DEPLOYMENT_NAME = "viv-sbc-poc-root-direct-dns-acme"
CONFIRMATION = "APPLY-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY"
PLAN_MAX_AGE_MINUTES = 10
EXPECTED_BICEP_VERSION = "0.46.1.21595"
EXPECTED_TEMPLATE_SHA256 = (
    "01374c71420c3faefdec5c8094c6b086486f02bb265cd9cf51361beb8fa11904"
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PARAMETER_PATH = (
    PROJECT_ROOT / "deploy/.state/root-direct-dns-acme.bicepparam"
)
EXPECTED_PLAN_PATH = (
    PROJECT_ROOT / "deploy/.state/root-direct-dns-acme-create-plan.json"
)


class RootDirectDnsDeployError(contract.RootDirectDnsError):
    """The protected create authority could not be proved."""


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
                raise RootDirectDnsDeployError(f"{label} contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise RootDirectDnsDeployError(f"{label} is malformed JSON") from exc


def _expected_parameter_values(inputs: contract.ExpectedInputs) -> dict[str, str]:
    return {
        "carrierPublicIpv4": inputs.carrier_public_ipv4,
        "cp1PrincipalId": inputs.cp1_principal_id,
        "sbc1PrincipalId": inputs.sbc1_principal_id,
        "sbc1PublicIpv4": inputs.sbc1_public_ipv4,
        "sbc2PrincipalId": inputs.sbc2_principal_id,
        "sbc2PublicIpv4": inputs.sbc2_public_ipv4,
    }


def _parameter_values(value: Any, *, allow_defaults: bool) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RootDirectDnsDeployError("compiled/deployed parameter inventory is malformed")
    result: dict[str, Any] = {}
    for name, wrapper in value.items():
        if not isinstance(wrapper, dict) or set(wrapper) != {"value"}:
            raise RootDirectDnsDeployError("parameter wrapper shape drifted")
        result[str(name)] = wrapper["value"]
    allowed_defaults = {
        "dnsResourceGroupName": contract.DNS_RESOURCE_GROUP,
        "dnsZoneName": contract.ROOT_ZONE,
    }
    if allow_defaults:
        for name, expected in allowed_defaults.items():
            if name in result and result[name] != expected:
                raise RootDirectDnsDeployError("deployment default parameter drifted")
    elif set(result) & set(allowed_defaults):
        raise RootDirectDnsDeployError("compiled parameters unexpectedly materialized defaults")
    return result


def compile_package(
    inputs: contract.ExpectedInputs,
    *,
    path: Path = EXPECTED_PARAMETER_PATH,
    runner: contract.Runner = contract.run,
) -> dict[str, str]:
    contract.validate_inputs(inputs)
    if path.is_symlink():
        raise RootDirectDnsDeployError("root DNS parameter file must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw_source = resolved.read_bytes()
    except OSError as exc:
        raise RootDirectDnsDeployError("root DNS parameter file is unavailable") from exc
    if (
        resolved != EXPECTED_PARAMETER_PATH.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
    ):
        raise RootDirectDnsDeployError(
            "use the exact owner-only protected root DNS parameter file"
        )
    envelope = _strict_json(
        runner(["az", "bicep", "build-params", "--file", str(resolved), "--stdout"]),
        "Bicep package envelope",
    )
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"parametersJson", "templateJson", "templateSpecId"}
        or envelope.get("templateSpecId") is not None
    ):
        raise RootDirectDnsDeployError("Bicep package envelope drifted")
    parameters = _strict_json(str(envelope.get("parametersJson", "")), "compiled parameters")
    template = _strict_json(str(envelope.get("templateJson", "")), "compiled template")
    if (
        not isinstance(parameters, dict)
        or set(parameters) != {"$schema", "contentVersion", "parameters"}
        or parameters.get("contentVersion") != "1.0.0.0"
    ):
        raise RootDirectDnsDeployError("compiled parameter document shape drifted")
    actual_values = _parameter_values(parameters.get("parameters"), allow_defaults=False)
    if actual_values != _expected_parameter_values(inputs):
        raise RootDirectDnsDeployError("compiled parameter values differ from live bindings")
    metadata_value = template.get("metadata") if isinstance(template, dict) else None
    generator = metadata_value.get("_generator") if isinstance(metadata_value, dict) else None
    if (
        not isinstance(generator, dict)
        or generator.get("name") != "bicep"
        or generator.get("version") != EXPECTED_BICEP_VERSION
    ):
        raise RootDirectDnsDeployError("Bicep compiler identity drifted")
    template_digest = _digest(template)
    if template_digest != EXPECTED_TEMPLATE_SHA256:
        raise RootDirectDnsDeployError("compiled template differs from the reviewed package")
    return {
        "bicepCompilerVersion": EXPECTED_BICEP_VERSION,
        "compiledParametersSha256": _digest(parameters),
        "compiledTemplateSha256": template_digest,
        "parameterFileSha256": hashlib.sha256(raw_source).hexdigest(),
    }


def _deployment_history(
    inputs: contract.ExpectedInputs, *, runner: contract.Runner
) -> list[dict[str, Any]]:
    raw = _strict_json(
        runner(
            [
                "az", "deployment", "sub", "list",
                "--subscription", inputs.subscription_id,
                "--query",
                (
                    f"[?name=='{DEPLOYMENT_NAME}'].{{id:id,name:name,location:location,"
                    "provisioningState:properties.provisioningState,parameters:properties.parameters}}"
                ),
                "--output", "json", "--only-show-errors",
            ]
        ),
        "subscription deployment history",
    )
    if not isinstance(raw, list) or len(raw) > 1:
        raise RootDirectDnsDeployError("root DNS deployment history is ambiguous")
    if not raw:
        return []
    item = raw[0]
    expected_id = (
        f"/subscriptions/{inputs.subscription_id}/providers/"
        f"Microsoft.Resources/deployments/{DEPLOYMENT_NAME}"
    )
    if (
        not isinstance(item, dict)
        or not contract.same_id(item.get("id"), expected_id)
        or item.get("name") != DEPLOYMENT_NAME
        or str(item.get("location", "")).lower() != contract.POC_LOCATION
        or item.get("provisioningState")
        not in {"Accepted", "Running", "Failed", "Canceled", "Succeeded"}
    ):
        raise RootDirectDnsDeployError("root DNS deployment history identity drifted")
    values = _parameter_values(item.get("parameters"), allow_defaults=True)
    expected = _expected_parameter_values(inputs)
    if any(values.get(name) != value for name, value in expected.items()):
        raise RootDirectDnsDeployError("prior deployment used different authority bindings")
    if set(values) - set(expected) - {"dnsResourceGroupName", "dnsZoneName"}:
        raise RootDirectDnsDeployError("prior deployment contains undeclared parameters")
    return [
        {
            "id": expected_id,
            "location": contract.POC_LOCATION,
            "name": DEPLOYMENT_NAME,
            "parametersSha256": _digest(values),
            "provisioningState": item["provisioningState"],
        }
    ]


def _resource_state(discovery: Mapping[str, Any]) -> dict[str, Any]:
    authority = discovery.get("authority")
    observed = discovery.get("observed")
    if not isinstance(authority, Mapping) or not isinstance(observed, Mapping):
        raise RootDirectDnsDeployError("root DNS discovery shape drifted")
    children = authority.get("childZones")
    parent = authority.get("parentRecords")
    child_observed = observed.get("childZones")
    vms = authority.get("virtualMachines")
    if (
        not isinstance(children, list)
        or not isinstance(parent, list)
        or not isinstance(child_observed, list)
        or len(child_observed) != 3
        or not isinstance(vms, list)
        or len(vms) != 3
    ):
        raise RootDirectDnsDeployError("root DNS discovery cardinality drifted")
    if any(item.get("challenge") is not None for item in child_observed):
        raise RootDirectDnsDeployError("ACME challenge exists during authority creation")
    if any(item.get("powerState") != "PowerState/deallocated" for item in vms):
        raise RootDirectDnsDeployError(
            "CP1 and both generation-3 SBCs must be Azure-deallocated before DNS creation"
        )
    presence: dict[str, bool] = {}
    for zone in contract.CHILD_ZONES:
        presence[contract.zone_id(discovery["scope"]["subscriptionId"], zone).lower()] = any(
            item.get("name") == zone for item in children
        )
    for spec in contract._expected_parent_specs(_inputs_from_discovery(discovery)):
        resource = contract.record_id(
            discovery["scope"]["subscriptionId"],
            contract.ROOT_ZONE,
            str(spec["type"]),
            str(spec["name"]),
        ).lower()
        presence[resource] = any(
            item.get("name") == spec["name"] and item.get("type") == spec["type"]
            for item in parent
        )
    role_id = contract.role_definition_id(discovery["scope"]["subscriptionId"]).lower()
    presence[role_id] = authority.get("customRoleDefinition") is not None
    assignments: dict[str, str | None] = {}
    by_zone = {item.get("name"): item for item in children if isinstance(item, dict)}
    for endpoint, zone in zip(contract.ENDPOINTS, contract.CHILD_ZONES):
        child = by_zone.get(zone)
        assignment = child.get("assignment") if isinstance(child, dict) else None
        assignments[endpoint] = (
            str(assignment["id"]).lower() if isinstance(assignment, dict) else None
        )
    count = sum(presence.values()) + sum(value is not None for value in assignments.values())
    state = "ABSENT" if count == 0 else "EXACT" if count == 16 else "PARTIAL_EXACT"
    return {
        "assignmentIds": assignments,
        "ownedResourceCount": count,
        "presence": dict(sorted(presence.items())),
        "state": state,
    }


def _inputs_from_discovery(discovery: Mapping[str, Any]) -> contract.ExpectedInputs:
    bindings = {
        item["name"]: item
        for item in discovery["authority"]["virtualMachines"]
    }
    return contract.ExpectedInputs(
        subscription_id=discovery["scope"]["subscriptionId"],
        tenant_id=discovery["scope"]["tenantId"],
        carrier_public_ipv4=bindings[contract.VM_NAMES["carrier"]]["ipAddress"],
        sbc1_public_ipv4=bindings[contract.VM_NAMES["sbc1"]]["ipAddress"],
        sbc2_public_ipv4=bindings[contract.VM_NAMES["sbc2"]]["ipAddress"],
        cp1_principal_id=bindings[contract.VM_NAMES["carrier"]]["principalId"],
        sbc1_principal_id=bindings[contract.VM_NAMES["sbc1"]]["principalId"],
        sbc2_principal_id=bindings[contract.VM_NAMES["sbc2"]]["principalId"],
    )


def _what_if(
    inputs: contract.ExpectedInputs, *, runner: contract.Runner
) -> Any:
    return _strict_json(
        runner(
            [
                "az", "deployment", "sub", "what-if",
                "--name", DEPLOYMENT_NAME,
                "--location", contract.POC_LOCATION,
                "--parameters", str(EXPECTED_PARAMETER_PATH),
                "--result-format", "ResourceIdOnly",
                "--no-pretty-print",
                "--validation-level", "Provider",
                "--subscription", inputs.subscription_id,
                "--output", "json", "--only-show-errors",
            ]
        ),
        "provider What-If",
    )


def _assignment_endpoint(resource_id: str, inputs: contract.ExpectedInputs) -> str | None:
    for endpoint, zone in zip(contract.ENDPOINTS, contract.CHILD_ZONES):
        prefix = (
            contract.zone_id(inputs.subscription_id, zone).lower()
            + "/providers/microsoft.authorization/roleassignments/"
        )
        if resource_id.startswith(prefix):
            suffix = resource_id[len(prefix):]
            if contract.UUID_RE.fullmatch(suffix) is None or "/" in suffix:
                raise RootDirectDnsDeployError("What-If role-assignment ID is malformed")
            return endpoint
    return None


def _validate_what_if(
    value: Any,
    state: Mapping[str, Any],
    inputs: contract.ExpectedInputs,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") != "Succeeded":
        raise RootDirectDnsDeployError("provider What-If did not succeed")
    changes = value.get("changes")
    if not isinstance(changes, list) or len(changes) != 16:
        raise RootDirectDnsDeployError("provider What-If must contain exactly 16 owned resources")
    fixed = state.get("presence")
    assignments = state.get("assignmentIds")
    if not isinstance(fixed, dict) or not isinstance(assignments, dict):
        raise RootDirectDnsDeployError("owned-resource state is malformed")
    seen_fixed: set[str] = set()
    seen_assignments: dict[str, str] = {}
    normalized: list[dict[str, str]] = []
    for item in changes:
        if not isinstance(item, dict):
            raise RootDirectDnsDeployError("provider What-If contains a malformed change")
        resource_id = str(item.get("resourceId", "")).rstrip("/").lower()
        change_type = item.get("changeType")
        if resource_id in fixed:
            if resource_id in seen_fixed:
                raise RootDirectDnsDeployError("provider What-If duplicates an owned resource")
            expected_change = "NoChange" if fixed[resource_id] else "Create"
            if change_type != expected_change:
                raise RootDirectDnsDeployError("provider What-If fixed-resource action drifted")
            seen_fixed.add(resource_id)
        else:
            endpoint = _assignment_endpoint(resource_id, inputs)
            if endpoint is None or endpoint in seen_assignments:
                raise RootDirectDnsDeployError("provider What-If contains an unowned resource")
            observed_id = assignments.get(endpoint)
            if observed_id is not None and resource_id != observed_id:
                raise RootDirectDnsDeployError("provider What-If assignment identity drifted")
            expected_change = "NoChange" if observed_id is not None else "Create"
            if change_type != expected_change:
                raise RootDirectDnsDeployError("provider What-If assignment action drifted")
            seen_assignments[endpoint] = resource_id
        normalized.append({"changeType": str(change_type), "resourceId": resource_id})
    if seen_fixed != set(fixed) or set(seen_assignments) != set(contract.ENDPOINTS):
        raise RootDirectDnsDeployError("provider What-If omits an owned resource")
    normalized.sort(key=lambda item: item["resourceId"])
    return {"changes": normalized, "sha256": _digest(normalized)}


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_plan(
    inputs: contract.ExpectedInputs,
    discovery: Mapping[str, Any],
    history: list[dict[str, Any]],
    package: Mapping[str, str],
    what_if: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    contract.validate_inputs(inputs)
    if _inputs_from_discovery(discovery) != inputs:
        raise RootDirectDnsDeployError("live VM/PIP/identity bindings differ from plan inputs")
    state = _resource_state(discovery)
    if state["state"] != "ABSENT" and not history:
        raise RootDirectDnsDeployError(
            "reserved root names/resources were not vacant and no exact prior deployment exists"
        )
    provider = _validate_what_if(what_if, state, inputs)
    generated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    expires = generated + timedelta(minutes=PLAN_MAX_AGE_MINUTES)
    body = {
        "apiVersion": API_VERSION,
        "authority": {
            "dnsResourceGroup": contract.DNS_RESOURCE_GROUP,
            "parentZone": contract.ROOT_ZONE,
            "subscriptionId": inputs.subscription_id,
            "tenantId": inputs.tenant_id,
        },
        "confirmationPhrase": CONFIRMATION,
        "deploymentHistory": history,
        "deploymentName": DEPLOYMENT_NAME,
        "expectedInputs": dict(inputs.__dict__),
        "expiresAtUtc": _utc(expires),
        "generatedAtUtc": _utc(generated),
        "kind": KIND,
        "observationSha256": _digest(discovery),
        "package": dict(package),
        "preserved": discovery["preserved"],
        "providerWhatIf": provider,
        "resourceState": state,
        "scope": discovery["scope"],
    }
    return {
        **body,
        "planSha256": _digest(body),
        "status": "ROOT_DIRECT_DNS_ACME_CREATE_PLAN_VALID",
    }


def create_live_plan(
    inputs: contract.ExpectedInputs,
    package: Mapping[str, str],
    *,
    runner: contract.Runner = contract.run,
    now: datetime | None = None,
) -> dict[str, Any]:
    discovery = contract.discover(
        inputs, runner=runner, require_complete=False, include_vms=True
    )
    history = _deployment_history(inputs, runner=runner)
    return build_plan(inputs, discovery, history, package, _what_if(inputs, runner=runner), now=now)


def write_plan(plan: Mapping[str, Any], path: Path = EXPECTED_PLAN_PATH) -> None:
    resolved_parent = path.parent.resolve()
    expected_parent = EXPECTED_PLAN_PATH.parent.resolve()
    if path != EXPECTED_PLAN_PATH or resolved_parent != expected_parent:
        raise RootDirectDnsDeployError("plan path is outside the protected state directory")
    resolved_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(resolved_parent, 0o700)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical_bytes(plan) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RootDirectDnsDeployError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RootDirectDnsDeployError(f"{label} must be canonical UTC") from exc


def read_plan(
    *,
    supplied_sha256: str,
    confirmation: str,
    path: Path = EXPECTED_PLAN_PATH,
    now: datetime | None = None,
) -> dict[str, Any]:
    if path.is_symlink():
        raise RootDirectDnsDeployError("saved plan must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise RootDirectDnsDeployError("saved plan is unavailable") from exc
    if (
        resolved != EXPECTED_PLAN_PATH.resolve()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
    ):
        raise RootDirectDnsDeployError("saved plan is not the exact owner-only plan")
    value = _strict_json(raw, "saved plan")
    expected_keys = {
        "apiVersion", "authority", "confirmationPhrase", "deploymentHistory",
        "deploymentName", "expectedInputs", "expiresAtUtc", "generatedAtUtc",
        "kind", "observationSha256", "package", "planSha256", "preserved",
        "providerWhatIf", "resourceState", "scope", "status",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise RootDirectDnsDeployError("saved plan fields are not exact")
    body = {key: item for key, item in value.items() if key not in {"planSha256", "status"}}
    digest = _digest(body)
    if value.get("planSha256") != digest or supplied_sha256 != digest:
        raise RootDirectDnsDeployError("saved plan SHA-256 authority does not match")
    if value.get("confirmationPhrase") != confirmation or confirmation != CONFIRMATION:
        raise RootDirectDnsDeployError("exact create confirmation is required")
    if (
        value.get("apiVersion") != API_VERSION
        or value.get("kind") != KIND
        or value.get("deploymentName") != DEPLOYMENT_NAME
        or value.get("status") != "ROOT_DIRECT_DNS_ACME_CREATE_PLAN_VALID"
    ):
        raise RootDirectDnsDeployError("saved plan contract identity drifted")
    generated = _parse_utc(value.get("generatedAtUtc"), "generatedAtUtc")
    expires = _parse_utc(value.get("expiresAtUtc"), "expiresAtUtc")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (
        expires - generated != timedelta(minutes=PLAN_MAX_AGE_MINUTES)
        or current < generated
        or current > expires
    ):
        raise RootDirectDnsDeployError("saved plan is outside its exact ten-minute window")
    inputs = contract.ExpectedInputs(**value["expectedInputs"])
    contract.validate_inputs(inputs)
    return value


def _stable_preserved(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return value


def apply_plan(
    plan: Mapping[str, Any], *, runner: contract.Runner = contract.run
) -> dict[str, Any]:
    inputs = contract.ExpectedInputs(**plan["expectedInputs"])
    package = compile_package(inputs, runner=runner)
    if package != plan.get("package"):
        raise RootDirectDnsDeployError("Bicep package changed after planning")
    discovery = contract.discover(
        inputs, runner=runner, require_complete=False, include_vms=True
    )
    history = _deployment_history(inputs, runner=runner)
    state = _resource_state(discovery)
    provider = _validate_what_if(_what_if(inputs, runner=runner), state, inputs)
    if (
        _digest(discovery) != plan.get("observationSha256")
        or history != plan.get("deploymentHistory")
        or state != plan.get("resourceState")
        or provider != plan.get("providerWhatIf")
        or _stable_preserved(discovery["preserved"]) != plan.get("preserved")
    ):
        raise RootDirectDnsDeployError("Azure authority changed after create planning")
    result = _strict_json(
        runner(
            [
                "az", "deployment", "sub", "create",
                "--name", DEPLOYMENT_NAME,
                "--location", contract.POC_LOCATION,
                "--parameters", str(EXPECTED_PARAMETER_PATH),
                "--subscription", inputs.subscription_id,
                "--only-show-errors", "--output", "json",
                "--query", "{id:id,name:name,provisioningState:properties.provisioningState}",
            ]
        ),
        "root DNS deployment result",
    )
    expected_id = (
        f"/subscriptions/{inputs.subscription_id}/providers/"
        f"Microsoft.Resources/deployments/{DEPLOYMENT_NAME}"
    )
    if (
        not isinstance(result, dict)
        or not contract.same_id(result.get("id"), expected_id)
        or result.get("name") != DEPLOYMENT_NAME
        or result.get("provisioningState") != "Succeeded"
    ):
        raise RootDirectDnsDeployError("root DNS provider deployment did not succeed exactly")
    post = contract.discover(
        inputs, runner=runner, require_complete=True, include_vms=True
    )
    post_state = _resource_state(post)
    if (
        post_state["state"] != "EXACT"
        or post_state["ownedResourceCount"] != 16
        or _stable_preserved(post["preserved"]) != plan.get("preserved")
    ):
        raise RootDirectDnsDeployError("root DNS create postcondition failed")
    return {
        "deploymentName": DEPLOYMENT_NAME,
        "ownedResourceCount": 16,
        "planSha256": plan["planSha256"],
        "status": "ROOT_DIRECT_DNS_ACME_AUTHORITY_DEPLOYED",
    }


def _add_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-carrier-public-ipv4", required=True)
    parser.add_argument("--expected-sbc1-public-ipv4", required=True)
    parser.add_argument("--expected-sbc2-public-ipv4", required=True)
    parser.add_argument("--expected-cp1-principal-id", required=True)
    parser.add_argument("--expected-sbc1-principal-id", required=True)
    parser.add_argument("--expected-sbc2-principal-id", required=True)


def _inputs(args: argparse.Namespace) -> contract.ExpectedInputs:
    return contract.ExpectedInputs(
        subscription_id=args.expected_subscription_id,
        tenant_id=args.expected_tenant_id,
        carrier_public_ipv4=args.expected_carrier_public_ipv4,
        sbc1_public_ipv4=args.expected_sbc1_public_ipv4,
        sbc2_public_ipv4=args.expected_sbc2_public_ipv4,
        cp1_principal_id=args.expected_cp1_principal_id,
        sbc1_principal_id=args.expected_sbc1_principal_id,
        sbc2_principal_id=args.expected_sbc2_principal_id,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="write a fresh read-only create plan")
    _add_inputs(plan_parser)
    execute_parser = subparsers.add_parser("execute", help="apply one protected create plan")
    execute_parser.add_argument("--plan-sha256", required=True)
    execute_parser.add_argument("--confirmation", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            inputs = _inputs(args)
            package = compile_package(inputs)
            plan = create_live_plan(inputs, package)
            write_plan(plan)
            output = {
                "expiresAtUtc": plan["expiresAtUtc"],
                "ownedResourceCount": plan["resourceState"]["ownedResourceCount"],
                "planPath": str(EXPECTED_PLAN_PATH),
                "planSha256": plan["planSha256"],
                "resourceState": plan["resourceState"]["state"],
                "status": plan["status"],
            }
        else:
            plan = read_plan(
                supplied_sha256=args.plan_sha256,
                confirmation=args.confirmation,
            )
            output = apply_plan(plan)
    except (contract.RootDirectDnsError, OSError, TypeError, ValueError) as exc:
        print(f"ROOT_DIRECT_DNS_ACME_CREATE_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
