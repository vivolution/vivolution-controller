#!/usr/bin/env python3
"""Plan or apply bounded teardown of root Direct Routing DNS/ACME authority.

The default is a read-only plan. Apply requires that plan's fresh SHA-256 and
an exact confirmation. Only nine exact root record sets, three exact role
assignments, three tagged child zones, and the dedicated custom role can be
deleted. The shared DNS resource group, ``vivolution.ae``, every unrelated
root record, ``voice.vivolution.ae`` and its ACME child zones are never targets.
Every exact partial create/teardown state is rediscovered and safely resumable.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping, Sequence

import root_direct_dns_acme_contract as contract


CONFIRMATION = "DELETE-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY"


def _stable_preserved(value: Mapping[str, Any]) -> dict[str, Any]:
    root = value["rootZone"]
    return {
        "rootUnrelatedRecordInventorySha256": value[
            "rootUnrelatedRecordInventorySha256"
        ],
        "rootZone": {
            "id": root["id"],
            "name": root["name"],
            "nameServers": root["nameServers"],
            "tags": root["tags"],
        },
        "voiceAuthorityZones": value["voiceAuthorityZones"],
    }


def _actions(discovery: Mapping[str, Any], inputs: contract.ExpectedInputs) -> list[dict[str, str]]:
    authority = discovery["authority"]
    observed = discovery["observed"]
    parent = authority["parentRecords"]
    children = authority["childZones"]
    role = authority["customRoleDefinition"]

    actions: list[dict[str, str]] = []
    for child in observed["childZones"]:
        challenge = child["challenge"]
        if challenge is not None:
            actions.append(
                {
                    "etag": challenge["etag"],
                    "id": challenge["id"],
                    "kind": "DELETE_ACME_CHALLENGE_TXT",
                    "name": challenge["name"],
                    "zone": child["name"],
                }
            )

    type_order = {"CNAME": 0, "NS": 1, "A": 2}
    for record in sorted(
        parent, key=lambda item: (type_order[item["type"]], item["name"])
    ):
        actions.append(
            {
                "etag": record["etag"],
                "id": record["id"],
                "kind": "DELETE_ROOT_RECORD_SET",
                "name": record["name"],
                "recordType": record["type"],
            }
        )

    child_by_name = {item["name"]: item for item in children}
    for endpoint, zone in zip(contract.ENDPOINTS, contract.CHILD_ZONES):
        child = child_by_name.get(zone)
        if child is None:
            continue
        assignment = child["assignment"]
        if assignment is not None:
            actions.append(
                {
                    "id": assignment["id"],
                    "kind": "DELETE_DIRECT_ACME_ROLE_ASSIGNMENT",
                    "principalId": inputs.principals[endpoint],
                    "roleDefinitionId": contract.role_definition_id(inputs.subscription_id),
                    "scope": assignment["scope"],
                    "zone": zone,
                }
            )
        actions.append(
            {
                "etag": child["etag"],
                "id": child["id"],
                "kind": "DELETE_DIRECT_ACME_CHILD_ZONE",
                "name": zone,
            }
        )
    if role is not None:
        actions.append(
            {
                "id": role["id"],
                "kind": "DELETE_DIRECT_ACME_CUSTOM_ROLE",
                "name": role["name"],
            }
        )
    return actions


def plan(
    inputs: contract.ExpectedInputs,
    *,
    runner: contract.Runner = contract.run,
) -> dict[str, Any]:
    discovery = contract.discover(
        inputs, runner=runner, require_complete=False, include_vms=True
    )
    actions = _actions(discovery, inputs)
    if actions and any(
        vm["powerState"] != "PowerState/deallocated"
        for vm in discovery["authority"]["virtualMachines"]
    ):
        raise contract.RootDirectDnsError(
            "CP1 and both generation-3 SBCs must be Azure-deallocated before DNS teardown"
        )
    base = {
        "actions": actions,
        "authority": discovery["authority"],
        "observed": discovery["observed"],
        "preserved": discovery["preserved"],
        "scope": discovery["scope"],
    }
    result = dict(base)
    result["planSha256"] = contract.canonical_json_sha256(base)
    result["status"] = (
        "ROOT_DIRECT_DNS_ACME_TEARDOWN_PLAN_READY"
        if actions
        else "ROOT_DIRECT_DNS_ACME_AUTHORITY_ABSENT"
    )
    return result


def _apply_action(
    action: Mapping[str, str], inputs: contract.ExpectedInputs, runner: contract.Runner
) -> None:
    subscription_id = inputs.subscription_id
    kind = action.get("kind")
    if kind == "DELETE_ACME_CHALLENGE_TXT":
        contract.delete_txt(action, subscription_id, runner)
    elif kind == "DELETE_ROOT_RECORD_SET":
        contract.delete_parent_record(action, subscription_id, runner)
    elif kind == "DELETE_DIRECT_ACME_ROLE_ASSIGNMENT":
        contract.delete_assignment(action, inputs, runner)
    elif kind == "DELETE_DIRECT_ACME_CHILD_ZONE":
        contract.delete_zone(action, subscription_id, runner)
    elif kind == "DELETE_DIRECT_ACME_CUSTOM_ROLE":
        contract.delete_role(action, subscription_id, runner)
    else:
        raise contract.RootDirectDnsError(f"unsupported teardown action {kind!r}")


def apply(
    inputs: contract.ExpectedInputs,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    runner: contract.Runner = contract.run,
) -> dict[str, Any]:
    if contract.DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise contract.RootDirectDnsError(
            "approved plan SHA-256 must be 64 lowercase hexadecimal characters"
        )
    if confirmation != CONFIRMATION:
        raise contract.RootDirectDnsError("exact teardown confirmation is required")
    approved = plan(inputs, runner=runner)
    if approved["planSha256"] != approved_plan_sha256:
        raise contract.RootDirectDnsError(
            "approved plan digest does not match freshly validated Azure state"
        )
    preserved = _stable_preserved(approved["preserved"])
    for index, action in enumerate(approved["actions"]):
        boundary = plan(inputs, runner=runner)
        if (
            boundary["scope"] != approved["scope"]
            or _stable_preserved(boundary["preserved"]) != preserved
            or boundary["actions"] != approved["actions"][index:]
        ):
            raise contract.RootDirectDnsError(
                "authority changed during teardown; generate and review a new plan"
            )
        _apply_action(action, inputs, runner)
    final = plan(inputs, runner=runner)
    if (
        final["status"] != "ROOT_DIRECT_DNS_ACME_AUTHORITY_ABSENT"
        or final["actions"]
        or final["scope"] != approved["scope"]
        or _stable_preserved(final["preserved"]) != preserved
    ):
        raise contract.RootDirectDnsError("root Direct DNS teardown postcondition failed")
    return {
        "appliedActions": len(approved["actions"]),
        "appliedPlanSha256": approved_plan_sha256,
        "postconditionPlanSha256": final["planSha256"],
        "scope": approved["scope"],
        "status": "ROOT_DIRECT_DNS_ACME_TEARDOWN_APPLIED",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-carrier-public-ipv4", required=True)
    parser.add_argument("--expected-sbc1-public-ipv4", required=True)
    parser.add_argument("--expected-sbc2-public-ipv4", required=True)
    parser.add_argument("--expected-cp1-principal-id", required=True)
    parser.add_argument("--expected-sbc1-principal-id", required=True)
    parser.add_argument("--expected-sbc2-principal-id", required=True)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--confirmation")
    return parser


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
    args = _parser().parse_args(argv)
    try:
        inputs = _inputs(args)
        if args.mode == "plan":
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise contract.RootDirectDnsError(
                    "plan mode refuses apply-only approval arguments"
                )
            evidence = plan(inputs)
        else:
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise contract.RootDirectDnsError(
                    "apply mode requires a plan digest and confirmation"
                )
            evidence = apply(
                inputs,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
    except contract.RootDirectDnsError as exc:
        print(f"ROOT_DIRECT_DNS_ACME_TEARDOWN_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
