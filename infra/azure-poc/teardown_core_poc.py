#!/usr/bin/env python3
"""Plan or apply deletion of only the exact, quiesced core POC resource group.

Plan mode is the default and cannot mutate Azure. Apply mode requires the
SHA-256 emitted by a fresh plan and an exact destructive confirmation phrase.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from typing import Any, Mapping, Sequence

import azure_lifecycle_contract as contract


CONFIRMATION = "DELETE-VIVOLUTION-SBC-POC-RESOURCE-GROUP"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _group_exists(
    subscription_id: str,
    name: str,
    *,
    runner: contract.Runner,
) -> bool:
    result = contract.parse_json(
        runner(
            contract.base_command(
                subscription_id,
                "group",
                "exists",
                "--name",
                name,
            )
        ),
        f"resource-group existence for {name}",
    )
    if not isinstance(result, bool):
        raise contract.LifecycleError(
            f"resource-group existence for {name} is not boolean"
        )
    return result


def _plan_body(
    subscription_id: str,
    tenant_id: str,
    *,
    runner: contract.Runner,
    today: dt.date | None,
) -> dict[str, Any]:
    contract.validate_account(subscription_id, tenant_id, runner=runner)
    preserved_cp1 = contract.validate_preserved_cp1(subscription_id, runner=runner)
    dns = contract.validate_parent_dns_absent(subscription_id, runner=runner)
    scope = {
        "deletableResourceGroup": contract.POC_RESOURCE_GROUP,
        "protectedResourceGroups": [
            contract.PRESERVED_CP1_RESOURCE_GROUP,
            contract.DNS_RESOURCE_GROUP,
        ],
        "subscriptionId": subscription_id,
        "tenantId": tenant_id,
    }
    if not _group_exists(
        subscription_id, contract.POC_RESOURCE_GROUP, runner=runner
    ):
        return {
            "actions": [],
            "scope": scope,
            "validated": {
                "dns": dns,
                "pocResourceGroup": "ABSENT",
                "preservedCp1Lock": preserved_cp1,
            },
        }

    group = contract.get_group(
        subscription_id, contract.POC_RESOURCE_GROUP, runner=runner
    )
    contract.validate_poc_group(group)
    contract.validate_poc_group_unlocked(subscription_id, runner=runner)
    budget = contract.validate_budget(subscription_id, runner=runner, today=today)
    inventory = contract.validate_core_inventory(subscription_id, runner=runner)
    deallocated_vms = contract.validate_vms_deallocated(
        subscription_id, runner=runner
    )
    inventory_digest = contract.canonical_digest({"resources": inventory})
    group_id = contract.resource_group_id(
        subscription_id, contract.POC_RESOURCE_GROUP
    )
    return {
        "actions": [
            {
                "id": group_id,
                "inventorySha256": inventory_digest,
                "kind": "DELETE_CORE_POC_RESOURCE_GROUP",
                "name": contract.POC_RESOURCE_GROUP,
            }
        ],
        "scope": scope,
        "validated": {
            "budget": budget,
            "deallocatedVms": deallocated_vms,
            "dns": dns,
            "inventory": inventory,
            "pocResourceGroup": {
                "id": group_id,
                "location": contract.LOCATION,
                "tags": contract.COMMON_TAGS,
            },
            "preservedCp1Lock": preserved_cp1,
        },
    }


def plan_teardown(
    subscription_id: str,
    tenant_id: str,
    *,
    runner: contract.Runner = contract.run,
    today: dt.date | None = None,
) -> dict[str, Any]:
    body = _plan_body(
        subscription_id,
        tenant_id,
        runner=runner,
        today=today,
    )
    return {
        **body,
        "planSha256": contract.canonical_digest(body),
        "status": (
            "POC_CORE_TEARDOWN_PLAN_READY"
            if body["actions"]
            else "POC_CORE_ALREADY_ABSENT"
        ),
    }


def _validate_single_action(action: Mapping[str, Any], subscription_id: str) -> None:
    expected_id = contract.resource_group_id(
        subscription_id, contract.POC_RESOURCE_GROUP
    )
    if (
        set(action)
        != {"id", "inventorySha256", "kind", "name"}
        or action.get("kind") != "DELETE_CORE_POC_RESOURCE_GROUP"
        or action.get("name") != contract.POC_RESOURCE_GROUP
        or not contract.same_id(action.get("id"), expected_id)
        or DIGEST_RE.fullmatch(str(action.get("inventorySha256", ""))) is None
    ):
        raise contract.LifecycleError("core teardown plan action escaped its exact boundary")


def apply_teardown(
    subscription_id: str,
    tenant_id: str,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    runner: contract.Runner = contract.run,
    today: dt.date | None = None,
) -> dict[str, Any]:
    if DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise contract.LifecycleError(
            "approved plan SHA-256 must be 64 lowercase hexadecimal characters"
        )
    if confirmation != CONFIRMATION:
        raise contract.LifecycleError(
            "exact core resource-group deletion confirmation was not supplied"
        )

    plan = plan_teardown(
        subscription_id,
        tenant_id,
        runner=runner,
        today=today,
    )
    if plan["planSha256"] != approved_plan_sha256:
        raise contract.LifecycleError(
            "approved plan digest does not match freshly validated Azure state"
        )
    if not plan["actions"]:
        return {
            "appliedPlanSha256": approved_plan_sha256,
            "deletedActions": 0,
            "scope": plan["scope"],
            "status": "POC_CORE_ALREADY_ABSENT",
        }
    if len(plan["actions"]) != 1:
        raise contract.LifecycleError("core teardown plan must contain exactly one action")
    _validate_single_action(plan["actions"][0], subscription_id)

    runner(
        [
            "az",
            "group",
            "delete",
            "--subscription",
            subscription_id,
            "--name",
            contract.POC_RESOURCE_GROUP,
            "--yes",
            "--only-show-errors",
        ]
    )
    if _group_exists(
        subscription_id, contract.POC_RESOURCE_GROUP, runner=runner
    ):
        raise contract.LifecycleError("core POC resource-group deletion postcondition failed")
    for protected in (
        contract.PRESERVED_CP1_RESOURCE_GROUP,
        contract.DNS_RESOURCE_GROUP,
    ):
        if not _group_exists(subscription_id, protected, runner=runner):
            raise contract.LifecycleError(
                f"protected resource group {protected} disappeared during teardown"
            )
    contract.validate_preserved_cp1(subscription_id, runner=runner)
    contract.validate_parent_dns_absent(subscription_id, runner=runner)
    return {
        "appliedPlanSha256": approved_plan_sha256,
        "deletedActions": 1,
        "scope": plan["scope"],
        "status": "POC_CORE_TEARDOWN_APPLIED",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--confirmation")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.mode == "plan":
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise contract.LifecycleError(
                    "plan mode refuses apply-only approval arguments"
                )
            evidence = plan_teardown(
                args.expected_subscription_id,
                args.expected_tenant_id,
            )
        else:
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise contract.LifecycleError(
                    "apply mode requires a plan digest and confirmation phrase"
                )
            evidence = apply_teardown(
                args.expected_subscription_id,
                args.expected_tenant_id,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
    except contract.LifecycleError as exc:
        print(f"POC_CORE_TEARDOWN_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
