#!/usr/bin/python3
"""Verify the fresh controller-signed carrier ACME workload-RBAC receipt."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


API_VERSION = "infra.vivolution.ae/carrier-acme-rbac-receipt/v0.1"
KIND = "CarrierAcmeRbacReceipt"
ROLE_GUID = "c5498bfb-a31f-40dd-b636-0f53e530ed53"
ROLE_NAME = "Vivolution Direct POC ACME TXT Record Operator"
ROLE_DESCRIPTION = (
    "Discover one assigned direct-routing public DNS child zone and manage only "
    "its TXT record sets for ACME DNS-01."
)
ROLE_ACTIONS = frozenset(
    {
        "Microsoft.Network/dnszones/read",
        "Microsoft.Network/dnszones/TXT/read",
        "Microsoft.Network/dnszones/TXT/write",
        "Microsoft.Network/dnszones/TXT/delete",
        "Microsoft.ResourceGraph/resources/read",
    }
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MAX_RECEIPT_BYTES = 256 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
WRAPPER_FIELDS = {
    "apiVersion",
    "kind",
    "payload",
    "payloadSha256",
    "signature",
    "signatureAlgorithm",
}
PAYLOAD_FIELDS = {
    "assignmentId",
    "authorityDiscoverySha256",
    "cp1PrincipalId",
    "dnsResourceGroup",
    "expiresAt",
    "humanSubscriptionAdministrationEvaluated",
    "issuedAt",
    "roleActions",
    "roleDefinitionGuid",
    "roleDefinitionId",
    "roleDescription",
    "roleName",
    "signingKeyId",
    "signingPublicKeySha256",
    "subscriptionId",
    "tenantId",
    "zone",
    "zoneResourceId",
}


class RbacReceiptError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _strict_json(content: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise RbacReceiptError("RBAC receipt contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(content, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RbacReceiptError("RBAC receipt is malformed JSON") from exc
    if not isinstance(value, dict):
        raise RbacReceiptError("RBAC receipt must be one JSON object")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RbacReceiptError(f"RBAC receipt {label} is malformed")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise RbacReceiptError(f"RBAC receipt {label} is malformed") from exc
    return parsed


def validate_receipt(
    receipt_bytes: bytes,
    public_key_pem: bytes,
    *,
    expected_subscription_id: str,
    expected_tenant_id: str,
    expected_cp1_principal_id: str,
    expected_resource_group: str,
    expected_zone: str,
    expected_signing_key_id: str,
    expected_public_key_sha256: str,
    maximum_lifetime_seconds: int,
    minimum_remaining_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    for value, label in (
        (expected_subscription_id, "subscription ID"),
        (expected_tenant_id, "tenant ID"),
        (expected_cp1_principal_id, "CP1 principal ID"),
    ):
        if UUID_RE.fullmatch(value) is None:
            raise RbacReceiptError(f"expected {label} is not a canonical UUID")
    if expected_resource_group != "DNS_Zones":
        raise RbacReceiptError("expected RBAC receipt resource group is not exact")
    if expected_zone != "acme-carrier.vivolution.ae":
        raise RbacReceiptError("expected RBAC receipt zone is not exact")
    if KEY_ID_RE.fullmatch(expected_signing_key_id) is None:
        raise RbacReceiptError("expected RBAC receipt signing key ID is invalid")
    if DIGEST_RE.fullmatch(expected_public_key_sha256) is None:
        raise RbacReceiptError("expected RBAC receipt public-key digest is invalid")
    if not 60 <= maximum_lifetime_seconds <= 3600:
        raise RbacReceiptError("RBAC receipt maximum lifetime is outside its bound")
    if not 30 <= minimum_remaining_seconds < maximum_lifetime_seconds:
        raise RbacReceiptError("RBAC receipt minimum remaining lifetime is invalid")
    if not 0 < len(receipt_bytes) <= MAX_RECEIPT_BYTES:
        raise RbacReceiptError("RBAC receipt is empty or oversized")
    if not 0 < len(public_key_pem) <= MAX_PUBLIC_KEY_BYTES:
        raise RbacReceiptError("RBAC receipt public key is empty or oversized")

    receipt = _strict_json(receipt_bytes)
    if set(receipt) != WRAPPER_FIELDS or receipt_bytes != _canonical(receipt) + b"\n":
        raise RbacReceiptError("RBAC receipt is not canonical or has unknown fields")
    payload = receipt.get("payload")
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
        raise RbacReceiptError("RBAC receipt payload fields differ from contract")
    if (
        receipt.get("apiVersion") != API_VERSION
        or receipt.get("kind") != KIND
        or receipt.get("signatureAlgorithm") != "Ed25519"
    ):
        raise RbacReceiptError("RBAC receipt envelope differs from contract")

    encoded_payload = _canonical(payload)
    if (
        DIGEST_RE.fullmatch(str(receipt.get("payloadSha256", ""))) is None
        or hashlib.sha256(encoded_payload).hexdigest() != receipt["payloadSha256"]
    ):
        raise RbacReceiptError("RBAC receipt payload digest differs")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise RbacReceiptError("RBAC receipt public key is invalid PEM") from exc
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise RbacReceiptError("RBAC receipt public key must be Ed25519")
    canonical_public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if public_key_pem != canonical_public_pem:
        raise RbacReceiptError("RBAC receipt public key is not canonical PEM")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_digest = hashlib.sha256(public_der).hexdigest()
    if (
        public_digest != expected_public_key_sha256
        or payload.get("signingPublicKeySha256") != public_digest
        or payload.get("signingKeyId") != expected_signing_key_id
    ):
        raise RbacReceiptError("RBAC receipt signing trust anchor differs")
    try:
        signature = base64.b64decode(
            str(receipt.get("signature", "")), validate=True
        )
    except (ValueError, TypeError) as exc:
        raise RbacReceiptError("RBAC receipt signature is malformed") from exc
    if len(signature) != 64:
        raise RbacReceiptError("RBAC receipt signature length is invalid")
    signed = {key: value for key, value in receipt.items() if key != "signature"}
    try:
        public_key.verify(signature, _canonical(signed))
    except InvalidSignature as exc:
        raise RbacReceiptError("RBAC receipt signature is invalid") from exc

    role_id = (
        f"/subscriptions/{expected_subscription_id}/providers/"
        f"Microsoft.Authorization/roleDefinitions/{ROLE_GUID}"
    )
    zone_id = (
        f"/subscriptions/{expected_subscription_id}/resourceGroups/"
        f"{expected_resource_group}/providers/Microsoft.Network/dnsZones/"
        f"{expected_zone}"
    )
    assignment_prefix = (
        zone_id + "/providers/Microsoft.Authorization/roleAssignments/"
    )
    assignment_id = payload.get("assignmentId")
    role_actions = payload.get("roleActions")
    if (
        payload.get("subscriptionId") != expected_subscription_id
        or payload.get("tenantId") != expected_tenant_id
        or payload.get("cp1PrincipalId") != expected_cp1_principal_id
        or payload.get("dnsResourceGroup") != expected_resource_group
        or payload.get("zone") != expected_zone
        or payload.get("zoneResourceId") != zone_id
        or payload.get("roleDefinitionGuid") != ROLE_GUID
        or payload.get("roleDefinitionId") != role_id
        or payload.get("roleName") != ROLE_NAME
        or payload.get("roleDescription") != ROLE_DESCRIPTION
        or not isinstance(role_actions, list)
        or len(role_actions) != len(ROLE_ACTIONS)
        or set(role_actions) != ROLE_ACTIONS
        or payload.get("humanSubscriptionAdministrationEvaluated") is not False
        or DIGEST_RE.fullmatch(
            str(payload.get("authorityDiscoverySha256", ""))
        )
        is None
        or not isinstance(assignment_id, str)
        or not assignment_id.startswith(assignment_prefix)
        or UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1]) is None
    ):
        raise RbacReceiptError("RBAC receipt Azure bindings differ from contract")

    issued_at = _timestamp(payload.get("issuedAt"), "issue time")
    expires_at = _timestamp(payload.get("expiresAt"), "expiry")
    check_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    lifetime = int((expires_at - issued_at).total_seconds())
    if (
        issued_at > check_time.replace(microsecond=0)
        or lifetime < 60
        or lifetime > maximum_lifetime_seconds
        or (expires_at - check_time).total_seconds() < minimum_remaining_seconds
    ):
        raise RbacReceiptError("RBAC receipt is stale, future-dated, or overlong")
    return {
        "assignmentId": assignment_id,
        "authorityDiscoverySha256": payload["authorityDiscoverySha256"],
        "expiresAt": payload["expiresAt"],
        "humanSubscriptionAdministrationEvaluated": False,
        "roleDefinitionId": role_id,
        "signingKeyId": expected_signing_key_id,
        "signingPublicKeySha256": public_digest,
        "status": "CARRIER_ACME_RBAC_RECEIPT_VALID",
        "zoneResourceId": zone_id,
    }


def _secure_read(path: Path, label: str, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as exc:
        raise RbacReceiptError(f"cannot read {label}: {exc}") from exc
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != 0
            or record.st_gid != 0
            or stat.S_IMODE(record.st_mode) != 0o400
            or not 0 < record.st_size <= maximum
        ):
            raise RbacReceiptError(f"{label} owner, mode, type, or size is unsafe")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        fingerprint = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
        )
        if (
            fingerprint(record) != fingerprint(after)
            or len(content) != record.st_size
            or len(content) > maximum
        ):
            raise RbacReceiptError(f"{label} changed during its bounded read")
        return content
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-cp1-principal-id", required=True)
    parser.add_argument("--expected-resource-group", required=True)
    parser.add_argument("--expected-zone", required=True)
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--maximum-lifetime-seconds", type=int, required=True)
    parser.add_argument("--minimum-remaining-seconds", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_receipt(
            _secure_read(args.receipt, "RBAC receipt", MAX_RECEIPT_BYTES),
            _secure_read(
                args.public_key,
                "RBAC receipt public key",
                MAX_PUBLIC_KEY_BYTES,
            ),
            expected_subscription_id=args.expected_subscription_id,
            expected_tenant_id=args.expected_tenant_id,
            expected_cp1_principal_id=args.expected_cp1_principal_id,
            expected_resource_group=args.expected_resource_group,
            expected_zone=args.expected_zone,
            expected_signing_key_id=args.expected_signing_key_id,
            expected_public_key_sha256=args.expected_public_key_sha256,
            maximum_lifetime_seconds=args.maximum_lifetime_seconds,
            minimum_remaining_seconds=args.minimum_remaining_seconds,
        )
    except RbacReceiptError as exc:
        print(f"CARRIER_ACME_RBAC_RECEIPT_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
