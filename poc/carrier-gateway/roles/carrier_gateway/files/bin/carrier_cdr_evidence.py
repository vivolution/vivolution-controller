#!/usr/bin/env python3
"""Produce protected, checkpoint-bound carrier CDR evidence.

The collector never trusts a pathname read: it opens with O_NOFOLLOW, verifies
the descriptor before and after the bounded read, and binds each run to the
digest of the previously accepted raw prefix. Billable evidence is accepted
only for exactly one new generic provider CDR row whose request ID has a
root-owned claim and broker receipt. Provider-specific external corroboration
is delegated to a root-owned adapter loaded through a strict, versioned
contract.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIELD_COUNT = 14
MAX_SOURCE_BYTES = 8 * 1024 * 1024
ALLOWED_ACCOUNTS = {
    "vivo-carrier-test-in": "EDGE_TO_LOCAL_TEST",
    "vivo-carrier-test-out": "LOCAL_TO_EDGE_TEST",
    "vivo-carrier-provider-out": "EDGE_TO_PROVIDER_OUTBOUND",
}
ALLOWED_DISPOSITIONS = {"ANSWERED", "BUSY", "FAILED", "NO ANSWER", "CONGESTION"}
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SAFE_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
SAFE_PROVIDER_PROFILE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SAFE_SIGNING_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
AUTHORITY_SCHEMA = "poc.vivolution.ae/carrier-call-authority/v2"
RECEIPT_SCHEMA = "poc.vivolution.ae/carrier-call-claim/v1"
PROVIDER_ADAPTER_API_VERSION = (
    "poc.vivolution.ae/carrier-cdr-provider-adapter/v1"
)
PROVIDER_CORROBORATION_STATUS = "EXACTLY_ONE_BILLED_CALL_CORROBORATED"
DEFAULT_PROVIDER_ADAPTER_ROOT = Path(__file__).resolve().with_name(
    "carrier_cdr_provider_adapters"
)
BLOCKED_DISPOSITIONS = {"FAILED", "CONGESTION"}
EGRESS_INGRESS_CHANNEL = re.compile(r"^PJSIP/gateway-inbound-[A-Za-z0-9]+$")
PROVIDER_CHANNEL = re.compile(r"^PJSIP/provider-[A-Za-z0-9]+$")
CORROBORATION_DOMAIN = b"VIVO_CARRIER_CORROBORATION_V1\0"


class EvidenceError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _exact_json(data: bytes, keys: set[str]) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError("duplicate JSON field")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("invalid protected JSON") from exc
    if not isinstance(value, dict) or set(value) != keys or _canonical(value) != data:
        raise EvidenceError("protected JSON is not exact and canonical")
    return value


def _read_open_file(
    path: Path,
    *,
    maximum: int,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise EvidenceError(f"cannot securely open {path.name}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EvidenceError(f"{path.name} must be one single-link regular file")
        if before.st_size > maximum:
            raise EvidenceError(f"{path.name} exceeds its size bound")
        if expected_uid is not None and before.st_uid != expected_uid:
            raise EvidenceError(f"{path.name} has the wrong owner")
        if expected_gid is not None and before.st_gid != expected_gid:
            raise EvidenceError(f"{path.name} has the wrong group")
        if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
            raise EvidenceError(f"{path.name} has the wrong mode")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
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
    if fingerprint(before) != fingerprint(after) or len(data) != before.st_size:
        raise EvidenceError(f"{path.name} changed during collection")
    return data, after


def _timestamp(value: str, label: str) -> datetime:
    # Asterisk emits RFC-3339-like offsets as +0000 on the pinned runtime;
    # normalize only that exact terminal form for Python versions that require
    # a colon in ``datetime.fromisoformat``.
    if re.search(r"[+-][0-9]{4}$", value):
        value = value[:-2] + ":" + value[-2:]
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EvidenceError(f"invalid {label} timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError(f"{label} timestamp lacks an offset")
    return parsed.astimezone(timezone.utc)


def _parse_row(row: list[str], row_number: int) -> dict[str, Any]:
    if len(row) != FIELD_COUNT:
        raise EvidenceError(f"CDR row {row_number} has an invalid field count")
    start, answer, end, duration, billsec, disposition = row[:6]
    src, dst, channel, dstchannel, uniqueid, linkedid, accountcode, userfield = row[6:14]
    if disposition not in ALLOWED_DISPOSITIONS:
        raise EvidenceError(f"CDR row {row_number} has an unknown disposition")
    try:
        duration_value = int(duration)
        billsec_value = int(billsec)
    except ValueError as exc:
        raise EvidenceError(f"CDR row {row_number} has a non-integer duration") from exc
    if not 0 <= billsec_value <= duration_value <= 3600:
        raise EvidenceError(f"CDR row {row_number} has an invalid duration bound")
    start_time = _timestamp(start, "start")
    end_time = _timestamp(end, "end")
    answer_time = _timestamp(answer, "answer") if answer else None
    if end_time < start_time or (answer_time and not start_time <= answer_time <= end_time):
        raise EvidenceError(f"CDR row {row_number} has inconsistent timestamps")
    if abs((end_time - start_time).total_seconds() - duration_value) > 2:
        raise EvidenceError(f"CDR row {row_number} duration does not match timestamps")
    if any("\x00" in value or "\r" in value or "\n" in value for value in row):
        raise EvidenceError(f"CDR row {row_number} contains control framing")
    if any(len(value) > 512 for value in row):
        raise EvidenceError(f"CDR row {row_number} contains an oversized field")
    return {
        "accountcode": accountcode,
        "answer": answer_time,
        "billsec": billsec_value,
        "channel": channel,
        "disposition": disposition,
        "dst": dst,
        "dstchannel": dstchannel,
        "duration": duration_value,
        "end": end_time,
        "linkedid": linkedid,
        "row": row,
        "rowNumber": row_number,
        "src": src,
        "start": start_time,
        "uniqueid": uniqueid,
        "userfield": userfield,
    }


def _rows(data: bytes, first_row: int = 1) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("CDR source is not UTF-8") from exc
    if data and not data.endswith(b"\n"):
        raise EvidenceError("CDR source ends with an incomplete record")
    try:
        parsed = list(csv.reader(io.StringIO(text, newline="")))
    except csv.Error as exc:
        raise EvidenceError("CDR source has invalid CSV framing") from exc
    return [_parse_row(row, first_row + index) for index, row in enumerate(parsed)]


def _normalized_record(parsed: dict[str, Any], direction: str) -> dict[str, Any]:
    return {
        "answerTimestamp": parsed["answer"].isoformat() if parsed["answer"] else None,
        "billsec": parsed["billsec"],
        "callLinkDigest": _digest(_canonical([parsed["uniqueid"], parsed["linkedid"]])),
        "direction": direction,
        "disposition": parsed["disposition"],
        "duration": parsed["duration"],
        "endTimestamp": parsed["end"].isoformat(),
        "evidenceId": parsed["userfield"],
        "observedCarrierEndpoint": "provider"
        if PROVIDER_CHANNEL.fullmatch(parsed["dstchannel"])
        else None,
        "observedCarrierChannelDigest": _digest(parsed["dstchannel"].encode())
        if parsed["dstchannel"]
        else None,
        "observedIngressEndpoint": "isolated-carrier-egress"
        if EGRESS_INGRESS_CHANNEL.fullmatch(parsed["channel"])
        else None,
        "observedIngressChannelDigest": _digest(parsed["channel"].encode())
        if parsed["channel"]
        else None,
        "recordDigest": _digest(_canonical(parsed["row"])),
        "row": parsed["rowNumber"],
        "startTimestamp": parsed["start"].isoformat(),
    }


def normalize(path: Path) -> dict[str, Any]:
    """Strict legacy normalizer retained for non-billable test evidence."""
    data, _status = _read_open_file(path, maximum=MAX_SOURCE_BYTES)
    records: list[dict[str, Any]] = []
    for parsed in _rows(data):
        account = parsed["accountcode"]
        if account not in ALLOWED_ACCOUNTS:
            raise EvidenceError(f"CDR row {parsed['rowNumber']} has an unknown account code")
        if not SAFE_ID.fullmatch(parsed["userfield"]):
            raise EvidenceError(f"CDR row {parsed['rowNumber']} has an unsafe evidence identifier")
        records.append(_normalized_record(parsed, ALLOWED_ACCOUNTS[account]))
    return {
        "apiVersion": "poc.vivolution.ae/carrier-cdr-evidence/v0.2",
        "kind": "CarrierGatewayCdrEvidence",
        "recordCount": len(records),
        "records": records,
        "sourceDigest": _digest(data),
        "status": "NORMALIZED_NO_TELEPHONE_NUMBERS",
    }


def _read_claim(
    authorization_root: Path, request_id: str, trusted_uid: int, trusted_gid: int
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    claimed_path = authorization_root / "claims" / f"{request_id}.claimed"
    receipt_path = authorization_root / "claims" / f"{request_id}.receipt.json"
    claimed_data, _ = _read_open_file(
        claimed_path,
        maximum=4096,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o600,
    )
    receipt_data, _ = _read_open_file(
        receipt_path,
        maximum=4096,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o600,
    )
    authority_keys = {
        "configDigest",
        "destination",
        "expiresEpoch",
        "issuedEpoch",
        "maxCallSeconds",
        "maxSpendMicroUsd",
        "maximumCalls",
        "requestId",
        "schema",
    }
    receipt_keys = {
        "authorityDigest",
        "claimedEpoch",
        "configDigest",
        "destinationDigest",
        "maxCallSeconds",
        "maxSpendMicroUsd",
        "peerUid",
        "requestId",
        "schema",
    }
    authority = _exact_json(claimed_data, authority_keys)
    receipt = _exact_json(receipt_data, receipt_keys)
    if (
        authority["schema"] != AUTHORITY_SCHEMA
        or receipt["schema"] != RECEIPT_SCHEMA
        or authority["requestId"] != request_id
        or receipt["requestId"] != request_id
        or receipt["authorityDigest"] != _digest(claimed_data)
        or receipt["configDigest"] != authority["configDigest"]
        or receipt["destinationDigest"] != _digest(authority["destination"].encode())
        or receipt["maxCallSeconds"] != authority["maxCallSeconds"]
        or receipt["maxSpendMicroUsd"] != authority["maxSpendMicroUsd"]
        or receipt["peerUid"] != 10004
        or authority["maximumCalls"] != 1
        or not DIGEST.fullmatch(authority["configDigest"])
    ):
        raise EvidenceError("claimed authority and broker receipt do not bind exactly")
    return authority, receipt, _digest(claimed_data), _digest(receipt_data)


def _read_checkpoint(
    checkpoint: Path, trusted_uid: int, trusted_gid: int
) -> dict[str, Any] | None:
    try:
        data, _status = _read_open_file(
            checkpoint,
            maximum=4096,
            expected_uid=trusted_uid,
            expected_gid=trusted_gid,
            expected_mode=0o600,
        )
    except EvidenceError:
        if not checkpoint.exists() and not checkpoint.is_symlink():
            return None
        raise
    return _checkpoint_value(data)


def _checkpoint_value(data: bytes) -> dict[str, Any]:
    keys = {
        "prefixDigest",
        "prefixLength",
        "schema",
        "sourceDevice",
        "sourceInode",
        "sourcePathDigest",
    }
    value = _exact_json(data, keys)
    if (
        value["schema"] != "poc.vivolution.ae/carrier-cdr-checkpoint/v1"
        or type(value["prefixLength"]) is not int
        or value["prefixLength"] < 0
        or type(value["sourceDevice"]) is not int
        or type(value["sourceInode"]) is not int
        or not DIGEST.fullmatch(value["prefixDigest"])
        or not DIGEST.fullmatch(value["sourcePathDigest"])
    ):
        raise EvidenceError("CDR checkpoint is invalid")
    return value


def observe_runtime_freeze(
    runtime_user: str,
    runtime_home: Path,
    runtime_dir: Path,
    image_id_path: Path,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", runtime_user):
        raise EvidenceError("unsafe runtime user")
    command = [
        "/usr/sbin/runuser",
        "-u",
        runtime_user,
        "--",
        "/usr/bin/env",
        f"HOME={runtime_home}",
        f"XDG_RUNTIME_DIR={runtime_dir}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus",
        "/usr/bin/systemctl",
        "--user",
        "show",
        "--property=ActiveState",
        "--value",
        "vivolution-carrier-gateway.service",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
    if result.returncode != 0 or result.stdout != "inactive\n" or result.stderr:
        raise EvidenceError("carrier runtime is not proven frozen and inactive")
    image_data, _ = _read_open_file(
        image_id_path,
        maximum=256,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o444,
    )
    try:
        image_id = image_data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise EvidenceError("runtime image identity is not ASCII") from exc
    if not DIGEST.fullmatch(image_id) or image_data != (image_id + "\n").encode():
        raise EvidenceError("runtime image identity is not one canonical digest")
    return {
        "activeState": "inactive",
        "imageId": image_id,
        "service": "vivolution-carrier-gateway.service",
        "status": "PINNED_RUNTIME_FROZEN_FOR_FINAL_CDR_CAPTURE",
    }


def observe_egress_freeze(
    image_id_path: Path,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> dict[str, Any]:
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=ActiveState",
            "--value",
            "vivolution-carrier-egress.service",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0 or result.stdout != "inactive\n" or result.stderr:
        raise EvidenceError("isolated carrier egress is not proven frozen and inactive")
    image_data, _ = _read_open_file(
        image_id_path,
        maximum=256,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o444,
    )
    try:
        image_id = image_data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise EvidenceError("egress image identity is not ASCII") from exc
    if not DIGEST.fullmatch(image_id) or image_data != (image_id + "\n").encode():
        raise EvidenceError("egress image identity is not one canonical digest")
    return {
        "activeState": "inactive",
        "imageId": image_id,
        "service": "vivolution-carrier-egress.service",
        "status": "PINNED_ISOLATED_EGRESS_FROZEN_FOR_FINAL_CDR_CAPTURE",
    }


def _decode_base64url(value: Any, label: str, expected_size: int) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise EvidenceError(f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise EvidenceError(f"{label} is invalid") from exc
    if (
        len(decoded) != expected_size
        or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value
    ):
        raise EvidenceError(f"{label} has the wrong canonical size")
    return decoded


def _verify_signed_corroboration(
    receipt_path: Path,
    public_key_path: Path,
    *,
    expected_key_id: str,
    payload_keys: set[str],
    trusted_uid: int,
    trusted_gid: int,
) -> tuple[dict[str, Any], str]:
    receipt_data, _ = _read_open_file(
        receipt_path,
        maximum=16384,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o400,
    )
    public_key_data, _ = _read_open_file(
        public_key_path,
        maximum=4096,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
        expected_mode=0o444,
    )
    envelope = _exact_json(receipt_data, {"payload", "signature"})
    payload = envelope["payload"]
    signature = envelope["signature"]
    if not isinstance(payload, dict) or set(payload) != payload_keys:
        raise EvidenceError("corroboration payload has an inexact field set")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "keyId", "value"}
        or signature["algorithm"] != "RSA-PKCS1v15-SHA256"
        or signature["keyId"] != expected_key_id
    ):
        raise EvidenceError("corroboration signature authority is inexact")
    signature_bytes = _decode_base64url(
        signature["value"], "corroboration signature", 384
    )
    with tempfile.TemporaryDirectory(prefix="vivo-carrier-corroboration-") as directory:
        temporary_root = Path(directory)
        temporary_key = temporary_root / "public.pem"
        temporary_signature = temporary_root / "signature.bin"
        temporary_key.write_bytes(public_key_data)
        temporary_signature.write_bytes(signature_bytes)
        os.chmod(temporary_key, 0o400)
        os.chmod(temporary_signature, 0o400)
        key_check = subprocess.run(
            [
                "/usr/bin/openssl",
                "pkey",
                "-pubin",
                "-in",
                str(temporary_key),
                "-text",
                "-noout",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if (
            key_check.returncode != 0
            or "Public-Key: (3072 bit)" not in key_check.stdout
            or key_check.stderr
        ):
            raise EvidenceError("corroboration key must be an exact RSA-3072 public key")
        verification = subprocess.run(
            [
                "/usr/bin/openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(temporary_key),
                "-signature",
                str(temporary_signature),
            ],
            input=CORROBORATION_DOMAIN + _canonical(payload),
            check=False,
            capture_output=True,
            timeout=5,
        )
        if (
            verification.returncode != 0
            or verification.stdout != b"Verified OK\n"
            or verification.stderr
        ):
            raise EvidenceError("corroboration signature did not verify")
    return payload, _digest(receipt_data)


class ProviderCorroborationContext:
    """Narrow service and immutable call bindings exposed to an adapter."""

    __slots__ = (
        "_public_key_path",
        "_receipt_path",
        "_trusted_gid",
        "_trusted_uid",
        "billed_duration_seconds",
        "carrier_record_digest",
        "destination_digest",
        "observed_end_timestamp",
        "request_id",
    )

    def __init__(
        self,
        *,
        receipt_path: Path,
        public_key_path: Path,
        request_id: str,
        destination_digest: str,
        carrier_record_digest: str,
        billed_duration_seconds: int,
        observed_end_timestamp: str,
        trusted_uid: int,
        trusted_gid: int,
    ) -> None:
        self._receipt_path = receipt_path
        self._public_key_path = public_key_path
        self._trusted_uid = trusted_uid
        self._trusted_gid = trusted_gid
        self.request_id = request_id
        self.destination_digest = destination_digest
        self.carrier_record_digest = carrier_record_digest
        self.billed_duration_seconds = billed_duration_seconds
        self.observed_end_timestamp = observed_end_timestamp

    def verify_signed_receipt(
        self,
        *,
        expected_key_id: str,
        payload_keys: set[str],
    ) -> tuple[dict[str, Any], str]:
        """Verify the generic protected envelope using adapter-owned policy."""
        return _verify_signed_corroboration(
            self._receipt_path,
            self._public_key_path,
            expected_key_id=expected_key_id,
            payload_keys=payload_keys,
            trusted_uid=self._trusted_uid,
            trusted_gid=self._trusted_gid,
        )

    @staticmethod
    def reject(message: str) -> None:
        raise EvidenceError(message)


def _load_provider_adapter(
    provider_profile: str,
    adapter_root: Path,
    trusted_uid: int,
    trusted_gid: int,
) -> tuple[Any, str]:
    """Load one trusted adapter source without a provider registry in core."""
    if (
        not isinstance(provider_profile, str)
        or not SAFE_PROVIDER_PROFILE.fullmatch(provider_profile)
    ):
        raise EvidenceError("unsafe provider profile")
    adapter_path = adapter_root / f"{provider_profile}.py"
    adapter_data, adapter_status = _read_open_file(
        adapter_path,
        maximum=65536,
        expected_uid=trusted_uid,
        expected_gid=trusted_gid,
    )
    if stat.S_IMODE(adapter_status.st_mode) & 0o022:
        raise EvidenceError("provider adapter must not be group- or other-writable")
    try:
        source = adapter_data.decode("utf-8")
        code = compile(source, str(adapter_path), "exec", dont_inherit=True)
        namespace: dict[str, Any] = {
            "__builtins__": __builtins__,
            "__file__": str(adapter_path),
            "__name__": f"vivolution_carrier_cdr_adapter_{provider_profile}",
            "__package__": None,
        }
        exec(code, namespace)
    except (SyntaxError, UnicodeError) as exc:
        raise EvidenceError("provider adapter source is invalid") from exc
    except Exception as exc:
        raise EvidenceError("provider adapter initialization failed") from exc
    if (
        namespace.get("ADAPTER_API_VERSION") != PROVIDER_ADAPTER_API_VERSION
        or namespace.get("PROVIDER_PROFILE") != provider_profile
        or not callable(namespace.get("verify"))
    ):
        raise EvidenceError("provider adapter contract is inexact")
    return namespace["verify"], _digest(adapter_data)


def _verify_provider_corroboration(
    provider_profile: str,
    provider_receipt: Path,
    provider_public_key: Path,
    *,
    request_id: str,
    destination_digest: str,
    carrier_record_digest: str,
    billed_duration_seconds: int,
    observed_end_timestamp: str,
    adapter_root: Path,
    trusted_uid: int,
    trusted_gid: int,
) -> tuple[dict[str, Any], str]:
    verify, adapter_digest = _load_provider_adapter(
        provider_profile,
        adapter_root,
        trusted_uid,
        trusted_gid,
    )
    context = ProviderCorroborationContext(
        receipt_path=provider_receipt,
        public_key_path=provider_public_key,
        request_id=request_id,
        destination_digest=destination_digest,
        carrier_record_digest=carrier_record_digest,
        billed_duration_seconds=billed_duration_seconds,
        observed_end_timestamp=observed_end_timestamp,
        trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    try:
        result = verify(context)
    except EvidenceError:
        raise
    except Exception as exc:
        raise EvidenceError("provider adapter verification failed") from exc
    expected_keys = {
        "adapterApiVersion",
        "providerProfile",
        "receiptDigest",
        "signingKeyId",
        "status",
    }
    if (
        not isinstance(result, dict)
        or set(result) != expected_keys
        or result["adapterApiVersion"] != PROVIDER_ADAPTER_API_VERSION
        or result["providerProfile"] != provider_profile
        or not isinstance(result["receiptDigest"], str)
        or not DIGEST.fullmatch(result["receiptDigest"])
        or not isinstance(result["signingKeyId"], str)
        or not SAFE_SIGNING_KEY_ID.fullmatch(result["signingKeyId"])
        or result["status"] != PROVIDER_CORROBORATION_STATUS
    ):
        raise EvidenceError("provider adapter result is inexact")
    return result, adapter_digest


def collect_authorized_call(
    source: Path,
    checkpoint: Path,
    authorization_root: Path,
    request_id: str,
    node_id: str,
    edge_id: str,
    edge_receipt: Path,
    edge_public_key: Path,
    provider_profile: str,
    provider_receipt: Path,
    provider_public_key: Path,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    source_uid: int = 10004,
    source_gid: int = 10004,
    source_mode: int = 0o600,
    collected_at: datetime | None = None,
    provider_adapter_root: Path = DEFAULT_PROVIDER_ADAPTER_ROOT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not SAFE_REQUEST_ID.fullmatch(request_id):
        raise EvidenceError("unsafe request ID")
    if not SAFE_ID.fullmatch(node_id) or not SAFE_ID.fullmatch(edge_id):
        raise EvidenceError("unsafe node or edge identity")
    data, source_status = _read_open_file(
        source,
        maximum=MAX_SOURCE_BYTES,
        expected_uid=source_uid,
        expected_gid=source_gid,
        expected_mode=source_mode,
    )
    previous = _read_checkpoint(checkpoint, trusted_uid, trusted_gid)
    offset = 0 if previous is None else previous["prefixLength"]
    if offset > len(data) or (offset and data[offset - 1 : offset] != b"\n"):
        raise EvidenceError("CDR checkpoint is beyond a complete source prefix")
    if previous is not None:
        if (
            previous["sourceDevice"] != source_status.st_dev
            or previous["sourceInode"] != source_status.st_ino
            or previous["sourcePathDigest"] != _digest(os.fsencode(source.resolve()))
            or previous["prefixDigest"] != _digest(data[:offset])
        ):
            raise EvidenceError("raw CDR prefix does not match the protected checkpoint")
    new_data = data[offset:]
    if not new_data:
        raise EvidenceError("no new CDR rows follow the protected checkpoint")
    first_row = data[:offset].count(b"\n") + 1
    parsed_rows = _rows(new_data, first_row)
    authority, receipt, authority_digest, receipt_digest = _read_claim(
        authorization_root, request_id, trusted_uid, trusted_gid
    )
    authorized = [
        row
        for row in parsed_rows
        if row["accountcode"] == "vivo-carrier-provider-out"
        and row["userfield"] == request_id
    ]
    if len(authorized) != 1:
        raise EvidenceError("new CDR extent does not contain exactly one claimed provider row")
    call = authorized[0]
    if call["dst"] != authority["destination"]:
        raise EvidenceError("provider CDR destination does not match claimed authority")
    if call["billsec"] > authority["maxCallSeconds"]:
        raise EvidenceError("provider CDR exceeds claimed duration")
    if not call["uniqueid"] or not call["linkedid"]:
        raise EvidenceError("provider CDR lacks safe call linkage inputs")
    if not EGRESS_INGRESS_CHANNEL.fullmatch(call["channel"]):
        raise EvidenceError("claimed provider row was not produced by isolated carrier egress")
    if not PROVIDER_CHANNEL.fullmatch(call["dstchannel"]):
        raise EvidenceError("claimed provider row lacks an observed provider destination channel")
    claimed_time = datetime.fromtimestamp(receipt["claimedEpoch"], timezone.utc)
    if not claimed_time.replace(microsecond=0) <= call["start"] <= datetime.fromtimestamp(
        receipt["claimedEpoch"] + 60, timezone.utc
    ):
        raise EvidenceError("provider CDR start is not temporally bound to the claim")
    classifications = {
        "authorizedProvider": 0,
        "nonBillable": 0,
        "unknownRejected": 0,
        "unroutedRejected": 0,
        "provenBlockedProvider": 0,
    }
    for row in parsed_rows:
        account = row["accountcode"]
        if row is call:
            classifications["authorizedProvider"] += 1
        elif account == "vivo-carrier-provider-out" or PROVIDER_CHANNEL.fullmatch(
            row["dstchannel"]
        ):
            proven_blocked = (
                row["userfield"] == ""
                and row["billsec"] == 0
                and row["answer"] is None
                and row["dstchannel"] == ""
                and row["disposition"] in BLOCKED_DISPOSITIONS
                and EGRESS_INGRESS_CHANNEL.fullmatch(row["channel"]) is not None
            )
            if not proven_blocked:
                raise EvidenceError(
                    "unmatched provider row is answered, billable, dialed, or not proven blocked"
                )
            classifications["provenBlockedProvider"] += 1
        elif account in ("vivo-carrier-test-in", "vivo-carrier-test-out"):
            classifications["nonBillable"] += 1
        elif account == "":
            if not (
                row["billsec"] == 0
                and row["answer"] is None
                and row["dstchannel"] == ""
                and row["disposition"] in BLOCKED_DISPOSITIONS
            ):
                raise EvidenceError("unrouted row is not proven blocked and non-billable")
            classifications["unroutedRejected"] += 1
        else:
            raise EvidenceError("new CDR extent contains an unclassifiable account code")
    collected_at = collected_at or datetime.now(timezone.utc)
    if collected_at.tzinfo is None:
        raise EvidenceError("collection timestamp must be timezone-aware")
    normalized_call = _normalized_record(call, "EDGE_TO_PROVIDER_OUTBOUND")
    edge_payload, edge_receipt_digest = _verify_signed_corroboration(
        edge_receipt,
        edge_public_key,
        expected_key_id=f"edge:{edge_id}",
        payload_keys={
            "carrierRecordDigest",
            "destinationDigest",
            "edgeId",
            "nodeId",
            "observedEndTimestamp",
            "observedStartTimestamp",
            "requestId",
            "schema",
            "sourceCursorDigest",
            "sourceService",
            "status",
        },
        trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    if (
        edge_payload["schema"]
        != "poc.vivolution.ae/edge-call-corroboration/v1"
        or edge_payload["status"] != "EDGE_CALL_OBSERVED"
        or edge_payload["requestId"] != request_id
        or edge_payload["nodeId"] != node_id
        or edge_payload["edgeId"] != edge_id
        or edge_payload["destinationDigest"]
        != _digest(authority["destination"].encode())
        or edge_payload["carrierRecordDigest"] != normalized_call["recordDigest"]
        or edge_payload["observedStartTimestamp"]
        != normalized_call["startTimestamp"]
        or edge_payload["observedEndTimestamp"] != normalized_call["endTimestamp"]
        or edge_payload["sourceService"] != "opensips.service"
        or not DIGEST.fullmatch(edge_payload["sourceCursorDigest"])
    ):
        raise EvidenceError(
            "signed Edge corroboration does not bind the carrier call exactly"
        )

    provider_result, provider_adapter_digest = _verify_provider_corroboration(
        provider_profile,
        provider_receipt,
        provider_public_key,
        request_id=request_id,
        destination_digest=_digest(authority["destination"].encode()),
        carrier_record_digest=normalized_call["recordDigest"],
        billed_duration_seconds=call["billsec"],
        observed_end_timestamp=normalized_call["endTimestamp"],
        adapter_root=provider_adapter_root,
        trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    evidence = {
        "apiVersion": "poc.vivolution.ae/carrier-cdr-evidence/v1",
        "authorityDigest": authority_digest,
        "authorizedCall": normalized_call,
        "claimReceiptDigest": receipt_digest,
        "classifiedNewRows": classifications,
        "collectedAt": collected_at.astimezone(timezone.utc).isoformat(),
        "corroboration": {
            "edgeReceiptDigest": edge_receipt_digest,
            "edgeSigningKeyId": f"edge:{edge_id}",
            "providerAdapterDigest": provider_adapter_digest,
            "providerProfile": provider_profile,
            "providerReceiptDigest": provider_result["receiptDigest"],
            "providerSigningKeyId": provider_result["signingKeyId"],
        },
        "kind": "CarrierGatewayAuthorizedCallEvidence",
        "observedPeerBinding": {
            "providerEndpoint": provider_profile,
            "edgeEndpoint": edge_id,
            "edgeIdentityScope": "signed-edge-journal-corroboration",
            "localProducer": "isolated-carrier-egress-uid-10004",
        },
        "operatorLabels": {
            "edgeId": edge_id,
            "nodeId": node_id,
            "status": "VERIFIED_BY_EDGE_AND_PROVIDER_CORROBORATION",
        },
        "requestId": request_id,
        "source": {
            "currentRawDigest": _digest(data),
            "newExtentDigest": _digest(new_data),
            "newExtentLength": len(new_data),
            "previousPrefixDigest": _digest(data[:offset]),
            "previousPrefixLength": offset,
            "sourceDevice": source_status.st_dev,
            "sourceInode": source_status.st_ino,
            "sourcePathDigest": _digest(os.fsencode(source.resolve())),
        },
        "status": "EXACTLY_ONE_NEW_ROOT_CLAIMED_AND_EXTERNALLY_CORROBORATED_PROVIDER_ROW",
    }
    next_checkpoint = {
        "prefixDigest": _digest(data),
        "prefixLength": len(data),
        "schema": "poc.vivolution.ae/carrier-cdr-checkpoint/v1",
        "sourceDevice": source_status.st_dev,
        "sourceInode": source_status.st_ino,
        "sourcePathDigest": _digest(os.fsencode(source.resolve())),
    }
    return evidence, next_checkpoint


def _write_exclusive(directory_fd: int, name: str, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise EvidenceError("short evidence write")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new(
    output: Path,
    result: dict[str, Any],
    next_checkpoint: dict[str, Any] | None = None,
) -> None:
    if output.exists() or output.is_symlink():
        raise EvidenceError("output directory must not already exist")
    output.mkdir(mode=0o700)
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        payload = _canonical(result)
        artifacts = [
            {"path": "evidence.json", "sha256": _digest(payload), "size": len(payload)}
        ]
        checkpoint_payload = None
        if next_checkpoint is not None:
            checkpoint_payload = _canonical(next_checkpoint)
            artifacts.append(
                {
                    "path": "checkpoint.next.json",
                    "sha256": _digest(checkpoint_payload),
                    "size": len(checkpoint_payload),
                }
            )
        manifest_value = {
            "artifacts": artifacts,
            "evidenceStatus": result.get("status"),
            "schema": "poc.vivolution.ae/protected-evidence-manifest/v1",
        }
        manifest = _canonical(manifest_value)
        checksum_lines = [f"{hashlib.sha256(payload).hexdigest()}  evidence.json\n"]
        if checkpoint_payload is not None:
            checksum_lines.append(
                f"{hashlib.sha256(checkpoint_payload).hexdigest()}  checkpoint.next.json\n"
            )
        checksum_lines.append(f"{hashlib.sha256(manifest).hexdigest()}  manifest.json\n")
        checksum = "".join(checksum_lines).encode()
        _write_exclusive(directory_fd, "evidence.json", payload)
        if checkpoint_payload is not None:
            _write_exclusive(directory_fd, "checkpoint.next.json", checkpoint_payload)
        _write_exclusive(directory_fd, "manifest.json", manifest)
        _write_exclusive(directory_fd, "MANIFEST.sha256", checksum)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def write_checkpoint(
    checkpoint: Path,
    value: dict[str, Any],
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
) -> None:
    parent = checkpoint.parent
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        status = os.fstat(parent_fd)
        if status.st_uid != trusted_uid or status.st_gid != trusted_gid:
            raise EvidenceError("checkpoint parent is not trusted")
        if checkpoint.exists() or checkpoint.is_symlink():
            _read_open_file(
                checkpoint,
                maximum=4096,
                expected_uid=trusted_uid,
                expected_gid=trusted_gid,
                expected_mode=0o600,
            )
        temporary = f".{checkpoint.name}.next-{os.getpid()}"
        _write_exclusive(parent_fd, temporary, _canonical(value))
        os.replace(temporary, checkpoint.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def recover_checkpoint_publication(
    output: Path,
    checkpoint: Path,
    source: Path,
    request_id: str,
    *,
    trusted_uid: int = 0,
    trusted_gid: int = 0,
    source_uid: int = 10004,
    source_gid: int = 10004,
    source_mode: int = 0o600,
) -> str:
    """Finish the only permitted crash window after immutable evidence publish."""
    try:
        output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise EvidenceError("existing evidence output is not a protected directory") from exc
    try:
        status = os.fstat(output_fd)
        if (
            status.st_uid != trusted_uid
            or status.st_gid != trusted_gid
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise EvidenceError("existing evidence output metadata is not trusted")
        names = sorted(os.listdir(output_fd))
        if names != [
            "MANIFEST.sha256",
            "checkpoint.next.json",
            "evidence.json",
            "manifest.json",
        ]:
            raise EvidenceError("existing evidence output is not an exact recovery set")
    finally:
        os.close(output_fd)

    values: dict[str, bytes] = {}
    for name, maximum in (
        ("evidence.json", 1024 * 1024),
        ("checkpoint.next.json", 4096),
        ("manifest.json", 4096),
        ("MANIFEST.sha256", 1024),
    ):
        values[name], _ = _read_open_file(
            output / name,
            maximum=maximum,
            expected_uid=trusted_uid,
            expected_gid=trusted_gid,
            expected_mode=0o600,
        )

    try:
        evidence = json.loads(values["evidence.json"])
        manifest = json.loads(values["manifest.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("existing recovery evidence JSON is invalid") from exc
    if (
        not isinstance(evidence, dict)
        or not isinstance(manifest, dict)
        or _canonical(evidence) != values["evidence.json"]
        or _canonical(manifest) != values["manifest.json"]
        or set(manifest) != {"artifacts", "evidenceStatus", "schema"}
        or manifest["schema"] != "poc.vivolution.ae/protected-evidence-manifest/v1"
        or manifest["evidenceStatus"] != evidence.get("status")
    ):
        raise EvidenceError("existing recovery evidence is not exact and canonical")
    expected_artifacts = [
        {
            "path": "evidence.json",
            "sha256": _digest(values["evidence.json"]),
            "size": len(values["evidence.json"]),
        },
        {
            "path": "checkpoint.next.json",
            "sha256": _digest(values["checkpoint.next.json"]),
            "size": len(values["checkpoint.next.json"]),
        },
    ]
    expected_checksum = (
        f"{hashlib.sha256(values['evidence.json']).hexdigest()}  evidence.json\n"
        f"{hashlib.sha256(values['checkpoint.next.json']).hexdigest()}  checkpoint.next.json\n"
        f"{hashlib.sha256(values['manifest.json']).hexdigest()}  manifest.json\n"
    ).encode()
    if manifest["artifacts"] != expected_artifacts or values["MANIFEST.sha256"] != expected_checksum:
        raise EvidenceError("existing recovery manifest does not bind every artifact")

    next_checkpoint = _checkpoint_value(values["checkpoint.next.json"])
    evidence_source = evidence.get("source")
    if (
        evidence.get("requestId") != request_id
        or not isinstance(evidence_source, dict)
        or evidence_source.get("currentRawDigest") != next_checkpoint["prefixDigest"]
        or evidence_source.get("sourceDevice") != next_checkpoint["sourceDevice"]
        or evidence_source.get("sourceInode") != next_checkpoint["sourceInode"]
        or evidence_source.get("sourcePathDigest") != next_checkpoint["sourcePathDigest"]
    ):
        raise EvidenceError("existing evidence does not bind the requested checkpoint")

    source_data, source_status = _read_open_file(
        source,
        maximum=MAX_SOURCE_BYTES,
        expected_uid=source_uid,
        expected_gid=source_gid,
        expected_mode=source_mode,
    )
    if (
        len(source_data) != next_checkpoint["prefixLength"]
        or _digest(source_data) != next_checkpoint["prefixDigest"]
        or source_status.st_dev != next_checkpoint["sourceDevice"]
        or source_status.st_ino != next_checkpoint["sourceInode"]
        or _digest(os.fsencode(source.resolve())) != next_checkpoint["sourcePathDigest"]
    ):
        raise EvidenceError("frozen CDR source changed after immutable evidence publication")

    previous = _read_checkpoint(checkpoint, trusted_uid, trusted_gid)
    if previous == next_checkpoint:
        return "CHECKPOINT_ALREADY_PUBLISHED"
    if previous is None:
        if evidence_source.get("previousPrefixLength") != 0:
            raise EvidenceError("missing checkpoint does not match evidence predecessor")
    elif (
        previous["prefixLength"] != evidence_source.get("previousPrefixLength")
        or previous["prefixDigest"] != evidence_source.get("previousPrefixDigest")
        or previous["sourceDevice"] != next_checkpoint["sourceDevice"]
        or previous["sourceInode"] != next_checkpoint["sourceInode"]
        or previous["sourcePathDigest"] != next_checkpoint["sourcePathDigest"]
    ):
        raise EvidenceError("protected checkpoint is not the evidence predecessor")
    write_checkpoint(
        checkpoint,
        next_checkpoint,
        trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    )
    return "RECOVERED_CHECKPOINT_PUBLICATION"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--authorization-root", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument(
        "--provider-profile",
        required=True,
        help="provider-specific external corroboration adapter",
    )
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--edge-id", required=True)
    parser.add_argument("--edge-receipt", type=Path, required=True)
    parser.add_argument("--edge-public-key", type=Path, required=True)
    parser.add_argument("--provider-receipt", type=Path, required=True)
    parser.add_argument("--provider-public-key", type=Path, required=True)
    parser.add_argument("--runtime-user", default="vivolution-carrier")
    parser.add_argument(
        "--runtime-home",
        type=Path,
        default=Path("/var/lib/vivolution/carrier-gateway/rootless-home"),
    )
    parser.add_argument("--runtime-dir", type=Path, default=Path("/run/user/10003"))
    parser.add_argument(
        "--runtime-image-id",
        type=Path,
        default=Path("/etc/vivolution/carrier-gateway/asterisk-image-id"),
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise EvidenceError("CDR evidence collection must run as root")
        freeze_before = {
            "edgeGateway": observe_runtime_freeze(
                args.runtime_user,
                args.runtime_home,
                args.runtime_dir,
                args.runtime_image_id,
            ),
            "isolatedCarrierEgress": observe_egress_freeze(args.runtime_image_id),
        }
        if args.output.exists() or args.output.is_symlink():
            recovery = recover_checkpoint_publication(
                args.output,
                args.checkpoint,
                args.input,
                args.request_id,
            )
            freeze_after = {
                "edgeGateway": observe_runtime_freeze(
                    args.runtime_user,
                    args.runtime_home,
                    args.runtime_dir,
                    args.runtime_image_id,
                ),
                "isolatedCarrierEgress": observe_egress_freeze(
                    args.runtime_image_id
                ),
            }
            if freeze_after != freeze_before:
                raise EvidenceError("runtime freeze identity changed during checkpoint recovery")
            print(recovery)
            return 0
        evidence, checkpoint = collect_authorized_call(
            args.input,
            args.checkpoint,
            args.authorization_root,
            args.request_id,
            args.node_id,
            args.edge_id,
            args.edge_receipt,
            args.edge_public_key,
            args.provider_profile,
            args.provider_receipt,
            args.provider_public_key,
        )
        freeze_after = {
            "edgeGateway": observe_runtime_freeze(
                args.runtime_user,
                args.runtime_home,
                args.runtime_dir,
                args.runtime_image_id,
            ),
            "isolatedCarrierEgress": observe_egress_freeze(args.runtime_image_id),
        }
        if freeze_after != freeze_before:
            raise EvidenceError("runtime freeze identity changed during CDR collection")
        evidence["runtimeFreeze"] = freeze_before
        # The staged next checkpoint is immutable and fsynced with evidence.
        # A rerun can finish only this exact publication after a crash.
        write_new(args.output, evidence, checkpoint)
        write_checkpoint(args.checkpoint, checkpoint)
        print("EVIDENCE_AND_CHECKPOINT_PUBLISHED")
    except (EvidenceError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
