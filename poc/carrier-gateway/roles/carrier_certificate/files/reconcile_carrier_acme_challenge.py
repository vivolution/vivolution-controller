#!/usr/bin/python3
"""Verify or safely reconcile the sole carrier ACME TXT record set."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
RESOURCE_GROUP_RE = re.compile(r"^[A-Za-z0-9._()-]{1,90}$")
DNS_ZONE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])$")
ETAG_RE = re.compile(r'^(?:W/)?"[^"\r\n]{1,128}"$')
TOKEN_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
)
ARM_API_VERSION = "2018-05-01"
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ATTEMPTS = 6
RETRY_SECONDS = 2


class ChallengeReconciliationError(RuntimeError):
    pass


def _read_bounded(response: object) -> bytes:
    content = response.read(MAX_RESPONSE_BYTES + 1)
    if len(content) > MAX_RESPONSE_BYTES:
        raise ChallengeReconciliationError("remote response exceeded its bound")
    return content


def _managed_identity_token(opener=urllib.request.urlopen) -> str:
    request = urllib.request.Request(IMDS_TOKEN_URL, headers={"Metadata": "true"})
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != IMDS_TOKEN_URL:
                raise ChallengeReconciliationError(
                    "managed-identity endpoint redirected"
                )
            payload = json.loads(_read_bounded(response))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise ChallengeReconciliationError(
            "managed-identity token request failed"
        ) from exc
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if (
        not isinstance(token, str)
        or not 64 <= len(token) <= 16384
        or token.strip() != token
        or any(character.isspace() for character in token)
    ):
        raise ChallengeReconciliationError(
            "managed-identity token response was malformed"
        )
    return token


def _token_claims(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ChallengeReconciliationError("managed-identity token is not a JWT")
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, UnicodeError) as exc:
        raise ChallengeReconciliationError(
            "managed-identity token claims are malformed"
        ) from exc
    if not isinstance(payload, dict):
        raise ChallengeReconciliationError(
            "managed-identity token claims are malformed"
        )
    return payload


def _record_url(subscription_id: str, resource_group: str, zone: str) -> str:
    segments = tuple(
        urllib.parse.quote(value, safe="")
        for value in (subscription_id, resource_group, zone)
    )
    return (
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/"
        "providers/Microsoft.Network/dnsZones/{}/TXT/_acme-challenge"
        "?api-version={}"
    ).format(*segments, ARM_API_VERSION)


def _get_record(
    url: str, token: str, *, opener=urllib.request.urlopen
) -> tuple[int, dict[str, object] | None]:
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token}, method="GET"
    )
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != url:
                raise ChallengeReconciliationError(
                    "Azure Resource Manager redirected"
                )
            status = response.status
            content = _read_bounded(response)
    except urllib.error.HTTPError as exc:
        try:
            if exc.geturl() != url:
                raise ChallengeReconciliationError(
                    "Azure Resource Manager redirected"
                )
            if exc.code == 404:
                return 404, None
            raise ChallengeReconciliationError(
                "Azure Resource Manager returned an unexpected record status"
            )
        finally:
            exc.close()
    except (OSError, urllib.error.URLError) as exc:
        raise ChallengeReconciliationError(
            "Azure Resource Manager record discovery failed"
        ) from exc
    if status == 404:
        return 404, None
    if status != 200:
        raise ChallengeReconciliationError(
            "Azure Resource Manager returned an unexpected record status"
        )
    try:
        payload = json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise ChallengeReconciliationError("Azure TXT response is malformed") from exc
    if not isinstance(payload, dict):
        raise ChallengeReconciliationError("Azure TXT response is malformed")
    return status, payload


def _validate_record(
    payload: dict[str, object], expected_id: str
) -> str:
    properties = payload.get("properties")
    records = properties.get("TXTRecords") if isinstance(properties, dict) else None
    ttl = properties.get("TTL") if isinstance(properties, dict) else None
    etag = payload.get("etag")
    if (
        str(payload.get("id", "")).lower() != expected_id.lower()
        or payload.get("name") != "_acme-challenge"
        or str(payload.get("type", "")).lower()
        != "microsoft.network/dnszones/txt"
        or ttl != 60
        or not isinstance(etag, str)
        or ETAG_RE.fullmatch(etag) is None
        or not isinstance(records, list)
        or not 1 <= len(records) <= 2
    ):
        raise ChallengeReconciliationError(
            "existing TXT record differs from the bounded Lego challenge shape"
        )
    values: list[str] = []
    for record in records:
        record_values = record.get("value") if isinstance(record, dict) else None
        if not isinstance(record_values, list) or len(record_values) != 1:
            raise ChallengeReconciliationError(
                "existing TXT record differs from the bounded Lego challenge shape"
            )
        value = record_values[0]
        if not isinstance(value, str) or TOKEN_VALUE_RE.fullmatch(value) is None:
            raise ChallengeReconciliationError(
                "existing TXT record differs from the bounded Lego challenge shape"
            )
        values.append(value)
    if len(set(values)) != len(values):
        raise ChallengeReconciliationError("existing TXT challenge values are duplicated")
    return etag


def reconcile_challenge(
    subscription_id: str,
    tenant_id: str,
    expected_principal_id: str,
    resource_group: str,
    zone: str,
    *,
    mode: str,
    opener=urllib.request.urlopen,
    sleeper=time.sleep,
    now: int | None = None,
) -> str:
    for value, label in (
        (subscription_id, "subscription ID"),
        (tenant_id, "tenant ID"),
        (expected_principal_id, "principal ID"),
    ):
        if UUID_RE.fullmatch(value) is None:
            raise ChallengeReconciliationError(
                f"{label} is not a canonical lowercase UUID"
            )
    if RESOURCE_GROUP_RE.fullmatch(resource_group) is None:
        raise ChallengeReconciliationError("DNS resource-group name is unsafe")
    if DNS_ZONE_RE.fullmatch(zone) is None:
        raise ChallengeReconciliationError("DNS zone name is unsafe")
    if mode not in {"reconcile", "verify-absent"}:
        raise ChallengeReconciliationError("unsupported reconciliation mode")

    token = _managed_identity_token(opener)
    claims = _token_claims(token)
    current = int(time.time()) if now is None else now
    if claims.get("aud") not in {
        "https://management.azure.com",
        "https://management.azure.com/",
    }:
        raise ChallengeReconciliationError(
            "managed-identity token has the wrong audience"
        )
    if claims.get("tid") != tenant_id or claims.get("oid") != expected_principal_id:
        raise ChallengeReconciliationError(
            "managed-identity token crosses the expected tenant or CP1 principal"
        )
    if not isinstance(claims.get("exp"), int) or int(claims["exp"]) < current + 60:
        raise ChallengeReconciliationError(
            "managed-identity token is expired or near expiry"
        )

    url = _record_url(subscription_id, resource_group, zone)
    expected_id = url.split("?", 1)[0]
    status, payload = _get_record(url, token, opener=opener)
    if status == 404:
        return "CARRIER_ACME_CHALLENGE_ABSENT"
    assert payload is not None
    etag = _validate_record(payload, expected_id)
    if mode == "verify-absent":
        raise ChallengeReconciliationError(
            "carrier ACME challenge TXT record remains"
        )

    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token, "If-Match": etag},
        method="DELETE",
    )
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != url or response.status not in {200, 202, 204}:
                raise ChallengeReconciliationError(
                    "Azure TXT deletion returned an unexpected response"
                )
            _read_bounded(response)
    except urllib.error.HTTPError as exc:
        try:
            if exc.geturl() != url:
                raise ChallengeReconciliationError(
                    "Azure Resource Manager redirected"
                )
            if exc.code == 412:
                raise ChallengeReconciliationError(
                    "Azure TXT record changed before conditional deletion"
                )
            raise ChallengeReconciliationError(
                "Azure TXT deletion returned an unexpected status"
            )
        finally:
            exc.close()
    except (OSError, urllib.error.URLError) as exc:
        raise ChallengeReconciliationError("Azure TXT deletion failed") from exc

    for attempt in range(MAX_ATTEMPTS):
        status, remaining = _get_record(url, token, opener=opener)
        if status == 404:
            return "CARRIER_ACME_CHALLENGE_RECONCILED"
        assert remaining is not None
        _validate_record(remaining, expected_id)
        if attempt + 1 < MAX_ATTEMPTS:
            sleeper(RETRY_SECONDS)
    raise ChallengeReconciliationError(
        "Azure TXT record remained after conditional deletion"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--expected-principal-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument(
        "--mode", choices=("reconcile", "verify-absent"), required=True
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = reconcile_challenge(
            args.subscription_id,
            args.tenant_id,
            args.expected_principal_id,
            args.resource_group,
            args.zone,
            mode=args.mode,
        )
    except ChallengeReconciliationError as exc:
        print(f"CARRIER_ACME_CHALLENGE_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
