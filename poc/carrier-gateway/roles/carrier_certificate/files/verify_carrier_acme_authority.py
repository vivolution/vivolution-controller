#!/usr/bin/python3
"""Bind CP1 managed identity to the exact carrier DNS-01 authority."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
RESOURCE_GROUP_RE = re.compile(r"^[A-Za-z0-9._()-]{1,90}$")
DNS_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])$")
CHALLENGE_NAME_RE = re.compile(
    r"^_acme-challenge\.[a-z0-9](?:[a-z0-9.-]{1,235}[a-z0-9])$"
)
IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
)
ARM_API_VERSION = "2018-05-01"
MAX_RESPONSE_BYTES = 256 * 1024
EXPECTED_TAGS = {
    "environment": "poc",
    "managedBy": "bicep",
    "profile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
    "purpose": "direct-routing-private-pbx-poc-acme-dns01",
    "workload": "vivolution-sbc",
}


class AuthorityVerificationError(RuntimeError):
    pass


def _read_bounded(response: object) -> bytes:
    content = response.read(MAX_RESPONSE_BYTES + 1)
    if len(content) > MAX_RESPONSE_BYTES:
        raise AuthorityVerificationError("remote response exceeded its bound")
    return content


def _managed_identity_token(opener=urllib.request.urlopen) -> str:
    request = urllib.request.Request(IMDS_TOKEN_URL, headers={"Metadata": "true"})
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != IMDS_TOKEN_URL:
                raise AuthorityVerificationError("managed-identity endpoint redirected")
            payload = json.loads(_read_bounded(response))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise AuthorityVerificationError("managed-identity token request failed") from exc
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if (
        not isinstance(token, str)
        or not 64 <= len(token) <= 16384
        or token.strip() != token
        or any(character.isspace() for character in token)
    ):
        raise AuthorityVerificationError("managed-identity token response was malformed")
    return token


def _token_claims(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthorityVerificationError("managed-identity access token is not a JWT")
    try:
        padding = "=" * (-len(parts[1]) % 4)
        value = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, UnicodeError) as exc:
        raise AuthorityVerificationError(
            "managed-identity access-token claims are malformed"
        ) from exc
    if not isinstance(value, dict):
        raise AuthorityVerificationError("managed-identity access-token claims are malformed")
    return value


def _zone_url(subscription_id: str, resource_group: str, zone: str) -> str:
    segments = tuple(
        urllib.parse.quote(value, safe="")
        for value in (subscription_id, resource_group, zone)
    )
    return (
        "https://management.azure.com/subscriptions/{}/resourceGroups/{}/"
        "providers/Microsoft.Network/dnsZones/{}?api-version={}"
    ).format(*segments, ARM_API_VERSION)


def _txt_url(subscription_id: str, resource_group: str, zone: str) -> str:
    return _zone_url(subscription_id, resource_group, zone).replace(
        "?api-version=", "/TXT/_acme-challenge?api-version="
    )


def _zone_id(subscription_id: str, resource_group: str, zone: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/"
        f"providers/Microsoft.Network/dnsZones/{zone}"
    )




def _arm_zone(
    token: str,
    subscription_id: str,
    resource_group: str,
    zone: str,
    *,
    opener=urllib.request.urlopen,
) -> dict[str, object]:
    url = _zone_url(subscription_id, resource_group, zone)
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token}, method="GET"
    )
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != url or response.status != 200:
                raise AuthorityVerificationError(
                    "Azure DNS zone discovery returned an unexpected response"
                )
            payload = json.loads(_read_bounded(response))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise AuthorityVerificationError("Azure DNS zone discovery failed") from exc
    if not isinstance(payload, dict):
        raise AuthorityVerificationError("Azure DNS zone response was malformed")
    return payload


def _require_challenge_absent(
    token: str,
    subscription_id: str,
    resource_group: str,
    zone: str,
    *,
    opener=urllib.request.urlopen,
) -> None:
    url = _txt_url(subscription_id, resource_group, zone)
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + token}, method="GET"
    )
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != url:
                raise AuthorityVerificationError("Azure Resource Manager redirected")
            status = response.status
    except urllib.error.HTTPError as exc:
        try:
            if exc.geturl() != url:
                raise AuthorityVerificationError("Azure Resource Manager redirected")
            status = exc.code
        finally:
            exc.close()
    except (OSError, urllib.error.URLError) as exc:
        raise AuthorityVerificationError(
            "Azure DNS challenge discovery failed"
        ) from exc
    if status == 404:
        return
    if status == 200:
        raise AuthorityVerificationError(
            "carrier ACME challenge record exists before issuance"
        )
    raise AuthorityVerificationError(
        "Azure DNS challenge discovery returned an unexpected status"
    )


def _dig(
    resolver: str,
    name: str,
    record_type: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[str]:
    try:
        result = runner(
            (
                "/usr/bin/dig",
                "+time=3",
                "+tries=1",
                "+short",
                "@" + resolver,
                name,
                record_type,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuthorityVerificationError("public DNS discovery could not execute") from exc
    if result.returncode != 0 or result.stderr.strip():
        raise AuthorityVerificationError("public DNS discovery failed closed")
    values = [line.strip().lower() for line in result.stdout.splitlines() if line.strip()]
    if any(len(value) > 253 for value in values):
        raise AuthorityVerificationError("public DNS response exceeded its name bound")
    return values


def validate_authority(
    *,
    subscription_id: str,
    tenant_id: str,
    expected_principal_id: str,
    resource_group: str,
    zone: str,
    certificate_name: str,
    challenge_alias: str,
    challenge_target: str,
    expected_public_ipv4: str,
    resolver: str,
    opener=urllib.request.urlopen,
    dig_runner=subprocess.run,
    now: int | None = None,
) -> dict[str, object]:
    for value, label in (
        (subscription_id, "subscription ID"),
        (tenant_id, "tenant ID"),
        (expected_principal_id, "principal ID"),
    ):
        if UUID_RE.fullmatch(value) is None:
            raise AuthorityVerificationError(f"{label} is not a canonical lowercase UUID")
    if RESOURCE_GROUP_RE.fullmatch(resource_group) is None:
        raise AuthorityVerificationError("DNS resource-group name is unsafe")
    for value in (zone, certificate_name):
        if DNS_NAME_RE.fullmatch(value) is None:
            raise AuthorityVerificationError("DNS authority contains an unsafe name")
    for value in (challenge_alias, challenge_target):
        if CHALLENGE_NAME_RE.fullmatch(value) is None:
            raise AuthorityVerificationError(
                "DNS authority contains an unsafe challenge name"
            )
    try:
        public_ipv4 = ipaddress.ip_address(expected_public_ipv4)
        resolver_ipv4 = ipaddress.ip_address(resolver)
    except ValueError as exc:
        raise AuthorityVerificationError("DNS authority contains an invalid IPv4") from exc
    if public_ipv4.version != 4 or not public_ipv4.is_global:
        raise AuthorityVerificationError("expected carrier address must be global IPv4")
    if resolver_ipv4.version != 4:
        raise AuthorityVerificationError("DNS resolver must be IPv4")

    token = _managed_identity_token(opener)
    claims = _token_claims(token)
    current = int(time.time()) if now is None else now
    if claims.get("aud") not in {
        "https://management.azure.com",
        "https://management.azure.com/",
    }:
        raise AuthorityVerificationError("managed-identity token has the wrong audience")
    if claims.get("tid") != tenant_id or claims.get("oid") != expected_principal_id:
        raise AuthorityVerificationError(
            "managed-identity token crosses the expected tenant or CP1 principal"
        )
    if not isinstance(claims.get("exp"), int) or int(claims["exp"]) < current + 60:
        raise AuthorityVerificationError("managed-identity token is expired or near expiry")

    payload = _arm_zone(
        token, subscription_id, resource_group, zone, opener=opener
    )
    expected_id = _zone_id(subscription_id, resource_group, zone)
    properties = payload.get("properties")
    nameservers = properties.get("nameServers") if isinstance(properties, dict) else None
    if (
        str(payload.get("id", "")).lower() != expected_id.lower()
        or payload.get("name") != zone
        or str(payload.get("type", "")).lower() != "microsoft.network/dnszones"
        or payload.get("location") != "global"
        or payload.get("tags") != EXPECTED_TAGS
        or not isinstance(nameservers, list)
        or len(nameservers) != 4
    ):
        raise AuthorityVerificationError(
            "Azure DNS zone differs from the isolated carrier authority"
        )
    normalized_nameservers = sorted(
        str(value).rstrip(".").lower() for value in nameservers
    )
    if (
        len(set(normalized_nameservers)) != 4
        or any(DNS_NAME_RE.fullmatch(value) is None for value in normalized_nameservers)
    ):
        raise AuthorityVerificationError("Azure DNS nameserver inventory is malformed")

    a_records = _dig(resolver, certificate_name, "A", runner=dig_runner)
    cname_records = _dig(resolver, challenge_alias, "CNAME", runner=dig_runner)
    ns_records = _dig(resolver, zone, "NS", runner=dig_runner)
    if a_records != [expected_public_ipv4]:
        raise AuthorityVerificationError("carrier public A record differs from CP1 authority")
    if [value.rstrip(".") for value in cname_records] != [challenge_target]:
        raise AuthorityVerificationError(
            "carrier challenge CNAME differs from the isolated child zone"
        )
    if sorted(value.rstrip(".") for value in ns_records) != normalized_nameservers:
        raise AuthorityVerificationError(
            "public child-zone delegation differs from Azure zone discovery"
        )
    _require_challenge_absent(
        token, subscription_id, resource_group, zone, opener=opener
    )
    return {
        "certificateFqdn": certificate_name,
        "challengeTarget": challenge_target,
        "managedIdentityPrincipalId": expected_principal_id,
        "nameServers": normalized_nameservers,
        "status": "CARRIER_ACME_AUTHORITY_BOUND",
        "zoneResourceId": expected_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--expected-principal-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--certificate-name", required=True)
    parser.add_argument("--challenge-alias", required=True)
    parser.add_argument("--challenge-target", required=True)
    parser.add_argument("--expected-public-ipv4", required=True)
    parser.add_argument("--resolver", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_authority(
            subscription_id=args.subscription_id,
            tenant_id=args.tenant_id,
            expected_principal_id=args.expected_principal_id,
            resource_group=args.resource_group,
            zone=args.zone,
            certificate_name=args.certificate_name,
            challenge_alias=args.challenge_alias,
            challenge_target=args.challenge_target,
            expected_public_ipv4=args.expected_public_ipv4,
            resolver=args.resolver,
        )
    except AuthorityVerificationError as exc:
        print(f"CARRIER_ACME_AUTHORITY_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
