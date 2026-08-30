#!/usr/bin/python3
"""Fail closed unless the isolated Azure DNS ACME TXT record set is absent."""

from __future__ import annotations

import argparse
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
IMDS_TOKEN_URL = (
    "http://169.254.169.254/metadata/identity/oauth2/token"
    "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
)
ARM_API_VERSION = "2018-05-01"
MAX_TOKEN_RESPONSE_BYTES = 65536
MAX_ATTEMPTS = 6
RETRY_SECONDS = 2


class CleanupVerificationError(RuntimeError):
    pass


def _read_bounded(response: object) -> bytes:
    content = response.read(MAX_TOKEN_RESPONSE_BYTES + 1)
    if len(content) > MAX_TOKEN_RESPONSE_BYTES:
        raise CleanupVerificationError("managed-identity response exceeded its bound")
    return content


def _managed_identity_token(opener=urllib.request.urlopen) -> str:
    request = urllib.request.Request(IMDS_TOKEN_URL, headers={"Metadata": "true"})
    try:
        with opener(request, timeout=5) as response:
            if response.geturl() != IMDS_TOKEN_URL:
                raise CleanupVerificationError("managed-identity endpoint redirected")
            payload = json.loads(_read_bounded(response))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise CleanupVerificationError("managed-identity token request failed") from exc
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if (
        not isinstance(token, str)
        or not 64 <= len(token) <= 16384
        or token.strip() != token
        or any(character.isspace() for character in token)
    ):
        raise CleanupVerificationError("managed-identity token response was malformed")
    return token


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


def verify_absent(
    subscription_id: str,
    resource_group: str,
    zone: str,
    *,
    opener=urllib.request.urlopen,
    sleeper=time.sleep,
) -> None:
    if UUID_RE.fullmatch(subscription_id) is None:
        raise CleanupVerificationError("subscription ID is not a canonical UUID")
    if RESOURCE_GROUP_RE.fullmatch(resource_group) is None:
        raise CleanupVerificationError("DNS resource-group name is unsafe")
    if DNS_ZONE_RE.fullmatch(zone) is None:
        raise CleanupVerificationError("DNS zone name is unsafe")

    token = _managed_identity_token(opener)
    url = _record_url(subscription_id, resource_group, zone)
    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token},
        method="GET",
    )
    last_status: int | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            with opener(request, timeout=5) as response:
                if response.geturl() != url:
                    raise CleanupVerificationError("Azure Resource Manager redirected")
                last_status = response.status
        except urllib.error.HTTPError as exc:
            try:
                if exc.geturl() != url:
                    raise CleanupVerificationError(
                        "Azure Resource Manager redirected"
                    )
                last_status = exc.code
            finally:
                exc.close()
        except (OSError, urllib.error.URLError) as exc:
            raise CleanupVerificationError(
                "Azure Resource Manager cleanup verification failed"
            ) from exc

        if last_status == 404:
            return
        if last_status not in {200, 429, 500, 502, 503, 504}:
            raise CleanupVerificationError(
                "Azure Resource Manager returned an unexpected cleanup status"
            )
        if attempt + 1 < MAX_ATTEMPTS:
            sleeper(RETRY_SECONDS)

    if last_status == 200:
        raise CleanupVerificationError("ACME challenge TXT record set remains after cleanup")
    raise CleanupVerificationError("Azure Resource Manager cleanup verification timed out")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--zone", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        verify_absent(args.subscription_id, args.resource_group, args.zone)
    except CleanupVerificationError as exc:
        print(f"EDGE_ACME_CLEANUP_REJECTED: {exc}", file=sys.stderr)
        return 1
    print("EDGE_ACME_CHALLENGE_RECORD_ABSENT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
