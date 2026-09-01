#!/usr/bin/python3
"""Compare a rendered nftables policy with live state without mutating it.

Rendered policies are evaluated in a fresh network namespace.  The resulting
JSON ruleset is stripped only of nftables runtime identifiers and compared with
the live JSON ruleset byte-for-byte after canonical JSON serialization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


NFT = Path("/usr/sbin/nft")
UNSHARE = Path("/usr/bin/unshare")
PROFILE_API_VERSION = "firewall.vivolution.ae/active-profile/v2"
LEGACY_PROFILE_API_VERSION = "firewall.vivolution.ae/active-profile/v1"
RUNTIME_KEYS = frozenset({"handle", "index", "position"})


class GuardError(RuntimeError):
    """The rendered, recorded, or live nftables contract is not exact."""


def _strict_json(raw: str, label: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise GuardError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise GuardError(f"{label} is malformed JSON") from exc


def _run(argv: Sequence[str], label: str) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise GuardError(f"{label} failed: {detail}")
    return result.stdout


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize(item)
            for key, item in sorted(value.items())
            if key not in RUNTIME_KEYS
        }
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _canonical_ruleset(raw: str, label: str) -> bytes:
    parsed = _strict_json(raw, label)
    if not isinstance(parsed, dict) or set(parsed) != {"nftables"}:
        raise GuardError(f"{label} is not one nftables JSON ruleset")
    entries = parsed["nftables"]
    if not isinstance(entries, list) or not entries:
        raise GuardError(f"{label} contains no nftables entries")
    semantic_entries = [
        _normalize(entry)
        for entry in entries
        if not (isinstance(entry, dict) and set(entry) == {"metainfo"})
    ]
    if not semantic_entries:
        raise GuardError(f"{label} contains no semantic nftables entries")
    return json.dumps(
        {"nftables": semantic_entries},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _config_json(config: Path) -> str:
    if config.is_symlink():
        raise GuardError("rendered nftables configuration must not be a symlink")
    try:
        metadata = config.stat()
    except OSError as exc:
        raise GuardError("rendered nftables configuration is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GuardError("rendered nftables configuration must be one regular file")
    return _run(
        [
            str(UNSHARE),
            "--net",
            "--",
            "/bin/sh",
            "-c",
            '"$1" --file "$2" && exec "$1" --json list ruleset',
            "vivolution-nftables-semantic-guard",
            str(NFT),
            str(config),
        ],
        "isolated rendered-policy evaluation",
    )


def canonical_config(config: Path) -> bytes:
    return _canonical_ruleset(_config_json(config), "rendered nftables ruleset")


def canonical_live() -> bytes:
    return _canonical_ruleset(
        _run([str(NFT), "--json", "list", "ruleset"], "live ruleset read"),
        "live nftables ruleset",
    )


def digest_config(config: Path) -> str:
    return hashlib.sha256(canonical_config(config)).hexdigest()


def compare_live(config: Path) -> str:
    expected = canonical_config(config)
    actual = canonical_live()
    expected_digest = hashlib.sha256(expected).hexdigest()
    actual_digest = hashlib.sha256(actual).hexdigest()
    if actual != expected:
        raise GuardError(
            "live nftables semantic digest "
            f"{actual_digest} differs from rendered digest {expected_digest}"
        )
    return expected_digest


def _read_profile(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise GuardError("active firewall profile must not be a symlink")
    try:
        metadata = path.stat()
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardError("active firewall profile is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise GuardError("active firewall profile protection drifted")
    value = _strict_json(raw, "active firewall profile")
    expected_keys = {
        "apiVersion",
        "carrierGatewayEnabled",
        "providerDestinationIpv4Cidrs",
        "providerEnabled",
        "semanticSha256",
        "voiceFixtureEnabled",
    }
    legacy_keys = {
        "apiVersion",
        "carrierGatewayEnabled",
        "semanticSha256",
        "twilioDestinationIpv4Cidrs",
        "twilioEnabled",
        "voiceFixtureEnabled",
    }
    if not isinstance(value, dict):
        raise GuardError("active firewall profile fields are not exact")
    # One migration read is retained for already-published generation-2
    # profiles. New writes are always provider-neutral v2 profiles; the legacy
    # Twilio field names are never emitted again.
    if set(value) == legacy_keys and value.get("apiVersion") == LEGACY_PROFILE_API_VERSION:
        value = {
            "apiVersion": PROFILE_API_VERSION,
            "carrierGatewayEnabled": value["carrierGatewayEnabled"],
            "providerDestinationIpv4Cidrs": value["twilioDestinationIpv4Cidrs"],
            "providerEnabled": value["twilioEnabled"],
            "semanticSha256": value["semanticSha256"],
            "voiceFixtureEnabled": value["voiceFixtureEnabled"],
        }
    elif set(value) != expected_keys:
        raise GuardError("active firewall profile fields are not exact")
    if (
        value.get("apiVersion") != PROFILE_API_VERSION
        or not isinstance(value.get("voiceFixtureEnabled"), bool)
        or not isinstance(value.get("carrierGatewayEnabled"), bool)
        or not isinstance(value.get("providerEnabled"), bool)
        or not isinstance(value.get("providerDestinationIpv4Cidrs"), list)
        or any(
            not isinstance(item, str)
            for item in value.get("providerDestinationIpv4Cidrs", [])
        )
        or value.get("providerDestinationIpv4Cidrs")
        != sorted(set(value.get("providerDestinationIpv4Cidrs", [])))
        or not isinstance(value.get("semanticSha256"), str)
        or len(value["semanticSha256"]) != 64
        or any(character not in "0123456789abcdef" for character in value["semanticSha256"])
        or (not value["providerEnabled"] and value["providerDestinationIpv4Cidrs"])
        or (value["providerEnabled"] and not value["carrierGatewayEnabled"])
    ):
        raise GuardError("active firewall profile values are not canonical")
    return value


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def verify_profile(
    config: Path,
    profile_path: Path,
    *,
    fixture_enabled: bool | None,
    carrier_enabled: bool | None,
    provider_enabled: bool | None,
    provider_destinations_json: str | None,
) -> str:
    profile = _read_profile(profile_path)
    expected_digest = compare_live(config)
    if profile["semanticSha256"] != expected_digest:
        raise GuardError("active firewall profile does not bind the rendered policy")
    requirements = (
        ("voiceFixtureEnabled", fixture_enabled),
        ("carrierGatewayEnabled", carrier_enabled),
        ("providerEnabled", provider_enabled),
    )
    for name, expected in requirements:
        if expected is not None and profile[name] is not expected:
            raise GuardError(f"active firewall profile {name} is not {expected}")
    if provider_destinations_json is not None:
        destinations = _strict_json(
            provider_destinations_json, "expected provider destination authority"
        )
        if (
            not isinstance(destinations, list)
            or any(not isinstance(item, str) for item in destinations)
            or destinations != sorted(set(destinations))
            or profile["providerDestinationIpv4Cidrs"] != destinations
        ):
            raise GuardError("active provider destination authority is not exact")
    return expected_digest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("--config", type=Path, required=True)
    compare_parser = subparsers.add_parser("compare-live")
    compare_parser.add_argument("--config", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-profile")
    verify_parser.add_argument("--config", type=Path, required=True)
    verify_parser.add_argument("--profile", type=Path, required=True)
    verify_parser.add_argument("--fixture-enabled", type=_parse_bool)
    verify_parser.add_argument("--carrier-enabled", type=_parse_bool)
    verify_parser.add_argument(
        "--provider-enabled", "--twilio-enabled", dest="provider_enabled", type=_parse_bool
    )
    verify_parser.add_argument(
        "--provider-destinations-json",
        "--twilio-destinations-json",
        dest="provider_destinations_json",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "digest":
            result = digest_config(args.config)
        elif args.command == "compare-live":
            result = compare_live(args.config)
        else:
            result = verify_profile(
                args.config,
                args.profile,
                fixture_enabled=args.fixture_enabled,
                carrier_enabled=args.carrier_enabled,
                provider_enabled=args.provider_enabled,
                provider_destinations_json=args.provider_destinations_json,
            )
    except GuardError as exc:
        print(f"NFTABLES_SEMANTIC_GUARD_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(f"NFTABLES_SEMANTIC_SHA256={result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
