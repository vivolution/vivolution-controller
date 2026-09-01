#!/usr/bin/python3
"""Validate the exact public carrier-certificate contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import DNSName, PolicyBuilder, Store


class CertificateContractError(ValueError):
    pass


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _read(path: Path, label: str) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise CertificateContractError(f"cannot read {label}: {exc}") from exc
    if not content:
        raise CertificateContractError(f"{label} is empty")
    if len(content) > 1024 * 1024:
        raise CertificateContractError(f"{label} exceeds its one-MiB bound")
    return content


def validate_certificate(
    certificate_pem: bytes,
    private_key_pem: bytes,
    trust_bundle_pem: bytes,
    expected_san: str,
    *,
    minimum_valid_seconds: int,
    now: datetime | None = None,
) -> dict[str, object]:
    if (
        not expected_san
        or expected_san != expected_san.lower()
        or expected_san.startswith("*.")
        or expected_san.endswith(".")
    ):
        raise CertificateContractError("expected DNS SAN must be one lowercase exact FQDN")
    if minimum_valid_seconds < 86400:
        raise CertificateContractError("minimum validity must be at least one day")

    try:
        chain = x509.load_pem_x509_certificates(certificate_pem)
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        trust_roots = x509.load_pem_x509_certificates(trust_bundle_pem)
    except (TypeError, ValueError) as exc:
        raise CertificateContractError(
            f"invalid certificate, key, or trust-bundle PEM: {exc}"
        ) from exc
    if len(chain) < 2:
        raise CertificateContractError(
            "full chain must contain the leaf and at least one issuer certificate"
        )
    if not trust_roots:
        raise CertificateContractError("public trust bundle contains no certificates")

    leaf = chain[0]
    for child, issuer in pairwise(chain):
        if child.issuer != issuer.subject:
            raise CertificateContractError(
                "certificate chain is not ordered leaf-to-issuer"
            )
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise CertificateContractError("leaf certificate must not be a CA")
    except x509.ExtensionNotFound as exc:
        raise CertificateContractError("leaf certificate lacks Basic Constraints") from exc

    public_key = leaf.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
        raise CertificateContractError("leaf certificate key must be exactly RSA-2048")
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 2048:
        raise CertificateContractError("private key must be exactly RSA-2048")
    if public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise CertificateContractError("leaf certificate and private key do not match")

    try:
        san_extension = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound as exc:
        raise CertificateContractError("leaf certificate lacks Subject Alternative Name") from exc
    dns_sans = san_extension.get_values_for_type(x509.DNSName)
    if dns_sans != [expected_san] or len(san_extension) != 1:
        raise CertificateContractError(
            "leaf SANs must contain exactly carrier.vivolution.ae and nothing else"
        )

    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateContractError("leaf certificate lacks Extended Key Usage") from exc
    eku_oids = list(eku)
    if eku_oids != [ExtendedKeyUsageOID.SERVER_AUTH]:
        raise CertificateContractError(
            "leaf certificate EKU must be exactly Server Authentication"
        )

    check_time = now or datetime.now(timezone.utc)
    not_before = _utc(
        leaf.not_valid_before_utc
        if hasattr(leaf, "not_valid_before_utc")
        else leaf.not_valid_before
    )
    not_after = _utc(
        leaf.not_valid_after_utc
        if hasattr(leaf, "not_valid_after_utc")
        else leaf.not_valid_after
    )
    if not_before > check_time or not_after < check_time + timedelta(
        seconds=minimum_valid_seconds
    ):
        raise CertificateContractError(
            "leaf certificate is not valid for the required remaining lifetime"
        )

    try:
        verifier = (
            PolicyBuilder()
            .store(Store(trust_roots))
            .time(check_time)
            .build_server_verifier(DNSName(expected_san))
        )
        verifier.verify(leaf, chain[1:])
    except Exception as exc:
        raise CertificateContractError(
            f"public certificate chain validation failed: {exc}"
        ) from exc

    return {
        "certificateSha256": hashlib.sha256(certificate_pem).hexdigest(),
        "chainCertificateCount": len(chain),
        "dnsSans": dns_sans,
        "leafKeyAlgorithm": "RSA",
        "leafKeyBits": public_key.key_size,
        "notAfter": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "publicTrustBundleSha256": hashlib.sha256(trust_bundle_pem).hexdigest(),
        "extendedKeyUsageOids": [oid.dotted_string for oid in eku_oids],
        "serverAuthenticationEku": True,
        "status": "CARRIER_PUBLIC_CERTIFICATE_VALID",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-bundle", type=Path, required=True)
    parser.add_argument("--expected-san", required=True)
    parser.add_argument("--minimum-valid-seconds", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_certificate(
            _read(args.certificate, "certificate chain"),
            _read(args.private_key, "private key"),
            _read(args.trust_bundle, "public trust bundle"),
            args.expected_san,
            minimum_valid_seconds=args.minimum_valid_seconds,
        )
    except CertificateContractError as exc:
        print(f"CARRIER_PUBLIC_CERTIFICATE_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
