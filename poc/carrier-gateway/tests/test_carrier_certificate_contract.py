from __future__ import annotations

import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = (
    ROOT
    / "roles/carrier_certificate/files/validate_carrier_certificate.py"
)
SPEC = importlib.util.spec_from_file_location(
    "carrier_certificate_validator", VALIDATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

NOW = datetime(2026, 8, 31, 8, 0, tzinfo=timezone.utc)
SERVER_NAME = "carrier.vivolution.ae"


def _root() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "POC public root")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=120))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _leaf(
    root_key: rsa.RSAPrivateKey,
    root_certificate: x509.Certificate,
    *,
    dns_names: list[str] | None = None,
    server_auth: bool = True,
    additional_ekus: list[x509.ObjectIdentifier] | None = None,
    rsa_key: bool = True,
    lifetime_days: int = 30,
) -> tuple[bytes, bytes]:
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if rsa_key
        else ec.generate_private_key(ec.SECP256R1())
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)])
        )
        .issuer_name(root_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(hours=1))
        .not_valid_after(NOW + timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (dns_names or [SERVER_NAME])]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if server_auth
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
                + (additional_ekus or [])
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class CarrierCertificateContractTests(unittest.TestCase):
    def material(self, **kwargs):
        root_key, root_certificate = _root()
        leaf, private_key = _leaf(root_key, root_certificate, **kwargs)
        root_pem = root_certificate.public_bytes(serialization.Encoding.PEM)
        return leaf + root_pem, private_key, root_pem

    def validate(self, material):
        return validator.validate_certificate(
            *material,
            SERVER_NAME,
            minimum_valid_seconds=1209600,
            now=NOW,
        )

    def test_exact_one_san_rsa_chain_and_server_auth_pass(self):
        evidence = self.validate(self.material())
        self.assertEqual(evidence["status"], "CARRIER_PUBLIC_CERTIFICATE_VALID")
        self.assertEqual(evidence["dnsSans"], [SERVER_NAME])
        self.assertEqual(evidence["chainCertificateCount"], 2)
        self.assertEqual(evidence["leafKeyBits"], 2048)
        self.assertEqual(
            evidence["extendedKeyUsageOids"],
            [ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
        )

    def test_extra_or_wrong_san_is_rejected(self):
        for names in (
            [SERVER_NAME, "extra.vivolution.ae"],
            ["wrong.vivolution.ae"],
            ["*.vivolution.ae"],
        ):
            with self.subTest(names=names), self.assertRaisesRegex(
                validator.CertificateContractError, "SANs must contain exactly"
            ):
                self.validate(self.material(dns_names=names))

    def test_ec_missing_server_auth_and_short_lifetime_are_rejected(self):
        cases = (
            ({"rsa_key": False}, "RSA-2048"),
            ({"server_auth": False}, "Server Authentication"),
            ({"lifetime_days": 10}, "remaining lifetime"),
        )
        for values, message in cases:
            with self.subTest(values=values), self.assertRaisesRegex(
                validator.CertificateContractError, message
            ):
                self.validate(self.material(**values))

    def test_server_auth_plus_any_additional_eku_is_rejected(self):
        with self.assertRaisesRegex(
            validator.CertificateContractError,
            "EKU must be exactly Server Authentication",
        ):
            self.validate(
                self.material(additional_ekus=[ExtendedKeyUsageOID.CLIENT_AUTH])
            )

    def test_mismatched_private_key_is_rejected(self):
        chain, _private_key, trust = self.material()
        _other_chain, other_key, _other_trust = self.material()
        with self.assertRaisesRegex(
            validator.CertificateContractError, "do not match"
        ):
            self.validate((chain, other_key, trust))


if __name__ == "__main__":
    unittest.main()
