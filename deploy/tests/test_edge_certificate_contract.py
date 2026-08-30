from __future__ import annotations

import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


DEPLOY = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = (
    DEPLOY
    / "roles/edge_certificate/files/validate_edge_certificate.py"
)
SPEC = importlib.util.spec_from_file_location("edge_certificate_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

NOW = datetime(2026, 8, 30, 8, 0, tzinfo=timezone.utc)
BASE = "sbc1.voice.vivolution.ae"
WILDCARD = "*." + BASE


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
        .not_valid_after(NOW + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
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
    rsa_key: bool = True,
) -> tuple[bytes, bytes]:
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if rsa_key
        else ec.generate_private_key(ec.SECP256R1())
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, BASE)]))
        .issuer_name(root_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(hours=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
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
                [x509.DNSName(name) for name in (dns_names or [BASE, WILDCARD])]
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
            ),
            critical=False,
        )
    )
    certificate = builder.sign(root_key, hashes.SHA256())
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class EdgeCertificateContractTests(unittest.TestCase):
    def material(self, **kwargs):
        root_key, root_certificate = _root()
        leaf, private_key = _leaf(root_key, root_certificate, **kwargs)
        root_pem = root_certificate.public_bytes(serialization.Encoding.PEM)
        return leaf + root_pem, private_key, root_pem

    def validate(self, material):
        return validator.validate_certificate(
            *material,
            [BASE, WILDCARD],
            minimum_valid_seconds=1209600,
            now=NOW,
        )

    def test_exact_rsa_chain_sans_and_server_auth_pass(self):
        evidence = self.validate(self.material())
        self.assertEqual(evidence["status"], "EDGE_PUBLIC_CERTIFICATE_VALID")
        self.assertEqual(evidence["dnsSans"], [WILDCARD, BASE])
        self.assertEqual(evidence["chainCertificateCount"], 2)
        self.assertEqual(evidence["leafKeyAlgorithm"], "RSA")
        self.assertEqual(evidence["leafKeyBits"], 2048)
        self.assertTrue(evidence["serverAuthenticationEku"])

    def test_ec_leaf_is_rejected(self):
        with self.assertRaisesRegex(validator.CertificateContractError, "RSA-2048"):
            self.validate(self.material(rsa_key=False))

    def test_missing_or_extra_san_is_rejected(self):
        for names in ([BASE], [BASE, WILDCARD, "extra.voice.vivolution.ae"]):
            with self.subTest(names=names):
                with self.assertRaisesRegex(validator.CertificateContractError, "SANs must be exactly"):
                    self.validate(self.material(dns_names=names))

    def test_missing_server_auth_is_rejected(self):
        with self.assertRaisesRegex(validator.CertificateContractError, "Server Authentication"):
            self.validate(self.material(server_auth=False))

    def test_leaf_without_chain_is_rejected(self):
        chain, private_key, root = self.material()
        leaf_only = chain.split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
        with self.assertRaisesRegex(validator.CertificateContractError, "full chain"):
            self.validate((leaf_only, private_key, root))


if __name__ == "__main__":
    unittest.main()
