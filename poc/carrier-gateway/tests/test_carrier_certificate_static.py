from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class CarrierCertificateStaticTests(unittest.TestCase):
    def test_install_issues_before_existing_gateway_pki_validation(self) -> None:
        install = read("install.yml")
        self.assertLess(
            install.index("role: carrier_certificate"),
            install.index("role: carrier_gateway"),
        )
        tasks = read("roles/carrier_certificate/tasks/main.yml")
        self.assertLess(
            tasks.index("Bootstrap the exact locked rootless carrier user"),
            tasks.index("Obtain or renew the one-SAN carrier certificate"),
        )
        self.assertIn("renew-certificate.yml", read("README.md"))

    def test_pinned_lego_and_exact_one_san_order(self) -> None:
        defaults = read("roles/carrier_certificate/defaults/main.yml")
        tasks = read("roles/carrier_certificate/tasks/main.yml")
        renewal = read(
            "roles/carrier_certificate/templates/renew-carrier-certificate.sh.j2"
        )
        self.assertIn("carrier_certificate_lego_version: 5.4.0", defaults)
        self.assertIn(
            "d3adf89392d606ce84d485c1cc20832edd42ace6ff9ced9dd3670d9d8b8aca38",
            defaults,
        )
        self.assertIn('checksum: "sha256:{{ carrier_certificate_lego_linux_amd64_archive_sha256 }}"', tasks)
        self.assertEqual(renewal.count("--domains {{ carrier_certificate_server_name | quote }}"), 2)
        self.assertNotIn("--domains '*.", renewal)
        self.assertIn("--server https://acme-v02.api.letsencrypt.org/directory", renewal)
        self.assertIn("--require-account", renewal)
        self.assertIn("--require-certificate", renewal)

    def test_managed_identity_dns_binding_and_etag_cleanup_are_fail_closed(self) -> None:
        authority = read(
            "roles/carrier_certificate/files/verify_carrier_acme_authority.py"
        )
        cleanup = read(
            "roles/carrier_certificate/files/reconcile_carrier_acme_challenge.py"
        )
        env = read("roles/carrier_certificate/templates/acme-azure.env.j2")
        self.assertIn("AZURE_AUTH_METHOD=msi", env)
        self.assertNotIn("AZURE_CLIENT_SECRET=", env.upper())
        self.assertIn("EXPECTED_TAGS", authority)
        self.assertIn("managedIdentityPrincipalId", authority)
        self.assertIn("carrier challenge CNAME differs", authority)
        self.assertIn("public child-zone delegation differs", authority)
        self.assertIn('"If-Match": etag', cleanup)
        self.assertIn("bounded Lego challenge shape", cleanup)
        self.assertIn("verify-absent", cleanup)

    def test_renewal_requires_fresh_signed_exclusive_rbac_before_dns_mutation(self) -> None:
        tasks = read("roles/carrier_certificate/tasks/main.yml")
        renewal = read(
            "roles/carrier_certificate/templates/renew-carrier-certificate.sh.j2"
        )
        self.assertIn("verify_carrier_acme_rbac_receipt.py", tasks)
        self.assertIn("carrier_certificate_rbac_signer_public_key_sha256", tasks)
        self.assertIn("CARRIER_ACME_RBAC_RECEIPT_VALID", tasks)
        self.assertLess(
            renewal.index("verify-carrier-acme-rbac-receipt"),
            renewal.index("trap cleanup_exit EXIT"),
        )
        receipt_check = renewal.index("verify-carrier-acme-rbac-receipt")
        self.assertLess(
            receipt_check,
            renewal.index("\nreconcile_challenge\n", receipt_check),
        )

    def test_activation_is_atomic_recoverable_and_readiness_gated(self) -> None:
        rotation = read(
            "roles/carrier_certificate/templates/rotate-carrier-certificate.py.j2"
        )
        self.assertIn("os.replace(temporary, path)", rotation)
        self.assertIn('mode=0o440, gid=RUNTIME_GID', rotation)
        self.assertIn("BACKUP_CERT", rotation)
        self.assertIn("transaction.json", rotation)
        self.assertIn("_restore_previous(journal)", rotation)
        self.assertIn("except BaseException:", rotation)
        self.assertIn("signal.SIGTERM", rotation)
        self.assertIn("_restart_and_check_services(", rotation)
        self.assertIn("carrier readiness after certificate rotation", rotation)
        self.assertIn("EGRESS_RUNTIME_GID", rotation)
        self.assertIn("EGRESS_LIVE_CERT", rotation)
        self.assertIn("hadEgressPair", rotation)
        self.assertIn("provider-egress TLS transport readiness", rotation)
        self.assertIn("common and provider-egress credentials differ", rotation)
        self.assertIn("CARRIER_CERTIFICATE_UNCHANGED", rotation)
        self.assertIn("MAINTENANCE_GATE", rotation)
        self.assertIn("certificate maintenance blocks activation", rotation)

        rollback = read("roles/carrier_gateway_rollback/tasks/main.yml")
        self.assertIn("Gate certificate work before rollback quiescence", rollback)
        self.assertIn("snapshot-pki", rollback)
        self.assertIn("PKI digest equality", rollback)

    def test_timer_hardening_qualification_and_teardown_are_integrated(self) -> None:
        service = read(
            "roles/carrier_certificate/templates/vivolution-carrier-certificate.service.j2"
        )
        timer = read(
            "roles/carrier_certificate/templates/vivolution-carrier-certificate.timer.j2"
        )
        qualify = read("qualify.yml")
        teardown = read("roles/carrier_gateway_teardown/tasks/main.yml")
        for setting in (
            "ProtectSystem=strict",
            "NoNewPrivileges=true",
            "PrivateDevices=true",
            "MemoryDenyWriteExecute=true",
            "RestrictNamespaces=true",
        ):
            self.assertIn(setting, service)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=2h", timer)
        self.assertIn("CARRIER_ACME_AUTHORITY_BOUND", qualify)
        self.assertIn("vivolution-carrier-certificate.timer", qualify)
        self.assertIn("Refuse teardown over an unrecovered certificate activation", teardown)
        self.assertIn("carrier_gateway_remove_pki | bool", teardown)
        self.assertIn("certificate scheduling and service units are no longer loadable", teardown)
        self.assertIn("Re-prove certificate quiescence immediately", teardown)
        self.assertIn("carrier-certificate-rbac-receipt.json", teardown)
        self.assertIn("carrier-certificate-rbac-signer.pem", teardown)


if __name__ == "__main__":
    unittest.main()
