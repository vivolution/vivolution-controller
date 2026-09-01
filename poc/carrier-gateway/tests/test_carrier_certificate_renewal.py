from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "roles/carrier_certificate/templates"
TOKEN_RE = re.compile(r"{{\s*(.*?)\s*}}")


def _render(name: str, values: dict[str, object]) -> str:
    """Render the small scalar-only Jinja subset used by these two templates."""

    def replace(match: re.Match[str]) -> str:
        expression = match.group(1)
        pieces = [piece.strip() for piece in expression.split("|")]
        source = pieces.pop(0)
        addition = re.fullmatch(r"\((\w+) \+ '([^']*)'\)", source)
        if addition:
            value: object = str(values[addition.group(1)]) + addition.group(2)
        else:
            value = values[source]
        for selected_filter in pieces:
            if selected_filter == "quote":
                value = shlex.quote(str(value))
            elif selected_filter == "int":
                value = str(int(value))
            else:  # pragma: no cover - catches future template expansion
                raise AssertionError(f"unsupported test-render filter: {selected_filter}")
        return str(value)

    rendered = TOKEN_RE.sub(replace, (TEMPLATES / name).read_text())
    if "{{" in rendered or "{%" in rendered:
        raise AssertionError("test renderer left a Jinja expression behind")
    return rendered


def _unit_directives(rendered: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    section = ""
    for raw_line in rendered.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section == "[Service]" and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, []).append(value)
    return values


class CarrierCertificateRenewalTests(unittest.TestCase):
    def test_rendered_unit_reexposes_only_the_exact_rootless_runtime(self) -> None:
        runtime_dir = "/run/user/10003"
        rootless_home = "/var/lib/vivolution/carrier-gateway/rootless-home"
        rendered = _render(
            "vivolution-carrier-certificate.service.j2",
            {
                "carrier_certificate_acme_root": (
                    "/var/lib/vivolution-carrier-certificate/acme"
                ),
                "carrier_certificate_libexec_root": (
                    "/usr/local/libexec/vivolution-carrier-certificate"
                ),
                "carrier_certificate_pki_root": (
                    "/etc/vivolution/carrier-gateway/pki"
                ),
                "carrier_certificate_egress_pki_root": (
                    "/etc/vivolution/carrier-gateway/egress-pki"
                ),
                "carrier_certificate_rootless_home": rootless_home,
                "carrier_certificate_rootless_runtime_dir": runtime_dir,
                "carrier_certificate_rotation_root": (
                    "/var/lib/vivolution-carrier-certificate/rotation"
                ),
            },
        )
        directives = _unit_directives(rendered)
        self.assertEqual(directives["ProtectHome"], ["tmpfs"])
        self.assertEqual(directives["BindPaths"], [runtime_dir])
        self.assertTrue((Path(runtime_dir) / "bus").is_relative_to(runtime_dir))
        writable = directives["ReadWritePaths"][0].split()
        self.assertIn(rootless_home, writable)
        self.assertIn("/etc/vivolution/carrier-gateway/egress-pki", writable)
        self.assertNotIn("/run/user", writable)
        self.assertNotIn("/home", writable)
        self.assertNotIn("/root", writable)
        self.assertEqual(directives["ProtectSystem"], ["strict"])
        self.assertEqual(directives["NoNewPrivileges"], ["true"])

    def test_concurrent_lock_loser_never_reconciles_winners_txt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acme_root = root / "acme"
            incoming = root / "rotation/incoming"
            libexec = root / "libexec"
            acme_root.mkdir()
            incoming.mkdir(parents=True)
            libexec.mkdir()
            log = root / "reconcile.log"
            ready = root / "winner.ready"

            flock_helper = root / "flock_helper.py"
            flock_helper.write_text(
                "import fcntl, sys\n"
                "try:\n"
                "    fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                "except BlockingIOError:\n"
                "    raise SystemExit(1)\n"
            )
            flock = root / "flock"
            flock.write_text(
                "#!/bin/sh\n"
                'exec "$FLOCK_TEST_PYTHON" "$FLOCK_TEST_HELPER" "$@"\n'
            )
            flock.chmod(0o755)

            reconcile = libexec / "reconcile-carrier-acme-challenge"
            reconcile.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$INVOCATION_LABEL" >>"$RECONCILE_LOG"\n'
            )
            reconcile.chmod(0o755)
            for helper in (
                "carrier-certificate-operation-guard",
                "verify-carrier-acme-authority",
                "verify-carrier-acme-rbac-receipt",
                "validate-carrier-acme-state",
                "validate-carrier-certificate",
                "rotate-carrier-certificate",
            ):
                path = libexec / helper
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            lego = libexec / "lego"
            lego.write_text(
                "#!/bin/sh\n"
                'printf "ready\\n" >"$WINNER_READY"\n'
                "trap 'exit 143' HUP INT TERM\n"
                "while :; do sleep 1; done\n"
            )
            lego.chmod(0o755)

            rendered = _render(
                "renew-carrier-certificate.sh.j2",
                {
                    "carrier_certificate_acme_challenge_alias": (
                        "_acme-challenge.carrier.vivolution.ae"
                    ),
                    "carrier_certificate_acme_challenge_target": (
                        "_acme-challenge.acme-carrier.vivolution.ae"
                    ),
                    "carrier_certificate_acme_email": "operator@example.com",
                    "carrier_certificate_acme_root": str(acme_root),
                    "carrier_certificate_acme_zone": (
                        "acme-carrier.vivolution.ae"
                    ),
                    "carrier_certificate_azure_dns_resolver_ipv4": (
                        "168.63.129.16"
                    ),
                    "carrier_certificate_azure_subscription_id": (
                        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                    ),
                    "carrier_certificate_azure_tenant_id": (
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
                    ),
                    "carrier_certificate_dns_resource_group": "DNS_Zones",
                    "carrier_certificate_expected_cp1_principal_id": (
                        "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                    ),
                    "carrier_certificate_expected_public_ipv4": "40.123.208.212",
                    "carrier_certificate_key_type": "rsa2048",
                    "carrier_certificate_libexec_root": str(libexec),
                    "carrier_certificate_minimum_valid_seconds": 1209600,
                    "carrier_certificate_operation_guard_path": str(
                        libexec / "carrier-certificate-operation-guard"
                    ),
                    "carrier_certificate_public_ca_bundle_path": str(root / "ca.pem"),
                    "carrier_certificate_rbac_receipt_maximum_lifetime_seconds": 3600,
                    "carrier_certificate_rbac_receipt_minimum_remaining_seconds": 60,
                    "carrier_certificate_rbac_receipt_path": str(root / "receipt.json"),
                    "carrier_certificate_rbac_signer_public_key_path": str(
                        root / "signer.pem"
                    ),
                    "carrier_certificate_rbac_signer_public_key_sha256": "1" * 64,
                    "carrier_certificate_rbac_signing_key_id": "carrier-acme-rbac-2026-08",
                    "carrier_certificate_renew_days": 30,
                    "carrier_certificate_rotation_root": str(root / "rotation"),
                    "carrier_certificate_server_name": "carrier.vivolution.ae",
                },
            ).replace("/usr/bin/flock", str(flock))
            script = root / "renew"
            script.write_text(rendered)
            script.chmod(0o700)
            syntax = subprocess.run(
                ("/bin/sh", "-n", str(script)),
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

            common_env = {
                **os.environ,
                "FLOCK_TEST_HELPER": str(flock_helper),
                "FLOCK_TEST_PYTHON": sys.executable,
                "RECONCILE_LOG": str(log),
                "WINNER_READY": str(ready),
            }
            winner = subprocess.Popen(
                (str(script),),
                env={**common_env, "INVOCATION_LABEL": "winner"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while (
                    not ready.exists()
                    and winner.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                if not ready.exists():
                    output, error = winner.communicate(timeout=2)
                    self.fail(
                        "winner did not reach Lego: "
                        f"rc={winner.returncode} stdout={output!r} stderr={error!r}"
                    )
                loser = subprocess.run(
                    (str(script),),
                    env={**common_env, "INVOCATION_LABEL": "loser"},
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(loser.returncode, 75, loser.stderr)
                self.assertNotIn("loser", log.read_text().splitlines())
            finally:
                if winner.poll() is None:
                    os.killpg(winner.pid, signal.SIGTERM)
                    winner.communicate(timeout=5)
            labels = log.read_text().splitlines()
            self.assertGreaterEqual(len(labels), 2)
            self.assertEqual(set(labels), {"winner"})


if __name__ == "__main__":
    unittest.main()
