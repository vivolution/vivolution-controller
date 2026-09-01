from __future__ import annotations

import csv
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import time
import unittest
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BROKER = load(
    "carrier_authority_broker",
    "roles/carrier_gateway/files/bin/carrier_authority_broker.py",
)
CDR = load(
    "carrier_cdr_evidence_integrity",
    "roles/carrier_gateway/files/bin/carrier_cdr_evidence.py",
)
TWILIO_ADAPTER = load(
    "carrier_cdr_provider_adapter_twilio",
    "roles/carrier_gateway/files/bin/carrier_cdr_provider_adapters/twilio.py",
)
BUNDLE = load(
    "carrier_rollback_bundle",
    "roles/carrier_gateway/files/bin/carrier_rollback_bundle.py",
)


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class AuthorityBrokerTests(unittest.TestCase):
    def make_store(self, root: pathlib.Path):
        authorization = root / "authorization"
        authorization.mkdir(mode=0o700)
        for name in ("claims", "invalidated", "ids"):
            (authorization / name).mkdir(mode=0o700)
        system = root / "system"
        artifact = system / "etc/test.conf"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("version=one\n", encoding="utf-8")
        store = BROKER.AuthorityStore(
            authorization,
            system_root=system,
            config_artifacts=("etc/test.conf",),
            trusted_uid=os.getuid(),
            trusted_gid=os.getgid(),
        )
        return store, authorization, artifact

    def request(self, request_id: str = "request-0001") -> dict[str, object]:
        return {
            "destination": "+971501234567",
            "expiresEpoch": int(time.time()) + 300,
            "maxCallSeconds": 60,
            "maxSpendMicroUsd": 1_000_000,
            "requestId": request_id,
        }

    def test_root_ledger_claim_is_uid_bound_one_shot_and_nonreplayable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authorization, _artifact = self.make_store(pathlib.Path(directory))
            store.arm(self.request())
            pending = authorization / "pending"
            self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
            self.assertEqual(pending.stat().st_nlink, 1)
            with self.assertRaises(BROKER.AuthorityError):
                store.claim("+971501234567", 10003)
            claimed = store.claim("+971501234567", 10004)
            self.assertEqual(claimed["record"]["requestId"], "request-0001")
            self.assertFalse(pending.exists())
            self.assertTrue((authorization / "claims/request-0001.claimed").is_file())
            self.assertTrue((authorization / "claims/request-0001.receipt.json").is_file())
            with self.assertRaises(BROKER.AuthorityError):
                store.claim("+971501234567", 10004)
            with self.assertRaises(BROKER.AuthorityError):
                store.arm(self.request())

    def test_config_drift_denies_and_invalidation_burns_pending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, authorization, artifact = self.make_store(pathlib.Path(directory))
            store.arm(self.request("request-0002"))
            artifact.write_text("version=two\n", encoding="utf-8")
            with self.assertRaises(BROKER.AuthorityError):
                store.claim("+971501234567", 10004)
            self.assertTrue(store.invalidate("config-drift"))
            self.assertFalse((authorization / "pending").exists())
            self.assertEqual(len(list((authorization / "invalidated").glob("*.invalidated"))), 1)

    def test_claim_crashes_at_every_link_fsync_unlink_boundary_are_burnable(self) -> None:
        boundaries = (
            "claim-after-link",
            "claim-after-claims-fsync",
            "claim-after-pending-unlink",
            "claim-after-root-fsync",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                store, authorization, _artifact = self.make_store(pathlib.Path(directory))
                request_id = f"claim-crash-{index:02d}"
                store.arm(self.request(request_id))

                def crash(name: str) -> None:
                    if name == boundary:
                        raise RuntimeError(name)

                store.fault_hook = crash
                with self.assertRaisesRegex(RuntimeError, boundary):
                    store.claim("+971501234567", 10004)
                store.fault_hook = None
                self.assertTrue(store.reconcile("claim-crash"))
                self.assertFalse((authorization / "pending").exists())
                receipt = authorization / "invalidated" / f"{request_id}.reconciled.json"
                self.assertTrue(receipt.is_file())
                self.assertEqual(
                    json.loads(receipt.read_text())["status"],
                    "AMBIGUOUS_AUTHORITY_BURNED",
                )
                with self.assertRaises(BROKER.AuthorityError):
                    store.claim("+971501234567", 10004)

    def test_invalidation_crashes_at_every_link_fsync_unlink_boundary_reconcile(self) -> None:
        boundaries = (
            "invalidate-after-link",
            "invalidate-after-invalidated-fsync",
            "invalidate-after-pending-unlink",
            "invalidate-after-root-fsync",
        )
        for index, boundary in enumerate(boundaries):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                store, authorization, _artifact = self.make_store(pathlib.Path(directory))
                request_id = f"burn-crash-{index:02d}"
                store.arm(self.request(request_id))

                def crash(name: str) -> None:
                    if name == boundary:
                        raise RuntimeError(name)

                store.fault_hook = crash
                with self.assertRaisesRegex(RuntimeError, boundary):
                    store.invalidate("test-burn")
                store.fault_hook = None
                self.assertTrue(store.reconcile("burn-recovery"))
                self.assertFalse((authorization / "pending").exists())
                invalidated = authorization / "invalidated" / f"{request_id}.invalidated"
                self.assertTrue(invalidated.is_file())
                self.assertTrue((authorization / "invalidated" / f"{request_id}.invalidated.json").is_file())

    def test_broker_request_timeout_and_concurrency_are_strictly_bounded(self) -> None:
        broker = source("roles/carrier_gateway/files/bin/carrier_authority_broker.py")
        service = source("roles/carrier_gateway/templates/vivolution-carrier-authority-broker.service.j2")
        socket_unit = source("roles/carrier_gateway/templates/vivolution-carrier-authority-broker.socket.j2")
        client = source("roles/carrier_gateway/files/asterisk/vivolution-authority-client.c")
        self.assertIn("threading.BoundedSemaphore(max_connections)", broker)
        self.assertIn("connection.settimeout(request_timeout_seconds)", broker)
        self.assertIn("--request-timeout-ms 1000", service)
        self.assertIn("--max-connections 4", service)
        self.assertIn("Backlog=4", socket_unit)
        self.assertIn("SO_RCVTIMEO", client)
        self.assertIn("SO_SNDTIMEO", client)

    def test_container_has_socket_only_and_start_invalidation(self) -> None:
        ingress_quadlet = source("roles/carrier_gateway/templates/vivolution-carrier-gateway.container.j2")
        egress_quadlet = source("roles/carrier_gateway/templates/vivolution-carrier-egress.container.j2")
        containerfile = source("roles/carrier_gateway/files/asterisk/Containerfile")
        entrypoint = source("roles/carrier_gateway/files/asterisk/vivolution-carrier-entrypoint")
        broker = source("roles/carrier_gateway/files/bin/carrier_authority_broker.py")
        self.assertNotIn("authorization:/var/lib/asterisk/authorization:rw", ingress_quadlet)
        self.assertNotIn("vivolution-carrier-authority.sock", ingress_quadlet)
        self.assertIn("vivolution-carrier-authority.sock", egress_quadlet)
        self.assertIn("SO_PEERCRED", broker)
        self.assertIn("peer_uid != self.expected_peer_uid", broker)
        self.assertIn("os.geteuid() != 0", broker)
        self.assertIn("os.link(", broker)
        self.assertIn("os.unlink(\"pending\"", broker)
        self.assertIn("--invalidate-start", entrypoint)
        self.assertIn("vivolution-carrier-entrypoint", containerfile)


class CdrIntegrityTests(unittest.TestCase):
    @staticmethod
    def signed_receipt(
        path: pathlib.Path,
        public_key_path: pathlib.Path,
        key_id: str,
        payload: dict[str, object],
    ) -> None:
        private_key = path.with_suffix(".private.pem")
        subprocess.run(
            ["/usr/bin/openssl", "genrsa", "-out", str(private_key), "3072"],
            check=True,
            capture_output=True,
        )
        public_result = subprocess.run(
            ["/usr/bin/openssl", "rsa", "-in", str(private_key), "-pubout"],
            check=True,
            capture_output=True,
        )
        public_key_path.write_bytes(public_result.stdout)
        signature_result = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(private_key)],
            input=CDR.CORROBORATION_DOMAIN + CDR._canonical(payload),
            check=True,
            capture_output=True,
        )
        private_key.unlink()
        envelope = {
            "payload": payload,
            "signature": {
                "algorithm": "RSA-PKCS1v15-SHA256",
                "keyId": key_id,
                "value": base64.urlsafe_b64encode(signature_result.stdout)
                .decode()
                .rstrip("="),
            },
        }
        path.write_bytes(CDR._canonical(envelope))
        path.chmod(0o400)
        public_key_path.chmod(0o444)

    def corroboration(
        self,
        root: pathlib.Path,
        row: list[str],
        request_id: str,
        *,
        node_id: str = "cp1",
        edge_id: str = "sbc1",
        billed_call_count: int = 1,
    ) -> tuple[pathlib.Path, pathlib.Path, str, pathlib.Path, pathlib.Path]:
        normalized = CDR._normalized_record(CDR._parse_row(row, 1), "EDGE_TO_PROVIDER_OUTBOUND")
        destination_digest = CDR._digest(row[7].encode())
        edge_payload = {
            "carrierRecordDigest": normalized["recordDigest"],
            "destinationDigest": destination_digest,
            "edgeId": edge_id,
            "nodeId": node_id,
            "observedEndTimestamp": normalized["endTimestamp"],
            "observedStartTimestamp": normalized["startTimestamp"],
            "requestId": request_id,
            "schema": "poc.vivolution.ae/edge-call-corroboration/v1",
            "sourceCursorDigest": "sha256:" + "11" * 32,
            "sourceService": "opensips.service",
            "status": "EDGE_CALL_OBSERVED",
        }
        twilio_payload = {
            "billedCallCount": billed_call_count,
            "billedDurationSeconds": int(row[4]),
            "carrierRecordDigest": normalized["recordDigest"],
            "destinationDigest": destination_digest,
            "observedAt": normalized["endTimestamp"],
            "requestId": request_id,
            "schema": "poc.vivolution.ae/twilio-call-log-corroboration/v1",
            "status": "TWILIO_EXACTLY_ONE_BILLED_CALL",
            "twilioAccountDigest": "sha256:" + "22" * 32,
            "twilioCallSidDigest": "sha256:" + "33" * 32,
        }
        edge_receipt = root / f"{request_id}-edge.json"
        edge_key = root / f"{request_id}-edge.pub"
        twilio_receipt = root / f"{request_id}-twilio.json"
        twilio_key = root / f"{request_id}-twilio.pub"
        self.signed_receipt(edge_receipt, edge_key, f"edge:{edge_id}", edge_payload)
        self.signed_receipt(
            twilio_receipt,
            twilio_key,
            "twilio:authoritative-call-log",
            twilio_payload,
        )
        return edge_receipt, edge_key, "twilio", twilio_receipt, twilio_key

    @staticmethod
    def row(
        account: str,
        userfield: str,
        start_epoch: int,
        destination: str = "+971501234567",
        unique: str = "unique-1",
        *,
        answered: bool = True,
        dialed: bool = True,
        disposition: str = "ANSWERED",
    ) -> list[str]:
        start = datetime.fromtimestamp(start_epoch, timezone.utc)
        answer = datetime.fromtimestamp(start_epoch + 1, timezone.utc) if answered else None
        end = datetime.fromtimestamp(start_epoch + 3, timezone.utc)
        return [
            start.isoformat(),
            answer.isoformat() if answer else "",
            end.isoformat(),
            "3",
            "2" if answered else "0",
            disposition,
            "+971555555555",
            destination,
            "PJSIP/gateway-inbound-a1b2",
            "PJSIP/provider-c3d4" if dialed else "",
            unique,
            "linked-1",
            account,
            userfield,
        ]

    def test_exact_new_claimed_row_with_checkpoint_and_classified_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = AuthorityBrokerTests()
            store, authorization, _artifact = helper.make_store(root)
            now = int(time.time())
            request = helper.request("request-0003")
            request["expiresEpoch"] = now + 300
            store.arm(request, now=now)
            store.claim("+971501234567", 10004, now=now)
            source_path = root / "carrier.csv"
            rows = [
                self.row(
                    "",
                    "",
                    now,
                    unique="blocked",
                    answered=False,
                    dialed=False,
                    disposition="FAILED",
                ),
                self.row(
                    "vivo-carrier-provider-out",
                    "",
                    now,
                    unique="blocked-before-agi",
                    answered=False,
                    dialed=False,
                    disposition="FAILED",
                ),
                self.row("vivo-carrier-provider-out", "request-0003", now),
            ]
            with source_path.open("w", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerows(rows)
            source_path.chmod(0o600)
            corroboration = self.corroboration(
                root, rows[-1], "request-0003"
            )
            checkpoint = root / "checkpoint.json"
            evidence, next_checkpoint = CDR.collect_authorized_call(
                source_path,
                checkpoint,
                authorization,
                "request-0003",
                "cp1",
                "sbc1",
                *corroboration,
                trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                source_uid=os.getuid(),
                source_gid=os.getgid(),
                collected_at=datetime.fromtimestamp(now + 5, timezone.utc),
            )
            self.assertEqual(evidence["classifiedNewRows"]["authorizedProvider"], 1)
            self.assertEqual(evidence["classifiedNewRows"]["provenBlockedProvider"], 1)
            self.assertEqual(evidence["classifiedNewRows"]["unroutedRejected"], 1)
            self.assertEqual(evidence["corroboration"]["providerProfile"], "twilio")
            self.assertEqual(
                evidence["observedPeerBinding"]["providerEndpoint"], "twilio"
            )
            self.assertNotIn("twilioReceiptDigest", evidence["corroboration"])
            payload = json.dumps(evidence, sort_keys=True)
            self.assertNotIn("+971501234567", payload)
            self.assertNotIn("unique-1", payload)
            output = root / "evidence"
            CDR.write_new(output, evidence)
            CDR.write_checkpoint(
                checkpoint,
                next_checkpoint,
                trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
            )
            self.assertTrue((output / "manifest.json").is_file())
            with source_path.open("a", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerow(self.row("", "", now + 10, unique="blocked-2"))
            with self.assertRaises(CDR.EvidenceError):
                CDR.collect_authorized_call(
                    source_path,
                    checkpoint,
                    authorization,
                    "request-0003",
                    "cp1",
                    "sbc1",
                    *corroboration,
                    trusted_uid=os.getuid(),
                    trusted_gid=os.getgid(),
                    source_uid=os.getuid(),
                    source_gid=os.getgid(),
                )

    def test_non_twilio_adapter_plugs_in_without_core_change(self) -> None:
        core_source = source(
            "roles/carrier_gateway/files/bin/carrier_cdr_evidence.py"
        )
        self.assertNotIn("twilio", core_source.lower())
        self.assertIn(
            "twilioAccountDigest",
            source(
                "roles/carrier_gateway/files/bin/"
                "carrier_cdr_provider_adapters/twilio.py"
            ),
        )
        install_tasks = source("roles/carrier_gateway/tasks/main.yml")
        self.assertIn("src: bin/carrier_cdr_provider_adapters/", install_tasks)
        self.assertIn(
            "dest: /usr/local/libexec/carrier_cdr_provider_adapters/",
            install_tasks,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = AuthorityBrokerTests()
            store, authorization, _artifact = helper.make_store(root)
            now = int(time.time())
            request_id = "adapter-example-01"
            request = helper.request(request_id)
            request["expiresEpoch"] = now + 300
            store.arm(request, now=now)
            store.claim("+971501234567", 10004, now=now)
            authorized_row = self.row(
                "vivo-carrier-provider-out", request_id, now
            )
            source_path = root / "carrier.csv"
            with source_path.open("w", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerow(authorized_row)
            source_path.chmod(0o600)

            normalized = CDR._normalized_record(
                CDR._parse_row(authorized_row, 1), "EDGE_TO_PROVIDER_OUTBOUND"
            )
            destination_digest = CDR._digest(authorized_row[7].encode())
            edge_payload = {
                "carrierRecordDigest": normalized["recordDigest"],
                "destinationDigest": destination_digest,
                "edgeId": "sbc1",
                "nodeId": "cp1",
                "observedEndTimestamp": normalized["endTimestamp"],
                "observedStartTimestamp": normalized["startTimestamp"],
                "requestId": request_id,
                "schema": "poc.vivolution.ae/edge-call-corroboration/v1",
                "sourceCursorDigest": "sha256:" + "44" * 32,
                "sourceService": "opensips.service",
                "status": "EDGE_CALL_OBSERVED",
            }
            provider_payload = {
                "billedDurationSeconds": int(authorized_row[4]),
                "requestId": request_id,
            }
            edge_receipt = root / "edge.json"
            edge_key = root / "edge.pub"
            provider_receipt = root / "provider.json"
            provider_key = root / "provider.pub"
            self.signed_receipt(edge_receipt, edge_key, "edge:sbc1", edge_payload)
            self.signed_receipt(
                provider_receipt,
                provider_key,
                "example:authoritative-billing",
                provider_payload,
            )

            adapter_root = root / "adapters"
            adapter_root.mkdir(mode=0o700)
            adapter = adapter_root / "example.py"
            adapter.write_text(
                """ADAPTER_API_VERSION = (
    \"poc.vivolution.ae/carrier-cdr-provider-adapter/v1\"
)
PROVIDER_PROFILE = \"example\"

def verify(context):
    payload, receipt_digest = context.verify_signed_receipt(
        expected_key_id=\"example:authoritative-billing\",
        payload_keys={\"billedDurationSeconds\", \"requestId\"},
    )
    if (
        payload[\"requestId\"] != context.request_id
        or payload[\"billedDurationSeconds\"] != context.billed_duration_seconds
    ):
        context.reject(\"example billing receipt does not bind the call\")
    return {
        \"adapterApiVersion\": ADAPTER_API_VERSION,
        \"providerProfile\": PROVIDER_PROFILE,
        \"receiptDigest\": receipt_digest,
        \"signingKeyId\": \"example:authoritative-billing\",
        \"status\": \"EXACTLY_ONE_BILLED_CALL_CORROBORATED\",
    }
""",
                encoding="utf-8",
            )
            adapter.chmod(0o644)

            evidence, _next_checkpoint = CDR.collect_authorized_call(
                source_path,
                root / "checkpoint.json",
                authorization,
                request_id,
                "cp1",
                "sbc1",
                edge_receipt,
                edge_key,
                "example",
                provider_receipt,
                provider_key,
                trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                source_uid=os.getuid(),
                source_gid=os.getgid(),
                collected_at=datetime.fromtimestamp(now + 5, timezone.utc),
                provider_adapter_root=adapter_root,
            )
            self.assertEqual(evidence["corroboration"]["providerProfile"], "example")
            self.assertEqual(
                evidence["corroboration"]["providerSigningKeyId"],
                "example:authoritative-billing",
            )
            self.assertRegex(
                evidence["corroboration"]["providerAdapterDigest"],
                r"^sha256:[0-9a-f]{64}$",
            )

    def test_twilio_adapter_owns_and_enforces_its_exact_contract(self) -> None:
        valid_payload = {
            "billedCallCount": 1,
            "billedDurationSeconds": 2,
            "carrierRecordDigest": "sha256:" + "55" * 32,
            "destinationDigest": "sha256:" + "66" * 32,
            "observedAt": "2026-09-01T05:00:03+00:00",
            "requestId": "twilio-adapter-01",
            "schema": "poc.vivolution.ae/twilio-call-log-corroboration/v1",
            "status": "TWILIO_EXACTLY_ONE_BILLED_CALL",
            "twilioAccountDigest": "sha256:" + "77" * 32,
            "twilioCallSidDigest": "sha256:" + "88" * 32,
        }

        test_case = self

        class Context:
            request_id = "twilio-adapter-01"
            destination_digest = "sha256:" + "66" * 32
            carrier_record_digest = "sha256:" + "55" * 32
            billed_duration_seconds = 2
            observed_end_timestamp = "2026-09-01T05:00:03+00:00"

            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = payload

            def verify_signed_receipt(
                self, *, expected_key_id: str, payload_keys: set[str]
            ) -> tuple[dict[str, object], str]:
                test_case.assertEqual(
                    expected_key_id, "twilio:authoritative-call-log"
                )
                test_case.assertEqual(payload_keys, set(valid_payload))
                return self.payload, "sha256:" + "99" * 32

            @staticmethod
            def reject(message: str) -> None:
                raise CDR.EvidenceError(message)

        accepted = TWILIO_ADAPTER.verify(Context(dict(valid_payload)))
        self.assertEqual(accepted["providerProfile"], "twilio")
        self.assertEqual(
            accepted["signingKeyId"], "twilio:authoritative-call-log"
        )
        invalid_values = {
            "billedCallCount": True,
            "billedDurationSeconds": 3,
            "carrierRecordDigest": "sha256:" + "00" * 32,
            "destinationDigest": "sha256:" + "00" * 32,
            "observedAt": "2026-09-01T05:00:04+00:00",
            "requestId": "twilio-adapter-02",
            "schema": "wrong-schema",
            "status": "WRONG_STATUS",
            "twilioAccountDigest": "not-a-digest",
            "twilioCallSidDigest": "not-a-digest",
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field):
                payload = dict(valid_payload)
                payload[field] = value
                with self.assertRaisesRegex(
                    CDR.EvidenceError, "signed Twilio call log"
                ):
                    TWILIO_ADAPTER.verify(Context(payload))

    def test_any_unmatched_answered_billable_or_dialed_provider_row_rejects_gate(self) -> None:
        variants = (
            {},
            {"answered": False, "dialed": True, "disposition": "NO ANSWER"},
        )
        for index, values in enumerate(variants):
            with self.subTest(values=values), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                helper = AuthorityBrokerTests()
                store, authorization, _artifact = helper.make_store(root)
                now = int(time.time())
                request = helper.request(f"evidence-fail-{index:02d}")
                request["expiresEpoch"] = now + 300
                store.arm(request, now=now)
                store.claim("+971501234567", 10004, now=now)
                source_path = root / "carrier.csv"
                rows = [
                    self.row(
                        "vivo-carrier-provider-out",
                        "",
                        now,
                        unique="unmatched",
                        **values,
                    ),
                    self.row(
                        "vivo-carrier-provider-out",
                        f"evidence-fail-{index:02d}",
                        now,
                    ),
                ]
                with source_path.open("w", encoding="utf-8", newline="") as handle:
                    csv.writer(handle).writerows(rows)
                source_path.chmod(0o600)
                corroboration = self.corroboration(
                    root, rows[-1], f"evidence-fail-{index:02d}"
                )
                with self.assertRaisesRegex(CDR.EvidenceError, "unmatched provider row"):
                    CDR.collect_authorized_call(
                        source_path,
                        root / "checkpoint.json",
                        authorization,
                        f"evidence-fail-{index:02d}",
                        "cp1",
                        "sbc1",
                        *corroboration,
                        trusted_uid=os.getuid(),
                        trusted_gid=os.getgid(),
                        source_uid=os.getuid(),
                        source_gid=os.getgid(),
                    )

    def test_crash_after_evidence_publish_recovers_exact_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = AuthorityBrokerTests()
            store, authorization, _artifact = helper.make_store(root)
            now = int(time.time())
            request = helper.request("checkpoint-recovery")
            request["expiresEpoch"] = now + 300
            store.arm(request, now=now)
            store.claim("+971501234567", 10004, now=now)
            source_path = root / "carrier.csv"
            authorized_row = self.row(
                "vivo-carrier-provider-out", "checkpoint-recovery", now
            )
            with source_path.open("w", encoding="utf-8", newline="") as handle:
                csv.writer(handle).writerow(authorized_row)
            source_path.chmod(0o600)
            corroboration = self.corroboration(
                root, authorized_row, "checkpoint-recovery"
            )
            checkpoint_path = root / "checkpoint.json"
            evidence, next_checkpoint = CDR.collect_authorized_call(
                source_path,
                checkpoint_path,
                authorization,
                "checkpoint-recovery",
                "cp1",
                "sbc1",
                *corroboration,
                trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                source_uid=os.getuid(),
                source_gid=os.getgid(),
                collected_at=datetime.fromtimestamp(now + 5, timezone.utc),
            )
            output = root / "evidence"
            CDR.write_new(output, evidence, next_checkpoint)
            self.assertFalse(checkpoint_path.exists())
            status = CDR.recover_checkpoint_publication(
                output,
                checkpoint_path,
                source_path,
                "checkpoint-recovery",
                trusted_uid=os.getuid(),
                trusted_gid=os.getgid(),
                source_uid=os.getuid(),
                source_gid=os.getgid(),
            )
            self.assertEqual(status, "RECOVERED_CHECKPOINT_PUBLICATION")
            self.assertEqual(
                CDR.recover_checkpoint_publication(
                    output,
                    checkpoint_path,
                    source_path,
                    "checkpoint-recovery",
                    trusted_uid=os.getuid(),
                    trusted_gid=os.getgid(),
                    source_uid=os.getuid(),
                    source_gid=os.getgid(),
                ),
                "CHECKPOINT_ALREADY_PUBLISHED",
            )

    def test_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source_path = root / "carrier.csv"
            source_path.write_text("", encoding="utf-8")
            link = root / "linked.csv"
            link.symlink_to(source_path)
            with self.assertRaises(CDR.EvidenceError):
                CDR.normalize(link)


class RollbackAndTeardownTests(unittest.TestCase):
    def test_bundle_is_exact_digest_bound_duplicate_free_and_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            system = root / "system"
            artifact = system / "etc/exact.conf"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("lkg\n", encoding="utf-8")
            original = BUNDLE.ARTIFACTS
            BUNDLE.ARTIFACTS = ("etc/exact.conf",)
            try:
                archive = root / "rollback.tar"
                detached = root / "rollback.tar.sha256"
                BUNDLE.create_bundle(archive, detached, system)
                extracted, manifest = BUNDLE.load_bundle(archive, detached)
                self.assertEqual(manifest["artifacts"][0]["path"], "etc/exact.conf")
                self.assertEqual(extracted["payload/etc/exact.conf"], b"lkg\n")
                artifact.write_text("broken\n", encoding="utf-8")
                BUNDLE.restore_bundle(archive, detached, system)
                self.assertEqual(artifact.read_text(encoding="utf-8"), "lkg\n")

                duplicate = root / "duplicate.tar"
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as bundle:
                    for _ in range(2):
                        info = tarfile.TarInfo("payload/etc/exact.conf")
                        info.size = 4
                        bundle.addfile(info, io.BytesIO(b"lkg\n"))
                duplicate.write_bytes(stream.getvalue())
                duplicate_digest = root / "duplicate.tar.sha256"
                duplicate_digest.write_text(
                    "sha256:" + hashlib.sha256(stream.getvalue()).hexdigest() + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(BUNDLE.BundleError):
                    BUNDLE.load_bundle(duplicate, duplicate_digest)
            finally:
                BUNDLE.ARTIFACTS = original

    def test_provider_profile_and_private_credential_are_one_rollback_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            system = root / "system"
            enabled_path = system / BUNDLE.PROVIDER_ENABLED
            profile_path = system / "etc/vivolution/carrier-gateway/provider-profile"
            endpoint_path = system / "etc/vivolution/carrier-gateway/egress/asterisk/pjsip.conf"
            secret_path = system / BUNDLE.PROVIDER_CREDENTIAL
            adapter_path = system / BUNDLE.PROVIDER_ADAPTER_ROOT / "example.py"
            for path in (
                enabled_path,
                profile_path,
                endpoint_path,
                secret_path,
                adapter_path,
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
            enabled_path.write_bytes(b"true\n")
            profile_path.write_bytes(b"example\n")
            endpoint_path.write_bytes(b"server_uri=sips:provider.example:5061\n")
            secret = b"username=opaque\npassword=do-not-emit-this-secret\n"
            secret_path.write_bytes(secret)
            secret_path.chmod(0o440)
            adapter_path.write_bytes(b"PROVIDER_PROFILE = 'example'\n")
            adapter_path.chmod(0o550)

            original_artifacts = BUNDLE.ARTIFACTS
            original_optional = BUNDLE.OPTIONAL_ARTIFACTS
            original_uid = BUNDLE.PROVIDER_CREDENTIAL_UID
            original_gid = BUNDLE.PROVIDER_CREDENTIAL_GID
            original_adapter_uid = BUNDLE.PROVIDER_ADAPTER_UID
            original_adapter_gid = BUNDLE.PROVIDER_ADAPTER_GID
            BUNDLE.ARTIFACTS = (
                BUNDLE.PROVIDER_ENABLED,
                BUNDLE.PROVIDER_PROFILE,
                "etc/vivolution/carrier-gateway/egress/asterisk/pjsip.conf",
            )
            BUNDLE.OPTIONAL_ARTIFACTS = (BUNDLE.PROVIDER_CREDENTIAL,)
            BUNDLE.PROVIDER_CREDENTIAL_UID = os.geteuid()
            BUNDLE.PROVIDER_CREDENTIAL_GID = os.getegid()
            BUNDLE.PROVIDER_ADAPTER_UID = os.geteuid()
            BUNDLE.PROVIDER_ADAPTER_GID = os.getegid()
            try:
                archive = root / "provider.tar"
                detached = root / "provider.tar.sha256"
                BUNDLE.create_bundle(archive, detached, system)
                _payloads, manifest = BUNDLE.load_bundle(archive, detached)
                manifest_bytes = BUNDLE.canonical(manifest)
                self.assertNotIn(secret, manifest_bytes)
                secret_entry = next(
                    entry
                    for entry in manifest["artifacts"]
                    if entry["path"] == BUNDLE.PROVIDER_CREDENTIAL
                )
                self.assertEqual(secret_entry["sha256"], BUNDLE.digest(secret))
                self.assertTrue(
                    any(
                        entry["path"] == (
                            BUNDLE.PROVIDER_ADAPTER_ROOT + "/example.py"
                        )
                        for entry in manifest["artifacts"]
                    )
                )

                secret_path.chmod(0o600)
                secret_path.write_bytes(b"password=new-and-wrong\n")
                secret_path.chmod(0o440)
                BUNDLE.restore_bundle(archive, detached, system)
                self.assertEqual(secret_path.read_bytes(), secret)

                secret_path.unlink()
                with self.assertRaisesRegex(BUNDLE.BundleError, "credential presence"):
                    BUNDLE.build_bundle(system)
            finally:
                BUNDLE.ARTIFACTS = original_artifacts
                BUNDLE.OPTIONAL_ARTIFACTS = original_optional
                BUNDLE.PROVIDER_CREDENTIAL_UID = original_uid
                BUNDLE.PROVIDER_CREDENTIAL_GID = original_gid
                BUNDLE.PROVIDER_ADAPTER_UID = original_adapter_uid
                BUNDLE.PROVIDER_ADAPTER_GID = original_adapter_gid

    def test_rollback_bundle_preserves_live_pki_and_transaction_phases_are_crash_safe(self) -> None:
        self.assertNotIn(
            "etc/vivolution/carrier-gateway/pki/carrier.fullchain.pem",
            BUNDLE.ARTIFACTS,
        )
        self.assertNotIn(
            "etc/vivolution/carrier-gateway/pki/carrier.key",
            BUNDLE.ARTIFACTS,
        )
        self.assertIn("etc/vivolution/carrier-gateway/pki", BUNDLE.EXCLUDED_STATE)
        boundaries = (
            "transaction-transition-after-next-fsync",
            "transaction-transition-after-replace",
            "transaction-transition-after-parent-fsync",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                journal = root / "transaction.json"
                BUNDLE.begin_transaction(journal, "previous-config")

                def crash(name: str) -> None:
                    if name == boundary:
                        raise RuntimeError(name)

                with self.assertRaisesRegex(RuntimeError, boundary):
                    BUNDLE.transition_transaction(
                        journal,
                        "PREPARING_PRE_ROLLBACK_LKG",
                        "PRE_ROLLBACK_LKG_PROTECTED",
                        fault_hook=crash,
                    )
                phase = BUNDLE.read_transaction(journal)["phase"]
                expected = (
                    "PREPARING_PRE_ROLLBACK_LKG"
                    if boundary == "transaction-transition-after-next-fsync"
                    else "PRE_ROLLBACK_LKG_PROTECTED"
                )
                self.assertEqual(phase, expected)

    def test_transaction_commit_precedes_cleanup_and_finalize_unlinks_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            journal = root / "transaction.json"
            BUNDLE.begin_transaction(journal, "previous-config")
            BUNDLE.transition_transaction(
                journal,
                "PREPARING_PRE_ROLLBACK_LKG",
                "PRE_ROLLBACK_LKG_PROTECTED",
            )
            BUNDLE.transition_transaction(
                journal,
                "PRE_ROLLBACK_LKG_PROTECTED",
                "RESTORE_STARTED",
            )
            BUNDLE.transition_transaction(journal, "RESTORE_STARTED", "TARGET_RESTORED")
            BUNDLE.transition_transaction(journal, "TARGET_RESTORED", "TARGET_ACCEPTED")

            BUNDLE.commit_transaction(journal, "TARGET_ACCEPTED")
            self.assertEqual(BUNDLE.read_transaction(journal)["phase"], "TARGET_COMMITTED")

            def crash(name: str) -> None:
                if name == "transaction-finalize-after-journal-unlink":
                    raise RuntimeError(name)

            with self.assertRaisesRegex(RuntimeError, "after-journal-unlink"):
                BUNDLE.finalize_transaction(journal, "TARGET_COMMITTED", fault_hook=crash)
            self.assertFalse(journal.exists())

    def test_rollback_never_archives_authority_and_recovers_from_journal(self) -> None:
        helper = source("roles/carrier_gateway/files/bin/carrier_rollback_bundle.py")
        rollback = source("roles/carrier_gateway_rollback/tasks/main.yml")
        self.assertIn("excludedMutableState", helper)
        self.assertNotIn('"var/lib/vivolution/carrier-gateway/authorization/pending"', helper)
        self.assertIn("transaction.json", rollback)
        self.assertIn("Recover an interrupted rollback deterministically", rollback)
        self.assertIn("pre-rollback-lkg.tar", rollback)
        self.assertIn("Reconcile and burn billable-call authority before any rollback action", rollback)
        self.assertIn("PREPARING_PRE_ROLLBACK_LKG", rollback)
        self.assertIn("Durably commit accepted target before cleanup", rollback)
        self.assertIn("Finalize accepted rollback after residue and certificate-gate cleanup", rollback)
        self.assertIn("Prove restored broker executable PID and version", rollback)
        self.assertIn("vivolution-carrier-certificate.timer", rollback)
        self.assertIn("/var/lib/vivolution-carrier-certificate/rotation/transaction.json", rollback)
        self.assertIn(BUNDLE.PROVIDER_CREDENTIAL, BUNDLE.OPTIONAL_ARTIFACTS)
        self.assertNotIn("etc/vivolution/carrier-gateway/secrets", BUNDLE.EXCLUDED_STATE)
        self.assertIn("quiesce-provider-egress.yml", rollback)
        self.assertIn("restart-provider-egress.yml", rollback)
        provider_restart = source(
            "roles/carrier_gateway_rollback/tasks/restart-provider-egress.yml"
        )
        self.assertIn("pjsip show transport provider-egress-tls", provider_restart)
        self.assertIn("stat.uid | int == 0", provider_restart)
        self.assertIn("stat.gid | int == 10004", provider_restart)
        self.assertIn("stat.mode == '0440'", provider_restart)

    def test_teardown_is_strict_and_has_external_gates_and_residue_proofs(self) -> None:
        teardown = source("roles/carrier_gateway_teardown/tasks/main.yml")
        defaults = source("roles/carrier_gateway_teardown/defaults/main.yml")
        self.assertNotIn("failed_when: false", teardown)
        self.assertIn("PUBLIC_CARRIER_DNS_AND_ACME_DELEGATION_REMOVED", teardown)
        self.assertIn("AZURE_CP1_CARRIER_NSG_OVERLAY_REMOVED", teardown)
        self.assertIn("PRESERVE_SHARED_CARRIER_GATEWAY_HOST_PACKAGES", teardown)
        self.assertIn("authorization-legacy-untrusted", teardown)
        self.assertIn("Prove broker, authority, rollback, config, and socket absence", teardown)
        self.assertIn("carrier_gateway_remove_runtime_identity", defaults)
        self.assertIn("/etc/subuid", teardown)
        self.assertIn("/etc/subgid", teardown)


if __name__ == "__main__":
    unittest.main()
