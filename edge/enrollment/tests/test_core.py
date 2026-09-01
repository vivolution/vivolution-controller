from __future__ import annotations

import base64
import io
import os
import stat
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from edge.enrollment.core import (
    SIGNED_REQUEST_PREFIX,
    STATE_API_VERSION,
    EnrollmentError,
    EnrollmentMetadata,
    Identity,
    ProtectedState,
    StateSecurityError,
    _path_is_tmpfs,
    canonical_json_bytes,
    consume_root_token_file,
    normalize_controller_url,
    read_token_stream,
)
from edge.schema import manifest_tool


class MetadataTests(unittest.TestCase):
    def test_canonical_metadata(self) -> None:
        metadata = EnrollmentMetadata(
            node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            cluster_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            slot="A",
            generation=2,
            release_digest="sha256:" + "1" * 64,
        )
        self.assertEqual(metadata.as_dict()["slot"], "A")

    def test_rejects_noncanonical_or_invalid_metadata(self) -> None:
        good = {
            "node_id": str(uuid.uuid4()),
            "cluster_id": str(uuid.uuid4()),
            "slot": "A",
            "generation": 1,
            "release_digest": "sha256:" + "1" * 64,
        }
        for field, value in (
            ("node_id", good["node_id"].upper()),
            ("cluster_id", "not-a-uuid"),
            ("slot", "C"),
            ("generation", 0),
            ("release_digest", "edge-0.1.0"),
        ):
            invalid = dict(good)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(EnrollmentError):
                EnrollmentMetadata(**invalid)


class ControllerUrlTests(unittest.TestCase):
    def test_normalizes_domain_origin(self) -> None:
        for supplied, expected in (
            (
                " https://Controller.Voice.Vivolution.AE/ ",
                "https://controller.voice.vivolution.ae",
            ),
            (
                " https://Probe.CloudPremises.com/ ",
                "https://probe.cloudpremises.com",
            ),
            ("https://cp.cloudved.com", "https://cp.cloudved.com"),
        ):
            with self.subTest(supplied=supplied):
                self.assertEqual(normalize_controller_url(supplied), expected)

    def test_rejects_non_https_credentials_query_fragment_and_traversal(self) -> None:
        for candidate in (
            "http://controller.example.com",
            "https://user:secret@controller.example.com",
            "https://controller.example.com/?x=1",
            "https://controller.example.com/#fragment",
            "https://controller.example.com/a/../b",
            "https://127.0.0.1",
            "https://controller",
            "https://controller.example.com:8443",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(EnrollmentError):
                normalize_controller_url(candidate)


class CanonicalJsonTests(unittest.TestCase):
    def test_is_copy_locked_to_existing_edge_canonicalizer(self) -> None:
        vectors = (
            {},
            {"z": [None, True, -7], "a": "voice-✓"},
            {"nested": {"b": "two", "a": "one"}, "sequence": 7},
        )
        for vector in vectors:
            with self.subTest(vector=vector):
                self.assertEqual(
                    canonical_json_bytes(vector),
                    manifest_tool.canonical_json_bytes(vector),
                )
                self.assertFalse(canonical_json_bytes(vector).endswith(b"\n"))

    def test_rejects_floats_large_integers_non_ascii_keys_and_unknown_types(self) -> None:
        for vector in (
            {"value": 1.0},
            {"value": 1 << 53},
            {"é": "non-ascii-key"},
            {"value": object()},
        ):
            with self.subTest(vector=repr(vector)), self.assertRaises(EnrollmentError):
                canonical_json_bytes(vector)


class TokenInputTests(unittest.TestCase):
    @staticmethod
    def grant() -> str:
        secret = base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode("ascii")
        return "v1.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa." + secret

    def test_reads_exactly_one_bounded_visible_ascii_token(self) -> None:
        token = self.grant()
        self.assertEqual(read_token_stream(io.BytesIO((token + "\n").encode())), token)

    def test_rejects_short_control_unicode_or_oversized_token(self) -> None:
        for candidate in (
            b"short\n",
            b"v1." + b"a" * 80,
            b"x" * 16 + b"\xff",
            b"a" * 4097,
        ):
            with self.subTest(size=len(candidate)), self.assertRaises(EnrollmentError):
                read_token_stream(io.BytesIO(candidate))

    def test_non_root_owned_file_is_rejected_and_not_deleted(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("test requires an ordinary account")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "grant"
            path.write_text(self.grant(), encoding="ascii")
            path.chmod(0o600)
            with self.assertRaises(StateSecurityError):
                consume_root_token_file(path)
            self.assertTrue(path.exists())

    @unittest.skipUnless(os.geteuid() == 0, "root ownership is required")
    def test_root_file_is_consumed_and_erased(self) -> None:
        if not Path("/run").is_dir():
            self.skipTest("Linux /run tmpfs is required")
        probe = Path("/run")
        if not _path_is_tmpfs(probe):
            self.skipTest("/run is not tmpfs in this environment")
        with tempfile.TemporaryDirectory(dir="/run") as temporary:
            path = Path(temporary) / "grant"
            path.write_text(self.grant() + "\n", encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(consume_root_token_file(path), self.grant())
            self.assertFalse(path.exists())


class IdentityTests(unittest.TestCase):
    def test_identity_is_ed25519_and_signature_verifies(self) -> None:
        identity = Identity.generate()
        self.assertEqual(len(identity.public_key_base64url), 43)
        self.assertRegex(identity.fingerprint, r"\Asha256:[0-9a-f]{64}\Z")
        payload = {"challenge_id": "challenge-1", "nonce": "n" * 32}
        signed_bytes = SIGNED_REQUEST_PREFIX + canonical_json_bytes(payload)
        signature = base64.urlsafe_b64decode(identity.sign_bytes(signed_bytes) + "==")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.from_private_bytes(identity.private_seed)
        key.public_key().verify(
            signature,
            signed_bytes,
        )

    def test_reloading_identity_preserves_fingerprint(self) -> None:
        original = Identity.generate()
        restored = Identity.from_seed(original.private_seed)
        self.assertEqual(restored.fingerprint, original.fingerprint)
        self.assertEqual(restored.public_key_base64url, original.public_key_base64url)


class ProtectedStateTests(unittest.TestCase):
    def test_identity_and_state_are_atomic_protected_and_token_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ProtectedState(
                Path(temporary) / "enrollment", expected_uid=os.geteuid()
            )
            identity, created = store.load_or_create_identity()
            self.assertTrue(created)
            restored, created_again = store.load_or_create_identity()
            self.assertFalse(created_again)
            self.assertEqual(identity.fingerprint, restored.fingerprint)
            state = {
                "api_version": STATE_API_VERSION,
                "controller_url": "https://controller.example.com",
                "public_key_fingerprint": identity.fingerprint,
                "status": "LOCAL_IDENTITY_READY",
            }
            store.write_state(state)
            self.assertEqual(store.read_state(), state)
            for name in (store.IDENTITY_NAME, store.STATE_NAME):
                record = (store.directory / name).lstat()
                self.assertTrue(stat.S_ISREG(record.st_mode))
                self.assertEqual(stat.S_IMODE(record.st_mode), 0o600)
                self.assertEqual(record.st_nlink, 1)
            serialized = (store.directory / store.STATE_NAME).read_text()
            self.assertNotIn("grant", serialized.lower())
            self.assertNotIn("token", serialized.lower())

    def test_refuses_to_persist_one_time_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ProtectedState(
                Path(temporary) / "enrollment", expected_uid=os.geteuid()
            )
            with self.assertRaises(EnrollmentError):
                store.write_state(
                    {
                        "api_version": STATE_API_VERSION,
                        "enrollment_token": "must-not-persist",
                    }
                )
            with self.assertRaises(EnrollmentError):
                store.write_state(
                    {
                        "api_version": STATE_API_VERSION,
                        "nested": {"innocent_name": TokenInputTests.grant()},
                    }
                )

    def test_rejects_permissive_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "enrollment"
            path.mkdir(mode=0o755)
            path.chmod(0o755)
            with self.assertRaises(StateSecurityError):
                ProtectedState(path, expected_uid=os.geteuid())

    def test_duplicate_state_member_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ProtectedState(
                Path(temporary) / "enrollment", expected_uid=os.geteuid()
            )
            path = store.directory / store.STATE_NAME
            path.write_text(
                '{"api_version":"%s","status":"A","status":"B"}\n'
                % STATE_API_VERSION,
                encoding="ascii",
            )
            path.chmod(0o600)
            with self.assertRaises(EnrollmentError):
                store.read_state()

    def test_concurrent_identity_creation_has_one_winner_and_one_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "enrollment"
            barrier = threading.Barrier(8)
            results: list[tuple[str, bool]] = []
            errors: list[BaseException] = []

            def create() -> None:
                try:
                    store = ProtectedState(directory, expected_uid=os.geteuid())
                    barrier.wait()
                    identity, created = store.load_or_create_identity()
                    results.append((identity.fingerprint, created))
                except BaseException as exc:  # pragma: no cover - test collector
                    errors.append(exc)

            threads = [threading.Thread(target=create) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(errors)
            self.assertEqual(len(results), 8)
            self.assertEqual(len({fingerprint for fingerprint, _ in results}), 1)
            self.assertEqual(sum(1 for _, created in results if created), 1)


if __name__ == "__main__":
    unittest.main()
