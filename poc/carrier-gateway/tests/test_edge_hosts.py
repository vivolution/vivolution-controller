from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "roles/carrier_gateway/files/bin/verify_edge_hosts.py"
SPEC = importlib.util.spec_from_file_location("verify_edge_hosts", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EdgeHostAuthorityTests(unittest.TestCase):
    def test_pre_post_and_absent_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "hosts"
            path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            MODULE.validate(path, "pre")
            MODULE.validate(path, "absent")
            path.write_text(
                "127.0.0.1 localhost\n"
                "# BEGIN VIVOLUTION CARRIER GATEWAY PRIVATE EDGE DNS\n"
                "10.20.2.6 sbc1.vivolution.ae\n"
                "10.20.2.7 sbc2.vivolution.ae\n"
                "# END VIVOLUTION CARRIER GATEWAY PRIVATE EDGE DNS\n",
                encoding="utf-8",
            )
            MODULE.validate(path, "pre")
            MODULE.validate(path, "post")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate(path, "absent")

    def test_rejects_conflict_duplicate_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "hosts"
            path.write_text("10.20.2.9 sbc1.vivolution.ae\n", encoding="utf-8")
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate(path, "pre")
            path.write_text(
                "10.20.2.6 sbc1.vivolution.ae\n10.20.2.6 sbc1.vivolution.ae\n",
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate(path, "post")
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaises(MODULE.ContractError):
                MODULE.validate(link, "pre")


if __name__ == "__main__":
    unittest.main()
