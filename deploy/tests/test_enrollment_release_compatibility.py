import ast
import importlib.util
import re
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def controller_supported_digest():
    source = (
        REPOSITORY_ROOT / "controller" / "cp1" / "edge_release.py"
    ).read_text(encoding="utf-8")
    module = ast.parse(source)
    for statement in module.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name)
            and target.id == "SUPPORTED_EDGE_ENROLLMENT_RELEASE_DIGEST"
            for target in statement.targets
        ):
            continue
        value = ast.literal_eval(statement.value)
        if isinstance(value, str):
            return value
    raise AssertionError("Controller supported Edge digest is missing")


def deployment_pinned_digest():
    defaults = (
        REPOSITORY_ROOT
        / "deploy"
        / "roles"
        / "edge_enrollment_install"
        / "defaults"
        / "main.yml"
    ).read_text(encoding="utf-8")
    matches = re.findall(
        r"^edge_enrollment_release_digest: (sha256:[0-9a-f]{64})$",
        defaults,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise AssertionError("Deployment must pin exactly one Edge enrollment digest")
    return matches[0]


def calculated_source_digest():
    module_path = REPOSITORY_ROOT / "edge" / "enrollment" / "release.py"
    spec = importlib.util.spec_from_file_location("edge_enrollment_release", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.calculate_release_digest(module_path.parent)


class EnrollmentReleaseCompatibilityTests(unittest.TestCase):
    def test_controller_edge_and_source_digests_are_identical(self):
        controller = controller_supported_digest()
        deployment = deployment_pinned_digest()
        calculated = calculated_source_digest()
        self.assertRegex(controller, EXPECTED_DIGEST_RE)
        self.assertEqual(controller, deployment)
        self.assertEqual(controller, calculated)

    def test_both_controller_ingresses_bound_content_length_and_chunked_bodies(self):
        templates = (
            REPOSITORY_ROOT / "deploy" / "roles" / "ingress" / "templates" / "Caddyfile.j2",
            REPOSITORY_ROOT
            / "installer"
            / "ansible"
            / "roles"
            / "ubuntu_ingress"
            / "templates"
            / "Caddyfile.j2",
        )
        for template in templates:
            with self.subTest(template=template):
                content = template.read_text(encoding="utf-8")
                self.assertIn("@edge_api path /api/edge/*", content)
                self.assertIn("request_body @edge_api", content)
                self.assertIn("max_size 16384B", content)


if __name__ == "__main__":
    unittest.main()
