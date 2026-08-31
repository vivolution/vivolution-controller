from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest


DEPLOY = Path(__file__).resolve().parents[1]


class EdgeRuntimeInstallStaticTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (DEPLOY / relative_path).read_text(encoding="utf-8")

    def evaluate_activation_reconciliation_selection(
        self, variables: dict[str, object]
    ) -> dict[str, object]:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        first_line = Path(executable).read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first_line.startswith("#!"))
        ansible_python = first_line[2:]
        script = r"""
import json
import sys

import yaml
from jinja2.nativetypes import NativeEnvironment

playbook = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
variables = json.loads(sys.argv[2])
tasks = playbook[0]["tasks"]
selection = next(
    item
    for item in tasks
    if item.get("name") == "Select only the Agent reconciliation command that executed"
)
guard = next(
    item
    for item in tasks
    if item.get("name")
    == "Require one exact successful Agent reconciliation command before parsing"
)
environment = NativeEnvironment(autoescape=False)
environment.filters["bool"] = bool
selected = environment.from_string(
    selection["ansible.builtin.set_fact"]["edge_agent_reconcile"]
).render(**variables)
variables["edge_agent_reconcile"] = selected
assertions = [
    bool(environment.compile_expression(expression)(**variables))
    for expression in guard["ansible.builtin.assert"]["that"]
]
print(
    json.dumps(
        {"assertions": assertions, "selected": selected},
        separators=(",", ":"),
        sort_keys=True,
    )
)
"""
        completed = subprocess.run(
            [
                ansible_python,
                "-c",
                script,
                str(DEPLOY / "playbooks/activate-edge.yml"),
                json.dumps(variables, separators=(",", ":")),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"{completed.stdout}\n{completed.stderr}",
        )
        return json.loads(completed.stdout)

    def test_install_playbook_adds_runtime_after_native_data_plane(self) -> None:
        playbook = self.read("playbooks/install-edge.yml")
        self.assertIn("role: edge_runtime_install", playbook)
        self.assertLess(
            playbook.index("role: edge_rtpengine"),
            playbook.index("role: edge_runtime_install"),
        )
        self.assertLess(
            playbook.index("role: edge_runtime_install"),
            playbook.index("role: edge_verify"),
        )

    def test_install_refuses_to_overwrite_an_active_runtime_candidate(self) -> None:
        playbook = self.read("playbooks/install-edge.yml")
        preflight = playbook.index(
            "Inspect protected runtime state before any bootstrap role can mutate live paths"
        )
        first_role = playbook.index("  roles:")
        self.assertLess(preflight, first_role)
        self.assertIn("highestSeenSequence | int == 0", playbook)
        self.assertIn("active.kind == 'BOOTSTRAP'", playbook)
        self.assertIn("transaction.json", playbook)
        self.assertIn("edge-state-v3.json", playbook)
        self.assertIn("edge-state-v2.json", playbook)
        self.assertIn("accepted-state-v1.json", playbook)
        self.assertIn("cannot overwrite protected Agent v3 state", playbook)
        self.assertIn("silently\n          migrate legacy v1/v2 state", playbook)
        self.assertIn(
            "install-edge cannot rerender bootstrap live paths after a signed",
            playbook,
        )
        self.assertIn("Reject runtime-managed live symlinks without protected state", playbook)

    def test_only_reviewed_python_packages_are_installed_immutable(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        expected = {
            "edge/schema/manifest_tool.py",
            "edge/schema/edge-desired-state-v0.1.schema.json",
            "edge/agent/__init__.py",
            "edge/agent/__main__.py",
            "edge/agent/cli.py",
            "edge/agent/security_core.py",
            "edge/compiler/__init__.py",
            "edge/compiler/__main__.py",
            "edge/compiler/core.py",
            "edge/runtime/__init__.py",
            "edge/runtime/__main__.py",
            "edge/runtime/cli.py",
            "edge/runtime/contracts.py",
            "edge/runtime/core.py",
        }
        installed = {
            line.split("src: ", 1)[1].split(",", 1)[0]
            for line in tasks.splitlines()
            if line.strip().startswith("- { src: edge/")
        }
        self.assertEqual(installed, expected)
        self.assertNotIn("edge/controlplane", tasks)
        self.assertNotIn("/tests/", tasks)
        self.assertNotIn("__pycache__", tasks)
        self.assertIn("/usr/lib/vivolution-edge/python", tasks)
        self.assertIn("mode: '0555'", tasks)
        self.assertIn("mode: '0444'", tasks)

    def test_synthetic_install_and_activation_accept_positive_replacement_generations(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        activation = self.read("playbooks/activate-edge.yml")
        for source in (tasks, activation):
            self.assertIn("edge_generation | int >= 1", source)
            self.assertNotIn("edge_generation | int == 1", source)
        self.assertIn("fixed CP1 fixture identity", tasks)
        self.assertIn("edge_pbx_source_ipv4_cidrs == ['10.20.1.4/32']", activation)

    def test_wrappers_clear_environment_and_root_helper_has_no_path_input(self) -> None:
        agent = self.read("roles/edge_runtime_install/templates/vivolution-edge-agent.j2")
        compiler = self.read("roles/edge_runtime_install/templates/vivolution-edge-compiler.j2")
        runtime = self.read("roles/edge_runtime_install/templates/vivolution-edge-runtime.j2")
        for wrapper in (agent, compiler, runtime):
            self.assertIn("/usr/bin/env -i", wrapper)
            self.assertIn("/usr/bin/python3 -I -B", wrapper)
            self.assertIn("/usr/lib/vivolution-edge/python", wrapper)
            self.assertNotIn("PYTHONPATH", wrapper)
        self.assertIn("activate|rollback", runtime)
        self.assertIn("recover|status", runtime)
        self.assertIn("[ \"$#\" -eq 5 ]", runtime)
        self.assertIn("[ \"$#\" -eq 1 ]", runtime)
        self.assertIn("edge_digest_length=$(/usr/bin/printf", runtime)
        self.assertIn("/usr/bin/wc -c", runtime)
        self.assertNotIn("${#", runtime)
        self.assertNotIn("eval ", runtime)
        self.assertNotIn("$6", runtime)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as wrapper:
            wrapper.write(runtime)
            wrapper.flush()
            syntax = subprocess.run(
                ["/bin/sh", "-n", wrapper.name],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            for digest in ("sha256:" + "a" * 63, "sha256:" + "a" * 65):
                rejected = subprocess.run(
                    [
                        "/bin/sh",
                        wrapper.name,
                        "activate",
                        "--sequence",
                        "1",
                        "--manifest-digest",
                        digest,
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(rejected.returncode, 64)

    def test_unprivileged_agent_state_and_fixed_root_directories(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        verify = self.read("roles/edge_verify/tasks/main.yml")
        activation = self.read("playbooks/activate-edge.yml")
        self.assertIn("name: vivolution-edge-agent", tasks)
        self.assertIn("shell: /usr/sbin/nologin", tasks)
        self.assertIn("Allow traversal only to independently protected Edge state leaves", tasks)
        self.assertIn("path: /var/lib/vivolution-edge\n    state: directory", tasks)
        self.assertIn("mode: '0751'", tasks)
        self.assertIn(
            "Grant only the Agent read-traverse access for secure path walking",
            tasks,
        )
        self.assertIn("entity: vivolution-edge-agent", tasks)
        self.assertIn("permissions: rx", tasks)
        self.assertIn("state: query", tasks)
        self.assertIn("user:vivolution-edge-agent:r-x", tasks)
        for path in (
            "/var/lib/vivolution-edge/agent-home",
            "/var/lib/vivolution-edge/agent-home/.ansible",
            "/var/lib/vivolution-edge/agent-home/.ansible/tmp",
        ):
            self.assertIn(f"path: {path}", tasks)
            self.assertIn(path, verify)
        for path in (
            "/var/lib/vivolution-edge/agent-home",
            "/var/lib/vivolution-edge/agent-home/.ansible",
        ):
            self.assertIn(
                f"- path: {path}\n"
                "      owner: root\n"
                "      group: vivolution-edge-agent\n"
                "      mode: '0710'",
                tasks,
            )
        self.assertIn(
            "- path: /var/lib/vivolution-edge/agent-home/.ansible/tmp\n"
            "      owner: vivolution-edge-agent\n"
            "      group: vivolution-edge-agent\n"
            "      mode: '0700'",
            tasks,
        )
        self.assertIn(
            "Require private Agent-owned execution paths for privilege dropping",
            verify,
        )
        self.assertIn("follow: false", tasks)
        self.assertIn("item.stat.pw_name ==", verify)
        self.assertIn("item.item.endswith('/tmp')", verify)
        self.assertIn("item.stat.gr_name == 'vivolution-edge-agent'", verify)
        self.assertIn("item.stat.mode == ('0700'", verify)
        self.assertIn("getent\n      - passwd\n      - vivolution-edge-agent", verify)
        self.assertIn("'/var/lib/vivolution-edge/agent-home'", verify)
        self.assertIn("'/usr/sbin/nologin'", verify)
        self.assertIn("edge_verify_agent_primary_group.stdout", verify)
        self.assertIn("Inspect the ACL package required for secure privilege dropping", verify)
        self.assertIn("path: /usr/bin/setfacl", verify)
        self.assertIn("edge_verify_acl_package.stdout | trim == 'installed|amd64'", verify)
        self.assertIn("edge_verify_setfacl.stat.mode == '0755'", verify)
        self.assertIn("/var/lib/vivolution-edge/agent-state/tenant", tasks)
        self.assertIn("owner: vivolution-edge-agent", tasks)
        self.assertIn("/var/lib/vivolution-edge/runtime-inbox", tasks)
        self.assertIn("/var/lib/vivolution-edge/runtime/evidence", tasks)
        self.assertIn("/var/lib/vivolution-edge/activation-evidence", tasks)
        self.assertIn("group: vivolution-edge-agent\n      mode: '0750'", tasks)
        self.assertGreaterEqual(tasks.count("mode: '0700'"), 3)
        self.assertIn("Inspect the shared Edge state traversal root", verify)
        self.assertIn("edge_verify_state_traversal_root.stat.mode == '0751'", verify)
        self.assertIn("edge_verify_state_traversal_acl.acl | sort", verify)
        self.assertIn("user:vivolution-edge-agent:r-x", verify)
        self.assertIn(
            "Inspect the shared Edge state traversal root before creating candidate paths",
            activation,
        )
        self.assertIn(
            "edge_activation_state_traversal_root.stat.mode == '0751'",
            activation,
        )
        self.assertIn("edge_activation_state_traversal_acl.acl | sort", activation)
        self.assertIn("user:vivolution-edge-agent:r-x", activation)
        self.assertLess(
            activation.index("Inspect the shared Edge state traversal root before creating candidate paths"),
            activation.index("Create the isolated unprivileged candidate workspace"),
        )

    def test_node_facts_and_runtime_authority_are_exact_and_separate(self) -> None:
        facts = self.read("roles/edge_runtime_install/templates/node-facts.json.j2")
        authority = self.read(
            "roles/edge_runtime_install/templates/runtime-authority.json.j2"
        )
        self.assertIn('"syntheticTeamsSourceIpv4Cidrs": []', facts)
        self.assertIn('"teamsSignalingSourceIpv4Cidrs"', facts)
        self.assertIn('"teamsMediaSourceIpv4Cidrs"', facts)
        self.assertIn('"tenantListenerPort": 15061', facts)
        self.assertIn('"clusterMediaPortEnd": 29999', facts)
        self.assertIn('"apiVersion": "edge.vivolution.ae/runtime-authority/v0.1"', authority)
        self.assertIn('"profile": {{ edge_runtime_profile | to_json }}', authority)
        self.assertNotIn("syntheticTeamsSourceIpv4Cidrs", authority)
        self.assertEqual(authority.count('"sha256:'), 0)

    def test_profile_selected_tls_files_are_remote_hashed_and_pinned(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        authority = self.read(
            "roles/edge_runtime_install/templates/runtime-authority.json.j2"
        )
        names = (
            "edgeCertificateChainPem",
            "edgePrivateKeyPem",
            "fixtureCaCrt",
            "fixtureClientCrt",
            "fixtureClientKey",
            "microsoftCaBundlePem",
            "pbxCaBundlePem",
            "publicCaBundlePem",
        )
        for name in names:
            self.assertIn(f"name: {name}", tasks)
        self.assertIn(
            '"secretDigests": {{ edge_runtime_secret_digests | to_json }}',
            authority,
        )
        self.assertIn("edge_runtime_common_tls_inventory", tasks)
        self.assertIn("edge_runtime_synthetic_tls_inventory", tasks)
        self.assertIn("edge_runtime_profile == 'SYNTHETIC_PRIVATE' else []", tasks)
        self.assertIn("edge_direct_pbx_ca_bundle_sha256", tasks)
        self.assertIn("DIRECT_ROUTING", tasks)
        self.assertIn("checksum_algorithm: sha256", tasks)
        self.assertIn("'sha256:' ~ item.stat.checksum", tasks)
        self.assertIn("group: opensips", tasks)
        self.assertIn("mode: '0440'", tasks)
        self.assertIn("validate_secret_material", tasks)
        self.assertIn("item.stat.checksum == item.item.sha256", tasks)

    def test_microsoft_bundle_is_exactly_extracted_not_a_general_ca_copy(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        builder = self.read(
            "roles/edge_runtime_install/files/build_microsoft_sip_bundle.py"
        )
        expected = (
            "17F3DE5E9F0F19E98EF61F32266E20C407AE30EE",
            "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",
            "7E04DE896A3E666D00E687D33FFAD93BE83D349E",
            "999A64C37FF47D9FAB95F14769891460EEC4C3C5",
            "A78849DC5D7C758C8CDE399856B3AAD0B2A57135",
            "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",
            "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
        )
        general_copy = tasks[
            tasks.index("Provision public certificate trust from the Debian trust store") :
            tasks.index("Extract the exact seven reviewed Microsoft SIP roots")
        ]
        self.assertNotIn("microsoft-ca-bundle.pem", general_copy)
        self.assertIn("MICROSOFT_SIP_ROOT_SHA1", builder)
        self.assertIn("x509.load_pem_x509_certificates", builder)
        self.assertIn("certificate.fingerprint(hashes.SHA1())", builder)
        self.assertIn("os.O_NOFOLLOW", builder)
        self.assertIn("os.replace(temporary, DESTINATION)", builder)
        self.assertIn('"changed": changed', builder)
        compile(builder, "build_microsoft_sip_bundle.py", "exec")
        self.assertIn("rootCount | int == 7", tasks)
        for thumbprint in expected:
            self.assertEqual(tasks.count(thumbprint), 1)

    def test_certificate_rotation_is_locked_transactional_and_authority_aware(self) -> None:
        tasks = self.read("roles/edge_certificate/tasks/main.yml")
        renew = self.read(
            "roles/edge_certificate/templates/renew-edge-certificate.sh.j2"
        )
        rotate = self.read(
            "roles/edge_certificate/templates/rotate-edge-certificate.py.j2"
        )
        wrapper = self.read(
            "roles/edge_certificate/templates/vivolution-edge-certificate-rotate.j2"
        )
        service = self.read(
            "roles/edge_certificate/templates/vivolution-edge-certificate.service.j2"
        )
        self.assertIn("rotate-edge-certificate.py", tasks)
        self.assertIn(
            "Hold certificate scheduling until protected runtime authority is installed",
            tasks,
        )
        hold = tasks.index(
            "Hold certificate scheduling until protected runtime authority is installed"
        )
        inspect = tasks.index(
            "Inspect protected runtime authority before certificate installation"
        )
        stop_bootstrap = tasks.index(
            "Stop OpenSIPS before bootstrap authority reconciliation"
        )
        authority_resume = tasks.index(
            "Require protected runtime state to have authority and allow exact authority-first resume"
        )
        issue = tasks.index("Obtain or renew the publicly trusted Edge certificate")
        self.assertLess(hold, issue)
        self.assertLess(hold, inspect)
        self.assertLess(inspect, stop_bootstrap)
        self.assertLess(stop_bootstrap, authority_resume)
        self.assertLess(authority_resume, issue)
        self.assertLess(stop_bootstrap, issue)
        self.assertIn("enabled: false", tasks[hold:issue])
        self.assertIn(
            "/var/lib/vivolution-edge/runtime/runtime-authority.json",
            tasks[inspect:issue],
        )
        self.assertIn(
            "/etc/vivolution-edge/runtime-authority.json",
            tasks[inspect:issue],
        )
        self.assertIn("forbidden legacy authority path", tasks[inspect:issue])
        self.assertIn("authority-first bootstrap interruption is resumable", tasks[inspect:issue])
        self.assertIn("state: stopped", tasks[stop_bootstrap:issue])
        self.assertIn("rotation_root=/var/lib/vivolution-edge/certificate-rotation", renew)
        self.assertIn('incoming_root="$rotation_root/incoming"', renew)
        self.assertIn("validate-edge-certificate", renew)
        self.assertIn("verify-acme-cleanup", renew)
        self.assertIn('/bin/cat "$certificate_source" >"$certificate_tmp"', renew)
        self.assertNotIn('/bin/cat "$issuer_source"', renew)
        self.assertIn("rotate-edge-certificate", renew)
        self.assertNotIn("/etc/vivolution-edge/tls/teams-fullchain.pem", renew)
        self.assertIn("[ \"$#\" -eq 0 ]", wrapper)
        self.assertIn("/usr/bin/env -i", wrapper)
        self.assertIn("fcntl.flock(lock_descriptor, fcntl.LOCK_EX)", rotate)
        for phase in (
            '"PREPARED"',
            '"SERVICE_STOPPED"',
            '"PAIR_INSTALLED"',
            '"AUTHORITY_RECONCILED"',
            '"HEALTHY"',
        ):
            self.assertIn(phase, rotate)
        self.assertIn("validate_secret_material(facts, reconciled, secret_bytes)", rotate)
        self.assertIn(
            'rotating_names = {"edgeCertificateChainPem", "edgePrivateKeyPem"}',
            rotate,
        )
        self.assertIn("drifted_non_certificate_names", rotate)
        self.assertIn("paths.as_mapping(authority.profile)", rotate)
        self.assertIn("_atomic_write(AUTHORITY, new_raw, mode=0o600, gid=0)", rotate)
        self.assertIn("_restore_previous(journal, opensips_gid)", rotate)
        self.assertIn(
            'raise RotationError("active OpenSIPS lacks protected runtime authority")',
            rotate,
        )
        self.assertLess(
            rotate.index('raise RotationError("active OpenSIPS lacks protected runtime authority")'),
            rotate.index('"status": "CERTIFICATE_UNCHANGED"'),
        )
        self.assertIn(
            'raise RotationError("bootstrap recovery found unexpected protected runtime authority")',
            rotate,
        )
        self.assertNotIn("_unlink(AUTHORITY)", rotate)
        transaction_start = rotate.index(
            "        try:\n            if was_active:", rotate.index("def main()")
        )
        self.assertLess(
            rotate.index("_stop_service()", transaction_start),
            rotate.index("_atomic_write(LIVE_CERT", transaction_start),
        )
        self.assertIn("/var/lib/vivolution-edge/runtime", service)
        self.assertNotIn("/etc/vivolution-edge/runtime-authority.json", service)
        self.assertIn("/var/lib/vivolution-edge/runtime", service)
        self.assertIn('AUTHORITY = RUNTIME_ROOT / "runtime-authority.json"', rotate)
        self.assertIn(
            'LEGACY_AUTHORITY = Path("/etc/vivolution-edge/runtime-authority.json")',
            rotate,
        )
        self.assertIn(
            'raise RotationError("legacy runtime authority path is forbidden")',
            rotate,
        )
        self.assertIn(
            "(facts.node_id, facts.generation, facts.slot) != expected_identity",
            rotate,
        )
        self.assertIn(
            "(authority.node_id, authority.generation, authority.slot) != expected_identity",
            rotate,
        )
        self.assertIn("authority.profile != EXPECTED_PROFILE", rotate)

        runtime_tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        enable = runtime_tasks.index(
            "Enable certificate renewal only after protected authority initialization"
        )
        self.assertGreater(enable, runtime_tasks.index("Verify only the recovery unit is enabled"))
        self.assertIn("enabled: true", runtime_tasks[enable:])

    def test_rendered_certificate_rotation_core_is_valid_python(self) -> None:
        source = self.read(
            "roles/edge_certificate/templates/rotate-edge-certificate.py.j2"
        )
        rendered = source.replace(
            "{{ edge_acme_node_fqdn | to_json }}",
            json.dumps("sbc1.voice.vivolution.ae"),
        ).replace(
            "{{ edge_acme_wildcard_fqdn | to_json }}",
            json.dumps("*.sbc1.voice.vivolution.ae"),
        ).replace(
            "{{ inventory_hostname | to_json }}",
            json.dumps("sbc1"),
        ).replace(
            "{{ edge_generation | int }}",
            "1",
        ).replace(
            "{{ edge_slot | to_json }}",
            json.dumps("A"),
        ).replace(
            "{{ edge_runtime_profile | to_json }}",
            json.dumps("SYNTHETIC_PRIVATE"),
        )
        compile(rendered, "rotate-edge-certificate.py", "exec")

    def test_bootstrap_certificate_recovery_never_restarts_unbound_opensips(self) -> None:
        source = self.read(
            "roles/edge_certificate/templates/rotate-edge-certificate.py.j2"
        )
        rendered = source.replace(
            "{{ edge_acme_node_fqdn | to_json }}",
            json.dumps("sbc1.voice.vivolution.ae"),
        ).replace(
            "{{ edge_acme_wildcard_fqdn | to_json }}",
            json.dumps("*.sbc1.voice.vivolution.ae"),
        ).replace(
            "{{ inventory_hostname | to_json }}",
            json.dumps("sbc1"),
        ).replace(
            "{{ edge_generation | int }}",
            "1",
        ).replace(
            "{{ edge_slot | to_json }}",
            json.dumps("A"),
        ).replace(
            "{{ edge_runtime_profile | to_json }}",
            json.dumps("SYNTHETIC_PRIVATE"),
        )
        namespace = {"__name__": "certificate_rotation_test"}
        exec(compile(rendered, "rotate-edge-certificate.py", "exec"), namespace)

        unlinked = []
        restarted = []
        namespace["_service_active"] = lambda: False
        namespace["_exists_regular"] = lambda _path: False
        namespace["_unlink"] = unlinked.append
        namespace["_start_and_check_service"] = restarted.append
        namespace["_restore_previous"](
            {
                "hadAuthority": False,
                "hadPair": False,
                "phase": "AUTHORITY_RECONCILED",
                "wasActive": True,
            },
            123,
        )

        self.assertEqual(restarted, [])
        self.assertIn(namespace["JOURNAL"], unlinked)
        self.assertNotIn(namespace["AUTHORITY"], unlinked)

        namespace["_exists_regular"] = (
            lambda path: path == namespace["AUTHORITY"]
        )
        with self.assertRaisesRegex(
            namespace["RotationError"],
            "unexpected protected runtime authority",
        ):
            namespace["_restore_previous"](
                {
                    "hadAuthority": False,
                    "hadPair": False,
                    "phase": "AUTHORITY_RECONCILED",
                    "wasActive": False,
                },
                123,
            )

        stopped = []
        unlinked.clear()
        namespace["_exists_regular"] = lambda _path: False
        namespace["_service_active"] = lambda: True
        namespace["_stop_service"] = lambda: stopped.append(True)
        namespace["_restore_previous"](
            {
                "hadAuthority": False,
                "hadPair": True,
                "phase": "HEALTHY",
                "wasActive": True,
            },
            123,
        )
        self.assertEqual(stopped, [True])
        self.assertEqual(unlinked, [namespace["JOURNAL"]])

        stopped.clear()
        namespace["_exists_regular"] = (
            lambda path: path == namespace["AUTHORITY"]
        )
        with self.assertRaisesRegex(
            namespace["RotationError"],
            "unexpected protected runtime authority",
        ):
            namespace["_restore_previous"](
                {
                    "hadAuthority": False,
                    "hadPair": True,
                    "phase": "HEALTHY",
                    "wasActive": True,
                },
                123,
            )
        self.assertEqual(stopped, [True])

    def test_no_signing_private_material_is_installed(self) -> None:
        combined = "\n".join(
            self.read(path)
            for path in (
                "roles/edge_runtime_install/tasks/main.yml",
                "inventories/poc-edge-template/group_vars/all.yml",
                "inventories/poc-edge-template/hosts.yml",
                "playbooks/activate-edge.yml",
            )
        )
        self.assertIn("edge_signing_public_key_base64", combined)
        self.assertNotIn("signing_private", combined)
        self.assertNotIn("signing_seed", combined)
        self.assertNotIn("PRIVATE KEY-----", combined)
        self.assertNotIn("sudoers", combined)

    def test_boot_recovery_is_the_only_enabled_data_plane_entry(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        recover = self.read(
            "roles/edge_runtime_install/templates/vivolution-edge-runtime-recover.service.j2"
        )
        target = self.read(
            "roles/edge_runtime_install/templates/vivolution-edge-dataplane.target.j2"
        )
        dropin = self.read(
            "roles/edge_runtime_install/templates/20-vivolution-runtime-managed.conf.j2"
        )
        self.assertIn("vivolution-edge-runtime recover", recover)
        self.assertIn("Requires=nftables.service", recover)
        self.assertIn("ConditionPathExists=/var/lib/vivolution-edge/runtime/state.json", recover)
        self.assertIn("ExecStartPost=/usr/bin/systemctl --no-block start vivolution-edge-dataplane.target", recover)
        self.assertIn("Requires=rtpengine-daemon.service opensips.service", target)
        self.assertIn("PartOf=vivolution-edge-dataplane.target", dropin)
        self.assertIn("item == 'opensips'", dropin)
        self.assertIn("Requires=rtpengine-daemon.service", dropin)
        self.assertIn("After=rtpengine-daemon.service", dropin)
        self.assertIn("enabled: false", tasks)
        self.assertIn("name: vivolution-edge-runtime-recover.service", tasks)
        self.assertNotIn("After=vivolution-edge-runtime-recover.service", dropin)

        verify = self.read("roles/edge_verify/tasks/main.yml")
        self.assertIn("--property=After", verify)
        self.assertIn("--property=Requires", verify)
        self.assertIn("rtpengine-daemon\\\\.service", verify)

    def test_edge_verification_requires_recovery_owned_boot_persistence(self) -> None:
        verify = self.read("roles/edge_verify/tasks/main.yml")
        self.assertIn("vivolution-edge-runtime-recover.service", verify)
        self.assertIn("allowed: [disabled, static]", verify)
        self.assertIn(
            "OpenSIPS/RTPengine can bypass the enabled\n      protected runtime recovery",
            verify,
        )
        self.assertIn("edge_verify_active_services", verify)
        self.assertNotIn("edge_verify_enabled_services", verify)

    def test_root_runtime_narrows_only_synthetic_rtp_advertisement(self) -> None:
        compiler = (DEPLOY.parent / "edge/compiler/core.py").read_text(encoding="utf-8")
        contracts = (DEPLOY.parent / "edge/runtime/contracts.py").read_text(
            encoding="utf-8"
        )
        runtime = (DEPLOY.parent / "edge/runtime/core.py").read_text(encoding="utf-8")
        self.assertIn(
            "interface = {facts.private_ipv4}!{facts.public_ipv4}", compiler
        )
        self.assertIn(
            'expected_interface = "{}!{}".format(facts.private_ipv4, facts.public_ipv4)',
            contracts,
        )
        self.assertIn("def render_runtime_rtpengine(", contracts)
        self.assertIn('authority.profile == "SYNTHETIC_PRIVATE"', contracts)
        self.assertIn('advertised_ipv4 = facts.private_ipv4', contracts)
        self.assertIn('authority.profile == "DIRECT_ROUTING"', contracts)
        self.assertIn('advertised_ipv4 = facts.public_ipv4', contracts)
        self.assertIn(
            "runtime authority profile cannot select an RTP advertisement", contracts
        )
        self.assertIn(
            "render_runtime_rtpengine(facts, authority, rtpengine)", contracts
        )
        self.assertIn("rtpengine-synthetic-private-advertisement", runtime)
        self.assertIn("rtpengine-direct-public-advertisement", runtime)
        self.assertIn('record["rtpAdvertisedIpv4"]', runtime)
        self.assertIn('record["runtimeProfile"]', runtime)

    def test_activation_uses_real_agent_compiler_and_exact_root_handoff(self) -> None:
        playbook = self.read("playbooks/activate-edge.yml")
        self.assertIn("become_user: vivolution-edge-agent", playbook)
        self.assertIn("'verify-and-stage'", playbook)
        self.assertIn("/usr/local/bin/vivolution-edge-compiler", playbook)
        self.assertIn("--pinned-key", playbook)
        self.assertIn("--expected-advertised-public-ip", playbook)
        self.assertIn("--authorized-pbx-source-cidr", playbook)
        for name in (
            "compile-evidence.json",
            "nftables-tenant-policy.json",
            "opensips-tenant.cfg",
            "rtpengine-tenant.conf",
            "signed-envelope.json",
            "verifier-receipt.json",
        ):
            self.assertIn(name, playbook)
        self.assertIn("mode: '0600'", playbook)
        self.assertIn("remote_src: true", playbook)
        self.assertIn("exactly six root-owned", playbook)
        self.assertIn("edge_activation_root_inbox_inventory.files | length == 6", playbook)
        self.assertNotIn("ansible.builtin.shell", playbook)
        self.assertNotIn("command: sudo", playbook)

    def test_privileged_runtime_independently_verifies_signed_authority(self) -> None:
        contracts = self.read("../edge/runtime/contracts.py")
        runtime = self.read("../edge/runtime/core.py")
        self.assertIn('"signed-envelope.json"', contracts)
        self.assertIn("agent_security.validate_structural_envelope", contracts)
        self.assertIn("agent_security.verify_authorized_signatures", contracts)
        self.assertIn("agent_security._enforce_exact_local_identity", contracts)
        self.assertIn("agent_security._enforce_local_network_allocation", contracts)
        self.assertIn("agent_security._enforce_lkg_artifact_lineage", contracts)
        self.assertIn("compiled artifacts differ from signed manifest declarations", contracts)
        self.assertIn("/usr/lib/vivolution-edge/config/signing-public-key.json", runtime)
        self.assertIn('"signedEnvelopeDigest"', runtime)
        self.assertIn('"verifiedKeyIds"', runtime)

    def test_activation_reconciles_only_exact_runtime_evidence(self) -> None:
        playbook = self.read("playbooks/activate-edge.yml")
        self.assertIn("RUNTIME_APPLIED_HEALTHY", playbook)
        self.assertIn("COMMIT_PENDING", playbook)
        self.assertIn("RUNTIME_APPLY_FAILED_ROLLED_BACK", playbook)
        self.assertIn("ABORT_PENDING", playbook)
        self.assertIn("'commit-pending'", playbook)
        self.assertIn("'abort-pending'", playbook)
        self.assertIn("--runtime-evidence-digest", playbook)
        self.assertNotIn("--health-gates-passed", playbook)
        self.assertIn("PENDING_COMMITTED_AFTER_SIGNED_LOCAL_HEALTH", playbook)
        self.assertIn("PENDING_ABORTED_ACTIVE_LKG_PRESERVED", playbook)
        self.assertIn("Pending Agent state is", playbook)
        self.assertNotIn("signed-envelope.json\"\n        dest: \"{{ edge_activation_local", playbook)

    def test_activation_selects_only_the_executed_reconciliation_register(self) -> None:
        playbook = self.read("playbooks/activate-edge.yml")
        commit_start = playbook.index(
            "Commit the exact pending Agent candidate only after healthy runtime evidence"
        )
        abort_start = playbook.index(
            "Abort the exact pending Agent candidate after verified safe no-change or rollback"
        )
        selection_start = playbook.index(
            "Select only the Agent reconciliation command that executed"
        )
        parse_start = playbook.index("Parse the Agent reconciliation evidence")
        commit_task = playbook[commit_start:abort_start]
        abort_task = playbook[abort_start:selection_start]
        selection = playbook[selection_start:parse_start]

        self.assertIn("register: edge_agent_commit_reconcile", commit_task)
        self.assertIn("until: edge_agent_commit_reconcile.rc == 0", commit_task)
        self.assertNotIn("register: edge_agent_reconcile", commit_task)
        self.assertIn("register: edge_agent_abort_reconcile", abort_task)
        self.assertIn("until: edge_agent_abort_reconcile.rc == 0", abort_task)
        self.assertNotIn("register: edge_agent_reconcile", abort_task)
        self.assertIn("else {}", selection)
        self.assertIn(
            "edge_agent_reconcile == edge_agent_commit_reconcile", selection
        )
        self.assertIn(
            "edge_agent_reconcile == edge_agent_abort_reconcile", selection
        )
        self.assertIn("not (edge_agent_reconcile.get('skipped', false) | bool)", selection)
        self.assertLess(commit_start, abort_start)
        self.assertLess(abort_start, selection_start)
        self.assertLess(selection_start, parse_start)

    def test_activation_reconciliation_selection_survives_skipped_sibling_task(
        self,
    ) -> None:
        commit_stdout = json.dumps(
            {
                "activeManifestDigest": "sha256:" + "a" * 64,
                "activeSequence": 1,
                "healthGates": [],
                "localHealthGatePlanDigest": "sha256:" + "b" * 64,
                "runtimeEvidenceDigest": "sha256:" + "c" * 64,
                "runtimeReleaseDigest": "sha256:" + "d" * 64,
                "status": "PENDING_COMMITTED_AFTER_SIGNED_LOCAL_HEALTH",
            },
            separators=(",", ":"),
        )
        abort_stdout = json.dumps(
            {
                "abortedManifestDigest": "sha256:" + "e" * 64,
                "abortedSequence": 2,
                "status": "PENDING_ABORTED_ACTIVE_LKG_PRESERVED",
            },
            separators=(",", ":"),
        )
        commit_result = {
            "changed": True,
            "rc": 0,
            "stderr": "",
            "stdout": commit_stdout,
        }
        abort_result = {
            "changed": True,
            "rc": 0,
            "stderr": "",
            "stdout": abort_stdout,
        }
        skipped = {
            "changed": False,
            "skip_reason": "Conditional result was False",
            "skipped": True,
        }

        committed = self.evaluate_activation_reconciliation_selection(
            {
                "edge_agent_abort_reconcile": skipped,
                "edge_agent_commit_reconcile": commit_result,
                "edge_runtime_apply_healthy": True,
                "edge_runtime_safe_abort": False,
            }
        )
        self.assertEqual(committed["selected"], commit_result)
        self.assertTrue(all(committed["assertions"]))

        aborted = self.evaluate_activation_reconciliation_selection(
            {
                "edge_agent_abort_reconcile": abort_result,
                "edge_agent_commit_reconcile": skipped,
                "edge_runtime_apply_healthy": False,
                "edge_runtime_safe_abort": True,
            }
        )
        self.assertEqual(aborted["selected"], abort_result)
        self.assertTrue(all(aborted["assertions"]))

        for healthy, safe_abort in ((False, False), (True, True)):
            ambiguous = self.evaluate_activation_reconciliation_selection(
                {
                    "edge_agent_abort_reconcile": abort_result,
                    "edge_agent_commit_reconcile": commit_result,
                    "edge_runtime_apply_healthy": healthy,
                    "edge_runtime_safe_abort": safe_abort,
                }
            )
            self.assertEqual(ambiguous["selected"], {})
            self.assertFalse(all(ambiguous["assertions"]))

    def test_direct_routing_requires_replacement_generation_and_preserves_predecessor(self) -> None:
        tasks = self.read("roles/edge_runtime_install/tasks/main.yml")
        activation = self.read("playbooks/activate-edge.yml")
        transition = self.read("playbooks/transition-direct-routing-replacement.yml")
        self.assertIn("INSTALL_DIRECT_ROUTING_REPLACEMENT_GENERATION", tasks)
        self.assertIn("ACTIVATE_DIRECT_ROUTING_REPLACEMENT_GENERATION", activation)
        self.assertIn("generation | int >= 2", tasks)
        self.assertIn("globally routable Direct Routing PBX source CIDRs", tasks)
        self.assertIn("TRANSITION_TO_DIRECT_ROUTING_REPLACEMENT_FLEET", transition)
        self.assertIn(
            "PRESERVE_SYNTHETIC_PREDECESSOR_UNTIL_SEPARATE_CUTOVER",
            transition,
        )
        self.assertIn("edge_direct_predecessor_ansible_host != ansible_host", transition)
        self.assertIn("edge_direct_predecessor_ansible_user", transition)
        self.assertIn("edge_direct_predecessor_ssh_private_key_file", transition)
        self.assertIn("edge_direct_predecessor_fixed_ssh_common_args", transition)
        self.assertIn("StrictHostKeyChecking=yes", transition)
        self.assertIn("GlobalKnownHostsFile=/dev/null", transition)
        self.assertIn("edge_direct_predecessor_known_hosts_file", transition)
        self.assertIn("Require protected predecessor SSH key and pinned host-key inventory", transition)
        self.assertEqual(
            transition.count('ansible_user: "{{ edge_direct_predecessor_ansible_user }}"'),
            8,
        )
        self.assertEqual(
            transition.count(
                'ansible_ssh_private_key_file: "{{ edge_direct_predecessor_ssh_private_key_file }}"'
            ),
            8,
        )
        self.assertEqual(
            transition.count('ansible_ssh_common_args: "{{ edge_direct_predecessor_fixed_ssh_common_args }}"'),
            8,
        )
        self.assertEqual(transition.count("Prove the preserved predecessor SSH endpoint"), 1)
        self.assertIn(
            "Re-prove the preserved predecessor SSH endpoint after replacement activation",
            transition,
        )
        self.assertIn("predecessorReachableAfterStaging", transition)
        self.assertIn("Require an exact healthy synthetic predecessor rollback LKG", transition)
        self.assertIn(
            "Prove the synthetic predecessor rollback LKG is unchanged after staging",
            transition,
        )
        self.assertIn(
            "edge_direct_predecessor_authority_after.content == edge_direct_predecessor_authority_before.content",
            transition,
        )
        self.assertGreaterEqual(
            transition.count("/usr/local/sbin/vivolution-edge-runtime, health"),
            3,
        )
        self.assertEqual(
            transition.count("/usr/local/sbin/vivolution-voice-fixture-test"),
            2,
        )
        self.assertIn(
            "PROBE_PRESERVED_SYNTHETIC_PREDECESSOR_BEFORE_AND_AFTER",
            transition,
        )
        self.assertIn("predecessorSyntheticCallsBeforeAndAfter", transition)
        self.assertIn("replacementLiveInteroperability", transition)
        self.assertIn("NOT_ASSERTED", transition)
        self.assertIn("import_playbook: install-edge.yml", transition)
        self.assertIn("import_playbook: activate-edge.yml", transition)

    def test_template_inventory_contains_only_placeholders_for_sensitive_inputs(self) -> None:
        variables = self.read("inventories/poc-edge-template/group_vars/all.yml")
        hosts = self.read("inventories/poc-edge-template/hosts.yml")
        self.assertIn("REPLACE_32_BYTE_ED25519_PUBLIC_KEY_BASE64", variables)
        self.assertIn("REPLACE_FIXTURE_CA_SHA256", variables)
        self.assertIn("generated/fixture/sbc1.key", hosts)
        self.assertIn("generated/fixture/sbc2.key", hosts)
        self.assertIn("REPLACE_SBC1_ENVELOPE_SHA256", hosts)
        self.assertIn("REPLACE_SBC2_ENVELOPE_SHA256", hosts)
        self.assertEqual(hosts.count("edge_direct_predecessor_ansible_user: cpadmin"), 2)
        self.assertEqual(hosts.count("edge_direct_predecessor_ssh_private_key_file:"), 2)
        self.assertNotIn("edge_direct_predecessor_ssh_common_args:", hosts)
        self.assertIn("REPLACE_DIRECT_PBX_CA_BUNDLE_SHA256", variables)
        self.assertIn(
            "REPLACE_WITH_TRANSITION_TO_DIRECT_ROUTING_REPLACEMENT_FLEET",
            variables,
        )
        self.assertIn("REPLACE_SBC1_SYNTHETIC_PREDECESSOR_HOST", hosts)
        self.assertIn("REPLACE_SBC2_SYNTHETIC_PREDECESSOR_HOST", hosts)
        self.assertNotIn("BEGIN PRIVATE KEY", variables + hosts)

    def test_install_and_activation_playbooks_pass_ansible_syntax(self) -> None:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        for playbook in (
            "playbooks/install-edge.yml",
            "playbooks/activate-edge.yml",
            "playbooks/transition-direct-routing-replacement.yml",
        ):
            completed = subprocess.run(
                [
                    executable,
                    "--syntax-check",
                    "-i",
                    "inventories/poc-edge-template/hosts.yml",
                    playbook,
                ],
                cwd=DEPLOY,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"{playbook}: {completed.stdout}\n{completed.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
