from pathlib import Path
import re
import unittest


ANSIBLE_ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ANSIBLE_ROOT / relative_path).read_text(encoding="utf-8")


class StandaloneAnsibleLayerTests(unittest.TestCase):
    def test_configuration_reuses_clean_deployment_roles(self):
        config = read("ansible.cfg")
        self.assertIn("roles_path = roles:../../deploy/roles", config)
        self.assertIn("inventory = inventory/localhost.yml", config)

    def test_playbook_is_local_and_role_order_is_safe(self):
        playbook = read("install-controller.yml")
        self.assertIn("hosts: localhost", playbook)
        self.assertIn("connection: local", playbook)
        ordered_roles = [
            "ubuntu_preflight",
            "ubuntu_base_os",
            "ubuntu_ssh_safety",
            "ubuntu_firewall",
            "podman",
            "postgres_local",
            "pgbouncer",
            "ubuntu_ingress",
            "controller_services",
            "ubuntu_session_maintenance",
        ]
        offsets = [playbook.index(f"name: {role}") for role in ordered_roles]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("always:", playbook)

    def test_playbook_contains_no_cloud_provider_contract(self):
        managed_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in ANSIBLE_ROOT.rglob("*.yml")
        ).lower()
        for forbidden in ("bicep", "terraform", "azure_", "aws_", "gcp_"):
            self.assertNotIn(forbidden, managed_text)

    def test_preflight_requires_exact_supported_os_architecture_and_capacity(self):
        tasks = read("roles/ubuntu_preflight/tasks/main.yml")
        self.assertIn("ansible_facts.distribution == 'Ubuntu'", tasks)
        self.assertIn("ansible_facts.distribution_version == '24.04'", tasks)
        self.assertIn("['x86_64', 'aarch64']", tasks)
        self.assertIn("cp_min_vcpus | int >= 2", tasks)
        self.assertIn("cp_min_memory_mb | int >= 4096", tasks)
        self.assertIn("cp_min_root_disk_gb | int >= 40", tasks)
        self.assertIn("NTPSynchronized", tasks)
        self.assertIn("timedatectl", tasks)
        self.assertIn("list-timezones", tasks)
        self.assertIn("cp_timezone in cp_host_timezone_choices.stdout_lines", tasks)
        self.assertIn("cp_ntp_mode in ['automatic', 'custom']", tasks)
        self.assertIn("cp_firewall_mode in ['infrastructure', 'installer']", tasks)
        self.assertIn("/var/run/reboot-required", tasks)

    def test_preflight_validates_node_shared_fqdns_and_exact_public_ip(self):
        tasks = read("roles/ubuntu_preflight/tasks/main.yml")
        self.assertIn("^cp1-[0-9a-f]{64}$", tasks)
        for token in (
            "cp_node_fqdn",
            "cp_shared_fqdn",
            "cp_public_ipv4",
            "cp_ingress_server_name == cp_shared_fqdn",
            "cp_acme_email is defined",
            "cp_acme_email is match",
            "resolve exclusively to",
            "must not publish an IPv6 AAAA record",
            "socket.AF_INET6",
            "address.is_global",
        ):
            self.assertIn(token, tasks)
        self.assertNotRegex(
            tasks,
            re.compile(r"cp_public_fqdn_pattern:\s*>-", re.MULTILINE),
            "security regexes must not be folded and gain whitespace",
        )
        self.assertIn("[A-Za-z0-9._/:+-]*@sha256:", tasks)

    def test_preflight_enforces_fresh_host_ownership_marker(self):
        tasks = read("roles/ubuntu_preflight/tasks/main.yml")
        self.assertIn("/etc/vivolution/installation-owner", tasks)
        self.assertIn("owner=vivolution-controller-installer\\nschema=1\\n", tasks)
        for collision in (
            "/etc/postgresql/17/main/postgresql.conf",
            "/etc/pgbouncer/pgbouncer.ini",
            "/etc/caddy/Caddyfile",
            "/etc/containers/systemd/vivolution-cp-web.container",
            "/var/lib/vivolution/releases",
            "/var/lib/vivolution/artifacts",
            "/var/lib/vivolution/backups",
            "/var/lib/vivolution/ownership",
        ):
            self.assertIn(collision, tasks)
        self.assertNotRegex(tasks, re.compile(r"(?m)^\s+- /var/lib/vivolution$"))
        self.assertIn("/var/lib/vivolution/installer transaction subtree", tasks)
        self.assertIn("Inspect the pre-install Chrony provider configuration", tasks)
        self.assertIn("cp_chrony_config_preexisting", tasks)

    def test_full_pgdg_primary_fingerprint_is_verified_before_repository(self):
        tasks = read("roles/ubuntu_base_os/tasks/main.yml")
        fingerprint = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
        fingerprint_offset = tasks.index(fingerprint)
        repo_offset = tasks.index("/etc/apt/sources.list.d/pgdg.sources")
        self.assertLess(fingerprint_offset, repo_offset)
        self.assertIn("--with-colons", tasks)
        self.assertIn("noble-pgdg", tasks)
        self.assertIn("Signed-By: {{ cp_pgdg_keyring_path }}", tasks)

    def test_required_packages_are_installed_while_auto_start_is_blocked(self):
        tasks = read("roles/ubuntu_base_os/tasks/main.yml")
        for package in (
            "caddy",
            "chrony",
            "podman",
            "pgbouncer",
            "postgresql-17",
            "postgresql-client-17",
            "postgresql-contrib-17",
            "unattended-upgrades",
        ):
            self.assertRegex(tasks, rf"(?m)^\s+- {re.escape(package)}$")
        self.assertIn("name: ufw", tasks)
        self.assertIn("when: cp_firewall_mode == 'installer'", tasks)
        self.assertLess(tasks.index("/usr/sbin/policy-rc.d"), tasks.index("postgresql-17"))
        self.assertIn("/run/vivolution-installer-policy-rc-active", tasks)
        self.assertIn("exit 0", tasks)
        self.assertLess(
            tasks.index("Persistently mask network services"),
            tasks.index("Install standalone controller foundation packages"),
        )
        self.assertIn("/var/run/reboot-required", tasks)
        self.assertIn("sudo ./installer/install.sh resume", tasks)
        for unit in (
            "caddy.service",
            "pgbouncer.service",
            "postgresql@17-main.service",
            "postgresql.service",
        ):
            self.assertIn(unit, tasks)
        firewall = read("roles/ubuntu_firewall/tasks/main.yml")
        self.assertLess(firewall.index("ufw, --force, enable"), firewall.index("state: absent"))
        self.assertLess(firewall.index("Status: active"), firewall.index("masked: false"))
        ingress = read("roles/ubuntu_ingress/tasks/main.yml")
        pgbouncer = (ANSIBLE_ROOT.parents[1] / "deploy/roles/pgbouncer/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("masked: false", ingress)
        self.assertIn("masked: false", pgbouncer)
        self.assertLess(
            ingress.index("Install dual-FQDN Caddy ingress policy"),
            ingress.index("masked: false"),
        )
        self.assertLess(
            pgbouncer.index("Configure PgBouncer"),
            pgbouncer.index("masked: false"),
        )
        playbook = read("install-controller.yml")
        self.assertIn("Remove only the exact installer-owned package policy", playbook)
        self.assertIn("Remove only the exact installer-owned volatile guard marker", playbook)

    def test_existing_controller_directory_modes_are_exact(self):
        tasks = read("roles/ubuntu_base_os/tasks/main.yml")
        self.assertIn("{path: /etc/vivolution, mode: '0750'}", tasks)
        self.assertIn("{path: /etc/vivolution/releases, mode: '0700'}", tasks)
        for state_dir in (
            "/var/lib/vivolution",
            "/var/lib/vivolution/releases",
            "/var/lib/vivolution/artifacts",
            "/var/lib/vivolution/backups",
        ):
            self.assertIn(state_dir, tasks)

    def test_ubuntu_security_journal_and_multicast_hardening_exist(self):
        tasks = read("roles/ubuntu_base_os/tasks/main.yml")
        resolver = read("roles/ubuntu_base_os/templates/99-vivolution-hardening.conf.j2")
        self.assertIn("${distro_id}:${distro_codename}-security", tasks)
        self.assertIn("Storage=persistent", tasks)
        self.assertIn("SystemMaxUse={{ cp_journal_max_use }}", tasks)
        self.assertIn("LLMNR=no", resolver)
        self.assertIn("MulticastDNS=no", resolver)
        self.assertIn(":5355", tasks)

    def test_ssh_password_hardening_occurs_only_after_real_key_proof(self):
        tasks = read("roles/ubuntu_ssh_safety/tasks/main.yml")
        option_free = tasks.index(
            "Require an option-free public key suitable for unrestricted reconnect"
        )
        option_free_crypto = tasks.index(
            "Require every option-free reconnect key to be cryptographically valid"
        )
        key_parse = tasks.index("Cryptographically parse every authorized SSH public key")
        key_assert = tasks.index("Require at least one real SHA-256-fingerprinted administrator key")
        hardening = tasks.index("Install key-only OpenSSH hardening after key proof")
        self.assertLess(option_free, option_free_crypto)
        self.assertLess(option_free_crypto, key_parse)
        self.assertLess(key_parse, key_assert)
        self.assertLess(key_assert, hardening)
        self.assertIn("ssh-keygen", tasks)
        self.assertIn("stat.mode is match('^0?[57][0145][0145]$')", tasks)
        self.assertIn("cp_ssh_option_free_public_key_pattern", tasks)
        self.assertIn("one canonical public key without from=", tasks)
        policy = read("roles/ubuntu_ssh_safety/templates/00-vivolution-hardening.conf.j2")
        self.assertIn("PermitRootLogin no", policy)
        self.assertIn("PasswordAuthentication no", policy)
        self.assertIn("AllowUsers {{ cp_ssh_allowed_user }}", policy)

    def test_option_free_reconnect_key_pattern_rejects_key_options_and_certificates(self):
        tasks = read("roles/ubuntu_ssh_safety/tasks/main.yml")
        pattern_match = re.search(
            r"cp_ssh_option_free_public_key_pattern: '([^']+)'",
            tasks,
        )
        self.assertIsNotNone(pattern_match)
        pattern = re.compile(pattern_match.group(1))
        key_blob = "A" * 64
        self.assertRegex(f"ssh-ed25519 {key_blob} admin-key", pattern)
        for unsafe_line in (
            f'from="192.0.2.10" ssh-ed25519 {key_blob} source-bound',
            f'expiry-time="20270101" ssh-ed25519 {key_blob} expiring',
            f'cert-authority ssh-ed25519 {key_blob} ca-only',
            f'command="false" ssh-ed25519 {key_blob} forced-command',
            f'ssh-ed25519-cert-v01@openssh.com {key_blob} certificate',
        ):
            self.assertNotRegex(unsafe_line, pattern)

    def test_firewall_preserves_active_client_and_has_no_broad_ssh_rule(self):
        tasks = read("roles/ubuntu_firewall/tasks/main.yml")
        defaults = read("roles/ubuntu_firewall/defaults/main.yml")
        self.assertIn("cp_firewall_mode: infrastructure", defaults)
        self.assertIn("SSH_CONNECTION", tasks)
        self.assertIn("cp_active_ssh_client_ipv4 ~ '/32'", tasks)
        self.assertEqual(tasks.count("- 0.0.0.0/0"), 1)
        self.assertIn("{port: 80, comment: Vivolution CP HTTP ACME}", tasks)
        self.assertIn("{port: 443, comment: Vivolution CP HTTPS}", tasks)
        self.assertIn("cp_firewall_ssh_source_ipv4_cidrs", tasks)
        self.assertNotIn("allow\n+      - OpenSSH", tasks)
        self.assertIn("cp_ufw_broad_ssh_rules | length == 0", tasks)
        self.assertIn("cp_ufw_ipv6_inbound_allow_rules | length == 0", tasks)
        self.assertIn("cp_ufw_ipv4_http_rules | length == 1", tasks)
        self.assertIn("cp_ufw_ipv4_https_rules | length == 1", tasks)
        self.assertIn(
            "(cp_firewall_ssh_source_ipv4_cidrs | length) + 2",
            tasks,
        )
        self.assertNotIn("(cp_firewall_ssh_source_ipv4_cidrs | length) + 4", tasks)
        self.assertIn("Preserve infrastructure-managed firewall ownership", tasks)
        self.assertIn("managed_policy=ufw", tasks)
        self.assertIn("managed_policy=none", tasks)
        self.assertGreaterEqual(
            tasks.count("when: cp_firewall_mode == 'installer'"),
            14,
        )

    def test_chrony_timezone_and_utc_gate_precede_controller_services(self):
        defaults = read("roles/ubuntu_base_os/defaults/main.yml")
        tasks = read("roles/ubuntu_base_os/tasks/main.yml")
        chrony = read("roles/ubuntu_base_os/templates/chrony.conf.j2")
        playbook = read("install-controller.yml")

        self.assertIn("cp_timezone: Etc/UTC", defaults)
        self.assertIn("cp_ntp_mode: automatic", defaults)
        self.assertIn("cp_ntp_servers: []", defaults)
        self.assertIn("timedatectl, set-timezone", tasks)
        self.assertIn("timedatectl, set-local-rtc, '0'", tasks)
        self.assertIn("chronyc", tasks)
        self.assertIn("waitsync", tasks)
        self.assertIn("systemd-timesyncd", tasks)
        self.assertIn("only active host time authority", tasks)
        self.assertIn("NTPSynchronized=yes", tasks)
        self.assertIn("controller, database, and ingress services remain masked", tasks)
        self.assertLess(tasks.index("waitsync"), tasks.index("Require PostgreSQL 17"))
        self.assertLess(
            playbook.index("name: ubuntu_base_os"),
            playbook.index("name: postgres_local"),
        )

        self.assertIn("{% for server in cp_ntp_servers %}", chrony)
        self.assertIn("server {{ server }} iburst", chrony)
        self.assertIn("rtcsync", chrony)
        self.assertIn("port 0", chrony)
        self.assertIn("cmdport 0", chrony)
        self.assertIn("when: cp_ntp_mode == 'custom'", tasks)
        self.assertIn("Automatic mode preserves safe provider sources", tasks)
        self.assertIn("chrony-preinstall.state", tasks)
        self.assertIn("original-host/chrony.conf", tasks)

    def test_owned_host_artifacts_have_protected_scoped_manifests(self):
        base = read("roles/ubuntu_base_os/tasks/main.yml")
        ssh = read("roles/ubuntu_ssh_safety/tasks/main.yml")
        firewall = read("roles/ubuntu_firewall/tasks/main.yml")
        manifest = read("roles/ubuntu_base_os/templates/ubuntu-host.manifest.j2")

        self.assertIn("/var/lib/vivolution/ownership", base)
        self.assertIn("mode: '0700'", base)
        self.assertIn("ubuntu-host.manifest", base)
        self.assertIn("ubuntu-ssh.manifest", ssh)
        self.assertIn("ubuntu-firewall.manifest", firewall)
        for content in (base, ssh, firewall):
            self.assertIn("mode: '0600'", content)
        self.assertIn("managed_file=/etc/chrony/chrony.conf", manifest)
        self.assertIn("managed_setting=hardware-clock-utc", manifest)

    def test_caddy_serves_both_fqdns_and_disables_admin_api(self):
        caddyfile = read("roles/ubuntu_ingress/templates/Caddyfile.j2")
        tasks = read("roles/ubuntu_ingress/tasks/main.yml")
        self.assertIn("https://{{ cp_shared_fqdn }}:443", caddyfile)
        self.assertIn("https://{{ cp_node_fqdn }}:443", caddyfile)
        self.assertIn("admin off", caddyfile)
        self.assertEqual(caddyfile.count("cert_issuer acme"), 1)
        self.assertIn(
            "dir https://acme-v02.api.letsencrypt.org/directory", caddyfile
        )
        self.assertIn("email {{ cp_acme_email | to_json }}", caddyfile)
        self.assertNotIn("zerossl", caddyfile.lower())
        self.assertNotIn("tls internal", caddyfile.lower())
        self.assertIn("@edge_api path /api/edge/*", caddyfile)
        self.assertIn("request_body @edge_api", caddyfile)
        self.assertIn("max_size 16384B", caddyfile)
        self.assertIn("':2019' not in cp_caddy_listeners.stdout", tasks)
        self.assertIn("Require only the Let's Encrypt production ACME issuer", tasks)
        self.assertIn("cp_caddy_tls_policies[0].issuers | length == 1", tasks)

    def test_post_install_checks_readiness_recovery_docs_and_node_name(self):
        playbook = read("install-controller.yml")
        self.assertIn("/health/ready", playbook)
        self.assertIn("/health/live", playbook)
        self.assertIn("/recovery/", playbook)
        self.assertIn("/docs/", playbook)
        self.assertIn(r"/admin/login/\\?next=/docs/", playbook)
        self.assertIn("cp_node_fqdn ~ ':443:127.0.0.1'", playbook)

    def test_daily_database_session_cleanup_is_bounded_and_verified(self):
        service = read(
            "roles/ubuntu_session_maintenance/templates/"
            "vivolution-cp-clearsessions.service.j2"
        )
        timer = read(
            "roles/ubuntu_session_maintenance/templates/"
            "vivolution-cp-clearsessions.timer.j2"
        )
        tasks = read("roles/ubuntu_session_maintenance/tasks/main.yml")
        self.assertIn(
            "/usr/bin/podman exec vivolution-cp-web python manage.py clearsessions",
            service,
        )
        self.assertIn("OnCalendar=*-*-* 03:30:00", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("RandomizedDelaySec=30m", timer)
        self.assertIn("daemon_reload: true", tasks)
        self.assertIn("enabled: true", tasks)
        self.assertIn("systemctl, is-enabled", tasks)
        self.assertIn("systemctl, is-active", tasks)


if __name__ == "__main__":
    unittest.main()
