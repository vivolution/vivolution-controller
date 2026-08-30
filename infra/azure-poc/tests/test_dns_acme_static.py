from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]


class DnsAcmeStaticTests(unittest.TestCase):
    def test_ephemeral_lego_records_do_not_own_the_rbac_scope(self) -> None:
        entrypoint = (ROOT / "dns-acme.bicep").read_text()
        module = (ROOT / "modules" / "dns-acme-zone.bicep").read_text()
        self.assertIn("Lego deletes the entire TXT record set", module)
        self.assertIn("acme-${sbc1RecordName}.${dnsZoneName}", module)
        self.assertIn("acme-${sbc2RecordName}.${dnsZoneName}", module)
        self.assertIn("resource sbc1AcmeZone 'Microsoft.Network/dnsZones@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeZone 'Microsoft.Network/dnsZones@2018-05-01'", module)
        self.assertIn("purpose: 'edge-acme-dns01'", module)
        self.assertNotIn("Microsoft.Authorization/locks", module)
        self.assertIn("A CanNotDelete lock on the zone is intentionally forbidden", module)
        self.assertIn("resource sbc1AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01'", module)
        self.assertIn("resource sbc1AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01'", module)
        self.assertEqual(module.count("sbc1AcmeZone.properties.nameServers["), 4)
        self.assertEqual(module.count("sbc2AcmeZone.properties.nameServers["), 4)
        self.assertEqual(module.count("scope: sbc1AcmeZone"), 1)
        self.assertEqual(module.count("scope: sbc2AcmeZone"), 1)
        self.assertNotIn("Microsoft.Network/dnsZones/TXT@", module)
        self.assertNotIn("scope: dnsZone\n", module)
        self.assertIn(
            "resource edgeAcmeTxtRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01'",
            entrypoint,
        )
        self.assertIn("c502c211-fd81-49aa-8ec3-45854ecd5e23", entrypoint)
        for action in (
            "Microsoft.Network/dnszones/read",
            "Microsoft.Network/dnszones/TXT/read",
            "Microsoft.Network/dnszones/TXT/write",
            "Microsoft.Network/dnszones/TXT/delete",
            "Microsoft.ResourceGraph/resources/read",
        ):
            self.assertEqual(entrypoint.count(action), 1)
        self.assertNotIn("Microsoft.Network/dnszones/write", entrypoint)
        self.assertNotIn("Microsoft.Network/dnszones/delete", entrypoint)
        self.assertNotIn("befefa01-2a29-4197-83a8-272ff33ce314", module)
        self.assertNotIn("acdd72a7-3385-48ef-bd42-f606fba81ae7", module)

    def test_each_edge_is_pinned_to_only_its_derived_acme_zone(self) -> None:
        hosts = (
            REPOSITORY
            / "deploy"
            / "inventories"
            / "poc-edge-template"
            / "hosts.yml"
        ).read_text()
        preflight = (
            REPOSITORY / "deploy" / "roles" / "edge_preflight" / "tasks" / "main.yml"
        ).read_text()
        environment = (
            REPOSITORY
            / "deploy"
            / "roles"
            / "edge_certificate"
            / "templates"
            / "acme-azure.env.j2"
        ).read_text()
        renewal = (
            REPOSITORY
            / "deploy"
            / "roles"
            / "edge_certificate"
            / "templates"
            / "renew-edge-certificate.sh.j2"
        ).read_text()
        certificate_tasks = (
            REPOSITORY
            / "deploy"
            / "roles"
            / "edge_certificate"
            / "tasks"
            / "main.yml"
        ).read_text()
        certificate_service = (
            REPOSITORY
            / "deploy"
            / "roles"
            / "edge_certificate"
            / "templates"
            / "vivolution-edge-certificate.service.j2"
        ).read_text()
        self.assertIn("edge_azure_dns_zone: acme-sbc1.voice.example.invalid", hosts)
        self.assertIn("edge_azure_dns_zone: acme-sbc2.voice.example.invalid", hosts)
        self.assertIn("edge_azure_dns_zone == 'acme-' ~ edge_acme_node_fqdn", preflight)
        self.assertIn("AZURE_ZONE_NAME={{ edge_azure_dns_zone }}", environment)
        self.assertIn("AZURE_PROPAGATION_TIMEOUT=180", environment)
        self.assertNotIn("LEGO_DISABLE_CNAME_SUPPORT", environment + renewal)
        self.assertEqual(
            renewal.count(
                "--dns.resolvers '{{ edge_azure_wire_server_ipv4 }}:53'"
            ),
            2,
        )
        self.assertEqual(renewal.count("--dns.propagation.disable-ans"), 2)
        self.assertNotIn("--dns.propagation.disable-rns", renewal)
        self.assertNotIn("--dns.propagation.wait", renewal)
        self.assertIn("Managed-identity and Resource Graph authorization", certificate_tasks)
        self.assertIn("exactly one delayed retry", certificate_tasks)
        self.assertIn("retries: 1", certificate_tasks)
        self.assertIn("delay: 180", certificate_tasks)
        self.assertNotIn("retries: 30", certificate_tasks)
        self.assertIn("TimeoutStartSec=10min", certificate_service)
        self.assertNotIn("TimeoutStartSec=5min", certificate_service)


if __name__ == "__main__":
    unittest.main()
