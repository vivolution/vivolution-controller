from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]


class DnsAcmeStaticTests(unittest.TestCase):
    def test_ephemeral_lego_records_do_not_own_the_rbac_scope(self) -> None:
        module = (ROOT / "modules" / "dns-acme-zone.bicep").read_text()
        self.assertIn("Lego deletes the entire TXT record set", module)
        self.assertIn("acme-${sbc1RecordName}.${dnsZoneName}", module)
        self.assertIn("acme-${sbc2RecordName}.${dnsZoneName}", module)
        self.assertIn("resource sbc1AcmeZone 'Microsoft.Network/dnsZones@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeZone 'Microsoft.Network/dnsZones@2018-05-01'", module)
        self.assertIn("purpose: 'edge-acme-dns01'", module)
        self.assertEqual(module.count("name: 'prevent-edge-acme-zone-deletion'"), 2)
        self.assertEqual(module.count("level: 'CanNotDelete'"), 2)
        self.assertIn("resource sbc1AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeDelegation 'Microsoft.Network/dnsZones/NS@2018-05-01'", module)
        self.assertIn("resource sbc1AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01'", module)
        self.assertIn("resource sbc2AcmeCname 'Microsoft.Network/dnsZones/CNAME@2018-05-01'", module)
        self.assertEqual(module.count("sbc1AcmeZone.properties.nameServers["), 4)
        self.assertEqual(module.count("sbc2AcmeZone.properties.nameServers["), 4)
        self.assertEqual(module.count("scope: sbc1AcmeZone"), 3)
        self.assertEqual(module.count("scope: sbc2AcmeZone"), 3)
        self.assertNotIn("scope: sbc1AcmeTxt", module)
        self.assertNotIn("scope: sbc2AcmeTxt", module)
        self.assertNotIn("scope: dnsZone\n", module)

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
        self.assertNotIn("LEGO_DISABLE_CNAME_SUPPORT", environment + renewal)
        self.assertIn("Managed-identity and Resource Graph authorization", certificate_tasks)
        self.assertIn("retries: 30", certificate_tasks)
        self.assertIn("delay: 20", certificate_tasks)
        self.assertIn("TimeoutStartSec=5min", certificate_service)


if __name__ == "__main__":
    unittest.main()
