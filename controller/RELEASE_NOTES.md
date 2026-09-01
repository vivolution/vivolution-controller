# Controller release notes

## v0.3.0-rc6 turnkey-installer beta

This section records the rc6 prerelease scope. Static, regression, and security
verification pass; fresh Ubuntu 24.04 installation and certificate issuance
remain live acceptance gates.

### Enabled beta paths

- Replaces the role-name prompt with a neutral five-option launcher:
  **Create a new Controller Plane**, **Join an existing Controller Plane**,
  **Deploy an Edge Appliance (SBC)**, **Manage an existing installation**, and
  **Diagnostics / network readiness test**.
- Enables only new one-node Controller creation, non-mutating diagnostics, and
  bounded Manage actions for status, redacted support bundle, resume,
  reconcile, and safe discard of a run proven to be pre-mutation.
- Keeps Controller join/HA and full SBC deployment visibly unavailable. The
  bounded Ubuntu Edge enrollment client is not presented as an SBC, and the
  complete private Debian 13 AMD64 voice POC is not presented as Ubuntu-ready.
- Removes CP1/CP2/CP3/SBC1/SBC2 naming guidance from product UX. Immutable node
  IDs and authoritative topology state are independent of operator-selected
  FQDNs/display names.

### Operator preflight contract

- Best-effort public-IP prefill compares multiple short-timeout HTTPS sources,
  warns that egress NAT may differ from the inbound service address, and
  requires confirmation/manual override.
- DNS validation retains entered answers and offers retry, bounded timed retry,
  change, a propagation-check link, and safe exit while reporting resolver
  lookup failure, wrong A, and unsupported AAAA; retries best-effort flush the
  local systemd-resolved cache. Authoritative/recursive and CAA diagnosis remain
  future work.
- Adds explicit `Infrastructure-managed` (default, no UFW ownership) and
  `Installer-managed` (previewed lockout-safe UFW) firewall modes.
- Selects timezone from the IANA list and configures Chrony with
  automatic/provider or validated custom NTP sources before Controller service
  activation. Durable timestamps remain UTC.

### Evidence, ownership, and failure cleanup

- Advances new rc6 runs to ledger schema 5, moves installer transaction state
  beneath `/var/lib/vivolution/installer`, moves installer evidence beneath
  `/var/log/vivolution/installer`, and records exact host ownership beneath
  `/var/lib/vivolution/ownership`.
- The complete FHS target still separates immutable releases in `/opt`,
  configuration/secrets in `/etc`, state in `/var/lib`, evidence in `/var/log`,
  staging in `/var/cache`, and volatile files in `/run`; rc6 does not claim the
  complete runtime/release migration.
- Adds levelled `TRACE` through `FATAL` records plus `AUDIT` events, RFC 3339
  UTC context, sanitized command metadata/output, 10 MiB/five-generation log
  rotation, and bounded per-command output. There is no unredacted or
  shell-trace mode; compression and longer-term export/retention remain future.
- The support bundle remains allowlist-based and excludes credentials, grants,
  private keys, database URLs, authorization headers, carrier secrets, and
  customer-sensitive call data.
- Adds only a fail-closed **schema-5 pre-mutation discard** contract: exact
  allow-listed objects are previewed by dry-run and removed only after
  `DISCARD-INCOMPLETE` when schema-5 evidence proves no mutation. Legacy state
  is detection/preview-only. Post-mutation
  uninstall, repair, rollback, upgrade, backup/restore, and node removal are not
  implemented by this candidate.

### rc5 migration boundary

- rc6 does not claim in-place resume or upgrade of an rc5 schema-4 run.
- It may detect and preview a recognized rc3-rc5 ledger when the exact legacy
  allowlist and phase states prove that no mutation began, but it refuses
  automated deletion because the legacy lock is not race-safe. Fresh Ubuntu
  24.04 remains the rc6 acceptance path.
- A possibly mutated rc5 host requires inspection and a separately qualified
  migration/removal procedure; pre-mutation discard refuses it.

## Let's Encrypt-only Controller HTTPS

- Adds a separately validated ACME contact email to the interactive and
  answer-file installer contracts.
- Pins Caddy to the Let's Encrypt production ACME directory as its single
  certificate issuer for both the unique Controller VM FQDN and stable shared
  FQDN, with no alternate public CA or local/self-signed fallback.
- Rejects published AAAA records because the standalone profile deliberately
  exposes only IPv4 ingress, and retains trusted HTTPS probes so incomplete
  public issuance fails installation closed.
- Leaves certificate storage and automatic renewal under Caddy's managed
  service lifecycle. Future Teams/SBC signaling certificates remain outside
  this Controller-web certificate scope.
- Advances the installer ledger schema so rc2 resume/reconcile is refused;
  existing alternate-CA certificate storage is not mislabeled as converted to
  the new Let's Encrypt-only contract.

## Release-matched operator documentation

- Adds staff-only HTML configuration guidance at `/docs/` using the existing Django
  authentication boundary and same-origin, manifest-hashed static assets.
- Adds a database-independent public `/recovery/` page containing only safe recovery
  direction, the installed release identifier, and links to liveness and operator login.
- Adds Vivolution console branding and a documentation link to Django Admin.
- Applies a script-free Content Security Policy, no-store caching, same-origin resource
  isolation, permissions restrictions, and search-engine exclusion to both document surfaces.
- Adds strictly selected, bounded PostgreSQL sessions to the standalone Ubuntu installer with
  immediate server-side logout revocation, while retaining the legacy-safe file default and
  explicit signed-cookie compatibility. Additional Controller nodes and
  round-robin remain planned, not released.
- Allows the privileged operator reconciler to validate, normalize and idempotently maintain
  an optional contact email without exposing identity administration to the runtime console.

## Historical initial functional vertical slice

- Django operator administration and health endpoints
- PostgreSQL-backed controller schema with tenant row-level security
- Rootless application process in a read-only Podman container
- Migration-aware readiness and database outage recovery

The August 28 independent audit withdrew the original broader qualification
claim. This section describes the historical functional slice only; it is not
current security or release acceptance.

This file is included in the immutable release content hash so operational
releases remain traceable even before an external artifact registry is added.

## Signed-only tenant isolation hardening

- Removes the temporary legacy RLS authorization clauses after the signed-capable bridge
  release was deployed and proven recoverable.
- Enables an explicit least-privilege runtime database contract with narrowly scoped shared
  PostgreSQL operator sessions and read-only Django identity/permission access.
- Allows tenant-scoped read access only to linked customer/M365 metadata while keeping all
  tenant-context/metadata writes and all edge-inventory access operator-only.
- Keeps migrations and initial operator reconciliation on an ephemeral schema-owner path.

## OpenSSL and vulnerability-evidence hardening

- Updates the exact controller image to Debian's OpenSSL 3.5.7 security build
  using architecture-specific, SHA-256-verified ARM64 and AMD64 packages.
- Squashes the final runtime image so deleted build/base packages cannot remain
  as stale vulnerable layers, while retaining the base digest and final SBOM.
- Blocks every Trivy-reported fixable High/Critical dependency or OS package
  finding and preserves findings without a reported fixed version as signed,
  explicitly counted residual risk.
- Binds scans to the exact running immutable image, its exported package
  database, the guest dpkg database, a committed Trivy binary digest, and an
  unchanged vulnerability database, with adversarial validator tests.
