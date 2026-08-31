# CP1 controller release notes

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
  explicit signed-cookie compatibility. CP2/CP3 and round-robin remain planned, not released.
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
