# CP1 controller release notes

## Initial qualified vertical slice

- Django operator administration and health endpoints
- PostgreSQL-backed controller schema with tenant row-level security
- Rootless application process in a read-only Podman container
- Migration-aware readiness and database outage recovery

This file is included in the immutable release content hash so operational
releases remain traceable even before an external artifact registry is added.

## Signed-only tenant isolation hardening

- Removes the temporary legacy RLS authorization clauses after the signed-capable bridge
  release was deployed and proven recoverable.
- Enables an explicit least-privilege runtime database contract with file-backed operator
  sessions and read-only Django identity/permission access.
- Allows tenant-scoped read access only to linked customer/M365 metadata while keeping all
  tenant-context/metadata writes and all edge-inventory access operator-only.
- Keeps migrations and initial operator reconciliation on an ephemeral schema-owner path.
