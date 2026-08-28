# CP1 controller release notes

## Initial qualified vertical slice

- Django operator administration and health endpoints
- PostgreSQL-backed controller schema with tenant row-level security
- Rootless application process in a read-only Podman container
- Migration-aware readiness and database outage recovery

This file is included in the immutable release content hash so operational
releases remain traceable even before an external artifact registry is added.
