# CP1 controller vertical slice

This directory contains the first runnable management-plane slice: Django 5.2 LTS,
PostgreSQL-only deployment settings, operator administration, liveness/readiness probes,
the narrow tenant/edge/configuration model, and PostgreSQL row-level security (RLS).

Enrollment, PKI, edge-agent commands, route compilation, customer-facing APIs, background
jobs, artifact signing, and the SIP/media data plane are intentionally out of scope here.

## Runtime assumptions

- Python 3.13 and PostgreSQL 17 are the qualified targets. The code requires Python 3.11+.
- The application always reaches PostgreSQL through `DATABASE_URL`; deployment may point it
  at local PgBouncer or Azure Database for PostgreSQL.
- Production uses two database identities: a table-owning migration role for one-shot
  migrations and a non-owner runtime role for the web process.
- RLS is a second barrier only for the non-owner runtime role. PostgreSQL table owners and
  superusers bypass non-forced RLS by design. Do not run the web process as either one.
- The reverse proxy terminates public TLS. Trust of `X-Forwarded-Proto` is opt-in and is safe
  only when CP1 cannot be reached around that proxy.
- Configuration artifacts are represented by digest only; this slice does not store or sign
  artifact bytes.

## Required configuration

Copy `.env.example` only as a reference; do not commit a real `.env` file.

- `DJANGO_SECRET_KEY`: random deployment secret; required.
- `DJANGO_ALLOWED_HOSTS`: comma-separated hostnames; required with debug disabled.
- `DATABASE_URL`: `postgresql://` URL. Percent-encode reserved characters in credentials.
- `RLS_CONTEXT_SIGNING_KEY`: an independent 32-byte key encoded as 64 lowercase hex
  characters. The web process uses it only to sign short-lived database authorization
  contexts; never reuse `DJANGO_SECRET_KEY` or a database password.
- `RLS_CONTEXT_TTL_SECONDS`: signed database-context lifetime, from 5 through 300 seconds;
  default `60`.
- `DJANGO_CSRF_TRUSTED_ORIGINS`: comma-separated HTTPS origins for the operator UI.
- `DJANGO_TRUST_X_FORWARDED_PROTO`: set to `true` only behind the trusted ingress proxy.
- `DJANGO_SECURE_SSL_REDIRECT`: enable after trusted proxy-header handling is verified.
- `DJANGO_SECURE_HSTS_SECONDS`: begin with a short value after public TLS is stable, then
  increase deliberately; do not preload or include subdomains without a domain-wide review.
- `DB_CONN_MAX_AGE`: persistent connection lifetime in seconds; default `60`.

The URL parser passes through only PostgreSQL's `sslmode`, `sslrootcert`, `sslcert`,
`sslkey`, and `target_session_attrs` options. The Azure profile should use
`sslmode=verify-full` with the managed-server hostname and a trusted CA root.

## Database and RLS contract

Migrations `0002_enable_rls`, `0003_signed_rls_context`, and
`0004_signed_only_rls_context` enable RLS, install the signed-context validator,
and remove the temporary legacy authorization clauses on:

- `TenantContext` (scope column is its immutable UUID primary key);
- `ConfigurationVersion`;
- `AuditEvent` (global events have a null tenant and are operator-only).

A tenant operation must execute inside `core.rls.tenant_scope(tenant_context_id)`. It opens
a transaction and installs a short-lived HMAC-signed PostgreSQL context. The current admin UI
is for authenticated Django staff only; middleware gives staff an independently signed,
transaction-local operator context. PostgreSQL validates signed contexts against key material
stored in the owner-only `cp_security` schema. No HTTP tenant-header shortcut exists because
an unverified header is not an authorization boundary.

Migration `0003` was the one-release compatibility bridge: its policies accepted the signed
context and the preceding release's transaction-local legacy settings while the bridge
application emitted both. Migration `0004` is the irreversible cutover to signed-only
authorization after that signed-capable bridge was deployed and proven recoverable as N-1.
Caller-controlled `app.is_operator` and `app.tenant_context_id` settings no longer grant
access.

Tenant contexts can read only the `CustomerAccount` and `M365Tenant` rows linked to their
own visible context so normal ORM joins remain usable. Those metadata policies and tenant
access to `TenantContext` are `SELECT`-only; every tenant-context/customer/M365 write and all
edge-inventory access require a valid signed operator context. The catalog contract is ten
explicit policies across seven tables.

After migrations, the schema owner must synchronize the database copy of the independent key
before starting the runtime process:

```sh
python manage.py migrate --noinput
python manage.py configure_rls_key
```

The database key table is deliberately unreadable by the runtime role. After the signed-only
policy migration and explicit least-privilege grants are active, a raw SQL-injection flaw can
reuse only the current transaction's scope; it cannot mint an operator or a different tenant
context. A fully compromised Python process can read its signing key and is outside this
boundary, so host/container controls and key rotation remain necessary.

RLS is enabled but not forced so the migration owner can migrate and repair the schema. The
final deployment grants the non-owner runtime role only explicit required table/sequence
rights. Operator sessions use the container's bounded `/tmp` tmpfs instead of the database,
and the runtime administrator cannot edit users, groups, or permissions; those identities are
reconciled only through the owner-credential deployment command.
The local deployment qualification connects as that runtime role and proves no-context,
legacy-setting forgery, signed-context forgery, same-tenant reads and writes, cross-tenant
read/write denial, explicit operator behavior, and runtime key-table denial against
PostgreSQL 17. The same behavioral gate must pass again against Azure Database for PostgreSQL
before production use.

## Local development and checks

Use the pinned lock, then run Django's checks and tests:

```sh
python3.13 -m venv .venv
.venv/bin/pip install --no-deps --require-hashes -c constraints.txt -r requirements.lock
DJANGO_SETTINGS_MODULE=cp1.settings_test .venv/bin/python manage.py check
DJANGO_SETTINGS_MODULE=cp1.settings_test .venv/bin/python manage.py makemigrations --check --dry-run
DJANGO_SETTINGS_MODULE=cp1.settings_test .venv/bin/python manage.py test
```

SQLite is used only by `cp1.settings_test` for fast unit tests. It does not exercise RLS. The
PostgreSQL test verifies the installed RLS policies when the test suite runs against a
PostgreSQL test database.

For a local PostgreSQL run, supply real environment variables and apply migrations with the
migration-owner URL:

```sh
python manage.py migrate --noinput
python manage.py createsuperuser
gunicorn cp1.wsgi:application --bind 127.0.0.1:8000
```

Endpoints:

- `GET /health/live` proves the process can answer without touching PostgreSQL.
- `GET /health/ready` proves PostgreSQL is reachable, migration `0004` is recorded, the
  application signing key matches the owner-only database copy, and the exact ten-policy
  signed-only catalog is intact.
- `/admin/` is the initial operator UI.

## Container

The `Containerfile` pins the official multi-architecture Python 3.13 Debian Trixie base by
OCI index digest, and every Python wheel/sdist in `requirements.lock` is SHA-256 hashed. The
qualified base index contains both ARM64 and AMD64 manifests. The process runs as fixed
unprivileged UID/GID `10001`; application files remain root-owned and the deployed container
uses a read-only root filesystem with all Linux capabilities dropped. Static admin assets are
built into the image.
Migrations are disabled by default; run one controlled instance with `RUN_MIGRATIONS=1` or,
preferably, use a separate one-shot migration unit before starting web replicas.

Do not bake an `.env`, database password, secret key, or certificate into the image. The
current deployment keeps versioned runtime environments root-only on the host and excludes
them from source, images, and evidence. Migration/administrator credentials exist only in a
root-only `/run` file for the one-shot operation and are removed in an `always` cleanup path.
Production key custody and a systemd-credential or equivalent secret-mount design remain
acceptance gates.

Controller schema migrations must follow expand/contract compatibility. Automatic activation
restores the exact prior image and runtime environment when a new release fails readiness, but
database migrations are intentionally not reversed. Manual image rollback therefore skips
migrations and assumes the current schema remains backward-compatible.
