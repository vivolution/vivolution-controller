# Edge enrollment client

This package installs the provider-neutral, outbound-only Edge enrollment
client/placeholder on a host. It does **not** install or configure an SBC, SIP
or RTP services, Microsoft Teams Direct Routing, or any carrier leg. The
current turnkey role is qualified on Ubuntu 24.04 LTS amd64/arm64 only. The
operator supplies a shared Controller HTTPS origin such as
`https://controller.voice.vivolution.ae`,
`https://probe.cloudpremises.com`, or `https://cp.cloudved.com`; no domain is
compiled into the client.

The bounded v1 result is **enrollment and fleet visibility**, not complete SBC
configuration management. An approved node reports its identity, grant-bound
cluster/slot/generation, agent/link health, boot ID, monotonic heartbeat
sequence, and inventory/release digests. Detailed capability upload, desired
state, secrets, remote actions, certificate issuance, and mTLS are deferred.
The client opens no listener and has no generic command/script execution path.

## Install and join

Install the client on a supported host with the checked-in Ansible role:

```sh
ansible-playbook -i /protected/inventory deploy/playbooks/install-edge-enrollment.yml
```

On a fresh Ubuntu 24.04 LTS host with the verified source bundle, the turnkey
entrypoint performs that local role installation and then opens the two prompts:

```sh
sudo ./installer/install-edge.sh
```

`--verify-only` validates the exact bundled client digest without changing the
host. `--dry-run` verifies the bundle and prints the planned boundary without
installing packages, services, or enrollment state.

Then run the interactive join as root:

```sh
sudo vivolution-edge-join enroll
```

It asks for:

1. the shared Controller HTTPS URL; and
2. the display-once enrollment grant, read from `/dev/tty` with echo disabled.

The CLI deliberately has no `--token` argument and does not read a grant from
an environment variable. For controlled automation, choose exactly one:

```sh
secure-secret-source | sudo vivolution-edge-join enroll \
  --controller https://probe.cloudpremises.com \
  --token-stdin
```

or use `--token-file /run/vivolution/enroll.token`. That file must be an
absolute, root-owned `0600`, single-link regular file on tmpfs. The client
consumes and unlinks it after a valid read. Unlinking is not secure erasure on
a persistent filesystem, which is why `/run`/tmpfs is mandatory. Never put the
grant literal in a command, shell history, cloud-init/user-data, reusable image,
environment variable, or service unit.

The grant is server-scoped to an expected node, cluster, slot (`A` or `B`),
generation, and immutable release digest. The client does not let the operator
override that authority. Before claiming, it independently recalculates the
deterministic digest of its root-owned installed client sources and requires an
exact match with the grant scope; it never merely echoes the Controller value.
It generates an Ed25519 key locally, shows the
fingerprint in local/controller status, and persists only protected state. The
display-once grant is never persisted. If the first claim response is lost,
the protected state retains the exact non-secret signed claim envelope so a
signed status request can discover an already committed claim without the
grant. If no claim was committed, a retry with the same/reissued grant replays
the same request ID, challenge, payload, and signature; it never asks the
Controller for an invalid second challenge.

Useful commands after the first claim:

```sh
sudo vivolution-edge-join status
sudo -u vivolution-edge-agent vivolution-edge-join poll
sudo -u vivolution-edge-agent vivolution-edge-join heartbeat
```

The installed timer runs `service-once`: Pending nodes poll for approval;
approved nodes send a signed heartbeat. Revocation blocks the node from
obtaining a fresh status or heartbeat challenge, so timer calls fail closed.
The Edge's protected local status may therefore remain at its last-known value
and must not be treated as authoritative revocation notification. The data
plane and its last-known-good calling state are outside this enrollment service
and are not removed when management is unavailable.

## Local protection

- `/var/lib/vivolution-edge/enrollment` is `0700`, owned by the dedicated
  non-login `vivolution-edge-agent` account.
- The raw 32-byte Ed25519 seed and JSON state are `0600`, single-link regular
  files written through an atomic replace.
- Identity creation is serialized with an owner-checked lock, so concurrent
  join commands cannot create two keys.
- State is bound to the exact Controller origin and key fingerprint. A changed
  origin, key, server scope, signature, digest, sequence, type, owner, mode, or
  JSON contract fails closed.
- `/usr/lib/vivolution-edge/config/enrollment-release-digest` is root-owned
  `0444`; every process recalculates the fixed installed Python source manifest
  and refuses enrollment/heartbeat if the artifact differs.
- The systemd service is unprivileged, has an empty capability set, a strict
  read-only system view, no environment secrets, and only outbound IPv4/IPv6
  HTTPS capability.
- HTTPS uses the system trust store, TLS 1.2 or newer, hostname validation, no
  redirects, no environment-derived proxy, bounded canonical JSON, and
  sanitized HTTP failures.

See [API_CONTRACT.md](API_CONTRACT.md) for the exact signed v1 contract.

## Tests

```sh
python3 -m unittest discover -s edge/enrollment/tests -p 'test_*.py'
python3 -m unittest deploy.tests.test_edge_enrollment_install_static
```

The suite covers protected input/state, concurrent key creation, canonical
JSON compatibility, origin/path/audience binding, signed claim verification,
lost-response exact replay, Pending-to-Approved transition, heartbeat sequence,
revocation, and installer/service hardening. A root-only tmpfs token-file test
is skipped when the suite runs under an ordinary local account.
