# Synthetic Edge/fixture call accounting

This POC records and reconciles exactly two logical calls for every serialized
private fixture test:

1. Teams fixture to PBX fixture
2. PBX fixture to Teams fixture

The acceptance artifact is
`edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1`. It binds the fixture
test ID, selected SBC node and slot, immutable tenant allocation, Edge runtime
authority, two OpenSIPS transaction outcomes, two Asterisk CDR records, and
the complete fixture manifest digest.

## Execution boundary

The signed tenant fragment contains guarded accounting hooks. The privileged
runtime renderer enables them only for `SYNTHETIC_PRIVATE`; the
`DIRECT_ROUTING` renderer does not define the guard, so the hooks are
preprocessed out. The synthetic runtime also sets the transaction module's
`onreply_avp_mode` to exactly `1`, so the immutable test identity and direction
AVPs set on the request transaction remain visible to its named reply route.
Direct Routing does not enable that parameter. OpenSIPS 3.6 provides `xlog`
from its pinned core binary; there is no separate `xlog.so` module to load. A
marker is emitted only when both fixed headers are present:

- `X-Vivolution-Fixture: no-pstn`
- `X-Vivolution-Test-ID: YYYYMMDDTHHMMSSZ-sbc1|sbc2-<pid>`

The marker contains only the fixed route token, direction, test ID, event and
result. It does not contain a SIP Call-ID, caller identity, From/To value,
contact, SDP, IP address, or media payload.

`vivolution-edge-synthetic-cdr-export` runs as root on the selected SBC. It
refuses Direct Routing, reads only the fixed root-owned node facts and runtime
authority, and queries only `opensips.service` within the test-derived bounded
journal window. It requires one `START` and one `FINAL` marker for each fixed
direction, exact OpenSIPS user/service provenance, a single boot identity per
call, and no duplicates. The parser accepts only the exact raw, `NOTICE:`, or
legacy `NOTICE:script: ` journal presentation immediately before the marker;
any other prefix fails closed. Prefix text is never retained in the canonical
evidence. The immutable canonical result is stored as
`/var/lib/vivolution-edge/synthetic-cdr-evidence/<test-id>.json` with mode
`0400`.

Changing the privileged runtime renderer alone does not rewrite an already
active immutable OpenSIPS configuration. After deploying reviewed source, the
Edge must receive a newly activated signed release (or an equivalently
qualified replacement release) before the reply-route setting can be claimed;
a source-refresh receipt by itself is not that activation evidence.
The exact committed-node maintenance path is
`deploy/playbooks/refresh-active-edge-cdr-exporter.yml`; it digest-pins and
atomically replaces only the root-only exporter, rolls exact old bytes back on
validation failure, and leaves runtime identity and health unchanged.

The voice fixture records Asterisk CDR CSV rows with direction-specific
account codes. Its normalizer requires exactly one answered logical record in
each direction, fixed synthetic numbers and channel shapes, the same test ID,
and no rows from an unrelated linked call. Its canonical `fixture-cdr.json`
contains hashes of the selected raw rows and linked-call identifiers rather
than raw channel or call identifiers.

The offline reconciler consumes one runner-owned mode-`0700` directory with
exactly these mode-`0600` files:

- `edge-cdr.json`
- `fixture-cdr.json`
- `fixture-asterisk-cdr-delta.csv`
- `fixture-MANIFEST.sha256`
- `fixture-RESULT`

It reconstructs fixture evidence from the raw CSV, validates both evidence
self-digests, requires `PASS`, verifies the manifest entries for all CDR
inputs, and matches the same test, node and ordered directions. It creates a
new mode-`0600` `reconciliation.json`; it never replaces an existing result.
The failover qualification performs this reconciliation independently for the
primary baseline, alternate SBC, and restored primary calls.

## What this proves

A successful reconciliation proves that both synthetic transactions reached
an accepted SIP outcome at the selected Edge and produced answered logical
records at the Asterisk fixture for the same bounded test identity. It also
binds those records to the protected fixture evidence manifest.

It does **not** prove live Microsoft 365 interoperability, PSTN connectivity,
carrier routing, emergency calling, active-call migration, production call
detail retention, billing accuracy, regulatory CDR compliance, or end-user
identity correlation. Edge elapsed time is the interval between OpenSIPS
transaction markers; it is not billed or connected-call duration.

## Retention and trust limitations

- The Edge host root and system journal are the evidence trust boundary. A
  party with root access can alter that boundary.
- Journald retention is bounded to 14 days and its configured size cap.
- The root-owned Edge evidence spool fails closed at 512 files or 16 MiB. It
  does not delete evidence automatically; an operator must archive reviewed
  evidence before capacity is exhausted.
- There is no production CDR database, write-ahead ingestion pipeline,
  external timestamp authority, or off-host immutable archive in this POC.
- The exact Asterisk CDR/channel shapes remain a live qualification gate. An
  image or dialplan change that alters those shapes must fail normalization
  until the contract and tests are deliberately reviewed.
