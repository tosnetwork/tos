# PoIW Shadow-Scoring Data Plane

## Status

- Document type: interim data-plane specification
- Status: implemented (tosctld); superseded later by a node-side JSON-RPC
  method serving the same rows
- Date: 2026-08-12

## Purpose

Proof of Intelligent Work (PoIW) scoring consumes settled, evidence-graded
work from public chain data. This document specifies the first, phase-A
form of that data plane: settlement events recorded by the `tosctld`
chain indexer and served over the authenticated HTTP query API, so a
scorer can shadow-score a localnet or testnet before any protocol change
exists.

The design intent (per the JSON-RPC policy: new capabilities are added as
explicit new methods) is that a node-side method eventually serves the
same rows; this tosctld surface defines their meaning.

## What gets recorded

The indexer records one settlement event per:

- **Task Escrow** whose decoded status reaches `settled` (terminal);
- **Service Actor request** whose lifecycle classification concludes
  `responded` — the only conclusion the snapshot-diff classifier can
  prove was a real, paid completion. `refunded`, `swept`, and
  `resolved_unknown` conclusions never produce an event.

Events are keyed by `(address, request_id)` and the first observation
wins: a settlement is a once-only transition, so re-scans and
re-observations are idempotent and cannot move an event to a different
seqno. The recorded `seqno` is the block in which the scan *observed*
the transition — an upper bound on, not necessarily equal to, the block
that executed it.

Settlement drains a Task Escrow, so its on-chain budget field is already
zero once the settled status is observable. The recorded `amount` is
therefore taken from the indexer's own pre-settlement observation of the
contract. A continuously-running indexer always has one; an indexer that
first sees an escrow only after settlement records `amount = 0` — the
same snapshot-diff limitation documented below, resolved for good by the
settlement-receipt schema.

## Endpoint

`GET /poiw/settled-work?from_seqno=&to_seqno=&offset=&limit=`
(authenticated, same bearer scheme as the other query endpoints).

Each row: `address`, `request_id` (empty for Task Escrows), `kind`
(`task_escrow` | `service_request`), `earner`, `payer`, `amount`
(settled nanotos), `evidence`, `seqno`, `observed_at`.

## Phase-A interim evidence mapping

The full settlement-receipt schema (capability class, measured work
units, rate-card valuation, explicit evidence level) is not on chain
yet. Until it lands, consumers apply this published mapping:

| On-chain fact | Mapped field |
|---|---|
| Settlement on a contract deployed with an attestor key (its settle/respond op carried a verified attestor signature) | `evidence = Attested` |
| Any other real settlement | `evidence = Observed` |
| Settled amount | both the work valuation and its price cap |
| Capability class, work units | not available; single default class |

Self-declared or unsettled work never appears in this feed at all, which
preserves the PoIW rule that `Declared`-level claims earn zero.

## Boundaries

- This is a read-only reporting surface. It mints nothing, pays nothing,
  and grants no authority; PoIW reward creation is a separate,
  design-stage protocol mechanism with its own launch gates.
- `earner`/`payer` are contract-role addresses (agent/creator,
  owner/caller). Control-domain and wash-trade classification happen in
  the scorer, not here.
- The indexer's snapshot-diff limits apply: a settlement whose contract
  the indexer never observes (e.g. discarded config and no later
  transaction) is not recorded, and `resolved_unknown` service requests
  are deliberately excluded rather than guessed.
