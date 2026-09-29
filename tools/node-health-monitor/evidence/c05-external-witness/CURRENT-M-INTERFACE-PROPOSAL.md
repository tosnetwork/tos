# C05 development-only current M interface proposal — review before code

This is a proposed boundary, not an implemented or accepted capability. The
existing `/witness-evidence/{endpoint}` acknowledgement is historical
`witness_archive_v1` only. Its database permits late valid generations and
must not be repurposed as a latest/current view. No production upstream
adapter or verified-finality input is implied.

## Activation and identity

Add an explicit approved `source_epoch` to each fixed endpoint in the
development Plan (one active epoch per endpoint per plan revision). A changed
epoch requires a new approved plan revision/activation; an observed upstream
epoch string is not itself authorization. M persists `(plan_hash,
observer_epoch, endpoint_id, approved_source_epoch, highest_generation,
source_hash)` in a separate current-state namespace. O and M validate the
same frozen Plan hash and exact source identity. A repeated generation/hash
cannot refresh time; same-generation changed hash quarantines. A lower
generation can still enter the historical archive, but cannot replace the
current state. On M restart the current view is unavailable until a new
qualified cache delivery under the approved activation; persisted high-water
still rejects regression. Plan replacement is an explicit operation, not a
side effect of changing an in-memory constructor.

## Age accounting and read surface

The collector starts a monotonic timer before the O cache GET and carries its
measured elapsed through bounded body read and POST enqueue. M starts its own
monotonic timer at ingress and adds queue, durable-write/qualification and
subsequent read elapsed. The gap during the collector-to-M POST cannot be
called zero. Before an agreed bounded transit witness exists, current age is
`unknown` and no freshness-dependent rule input is emitted; an archive ACK
does not close that gap. A later implementation may use a protocol-bound
client deadline as a conservative *upper bound* for that leg, but must bind
the specific fixed collector and prove the timeout applies to the whole
request. Overflow of any sum yields unknown, never zero. Remote UTC is not
subtracted from another host's clock. O's original-row first receipt,
observer clock quality and source reported age remain immutable across O
generation republish; M adds elapsed and cannot renew an old row by another
cache GET or duplicate archive delivery.

Expose a separate bounded `current_witness` result only after activation,
ordering, age and role checks; never through the historical archive ACK or
ordinary observation watermark. Reuse the exact cache wire decoder and
plan-bound role/raw-scope context. The output retains five distinct dimensions:
local action and persistence stay unknown without approved local sources;
remote network observation, certificate membership and reported proof remain
reported, not locally verified. Missing private votes remain partial. A
reported quorum, highest height, mismatched unfinalized candidate or remote
`reported_valid` cannot generate a validator fault or verified-finality
conflict. A lacks any on-demand source call.

## Bounded development profile and proof obligations

Use the existing 16 approved endpoints, 32 targets, at most three refs per
target, 32 KiB cache-wire body and fixed 15-second collector schedule.
Current state retains at most one body/qualification set per endpoint plus a
bounded persisted high-water row; old rows remain in the separately capped
historical archive. No O/M/A route may initiate an upstream query on read.
Required actual controls: one valid activated generation; identical duplicate
does not refresh; lower generation after higher archives but never becomes
current; changed same-generation hash quarantines across reopen; new epoch
without activation refuses; missing measured transit stays unknown; elapsed
queue/read can turn fresh to stale; source/plan/raw-scope or role-window splice
refuses; clock-unknown keeps relative age distinct from role/remote-clock
claims. Neither a good archive ACK nor a candidate comparison is a rule fact.

## Independent O absence control

The existing isolated subprocess test uses an outside HTTP client to read the
O heartbeat during invalid witness source and failed delayed notice. The next
assertion stops that process and requires the outside client to observe the
heartbeat route's absence. It is a test-only absence witness, not an external
production receiver or an invented O dead-man threshold. Delivery failure
remains distinct from M/V health. A production independent receiver and its
failure-domain/deadline configuration remain unverified.
