# C05 witness contract and source plan — review draft

Baseline `88d5d95ad98413e035c4fec04a68c6306b5bb26d`; authority is memo
`C05-EXECUTION-ORDER-20260929.md` at `9558b9010639bb0030522c566ab26e21dc3438f9`
and R4 §§5.1, 7.1–7.2, 9, including the memo's C05 source-gap ruling. This is
a development contract proposal, not an approved production witness or
finality source.

Implementation checkpoint: closed plan/source DTOs, strict decoders, O
read-only cache with four generations per endpoint, development-only fixed
15-second owner, M historical archive, and M fixed cache collector are coded.
The restored contract/workspace suite passed; targeted runtime and mutation
evidence remains under review. Production source, restart/quarantine
restoration, current M/A rule qualification, deterministic proof, measured
source cost and deployment gates remain unsupported. The historical archive
ACK is not a current/fresh health fact.

## Reconciled source inventory

| Existing source | Actual capability | C05 consequence |
|---|---|---|
| `health-core/src/observer.rs` | Pure full block identity comparison and process/pipeline dead-men. No network/scope/point in `BlockIdentity`, no witness schedule or evidence. | Keep pure primitive; add separate closed typed witness contract. |
| `health-services/src/watchdog.rs`, `bin/health-watchdog.rs` | M heartbeat, Alertmanager pipeline and own notice. No chain witness. | Preserve independent O self-health; add a separate bounded witness lane, never classify O outage as V fault. |
| `health-services/src/collector.rs`, `manager.rs`, `durable.rs` | Edge snapshot archival and bounded immutable evidence storage; no witness route/adapter. | M accepts only O-retained validated witness records, not dynamic target or URL requests. No witness fact until validated archival and quality mapping. |
| `contracts/source-manifest.json`, `rule-manifest.json` | Witness adapter unsupported; `observer_disagreement` is `pending_C05`. | Keep production gate false and rule pending until actual adapter evidence exists. |
| `health-core/src/query_output.rs` | Five dimensions are fixed unknown/unavailable/not_checked placeholders. | Never fill them from a live RPC or infer proof/membership from a height comparison. Materialized evidence only. |
| Native C04 / edge | Consensus session/slot only; edge block anchors unsupported. Existing `getNodeConsensusStatus` is an on-demand manager query and partial block ID, not a cache-only finalized-block source. | No hidden V RPC fallback or slot→seqno conversion. C05 synthetic approved cache-only witness protocol can test external progress/reachability; production finality source remains unsupported pending a real source/cost contract. |

## Fixed development plan and global bounds

- At most **32 targets**, **16 unique approved HTTPS cache endpoints**, and
  **three endpoint IDs per target**. All endpoint IDs must resolve in the plan;
  no dynamic URL, redirect, query or path construction from a target. A fixed
  endpoint is polled **once per 15-second tick** for all referenced targets.
- At most **four actual local HTTP requests in flight globally**, at most one
  per endpoint; missed ticks skip, with no catch-up. Connect timeout 2 seconds,
  local response deadline 3 seconds, maximum 16 KiB decoded JSON per endpoint,
  maximum **32 target rows per endpoint response**, and 256 KiB total received
  bytes per tick. Count request bytes/egress separately;
  a future production profile must bind measured egress and server work.
- Retain at most four generations per endpoint (**64 total samples**) and
  **2 MiB total resident** for immutable raw bytes and bounded metadata.
  Parsed DTOs are not retained; an in-flight request reserves raw, typed-parse
  and index work before admission. A fixed conservative reservation of
  `5 × 16 KiB + 4 KiB` per active request is charged against that same 2 MiB
  cap until the parse completes; up to four requests may hold it. Retained
  entries are charged using `size_of::<CacheRecord>()`, raw `Vec::capacity()`,
  every retained `String::capacity()`, container capacity × element size,
  and an explicit allocator/index margin per entry. Endpoint/retired-epoch/
  quarantine arrays and the fixed plan are included in the resident sum;
  parse DTOs and body copies are transient and covered by the in-flight
  reservation. Admission refuses before crossing 2 MiB. This is a development
  accounted bound, not a whole-process heap measurement or a production
  performance gate. A sample is usable for at most
  **45 seconds from its original observation** when original age is known;
  the wire can report larger stale age without clamping it. A duplicate generation+hash
  does not renew age, while changed hash for that generation conflicts. A
  timeout marks remote work completion unknown and quarantines that endpoint
  from further polls; a late reply cannot publish. Any source-epoch switch
  within one in-memory plan/observer epoch is quarantined; production restart
  restore and retired-epoch lifecycle are not implemented. Only an explicit approved
  new plan revision **and new observer epoch** can clear that quarantine. A
  local timeout is not remote cancellation evidence.
- The plan fixes observer ID, observer epoch, target IDs/node IDs, network ID,
  genesis hash, raw scope workchain/shard and approved alias, role
  (`normal`, `probe_only`, `non_voting`) with UTC-Z valid-from/valid-until,
  endpoint IDs, and a bounded clock-skew allowance (development 5 seconds;
  production needs measured clock evidence). `probe_only` and `non_voting`
  grant only the same fixed HTTPS cache read, no P2P or private overlay access.

The **256 KiB per round** cap above is the sum of decoded upstream response
bodies, not total wire bytes. Fixed GET requests have no body; actual HTTP/TLS
headers, handshakes, retries and upstream work need separate measured egress
and server-cost evidence before any production gate. There is no retry within
a round. The O→M cache read is separate from upstream polling and is limited
to one fixed cache read per planned endpoint (up to 16), with a 32 KiB read
body and 32 KiB archive POST per endpoint generation. The M evidence writer
retains until its configured DB quota; an exhausted writer refuses receipt,
never silently evicts or declares a successful archive. At most 16 such
records are accepted per fixed 15-second collector round.

## Exact bounded DTO proposal

All objects deny unknown fields, all declared fields are required (nullable
where stated), decimal u64 values use the existing canonical `U64` parser,
and duplicate map keys are refused. Strings have these fixed bounds:
IDs/aliases 1..64 ASCII `[a-z][a-z0-9_-]*`; observer/source epochs 1..128
printable ASCII; network/genesis/root/file/session/candidate hashes exactly
64 lowercase hex; URL at most 512 bytes and fixed HTTPS with no credentials,
query, fragment or redirect; UTC-Z timestamps at most 40 bytes. No arbitrary
labels, events, nested JSON payloads or free-text reasons are accepted.

`WitnessPlan`: schema_version=1, revision hex64, observer_id, observer_epoch,
network_id, genesis, clock_skew_allowance_ms=5000 in the development profile,
`endpoints[1..16]` and `targets[1..32]`. Each endpoint has endpoint_id,
fixed_url, failure_domain alias and kind=`approved_cache_only_https`.
Each target has target_id, node_id, role enum
`normal|probe_only|non_voting`, valid_from/valid_until UTC-Z, scope_id,
workchain i32, shard decimal u64 and `endpoint_ids[1..3]` sorted unique.
Endpoint IDs, target IDs and target node+scope identities are unique. A target
must have a nonempty role window, and every endpoint reference resolves to a
plan entry. The plan network/genesis is the authority for every record.

`WitnessSource`: schema_version=1, endpoint_id, source_epoch, generation,
network_id, genesis, observed_at (required-nullable UTC-Z), source_age_ms
(required-nullable canonical u64; no artificial 45-second wire cap),
clock_quality enum `valid|unknown`, coverage enum `complete|partial|unknown`,
and `rows[0..32]` with unique target IDs. A row is accepted only if that
target's plan explicitly references **this endpoint**. Each row has target_id,
its own observed_at (required-nullable UTC-Z) and source_age_ms
(required-nullable canonical u64), anchor (required-nullable), network_observation enum
`observed|not_observed_in_window|unavailable`, reported_certificate_membership
enum `included|not_in_this_certificate|not_checked|unavailable`,
reported_proof enum `not_checked|reported_valid|unavailable`,
private_vote_visibility enum `observed|not_observed_in_window|unavailable`,
coverage enum `complete|partial|unknown`, and missing_fields (sorted unique,
max eight values from finite `anchor|private_vote|certificate|proof|clock|role`).
There are no other arrays or maps in the source DTO; every string is covered
by the fixed ID/hash/UTC/URL lengths above. Missing fields are sorted unique.
The source's top-level time/age never fills a row's missing original time/age;
a newer endpoint generation cannot freshen an older row.
Within one source generation the typed content, including original
source_age_ms values, is immutable. The `source_hash` is SHA-256 of the
validated typed DTO encoded as recursively object-key-sorted JSON (arrays
remain ordered); `raw_transport_hash` separately binds exact received bytes.
If an upstream cache emits a changing current age under one generation it
does not satisfy this development protocol and must not be silently treated
as a changed source fact. O computes current age from the immutable original
age plus measured duration and monotonic elapsed time.
There are no five-dimension local-action/persistence claims in this untrusted
upstream object. Missing or no single vote never asserts a local duty fault.

`BlockWitnessAnchor`: kind=`block`, network_id, genesis, scope_id,
workchain i32, shard decimal u64, seqno u32, root_hash and file_hash hex64,
point=`reported_finalized|reported_applied`. The point is explicitly a remote
report, not proof. `ConsensusWitnessAnchor`: kind=`consensus`, network_id,
genesis, scope_id, workchain i32, shard decimal u64, session_id hex64,
slot u32, candidate_id hex64 or null,
phase=`reported_candidate|reported_vote`. The two anchor kinds never coerce.
An unfinalized candidate is never a finalized block disagreement.
`masterchain` maps only to workchain -1 and shard 9223372036854775808;
every workchain -1 target uses that all-shard raw value. Each scope alias
maps to one raw tuple throughout the plan; node+scope alias is unique.

`ObserverCachedWitness` adds observer_id/observer_epoch, original source
identity and semantic/raw hashes, first received UTC-Z time, request_duration_ms,
original row age at first receipt, original row observer-clock quality,
monotonic elapsed duration, fixed plan revision and plan-content hash, plus
the original validated source JSON. The cache also emits conservative row
ages; qualification re-decodes this same bounded wire before use.
The public cache route is keyed by an endpoint ID from the fixed plan and
never performs network I/O. Source epoch/generation/hash are immutable:
same-generation/same-hash relay increments only a receipt counter, not
distinct samples or freshness; changed hash conflicts and quarantines;
regressed generation or source-epoch switch refuses. No retired-epoch history
or restart restoration is claimed in this development implementation. The
quarantine and inflight indices each have at most **16 endpoint entries**.
Observer heartbeat epoch is a separate lifecycle from witness source epoch
and never substitutes for it. M preserves O observer epoch as process epoch,
the original witness source epoch, endpoint ID + generation as source-record
identity, the original content hash, row times/ages and first receipt. It
deduplicates same identity+hash and quarantines changed identity+hash without
renewing original time. Archive success means durable M receipt only.

Freshness is each row's original source_age_ms + conservative measured request
duration + O monotonic elapsed since that row's **first** receipt, with
checked arithmetic. Null original age remains unknown and cannot claim fresh
progress. No remote/local wall-clock subtraction is used to manufacture a
precise age. O's own valid local UTC can assess the current configured role
window for polling; unknown remote UTC independently prevents proving that
role at the source observation time. Unknown remote clock alone does not
erase an independently known relative age, but it cannot authorize a
role-based fault or precise wall-clock duration. If valid remote observed_at
exceeds trusted O receipt UTC plus the measured plan skew allowance, qualify
`future_clock`, not a validator fault. A local request timeout never publishes a later reply
and cannot clear remote completion uncertainty. Only an operator-reviewed
new plan revision **and** new observer epoch may resume that endpoint; a
new source epoch alone, process restart or repeat request is not enough. An
approved owned cache-only endpoint may cite a separately proven server-side
completion bound during that operator review; until then its timeout follows
the same fail-closed quarantine path as a third party. No state transition
claims that remote work was cancelled.

## Closed evidence semantics to encode

- The endpoint's response is one strict bounded source generation containing
  `schema_version`, endpoint identity, source epoch, decimal-u64
  generation, network/genesis, source observed UTC-Z time, and at most 32
  target rows. One response can cover multiple planned targets. Each row has
  the target ID, explicit coverage/clock quality, and a tagged anchor:
  `block` carries network/genesis/scope/workchain/shard/seqno/root+file hashes
  and a reported point; `consensus` carries network/genesis/scope/raw-workchain/
  raw-shard/session/slot/
  candidate. Cross-kind comparison is forbidden.
- Five separate aggregate dimensions are always present: local action,
  network observation, certificate membership, proof verification and local
  persistence. A witness cannot assert local action or local persistence;
  absent separately retained local evidence leaves those `unknown`. Its
  `reported_valid` is not `locally_verified`; no deserializable witness value
  can authorize verified finality. Private single-vote invisibility remains
  partial, even for valid reported quorum excluding this node.
- Only matching network, genesis, scope and same-type full anchor context may
  produce `same` or `observed_disagreement`. Different genesis, session, slot,
  candidate status or invalid/future/stale source stays separately qualified.
  Highest height is never selected as truth. Raw differing reported-finalized
  blocks cannot emit `ConflictingVerifiedFinalityEvidence` without an approved
  deterministic local verifier (unsupported in C05 development).
- O exposes only its retained, already-fetched bounded generation to M;
  M's fixed collector polls every 15 seconds. Each archival POST is limited
  to **32 KiB**, one endpoint generation per request; it archives with original
  source time/hash and never
  creates an RPC path back to a witness. M/A cache miss yields unavailable.

## Planned negative controls

Actual isolated HTTP source → O timer/cache → M retained archive checks must
cover endpoint reuse and global counts; source timeout plus late server reply;
same height/different genesis; same slot/different session; unfinalized
candidate disagreement; wrong maximum height; quorum excluding local node;
absent visible private vote; cross-host future clock; role validity/permission;
O heartbeat and notification outage separately from V source failure; replay,
changed same-generation content, overflow/unknown fields, and no live query on
M/A read. Only changed-property compiled mutations will be run.
