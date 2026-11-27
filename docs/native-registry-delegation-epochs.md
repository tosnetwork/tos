# Native registry delegation withdrawal and authorization epochs

Status: **design for non-author review; no contract or client implementation**.
This does not authorize deployment, a network reset or changing existing Agents.

Source pins: tos `fabd9ffe4238a61e16184cecf6020770953e19a4`; ai
`77447f22fb225c3f164403bc9e411ff13067d109`. Requirements are ai
`spec/docs/MESSENGER_TRANSPORT_V2.md` sections 5.1, 17 and 18 Q1, and the
coordinator's delegated decisions 24 and 31. The requirements belong to that
specification; this document defines the separate registry/client delivery.

Upstream comparison: fetched upstream default
`99143587e6babb2e577eadea0fc741cb1b413fab` has no
`crypto/smartcont/native-registry-code.fc` or matching native Agent registry.
The contract and ai mirror are TOS-specific; no upstream fix is being replaced.

## 1. Invariants and current gaps

The registry currently stores an Agent root with generation, sequence and last
action hash, policy, one delegation dictionary and pending recovery
(`native-registry-code.fc:482-509`). A delegation is a digest with a one-bit
value (`:763-771`); no admission epoch or selective withdrawal exists. Policy
update retains that dictionary (`:759-762`), while recovery completion and
tombstone clear it (`:780-792`). Generation changes only at recovery completion;
sequence changes for every mutation (`:679-697`). Neither is an authorization
epoch. Do not derive the new epoch from either value or the policy hash.

Required state-machine invariants:

- Registration establishes authorization epoch **1**. Policy update, including
  identical policy bytes, recovery completion and tombstone increment it once.
  All other actions leave it unchanged. Overflow refuses atomically.
- Add and withdrawal bind their payload to the current epoch. Admission records
  that epoch. A verifier requires encoded epoch = admission epoch = current epoch.
- Withdrawal changes one live digest to withdrawn without changing the epoch,
  other digests or total admissions. It cannot fail because either count is full.
- Within an epoch, at most 128 digests are live and at most 384 have ever been
  admitted. Re-admission of a withdrawn digest is refused.
- Every epoch bump clears both logical sets and restores admission capacity.
  No migration/downgrade resets an existing epoch or reuses an Agent identity
  as a supposedly new epoch-1 account.
- An exact replay of the last action is a no-op, including after tombstone or
  at epoch maximum; an older replay fails predecessor/sequence checks. Neither
  case increments an epoch or changes a delegation twice.

The phrase “full until the next bump” is interpreted literally: after an add
reaches either bound, admission is latched closed for that epoch. Withdrawing
from 128 live to 127 does not reopen it. The explicit bit below encodes this;
review must confirm this interpretation before implementation rather than
silently relaxing it to current-count-only checks.

## 2. Storage: versioned Agent root and one tagged dictionary

Keep the registry's outer data/config encoding and Capability state encoding
unchanged. Version **only the typed Agent state** explicitly:

```text
AgentState schema 2 (ordinary root):
  magic:uint32 = NVS1
  schema:uint16 = 2
  object_kind:uint8 = 1
  tombstone:Bool
  generation:uint64
  sequence:uint64
  last_action_hash:uint256
  authorization_epoch:uint64       // strictly positive
  ^policy ^delegations ^recovery

Delegations (ordinary wrapper):
  live_count:uint16                // 0 .. 128
  total_count:uint16               // live .. 384
  admission_closed:Bool
  entries:HashmapE 256 Entry

Entry (inline ordinary leaf value, no references):
  admission_epoch:uint64           // equals Agent authorization_epoch
  withdrawn:Bool                  // 0 = live, 1 = withdrawn
```

The two sets are **logical views of one dictionary**, not two capacity-bearing
maps. Withdrawal overwrites a fixed-size leaf; it never inserts a second key,
allocates another logical slot, or increments total_count. This also avoids a
“withdrawn map full” branch. It still needs ordinary execution funding and
storage rent: “no space failure” is a logical capacity guarantee, not free gas,
free storage or recovery of a frozen account.

The root grows from **441 to 505 bits**, still three references. The empty
wrapper grows from 17 to **34 bits**. A dictionary value grows from 1 to 65 bits.
Counters are maintained from trusted admitted state; the on-chain mutation does
not enumerate 384 entries on every call. Strict external readers validate full
bounded shape, count equality, nonzero unique digest keys, exact leaf length,
no exotic/trailing cells, epoch equality and the live/withdrawn partition.
`admission_closed = false` is invalid when either current bound is reached;
`true` may persist below 128 live after withdrawals.

A bump writes an empty wrapper with counts zero, closed=false and no dictionary
root. Dropping the old reference does not walk/rewrite individual digests in the
contract. Full transaction storage-statistics and pruning costs are still tested;
constant VM work is not a claim of zero node-side storage work.

Capability roots remain schema 1/kind 2. Every decoder dispatches on both kind
and schema; it must not accept schema 1 as an epoch-aware Agent or interpret
Capability owner bits as an epoch. Unknown schemas refuse.

## 3. Measurements: exact scope, bounds and remaining gas gate

No prototype registry action was implemented. Measurements below constructed
only candidate **data fixtures** using the existing Fift dictionary builder and
ran the existing generic `DICTUSETB` instruction at global version 16. They do
not execute a proposed new withdrawal entry point.

Tool: Fift built from `b9a5a0406193d3577022b5c856bab9f77836f58b`, SHA-256
`a6a382c33d1f2a2a58c2a2990f3d427a3f64ade9408350067a7ffc5d6be0e69d`.
There is no diff in `crypto/vm/` or `crypto/fift/words.cpp` between that build's
source and the tos design pin. Current `Asm.fif` was used, with version 16
explicitly supplied to `runvmx` and a 2,000,000 gas limit.

| Key shape | Live / total | Unique cells | Stored bits | References | Depth | Serialized BOC bytes | Isolated leaf overwrite gas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Empty | 0 / 0 | 1 | 34 | 0 | 0 | 18 | not applicable |
| Hash-shaped | 128 / 128 | 256 | 41,694 | 255 | 11 | 6,402 | 5,465 |
| Hash-shaped | 128 / 384 | 768 | 124,454 | 767 | 12 | 19,096 | 6,665 |
| Hash-shaped | 0 / 384 | 768 | 124,454 | 767 | 12 | 19,096 | 6,665 |
| Deep spine | 128 / 128 | 256 | 9,772 | 255 | 128 | 2,435 | 76,865 |
| Deep spine | 128 / 384 | 521 | 19,833 | 527 | 256 | 4,933 | 153,665 |
| Deep spine | 0 / 384 | 520 | 19,762 | 527 | 256 | 4,922 | 153,665 |

These are the wrapper plus its reachable dictionary cells, **excluding** policy,
pending recovery, Agent root, outer account data and code. Unique cell sharing
explains the spine's smaller size; its much larger operation gas demonstrates
why random digests alone are insufficient. The specification's approximate
12 KiB is not a billable full-state bound: even this hash-shaped wrapper has
about 15.2 KiB of bits and an 18.6 KiB BOC. BOC bytes are not storage-fee bytes.
Storage rent must use actual unique cell/bit counts and the deployment's CP18,
not multiply serialized BOC size by a guessed rate.

Reproduction inputs:

- Epoch 1, 384 keys, first `live` inserted keys live and the rest withdrawn.
- Hash-shaped key i: big-endian SHA-256 of UTF-8
  `registry-epoch-measure-` followed by the decimal i, i=0..383.
- Spine: `2^i` for i=0..255, followed by `2^255 + j`, j=1..128.
- Build entries with Fift `udict!`, 256-bit unsigned keys and inline values
  `<b 1 64 u, withdrawn 1 u, b> <s`; serialize the specified wrapper using
  `boc>B`. Count unique representation hashes, bits, references and depth from
  the BOC. The first chosen key is the overwrite target.
- Kernel stack is value-builder, key, dictionary; code is
  `<{ 256 PUSHINT DICTUSETB }>s`, run with gas limit 2,000,000 and version 16.
  It returned exit 0 in every nonempty case. Gas includes this tiny program's
  dispatch and implicit return, **not** an authorization, lookup/check, wrapper
  counter update, outer state save or transaction action phase.

Selected fixture SHA-256 values:

| Fixture | BOC SHA-256 |
| --- | --- |
| Hash-shaped 128 / 384 | `46e53c3410dab504084f4adeb67ed74bf62593dc139422e02b97a04fb3670241` |
| Spine 128 / 384 | `6500bedd13693665cb3e2e7c38935e16f82788b17b2dfb49166357d2d03d6e67` |

The **existing**, unchanged registry's supported-width measurement test passed
at the design pin (eight controllers, 2,000,000 transaction gas limit):

| Existing path | Measured gas |
| --- | ---: |
| register_agent | 92,005 |
| delegate_agent (empty set) | 82,352 |
| revoke_agent | 82,025 |
| update_agent_policy | 175,444 |
| initiate_recovery | 177,113 |
| complete_recovery | 83,390 |

Command: `cargo test --manifest-path tosctl/src/Cargo.toml --release --locked
-p contracts --test native_registry_sandbox
every_policy_path_fits_the_gas_ceiling_at_the_supported_width -- --nocapture`,
with explicit `TOS_ROOT`, `FUNC_PATH`, `FIFT_PATH` and external target directory.
One test passed. Existing warnings were not rewritten.

**Unmeasured and not claimed:** complete new add/withdraw/bump transaction gas,
fees, maximum signed-message size and total account rent at the bound. Those
require the reviewed implementation. Do not add the baseline and kernel numbers
to invent a total. Implementation acceptance must measure them through both
engines with one and eight signers, 128/384 populations, deep/clustered/hashed
keys, cold and repeated paths, actual storage statistics and CP18/20/21/43.
Every authority-changing path and withdrawal must stay inside the existing
80%-of-transaction-gas release ceiling. A bound that cannot withdraw or bump
is a failed implementation, not permission to lower the requirement silently.

Measured artifacts are retained outside Git through design review and for at
least 30 days; the draft review receipt gives their local artifact directory.
The small index below binds the exact measurement inputs/results without
checking build output into the source tree. Fixture generation is measurement
scaffolding only, not a registry action implementation.

| Retained artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `measure.py` | 2586 | `bb8f7050cefe146194b5d83887000f8b2b7b293736ae2cdea25684202fe469bf` |
| `cells-and-kernel.json` | 2716 | `f32d6230ba2e7c4b0e354697374b78f62a497f10543cd13dc7d50aee6b0df4d9` |
| `registry-design-baseline-gas.log` | 9453 | `fb15825c0566306686698eee6b37bc546c8e118a867107bcd833c0b65c4f7001` |

## 4. Action encoding, checks and update order

Keep the signed action envelope NVA1/schema 1, network/code binding, predecessor,
generation and sequence rules. Contract code identity changes, so an old contract
cannot accidentally accept the expanded payload. Current kind 3 remains add;
allocate **kind 11** for withdrawal (current action kinds are 1 through 10).
Mirror it as `KindWithdrawAgentDelegation`; it is not a generation-reset action.

```text
DelegateAgentV1 payload:           digest:uint256 expected_epoch:uint64
WithdrawAgentDelegationV1 payload: digest:uint256 expected_epoch:uint64
```

Both use the existing delegation-purpose threshold, no counterparty signatures,
and no new off-chain authority. Each payload ends exactly, rejects digest zero
and epoch zero, and signs the expected epoch as part of the action cell hash.

Common path, preserving the current replay boundary:

1. Bound and strictly parse the ordinary envelope, references, kinds, target and
   domain. Keep the current counterparty-signature shape restrictions.
2. Verify network and contract code domain; decode the correctly versioned state.
3. If the stored last_action_hash equals this action hash, return without a
   transition, as at `native-registry-code.fc:687`. This precedes the tombstone,
   predecessor, next-sequence and epoch-overflow checks. A re-signed copy is the
   same action; query id is transport context, not a second mutation.
4. For a new action, reject tombstone, wrong predecessor, wrong generation or
   sequence. Keep checked u64 generation/sequence increments and reset sequence
   to 1 only for existing recovery-completion semantics. Epoch is independent.
5. Strictly parse the action payload and check cheap shape/epoch/capacity
   preconditions. Check threshold authorization under the current policy, with
   existing possession/consent rules where a new policy is admitted. No state
   is saved if any check/signature fails.
6. Construct the complete next state with checked counters/epoch; atomically
   save once. There is no intermediate state with the epoch changed but live
   entries retained, nor live removed without withdrawn recorded.

| Action | Checks after common replay/order checks | State transition |
| --- | --- | --- |
| Register Agent | Absent target, existing identity derivation/initial-policy possession and consent | Epoch 1; empty entries; open admission; existing generation/sequence 1 |
| Add delegation | expected_epoch=current; nonzero digest absent from both logical sets; admission not latched; live<128 and total<384; delegation-purpose authorization | Insert `(current_epoch,false)`; checked live+1,total+1; latch admission if either resulting bound is reached; epoch/policy/recovery unchanged |
| Withdraw delegation | expected_epoch=current; digest exists, admission_epoch=current, withdrawn=false; same purpose authorization | Flip withdrawn=true; checked live-1; total/epoch/closed flag unchanged; no capacity check and no separate-map insert |
| Update policy | Current-policy authorization, new-policy possession and shape/threshold rules, epoch<MAX | Epoch+1; new policy, both sets cleared, admission reopened; clear pending recovery even for identical policy bytes |
| Initiate recovery | Existing recovery authorization/new-policy possession and timelock checks | Pending recovery changes only; epoch, entries and admission flag unchanged |
| Complete recovery | Exact pending initiation, initiating-policy hash, timelock and recovery authorization; generation and epoch below MAX | Existing generation reset, epoch+1; promote policy; clear recovery and both sets; reopen admission |
| Tombstone | Existing Agent-control authorization, epoch<MAX | Epoch+1; tombstone=true; clear recovery/both sets; no future action except exact replay |
| Capability operations | Existing owner/threshold, generation/sequence/version checks | No owner-Agent epoch change; Capability root schema remains 1 |

A duplicate digest in a **new** add action refuses; identical last-action replay
succeeds as a no-op. Withdrawing a non-live or already withdrawn digest refuses;
exact replay succeeds. At epoch MAX, add/withdraw are still permitted subject to
normal bounds; bumps refuse before any save. Do not wrap to zero, saturate and
pretend to bump, or exempt tombstone from checked overflow.

Allocate these currently unused registry errors consistently in FunC, Rust,
Go and vectors: **2216** epoch mismatch, **2217** epoch exhausted, **2218**
withdrawn digest, **2219** admission closed/capacity, **2220** digest not live.
Existing envelope, duplicate-live-digest and authorization errors keep their
meanings. Re-check collisions at the implementation base; a collision requires
reviewed renumbering before vectors, not diverging tables across clients.

## 5. Getter, client and projection contract

`get_native_state()` keeps its `(state,found)` result, returning the versioned
cell; `get_native_config()` keeps its six-item static identity tuple. No new
unbounded getter or separately refreshed epoch getter is needed. Clients decode
one authenticated account state at one finalized checkpoint, then derive epoch,
live/withdrawn entries, counts, policy hash and admission epochs from that cell.
Never join membership at one block to epoch at another.

Rust `NativeRegistryState`/Agent detail gain epoch, counts/closed and typed
entries. Replace delegation use of generic `native_dict_contains` with a typed
lookup returning admission_epoch and withdrawn. Do **not** change that generic
helper's meaning for Capability version dictionaries. Update the Agent-policy,
parts/replay and owner-authorization parsers; keep Capability offsets distinct.

Proposed ai representation (still the one `tos_service_v1` protocol):

- Add AgentStateV1 fields **12** authorization_epoch (u64), **13** repeated
  DelegationAdmissionV1, **14** admission_closed (bool), **15** encoding_version
  (u32, value 2). The digest-sorted entry has fields 1 digest, 2 admission_epoch
  (u64), 3 withdrawn (bool). Bound the collection at 384 and live entries at 128.
- Replace the old digest-only field; reserve its protobuf number 6 rather than
  retain a second mutable membership authority. Use the unused tags listed here in
  both spec and API proto; regenerate Go/schema outputs from spec first.
- DelegateAgentV1 gains required positive authorization_epoch at field **2**.
  Add WithdrawAgentDelegationV1 fields 1 digest/2 epoch, selected by NativeActionV1
  oneof field **30** (the current oneof ends at 29). Update purpose dispatch and the
  native wallet/relayer's action-specific preflight from the same finalized read.
- Portable projections include state encoding version, current epoch, typed
  entries and the closed flag, with strict canonical ordering. They remain
  interchange views, never accepted as on-chain authority or next state.
- `toschain/simplified_native.go` and the shared nativecore decoder return the
  same validated state. Build the real agenttransport epoch-aware adapter from
  **one** resolved state, populating State, CurrentEpoch, AdmissionEpochs (live
  only) and EpochCheckpoint together. No additional history/timestamp dependency.

Messaging Endpoint delegation is currently wire schema
`tos.messaging.endpoint-delegation.v2`. Introduce strict schema/domain
`tos.messaging.endpoint-delegation.v3` and encode the u64 epoch immediately after the Agent id in its canonical
preimage and JSON. Missing/zero/stale/future epochs refuse. Update Validate,
CanonicalBytes, Digest, Encode/Decode, issuance and VerifyWithCheckpoint together.
The verifier requires membership live, encoded=admitted=current, same network,
code-pinned finalized state and the existing time/purpose checks. Do not retain
a legacy endpoint decoder as a fallback in the production verifier.

Transport delegation already includes the epoch in its 167-byte encoding;
its wire bytes do not change. The current production gate remains closed until
an actual finalized schema-2 registry and real epoch-aware adapter are deployed.
Remove no gate merely because synthetic Snapshot tests pass. During the existing
pre-rollout phase, any reviewed legacy test-network exception stays isolated from
production. On coordinated schema-2 rollout, migrate test fixtures to real epochs
and retire the obsolete legacy-only adapter/mode; there is no compatibility duty
to keep old funded identities usable under the new code. Epoch zero is never
inferred for a failed new decode. Historical schema-1 inspection, if retained,
cannot feed a production authorization resolver.

Caching keeps the existing 300-second refresh / 600-second failure bounds. A
newly observed withdrawal, epoch mismatch or tombstone is a refusal, not an
availability error that can revive an old cached pass. All issuance tooling
(tosctl, nativewallet/tos-service-wallet, agenttransport and endpoint builders)
reads current epoch before building/submitting and checks it again at signing
preflight; a concurrent bump is an ordinary stale-predecessor/epoch refusal.
The registry cannot inspect an opaque digest's embedded epoch; verifier equality
is therefore essential, including for manually crafted future-epoch documents.

Decision 31 stays unchanged: relay per-issuer limits/default channels use verified
issuer_chain, uniqueness uses `(credential_id,nonce)`, and explicit lane/default
issuer keys have distinct namespaces. An epoch bump/withdrawal does not clear
replay history or accept unverified issuer identity as a shortcut.

## 6. Caller and release inventory

Searches, run on both pins, not inferred from memory:

```text
git grep -n -E 'native.registry|native_registry|NATIVE_REGISTRY'
git grep -n -E 'DelegateAgentV1|DelegationDigests|AgentStateV1'
git grep -n -E 'DecodeData\(|DecodeDataAny\(|DecodeRegistryTransition\('
git grep -n -E 'MessagingEndpointDelegation|endpoint-delegation|AdmissionEpoch|CurrentEpoch'
```

Tos runtime/build consumers:

- `crypto/smartcont/native-registry-code.fc`: common replay, Agent helpers,
  registration/update/delegate/recovery/revoke and owner authorization.
- `tosctl/src/node-control/contracts/src/native_registry.rs`: action constants,
  required purpose, payload builder, typed state/lookup and next-position checks.
- `tosctl/src/node-control/commands/src/commands/nodectl/native_registry_cmd.rs`:
  CLI action enum/options, builders, finalized preflight and inspect output.
- Sibling commands `agent_cmd.rs`, `agent_cmd/mldsa44.rs`, `service_actor_cmd.rs`,
  `service_actor_token_cmd.rs`, `mod.rs`: new registry identity/CLI dispatch.
- Sibling contracts `lib.rs`, `agent_account_auth.rs`, `agent_account_custody.rs`,
  `agent_account_reconfigure.rs`, `service_actor.rs`, `service_actor_token.rs`:
  owner-Agent state decoding and code/identity/release pins; do not add epoch
  bumps to ordinary Capability or Agent-account wallet operations.
- `scripts/build-tos-service-native-registry-v1.sh`,
  `embed-tos-service-native-registry-v1.sh`, `tos_service_native_registry_release.py`,
  `tos_service_native_registry_pq.py` and corresponding `test_*` scripts:
  regenerate the reviewed contract release, not a stale frozen BOC.
- `CMakeLists.txt`, release artifact inventory and source-guard/hygiene/build
  workflows: update the registry artifact/version inputs and validation guards.
  Use a new contract release revision (v2) rather than silently replacing a
  frozen v1 artifact. The application protocol remains tos_service_v1.

Ai direct runtime readers/builders (paths relative to ai):

- `protocol/pkg/nativecore/{action,errors,state,projection,relay,registry_transition}.go`
- `protocol/pkg/nativewallet/wallet.go`, `protocol/cmd/tos-service-wallet/main.go`
- `protocol/pkg/toschain/{simplified_native,registry_transition,guarantor_authority}.go`
- `protocol/pkg/agenttransport/{verify,chain,legacy}.go`: new real adapter and
  explicit schema/production gating; no synthetic epoch inference.
- `messenger/pkg/identity/{delegation,chain}.go`, `messenger/internal/canon`:
  canonical schema/domain, finalized verifier and issuance boundary.
- `messenger/pkg/daemon/finalized.go`: finalized endpoint and packet adapters.
- `protocol/pkg/agentpacket/packet.go`, `protocol/pkg/buyersdk/provider_card.go`,
  `provider/pkg/servicebridge/{preflight_relay,receiver,relay_cards}.go`: typed
  Agent consumers/code pins; preserve their separate signature/purpose checks.
- `protocol/internal/purchasefixture/fixture.go` and
  `protocol/pkg/agentpacketseal/keycardtest/keycardtest.go`: fixture state shape.
- `spec/proto/tos/service/v1/native.proto`, `protocol/api/tos/service/v1/native.proto`,
  generated `protocol/gen/tos/service/v1/native.pb.go`, generated schemas and
  native/transport/endpoint vector generators and their consumers.

Supporting tos scripts found by search: `agent-account-mldsa44-strict-rehearsal.py`,
`agent-economy-composed-e2e.py`, `prediction-market-v1-lifecycle-e2e.py`,
`service-actor-e2e.py`, `tos-service-agentpacket-buyer-deploy.py`,
`tos-service-native-registry-local-gate-c.py`, `tos-service-paid-demand-native-fixture.py`,
`tos-service-software-work-capability-deploy.py`, the native registry lifecycle
shell gates, `check-no-legacy-escrow.py` and `x02_four_node_inputs.json`.
Some need only new release pins/fixture expectations; the implementation must
record that classification rather than churn unrelated behaviour.

Tests/fixtures and docs to update in the same coordinated delivery:

- Tos registry/capability/Agent-account/service-actor/token-actor sandbox consumers,
  `tests/fixtures/native_registry/` (protocol, authority and guarantor signatures),
  native release/PQ/lifecycle guard tests and release manifests.
- Ai nativecore action/state/relay/projection and transition vectors/tests;
  `protocol/pkg/nativecore/testdata/native_registry_v1_vectors.json`;
  `spec/test-vectors/tos-service-v1-registry.json`; `protocol/cmd/native-vector-reference`.
- Ai agenttransport verifier/network/credential/reachability vectors and
  `protocol/scripts/agenttransport-mutants.py`; endpoint delegation/chain tests.
- Every Agent-state fixture in messenger admission, packet bridge, attachments,
  contact, daemon, directory and mailbox; protocol buyer/provider/service-actor,
  purchaseevidence, quoteprovider, discovery, DNS/guarantor/keycard fixtures;
  provider servicebridge and execution railgate fixtures. Re-run the searches
  above after regeneration; no digest-only membership read may remain hidden.
- Normative ai `NATIVE_REGISTRY_STATE_MACHINES.md`,
  `MESSENGER_TRANSPORT_V2.md`, `AGENT_NATIVE_MESSENGER_V1.md`, native/messenger
  wire-format documentation and release/deployment metadata. This design PR does
  not edit those normative schemas yet; their coordinated update precedes code.

This inventory identifies users that must change **or be proven unchanged**;
it is not a request to rewrite all those modules. Keep historical records marked
as historical. Code-hash changes also change deterministic account addresses;
never update a pin without recomputing the matching StateInit/address fixtures.

## 7. Vectors, tests and sensitivity controls

Use independently reproducible Rust and Go builders plus the real FunC contract.
Freeze inputs, action BOC/hash, before/after typed cells/hashes, counts, epochs,
withdrawal flag and expected exit codes. Generate signatures and hashes; do not
transcribe them. Every vector records the exact release code and network domain.

Required vector sequences:

1. Register E=1; add A and B at E=1; withdraw A; B remains valid; re-add A
   refuses; replay the withdrawal is a no-op.
2. Policy A→B→A and same-bytes A→A: epoch advances every time, both sets clear,
   and the old delegation never verifies simply because the hash matches again.
3. Recovery initiate leaves E/membership unchanged; complete advances E exactly
   once and clears both sets. Wrong initiation/hash/timelock/signatures refuse.
4. Tombstone advances E and clears; exact replay after tombstone does not bump;
   every different subsequent action refuses.
5. Crafted encoded E+1 digest admitted with expected E is unusable at E; after
   bump it is absent. Tooling refuses issuing it; if the actual Agent authority
   deliberately admits it anew at E+1 that is a new authorized admission, not
   a claimed defense against the Agent's own authority.
6. Epoch 0/MAX-1/MAX, stale/future expected epoch, overflow on each bump and
   generation/sequence overflow; exact-last-action and older replays.
7. 128 live, then withdrawal: admission remains latched until bump; separately
   churn below 128 to total 384. Construct 128 live/256 withdrawn, withdraw at
   full total, then 0 live/384 withdrawn. Add refuses; update/complete recovery
   clears and admits again. No early bump/withdraw failure due to count.
8. Malformed version/kind, counter mismatch, total<live, >384 entries, duplicate
   keys, wrong admission epoch, missing leaf bits, trailing bits/refs/exotic
   cells, missing epoch metadata and mixed-block projections all refuse.
9. Endpoint epoch/digest vectors and real finalized adapter; healthy cache
   revocation, unavailable-read cutoff, wrong registry/network and production
   epoch-zero refusals. Decision-31 replay/namespace/isolation tests stay green.
10. Capability owner authorization/version/transfer/tombstone regression vectors
    preserve their current sequence/generation semantics without Agent epoch bumps.

Bound/resource gate: eight-controller and one-controller actions at all four
populations and adversarial key shapes, every withdrawal position, registration,
identical/disjoint update, initiate/complete recovery, tombstone, rejected add and
replays. Measure gas, storage cells/bits/depth, fees, message bytes and out actions
with Rust transaction execution and native replay. Include insufficient funding
and account limits, while distinguishing those from forbidden capacity refusal.
Clearing all references is tested for actual post-transaction storage reduction.

Sensitivity controls must each fail a named assertion, not collection/compile
errors: omit each epoch bump; bump on add/withdraw/initiate; wrap/saturate MAX;
check overflow before exact replay; preserve either set on bump; ignore expected
or admission epoch; permit withdrawn re-add; clear the admission latch on
withdraw; add a capacity check to withdrawal; weaken each 128/384 bound; drop
stored counts or leaf-shape checks; accept legacy schema/epoch zero in production;
join two checkpoints; skip endpoint canonical epoch binding; treat observed
revocation as ErrUnavailable; leave a CLI/relay caller on digest-only preflight.
Keep independent red controls for live cap, total cap and their reset.

Fuzz small valid action sequences against a simple Go reference set model and
the real contract: after every result compare the complete state and permitted
future actions, not just the final count. Shrink failures; persist the seed and
minimal failing sequence. Counter/epoch mutations include every boundary.

## 8. Rollout and migration boundary

1. Non-author design approval; settle the sticky admission interpretation and
   freeze action/error/field numbers. No implementation in this PR.
2. Coordinated normative ai schema/vector plan, FunC/Rust release implementation,
   Go mirror/projection/readers and both delegation verifiers/builders. Keep the
   production transport gate closed while any layer is incomplete.
3. Generate and pin the new frozen contract release; source/artifact checks,
   spec/schema/boundary checks, focused Rust/Go suites, Go race tests, mutants
   and source guards. Use `GOWORK=off` for worktree Go/make commands.
4. On a separately approved pre-launch **local** namespace, deploy new registry
   identities with fresh registration nonces. Do not reset the existing local
   bridge/USDT network or operate on existing funded Agents for this rehearsal.
   Run the vector sequences as real finalized transactions; retain per-step
   BOCs/verifier results and reconstruct on independent reference endpoints.
5. Only after measured full-action gas/space limits, real epoch-aware transport
   admission, endpoint revocation and multi-client vectors pass may the production
   registry gate open. Public deployment still needs its own authorization.

There is **no automatic in-place migration from schema 1**: it has no known
monotonic authorization epoch, so setting an existing identity to 1 would invent
history. Code changes alone alter the account address but **do not** alter the
Agent id (which depends on registration nonce, policy and network). Therefore a
fresh code address with the same Agent id is not an acceptable “new” epoch-1
identity; use a fresh nonce/id, or a future separately reviewed migration that
carries a proven monotonic epoch. No alias silently maps old delegations onto it.

Any future schema-2 migration must preserve or explicitly advance the existing
u64 epoch and exact state linkage, never reset/wrap it. There is no epoch-lowering
rollback. If rollout fails, keep production disabled and use the original
namespace for its existing work; do not reinterpret new-format state with an
old reader. No backward-compatibility product path is introduced.

## Appendix: frozen search-hit inventory

These are search hits at the pinned revisions, including compile-time fixture
consumers. Runtime changes are classified above; a hit is not by itself a claim
that its behaviour must change. Regenerate this inventory when rebasing the
implementation. Historical checkpoint prose is excluded from the caller list.

### Tos paths

```text
.github/workflows/source-guards.yml
.github/workflows/source-hygiene.yml
.github/workflows/tosctl-nixos.yml
crypto/smartcont/native-registry-code.fc
crypto/smartcont/tos-service-native-registry-v1.release.json
scripts/agent-account-mldsa44-strict-rehearsal.py
scripts/agent-economy-composed-e2e.py
scripts/build-tos-service-native-registry-v1.sh
scripts/check-no-legacy-escrow.py
scripts/embed-tos-service-native-registry-v1.sh
scripts/prediction-market-v1-lifecycle-e2e.py
scripts/service-actor-e2e.py
scripts/test-tos-service-native-registry-tvm-lifecycle.sh
scripts/test-tos-service-native-registry-v1.sh
scripts/test_tos_service_native_registry_pq.py
scripts/test_tos_service_native_registry_release.py
scripts/tos-service-agentpacket-buyer-deploy.py
scripts/tos-service-native-registry-local-gate-c.py
scripts/tos-service-paid-demand-native-fixture.py
scripts/tos-service-software-work-capability-deploy.py
scripts/tos_service_native_registry_pq.py
scripts/tos_service_native_registry_release.py
scripts/x02_four_node_inputs.json
tosctl/src/node-control/commands/src/commands/nodectl/agent_cmd.rs
tosctl/src/node-control/commands/src/commands/nodectl/agent_cmd/mldsa44.rs
tosctl/src/node-control/commands/src/commands/nodectl/mod.rs
tosctl/src/node-control/commands/src/commands/nodectl/native_registry_cmd.rs
tosctl/src/node-control/commands/src/commands/nodectl/service_actor_cmd.rs
tosctl/src/node-control/commands/src/commands/nodectl/service_actor_token_cmd.rs
tosctl/src/node-control/commands/src/commands/nodectl/service_actor_token_cmd_tests.rs
tosctl/src/node-control/contracts/src/agent_account_auth.rs
tosctl/src/node-control/contracts/src/agent_account_custody.rs
tosctl/src/node-control/contracts/src/agent_account_reconfigure.rs
tosctl/src/node-control/contracts/src/lib.rs
tosctl/src/node-control/contracts/src/native_registry.rs
tosctl/src/node-control/contracts/src/service_actor.rs
tosctl/src/node-control/contracts/src/service_actor_token.rs
tosctl/src/node-control/contracts/tests/agent_account_mldsa44_sandbox.rs
tosctl/src/node-control/contracts/tests/agent_account_mldsa44_strict_sandbox.rs
tosctl/src/node-control/contracts/tests/native_registry_sandbox.rs
tosctl/src/node-control/contracts/tests/service_actor_sandbox.rs
tosctl/src/node-control/contracts/tests/service_actor_token/capacity.rs
tosctl/src/node-control/contracts/tests/service_actor_token/ported.rs
```

### Ai state/delegation paths

```text
execution/pkg/railgate/fixture_test.go
messenger/pkg/admission/admission_test.go
messenger/pkg/admission/invite_review_test.go
messenger/pkg/agentpacketbridge/bridge_test.go
messenger/pkg/attachments/finalized_test.go
messenger/pkg/contact/resolver_test.go
messenger/pkg/daemon/agent_packet_send_test.go
messenger/pkg/daemon/daemon_test.go
messenger/pkg/daemon/finalized.go
messenger/pkg/daemon/inbound_test.go
messenger/pkg/daemon/relay_review_test.go
messenger/pkg/daemon/relay_test.go
messenger/pkg/directory/directory_test.go
messenger/pkg/directory/relay_test.go
messenger/pkg/identity/chain.go
messenger/pkg/identity/delegation.go
messenger/pkg/identity/delegation_test.go
messenger/pkg/mailbox/finalized_test.go
protocol/api/tos/service/v1/native.proto
protocol/cmd/native-vector-reference/main.go
protocol/cmd/tos-service-wallet/main.go
protocol/gen/tos/service/v1/native.pb.go
protocol/internal/purchasefixture/fixture.go
protocol/pkg/agentguarantor/native_authority_test.go
protocol/pkg/agentpacket/packet.go
protocol/pkg/agentpacket/packet_test.go
protocol/pkg/agentpacketseal/keycard_test.go
protocol/pkg/agentpacketseal/keycardtest/keycardtest.go
protocol/pkg/agenttransport/chain.go
protocol/pkg/agenttransport/legacy.go
protocol/pkg/agenttransport/verify.go
protocol/pkg/agenttransport/verify_test.go
protocol/pkg/buyeragent/carrier_test.go
protocol/pkg/buyeragent/market_test.go
protocol/pkg/buyerinit/fixture_test.go
protocol/pkg/buyerinit/init_test.go
protocol/pkg/buyersdk/provider_card.go
protocol/pkg/buyersdk/service_actor_buyer_test.go
protocol/pkg/dnsalias/dnsalias_test.go
protocol/pkg/nativecore/action.go
protocol/pkg/nativecore/action_test.go
protocol/pkg/nativecore/projection.go
protocol/pkg/nativecore/registry_transition.go
protocol/pkg/nativecore/relay.go
protocol/pkg/nativecore/relay_refresh_test.go
protocol/pkg/nativecore/relay_resign_test.go
protocol/pkg/nativecore/relay_test.go
protocol/pkg/nativecore/state.go
protocol/pkg/nativewallet/wallet.go
protocol/pkg/providersdk/provider_test.go
protocol/pkg/purchaseevidence/token_test.go
protocol/pkg/quoteprovider/token_test.go
protocol/pkg/serviceactor/verify_test.go
protocol/pkg/serviceactorindex/discovery_test.go
protocol/pkg/toschain/guarantor_authority.go
protocol/pkg/toschain/registry_transition.go
protocol/pkg/toschain/simplified_native.go
protocol/scripts/agenttransport-mutants.py
provider/pkg/servicebridge/gate_fixture_test.go
provider/pkg/servicebridge/preflight_relay.go
provider/pkg/servicebridge/preflight_test.go
provider/pkg/servicebridge/receiver.go
provider/pkg/servicebridge/relay_cards.go
provider/pkg/servicebridge/relay_test.go
provider/pkg/servicebridge/setup_fake_test.go
provider/pkg/servicebridge/token_test.go
provider/pkg/servicebridge/transport_test.go
spec/docs/AGENT_NATIVE_MESSENGER_V1.md
spec/docs/MESSENGER_TRANSPORT_V2.md
spec/proto/tos/service/v1/native.proto
```
