# Native registry delegation withdrawal and authorization epochs

Status: **design for non-author review; no contract or client implementation**.
This does not authorize deployment, a network reset or changing existing Agents.

Source pins: tos `fabd9ffe4238a61e16184cecf6020770953e19a4`; ai
`77447f22fb225c3f164403bc9e411ff13067d109`. Requirements are ai
`spec/docs/MESSENGER_TRANSPORT_V2.md` sections 5.1, 17 and 18 Q1, and the
coordinator's delegated decisions 24, 31 and 33. The requirements belong to that
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

Decision 33 clarifies **refused while full**, not a sticky admission lock.
An add checks the current live and total counts. At 128 live, withdrawing a bad
key permits a replacement as soon as live is 127, provided total is below 384.
Total never decreases within the epoch, so the 384 bound remains closed until
a bump. There is no admission_closed bit, protobuf field or latch mutant.

## 2. Storage: versioned Agent root and one tagged dictionary

Keep the registry's outer data/config encoding unchanged. Both typed state
kinds use schema **2**. Agent gains the epoch; Capability retains its current
bit layout apart from the schema value:

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
wrapper grows from 17 to **33 bits**. A dictionary value grows from 1 to 65 bits.
Counters are maintained from trusted admitted state; the on-chain mutation does
not enumerate 384 entries on every call. Strict external readers validate full
bounded shape, count equality, nonzero unique digest keys, exact leaf length,
no exotic/trailing cells, epoch equality and the live/withdrawn partition.
The on-chain writer preserves these entry invariants; strict readers own their
validation against synthetic or malformed state. Count checks remain reachable
independently: live=128,total=128 refuses for live; live=127,total=384 for total.

A bump writes an empty wrapper with counts zero and no dictionary
root. Dropping the old reference does not walk/rewrite individual digests in the
contract. Full transaction storage-statistics and pruning costs are still tested;
constant VM work is not a claim of zero node-side storage work.

Capability roots use schema 2/kind 2 with the unchanged 697-bit header/owner
layout and version reference. Every v2 decoder requires schema 2 for either
kind. It must not interpret Capability owner bits as an Agent epoch or accept
schema 1 under a v2 code hash. Schema-1 decoding belongs only to the separately
pinned legacy release/profile, never a v2 verification fallback.

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
| Empty | 0 / 0 | 1 | 33 | 0 | 0 | 18 | not applicable |
| Hash-shaped | 128 / 128 | 256 | 41,693 | 255 | 11 | 6,402 | 5,465 |
| Hash-shaped | 128 / 384 | 768 | 124,453 | 767 | 12 | 19,096 | 6,665 |
| Hash-shaped | 0 / 384 | 768 | 124,453 | 767 | 12 | 19,096 | 6,665 |
| Deep spine | 128 / 128 | 256 | 9,771 | 255 | 128 | 2,435 | 76,865 |
| Deep spine | 128 / 384 | 521 | 19,832 | 527 | 256 | 4,933 | 153,665 |
| Deep spine | 0 / 384 | 520 | 19,761 | 527 | 256 | 4,922 | 153,665 |

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
| Hash-shaped 128 / 384 | `fa256b457843534d8271ed872adfbd8ee6c063aabba91cc10b779ef2b233fe8c` |
| Spine 128 / 384 | `7cbc927fc3e3a6296aebb72538e5c470fdf9db1b1b505c6dd20fbe6ebd53905b` |

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
Every changed successful path and refused add must stay at or below the existing
**800,000 gas** release ceiling (`NATIVE_REGISTRY_GAS_CEILING`), with the fixture
transaction limit fixed at **2,000,000 gas**; do not reinterpret that fixed
ceiling as 80% of the current limit. A bound that cannot withdraw or bump
is a failed implementation, not permission to lower the requirement silently.

Measured artifacts are retained outside Git through design review and for at
least 30 days; the draft review receipt gives their local artifact directory.
The small index below binds the exact measurement inputs/results without
checking build output into the source tree. Fixture generation is measurement
scaffolding only, not a registry action implementation.

| Retained artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `measure.py` | 2553 | `7e88b6dc3bb3a4ac03f69826f34e12b90468441ede54e342782e6b5b5462d0bf` |
| `cells-and-kernel.json` | 2716 | `d45dfd2ae80774e0cb8e7db521305f5c9c5c25292bfa18023aea094975217c84` |
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
| Add delegation | expected_epoch=current; nonzero digest absent from both logical sets; live<128 and total<384; delegation-purpose authorization | Insert `(current_epoch,false)`; checked live+1,total+1; epoch/policy/recovery unchanged |
| Withdraw delegation | expected_epoch=current; digest exists and withdrawn=false; same purpose authorization | Flip withdrawn=true; checked live-1; total/epoch unchanged; no capacity check and no separate-map insert |
| Update policy | Current-policy authorization, new-policy possession and shape/threshold rules, epoch<MAX | Epoch+1; new policy, both sets cleared; clear pending recovery even for identical policy bytes |
| Initiate recovery | Existing recovery authorization/new-policy possession and timelock checks | Pending recovery changes only; epoch and entries unchanged |
| Complete recovery | Exact pending initiation, initiating-policy hash, timelock and recovery authorization; generation and epoch below MAX | Existing generation reset, epoch+1; promote policy; clear recovery and both sets |
| Tombstone | Existing Agent-control authorization, epoch<MAX | Epoch+1; tombstone=true; clear recovery/both sets; no future action except exact replay |
| Capability operations | Existing owner/threshold, generation/sequence/version checks | No owner-Agent epoch change; Capability schema 2 with otherwise unchanged layout |

A duplicate digest in a **new** add action refuses; identical last-action replay
succeeds as a no-op. Withdrawing a non-live or already withdrawn digest refuses;
exact replay succeeds. At epoch MAX, add/withdraw are still permitted subject to
normal bounds; bumps refuse before any save. Do not wrap to zero, saturate and
pretend to bump, or exempt tombstone from checked overflow.

Allocate these currently unused registry errors consistently in FunC, Rust,
Go and vectors: **2216** epoch mismatch, **2217** epoch exhausted, **2218**
withdrawn digest, **2219** capacity full, **2220** digest not live.
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

Rust `NativeRegistryState`/Agent detail gain epoch, counts and typed
entries. Capability readers require schema 2 without shifting its fields. Replace delegation use of generic `native_dict_contains` with a typed
lookup returning admission_epoch and withdrawn. Do **not** change that generic
helper's meaning for Capability version dictionaries. Update the Agent-policy,
parts/replay and owner-authorization parsers; keep Capability offsets distinct.

Proposed ai representation (still the one `tos_service_v1` protocol):

- Add AgentStateV1 fields **12** authorization_epoch (u64), **13** repeated
  DelegationAdmissionV1, **15** encoding_version
  (u32, value 2). The digest-sorted entry has fields 1 digest, 2 admission_epoch
  (u64), 3 withdrawn (bool). CapabilityStateV1 adds encoding_version at unused
  field **9**, value 2, for its typed/projection header; its stored layout stays
  unchanged apart from the schema value. Bound the collection at 384 and live entries at 128.
- Replace the old digest-only field; reserve its protobuf number 6 rather than
  retain a second mutable membership authority. Use the unused tags listed here in
  both spec and API proto; regenerate Go/schema outputs from spec first.
- DelegateAgentV1 gains required positive authorization_epoch at field **2**.
  Add WithdrawAgentDelegationV1 fields 1 digest/2 epoch, selected by NativeActionV1
  oneof field **31**; **30 is reserved** in both proto files. Update dispatch and the
  native wallet/relayer's action-specific preflight from the same finalized read.
- Portable projections include state encoding version, current epoch, typed
  entries and counts, with strict canonical ordering. Field 14 stays unallocated;
  the never-shipped latch proposal does not reserve it. They remain
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
its wire bytes do not change. A network profile selects **one** registry release:

- The December 1–4 release and public testnet use the existing v1 registry and
  epoch-0 legacy mode. This design is not a gate for that release and does not
  change its default code/artifact pins.
- The existing local v1 deployment continues with its reviewed legacy profile
  until a separately approved v2 local deployment. At that adoption point the
  v1 fixture population is abandoned, not migrated or used as fallback.
- An adopted-v2 network accepts **only v2 code hashes**. Remove its v1 hashes
  from allowlists/daemon Registries and remove epoch-0 legacy mode for it.
  Separate pinned release tooling may still serve the legacy network; no v2
  verifier can switch to it after withdrawal, a missing epoch or a failed read.
- Schema-2 production verification opens only with real finalized state and the
  real epoch-aware adapter, not synthetic Snapshot tests. Never infer epoch zero
  for malformed/uninitialized new state. Historical inspection is not authority.

The **Agent** identity preimage byte changes from 1 to **2** at
`native-registry-code.fc:711` and the mirrored Rust/Go Agent derivation. All
remaining fields keep their order. The existing Capability identity already
uses byte 2 (`:737`) and two references; do not add another byte or mistakenly
shift that layout. Its owner is a new v2 Agent id, so new Capability ids follow
from that new owner binding. Agent and Capability preimages remain structurally
distinct (one versus two references), with typed ids and account kinds. Thus v2
Agent ids differ, not merely their account addresses. Combined with v2-only code-hash
selection this prevents v1 identity re-registration/lookup from reviving a v2
withdrawn digest. Recompute all id/StateInit/address/signature vectors; an alias
from an old id would undo this boundary and is forbidden.

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

### Check ownership and reachable negative controls

| Layer | Owned check / vector construction |
| --- | --- |
| On-chain add/withdraw | expected_epoch=current, digest membership/status, independent live/total bounds, existing purpose/sequence/predecessor and atomic save |
| On-chain writer | A leaf is created with current epoch and every bump clears all leaves; this makes a later withdrawal admission_epoch mismatch unreachable by valid transitions |
| Strict Rust/Go state readers | Every stored admission_epoch=current, valid statuses/counts/schema/kind. No redundant withdrawal throw/mutant for the writer invariant |
| Transport and Endpoint verifiers | encoded=admitted=current, live/not withdrawn, network/code/profile/time. Use synthetic authenticated-shaped snapshots to isolate each equality from the strict-reader check |
| Issuance/preflight | Current encoded epoch; nativewallet journal validation also matches decoded document epoch to the action payload's expected_epoch |

To reach contract error **2216**, use the **current predecessor and valid next
sequence** with only expected_epoch wrong, for both add and withdrawal. A stale
predecessor tests 2204, not the epoch guard. For admission-epoch-reader mutants,
craft the leaf directly; for verifier mutants, inject a snapshot that bypasses
the real strict reader and makes all other checks pass. Each test names its
layer and reaches only the intended refusal. Epoch overflow **2217** needs a
sandbox-seeded MAX state; it is not reachable in a practical live action count,
but its MAX-1/MAX and exact-replay tests remain mandatory.

### Withdrawal concurrency and operational result

Confirm a withdrawal from a **finalized** post-state: digest withdrawn, or a
proven intervening epoch bump has cleared the formerly live digest. Merely
submitting it or seeing a transaction is not revocation confirmation.

Withdraw and update built from the same predecessor in one block serialize:
whichever executes second gets bad_predecessor. Reconcile the exact submitted
action first; after confirmed rejection, read the new finalized state, rebuild
with its current epoch/predecessor/sequence and obtain the normal signature
approval before resubmission. Never resend blindly or rebuild an unknown send.
A 2220 after a proven bump, with the former digest absent in that post-state,
means already revoked and requires no further withdrawal. Error 2220 alone,
an account-not-found result or a missing read is not that proof. Test both
orderings and the goal-level confirmation; no silently dropped revocation.

A policy update/controller rotation kills every Endpoint delegation. Nativewallet
and tosctl must show that result and issue/commit fresh delegation bytes at E+1
before reconnecting the Endpoint/transport. Do not reuse the old document just
because the policy bytes/key happen to match after rotation.

Frozen and uninitialized Agent accounts are **refusals**, not ErrUnavailable:
no stale-pass fallback. A frozen account cannot withdraw until it is legitimately
unfrozen; an uninitialized account needs registration. Diagnose/fund/recover only
through the normal approved operator procedure, not an override or epoch reset.

### Required complete-action measurements before implementation merge

Both engines must measure <=800,000 gas, not a sum of kernels, for add 127→128
live; add 383→384 total with live below 128; every withdrawal position at full
128/384 with eight signatures and hashed/deep keys; each refused add; and policy
update, recovery completion and tombstone with all 384 entries populated. Include
registration/initiation and all existing eight-controller regressions.

Measure signed message bytes against the actual CP43 limit (fixture maximum
**65,535 bytes**), and require both the fixture and deployment limit. Record
actual full-account unique cells/bits, CP18 price schedule, last-paid time and
charged rent. Read freeze_due_limit/delete_due_limit from **CP21 gas parameters**
for this basechain registry (not from CP18). Measure rent/debt at ordinary ages
and at either side of the freeze threshold, plus the resulting frozen-state
refusal. Retain a fee/reserve recommendation from those results; do not guess
one from BOC size. This remains an implementation merge gate, not a claim that
new action gas or full account rent has been measured in this document.

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
  `service_actor_token_cmd.rs`, `mod.rs`: new registry identity/CLI dispatch; wrappers must use the selected network profile.
- Sibling contracts `lib.rs`, `agent_account_auth.rs`, `agent_account_custody.rs`,
  `agent_account_reconfigure.rs`, `service_actor.rs`, `service_actor_token.rs`:
  classified **proven unchanged for business logic**: they do not own the Agent
  epoch decoder/transition. Keep runtime source unchanged; regenerate dependent
  fixture/release pins and run their authorization regressions. Do not add epoch
  bumps to ordinary Capability or Agent-account wallet operations.
- `scripts/build-tos-service-native-registry-v1.sh`,
  `embed-tos-service-native-registry-v1.sh`, `tos_service_native_registry_release.py`,
  `tos_service_native_registry_pq.py` and corresponding `test_*` scripts:
  regenerate the reviewed contract release, not a stale frozen BOC.
- `CMakeLists.txt`, `crypto/CMakeLists.txt`,
  `assembly/nix/tosctl/{inputs.json,package.nix}`, release artifact inventory and source-guard/hygiene/build
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

Additional caller/pin inventory from re-review (all searched/read):

- `protocol/pkg/agenttransport/delegation.go`: issuance encoding and current-epoch
  check; `messenger/internal/canon/domains.go`: explicit Endpoint v3 domain.
- `messenger/pkg/daemon/config.go`: validate **all** Registries, Chain() and the
  selected NativeRegistryCodeHash. On v2 adoption it is not enough to change only
  the selected hash while accepting v1 in the verifier's complete registry set.
- `messenger/docs/daemon-config.example.json`,
  `gateway/docs/provider-quote-profile.example.json`, and active
  `spec/deployments/*.json`: reviewed network-specific code/identity/profile pins.
  Historical records stay historical, not silently rewritten as new deployments.
- `protocol/pkg/buyersdk/tosctl_init.go`,
  `provider/pkg/servicebridge/{setup_tosctl,controller_probe}.go`,
  `protocol/pkg/mldsa44/tosctl.go`: selected release/CLI compatibility, decoding,
  signing preflight and re-delegation after policy rotation.
- `execution/internal/actionauthoritytest`, `gateway/internal/actionauthoritytest`,
  `messenger/internal/actionauthoritytest`: independent signature/state helpers.
- `messenger/internal/vectors/testdata/{vectors,adversarial-corpus}.json`,
  `vectors_test.go`, corpus builder/verify tests and other relay vector consumers.
- `protocol/cmd/agenttransport-vectors`,
  `protocol/cmd/agenttransport-reachability-vectors`,
  `spec/test-vectors/agent-transport-reachability-v1.json`, and
  `spec/scripts/reproduce-agent-transport-reachability-v1.py`.
- Nativewallet transport work at separate branch
  `feat/service-wallet-transport-delegation`, inspected commit
  `0ef1d5a3b6475d5b3d076f03d23c6cf934767703` (not yet on the ai pin):
  `protocol/pkg/nativewallet/transport.go:219,355` must both build expected_epoch
  and compare the journaled action's epoch with the decoded delegation and fresh
  finalized state. Also update its transport/storage tests and
  `protocol/cmd/tos-service-wallet/{main,transport,transport_test}.go`.
  Never rewrite an old signed journal draft to add an epoch: reconcile its exact
  bytes, refuse incompatible drafts and obtain a fresh approved action if needed.
  Re-check this inventory after that branch merges.

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
7. 128 live, then withdrawal: replacement add succeeds at 127 if total<384; separately
   churn below 128 to total 384. Construct 128 live/256 withdrawn, withdraw at
   full total, then 0 live/384 withdrawn. Add refuses; update/complete recovery
   clears and admits again. No early bump/withdraw failure due to count.
8. Malformed version/kind, counter mismatch, total<live, >384 entries, duplicate
   keys, wrong admission epoch, missing leaf bits, trailing bits/refs/exotic
   cells, missing epoch metadata and mixed-block projections all refuse.
9. Endpoint epoch/digest vectors and real finalized adapter; healthy cache
   revocation, unavailable-read cutoff, wrong registry/network and production
   epoch-zero refusals. Decision-31 replay/namespace/isolation tests stay green.
10. Capability schema-2 owner authorization/version/transfer/tombstone vectors
    preserve their current layout, sequence/generation and no-Agent-bump semantics.
    Cover withdraw/update both orders in one block and finalized revoked/already-
    revoked confirmation; frozen/uninitialized refuses cannot use stale fallback.

Bound/resource gate: eight-controller and one-controller actions at all four
populations and adversarial key shapes, every withdrawal position, registration,
identical/disjoint update, initiate/complete recovery, tombstone, rejected add and
replays. Measure gas, storage cells/bits/depth, fees, message bytes and out actions
with Rust transaction execution and native replay. Include insufficient funding
and account limits, while distinguishing those from forbidden capacity refusal.
Clearing all references is tested for actual post-transaction storage reduction.

Sensitivity controls must each fail a named assertion, not collection/compile
errors: omit each epoch bump; bump on add/withdraw/initiate; wrap/saturate MAX;
check overflow before exact replay; preserve either set on bump; ignore
expected_epoch on chain with a fresh predecessor; ignore stored admission epoch
in a strict-reader synthetic BOC; ignore encoded/admitted/current equality in a
verifier-only synthetic Snapshot; permit withdrawn re-add; add a capacity check to withdrawal; weaken each 128/384 bound; drop
stored counts or leaf-shape checks; accept legacy schema/epoch zero in production;
join two checkpoints; skip endpoint canonical epoch binding; treat observed
revocation as ErrUnavailable; leave a CLI/relay caller on digest-only preflight. Add separate controls where
withdrawal changes total_count or its registry transaction emits any out-action;
neither is allowed (wallet change elsewhere in the transport graph is separate).
Add identity-byte-1, schema-1 Capability, mixed Registries (selected v2 but accepted
v1), and legacy fallback under an adopted-v2 profile controls. Isolate these from
other identity checks with matching ids/policy/network for the intended branch.
Keep independent red controls for live cap, total cap and their reset.

Fuzz small valid action sequences against a simple Go reference set model and
the real contract: after every result compare the complete state and permitted
future actions, not just the final count. Shrink failures; persist the seed and
minimal failing sequence. Counter/epoch mutations include every boundary.

## 8. Local adoption, release boundary and no migration

1. Non-author design approval first. No contract/client implementation here.
2. Coordinated normative ai schema/vector changes and FunC/Rust/Go implementation:
   oneof 31, Agent identity preimage byte 2, both state kinds schema 2, count-only bounds,
   and explicit layer ownership. Correct the transport spec's “until next bump”
   wording to “while full” and its approximate storage figure to **15.2 KiB of
   bits** (plus cell overhead/policy/etc). Record Endpoint v3 as a deliberate
   canonical-domain change in `AGENT_NATIVE_MESSENGER_V1.md` section 9.2.
3. Complete numeric gas/rent/message gates above, independent vectors, mutants,
   spec/schema/boundary checks, focused Go/Rust/race suites and source guards.
   Use `GOWORK=off` for worktree Go/make. No December v1 release pin changes.
4. Until the separate local v2 GO, existing local v1 Agents/Capabilities and
   dependent fixtures continue on their original legacy release. Do not reset
   the existing bridge/USDT network to make this rehearsal convenient.
5. On local adoption deploy new v2 identities and fixtures, switch that network's
   code-hash selection to v2 only and remove legacy epoch-0/v1 acceptance for it.
   Reconstruct real action sequences and Endpoint/transport refusal on independent
   references; archive per step. Check daemon Registries cannot select a v1
   alternative for the same logical lookup. No public activation is authorized.

Explicit v1 fixture populations to leave unchanged until local adoption, then
abandon rather than migrate:

| Population | Existing artifacts/consumers; v2 handling |
| --- | --- |
| Local T10/T18 Agents and Capabilities | Original USDC, refusal-namespace and USDT provider Agent/Capability/offer deployments; service-actor/native/token contract fixture worlds. Preserve their run records and v1 pins; create new identities/addresses for v2, do not repoint old offers |
| Agent-account owner/control fixtures | `agent_account_mldsa44_sandbox.rs`, strict variant, `agent-economy-composed-e2e.py`, strict rehearsal, paid-demand fixture and ai agentgift/native-relay testdata. Preserve prior on-chain state; rebuild owner Agent bindings/permissions in fresh v2 fixtures |
| Guarantor fixtures | `agent-guarantor-signature-vector.json`, ai agentguarantor authority tests, toschain guarantor resolver and servicebridge action-authority fixtures. Regenerate ids, signatures, registry-code pins and authority proofs; never alias the old identity |
| Messenger/transport fixtures | Existing Endpoint v2/epoch-0 local documents, contact/directory/daemon/vectors and nativewallet transport journals. Abandon/reissue v3 Endpoint and current-epoch transport delegations on fresh v2 identities; no journal edit to turn an old draft into new authority |

The local adoption receipt must enumerate actual object/account ids from the
retained deployment records for these populations and list the services/configs
using them before switching; this design is not permission to delete their keys,
funds or evidence. Abandonment means no v2 authorization/alias, not erasure.

The December 1–4 release/public testnet explicitly remain v1 legacy under decision
33. Their pinned old bundle stays separate from this v2 local rollout. A network
adopts one profile at a time; a code list containing both v1 and v2 is invalid for
an adopted-v2 network. No v1 fallback after withdrawal or read failure.

No in-place migration is required pre-launch. V2 registration derives ids with
identity version byte 2; keep fresh registration nonces as well. An old v1 id is
never registered as a v2 id, and there is no alias mapping its old delegation to
v2. Future schema migrations of existing v2 state must preserve or advance its
proven u64 epoch and linkage, never reset/saturate/wrap it. Do not downgrade an
adopted-v2 network to legacy acceptance to recover a rejected delegation.

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

### Re-review additions at the ai main pin

```text
protocol/pkg/agenttransport/delegation.go
messenger/internal/canon/domains.go
messenger/pkg/daemon/config.go
messenger/docs/daemon-config.example.json
gateway/docs/provider-quote-profile.example.json
protocol/pkg/buyersdk/tosctl_init.go
provider/pkg/servicebridge/setup_tosctl.go
provider/pkg/servicebridge/controller_probe.go
protocol/pkg/mldsa44/tosctl.go
execution/internal/actionauthoritytest/actionauthoritytest.go
gateway/internal/actionauthoritytest/actionauthoritytest.go
messenger/internal/actionauthoritytest/actionauthoritytest.go
messenger/internal/vectors/testdata/vectors.json
messenger/internal/vectors/testdata/adversarial-corpus.json
messenger/internal/vectors/vectors_test.go
messenger/internal/vectors/corpus_builders_test.go
messenger/internal/vectors/corpus_verify_test.go
protocol/cmd/agenttransport-vectors
protocol/cmd/agenttransport-reachability-vectors
spec/test-vectors/agent-transport-reachability-v1.json
spec/scripts/reproduce-agent-transport-reachability-v1.py
```

Tos additions: `assembly/nix/tosctl/inputs.json`,
`assembly/nix/tosctl/package.nix`, `crypto/CMakeLists.txt`.
Deployment-record selection is the active `spec/deployments/*.json` glob;
archived records retain their original provenance. Separate-branch nativewallet
transport files and the inspected pin are listed above, not claimed to be main.
