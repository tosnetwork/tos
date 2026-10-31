# Permissionless Bonded External Relayer (BR1)

Status: implementation candidate; **not approved for production activation**.
Base: `084e4315899cc3a5bf64cc434ee327e1db487173`.

## Purpose and non-goals

Provide permissionless third-party submission of a user's already-authorized
Shield transaction, independently funded in native TOS, with real economic
accountability and success-contingent private payment. Energy is not implemented
and is not a dependency. An external operator is not a TVM external-message gas
exception: the pool continues to receive a funded internal message.

This is not a guarantee of anonymity against a global network observer, delivery
by a particular time, or post-quantum soundness of the existing Groth16 proof.
It grants no custody, proof-generation authority, or withdrawal authority to a
relayer. Never send a mnemonic, input-note secret, proving witness, or spend key
to a relayer. A proof and an authorized message are bearer-executable material.

## Reuse map

* Preserve Native Service Registry V1 and its frozen code identity. An operator
  may use its existing Agent Account as the bond owner and publish a capability
  manifest there. Discovery does not confer signing or spending authority.
* Do not use the legacy Capability Registry's `bond` as slashable collateral.
  Its owner can withdraw immediately and choose its reputation verifier.
* Reuse the per-actor deterministic-address model. Each immutable worker has its
  own bond actor. An operator can run several workers without a global gatekeeper.
  Key rotation means deploying a new worker bond and retiring the old one through
  its complete challenge period; a worker key cannot be overwritten to erase
  responsibility. This is deliberate, not a hidden in-place rotation mechanism.
* Reuse the existing chain indexer for candidate discovery, but validate the
  exact code, canonical initial identity, full network domain, current status,
  live backing and policy independently before choosing a candidate.
* Reuse Shield wallet delivery/import validation for a private commission output.
  Do not modify the frozen V1 circuit, verifying key, public inputs or pool code.
* Reuse the durable-attempt and exact-receipt discipline of PQ relay tooling;
  test-only signers and `test/tostester` helpers are never production adapters.

## Security boundary and release gate

Contract code, application logic, simulation tests, live-network acceptance and
production authorization are distinct deliverables. A generic adapter, an RPC
success string, a test fixture, or a self-reported code hash is not verified chain
state. Do not advertise an active public network while the native compilation,
transaction tests, finality adapter and deployment-policy approval gates remain
open. The Shield activation gates still apply independently.

## Bond actor

The immutable configuration binds owner, worker funding address, ML-DSA-44 worker
public key, random deployment salt, global ID, full genesis identity, optional
Native Registry identity reference, and an immutable economic policy. An optional
identity reference is metadata until its controller association is independently
verified. The actor recomputes its address from `MYCODE` and the canonical empty
initial state, so a hand-crafted initial state cannot invent funded collateral.

States: `UNFUNDED -> ACTIVE -> EXITING -> CLOSED`, or
`ACTIVE/EXITING -> SLASHED`. Terminal actors cannot be reactivated. A fresh salt
and worker key are required for a replacement. No SETCODE, administrator, owner
bypass, global operator allowlist, or verification committee is introduced.

Owner-funded activation requires proof of possession of the worker key. Stake is
accounted as an explicit principal, not the full incoming message value: the
sender separately funds a conservative compute ceiling and operating reserve.
Only the owner can add principal or request retirement. Third-party plain top-ups
are donations to the operating reserve, not a reclaimable third-party stake.

The immutable policy contains minimum principal, operating reserve and exit delay.
Clients MUST pin the approved policy hash as well as the code hash; arbitrary
self-deployed policies do not qualify merely because the code matches. Values in
tests are not approved production economics. Exit delay must exceed the acceptance
lifetime plus the evidence window. Storage rent can reduce live backing, so the
advertised collateral is never more than `min(recorded principal, live balance -
operating reserve)`. A balance getter alone does not prove current eligibility.

Retirement stops admission immediately. It never erases worker identity or evidence
liability. Withdrawal is only possible after the complete delay, with action-phase
failure rolling back the transition. Leave an operating reserve for the terminal
record. A slashed principal is irreversibly forfeited in the actor, not a supply-burn
claim and not an owner-withdrawable balance. No reporter-selected payout can turn
self-slashing into an early withdrawal. The first valid evidence closes the actor;
there is no unbounded on-chain evidence dictionary.

## Precisely defined slashable behavior

Only **acceptance equivocation** is slashable in BR1: two distinct, valid ML-DSA-44
acceptance commitments for the same bond actor and worker-assigned acceptance slot.
An acceptance commits to one exact request, signed terms, fee output and expiry.
A quote is not an acceptance. Revised quotes do not constitute equivocation.

The signature domain binds the operation tag, live global ID, bond address and
immutable configuration hash. The canonical acceptance binds slot, issue time,
expiry, Shield intent digest, exact submitted-body hash, quote hash and fee-note
body. Both statements must belong to the same actor lifetime and evidence window.
Different requests in different slots and repeated identical statements are valid.
Comparing signature bytes rather than signed statements is expressly forbidden.

Anyone can submit a conflict proof, paying its compute. Invalid evidence changes
no state. An owner cannot swap the key, metadata or service endpoint to evade a
valid proof. A delayed/failed/unknown broadcast, fee-price movement, censorship or
an HTTP timeout is **not** a proof of malice and is not slashable. BR1 does not
silently introduce a trusted availability oracle. It provides a narrow, real,
objectively enforceable bond rather than claiming universal service insurance.

## Private commission and success semantics

A client allocates one ordinary output of the existing three-output Shield
transaction to the selected worker's pool-specific receiving descriptor. The
operator quotes a fresh note-key index and exact fee; quote slots and note indices
must be durably allocated before publication. The fee is a private output note,
not the pool's immutable `withdrawal_fee` and not a second public payout.

Before spending gas, the worker decrypts its own prospective output and runs the
existing owner/PQ-key/amount/note-body checks against the exact candidate body.
It checks slot, exact quoted amount, non-dummy/non-recovery kind and descriptor
index. That is fee preflight, **not proof validation or a balance credit**. The
complete exact transaction must also pass native simulation/proof verification
against a pinned pool state. A matching forged ciphertext without a valid proof
must never buy a submission. User input secrets are unnecessary for these checks.

The note is credited only after proof-authenticated finality for the exact pool
execution and assigned output commitment. A source wallet send, successful HTTP
reply, or a consumed input nullifier alone is insufficient. Pool rejection creates
no fee note. A competing relayer submitting identical bytes cannot redirect the
signed fee. A user choosing another relayer must make a new transaction/fee output;
its proof and authorization cannot be relabelled. If a public withdrawal later
bounces, the already-successful pool submission and its fee are not undone; the
pool's existing recovery rules govern the user's payout. Quotes must state this.

## Relay engine, transport and discovery

The durable engine reserves exact request identity, acceptance slot, input-nullifier
locks and funding cap before signing or writing to the network. It persists the
signed, exact outbound bytes before a single broadcast. Recovery never re-signs an
unknown attempt. Unknown outcomes keep reservations until finality-backed evidence
establishes success or terminal refusal. SQLite protects one operator journal, not
competition across independent relayers. Enforce bounded body size, queue size,
request lifetime, per-worker gas exposure and simulation work.

A release adapter must verify current code/config/network/worker identity and
backing, validate fee preflight and the whole proof, build a funded internal message,
sign through a production key boundary, submit exact bytes and prove destination
execution. Interfaces must fail closed when any of these capabilities is absent.
Do not substitute the manual unpinned `wallet broadcast-prepared` path, mocked
transport, self-reported finality, or the TEST ONLY PQ signer.

The directory is an untrusted read-only view of chain-discovered bond actors. It
may be served by multiple independent indexers or a self-hosted node. Its records
are hints, not authorization. A public directory must not expose the existing
operator-management API or its credentials. Never require an ENS name, governance
approval, a proprietary API key, or a privileged central registration transaction
for on-chain membership. Privacy transport, endpoint authentication, anti-DoS and
metadata leakage require separate review; an HTTPS endpoint is not anonymous.

## Acceptance matrix

Required negative controls include forged initial collateral, wrong owner/network/
actor/key/context, malformed byte chains and trailing data, underfunded compute,
storage-rent erosion, immediate/duplicate exit, key-replacement escape, identical
statements vs real conflicts, cross-slot/cross-instance evidence, expired evidence,
action failure, fee amount/owner/index/payload substitution, invalid proof with a
valid-looking fee note, crash before/after broadcast, concurrent duplicates,
ambiguous outcomes, unrelated receipts, and body/queue/funding resource limits.

Run native transaction tests, not only a Python state model; keep compile failures
separate from assertion failures. Mutation controls must remove an actual guard and
make its designated test fail. A distributed, funded localnet drill with two
independent operators, restart and failover is a production activation gate, as are
independent security review and a reviewed release manifest.

## External references

Tornado Cash's registered-worker separation and relay queues are architectural
references, not code dependencies or evidence that arbitrary non-performance is
slashable. RAILGUN's broadcaster fee-output approach is a reference for private
success-contingent payment. Waku may be evaluated as a transport later; RLN is not
required to make this bond enforceable. EVM atomicity, governance TORN staking and
ENS assumptions are not copied into TVM.
