# Strengthening TOS from the Actor-Model First Principle

## 0. Reference

Throughout this document, *Actor Model* refers to the formal model
introduced by Carl Hewitt, Peter Bishop, and Richard Steiger in 1973
and refined by Gul Agha, William Clinger, and others. The canonical
encyclopedic reference is:

- <https://en.wikipedia.org/wiki/Actor_model>

We will appeal directly to its three behavioral axioms — **send**,
**create**, and **become** (designate next behavior) — as well as
its background properties: private state, asynchronous messages,
locality of reference, and fairness.

## 1. First principles: actors are forced, not chosen

The actor model is not adopted in TOS because it is fashionable, nor
because it is convenient. It is the unique design that survives a
small number of axiomatic commitments TOS has already made:

1. **Replication for fault tolerance.** A blockchain is a replicated
   state machine. Every validator must reach the same post-state
   from the same pre-state and the same input.
2. **Partitioning for scale.** No single physical machine can hold
   or process the entire global state at the throughput TOS targets.
   State must be partitionable, and the partitions must be servable
   independently — this is the architectural prerequisite for
   sharding.
3. **No shared memory across partitions.** Two partitions, by
   definition, cannot share mutable memory; if they could, they
   would be one partition.
4. **Concurrent progress.** Different partitions must be able to
   make progress without waiting on each other; otherwise scale is
   illusory.

From (3) and (4) the only available interaction primitive between
state owners is the **asynchronous message**: a value handed off,
received later, with no shared call stack and no shared lock.

Once asynchronous messages are the only primitive, the natural unit
of ownership is whatever holds:

- a private mutable state,
- an inbound message capability (an "address"),
- a transition rule that maps `(state, message) → (new state,
  outbound messages)`.

That object is an **actor** in the precise sense of Hewitt 1973.
There is no other consistent endpoint for the message machinery.

So the choice is not "actor model vs. some other model" — it is
"actor model, or break one of axioms (1)–(4)". Synchronous
shared-memory models break (3); single-threaded global-VM models
break (2); blocking RPC models break (4). TOS holds all four, and
so the actor model is forced upon it as a theorem rather than chosen
as a style.

The remaining design freedom is **how completely** the model is
realized. TOS today realizes it in execution semantics; the rest of
this document is about realizing it in fault tolerance, time, and
composition as well.

## 2. What TOS already realizes faithfully

On the native workchain (wc=0), every account is an actor, and the
mapping to Hewitt's model is exact:

- **Identity = address.** `account_id = hash(StateInit)` over the
  workchain serves as the actor's unique reference.
- **Private state.** Each account's `data` cell — and through the
  cell DAG, its full storage — is writable only by the account
  itself. There is no protocol-level mechanism to read or write
  another account's storage synchronously.
- **`send` axiom.** TVM's `SENDRAWMSG` (and the higher-level
  wrappers) emits outbound internal messages, the only inter-actor
  interaction primitive.
- **`create` axiom.** Sending a message that carries `StateInit` to
  a not-yet-deployed address materializes a new actor — exactly the
  Hewitt creation primitive.
- **`become` axiom.** TVM's commit phase writes back the `c4` (data)
  register, and `SETCODE` writes back the `c3` (code) register.
  Together they realize *designate next behavior* faithfully — and
  in fact more completely than most actor frameworks, because the
  actor's *code itself* can be replaced for the next message.
- **Single-message atomicity.** A transaction processes exactly one
  inbound message to commit-or-abort.
- **No synchronous cross-actor calls.** Two contracts cannot share
  a call stack; they can only message each other.

This is the baseline. Everything below is what is missing on top of
it.

## 3. Three concessions to physical reality

The pure Hewitt model is non-deterministic, address-opaque, and
computationally unbounded. None of those three properties survives
contact with a public blockchain. TOS has, by necessity, made the
following concessions:

- **Determinism over non-determinism.** Validators must converge on
  the same post-state, so the protocol fixes a specific
  deterministic schedule (logical time `lt`, FIFO between any
  sender/recipient pair, intra-block ordering) out of the set of
  schedules Hewitt would consider legal. The execution is still in
  the legal set; the freedom of choice within it is what is given
  up.
- **Content addressing.** Sharding requires that addresses be
  computable from `(code, data)` ahead of deployment. This forfeits
  Hewitt's locality-of-reference property in mechanism, although
  unforgeability of the *sender* of a message is preserved by the
  protocol.
- **Bounded computation per message.** Gas, storage rent, and the
  bounce mechanism layer economic and operational reality on top of
  the model. These are extensions, not violations, but they are
  not in the original model.

The strengthening proposals below explicitly do not try to undo any
of these three — they are load-bearing for sharding, consensus, and
liveness. The goal is to make the rest of the model more complete
within these constraints.

## 4. Strengthening directions, ordered by leverage

### 4.1. Supervision trees ("let it crash")

**Gap.** The single largest piece of the actor model that TOS does
not implement is fault tolerance through supervision. The Hewitt
axioms describe how an actor processes a message; they do not, on
their own, describe how a system survives an actor failing. The
empirical answer — from decades of running actor systems in
production — is *let it crash + supervisors*: a failed actor is
restarted by a supervisor according to a declared strategy, and
failure is escalated upward when local restart is insufficient.

Today, when a TOS contract aborts, the caller receives a narrow
bounce stub and is left to its own devices. There is no notion of
*linked actors*, *restart strategies*, or *failure escalation* at the
protocol level.

**Direction.**

- Allow a contract to declare a **supervisor address** at deployment
  time (or via a protocol-level register).
- The protocol guarantees that on abnormal termination of the child
  (compute-phase exception, frozen account, exhausted storage rent,
  permanent unavailability) a structured **failure message** is
  delivered to the supervisor.
- Standardize OTP-equivalent restart semantics adapted to chain
  reality — *one-for-one*, *all-for-one*, *rest-for-one* — where
  "restart" maps to "issue a compensating or re-initialization
  message".
- Provide a system-level root supervisor that catches truly orphaned
  failures (a dead-letter sink).

**Why it matters.** Supervision is what turns an actor system from
"a concurrency model" into "a fault-tolerant system". Without it,
every contract author re-invents partial recovery logic, usually
incorrectly.

### 4.2. Time as a first-class message primitive

**Gap.** The Hewitt axioms guarantee *eventual delivery* (fairness)
but say nothing about deadlines. Every working actor system makes
time a primitive, because timeouts and expirations cannot be
expressed otherwise. Today, in TOS, "fire in 30 minutes" requires
either an off-chain keeper bot or a `now()` check stuffed into every
inbound message — both of which leak the time concern outside the
actor.

**Direction.**

- Add a native `send_at(target, body, when)` primitive, where `when`
  may be a logical time, a unix timestamp, or a block number. The
  protocol takes responsibility for delivering no earlier than that
  point, with a bounded fairness window.
- Define semantics for cancellation (`cancel_scheduled(handle)`) and
  for what happens to scheduled messages addressed to frozen or
  deleted accounts.

**Why it matters.** Escrows, vote deadlines, order expirations,
vesting cliffs, and time-locked transfers all currently rely on
external keepers or per-message "is it time yet?" logic. Once time
is a protocol primitive, an entire class of off-chain infrastructure
disappears, and the resulting contracts become self-contained actors
again — exactly as the model intends.

### 4.3. Structured error / bounce protocol

**Gap.** A bounce body today carries roughly 224 usable bits of
payload and only fires on a subset of failure paths (compute-phase
abort). For the actor model this is the equivalent of allowing only
an integer as an exit reason: too narrow to drive any non-trivial
failure-handling logic.

**Direction.**

- Carry a fully structured error in bounce messages: error class,
  originating actor address, original message hash, and an optional
  data cell for diagnostic detail.
- Distinguish **transient** failures (out-of-gas, temporarily
  unreachable, queue congestion) from **permanent** failures
  (uncaught exception, frozen account, code rejected).
- Surface a "linked actor crashed" signal automatically when 4.1
  (supervision) is in place.

**Why it matters.** Combined with 4.1, this is what makes "let it
crash" actually viable. Without structured errors, supervisors have
nothing to discriminate on and can only blanket-restart, which is
unsafe in a financial setting.

### 4.4. Capability addressing as a complement to content addressing

**Gap.** TOS addresses are *content-addressed*: `account_id =
hash(StateInit)`. This is what makes sharding work and what lets
clients predict-and-pre-fund addresses (jetton wallets, wallet-vN
derivation). The cost is that Hewitt's **locality of reference**
property — that an actor only knows addresses it has been given —
is given up: anyone can compute any address and send to it. This is
the structural root cause of dust-spam, phishing-jetton, and
"scam NFT in your wallet" attacks at the application layer.

**Direction.** Layer **per-relationship capability handles** on top
of content-addressed identities. A capability is an unforgeable
token that grants the bearer the right to send messages to a
*specific internal entry point* of the holder. Inspirations include
Pony's reference capabilities, the Pact capability system, and
E-language unguessable references.

A pragmatic shape:

- A contract can mint a capability that authorizes a specific peer
  to invoke a specific receive-handler with specific arguments.
- The protocol verifies the capability at message admission time,
  so ACL logic does not need to be re-implemented in every
  contract.
- Capabilities are revocable and transferable under
  contract-defined policy.

**Why it matters.** It pulls access control down from the
application layer (each contract handcrafting allowlists) into the
protocol or language layer. Strictly speaking, **Hewitt's addresses
already are capabilities** — TOS has, for sharding reasons,
degraded them to public IDs; introducing a capability layer gives
that property back without giving up content addressing.

This is the most research-heavy item in the list and is best driven
through a public design document before any implementation work.

### 4.5. `become` as an explicit language primitive

**Gap.** In FunC, `become` is implemented by hand as bit layout in
`c4`; the compiler has no idea which behavior the contract is
currently in. Tolk's `receive(...)` style is a step in the right
direction but still lacks the notion of a *current state* as a
first-class concept.

**Direction.** Introduce explicit state-machine syntax in Tolk:

```tolk
contract Auction {
    states: Open, Settling, Closed

    receive("bid")    on Open     { ... become Settling }
    receive("settle") on Settling { ... become Closed   }
}
```

The compiler can then statically verify:

- **Exhaustiveness.** For every state, what happens to every defined
  message — bounce, ignore, or handle?
- **Reachability.** Is any state unreachable? Is any state a sink
  with no exits?
- **Invariant preservation.** Data fields valid only in certain
  states cannot be read in others.

**Why it matters.** This lifts Hewitt's *designate next behavior*
from an implicit convention buried in `c4` field layout to a
statically checkable contract skeleton. A large class of
high-severity contract bugs — state confusion, double-handling,
missing transitions — becomes a compile-time error.

### 4.6. Standardize request/reply correlation

**Gap.** Every contract author re-invents `query_id` to pair a
response with its request. Each token contract, each NFT standard,
each TEP-style application surface ships its own variant. This is
precisely the kernel of OTP's `gen_server:call` — the canonical
case of *"do it once at the protocol level, every contract reuses
it"*.

**Direction.**

- Add `query_id` (or a richer correlation token) and an optional
  `reply_to` to the standard message header.
- Make timeouts on outstanding requests a first-class feature
  (composes with 4.2).
- Expose this in Tolk as something close to `co_await
  send_request(target, body)` — the C++20 coroutine layer already
  present in `tdactor/` is a useful reference for the surface
  design, even though the language-side implementation is
  independent.

**Why it matters.** Pure developer experience: it eliminates a
recurring source of bugs (mismatched query IDs, lost replies) and
makes contracts read like straight-line code while remaining honest
async actors underneath.

### 4.7. Cross-shard delivery SLA and dead-letter handling

**Gap.** Theory says messages are delivered eventually. In
practice, cross-shard messages can stall: queue congestion, frozen
recipients, fork resolution. There is no explicit "if undeliverable
after N blocks, route to dead-letter" mechanism today.

**Direction.**

- Define a maximum delivery window per message (default + override).
- On expiry, route to either (a) the sender's bounce handler with an
  `Undeliverable` error class, or (b) a system-level dead-letter
  actor.
- Expose queue-pressure metrics to the sender so it can apply
  back-pressure rather than blindly enqueuing.

**Why it matters.** Stuck cross-shard messages are a recurring pain
point and currently force application-layer timeouts everywhere.
Solving this at the protocol level removes a class of liveness
bugs.

### 4.8. Actor-level observability

**Gap.** Actor introspection — Erlang's `process_info`, OTP's
tracing, and similar facilities — is what makes large actor systems
debuggable in production. TOS contracts today are debugged
primarily by replaying transactions off-chain.

**Direction.** Provide each contract with deterministic
introspection into its own:

- recent message history (windowed, bounded);
- inbound mailbox depth, where any future model gives that concept
  meaning;
- the up- and downstream actors it has interacted with recently.

The on-chain surface should remain deterministic; the richer view
can live in a standardized off-chain indexer protocol.

**Why it matters.** It is hard to overstate the productivity delta
between "ask the actor what it just did" and "replay the chain".
Once contracts get larger and supervised (4.1), this becomes
essential rather than nice-to-have.

## 5. Prioritization

If TOS resources are constrained, the recommendation is:

1. **4.1 (supervision) + 4.3 (structured errors) + 4.2 (time
   primitive)** — together, this is *the minimum industrial-grade
   actor system*. Doing all three is the most visible
   first-principles win, and they reinforce each other.

2. **4.5 (`become` syntax) + 4.6 (request/reply standardization)** —
   developer-experience layer. Lower protocol risk, very high
   bug-prevention value. Best done in coordination with the Tolk
   language team.

3. **4.4 (capability addressing)** — long-horizon research item.
   Highest theoretical payoff (closes the locality-of-reference
   gap) but largest design space. Should start with a public
   design document.

4. **4.7–4.8** — important but lower urgency; pick up once 4.1–4.6
   are in motion.

## 6. Closing framing

TOS encodes the Actor Model into its **execution semantics**. From
first principles — replication, partitioning, no shared memory,
concurrent progress — that was the only consistent choice. What
remains is to encode the same model into **fault tolerance**
(4.1, 4.3), **time** (4.2), **composition** (4.5, 4.6), **access
control** (4.4), and **observability** (4.7, 4.8).

Strengthening these layers is what would let TOS state, accurately
and from first principles, that it is an actor-faithful blockchain
by derivation, not by analogy.
