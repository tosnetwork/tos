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

## 4. The empirical reference: Erlang/OTP

The Hewitt papers describe what an actor *is*. They do not, on
their own, describe what a *system of actors* needs to survive in
production. The empirical answer to that question has existed since
the late 1980s, in the form of **Erlang** and the **Open Telecom
Platform (OTP)**.

Erlang was designed at Ericsson by Joe Armstrong, Robert Virding,
and Mike Williams to run telephone switches whose availability
budget was measured in tens of milliseconds of downtime per year.
OTP is the standard library that crystallized the patterns those
switches needed:

- `gen_server` — generic server actor with a structured request /
  reply and cast protocol;
- `gen_statem` — generic finite-state-machine actor with named
  states and explicit transition functions;
- `supervisor` — actor whose only job is to start, monitor, and
  restart child actors under a declared strategy
  (`one_for_one`, `one_for_all`, `rest_for_one`,
  `simple_one_for_one`);
- `application` — a top-level supervised unit of deployment with
  start, stop, and configuration semantics.

Decades later this stack runs WhatsApp's messaging backplane,
Discord's session layer, RabbitMQ, CouchDB, Riak, and ejabberd. It
is the only Actor Model implementation with a multi-decade,
billion-user production track record.

Every strengthening direction in §5 below has a direct precedent in
Erlang/OTP:

| Direction | Erlang / OTP precedent |
|---|---|
| 5.1 Supervision trees | `supervisor` behaviour with `one_for_one`, `one_for_all`, `rest_for_one`, `simple_one_for_one`; `link/1`, `spawn_link/1`, `trap_exit` |
| 5.2 Time as a primitive | `receive ... after Timeout -> ...`; `erlang:send_after/3`; `erlang:start_timer/3,4`; `gen_server:call/3` timeouts |
| 5.3 Structured errors | `{'EXIT', Pid, Reason}` exit signals; `monitor/2` and `{'DOWN', Ref, process, Pid, Reason}` messages; OTP `{stop, Reason, State}` return values |
| 5.5 `become` as language primitive | `gen_statem` named states with explicit `StateName(EventType, Event, Data)` transition clauses; `code_change/4` for in-flight behavior upgrades |
| 5.6 Request/reply correlation | `gen_server:call/2,3` with a built-in monotonic reference tag, default 5 s timeout, and structured `{reply, Reply, NewState}` returns |
| 5.7 Dead-letter handling | OTP `sys` debug interface; system `error_logger` / `logger` sink; supervisor escalation on repeated child failure |
| 5.8 Observability | `process_info/1,2`; `erlang:trace/3`; `dbg`; the `observer` GUI; the `recon` library |

These are not analogies. They are the closest existing artifacts
to what TOS would be standing up at the protocol layer. The
engineering decisions that made them work — restart strategies as
declarative policy rather than imperative recovery code, exit
signals as structured messages rather than ad-hoc return codes,
named states as compile-checkable rather than as a convention — are
the actual deliverables we need.

Pure Hewitt gives us the math of what an actor is. Erlang/OTP
gives us the engineering of how actors survive in production.
Skipping the second half means re-running 1980s Ericsson R&D from
scratch, with a smaller budget and a public chain as the test
environment. The strengthening directions below take the second
half as a given.

## 5. Strengthening directions, ordered by leverage

### 5.1. Supervision trees ("let it crash")

**Gap.** The single largest piece of the actor model that TOS does
not implement is fault tolerance through supervision. The Hewitt
axioms describe how an actor processes a message; they do not, on
their own, describe how a system survives an actor failing. The
empirical answer — Joe Armstrong's *let it crash + supervisors* —
is that a failed actor is restarted by a supervisor according to a
declared strategy, and failure is escalated upward when local
restart is insufficient.

Today, when a TOS contract aborts, the caller receives a narrow
bounce stub and is left to its own devices. There is no notion of
*linked actors*, *restart strategies*, or *failure escalation* at
the protocol level.

**Direction.**

- Allow a contract to declare a **supervisor address** at deployment
  time (or via a protocol-level register). This is the on-chain
  analogue of OTP's `supervisor` behaviour declaring its child
  specs.
- The protocol guarantees that on abnormal termination of the child
  (compute-phase exception, frozen account, exhausted storage rent,
  permanent unavailability) a structured **failure message** is
  delivered to the supervisor — the on-chain analogue of an
  `{'EXIT', ChildAddress, Reason}` signal.
- Standardize the four OTP restart strategies — `one_for_one`,
  `one_for_all`, `rest_for_one`, `simple_one_for_one` — adapted
  to chain reality, where "restart" maps to "issue a compensating
  or re-initialization message".
- Provide a system-level root supervisor that catches truly orphaned
  failures (a dead-letter sink, analogous to OTP's `error_logger` /
  `logger`).

**Why it matters.** Supervision is what turns an actor system from
"a concurrency model" into "a fault-tolerant system". Erlang's
nine-9s telecom record, and every billion-user OTP deployment
since, rests on this single feature. Without it, every contract
author re-invents partial recovery logic, usually incorrectly.

### 5.2. Time as a first-class message primitive

**Gap.** The Hewitt axioms guarantee *eventual delivery* (fairness)
but say nothing about deadlines. Every working actor system makes
time a primitive — Erlang's `receive ... after Timeout -> ...` and
`erlang:send_after/3` are the canonical example — because timeouts
and expirations cannot be expressed otherwise. Today, in TOS,
"fire in 30 minutes" requires either an off-chain keeper bot or a
`now()` check stuffed into every inbound message — both of which
leak the time concern outside the actor.

**Direction.**

- Add a native `send_at(target, body, when)` primitive — the
  on-chain analogue of `erlang:send_after/3` — where `when` may
  be a logical time, a unix timestamp, or a block number. The
  protocol takes responsibility for delivering no earlier than that
  point, with a bounded fairness window.
- Define semantics for cancellation (`cancel_scheduled(handle)`,
  analogous to `erlang:cancel_timer/1`) and for what happens to
  scheduled messages addressed to frozen or deleted accounts.
- Provide `gen_server:call`-style per-request timeout on the
  request/reply path (see 5.6).

**Why it matters.** Escrows, vote deadlines, order expirations,
vesting cliffs, and time-locked transfers all currently rely on
external keepers or per-message "is it time yet?" logic. Once time
is a protocol primitive, an entire class of off-chain infrastructure
disappears, and the resulting contracts become self-contained
actors again — exactly as the model intends.

### 5.3. Structured error / bounce protocol

**Gap.** A bounce body today carries roughly 224 usable bits of
payload and only fires on a subset of failure paths (compute-phase
abort). For the actor model this is the equivalent of allowing only
an integer as an exit reason. Erlang's `{'EXIT', Pid, Reason}`
signals (and OTP's `{stop, Reason, State}` return values) carry
arbitrary structured `Reason` terms precisely because flat error
codes are not enough to drive non-trivial recovery.

**Direction.**

- Carry a fully structured error in bounce messages — error class,
  originating actor address, original message hash, optional data
  cell for diagnostic detail — directly analogous to Erlang's
  arbitrary-term `Reason`.
- Distinguish **transient** failures (out-of-gas, temporarily
  unreachable, queue congestion) from **permanent** failures
  (uncaught exception, frozen account, code rejected). OTP makes
  the same distinction through `{stop, normal, _}` vs.
  `{stop, Reason, _}` — only abnormal stops trigger supervisor
  restart.
- Surface a "linked actor crashed" signal automatically when 5.1
  (supervision) is in place, equivalent to the `{'DOWN', Ref,
  process, Pid, Reason}` message a `monitor/2` caller receives.

**Why it matters.** Combined with 5.1, this is what makes "let it
crash" actually viable. Without structured errors, supervisors have
nothing to discriminate on and can only blanket-restart, which is
unsafe in a financial setting.

### 5.4. Capability addressing as a complement to content addressing

**Gap.** TOS addresses are *content-addressed*: `account_id =
hash(StateInit)`. This is what makes sharding work and what lets
clients predict-and-pre-fund addresses (jetton wallets, wallet-vN
derivation). The cost is that Hewitt's **locality of reference**
property — that an actor only knows addresses it has been given —
is given up: anyone can compute any address and send to it. This
is the structural root cause of dust-spam, phishing-jetton, and
"scam NFT in your wallet" attacks at the application layer.

**Direction.** Layer **per-relationship capability handles** on top
of content-addressed identities. A capability is an unforgeable
token that grants the bearer the right to send messages to a
*specific internal entry point* of the holder. Inspirations include
Pony's reference capabilities, the Pact capability system, and
E-language unguessable references. (Erlang's process identifiers
also have this property — a `Pid` is unguessable and unforgeable —
which is part of why Erlang systems do not need application-layer
allowlists.)

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
protocol or language layer. Strictly speaking, **Hewitt's
addresses already are capabilities** — TOS has, for sharding
reasons, degraded them to public IDs; introducing a capability
layer gives that property back without giving up content
addressing.

This is the most research-heavy item in the list and is best driven
through a public design document before any implementation work.

### 5.5. `become` as an explicit language primitive

**Gap.** In FunC, `become` is implemented by hand as bit layout in
`c4`; the compiler has no idea which behavior the contract is
currently in. Tolk's `receive(...)` style is a step in the right
direction but still lacks the notion of a *current state* as a
first-class concept.

The OTP precedent is `gen_statem`: an actor is declared with named
states, and message handlers are written as `StateName(EventType,
Event, Data) -> {next_state, NextStateName, NewData, Actions}`.
The compiler — and the runtime dispatcher — knows which state the
actor is in and routes messages accordingly. State confusion bugs
that are common in hand-coded state machines become structurally
impossible.

**Direction.** Introduce explicit state-machine syntax in Tolk
that maps cleanly onto the `gen_statem` model:

```tolk
contract Auction {
    states: Open, Settling, Closed

    receive("bid")    on Open     { ... become Settling }
    receive("settle") on Settling { ... become Closed   }
}
```

The compiler can then statically verify:

- **Exhaustiveness.** For every state, what happens to every
  defined message — bounce, ignore, or handle?
- **Reachability.** Is any state unreachable? Is any state a sink
  with no exits?
- **Invariant preservation.** Data fields valid only in certain
  states cannot be read in others.

`SETCODE` already provides the on-chain analogue of OTP's
`code_change/4` callback for in-flight behavior replacement; what
is missing is the *named-state* layer above it.

**Why it matters.** This lifts Hewitt's *designate next behavior*
from an implicit convention buried in `c4` field layout to a
statically checkable contract skeleton. A large class of
high-severity contract bugs — state confusion, double-handling,
missing transitions — becomes a compile-time error.

### 5.6. Standardize request/reply correlation

**Gap.** Every contract author re-invents `query_id` to pair a
response with its request. Each token contract, each NFT
standard, each TEP-style application surface ships its own
variant. This is precisely the kernel of OTP's `gen_server:call/2,3`
— the canonical case of *"do it once at the protocol level, every
contract reuses it"*. `gen_server:call` ships with a built-in
monotonic reference tag, a default 5 s timeout, and a `{reply,
Reply, NewState}` return contract; clients never write that
plumbing themselves.

**Direction.**

- Add `query_id` (or a richer correlation token, modeled on the
  Erlang reference) and an optional `reply_to` to the standard
  message header.
- Make timeouts on outstanding requests a first-class feature,
  matching `gen_server:call`'s timeout argument; composes with
  5.2.
- Expose this in Tolk as something close to `co_await
  send_request(target, body)` — semantically equivalent to a
  `gen_server:call`. The C++20 coroutine layer already present in
  `tdactor/` is a useful reference for the surface design, even
  though the language-side implementation is independent.

**Why it matters.** Pure developer experience: it eliminates a
recurring source of bugs (mismatched query IDs, lost replies) and
makes contracts read like straight-line code while remaining
honest async actors underneath — exactly the readability /
correctness gain `gen_server:call` delivered four decades ago.

### 5.7. Cross-shard delivery SLA and dead-letter handling

**Gap.** Theory says messages are delivered eventually. In
practice, cross-shard messages can stall: queue congestion, frozen
recipients, fork resolution. There is no explicit "if undeliverable
after N blocks, route to dead-letter" mechanism today. OTP solves
this with supervisor escalation when a child fails repeatedly and
with the system `error_logger` / `logger` sink that catches
unhandled exits — both are needed at the protocol layer here.

**Direction.**

- Define a maximum delivery window per message (default + override).
- On expiry, route to either (a) the sender's bounce handler with
  an `Undeliverable` error class, or (b) a system-level dead-letter
  actor (the analogue of OTP's `error_logger`).
- Expose queue-pressure metrics to the sender so it can apply
  back-pressure rather than blindly enqueuing.

**Why it matters.** Stuck cross-shard messages are a recurring pain
point and currently force application-layer timeouts everywhere.
Solving this at the protocol level removes a class of liveness
bugs.

### 5.8. Actor-level observability

**Gap.** Actor introspection is what makes large actor systems
debuggable in production. Erlang/OTP's toolset is the gold
standard: `process_info/1,2` for live process inspection,
`erlang:trace/3` and `dbg` for selective message tracing, the
`observer` GUI for system-wide views, and the `recon` library for
production-safe deep-dive diagnostics. TOS contracts today are
debugged primarily by replaying transactions off-chain — a much
weaker substitute.

**Direction.** Provide each contract with deterministic
introspection into its own:

- recent message history (windowed, bounded) — analogue of
  `process_info(Pid, messages)`;
- inbound mailbox depth, where any future model gives that concept
  meaning — analogue of `process_info(Pid, message_queue_len)`;
- the up- and downstream actors it has interacted with recently —
  analogue of `process_info(Pid, links)` and `monitors`.

The on-chain surface should remain deterministic; the richer view
(`erlang:trace`-equivalent message-flow inspection, `observer`-style
dashboards) can live in a standardized off-chain indexer protocol.

**Why it matters.** It is hard to overstate the productivity delta
between "ask the actor what it just did" and "replay the chain".
Once contracts get larger and supervised (5.1), this becomes
essential rather than nice-to-have.

## 6. Prioritization

If TOS resources are constrained, the recommendation is:

1. **5.1 (supervision) + 5.3 (structured errors) + 5.2 (time
   primitive)** — together, this is *the minimum industrial-grade
   actor system*, and it maps almost one-to-one onto the OTP
   triad of `supervisor` + exit-signal protocol + `send_after` /
   `after Timeout`. Doing all three is the most visible
   first-principles win, and they reinforce each other.

2. **5.5 (`become` syntax) + 5.6 (request/reply standardization)** —
   developer-experience layer, modeled on `gen_statem` and
   `gen_server:call`. Lower protocol risk, very high
   bug-prevention value. Best done in coordination with the Tolk
   language team.

3. **5.4 (capability addressing)** — long-horizon research item.
   Highest theoretical payoff (closes the locality-of-reference
   gap) but largest design space. Should start with a public
   design document.

4. **5.7–5.8** — important but lower urgency; pick up once 5.1–5.6
   are in motion.

## 7. Closing framing

TOS encodes the Actor Model into its **execution semantics**. From
first principles — replication, partitioning, no shared memory,
concurrent progress — that was the only consistent choice. What
remains is to encode the same model into **fault tolerance**
(5.1, 5.3), **time** (5.2), **composition** (5.5, 5.6), **access
control** (5.4), and **observability** (5.7, 5.8).

Erlang/OTP has shown for forty years that those layers are
necessary for an actor system to survive in production, and what
the right shape of each layer looks like. Strengthening these
layers, with OTP as the empirical reference, is what would let TOS
state — accurately and from first principles — that it is an
actor-faithful blockchain by derivation, not by analogy.
