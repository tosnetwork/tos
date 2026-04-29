# Strengthening TOS from Actor-Model First Principles

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

## 1. First principles: actors are the cleanest fit for TOS

The actor model is not adopted in TOS because it is fashionable, nor
because it is convenient. It is the cleanest semantic fit for a small
number of architectural commitments TOS has already made:

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

From (3) and (4), shared-memory and blocking-RPC designs are ruled
out as foundation primitives between state owners. What remains is
an **asynchronous, consensus-ordered handoff**: a value handed off,
received later, with no shared call stack and no shared lock. Other
distributed systems can encode that handoff as a log record,
cross-shard receipt, or deterministic transaction batch. TOS exposes
it directly as an internal message.

Given TOS's internal-message primitive, the natural unit of
ownership is whatever holds:

- a private mutable state,
- an inbound message capability (an "address"),
- a transition rule that maps `(state, message) → (new state,
  outbound messages)`.

That object is an **actor** in the precise sense that matters for
TOS engineering: private state, addressable identity, and a message
transition function.

The claim is therefore narrower than a mathematical uniqueness
theorem. Sharded synchronous L1s, rollup sequencers with
deterministic ordering, and partitioned databases with asynchronous
replication can satisfy related constraints without exposing actors
as their user-facing semantic unit. For TOS specifically, however,
the account + internal-message + single-transaction execution model
already has actor shape. Treating it as an actor system makes the
implicit semantics explicit instead of inventing a parallel model.

The remaining design freedom is **how completely** the model is
realized. TOS today realizes it in execution semantics; the rest of
this document is about realizing it in fault tolerance, time, and
composition as well.

## 2. What TOS already realizes faithfully

On the native workchain (wc=0), every account is an actor, and the
mapping to Hewitt's model is close enough to be the right engineering
baseline:

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
  a not-yet-deployed address can materialize a new actor, subject to
  the chain's deployment, funding, and validation rules. This maps
  closely to Hewitt's creation primitive.
- **`become` axiom.** TVM's commit phase writes back the `c4` (data)
  register. `SETCODE` does not write `c3`; it creates an output
  action that, after normal transaction termination, replaces the
  account's persistent code root. Together these implement a
  persistent on-chain form of *designate next behavior*: the account
  commits both its next data and, when `SETCODE` is used, its next
  code. This is lower-level and more durable than library-level
  behavior switching, but it is not by itself an OTP-grade upgrade
  protocol. Erlang's `code_change/4` and release handling remain the
  stronger precedent for coordinated in-flight behavior migration.
- **Single-message atomicity.** A transaction processes exactly one
  inbound message to commit-or-abort.
- **No synchronous cross-actor calls.** Two contracts cannot share
  a call stack or synchronously mutate each other's storage; they
  can only message each other.

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
  schedules Hewitt would consider legal. This is more than a
  harmless implementation detail: validator inclusion, block
  ordering, gas failure, bounce behavior, and MEV become part of
  the semantics. TOS is therefore best understood as a deterministic
  specialization of the actor model, not merely as a runtime that
  happens to pick one schedule.
- **Content-addressed identities.** Sharding does not logically
  require addresses to be hashes of `(code, data)`, but TOS uses
  content-derived account identities because they make predeployment
  address derivation, pre-funding, and shard routing operationally
  simple. This forfeits Hewitt's locality-of-reference property in
  mechanism, although unforgeability of the *sender* of a message
  is preserved by the protocol.
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
  restart child actors under a declared strategy (`one_for_one`,
  `one_for_all`, `rest_for_one`, plus the legacy/specialized
  dynamic-child strategy `simple_one_for_one`);
- `application` — a top-level supervised unit of deployment with
  start, stop, and configuration semantics.

Decades later this stack runs WhatsApp's messaging backplane,
Discord's session layer, RabbitMQ, CouchDB, Riak, and ejabberd. It
is the strongest empirical reference for a multi-decade,
billion-user actor-system production track record.

Every strengthening direction in §5 below has a useful precedent in
Erlang/OTP, but not a one-to-one transplant. TOS must re-express
each idea under consensus determinism, sharding, gas accounting, and
public-chain denial-of-service constraints:

| Direction | Erlang / OTP precedent |
|---|---|
| 5.1 Supervision trees | `supervisor` behaviour with `one_for_one`, `one_for_all`, `rest_for_one`, and legacy/specialized `simple_one_for_one`; `link/1`, `spawn_link/1`, `process_flag(trap_exit, true)` |
| 5.2 Time as a primitive | `receive ... after Timeout -> ...`; `erlang:send_after/3`; `erlang:start_timer/3,4`; `gen_server:call/3` timeouts |
| 5.3 Structured errors | `{'EXIT', Pid, Reason}` exit signals; `monitor/2` and `{'DOWN', Ref, process, Pid, Reason}` messages; OTP `{stop, Reason, State}` return values |
| 5.5 `become` as language primitive | `gen_statem` named states with explicit `StateName(EventType, Event, Data)` transition clauses; `code_change/4` for in-flight behavior upgrades |
| 5.6 Request/reply correlation | `gen_server:call/2,3` and newer request-id APIs with opaque request identifiers, default 5 s timeout for `call/2`, and structured `{reply, Reply, NewState}` returns |
| 5.7 Delivery failure handling | No exact OTP equivalent; closest precedents are supervisor escalation, timeout handling, and the `logger` sink for unhandled failures |
| 5.8 Observability | `process_info/1,2`; `erlang:trace/3`; `dbg`; the `observer` GUI; the `recon` library |
| 5.9 Selective receive / postponement | Erlang selective receive; `gen_statem` event postponement |

These are strong analogies, not direct equivalences. They are the
closest existing artifacts to what TOS would be standing up at the
protocol and language layers. The engineering decisions that made
them work — restart strategies as declarative policy rather than
imperative recovery code, exit signals as structured messages
rather than ad-hoc return codes, named states as an explicit
runtime/language concept rather than as a convention — are the
deliverables TOS should learn from.

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
- Standardize the OTP restart-strategy family — `one_for_one`,
  `one_for_all`, `rest_for_one`, and a carefully designed dynamic
  child pattern inspired by `simple_one_for_one` — adapted to chain
  reality, where "restart" maps to "issue a compensating or
  re-initialization message".
- Provide a system-level failure sink for truly orphaned failures,
  closer to a protocol health/audit log than to a direct copy of
  OTP's logging subsystem.

The hard part is not the vocabulary. In Erlang, a crash and restart
are local runtime events. On-chain, every notification and recovery
action is a consensus-visible message that consumes gas, can be
griefed, and can amplify load. A viable design needs explicit
budgets, restart-intensity limits, funding rules for supervisor
messages, and protection against restart storms. The single
`supervisor address` sketch above is only a starting point; see 6.3
for the link/monitor split and 6.4 for restart-intensity and circuit
breaker rules.

**Why it matters.** Supervision is what turns an actor system from
"a concurrency model" into "a fault-tolerant system". Erlang's
telecom availability story and many large OTP deployments depend
heavily on this feature. Without an equivalent failure model, every
contract author re-invents partial recovery logic, usually
incorrectly.

### 5.2. Time as a first-class message primitive

**Gap.** The Hewitt axioms guarantee *eventual delivery* (fairness)
but say nothing about deadlines. Production actor systems usually
make time a primitive — Erlang's `receive ... after Timeout -> ...`
and `erlang:send_after/3` are the canonical examples — because
timeouts and expirations are otherwise pushed into ad-hoc protocol
logic. Today, in TOS,
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

The primitive must be priced and bounded as a chain resource. Timer
queues create validator work, persistent state, and MEV-sensitive
expiry points. Any design must specify maximum outstanding timers,
rent for scheduled messages, cancellation race semantics, and DoS
limits before it can be protocol-safe.

**Why it matters.** Escrows, vote deadlines, order expirations,
vesting cliffs, and time-locked transfers all currently rely on
external keepers or per-message "is it time yet?" logic. Once time
is a protocol primitive, much of that off-chain infrastructure can
be reduced or standardized, and the resulting contracts become more
self-contained actors.

### 5.3. Structured error / bounce protocol

**Gap.** TOS has already moved beyond the old narrow bounce format.
TVM v12 introduced full bounces: when the new bounce flag is enabled,
the bounced message can include the original body, original value and
time metadata, the phase that caused the bounce, the exit code, and
compute-phase gas/step information. That is a major improvement over
the historical 224-bit bounce stub. The remaining gap is
standardization: failure payloads still need a canonical taxonomy and
a stable contract-level interpretation so they can drive recovery
logic rather than merely report that something failed. Erlang's
`{'EXIT', Pid, Reason}` signals (and OTP's `{stop, Reason, State}`
return values) carry arbitrary structured `Reason` terms precisely
because flat error codes are not enough to drive non-trivial recovery.

**Direction.**

- Carry a bounded, canonical structured error in bounce messages —
  error class, originating actor address, original message hash, and
  an optional gas-charged diagnostic cell. Erlang's arbitrary-term
  `Reason` is the conceptual precedent, but TOS cannot allow
  unbounded or non-canonical error payloads.
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
hash(StateInit)`. This is operationally useful: clients can derive
and pre-fund addresses before deployment (jetton wallets, wallet-vN
derivation), and validators can route by address. The cost is that
Hewitt's **locality of reference** property — that an actor only
knows addresses it has been given — is given up at the base address
layer. Anyone can compute or learn a public account address and send
to it. This is one structural cause of dust-spam, phishing-jetton,
and "scam NFT in your wallet" attacks at the application layer.

**Direction.** Layer **per-relationship authorization handles** on
top of content-addressed identities. This would not make the account
address secret again; it would add a second admission-control plane
that determines which peers may invoke which internal entry points.
The closest conceptual inspiration is E-language unguessable
references. Pony reference capabilities are more about type-system
permissions than bearer routing tokens, and Pact capabilities are
scoped authorization during transaction execution; both are useful
references, but neither can be copied directly into a public chain.

A pragmatic shape:

- A contract can mint an authorization handle that lets a specific
  peer invoke a specific receive-handler with specific argument
  bounds.
- The protocol or language runtime verifies the handle before the
  handler runs, so common ACL logic does not need to be reimplemented
  in every contract.
- Revocation, transfer, replay protection, leakage, and expiry must
  be first-class parts of the design, not afterthoughts.

**Why it matters.** It pulls access control down from the
application layer (each contract handcrafting allowlists) into the
protocol or language layer. But this should be described precisely:
it does not recover pure Hewitt locality of reference, because the
base account address remains public. It can only restore some of the
security properties of capabilities at the entry-point authorization
layer.

This is the most research-heavy item in the list. A design document
must decide whether a handle is a private bearer secret, a signature
or MAC, a public on-chain grant, or a stateful registry entry. Each
choice has different consequences for secrecy, revocation, validator
load, state bloat, and phishing resistance. No implementation should
start before those tradeoffs are explicit.

### 5.5. `become` as an explicit language primitive

**Gap.** In FunC, `become` is implemented by hand as bit layout in
`c4`; the compiler has no idea which behavior the contract is
currently in. Tol's `receive(...)` style is a step in the right
direction but still lacks the notion of a *current state* as a
first-class concept.

The OTP precedent is `gen_statem`: an actor is declared with named
states, and message handlers are written as `StateName(EventType,
Event, Data) -> {next_state, NextStateName, NewData, Actions}`.
The runtime dispatcher knows which state the actor is in and routes
events accordingly. Erlang itself does not statically prove
exhaustiveness or reachability; those would be additional guarantees
Tol could add at the language layer.

**Direction.** Introduce explicit state-machine syntax in Tol
that maps cleanly onto the `gen_statem` model:

```tol
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

`SETCODE` already provides the low-level on-chain mechanism for
future behavior replacement. OTP's `code_change/4` remains the
better precedent for coordinated state migration during behavior
upgrades; what is missing in TOS is the *named-state* layer above
the raw `c4`/`SETCODE` convention.

**Why it matters.** This lifts Hewitt's *designate next behavior*
from an implicit convention buried in `c4` field layout to a
statically checkable contract skeleton. A large class of
high-severity contract bugs — state confusion, double-handling,
missing transitions — can become compile-time errors if the Tol
type system makes state, messages, and allowed transitions explicit.
Section 6.5 generalizes this idea from one syntax feature into a
library of reusable Tol behaviour patterns.

### 5.6. Standardize request/reply correlation

**Gap.** Every contract author re-invents `query_id` to pair a
response with its request. Each token contract, each NFT
standard, each TEP-style application surface ships its own
variant. This is precisely the kernel of OTP's `gen_server:call/2,3`
— the canonical case of *"do it once at the protocol level, every
contract reuses it"*. `gen_server:call/2` ships with an opaque
request identity, a default 5 s timeout, and a `{reply, Reply,
NewState}` return contract; clients never write that plumbing
themselves.

**Direction.**

- Add `query_id` (or a richer correlation token, modeled on the
  Erlang reference) and an optional `reply_to` to the standard
  message header.
- Make timeouts on outstanding requests a first-class feature,
  matching `gen_server:call`'s timeout argument; composes with
  5.2.
- Expose this in Tol as something close to `co_await
  send_request(target, body)` at the source level. This cannot
  literally block a transaction; it must compile to continuation
  state, callbacks, or an explicit state-machine transition. The
  C++20 coroutine layer already present in `tdactor/` is a useful
  reference for the surface design, even though the language-side
  implementation is independent.

The protocol surface must also define duplicate replies, replayed
messages, spoofed `reply_to`, timeout cleanup, and backward
compatibility with existing TEP-style `query_id` conventions.

**Why it matters.** Pure developer experience: it eliminates a
recurring source of bugs (mismatched query IDs, lost replies) and
makes contracts read like straight-line code while remaining
honest async actors underneath — the same kind of readability /
correctness gain `gen_server:call` delivered four decades ago.

### 5.7. Cross-shard delivery SLA and dead-letter handling

**Gap.** Theory says messages are delivered eventually. In
practice, cross-shard messages can stall: queue congestion, frozen
recipients, fork resolution. There is no explicit "if undeliverable
after N blocks, route to dead-letter" mechanism today. OTP does not
provide an exact equivalent for sharded-chain delivery failure; the
closest precedents are supervisor escalation, timeout handling, and
centralized logging of unhandled failures.

**Direction.**

- Define a maximum delivery window per message (default + override).
- On expiry, route to either (a) the sender's bounce handler with
  an `Undeliverable` error class, or (b) a system-level dead-letter
  actor.
- Expose queue-pressure metrics to the sender so it can apply
  back-pressure rather than blindly enqueuing.

This is a consensus and congestion-control feature, not just an
actor-library feature. It must account for expiry MEV, forced-bounce
amplification, queue-pressure information leakage, and the exact
definition of "undeliverable" across forks, shard splits, frozen
accounts, and delayed imports.

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

**Direction.** Provide each contract and off-chain tooling with
bounded, deterministic introspection into:

- pending inbound messages or queue length, where any future model
  gives that concept meaning — analogous to `process_info(Pid,
  messages)` and `process_info(Pid, message_queue_len)`;
- explicit supervision or monitoring relationships, if 5.1 exists —
  analogous to `process_info(Pid, links)` and `monitors`;
- recent message history through a bounded off-chain trace/indexer
  protocol rather than as unbounded on-chain account state.

The on-chain surface should remain deterministic; the richer view
(`erlang:trace`-equivalent message-flow inspection, `observer`-style
dashboards) can live in a standardized off-chain indexer protocol.
Putting full history directly in contract state would create state
bloat and privacy leakage.

**Why it matters.** It is hard to overstate the productivity delta
between "ask the actor what it just did" and "replay the chain".
Once contracts get larger and supervised (5.1), this becomes
essential rather than nice-to-have.

### 5.9. Selective receive and message postponement

**Gap.** Erlang actors can use selective receive to handle one class
of message while leaving other messages in the mailbox. `gen_statem`
also has an explicit postponement mechanism: an event that is not
valid in the current state can be deferred until a later state. TOS
contracts today mostly approximate this by rejecting, bouncing,
ignoring, or manually storing messages in contract state. That pushes
ordering and deferral policy into each contract.

**Direction.** TOS should not copy Erlang selective receive directly.
Unbounded mailbox scanning is a poor fit for a deterministic,
gas-metered chain: it creates order-dependence, DoS risk, and
validator work that is hard to price. The safer direction is a
bounded postponement primitive or language pattern:

- a contract can declare which message classes are valid in each
  state;
- invalid-but-deferrable messages can be postponed under a strict
  count, size, gas, and time/rent budget;
- postponed messages have explicit expiry and failure behavior;
- the execution order remains deterministic and auditable;
- the feature composes with 5.5 state-machine syntax and 5.7
  delivery failure handling.

**Why it matters.** Many real actor protocols need to defer messages
that arrive "too early" without treating them as fatal errors:
settlement before auction close, completion before dependency ready,
or retry after temporary congestion. A bounded postponement model
would give TOS the useful part of selective receive without importing
Erlang's unpriced mailbox-scanning semantics.

## 6. Additional OTP lessons for TOS

The nine directions above cover the main actor-facing features.
Several additional OTP lessons remain: some are operational
disciplines, while others are protocol-level refinements that the
§5 directions need in order to land safely.

### 6.1. Release handling and upgrade discipline

OTP's release handling is not merely "hot code upgrade". It is a
disciplined system for packaging applications, declaring upgrade and
downgrade steps, running `code_change/4`, and rolling a live system
forward or backward through explicit release metadata.

TOS should learn that discipline at the protocol and contract
standard layer:

- feature activation by height or capability flag;
- explicit compatibility windows for old and new message headers;
- migration plans for system contracts and critical libraries;
- rollback plans for failed upgrades;
- state-migration proofs or audit artifacts for changes that rewrite
  persisted state.

This matters because TOS already has persistent `SETCODE`-style
behavior replacement. The missing part is the operational discipline
around upgrade sequencing, compatibility, and rollback.

### 6.2. Application boundaries and lifecycle

OTP systems are not just loose collections of processes. They are
grouped into applications with start, stop, configuration, and
supervision boundaries. That boundary is what makes deployment and
operations tractable.

TOS should mirror this at the system level:

- validator subsystem lifecycle boundaries;
- workchain feature lifecycle boundaries;
- system-contract package boundaries;
- activation and deactivation hooks;
- readiness and health state for validator, DHT, RPC, archive, and
  state-sync subsystems.

The goal is not to add ceremony. The goal is to make clear which
module owns boot, shutdown, upgrade, failure reporting, and health
for each part of the chain.

### 6.3. Monitors versus links

Erlang deliberately separates links from monitors. A link is a
bidirectional failure relationship; a monitor is a one-way
observation that delivers a `DOWN` message without tying the
observer's fate to the observed process.

TOS should keep the same distinction when designing supervision and
failure notifications:

- "I depend on this actor, and its failure should affect me";
- "I only want to be told if this actor fails";
- "I want a one-shot completion/failure signal for this request";
- "I am responsible for recovery and may issue compensating
  messages".

A single `supervisor` field is too coarse for all of these. Links,
monitors, request correlation, and supervision should be separate
concepts with separate costs and delivery semantics.

### 6.4. Restart intensity and circuit breakers

OTP supervisors do not restart children forever without limits. They
have restart-intensity windows so repeated failure escalates instead
of becoming an infinite loop.

The on-chain equivalent is mandatory. Any TOS supervision design
needs:

- restart budgets;
- failure windows;
- retry cooldowns;
- exponential backoff or rate limits;
- gas escrow depletion rules;
- circuit breakers that stop recovery when it becomes unsafe.

Without this, on-chain supervision can become a message-amplification
attack surface: an adversary triggers a failure and the protocol or
supervisor pays to repeat the failure indefinitely.

### 6.5. Behaviour patterns for Tol contracts

OTP's most reusable abstraction is the behaviour: `gen_server`,
`gen_statem`, and `supervisor` are standard callback contracts that
make common process shapes explicit.

Tol can use the same idea for smart-contract patterns:

- `request_server` for request/reply contracts;
- `timed_actor` for contracts with scheduled actions;
- `supervised_actor` for contracts with failure relationships;
- `state_machine` for explicit `gen_statem`-style transitions;
- domain behaviours such as wallet, jetton wallet, auction, bridge,
  or oracle.

This would give the compiler and tooling a standard place to check
message schemas, states, replies, errors, and timeouts. It is lower
risk than protocol-level supervision and likely to produce immediate
developer-safety wins.

### 6.6. Crash reports and `sys`-style diagnostics

OTP behaviours integrate with `sys` and the logging stack so that
operators can inspect status, trace messages, and receive structured
crash, supervisor, and progress reports.

TOS should standardize the equivalent reporting surfaces:

- structured validator-subsystem crash reports;
- state-sync, import, rollback, archive, and DHT failure reports;
- stable incident correlation IDs across logs, metrics, and on-chain
  events;
- node-local admin/status interfaces;
- deterministic replay trace formats;
- standardized off-chain indexer schemas for actor-level events.

This is especially important for chain operations. "Let it crash"
only works when the crash is isolated, reported, classified, bounded,
and recoverable. A financial chain should interpret that philosophy
as "fail closed with structured recovery", not as permission to crash
silently or restart blindly.

## 7. Prioritization

If TOS resources are constrained, the recommendation is:

1. **Cross-cutting resource semantics.** Before protocol-level
   supervision, timers, or delivery SLAs, define mailbox/back-pressure
   rules, queue limits, retry/idempotency semantics, actor lifecycle
   rules (undeployed, frozen, deleted, rent-expired), and upgrade
   compatibility for old contracts. Without these, the higher-level
   actor features can become message-amplification or state-bloat
   vectors.

2. **5.3 (structured errors) + 5.6 (request/reply correlation).**
   These are the lowest-risk, highest-leverage primitives. They
   improve current contract standards immediately, reduce duplicated
   `query_id`/bounce plumbing, and form the substrate for supervision
   and timeouts later.

3. **5.5 (`become` syntax) + 5.9 (bounded postponement).** This is
   primarily a Tol/compiler improvement modeled on `gen_statem`,
   with lower consensus risk than protocol-level recovery. It gives
   developers explicit state machines and a controlled way to defer
   early messages before the protocol tries to supervise them.

4. **5.2 (time primitive).** Timeouts and scheduled messages compose
   with request/reply and structured errors, but they must wait until
   the resource model for timer queues is explicit.

5. **5.1 (supervision).** Supervision is the right long-term
   fault-tolerance model, but it is expensive on-chain. It should be
   built after structured errors, correlation IDs, and resource
   limits exist.

6. **5.7–5.8.** Delivery failure handling and observability are
   important but should be split: standardized off-chain observability
   can move earlier, while consensus-level delivery SLA should wait
   for back-pressure and timer semantics.

7. **5.4 (capability addressing).** This remains long-horizon
   research. It has high theoretical payoff, but the tension between
   public content-derived identities and private authorization
   handles must be resolved in a separate public design document.

## 8. Closing framing

TOS encodes the Actor Model into its **execution semantics**. From
first principles — replication, partitioning, no shared memory,
concurrent progress — that is the most coherent way to describe the
system TOS has already built. What remains is to encode the same
model into **failure semantics** (5.1, 5.3, 6.3, 6.4), **time**
(5.2), **composition** (5.5, 5.6, 5.9, 6.5), **upgrade discipline**
(6.1, 6.2), **access control** (5.4), and **observability** (5.7,
5.8, 6.6), while keeping the chain-specific constraints explicit.

Erlang/OTP has shown for forty years that actor systems need
structured failure handling, standard request/reply paths, explicit
state machines, timeouts, and observability to survive in
production. TOS should learn those patterns without copying their
cost model. Strengthening these layers, with OTP as the empirical
reference and blockchain constraints as the hard boundary, is what
would let TOS state accurately that it is an actor-faithful
blockchain by derivation, not by analogy.
