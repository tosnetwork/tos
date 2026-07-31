# AI Actor Threat Model

This document defines the baseline threat model for AI actor workflows on TOS.

It applies to agent accounts, task actors, service actors, verifier actors,
workflow indexers, off-chain agent runners, and
[AI Edge Computing Terminals](ai-edge-computing-terminal-architecture.md) that
interact with native TVM contracts. It also covers public ARD catalogs, TOS
ARD Registries, registry federation, and discovery clients as defined by the
[TOS ARD compatibility profile](tos-ard-compatibility.md).

## Assets

- task escrow balances
- agent account balances
- service actor payment streams
- owner and controller keys
- delegated agent permissions
- task state and settlement decisions
- result metadata and evidence references
- verifier decisions and reputation inputs
- terminal runtime keys, paid task state, model/artifact commitments, and
  bounded local compute resources
- site sensor data, physical safety state, actuator authority, offline
  journals, update/model signers, and fleet delegation
- ARD publisher identities, catalog integrity, registry provenance, private
  resource visibility, and discovery-policy state

## Trust Boundaries

- Chain state is authoritative for balances, permissions, task status, deadlines, and settlement.
- Off-chain agent runners are not trusted by default.
- Service endpoints are not trusted by default.
- Indexers and workflow dashboards provide derived views only.
- ARD catalogs and Registry results are untrusted discovery inputs, not
  authorization, current availability, price, payment destination, execution
  evidence, or settlement state.
- Public ARD publisher identity is anchored in the verified publisher FQDN.
  A `.tos` name or raw ADNL address requires a documented gateway or private
  registry trust policy and is not automatically equivalent to public DNS
  control.
- Evidence references are claims until verified by a verifier actor, proof adapter, signature check, or trusted policy.
- A site-bound terminal's independent local safety controller has final
  actuator authority; chain payment or a valid network signature cannot
  override it.
- Cached offline authority is valid only within its signed value, quantity,
  age, capability, and expiry bounds.
- Fleet dashboards, desired configuration, and health aggregation are
  off-chain derived state and cannot override chain authorization or local
  safety.

## Primary Threats

### Permission Escalation

An agent, session, or service gains owner-equivalent authority without an explicit grant.

Required controls:

- bounded delegation
- explicit spending limits
- separate owner, controller, fee payer, service, and verifier roles
- inspectable permission state

### Owner and Controller Key Confusion

An off-chain agent runtime obtains the Agent Wallet owner key, or an operator mistakes a
controller-authorized action for an unrestricted owner-authorized wallet transfer.

Required controls:

- keep the Agent Wallet owner key in the operator-controlled vault and never export it to the
  agent runtime
- use the controller key only through Agent Account messages that enforce sequence numbers,
  expiry, per-action limits, and daily limits on-chain
- require `tosctl agent wallet send` to use the owner key and explicit operator confirmation
- do not allow `tosctl agent wallet send` to accept controller signatures or runtime manifests
- reserve owner-authorized transfers for manual treasury maintenance, refunds, emergency
  withdrawals, and agent retirement
- route automated task and service spending through the policy-enforced Agent Account path

### Escrow Theft

A task actor releases funds to the wrong party or releases funds before the required result or verification state exists.

Required controls:

- explicit task state machine
- sender checks on settlement messages
- deterministic timeout behavior
- payout amounts derived from escrow state

### Replay and Cross-Domain Confusion

A valid message or capability grant is replayed against another task, deployment, chain, or service actor.

Required controls:

- `query_id` correlation
- task id in lifecycle messages
- replay domain in capability constraints
- global id and address binding in signed payloads where applicable

### Service Overcharging

A service actor charges without an authorized request or charges more than the task budget allows.

Required controls:

- service-call authorization tied to task state
- max-value constraints
- signed or hash-referenced service responses
- settlement checks against verified chain state

### Terminal Capability Fraud and Resource Exhaustion

A terminal falsifies a hardware, model, benchmark, region, privacy, or
availability claim, or an anonymous caller creates unbounded RAM, VRAM, disk,
queue, watcher, cache, or settlement growth.

Required controls:

- distinguish declared, observed, benchmarked, audited, attested, and
  replicated claims
- bind quotes to exact service, model, runtime-policy, price, and evidence
  revisions
- enforce local admission before allocating expensive model/runtime resources
- bound connections, sessions, queues, contexts, outputs, retries, caches,
  temporary files, watchers, and durable reconciliation
- release resources after success, cancellation, timeout, disconnect, failed
  payment, adapter crash, OOM, and restart
- isolate co-located AI, storage, and commerce credentials, queues, and data
- use extended anonymous-load and fault-injection soak tests

### ARD Catalog and Registry Poisoning

A publisher, crawler target, compromised registry, federated peer, or
catalog-supplied natural-language field causes identity confusion, endpoint
substitution, stale discovery, prompt injection, private-resource disclosure,
server-side request forgery, ranking manipulation, or unbounded crawler and
index growth.

Required controls:

- pin and validate the supported ARD version, schema, media types,
  value-or-reference rules, domain-anchored identifiers, and publisher binding
- treat descriptions, representative queries, tags, endpoints, references,
  trust metadata, and nested catalogs as untrusted data, never as executable
  instructions
- allow only approved schemes, ports, address classes, redirect policies, and
  content types; resolve and recheck targets to prevent DNS rebinding and SSRF
- impose catalog, entry, field, reference, redirect, recursion, federation
  hop, cycle, response, time, retry, cache, index, and per-publisher quotas
- preserve field-level provenance and distinguish publisher data,
  registry-derived ranking, on-chain state, observations, and attestations
- require expiry, revalidation, rollback/equivocation handling, and bounded
  stale-result retention
- apply visibility policy before indexing or federating private catalogs and
  never publish credentials, private endpoints, topology, raw sensor data, or
  customer payloads
- independently verify the current TOS descriptor, runtime authorization,
  manifest commitment, live quote, admission decision, and payment
  destination before invocation or value transfer
- ensure an ARD result never grants terminal, wallet, update, model, fleet, or
  actuator authority

### Offline Authority and Reconciliation Failure

A disconnected physical terminal accepts work using stale or revoked
authority, grows an unbounded journal, or duplicates events, actions, charges,
or settlement after reconnect.

Required controls:

- allow only explicitly pre-authorized offline capabilities with bounded value,
  quantity, age, and expiry
- continue site-owned local safety work without inventing payment authority
- bound journal bytes, entries, age, unacknowledged receipts, retry work, and
  compaction
- use idempotent event, action, voucher, receipt, and settlement identities
- observe current key, policy, model, and terminal revocation before new
  network admission
- discard expired queued requests and reconcile acknowledged journal segments
  with bounded work

### Malicious or Faulty Model and Software Update

An attacker, compromised update service, incompatible package, or interrupted
activation changes physical behavior, disables a terminal, or compromises a
fleet.

Required controls:

- content-address and sign every model, runtime, firmware, configuration, and
  policy package under separate scoped authorities
- verify target hardware, dependencies, security revision, license, resource
  requirements, and migration compatibility
- use bounded staging plus active and known-good rollback slots
- activate crash-safely and recover from power loss at every phase
- deploy through lab/canary/cohort rollout rings with automatic health gates
- support authorized emergency rollback while preventing silent rollback to a
  known-vulnerable revision
- bind active quotes and receipts to the exact model/runtime/policy revision

### Actuator and Physical-I/O Escalation

A remote caller, compromised model, or service adapter bypasses local policy
and sends unsafe commands to CAN, GPIO, serial, fieldbus, motors, steering,
brakes, doors, valves, or robotic joints.

Required controls:

- expose no generic raw physical-I/O API through TOS
- represent allowed actions as narrow semantic capabilities
- enforce caller, task, state, rate, value, deadline, and location constraints
- require idempotent action identifiers and local audit
- keep actuator authority separate from wallet, runtime, update, and model
  keys
- place an independent local safety controller or interlock in final authority
- define a safe operating state for network loss, restart, update, and policy
  failure

### Real-Time Priority Inversion

External requests, telemetry, model downloads, compaction, or fleet commands
starve a safety, control, or local perception deadline.

Required controls:

- enforce emergency, control, real-time perception, local asynchronous,
  external-service, and background priority classes
- reserve CPU, accelerator memory, RAM, I/O, disk, network, and thermal
  headroom before advertising capacity
- reject or preempt lower-priority work first
- keep TOS networking and settlement outside the hard real-time loop
- test deadline behavior under external saturation, OOM, thermal pressure,
  update, reconnect, and telemetry load

### Fleet Authority and Fan-Out Compromise

A fleet key, site administrator, rollout command, health collector, or retry
loop gains excessive authority or affects every terminal at once.

Required controls:

- separate fleet owner, site administrator, terminal runtime, update, model,
  payment, and actuator authorities
- scope delegation by terminal group, capability, configuration field, value,
  rollout operation, and expiry
- revoke one terminal without authorizing or revoking peers
- stage fleet-wide changes through explicit rollout rings and health gates
- bound group size, pagination, fan-out, retries, watchers, offline records,
  history, and health retention
- keep detailed fleet topology and continuous telemetry off-chain
- expire permanently offline terminals from active health without immortal
  retry or watcher state

### Fake Results or Evidence

An agent submits a result hash, transcript, or evidence reference that is not connected to the requested task.

Required controls:

- result metadata hash bound to task id
- optional verifier actor decision
- evidence reference hash
- result acceptance rules visible from contract state

### Indexer Authority Drift

Clients treat derived workflow timelines, ARD search results, registry health
signals, rankings, or reputation data as authoritative for spending,
invocation, physical action, or settlement.

Required controls:

- trust-tier labeling
- node-verified checks for balances and permissions
- clear distinction between indexed views and contract state
- field-level discovery provenance and client-side revalidation of publisher,
  endpoint, descriptor, quote, and payment bindings

### Message Amplification

Retries, supervision, scheduled messages, or back-pressure responses create unbounded traffic.

Required controls:

- funded retries
- bounded scheduled-message queues
- restart intensity limits
- delivery-SLA failure records
- explicit backoff guidance

## Minimum Review Before Production

Every production AI actor primitive should receive review for:

- authorization and role separation
- replay domains
- escrow accounting
- timeout and cancellation paths
- service-call payment limits
- evidence and verifier semantics
- indexer trust boundaries
- ARD publisher binding, catalog parsing, Registry provenance, federation,
  SSRF, prompt-injection, privacy, and bounded-state controls
- denial-of-service and message amplification
- local testnet restart and catch-up behavior
