# TOS Network Development Roadmap

Status: active cross-repository roadmap  
Last reviewed: 2026-08-01

This document is the canonical program-level view of delivery across the TOS
blockchain, `tos-protocol`, and `tos-ai`. It records implementation status,
not product vision. Detailed requirements remain in
[The TOS Protocol Implementation Plan](the-tos-protocol-implementation-plan.md)
and the linked architecture documents.

Repository-level execution plans are maintained in:

- [`tos-protocol/ROADMAP.md`](https://github.com/tosnetwork/tos-protocol/blob/main/ROADMAP.md)
- [`tos-ai/ROADMAP.md`](https://github.com/tosnetwork/tos-ai/blob/main/ROADMAP.md)

## Status rules

- **Completed** means merged into `main`, covered by automated tests, and not
  dependent on an unstated future implementation.
- **In Progress** is the active delivery milestone. It may include integration
  work split across repositories.
- **Next** is ordered future engineering work, not a promise that every item
  belongs in the next release.
- **External Certification** requires evidence from a real chain, physical
  terminal, production key ceremony, network perimeter, or sustained load. It
  cannot be closed by unit tests alone.

The roadmap does not use a single percentage for the whole TOS vision. A
code-complete protocol library, a deployable terminal, and a production-
certified public service are different milestones and must not be conflated.

## Current milestone

The active milestone is **M1: deployable non-streaming AI Edge service**.

The generic non-streaming v0.1 protocol and private AI Worker foundations are
code-complete candidates. The next product boundary is a public
`tos-ai-edge` composition that connects the reviewed protocol ingress to one
private Worker, current TOS chain authority, purpose-specific key custody,
ARD publication, and an operator-selected authentication policy.

## Completed

### TOS blockchain foundation

- Validator, VM, wallet, smart-contract, JSON-RPC, and query foundations.
- TOS DNS plus ADNL, DHT, RLDP, and TOS Sites transport infrastructure.
- Agent Account, service escrow, task/dispute, capability, and attestation
  primitives required by higher-level service protocols.
- Stable separation between blockchain infrastructure and off-chain product
  repositories; AI workloads do not execute inside validator processes.

### Generic service protocol foundation

- Deterministic base values, canonical encoding, signatures, descriptors,
  manifests, profile selection, sessions, delegation, quotes, payment
  authorization, receipts, and conformance vectors.
- Current TOS authority, client-key, and finalized native-payment adapters
  with strict-majority observation and monotonic chain high-water checks.
- Bounded durable Edge Core with idempotent paid actions, at-most-once Worker
  invocation, restart recovery through read-only task lookup, and signed
  terminal outcomes.
- Purpose-fixed private Quote and Receipt signer sidecars.
- Bounded ARD `POST /search` Registry, optional minimal List, local catalog
  reload, Worker-to-ARD projection, and explicit privacy/resource limits.
- Unary WorkerService v0.1 with structured readiness, resource claims, Quote,
  Invoke, exact Cancel, and retained `GetTask` recovery.

### AI terminal foundation

- Private bounded Unix-socket Worker and diagnostic CLI.
- Resource probes, owner reservations, scheduling, admission, task persistence,
  cancellation, restart reconciliation, and bounded operational metrics.
- Deterministic, Ollama, and OpenAI-compatible runtime adapters.
- Signed model/update verification, bounded model cache, activation, rollback,
  anti-rollback, and local trust policy foundations.
- Immutable `tos.ai.text-generation` v0.1 profile mapper and live Worker
  capability-derived Edge deployment plan with route-identity drift checks.
- Opt-in CPU-only, `network=none` containerd execution foundation and reusable
  isolated-backend conformance tests.
- `tos-ai` pinned to an immutable `tos-protocol` revision, with both repositories
  passing independent race tests and CI.

## In Progress

### M1: deployable non-streaming AI Edge service

- Build a production `tos-ai-edge` executable that composes public Edge Core,
  the text-generation profile, private Worker, chain adapters, Quote/Receipt
  custody, ARD catalog publication, and bounded ingress.
- Select and implement the deployment authentication ceremony for session and
  Quote issuance plus authenticated Action/Receipt status access.
- Configure the three-node local TOS network as the first real authority,
  client-key, payment, controller-rotation, and reorganization test target.
- Package one Tier 1 Linux/NVIDIA terminal configuration without exposing a
  public runtime endpoint, raw GPU rental, arbitrary container, or shell.
- Turn the production-gate checklist into repeatable deployment rehearsals and
  capture artifacts instead of relying on narrative confirmation.
- Freeze and tag the first compatible `tos-protocol`/`tos-ai` release pair only
  after the M1 integration checks pass.

## Next

Work is ordered by dependency, not by repository size.

1. Complete the M1 three-node flow: publish, discover, authenticate, quote,
   pay, execute, recover, deliver a signed receipt, rotate authority, restart,
   and reconcile.
2. Add a bounded ARD remote crawler and federation policy with SSRF, redirect,
   recursion, fan-out, publisher, expiry, and aggregate-index controls.
3. Complete the `.tos` registrar application and stable client SDK surfaces
   needed by independent operators.
4. Specify and implement Worker/result streaming as v0.2 with ordering,
   backpressure, cancellation, resume, usage, and receipt binding; unary v0.1
   remains stable.
5. Add reviewed GPU container isolation and additional fixed runtime activation
   backends only after the Tier 1 non-streaming path is certified.
6. Implement the site-bound physical AI terminal track: offline journal,
   signed update slots, real-time priority, safety isolation, reconnect, and
   fleet management.
7. Start storage, commerce, and human-service profiles only from the stable
   base protocol; they must not fork identity, payment, receipt, or discovery
   formats.
8. Add production relays, multi-region routing, subscriptions/channels,
   replication, and advanced evidence as later milestones.

## External Certification

These items remain open even when all repository tests pass:

- **Live chain:** deploy reviewed contracts and demonstrate controller/key
  rotation, revocation, stale-node rejection, finality, payment observation,
  reorganization, and restart behavior against independent RPC endpoints.
- **Key custody:** conduct Quote and Receipt key ceremonies; bind manifest roles
  to sidecars or HSMs; rehearse rotation, revocation, restart, and outage.
- **Physical isolation:** certify the exact kernel, cgroup v2, containerd,
  runc, seccomp, namespace, filesystem, and any NVIDIA device configuration.
- **Model supply chain:** provision trust roots and rehearse corruption,
  interrupted update, power loss, disk full, anti-rollback, known-good
  rollback, and disconnected operation on target hardware.
- **Availability and memory:** run sustained anonymous-load, malformed-input,
  slow-client, chain/signer/Worker outage, restart, and disk-quota tests while
  recording RSS, heap, goroutines, file descriptors, durable state, RAM, VRAM,
  and cache behavior.
- **Network perimeter:** certify TLS termination, rate and connection limits,
  private sockets, firewall policy, public-response redaction, and home/relay
  reachability.
- **ARD publication:** publish an operator-approved catalog under the selected
  domain or TOS naming path and run the pinned official conformance tooling.
- **Release governance:** reproducible builds, compatibility matrix, rollback
  procedure, independent security review, testnet observation, and signed
  release artifacts.

## Milestone sequence

| Milestone | Exit condition | Current state |
|---|---|---|
| M0: non-streaming foundations | Base protocol, chain adapters, Edge Core, private Worker, text-generation profile, bounded Registry, race-tested cross-repository compatibility | Completed |
| M1: deployable AI Edge service | One public bounded composition completes the three-node discovery-to-receipt flow and passes deployment rehearsals | In Progress |
| M2: v0.1 production candidate | Immutable release pair plus required security, isolation, memory, key, and network evidence | Next |
| M3: streaming and extended discovery | Versioned streaming v0.2, bounded crawler/federation, stable client SDKs | Next |
| M4: physical AI terminal | Offline operation, safe updates, real-time priority, device isolation, and fleet lifecycle | Next |
| M5: additional service profiles | Storage, commerce, and human-service products reuse the stable base protocol | Next |

## Maintenance

Every merged feature that changes a milestone must update the owning
repository ROADMAP. The program roadmap changes only when a cross-repository
deliverable moves category. CI success may close a code item, but only an
attached deployment artifact may close an External Certification item.
