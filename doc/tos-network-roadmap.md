# TOS Network Development Roadmap

Status: active cross-repository roadmap  
Last reviewed: 2026-08-02

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

The active milestone is **M2: v0.1 production candidate**.

M1's bounded public `tos-ai-edge` composition and local three-node
discovery-to-Receipt rehearsal are complete. The current boundary is to make
the merged protocol/AI pair a signed release, select the deployment
authentication/custody policy, and certify only the hardware, isolation,
model, memory and network claims the first production terminal will actually
advertise.

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

### Deployable non-streaming AI Edge integration

- Strict `tos-ai-edge` composition with bounded discovery/Action HTTP,
  current-chain authority/client/payment adapters, private Worker and
  purpose-fixed signing boundaries.
- Real local service and client Agent Accounts, exact finalized native payment,
  text-generation execution, signed Receipt and exact same-process replay.
- Byte-identical terminal response after restarting both Worker and Edge,
  backed by one Worker-owned durable completion timestamp shared by Invoke and
  retained GetTask.
- One-of-three RPC loss tolerance, two-of-three fail-closed startup,
  signer/Worker readiness degradation, strict production configuration and
  systemd templates, plus a bounded anonymous malformed-input sample.
- Complete deterministic release bundles for both off-chain repositories,
  including full SHA-256 manifests, optional detached Ed25519 verification,
  archive-safety/tamper gates and CI integration.
- Two-slot terminal software updates with exact candidate-boot health,
  power-loss rollback, anti-rollback revisions, terminal-bound signed
  administrator lifecycle commands and bounded privacy-minimized history.
- A successful local run of the full CPU-only lifecycle suite on real
  containerd/runc, plus MOCK NVIDIA telemetry, VRAM admission, device-loss and
  recovery. Target NVIDIA device isolation remains external certification.

## In Progress

### M2: v0.1 production candidate

- Keep the exact immutable protocol/AI revision pair, run independent CI,
  conduct the offline signing ceremony and approve the signed artifacts built
  by the completed deterministic release pipeline.
- Select and audit the deployment authentication ceremony for session/Quote
  issuance and Action-status/Receipt-read access.
- Exercise controller/key rotation, revocation, stale-node rejection and the
  selected settlement policy without weakening strict-majority finality.
- Install and certify one Tier 1 Linux/NVIDIA terminal configuration without
  exposing a public runtime endpoint, raw GPU rental, arbitrary container or
  shell.
- Complete the applicable key-custody, model, isolation, long-duration memory,
  public perimeter, ARD and release-governance gates before making production
  claims.

## Next

Work is ordered by dependency, not by repository size.

1. Add a bounded ARD remote crawler and federation policy with SSRF, redirect,
   recursion, fan-out, publisher, expiry, and aggregate-index controls.
2. Complete the `.tos` registrar application and stable client SDK surfaces
   needed by independent operators.
3. Specify and implement Worker/result streaming as v0.2 with ordering,
   backpressure, cancellation, resume, usage, and receipt binding; unary v0.1
   remains stable.
4. Add reviewed GPU container isolation and additional fixed runtime activation
   backends only after the Tier 1 non-streaming path is certified.
5. Implement the site-bound physical AI terminal track: offline journal,
   signed update slots, real-time priority, safety isolation, reconnect, and
   fleet management.
6. Start storage, commerce, and human-service profiles only from the stable
   base protocol; they must not fork identity, payment, receipt, or discovery
   formats.
7. Add production relays, multi-region routing, subscriptions/channels,
   replication, and advanced evidence as later milestones.

## External Certification

External certification remains separate from repository completion. It covers
live-chain and settlement behavior, key custody and public authentication,
target hardware and isolation, model/update trust, sustained availability and
memory, public networking, ARD publication, and release governance. Deferred
offline physical-control and fleet claims are not part of non-streaming v0.1.

The canonical mutable status ledger is
[`tos-protocol/docs/non-streaming-v0.1-production-gates.md`](https://github.com/tosnetwork/tos-protocol/blob/main/docs/non-streaming-v0.1-production-gates.md).
The repository ROADMAPs and this program roadmap summarize scope only; dated
test reports remain historical evidence and do not maintain independent gate
status.

## Milestone sequence

| Milestone | Exit condition | Current state |
|---|---|---|
| M0: non-streaming foundations | Base protocol, chain adapters, Edge Core, private Worker, text-generation profile, bounded Registry, race-tested cross-repository compatibility | Completed |
| M1: deployable AI Edge service | One public bounded composition completes the three-node discovery-to-receipt flow and passes deployment rehearsals | Completed |
| M2: v0.1 production candidate | Immutable release pair plus required security, isolation, memory, key, and network evidence | In Progress |
| M3: streaming and extended discovery | Versioned streaming v0.2, bounded crawler/federation, stable client SDKs | Next |
| M4: physical AI terminal | Offline operation, safe updates, real-time priority, device isolation, and fleet lifecycle | Next |
| M5: additional service profiles | Storage, commerce, and human-service products reuse the stable base protocol | Next |

## Maintenance

Every merged feature that changes a milestone must update the owning
repository ROADMAP. The program roadmap changes only when a cross-repository
deliverable moves category. CI success may close a code item, but external
gate status changes only in the canonical production-gate ledger and requires
linked deployment evidence.
