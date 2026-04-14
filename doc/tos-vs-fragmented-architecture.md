# TOS vs Fragmented Architecture

Version: v1.0

## Purpose

This document explains the architectural difference between:

- a fragmented blockchain tooling ecosystem
- the target TOS architecture

It is meant to make one design point explicit:

> TOS should not grow by adding more parallel entry points.
> It should grow by consolidating the canonical path.

This document complements:

- [tos-north-star.md](tos-north-star.md)
- [tos-roadmap-12m.md](tos-roadmap-12m.md)
- [tos-standards-map.md](tos-standards-map.md)
- [tos-release-policy.md](tos-release-policy.md)

## The Fragmented Pattern

In a fragmented ecosystem, the major product surfaces grow independently:

- node software
- low-level query tools
- language bindings
- HTTP wrappers
- third-party APIs
- operator tools
- indexers
- explorers
- wallet backends
- contract developer tooling

Each layer may solve a real problem.
But over time the ecosystem becomes harder to reason about because no single path is canonical.

### Typical Shape

```text
Users / wallets / applications / operators / data services
                         │
     ┌───────────────────┼───────────────────┐
     │                   │                   │
 wallet layer        contract layer      operator layer
     │                   │                   │
     └───────────────┬───┴───────────────┬───┘
                     │                   │
                 API layer           data layer
                 wrappers            indexers / explorers
                 SDK adapters        analytics / archives
                 third-party APIs    wallet backends
                     │
              low-level query path
                     │
                    node
                     │
          consensus / network / storage
```

### What Goes Wrong

The problem is not merely that there are many tools.
The problem is that multiple layers become de facto primary entry points.

That usually creates:

- multiple overlapping ways to read chain state
- multiple overlapping ways to send transactions
- separate operator paths for node control versus service management
- dependence on wrappers and sidecars for basic functionality
- private glue code in wallets, explorers, and backend systems
- growing ambiguity about which layer defines canonical behavior

At that point, the ecosystem still functions, but it becomes expensive to integrate and hard to standardize.

## The TOS Target Pattern

TOS should converge around one primary service core and one primary operator path.

The key design decision is:

> the node should expose the canonical machine-facing surface,
> and the operator CLI should expose the canonical human-facing surface.

Everything else should either:

- build on top of these surfaces
- or remain explicitly secondary

### Target Shape

```text
Users / wallets / applications / operators / data services
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   wallet layer       contract layer     operator layer
   SDKs and apps      compiler/test      tosctl
                      deploy flow         canonical CLI
        │                  │                  │
        └──────────────────┴──────────────┬───┘
                                          │
                            canonical public surfaces
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
     embedded JSON-RPC            health/readiness/metrics      indexed data contracts
            │                             │                             │
            └─────────────────────────────┴─────────────────────────────┘
                                          │
                                 node-native capabilities
                                          │
                            consensus / network / storage
```

## Structural Difference

The fragmented pattern usually evolves like this:

```text
node
  -> low-level query path
  -> wrappers
  -> third-party APIs
  -> custom wallet backend glue
  -> custom explorer/indexer glue
```

The TOS target should evolve like this:

```text
node
  -> canonical embedded APIs
  -> canonical operator CLI
  -> explicit indexed-data contracts
  -> wallets / applications / explorers / automation
```

The difference is not cosmetic.
It changes where complexity lives.

In the fragmented model, each downstream team absorbs complexity privately.
In the TOS model, complexity is absorbed once into the canonical path.

## What Should Be Canonical in TOS

The following surfaces should converge toward canonical status:

- embedded JSON-RPC for read, estimate, send, and tracking flows
- health, readiness, metrics, and structured node status
- `tosctl` for node and validator operations
- published historical and indexed data contracts
- explicit trust-tier definitions
- explicit account and permission semantics

The following may still exist, but should not remain the default path:

- low-level debug binaries
- expert-only internal tools
- temporary compatibility shims
- narrowly scoped migration helpers

## Decision Rule

When adding a new tool or public surface, TOS should ask:

1. Does this strengthen the canonical path?
2. Does this move functionality closer to node-native capability?
3. Does this reduce custom glue in wallets, indexers, explorers, or operators?
4. Does this create another de facto primary entry point?

If the answer to the last question is yes, the burden of proof should be high.

## Repository Implication

This architectural choice implies a clear repository boundary:

### `~/tos`

Should own:

- node-native APIs
- embedded JSON-RPC
- health, readiness, metrics
- structured control-plane capability
- trust and verification primitives
- data and protocol-facing primitives

### `~/tos/tosctl`

Should own:

- canonical operator workflows
- CLI structure and operator UX
- config orchestration
- automation ergonomics
- truthful workflow documentation

### Shared Design Discipline

Both repos must coordinate on:

- wallet-facing transaction lifecycle semantics
- fee estimation and send-flow consistency
- indexing and historical data contracts
- account and permission standards
- compatibility and release discipline

## What TOS Must Avoid

TOS should avoid drifting into a fragmented pattern by:

- adding many overlapping public APIs
- relying on external wrappers for basic canonical workflows
- allowing operator workflows to split across unrelated tools
- leaving data contracts implicit
- allowing trust assumptions to live in private application glue
- documenting migration tools as if they were permanent architecture

## Success Condition

TOS is succeeding architecturally when downstream consumers can answer:

- which API should I integrate against?
- which CLI should I automate?
- which data contract should I depend on?
- which trust tier am I using?
- which account and permission semantics are canonical?

If those answers are still ambiguous, the architecture is still fragmented.

## Final Rule

TOS should not try to hide fragmentation with better documentation alone.

It should reduce fragmentation structurally by making:

- the node the canonical service core
- `tosctl` the canonical operator path
- standards explicit
- compatibility disciplined
- secondary tools truly secondary
