# TOS Smart Contract Guidelines

This document captures practical contract design rules for TOS and TVM-based development.

## Prefer Message-Driven Design

TOS follows an actor-oriented execution model:

- contracts own isolated state
- communication happens through messages
- there is no shared mutable memory between contracts

Design contracts as explicit message handlers, not synchronous call graphs.

## Internal Messages

Use internal messages for contract-to-contract interaction.

Recommended structure:

- reserve an operation code space
- include `query_id` when a response may be needed
- make success and failure paths explicit

## Bounce Handling

Default to bounceable internal messages.

Your contract should:

- check the `bounced` flag before normal dispatch
- avoid executing a bounced payload as a fresh request
- handle partial failure paths cleanly

## Replay Protection for External Messages

Protect external entrypoints with at least one of:

- `seqno`
- expiration timestamp
- a replay cache for recent accepted messages

For wallet-like contracts, `seqno + expiry` is the normal baseline.

## Value Flow

When sending value together with a request:

- account for forwarding fees
- account for compute fees at the receiver
- decide how unused value returns on success and failure

Never assume the peer contract will absorb all value exactly as intended.

## Get Methods

Expose get methods for observable state that clients need frequently.

Common examples:

- `seqno`
- configuration/state snapshot methods
- resolver-style lookup methods for directory contracts

## Serialization Discipline

- define message bodies clearly
- keep cell layout stable across upgrades
- document versioned payloads when the format can evolve

Treat schema changes as compatibility events.

## Error Handling

- reject malformed inputs early
- use deterministic failure paths
- avoid ambiguous partial state updates

When in doubt, fail fast and leave state unchanged.

## Design Checklist

- Is every external method replay-safe?
- Are bounced messages handled?
- Is message schema versioned if needed?
- Is value accounting explicit?
- Are read-only queries available for operators and clients?

## Related Docs

- [actor.md](actor.md)
- [tblkch.tex](tblkch.tex)
