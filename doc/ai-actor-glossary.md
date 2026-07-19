# AI Actor Glossary

This glossary defines terms used by AI actor documentation.

## Agent Account

An on-chain account that represents an AI agent or an automation controller. It owns state, receives messages, and acts under explicit owner and controller policy.

## Agent Runner

An off-chain process that observes chain state and submits messages on behalf of an agent account. It is not trusted unless its actions are authorized on-chain.

## Task Actor

A contract that represents a unit of work. It stores task status, escrow, assigned agent, deadlines, result references, and settlement policy.

## Service Actor

A contract or account that represents a model, data, tool, compute, or API service. It publishes service metadata and participates in payment or result flows.

## Verifier Actor

A contract or account that reviews task results, evidence, or service responses and emits typed decisions.

## Evidence Reference

A compact hash or authenticated reference to off-chain data such as model output, transcript, proof bundle, or attestation.

## Workflow Indexer

An off-chain component that reconstructs task timelines and agent activity from chain data. It provides derived views, not settlement authority.

## Replay Domain

A value that scopes a signed message or capability grant to a task, deployment, chain, service, or contract context.

## Settlement Policy

The contract-visible rule that determines payout, refund, slash, or dispute behavior.

## Capability Grant

A bounded authorization object that allows a grantee to invoke a specific target action under explicit constraints.

## Controller

The key or account allowed to operate an agent within policy limits. A controller is not the owner unless the agent account explicitly makes it so.

## Owner

The authority that can update high-impact policy such as controller, spending limit, service endpoint, or recovery settings.

## Task Id

The stable identifier of a task actor or task instance. Lifecycle messages should bind to it to prevent replay or cross-task confusion.

## Workflow Timeline

A derived sequence of task-related transactions reconstructed by an indexer or client. It is useful for UX but is not the authority for settlement.

## Service Charge

A requested payment for model, data, tool, or compute work performed by a service actor. It must be bounded by prior authorization.

## Verifier Decision

A typed on-chain message that accepts, rejects, scores, or disputes a result or evidence reference.
