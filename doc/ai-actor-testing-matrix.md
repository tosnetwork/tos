# AI Actor Testing Matrix

This document defines the minimum test matrix for AI actor primitives.

## Unit Tests

Agent account:

- owner updates controller
- non-owner cannot update controller
- controller can accept allowed task
- controller cannot exceed spending limit
- expired delegation fails

Task escrow:

- create task with budget
- accept open task
- reject duplicate accept
- submit result from assigned agent
- reject result from unassigned agent
- settle accepted result
- reject duplicate settlement
- cancel open task
- timeout overdue task
- dispute submitted result

Service actor:

- quote service price
- authorize service call
- reject unauthorized service call
- reject over-budget charge
- bind result hash to request hash

Verifier actor:

- submit accept decision
- submit reject decision
- reject unauthorized verifier
- bind decision to task id and result hash

## Integration Tests

- user creates task, agent accepts, agent submits result, user settles
- user creates task, agent accepts, deadline expires, task times out
- agent calls service actor, service result is referenced by task result
- verifier reviews result, task settles according to verifier decision
- indexer reconstructs workflow from transaction history

## Local Testnet Tests

- deploy task and agent contracts on wc=0
- run workflow through validator JSON-RPC
- restart one validator during task lifecycle
- stop one validator long enough to catch up
- verify transaction history after catch-up
- verify no additional execution domains are registered

## Negative Tests

- malformed opcode
- malformed body
- wrong `query_id`
- replayed message
- wrong sender
- wrong task id
- insufficient value
- expired capability
- service charge above maximum
- settlement without result

## Release Gates

Before Level 2 support:

- all unit tests pass
- local testnet workflow passes
- restart and catch-up test passes
- security review complete
- message catalog updated
- operator runbook updated

