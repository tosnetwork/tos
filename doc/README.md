# TOS Documentation

This directory contains protocol, operator, standards, and design documents for TOS.

The current project direction is the AI Actor Model:

- accounts, contracts, agents, services, and tasks are modeled as independent actors
- workflows use asynchronous messages instead of synchronous cross-contract calls
- native TVM execution remains the focused execution surface
- task state, payments, permissions, and verification metadata remain inspectable from chain state

Implementation rule: AI actor work should add native contracts, message schemas,
SDK/RPC helpers, tests, and operator workflows. It should not add unrelated
execution engines or bypass the native TVM actor model.

Start with:

- [ai-actors.md](ai-actors.md) - AI actor product and protocol direction
- [the-tos-protocol-implementation-plan.md](the-tos-protocol-implementation-plan.md) - repository boundaries and delivery plan for owner-operated TOS services
- [tos-ard-compatibility.md](tos-ard-compatibility.md) - pinned ARD compatibility profile, catalog publication, federated Registry architecture, security bounds, and TOS handoff
- [ai-edge-computing-terminal-architecture.md](ai-edge-computing-terminal-architecture.md) - primary off-chain product architecture for turning owner-controlled hardware into bounded AI services
- [local-gpu-sharing-use-case.md](local-gpu-sharing-use-case.md) - managed AI services on owner-controlled GPU hardware; bare GPU rental is excluded
- [physical-ai-edge-terminal-use-case.md](physical-ai-edge-terminal-use-case.md) - site-bound Jetson/industrial terminals, offline operation, safe updates, real-time priority, actuator isolation, and fleet management
- [local-open-weight-model-sharing-use-case.md](local-open-weight-model-sharing-use-case.md) - locally hosted open-weight model service requirements
- [ai-actor-glossary.md](ai-actor-glossary.md) - shared terminology for agent, task, service, and verifier workflows
- [ai-actor-message-catalog.md](ai-actor-message-catalog.md) - initial task, service, and verifier message catalog
- [ai-actor-contract-guidelines.md](ai-actor-contract-guidelines.md) - contract design guidance for agent accounts, task escrow, service actors, and verifier actors
- [agent-wallet-mvp.md](agent-wallet-mvp.md) - first `tosctl agent wallet` implementation slice for profiles, funding, activation, policy updates, runtime binding, controller rotation, policy export and removal
- [ai-actor-threat-model.md](ai-actor-threat-model.md) - baseline threat model
- [service-actor-concurrent-escrow-upgrade.md](service-actor-concurrent-escrow-upgrade.md) - pre-testnet in-place upgrade for concurrent paid requests, settlement, and refunds
- [ai-actor-testing-matrix.md](ai-actor-testing-matrix.md) - required test coverage
- [ai-actor-operations-runbook.md](ai-actor-operations-runbook.md) - operational guidance for agent and service infrastructure
- [actor.md](actor.md) - actor-model first principles for TOS
- [tos-message-policy.md](tos-message-policy.md) - message envelope and lifecycle policy
- [tos-account-permission-model.md](tos-account-permission-model.md) - account, delegation, session, and agent permissions
- [tos-capability-policy.md](tos-capability-policy.md) - capability addressing and authorization policy

AI actor protocol support:

- [tos-time-policy.md](tos-time-policy.md) - scheduled messages for task deadlines and timeout windows
- [tos-delivery-sla-policy.md](tos-delivery-sla-policy.md) - delivery failure records, dead letters, and retry guidance
- [tos-supervision-policy.md](tos-supervision-policy.md) - monitor and supervision relationships for actor failures
- [tos-postponement-policy.md](tos-postponement-policy.md) - bounded selective receive for out-of-phase workflow messages
- [tos-language-syntax-policy.md](tos-language-syntax-policy.md) - Tol contract syntax direction for actor-shaped contracts

Client, trust, and indexing docs:

- [json-rpc-policy.md](json-rpc-policy.md)
- [tos-trust-tiers.md](tos-trust-tiers.md)
- [tos-transaction-history.md](tos-transaction-history.md)
- [tos-wc0-wallet-index.md](tos-wc0-wallet-index.md)
- [tos-wallet-send-track.md](tos-wallet-send-track.md)
- [tos-tep-token-standards.md](tos-tep-token-standards.md)

Operator and launch docs:

- [Validator.md](Validator.md)
- [Validator-Local.md](Validator-Local.md)
- [validator-genesis-bootstrap.md](validator-genesis-bootstrap.md)
- [Zerostate.md](Zerostate.md)
- [ConfigParam.md](ConfigParam.md)
- [FullNode.md](FullNode.md)
- [LiteClient.md](LiteClient.md)

Review and release docs:

- [tos-release-policy.md](tos-release-policy.md)
- [tos-upgrade-process.md](tos-upgrade-process.md)
- [security-audit-native-2026-06.md](security-audit-native-2026-06.md)
- [ops/tos31-tos32-validation.md](ops/tos31-tos32-validation.md)
- [adr/README.md](adr/README.md)
