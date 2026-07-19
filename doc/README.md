# TOS Documentation

This directory contains protocol, operator, standards, and design documents for TOS.

The current project direction is the AI Actor Model:

- accounts, contracts, agents, services, and tasks are modeled as independent actors
- workflows use asynchronous messages instead of synchronous cross-contract calls
- native TVM execution remains the focused execution surface
- task state, payments, permissions, and verification metadata remain inspectable from chain state

Start with:

- [ai-actors.md](ai-actors.md) - AI actor product and protocol direction
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
