# Catchain DoS Protection

This note summarizes the intended operator and protocol posture for catchain DoS resistance.

AI actor workloads can create bursty task, service, and verifier traffic. Consensus protections must be evaluated against those burst patterns before any AI actor feature is promoted beyond experimental use.

## Upgrade Safety

Catchain is consensus-critical. Any protocol change must be rolled out in a way that preserves overlapping validator agreement during transition.

Recommended process:

1. upgrade validator binaries first
2. coordinate rollout across validators
3. activate new behavior only through on-chain config once enough stake has upgraded

## Config Dependencies

Catchain behavior is governed by consensus-related config parameters, especially:

- catchain lifetime and timing
- dependency sizing
- protocol version fields
- max block production controls

Treat these as governance-managed parameters, not ad hoc local tuning.

## Protection Strategy

The main defenses are:

- bounded message sizes
- bounded effective dependency growth
- bounded processed block height
- fork-aware peer suppression

## Operational Guidance

- do not deploy catchain behavior changes without coordinated validator rollout
- prefer config-gated activation over hard behavior flips
- monitor bad-node and fork-related events closely during upgrades
- validate parameter changes in a non-production environment first
- load-test agent/task traffic patterns before raising message throughput assumptions

## Related Docs

- [ConfigParam.md](ConfigParam.md)
- [Validator.md](Validator.md)
- [ai-actors.md](ai-actors.md)
