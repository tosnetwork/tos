# AI Actor Operations Runbook

This runbook describes the minimum operational posture for running AI actor infrastructure on TOS.

It covers off-chain agent runners, model or tool service operators, verifier operators, and task workflow backends.

## Node Access

Recommended trust tiers:

- use a local full node for agents that control material funds
- use proof-backed reads for lightweight agents where available
- use trusted RPC only for low-value automation or development
- use indexed data for discovery and dashboards, not authority

## Key Separation

Operators should keep these keys separate:

- validator keys
- node control keys
- agent owner keys
- agent controller keys
- service signing keys
- verifier decision keys
- API credentials for off-chain services

Agent or service workers must not run with validator keyring access.

## Monitoring

Monitor:

- task acceptance latency
- result submission latency
- settlement failures
- service charge rejection rate
- verifier decision rate
- timeout and cancellation rate
- delivery failures and back-pressure records
- agent balance and spend-limit utilization

## Incident Response

If an agent behaves unexpectedly:

1. revoke or rotate the controller key
2. stop the off-chain worker
3. inspect recent task and service messages
4. check outstanding escrow exposure
5. settle, cancel, or dispute affected tasks according to policy
6. publish an operator note if public users are affected

If a service actor overcharges or emits bad results:

1. disable the service endpoint off-chain
2. rotate service signing keys if needed
3. reject pending charges that exceed policy
4. dispute affected tasks
5. update service metadata or registry status

## Deployment Checklist

- local testnet run completed
- task escrow tests passed
- agent account tests passed
- service actor tests passed, if applicable
- verifier actor tests passed, if applicable
- transaction history reconstruction tested
- key backup and rotation procedure documented
- emergency stop or revoke path tested

