# Sponsored Stablecoin Transfer MVP

> **Status: Reserved / On Hold**
>
> Preserve this design as a post-mainnet engineering target. Implementation must not
> begin on the current mainline before the TOS mainnet launch. After mainnet is live,
> create a dedicated development branch for this MVP and review the design against the
> production network's observed fee behavior, validator economics and security limits
> before writing consensus-adjacent or contract code.

## Product Definition

> Gasless Stablecoin Payments for AI Agents, backed by protocol-enforced spending policies and issuer-funded gas credits.

TOS should let an AI Agent transfer an approved stablecoin without holding TOS in its
operational wallet. The first implementation should use sponsored execution: the Agent
signs a bounded transfer intent, while a Relayer attaches the TOS required for TVM
execution and message forwarding.

"Gasless" describes the Agent experience, not the underlying resource cost. Validators
still execute transactions, contracts still consume gas, and messages still consume
forwarding capacity. The MVP makes those costs explicit and assigns them to a Sponsor.

## Executive Conclusion

TOS can support gasless stablecoin transfers, but it should not begin by making arbitrary
contract execution free at the protocol level.

The recommended sequence is:

1. Implement sponsored stablecoin transfers without a consensus change.
2. Add issuer-funded, protocol-accounted gas credits after measuring real transfer costs.
3. Consider a restricted protocol-level free lane only after its eligibility rules,
   validator compensation and denial-of-service controls are proven.

This approach fits the TOS AI Actor Model. An Agent can authorize a payment without
holding the native gas asset, while its Agent Account continues to enforce recipient,
amount, expiry, replay and spending-policy constraints.

## Reference Model: Sui

Sui has used two distinct gasless models.

### Sponsored Transactions

In the sponsored model, the transaction sender and gas owner are different accounts. The
sender authorizes the requested action, the Sponsor supplies the native gas asset, and
both parties sign the transaction. The user does not hold the native asset, but the
network still receives a fee.

This is the closest reference for the TOS MVP.

### Protocol-Level Gasless Stablecoin Transfers

Sui later introduced a restricted protocol-level path for supported stablecoins. Eligible
transfers use zero gas price and budget with no gas payment object. The path is limited to
allowlisted stablecoins and verified balance-transfer operations, with minimum transfer
amounts and protocol resource limits.

The important design lesson is that the free path is not arbitrary smart-contract
execution. It is a narrow, governance-controlled payment primitive with explicit abuse
controls.

References:

- [Sui sponsored transaction design](https://github.com/MystenLabs/sui/issues/2418)
- [Sui mainnet gasless feature activation](https://github.com/MystenLabs/sui/pull/26504)
- [Sui stablecoin allowlist](https://github.com/MystenLabs/sui/pull/26417)
- [Sui gasless stablecoin announcement](https://blog.sui.io/sui-launches-gasless-stablecoin-transfers/)

## TOS Constraints

TOS stablecoins use the Jetton model. A balance belongs to a per-owner Jetton Wallet
contract, and a transfer normally requires multiple asynchronous steps:

1. The owner sends `transfer` to its Jetton Wallet.
2. The sender Jetton Wallet debits its token balance.
3. It sends `internal_transfer` to the recipient Jetton Wallet.
4. The recipient wallet credits the balance and may send a notification or excess
   message.

Each TVM execution and internal message has a native TOS cost. A new recipient may also
require deployment of its Jetton Wallet. Therefore, changing a CLI fee display to zero
would not create a safe gasless transfer mechanism.

The existing standards and Agent authorization model provide useful foundations:

- [TOS Jetton standard](tos-tep-token-standards.md)
- [Agent Wallet MVP](agent-wallet-mvp.md)
- [Account permission model](tos-account-permission-model.md)
- [`agent-account-code.fc`](../crypto/smartcont/agent-account-code.fc)

## MVP Architecture

The MVP has five roles:

- **Agent**: requests and signs the stablecoin transfer.
- **Agent Account**: enforces the Agent's on-chain spending policy.
- **Sponsored Jetton Wallet**: verifies the signed intent and executes the token transfer.
- **Relayer**: submits the intent and attaches enough TOS for execution and forwarding.
- **Sponsor**: funds the Relayer and defines service-level eligibility and rate limits.

The Relayer and Sponsor may be operated by the same service in the MVP.

```text
Agent runtime
    |
    | signs StablecoinTransferIntent
    v
Relayer / Sponsor
    |
    | internal message + attached TOS
    v
Agent Account or Sponsored Jetton Wallet
    |
    | policy and signature verification
    v
Recipient Jetton Wallet
```

## Signed Transfer Intent

The signature must bind the complete economic action. The canonical payload should
include at least:

```text
domain_separator
global_id
agent_account
jetton_master
sender_jetton_wallet
recipient
amount
forward_tos_amount
response_destination
payload_hash
relayer_policy_hash
seqno
valid_until
```

Requirements:

- `domain_separator` prevents reuse in another protocol or operation.
- `global_id` prevents cross-network replay.
- `agent_account` and `sender_jetton_wallet` bind the authority and asset account.
- `jetton_master` prevents substitution of a different token.
- `recipient`, `amount` and `payload_hash` bind all payment effects.
- `seqno` provides strict replay protection.
- `valid_until` bounds delayed or withheld submissions.
- `relayer_policy_hash` optionally binds an approved Sponsor policy.

Serialization and hashing must be canonical and documented before deployment. Relayers
must not transform any signed economic field.

## On-Chain Policy

The Agent Account should enforce the payment independently of Relayer policy. At minimum:

- approved Jetton master or token class
- maximum amount per transfer
- cumulative daily stablecoin limit
- recipient allowlist or recipient-policy hash
- optional task or service reference
- controller signature
- exact sequence number
- expiration time
- optional owner-approval threshold

The Relayer may apply stricter off-chain limits, but those checks are not a replacement
for contract enforcement.

## Relayer Responsibilities

Before submission, the Relayer must:

1. Decode the intent with a structured parser.
2. Verify the controller signature, network, sequence and expiration.
3. Confirm that the Jetton master and wallet code are supported.
4. Estimate compute, forwarding and possible wallet-deployment costs.
5. Apply Sponsor quotas and abuse controls.
6. Attach a bounded TOS amount and submit the internal message.
7. Track the resulting transaction chain to a terminal outcome.
8. Return a machine-readable receipt containing transaction hashes and failure reasons.

The Relayer must never accept an unbounded forwarding amount or arbitrary executable
payload under the stablecoin-transfer fee policy.

## Stablecoin Eligibility

MVP support must be allowlist-based. An entry should bind:

- Jetton master address
- approved Jetton Wallet code hash
- token decimals
- minimum transfer amount
- maximum sponsored transfer amount
- maximum payload size
- maximum internal message count
- expected deployment behavior
- Sponsor budget and status

Checking only the `transfer` opcode is insufficient because arbitrary contracts can expose
the same opcode.

## Failure and Accounting Rules

- A rejected signature or policy check must not debit stablecoins.
- A failed transfer may still consume Sponsor TOS; the receipt must report that cost.
- The Agent must never reimburse an unspecified amount after execution.
- Duplicate intents must be rejected on-chain by sequence number.
- Sponsor budget exhaustion must fail closed or explicitly fall back to a normal paid
  transfer; it must not silently change the signed action.
- Excess attached TOS should return to the Sponsor-controlled response address.
- Relayer accounting must distinguish successful transfers, contract rejection, expiry,
  insufficient attached value and incomplete asynchronous delivery.

## CLI and Service Surface

The initial operator interface should provide:

```text
tosctl agent stablecoin intent build
tosctl agent stablecoin intent sign
tosctl agent stablecoin sponsored-send
tosctl agent stablecoin status
```

Machine-facing service endpoints should support intent submission, status lookup and
Sponsor policy discovery. Stable response objects should include an intent hash, current
state, involved addresses, transaction hashes, Sponsor cost and structured error code.

## Security Requirements

The MVP is not complete without tests for:

- valid sponsored transfer
- wrong controller key
- replayed sequence number
- expired intent
- wrong network or Jetton master
- modified recipient, amount or payload
- per-transfer and daily-limit overflow
- unauthorized recipient
- unsupported wallet code hash
- insufficient Sponsor value
- recipient wallet deployment
- bounced internal transfer
- Relayer resubmission after uncertain delivery
- concurrent intents with adjacent sequence numbers
- Sponsor quota exhaustion
- oversized payload and excessive message fan-out

At least one acceptance test must run the complete flow against a real local validator,
not only an offline TVM emulator.

## Recommended Implementation Phases

### Phase A: Sponsored Transfer MVP

- Define the canonical signed intent and TLB schema.
- Extend Agent Account policy for allowlisted stablecoins and recipients.
- Implement a compatible Sponsored Jetton Wallet operation.
- Add Rust SDK builders, decoders and receipt types.
- Add `tosctl` intent and sponsored-send commands.
- Implement a bounded Relayer service.
- Complete sandbox and real-localnet lifecycle tests.

This phase requires no consensus change. The Sponsor pays normal TOS fees.

### Phase B: Issuer-Funded Gas Credits

Introduce protocol-visible or contract-enforced credit accounting with configuration for:

```text
gas_credit_enabled
approved_jetton_masters
minimum_transfer
max_gas_per_transfer
max_messages_per_transfer
max_gasless_tps
epoch_gas_budget
```

Eligible transfers continue to meter real gas, but the charge is paid from an
issuer-funded or governance-funded TOS pool. Validators remain compensated, budgets are
auditable, and exhausted credits fall back predictably.

### Phase C: Restricted Protocol-Free Lane

Consider a true zero-fee lane only after Phase B provides cost and abuse data. Eligibility
must require an approved master, approved wallet code hash, canonical transfer shape,
minimum value, bounded payload, bounded computation, bounded message fan-out and
per-block or per-epoch quotas.

Arbitrary TVM execution must remain ineligible.

## Acceptance Criteria

The Sponsored Stablecoin Transfer MVP is complete when:

- an Agent holding an approved stablecoin but no TOS can authorize a transfer
- an independent Relayer can submit that authorization and pay all native fees
- the Agent Account enforces token, recipient, amount, sequence and expiry policy on-chain
- the recipient receives the exact stablecoin amount
- excess TOS returns to the Sponsor path
- replay and mutation attempts fail deterministically
- the CLI and SDK expose stable machine-readable intent and receipt formats
- sandbox tests and a real-localnet end-to-end test pass
- Sponsor cost and failure outcomes are observable

## Non-Goals

The MVP does not:

- make arbitrary smart-contract calls free
- let validators execute uncompensated work
- accept every Jetton as a stablecoin
- trust an opcode without validating the master and wallet implementation
- replace Agent Account spending policy with Relayer policy
- introduce oracle-priced payment of gas in arbitrary tokens
- promise zero network cost
