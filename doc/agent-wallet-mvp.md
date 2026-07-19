# Agent Wallet MVP

This document defines the first implementation slice for TOS Agent Wallets.

The MVP combines a local `tosctl` profile layer with the first native Agent Account contract. It gives operators and agent runtimes a concrete way to create wallet identities, separate owner and controller keys, store machine-readable spending policy, derive deterministic contract state and deploy that state on-chain.

The repository also includes the first native Agent Account contract template:

- [`crypto/smartcont/agent-account-code.fc`](../crypto/smartcont/agent-account-code.fc)
- [`crypto/smartcont/agent-account.tlb`](../crypto/smartcont/agent-account.tlb)

The MVP also includes the native Task Escrow actor foundation:

- [`crypto/smartcont/task-escrow-code.fc`](../crypto/smartcont/task-escrow-code.fc)
- [`crypto/smartcont/task-escrow.tlb`](../crypto/smartcont/task-escrow.tlb)
- [`tosctl/src/node-control/contracts/src/task_escrow.rs`](../tosctl/src/node-control/contracts/src/task_escrow.rs)

Task Escrow stores the creator, optional assigned Agent, budget, deadline, lifecycle status,
result hash, evidence hash and settlement policy hash. Its message surface covers accept,
result submission, settlement, cancellation and deterministic timeout. The Rust wrapper
currently provides deterministic StateInit/address construction, message encoding and TVM
stack decoding; CLI orchestration and testnet settlement flows are the next implementation slice.

This contract is intentionally minimal. It stores owner identity, controller public key and policy data, exposes get-methods, and accepts owner-only internal messages for policy and controller updates. Policy data is stored in a referenced cell so metadata and endpoint hashes fit within TVM cell limits. It does not yet execute controller spending, escrow settlement or task routing.

`tosctl` can derive and deploy Agent Account StateInit from a local Agent Wallet profile. This makes the local profile and the native contract template share one deterministic owner/controller/policy encoding.

## Scope

The MVP provides:

- local Agent Wallet profiles in `tosctl-config.json`
- owner key generation in the configured secrets vault
- controller key generation for bounded agent-runtime actions
- runtime binding for off-chain agent runners
- controller key rotation without changing the owner wallet address
- funding transfers from existing configured wallets or `master_wallet`
- chain status inspection for balance, state, wallet type and seqno
- activation of the underlying native wallet contract after funding
- policy updates for limits, services, task categories, metadata hashes and capabilities
- safe removal of local Agent Wallet profiles, with optional vault-key deletion
- a native Agent Account contract template for owner/controller/policy state
- deterministic Agent Account StateInit generation and deployment through a configured funding wallet
- wallet address derivation using the existing native wallet implementation
- policy fields for per-action spend, daily spend, allowed services, task categories and owner-approval threshold
- JSON output for automation and service integration

The MVP intentionally avoids:

- consumer Android or iOS wallet UX
- a separate execution engine
- storing prompts, model outputs, private credentials or large task payloads on-chain
- treating the controller key as owner-equivalent authority

## Commands

Create a local Agent Wallet profile:

```bash
tosctl agent wallet create \
  --name research-agent \
  --max-per-tx 0.5 \
  --daily-limit 5 \
  --service model-router \
  --task-category research \
  --capability web-research \
  --format json
```

List configured Agent Wallet profiles:

```bash
tosctl agent wallet ls
```

Show one Agent Wallet profile:

```bash
tosctl agent wallet show --name research-agent --format json
```

Show Agent Account contract template metadata:

```bash
tosctl agent account show-template
```

Build Agent Account StateInit from a profile:

```bash
tosctl agent account build-state --wallet research-agent --format json
```

For on-chain Agent Account StateInit generation, `metadata-hash` and `service-endpoint-hash` must be 32-byte hex strings when present.

The `build-state` output includes:

- deterministic Agent Account address
- owner address derived from the Agent Wallet profile
- controller public key
- code hash and data hash
- base64 StateInit BOC

Deploy the deterministic Agent Account through an active configured wallet:

```bash
tosctl agent account deploy \
  --wallet research-agent \
  --from master_wallet \
  --amount 0.2 \
  --yes \
  --format json
```

The deployment command rejects active or frozen target accounts, validates the payer state and balance, sends the generated StateInit as an internal message, and waits for the Agent Account to become active.

Compare a local profile with its deterministic Agent Account chain state:

```bash
tosctl agent account status --wallet research-agent --format json
```

Inspect an Agent Account directly by address:

```bash
tosctl agent account show --address <agent-account-address> --format json
```

`status` verifies the deployed code hash and compares owner, controller key, limits, timeout and optional metadata hashes with the local profile. `show` reads the same native get-method without requiring a local Agent Wallet profile.

Apply the policy fields from the local profile to the deployed Agent Account:

```bash
tosctl agent account update-policy \
  --wallet research-agent \
  --amount 0.05 \
  --yes \
  --format json
```

Apply the current local controller public key to the deployed Agent Account:

```bash
tosctl agent wallet rotate-controller --name research-agent
tosctl agent account rotate-controller \
  --wallet research-agent \
  --amount 0.05 \
  --yes \
  --format json
```

Both chain actions are sent by the active underlying Agent Wallet, which is the Agent Account owner. They reject unknown contract code or an owner mismatch and verify the resulting get-method state before reporting success. Deployment persists `agent_account_address` in the local profile so later policy or controller changes keep targeting the original account. Re-running `deploy` safely records an already-active matching account without sending another deployment transaction.

Export only the policy:

```bash
tosctl agent wallet policy --name research-agent
```

Update policy and metadata:

```bash
tosctl agent wallet update-policy \
  --name research-agent \
  --max-per-tx 1 \
  --daily-limit 8 \
  --approval-above 3 \
  --service model-router \
  --service data-feed \
  --task-category research \
  --capability web-research \
  --metadata-hash <agent-metadata-hash>
```

Clear selected policy fields:

```bash
tosctl agent wallet update-policy \
  --name research-agent \
  --clear-services \
  --clear-approval-above
```

Bind the profile to an off-chain runtime:

```bash
tosctl agent wallet bind-runtime \
  --name research-agent \
  --runner-id runner-sfo-1 \
  --endpoint https://agent.example/runtime \
  --attestation-hash <optional-runtime-attestation-hash>
```

Rotate the controller key:

```bash
tosctl agent wallet rotate-controller --name research-agent
```

Export the runtime-facing manifest:

```bash
tosctl agent wallet export-runtime --name research-agent
```

Remove a local profile while preserving vault keys:

```bash
tosctl agent wallet rm --name research-agent
```

Remove a local profile and delete its owner/controller vault keys:

```bash
tosctl agent wallet rm --name research-agent --delete-keys --yes
```

Fund the Agent Wallet from an existing configured wallet:

```bash
tosctl agent wallet fund \
  --name research-agent \
  --from master_wallet \
  --amount 2.5 \
  --message "agent operating budget"
```

Check chain status:

```bash
tosctl agent wallet status --name research-agent
```

Activate the underlying native wallet contract after funding:

```bash
tosctl agent wallet activate --name research-agent
```

The recommended local lifecycle is:

1. `create` the Agent Wallet profile.
2. `fund` the derived address from `master_wallet` or another configured wallet.
3. `activate` the underlying native wallet contract once the address has enough balance.
4. `build-state` to inspect the deterministic Agent Account address and state before deployment.
5. `account deploy` to deploy the native Agent Account through an active configured wallet.
6. `wallet update-policy`, then `account update-policy`, when on-chain policy fields change.
7. `wallet rotate-controller`, then `account rotate-controller`, when rotating runtime authority.
8. `bind-runtime` to an agent runner.
9. `export-runtime` for the runner manifest.
10. `rm` stale local profiles when an agent is retired or a test profile is no longer needed.

## Config Shape

`tosctl` stores Agent Wallets under `agent_wallets`:

```json
{
  "agent_wallets": {
    "research-agent": {
      "wallet": {
        "key": { "kind": "VaultKey", "name": "agent-wallet-research-agent-owner" },
        "version": "V5R1",
        "subwallet_id": 4242,
        "workchain": -1
      },
      "agent_account_address": "-1:<deployed-agent-account-id>",
      "controller_key": { "kind": "VaultKey", "name": "agent-wallet-research-agent-controller" },
      "policy": {
        "max_per_tx": 500000000,
        "daily_limit": 5000000000,
        "allowed_service_actors": ["model-router"],
        "allowed_task_categories": ["research"],
        "default_task_timeout_secs": 3600
      },
      "runtime": {
        "runner_id": "runner-sfo-1",
        "endpoint": "https://agent.example/runtime",
        "attestation_hash": "runtime-attestation-hash",
        "bound_at": 1784428000
      },
      "capabilities": ["web-research"]
    }
  }
}
```

## Next Engineering Step

The next slice should make the deployed Agent Account useful for task settlement:

- add task-contract messages that spend through the Agent Account policy
- add deployment and policy-transition integration tests against a local network
