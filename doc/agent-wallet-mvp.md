# Agent Wallet MVP

This document defines the first implementation slice for TOS Agent Wallets.

The MVP is a local `tosctl` profile layer. It does not replace the future on-chain Agent Account contract. It gives operators and agent runtimes a concrete way to create wallet identities, separate owner and controller keys, and store machine-readable spending policy before the native contract templates are finalized.

The repository also includes the first native Agent Account contract template:

- [`crypto/smartcont/agent-account-code.fc`](../crypto/smartcont/agent-account-code.fc)
- [`crypto/smartcont/agent-account.tlb`](../crypto/smartcont/agent-account.tlb)

This contract is intentionally minimal. It stores owner identity, controller public key and policy data, exposes get-methods, and accepts owner-only internal messages for policy and controller updates. It does not yet execute controller spending, escrow settlement or task routing.

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
4. `update-policy` when spending limits, service actors, task categories or metadata change.
5. `bind-runtime` to an agent runner.
6. `export-runtime` for the runner manifest.
7. `rm` stale local profiles when an agent is retired or a test profile is no longer needed.

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

The next slice should bind this local profile to a native Agent Account contract:

- add `tosctl agent account` deploy/build helpers for the Agent Account contract template
- derive Agent Account state-init from owner address, controller public key and policy fields
- expose RPC/CLI inspection for `get_agent_account_data`, `get_owner`, `get_controller_pubkey` and `get_agent_policy`
- add task-contract messages that spend through the Agent Account policy
- add native Agent Account deployment after the contract template exists
- make controller rotation an on-chain policy update after the Agent Account contract exists
