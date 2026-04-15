# E2E Test Scripts

End-to-end tests that exercise `tosctl` and the validator-engine JSON-RPC
server against a running TOS testnet.

## Prerequisites

- A local 3-node TOS testnet running with:
  - JSON-RPC HTTP on ports **2011**, **2012**, **2013**
  - Console on ports **2004**, **2007**, **2010**
- `cargo` (Rust toolchain) on `$PATH`
- `curl` and `python3` on `$PATH`

## Scripts

### `e2e-test.sh`

Exercises tosctl CLI commands: host/node status, account queries, wallet
lifecycle, bookmarks, backup create/verify, and vote inspection.

```bash
# Run with defaults (RPC at 127.0.0.1:2011)
./scripts/e2e-test.sh

# Override the RPC endpoint
RPC_URL=http://10.0.0.1:2011 ./scripts/e2e-test.sh
```

### `e2e-account-permission.sh`

Deploys account-permission fixtures through the JSON-RPC deployer, then exercises:
- `tosctl account capability/delegations/sessions/agents`
- `tosctl account delegation-grant/delegation-revoke`
- unsupported / immutable lifecycle behavior for session and agent mutations

```bash
# Run with defaults (RPC at 127.0.0.1:8011)
./scripts/e2e-account-permission.sh

# Override the RPC endpoint
RPC_URL=http://10.0.0.1:8011 ./scripts/e2e-account-permission.sh
```

### `e2e-jsonrpc-test.sh`

Tests every JSON-RPC method exposed by the validator-engine embedded HTTP
server: health probes, address/block/transaction queries, `runGetMethod`,
fee estimation, and send endpoints.

```bash
# Run with defaults
./scripts/e2e-jsonrpc-test.sh

# Custom endpoint
./scripts/e2e-jsonrpc-test.sh http://10.0.0.1:2011
```

## Exit codes

Both scripts exit **0** when all checks pass and **1** when any check fails.
