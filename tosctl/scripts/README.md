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

### `local_test_vault.py`

`local_test_vault.py` gives one local test command a new, ephemeral TOS
`file://` SecretsVault capability. It is intentionally not a network service
and not a production HSM.

It creates a new owner-only directory, generates an in-memory random 256-bit
master key, injects the resulting `VAULT_URL` only into its child command, and
deletes the encrypted vault directory when that command exits. It never prints
the master key or URL.

For an OpenFox acceptance run, pass the same ephemeral capability under the
explicit test variable expected by the test:

```bash
python3 tosctl/scripts/local_test_vault.py \
  --also-export OPENFOX_TOS_VAULT_URL \
  --also-export OPENFOX_PREDICTION_VAULT_URL -- \
  go test ./pkg/earning -run TestTOSCTLPaymentSinkThreeNode -count=1
```

The child must still receive its normal non-secret local-chain configuration.
For debugging only, `--keep` retains the owner-only encrypted directory. Never
use `--keep` in CI, and never use this helper for persistent, shared, testnet,
or mainnet credentials.

Run its unit tests with:

```bash
python3 -m unittest tosctl/scripts/tests/test_local_test_vault.py -v
```

## Exit codes

Both scripts exit **0** when all checks pass and **1** when any check fails.
