# Phase 7 Migration Note — Testnet-Focused Integration Validation

**Date:** 2026-04-12  
**Phase:** 7 of 8 (executed 7th per recommended order)  
**Status:** Partial — validated against local 3-node TOS testnet

---

## Test Environment

Local 3-node TOS testnet on `127.0.0.1`:

| Node | Console Port | Liteserver Port | Data Dir |
|------|-------------|----------------|----------|
| tos1 | 2004 | 2003 | /data/tos1/ |
| tos2 | 2007 | 2006 | /data/tos2/ |
| tos3 | 2010 | 2009 | /data/tos3/ |

Network params: `global_id=3`, 3 validators, election period 2400s, min stake 10,000 TOS.

---

## Validation Results

### Config Generation — PASS

```
tosctl config generate --output tosctl-test.json --force
```

Generates valid JSON config with `chain_rpc`, `elections`, `http`, `log` sections. All field names use TOS-neutral naming (`chain_rpc` not `ton_http_api`).

### Node Add — PASS

```
tosctl config node add --name tos1 --control-server-endpoint "127.0.0.1:2004" \
  --control-server-pubkey "z8karm..." --control-client-secret-name "tos1-console-client"
```

Successfully adds nodes to config. Supports `add`, `ls`, `rm` operations.

### Node List with Connectivity — PARTIAL

```
tosctl config node ls -c tosctl-test.json
```

- Lists all 3 nodes: PASS
- ADNL handshake to each node: PASS (connection established, node responds)
- Ping health check: FAIL — TOS control server rejects `tcp.ping` (TL `#1faaa1bf`) with "Wrong constructor found at 4"

**Root cause:** The ADNL client sends a raw `tcp.ping` query, but the TOS control interface only accepts queries wrapped in `engine.validator.controlQuery`. The `tcp.ping` constructor is not recognized as a valid validator control query.

**Impact:** Status display shows an error string instead of "OK", but actual control operations (key generation, signing, config queries) use proper `engine.validator.*` TL methods and should work correctly.

**Recommended fix:** Update the ADNL ping to use a control-compatible query (e.g., `engine.validator.getConfig`) as the health check instead of `tcp.ping`.

### Chain RPC Connectivity — NOT TESTED

The local testnet does not run a JSON-RPC HTTP server. `tosctl` chain queries (`config-param`, wallet operations, contract deployment) require a JSON-RPC proxy or built-in HTTP server.

**Gap:** Need to either:
1. Enable `json_rpc_server` in the TOS node config, or
2. Run a JSON-RPC proxy in front of the liteservers

### Key Management — NOT TESTED (requires Vault)

Key generation/import via `tosctl key` commands require a HashiCorp Vault instance. Local testing used manually constructed `PrivateKey` entries in the config JSON.

**Note:** `KeyConfig` supports inline `PrivateKey` (type_id + base64) and `KeyPair` (hex) formats in addition to Vault references, allowing operation without Vault for testing.

### Service Startup — NOT TESTED

Service mode (`tosctl service`) requires both Chain RPC and Vault to be configured. Deferred until JSON-RPC endpoint is available.

---

## Key Findings

### 1. ADNL Control Protocol is Compatible

The TOS validator engine accepts ADNL connections on the control port and correctly responds to TL-serialized queries. The handshake, encryption, and TL deserialization all work. Only the `tcp.ping` query is rejected because it's not wrapped in `engine.validator.controlQuery`.

### 2. Config Format Works

The `tosctl` config file format (`chain_rpc`, `nodes`, `wallets`, `pools`, `bindings`, `elections`, `http`) loads and saves correctly. The `AdnlConfig` struct correctly handles inline Ed25519 keys with `type_id: 1209251014`.

### 3. JSON-RPC Gap

The local testnet exposes liteserver (TCP) and console (ADNL) interfaces but not an HTTP JSON-RPC server. For full `tosctl` validation, a JSON-RPC endpoint is needed.

---

## Remaining Test Items (Require JSON-RPC)

| Test | Dependency | Priority |
|------|-----------|----------|
| `config-param 34` (validator set) | Chain RPC | High |
| Wallet lookup + balance | Chain RPC | High |
| Wallet transfer flow | Chain RPC + Vault | Medium |
| Contract deployment | Chain RPC + Vault | Medium |
| Election dry-run queries | Chain RPC | Medium |
| Validator snapshot queries via REST API | Service mode | Low |

---

## Remaining Test Items (Require Ping Fix)

| Test | Fix Needed | Priority |
|------|-----------|----------|
| Node health check (`node ls` status) | Use `getConfig` instead of `tcp.ping` | Medium |
| Control-plane config param queries | Should work with proper `engine.validator.*` TL methods | High |
