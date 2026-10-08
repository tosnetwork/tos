# Secrets Vault

A Rust library for secure secret management with pluggable storage backends and cryptographic implementations. Provides encrypted storage for key pairs, symmetric keys, and arbitrary blobs with OS-level memory protection.

## Features

- **Pluggable storage backends** — encrypted local JSON files or remote HashiCorp Vault
- **Pluggable cryptographic implementations** — `ed25519-dalek` (default) or `tos_block`- compatible implementation
- **Protected memory** — page-aligned, mlock'd, mprotect'd buffers with automatic zeroing on drop
- **Secret types** — Ed25519 key pairs, AES-256-GCM symmetric keys, arbitrary binary blobs
- **Async API** — fully async with `tokio`

## File storage ownership

A file-backed instance takes an exclusive operating-system lock before loading
its snapshot and holds it until the storage instance is dropped. Share one
`SecretVault`/storage instance through `Arc` inside a process; opening the same
file again while it is live fails, including read-only usage of the current API.
Standalone migration takes the same lock. Close all instances before migration
or reopening with another master key.

The lock uses a stable `<vault filename>.lock` sidecar. Do not delete this file
while any process may use the Vault; its existence alone does not mean the lock
is held. Parent paths are canonicalized; vault symlink and Unix hard-link aliases
are rejected. Unix lock files must be regular, single-linked, owned by the current
user and mode 0600. Keep the parent directory trusted. Programs that bypass this
library, old versions without locking, shared filesystem lock semantics and
rollback of a closed Vault remain outside this ownership guarantee.

Saves use exclusive random mode-0600 temporary files, atomic replacement and
Unix directory synchronization. A failed save can leave persistence uncertain;
this locking mechanism does not turn a multi-step application workflow into a
transaction or provide cross-device anti-rollback protection.

## Quick Start

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
secrets-vault = { path = "../secrets-vault", features = ["file-storage-json", "crypto-default"] }
```

Create a vault from a URL:

```rust
use secrets_vault::{
    vault_builder::SecretVaultBuilder,
    types::{algorithm::Algorithm, secret_spec::SecretSpec},
};

let vault = SecretVaultBuilder::from_url(
    "file:///path/to/vault.json?master_key=abcdef...64hex"
).await?;

// Generate an Ed25519 key pair
let spec = SecretSpec::new(Algorithm::Ed25519).extractable(true);
let secret = vault.generate_secret(&spec, &"my_key".into()).await?;
vault.flush().await?;

// Sign and verify
let keypair = vault.get(&"my_key".into()).await?;
let sig = keypair.as_keypair()?.sign(b"hello").await?;
keypair.as_keypair()?.verify(b"hello", &sig).await?;
```

### From Environment

Set `VAULT_URL` and open the vault:

```rust
let vault = SecretVaultBuilder::from_env().await?;
```

## Vault URL Schemes

### File Backend (`file://`)

```
file://<path>?master_key=<64_hex_chars>[&auto_migrate=true]
```

| Parameter      | Required | Description                                       |
|----------------|----------|---------------------------------------------------|
| `master_key`   | Yes      | 256-bit AES master key (64 hex characters)        |
| `auto_migrate` | No       | Auto-migrate storage format on open (default: true)|

Secrets are encrypted with AES-256-GCM under the master key and stored in a hierarchical JSON tree.

### HashiCorp Vault Backend (`hashicorp://`)

```
hashicorp://<vault_address>?api_key=<token>[&namespace=<ns>][&prefer_local_crypto=false]
```

| Parameter   | Required | Description                                          |
|-------------|----------|------------------------------------------------------|
| `api_key`   | Yes      | Vault authentication token                           |
| `namespace` | No       | Vault namespace                                      |
| `prefer_local_crypto` | No       | Cache extractable private keys locally (default: false)|

Ed25519 keys are managed via Transit engine. Blobs are stored in KV v2 engine.

## Core API

### SecretVault

| Method                              | Description                          |
|-------------------------------------|--------------------------------------|
| `generate_secret(spec, secret_id)`  | Generate and store a new secret      |
| `get(secret_id)`                    | Load a secret by ID                  |
| `put(secret, mode)`                 | Store a secret with mode control     |
| `delete(secret_id)`                 | Remove a secret                      |
| `exists(secret_id)`                 | Check if a secret exists             |
| `load_metadata(secret_id)`          | Get metadata without loading secret  |
| `list_metadata()`                   | List all secret metadata             |
| `flush()`                           | Persist pending changes to storage   |

### SecretSpec

Defines parameters for secret generation:

```rust
let spec = SecretSpec::new(Algorithm::Ed25519)
    .extractable(true)
    .with_tag("env", "production")
    .with_expiration(expires_at);

// For blobs with custom size
let blob_spec = SecretSpec::new(Algorithm::None).size(64);
```

### StoreMode

Controls `put()` behavior:

| Mode              | Behavior                          |
|-------------------|-----------------------------------|
| `NewOnly`         | Fail if secret already exists     |
| `ReplaceExists`   | Fail if secret does not exist     |
| `CreateOrReplace` | Always write                      |

### Secret Types

| Type           | Algorithm     | Operations                    |
|----------------|---------------|-------------------------------|
| `KeyPair`      | `Ed25519`     | sign, verify, export          |
| `SymmetricKey` | `Aes256Gcm`   | store, export (see note)      |
| `Blob`         | `None`        | read/write raw data           |

The `SymmetricKey` trait declares `encrypt`/`decrypt`, but the bundled
in-memory implementation does not provide them: it stores and returns key
material, and both operations return an error. Vault contents are still
encrypted at rest under the master key -- that is storage-level encryption and
is unrelated to these per-key operations.

Access typed data via `secret.as_keypair()`, `secret.as_symmetric_key()`, or `secret.as_blob()`.

### Hierarchical Secret IDs

Secret IDs support `.`-delimited hierarchical paths:

```rust
use secrets_vault::make_secret_id;

let id = make_secret_id!("keys", "validators", "node_01");
// Stored at keys.validators.node_01 in the tree
```

## Architecture

```
SecretVault
  |
  +-- Storage (trait)
  |     +-- FileJsonStorage   [feature: file-storage-json]
  |     +-- HashicorpStorage  [feature: hashicorp-storage]
  |
  +-- CryptoFactory (trait)
  |     +-- AutoCryptoFactory    (selects best available)
  |     +-- DefaultCryptoFactory (ed25519-dalek)
  |     +-- BlockCryptoFactory   (tos_block)
  |
  +-- CryptoImpl<B: Ed25519Backend>
  |     +-- DefaultEd25519  [feature: crypto-default]
  |     +-- BlockEd25519    [feature: crypto-block]
  |
  +-- ProtectedMemory
        (mlock + mprotect + zeroize-on-drop)
```

## Cargo Features

| Feature              | Description                                | Default |
|----------------------|--------------------------------------------|---------|
| `file-storage-json`  | Local encrypted JSON file storage          | Yes     |
| `crypto-default`     | Ed25519 via `ed25519-dalek` + AES-GCM      | Yes     |
| `with-base64`        | Base64 encoding support                    | Yes     |
| `crypto-block`       | Ed25519 via `tos_block` (TOS-compatible)   | No      |
| `hashicorp-storage`  | HashiCorp Vault remote backend             | No      |
| `secrets-vault-cli`  | CLI binary                                 | No      |

At least one of `crypto-default` or `crypto-block` must be enabled. When both are enabled, `crypto-block` takes priority in `AutoCryptoFactory`.

## Error Codes

Errors are categorized by numeric code ranges:

| Range   | Category         | Examples                                     |
|---------|------------------|----------------------------------------------|
| 1xx     | Secret errors    | not found, already exists, non-extractable   |
| 2xx     | Crypto errors    | invalid signature, decryption failed         |
| 3xx     | Storage errors   | corrupted, read/write failure, lock timeout  |
| 4xx     | Backend errors   | connection failed, auth failed               |
| 5xx     | Config errors    | invalid URL, missing master key              |
| 6xx     | Internal errors  | serialization, deserialization               |

All errors implement `std::error::Error` with `.code()` for the numeric code and `.message()` for context.

## CLI

See [cli/README.md](cli/README.md) for the command-line interface documentation.

Build with:

```bash
cargo build -p secrets-vault --features secrets-vault-cli
```
