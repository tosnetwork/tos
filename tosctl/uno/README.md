# tosctl-uno

Wallet CLI for the Uno Workchain (wc=2 PQ-native privacy L1). This is the
**P.6 foundation** build: receive-side and key management work end-to-end;
`send` is stubbed until the full P.2 Transfer AIR lands.

Design reference: [`doc/uno-workchain.md`](../../doc/uno-workchain.md) §2.6
(key hierarchy), §2.7 (hybrid KEM), §5.8 (wallet sync), §7.5 (scan), §9
(RPC).

## Build

```sh
cd tosctl/uno
cargo build --release
# → target/release/tosctl-uno
```

Run the Rust test suite (includes the integration test: derive keys → build
address → verify `ivk_commitment`):

```sh
cargo test
```

## Subcommands

### `keygen` — derive FVK from main TOS seed

```sh
tosctl-uno keygen --seed "abandon abandon abandon ... abandon art" --out fvk.json
# or
tosctl-uno keygen --from-tos-seed ~/.tos/seed.hex --out fvk.json
```

The FVK JSON contains `uno_seed`, `nk`, `ivk`, `ovk`, `mlkem_seed`,
`pk_mlkem`, `sk_mlkem` (§2.6). Keep this file private — it carries
`sk_mlkem` and `ivk`, which together can decrypt every incoming note.

### `address` — build a diversified Address

```sh
tosctl-uno address --fvk fvk.json --random
tosctl-uno address --fvk fvk.json --diversifier 000102030405060708090a
```

Emits the 1259-byte wire form, the four component fields (`d`, `pk_d`,
`ivk_commitment`, `pk_mlkem`), and a string-encoded form
(`uno1<base58(bytes || BLAKE3[:4])>`, ~1680 chars).

### `scan` — compact-filter GCS + hybrid-KEM trial-decrypt

```sh
tosctl-uno scan --fvk fvk.json --rpc http://localhost:8080 --from-block 0
```

For each block in `[from_block, to_block)` the scanner fetches
`uno_getBlockFilter(seqno)` + `uno_getOutputsAtBlock(seqno, ...)`, runs
`s_dh = ivk · epk` and `ML-KEM-768.Decap(sk_mlkem, mlkem_ct)` per output,
derives `k_aead`, and attempts ChaCha20-Poly1305 Open. Matches are emitted
as a JSON array of owned notes.

### `balance` — unspent notes sum

```sh
tosctl-uno balance --fvk fvk.json --rpc http://localhost:8080
```

Runs `scan` internally, then queries `uno_getNullifierStatus` per note to
drop spent entries.

### `chain-info` — smoke-test the RPC endpoint

```sh
tosctl-uno chain-info --rpc http://localhost:8080
```

### `send` — NOT in P.6

```sh
tosctl-uno send ...   # returns an explicit "not yet available" error
```

Requires the full P.2 Transfer AIR prover; not shipped in this foundation.

## Primitive choices

| §2 primitive                    | Crate                                                     |
|---------------------------------|-----------------------------------------------------------|
| BLAKE2b-256 / -512 (seed deriv) | `blake2`                                                  |
| BLAKE3 (hybrid-KEM KDF + nonce) | `blake3`                                                  |
| ChaCha20-Poly1305 (note AEAD)   | `chacha20poly1305`                                        |
| Ristretto255 (ECDH, HashToCurve)| `curve25519-dalek` (`from_uniform_bytes`)                 |
| ML-KEM-768 (PQ KEM)             | `ml-kem` (RustCrypto, FIPS 203)                           |
| Poseidon2-over-Goldilocks       | `p3-poseidon2` + `p3-goldilocks` pinned to Plonky3 rev `6374a36f` (same pin as `uno/plonky3-ffi/`) |
| BIP-39                          | `bip39` (24-word English)                                 |

Each primitive produces outputs byte-identical to the C++ side under
`uno/crypto/*`; the in-tree tests in `src/*::tests` assert the receiving-end
contracts (deterministic key derivation, `ivk_commitment` binding,
filter_tag stability, hybrid-KEM transcript binding, base58-checksum
round-trip).

## Off-spec choices

- **Address string format.** The design doc only fixes the 1259-byte wire
  format. This CLI uses `hrp || base58(bytes || BLAKE3(bytes)[..4])` with
  `hrp ∈ {"uno1", "unos"}`. Base58 keeps the string manageable (~1680
  chars) and the 4-byte BLAKE3 checksum catches most transcription errors.
  A future chain-wide convention (Bech32m, or a multi-part "piece" scheme
  suited to QR codes) can replace this without breaking the wire bytes.

- **Standalone Rust workspace.** `tosctl/uno/` is its own Cargo workspace
  rather than a member of `tosctl/src/Cargo.toml`. The main tosctl workspace
  pins Rust 1.91.1 / edition 2024; this crate uses edition 2021 with no
  toolchain pin, so it builds on any recent stable Rust. Binary is named
  `tosctl-uno` and can be dropped alongside `tosctl` in a release bundle.

## Not in scope

`tosctl uno send` (requires P.2 AIR). The stub exits with a clear error
message directing the user to check back after P.2 ships.
