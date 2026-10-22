# Offline StateDb compatibility gate

This crate is the compatibility boundary for node-data sync. It does not enable
operator restoration. The default feature set provides schema keys only. Native
access requires `native` and the database archive built from this checkout;
there is no system-library or raw-directory-copy fallback.

`open_existing` requires an existing real directory, takes the native exclusive
lock, replays WAL and requires schema version 2. It must only open a private,
stopped image: it is not a read-only verification API. `create_staging` creates
a private new directory. Writes are one synced native batch. `None` means delete;
`Some([])` means a present empty value. The version key is boxed TL bytes; named
TL keys are hashed. Local raw cleanup keys preserve their native encoding,
including uppercase session hex.

Run in the builder image, from the repository root, after configuring a Release
build with the production compiler arguments:

```sh
cmake --build build --parallel 24 --target \
  validator-engine test-node-store-fixture dht-server validator-engine-console \
  toslibjson gen_fif create-state func fift generate-random-id tos-pq-consensus-key
export NODE_STORE_NATIVE_DIR="$PWD/build/third-party/rocksdb"
export NODE_STORE_FIXTURE="$PWD/build/test-node-store-fixture"
export CARGO_TARGET_DIR="$PWD/build/node-store-target"
cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-store \
  --features native --test native_fixture -- --nocapture
cargo build --manifest-path tosctl/src/Cargo.toml --locked -p node-store \
  --features native --example reconstruct_fixture
uv sync --no-dev
uv run test/tostester/generate_tl.py
uv run python test/integration/node_store_native_reopen.py \
  --root build/node-store-native-reopen --build build \
  --reconstruct build/node-store-target/debug/examples/reconstruct_fixture
```

The first test requires a non-empty WAL and no SST before opening the fixture,
then checks native readback after reconstruction, local byte preservation,
missing versus empty, lock exclusion, missing-source refusal and version refusal.
The native helper uses production StateDb methods and exits without destructors
after acknowledged writes. It is not a mock key/value map.

The second test starts four disposable validators and one non-validator on
global id 3, reconstructs the non-validator's StateDb using the typed wrapper,
then reopens it in the production engine and checks the same full block ID.
`reconstruct_fixture` is a test example with a closed, small fixture key inventory;
it refuses unrecognized records. It is not a complete exporter or restore CLI.

The local network creates private fixture keys beneath its explicitly selected
root. Never publish that directory. Tests refuse an existing root; stop their
processes before deleting it. These compatibility results do not qualify dump
capture, transactional cutover, the recovery-material policy or a 30-minute rejoin.
