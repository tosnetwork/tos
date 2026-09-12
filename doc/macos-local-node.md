# Running a local TOS chain on macOS

`scripts/setup-testnet.sh` installs systemd units and writes under `/data`, so it
only works on Linux. On macOS the same node binaries can be driven in-process by
`scripts/localnet-jsonrpc.py`, which brings up one DHT server and N validators
and leaves them resident.

Everything below runs the real `validator-engine`; the chain produces real blocks
and executes real transactions. The Python harness only generates the zerostate
and launches the processes. Once the chain is up, nothing else needs it: contract
deployment, transfers and inspection all go through `lite-client`.

## Prerequisites

- Xcode command line tools, CMake, Ninja, and `uv` (`brew install cmake ninja uv`).
- A configured build directory. The first configure downloads and builds the
  vendored third-party trees and takes a long time; later ones are incremental.

## Build the binaries the chain needs

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target create-state generate-random-id validator-engine \
  dht-server validator-engine-console lite-client -j8
```

To work with contracts as well, add `func fift tol emulator` to that target list.

## Start a chain

```sh
uv run python scripts/localnet-jsonrpc.py --validators 1 \
  --rpc 127.0.0.1:18545 --control 127.0.0.1:18745 \
  --workdir test/integration/.localnet
```

It stays in the foreground until Ctrl-C. Do not pipe it through `tail` or `head`:
Python block-buffers its own output when redirected, so the startup banner will
not appear until the process exits, which looks like a hang.

Useful flags: `--demo` runs a faucet self-test after boot, `--fund 0:<hex>:25`
sends TOS to an address, `--reuse` resumes an existing validator database, and
`--base-port` moves the DHT and liteserver ports for a second concurrent chain.

## Check that it is alive

```sh
curl -s -X POST http://127.0.0.1:18545/jsonRPC \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getMasterchainInfo","params":{}}'
```

A climbing `result.last.seqno` means blocks are being produced. The same endpoint
answers `getAddressInformation` with `{"address": "0:<hex>"}`.

## Fund an address

The script exposes a localhost-only faucet on the `--control` port:

```sh
curl -s -X POST http://127.0.0.1:18745/transfer \
  -H 'content-type: application/json' \
  -d '{"address":"0:<64 hex>","amount":5}'
```

It replies with the destination balance before and after, and waits for the
transfer to confirm. The faucet is the zerostate main wallet at
`-1:0000…0000`; its key is in `<workdir>/state/main-wallet.pk`.

## Inspect the chain with lite-client

Use batch mode. Piping commands into its stdin does not work.

```sh
LC="build/lite-client/lite-client -C <workdir>/lite-client.json -r -v 0 -t 25"
$LC -c "getconfig 8"                      # global version and capabilities
$LC -c "getconfig 19"                     # global_id, needed to sign messages
$LC -c "getaccount 0:<hex>"               # state, balance, last transaction
$LC -c "runmethod 0:<hex> seqno"          # call a get method
$LC -c "lasttransdump 0:<hex> <lt> <hash> 3"   # phases and exit codes
$LC -c "sendfile message.boc"             # submit an external message
```

`lasttransdump` is how you find out why something failed: look for `exit_code`
(compute phase) and `result_code` (action phase). An account that received a
message but produced nothing, with a low gas figure and `exit_code:0`, silently
returned early rather than failing.

## Deploying contracts and sending transfers

The chain's `global_id` is part of what wallets sign, so read it from
`getconfig 19` rather than reusing a value from the test suites — the local chain
uses `3` while the contract test harnesses use `42`. Signed messages also carry
real wall-clock expiry, so build `valid_until` from `time.time()`, not from the
fixed timestamp those harnesses use.

The cell builders and message shapes are already written in
`test/auth-extensions/` (`cells.py`, `native.py`) and `test/mldsa-auth/`
(`protocol.py`). They are used against the emulator there, but the bytes are the
same: build the message, write `cell.boc()` to a file, and `sendfile` it.

A wallet can be deployed by an external message carrying its StateInit, because
wallets accept external messages. A contract that refuses external messages —
the ML-DSA authentication module throws on every one of them by design — cannot
be deployed that way. Send it an internal message carrying the StateInit from a
wallet instead; the contract does not have to accept anything for that to work.

## Rehearsing a protocol version this build does not advertise

```sh
TOS_GLOBAL_VERSION=16 uv run python scripts/localnet-jsonrpc.py ...
```

The override is applied before the zerostate is generated and shows up as
`version : global_version=16` in the banner, and as
`ConfigParam(8) = (capabilities version:16 …)` on the chain.

Note what this does and does not mean. `common/global-version.h` declares the
version this build advertises. When the configured version is higher, the
collator and the validator log

```
block version 16 have been enabled in global configuration,
but we support only 15 (upgrade validator software?)
```

and then **continue**: `collator.cpp` and `validate-query.cpp` only `LOG(ERROR)`,
they do not refuse. Blocks are produced, the VM receives the configured version,
and instructions gated on it execute. So this override is enough to rehearse a
future version locally, and `SUPPORTED_VERSION` should not be read as a gate that
prevents a node from running at a higher version.

The message above was what a v15-advertising build printed at ConfigParam 8
version 16, roughly twice per block. `SUPPORTED_VERSION` is now 16, so it no
longer appears at that configuration; set `TOS_GLOBAL_VERSION=17` and it returns,
naming 17 and 16. Its companion line about capabilities is a different check and
is unaffected.

## Things that cost time

- **Piping the launcher** through another command hides its output until exit.
- **`.so` versus `.dylib`.** Anything that hard-codes a shared library suffix
  fails on macOS. Look the file up instead of assuming one.
- **Stale `__pycache__`.** When a script is edited and reverted within the same
  second, and the file length does not change, Python may reuse the cached
  bytecode. Export `PYTHONDONTWRITEBYTECODE=1` for anything that rewrites
  sources, such as a mutation run.
- **A relayer that runs out of funds** simply does not emit its message. The
  symptom looks like the destination contract ignoring a request; check the
  sender's balance and seqno before blaming the receiver.
- **Deploying twice.** Sending a StateInit to an already active account is not an
  error; the value is credited and the init is ignored, which can quietly drain a
  wallet that was meant to pay for something else.

## Stop and clean

Ctrl-C, or:

```sh
pkill -f localnet-jsonrpc.py
pkill -f 'validator-engine --global-config'
pkill -f 'dht-server --global-config'
rm -rf <workdir>
```

Each workdir is self-contained, so several chains can coexist with different
zerostates. Give each one its own `--rpc`, `--control` **and** `--base-port`:
the first two only move the HTTP endpoints, while the DHT and liteserver ports
come from `--base-port` and collide at its default otherwise.
