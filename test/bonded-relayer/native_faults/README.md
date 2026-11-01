# Native local fault controls

These runners exercise an existing **isolated global-id-3** BR1 deployment.
They use its real provider, durable journals, audited client candidate and native
proof verifier. They do not manufacture finality or accept a public-network
configuration. Keep this directory in the checkout; all inputs, captures and
outputs belong in private storage outside Git.

Use Linux Python with `os.memfd_create` (on toserver, `/usr/bin/python3`). First
provision and fund the local provider as described in
[`provider/README.md`](../../../tools/bonded-relayer/provider/README.md).
The private service config pins the provider ELF and release; its provider config
pins the proof helper, genesis, pool and Bond. A fresh client candidate is the
normal `Request` JSON object consumed by `/v1/submit`, built from an issued quote
using the audited wallet `PublicClient` planning API. The quote must already be
in this worker's journal, its fee descriptor must own the selected encrypted
output, and its source notes must be unspent. Key generation, ceremony and note
funding are setup prerequisites, not simulated by these controls. No seed,
status capability or signed candidate is checked into the repository.

## Lost reply and process crash

Start the gate in its own user unit, retaining a private capture directory:

```sh
umask 077
systemd-run --user --unit br1-rpc-fault-v2 --property=UMask=0077 \
  /usr/bin/python3 "$CHECKOUT/test/bonded-relayer/native_faults/proxy.py" \
  --port 34821 --upstream-port 34811 --out "$PRIVATE/wire"
```

Set only the disposable worker's `provider.json.rpc_url` to
`http://127.0.0.1:34821/jsonRPC`. Preserve its keys, release, database and sequence.
The gate forwards each request once, captures exact bytes, and closes the
connection after receiving a `sendBoc` response. It never retries. Captures are
bounded and numbered monotonically across gate restarts; existing files cannot
be overwritten. To kill the relayer immediately after upstream acceptance, add
`--kill-unit br1-operator-c.service`. Use the worker's existing systemd restart
policy. A `.fault.json` records the exact message digest, response digest, reply
loss and selected killed unit. Run a separate fresh candidate for each case.

```sh
/usr/bin/python3 "$CHECKOUT/test/bonded-relayer/native_faults/control.py" \
  --mode submit --config "$PRIVATE/operator-c/service.json" \
  --request "$PRIVATE/fresh-request.json" --token "$PRIVATE/status-token" \
  --capture "$PRIVATE/wire" --out "$PRIVATE/lost-reply"
```

The runner writes a one-shot marker before submitting and refuses an existing
job. After any submit error it queries the original identity only. It requires
`executed`, matching persisted wallet bytes, exactly one captured send of those
bytes, and one finalized native fee import. These are distinct from an RPC ACK.
If the runner itself stops, resume without signing or submitting again:

```sh
/usr/bin/python3 "$CHECKOUT/test/bonded-relayer/native_faults/control.py" \
  --mode reconcile --config "$PRIVATE/operator-c/service.json" \
  --request "$PRIVATE/fresh-request.json" --token "$PRIVATE/status-token" \
  --capture "$PRIVATE/wire" --out "$PRIVATE/reconcile-readonly"
```

A deliberate duplicate capture must fail with `exact original message sent 2
times`; this checks the instrument without resending funds. Restore direct RPC
and stop the gate after each acceptance run.

## Signed wallet expires while the Shield candidate remains valid

Issue a new quote and build another fresh candidate with close to its full
300-second lifetime. Stop this worker's HTTP unit before running the control,
so its recovery thread cannot race the old/new permit comparison. Supply the
reviewed old provider ELF and its independently recorded SHA-256:

```sh
systemctl --user stop br1-operator-c
/usr/bin/python3 "$CHECKOUT/test/bonded-relayer/native_faults/control.py" \
  --mode expiry --config "$PRIVATE/operator-c/service.json" \
  --request "$PRIVATE/fresh-expiry-request.json" \
  --baseline "$PRIVATE/bin/br1-provider-r3" \
  --baseline-sha256 "$REVIEWED_OLD_PROVIDER_SHA256" --out "$PRIVATE/expiry"
```

Both ELF pins are validated before reservation or signing. This uses the real Engine, NativeAdapter, SQLite journals, preflight and signer.
Only the test adapter's recheck is interrupted: it raises after Engine durably
claims UNKNOWN and before any RPC write. The runner keeps the original bytes,
waits 122 seconds beyond persistence for the SDK wallet's 120-second TTL, then
requires historical validation to pass, the Shield candidate to remain live,
the old provider to issue a permit, and the new provider to refuse. It does not
broadcast. An interrupted runner resumes with `--mode expiry-resume` and the
same arguments/output directory, checking the original stored bytes instead of
preparing a second message.

Do **not** restart recovery until the permit comparison and VERDICT finish.
The native sequence lease, Python input locks and UNKNOWN job are retained.
With the #388 provider, drain that worker; no terminal nonacceptance path is
claimed. A later independently reviewed recovery implementation must prove
nonacceptance before releasing these reservations. Never delete custody or
edit journal rows to make a test pass.

## Retained November 1 run and commands

`../evidence/native-faults-20261101.json` identifies the implementation, initial
historical harness hashes, original case receipts and their limitations. The
new durable runner is additionally exercised against those original bytes:

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/control.py \
  --mode reconcile --config /tos/build/br1-localnet/operator-a/service.json \
  --request /tos/build/br1-localnet/e2e-crash/crash-after-accepted-write-request.json \
  --token /tos/build/br1-localnet/e2e-crash/crash-after-accepted-write-token \
  --capture /tos/build/br1-localnet/fault-wire \
  --out /tos/build/br1-localnet/durable-control-recheck
```

A fresh real lost-reply run uses the committed gate and `--mode submit`, config
`operator-c/service.json`, request/token under `e2e-durable/durable-fault-*`,
capture `wire-durable`, and output `durable-submit`, all beneath
`/tos/build/br1-localnet`. Raw proofs, inputs and outputs remain private there;
public indexes contain only hashes and outcomes. A repeat must use `reconcile`
and a fresh output directory. These controls cover these named boundaries;
full C2, refusal/liveness cases and public activation remain separate gates.

The fresh D TTL command retained for this PR was:

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/control.py \
  --mode expiry --config /tos/build/br1-localnet/operator-d/service.json \
  --request /tos/build/br1-localnet/e2e-durable-expiry-d/durable-expiry-d-request.json \
  --baseline /tos/build/br1-localnet/bin/br1-provider-r3 \
  --baseline-sha256 767541af088ad03140ffe358c5a69b8af2627fd77293232be3ad19a58122d00e \
  --out /tos/build/br1-localnet/durable-expiry-d
```

D used the pinned #388 ELF and remained stopped/drained after its signed,
never-sent case. Its old/new TTL comparison passed. Historical candidate
files eventually expire; a new acceptance run needs fresh quoted client input,
not a replay of an old submit or a database reset.

## Proven nonacceptance after the before-RPC interruption

The provider's newer recovery implementation retains the pre-signing funding
head and requires a native proof of the unchanged wallet shard at or after
expiry. After `expiry` succeeds, restart that disposable worker and wait for its
original UNKNOWN job to become rejected; never submit a replacement to provoke
this transition. The native refusal receipt retains its witness and digest.
The audit below is read-only for journals and signatures. `--cache-without-rpc`
requires the HTTP worker stopped, saves a private provider-config backup,
temporarily makes RPC unavailable, queries the retained proof twice, and restores
the configuration in a finally block. The helper never edits journal rows.

```sh
systemctl --user stop br1-operator-c
/usr/bin/python3 test/bonded-relayer/native_faults/control.py \
  --mode refusal --cache-without-rpc \
  --config /tos/build/br1-localnet/operator-c/service.json \
  --request /tos/build/br1-localnet/e2e-strict-expiry/strict-expiry-request.json \
  --out /tos/build/br1-localnet/strict-durable-refusal
systemctl --user start br1-operator-c
```

The original case verifies retired native lease, consumed old permits, released
Python input locks, zero fee imports for the refused candidate, unchanged
sequence/head/logical-time bindings, and `wallet_shard_time >= wallet_expiry`.
A subsequent fresh quoted transaction spends the same still-unspent input notes
through that worker, using the safely released funding sequence. The committed
gate additionally kills it after that write is accepted; `--mode submit`
reconciles original bytes with exactly one send/fee import. Native and Python
tombstones from the refused job are retained. This is isolated local acceptance,
not public activation approval or full C2 coverage.

## Public failure receipts, retention and access

`../evidence/native-nonacceptance-failures-20261101.json` retains bounded,
redacted **actual runtime failure sections** for all nine guard mutations, their
exact replacement anchors, command, exit codes and restored22 summary. It is
retained in normal Git history with no scheduled expiry; hashes alone are not
the public evidence. No private-host access is needed to inspect these failures
or reproduce the assertions from source.

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/nonacceptance_mutations.py \
  --scratch /tos/worktrees/tos/br1-nonacceptance-controls-20261101 \
  --out /tos/build/br1-nonacceptance-repro-20261101 \
  --target-dir /tos/build/br1-native-provider/cargo
```

All three paths must be absolute. Scratch and output must not already exist.
The runner creates its own detached worktree at the receipt's exact frozen core
commit, mutates only that new copy, checks
for runtime test failures (compiler errors do not count), restores each source
in finally, and checks the complete22 inventory. It never accepts an existing
checkout as scratch and never force-removes dirty work. On toserver use the
thermal guard around this command and keep new worktrees under `/tos/worktrees`.
Other review hosts can choose equivalent private scratch/cache directories.

Full logs and private chain-case material under `/tos/build/br1-terminal-
nonacceptance` and `/tos/build/br1-localnet` are retained at least until
**2027-02-01 UTC**. Authorized operators retrieve them through the existing
authenticated SSH access to toserver; this PR grants no new/public credentials
or permissions. Seeds, status tokens, SQL blobs and unredacted live payloads are
not published. Historical block states and expired signing windows cannot be
regenerated after chain progress; compiler-log paths and timings also vary.
The public excerpts are the minimal necessary failure receipts; fresh assertion
semantics are reproducible with the committed runner above.


## Competing spend and destination abort

`race_proxy.py` is deliberately restricted to the disposable C worker, global
id3 and ports34821/34811. Its private scenario contains `request_id`,
`winner_body`, `target_body` (absolute BOC paths) and
`commitments_after_winner`. Build two fresh, valid candidates over the same
unspent notes: the target uses C's issued quote; the winner is the competing
ordinary wallet transfer. Both must forbid public withdrawals. Start the gate:

```sh
systemd-run --user --unit br1-race-proxy --property=UMask=0077 \
 /usr/bin/python3 "$CHECKOUT/test/bonded-relayer/native_faults/race_proxy.py" \
 --root "$PRIVATE" --config "$PRIVATE/operator-c/service.json" \
 --scenario "$PRIVATE/e2e-race/scenario.json" --out "$PRIVATE/wire-race" \
 --client-python "$CLIENT_PYTHON" --toslib "$TOSLIB"
```

Route only C's provider RPC through34821, then submit the target **once** using
its normal HTTP client/status token. The gate checks the stored prepared bytes,
submits the winner once, observes its pool counter, forwards the original once,
kills/stops C, then sends one newer identical-body replay from the faucet.
Diagnostic counters select the cut points; they are not finality evidence.
If interrupted, inspect existing captures and journals; never restart a send.
Restore direct34811 RPC, install the reviewed refusal provider and restart C.
The native evidence path must authenticate its own failed transaction through
source and destination proofs, skipping the newer foreign replay. Audit it:

```sh
systemctl --user stop br1-operator-c
/usr/bin/python3 test/bonded-relayer/native_faults/control.py \
 --mode destination-refusal --cache-without-rpc \
 --config "$PRIVATE/operator-c/service.json" \
 --request "$PRIVATE/e2e-race/target-request.json" \
 --capture "$PRIVATE/wire-race" --out "$PRIVATE/destination-durable-refusal"
systemctl --user start br1-operator-c
```

This asserts rejected status, released input locks, retired lease, no surviving
permit and no fee import; it replays the immutable refusal twice with RPC down.
No journal rows are edited. The retained run had both failed transactions exit
152; only the winner advanced pool commitments38→41 and nullifiers25→27.
Pool liability remained2000000000 and reserved recovery leaves0.

## Native execution-phase fixtures and complete local history

Regenerate the small synthetic fixtures with the real C++ emulator on global
version16/id3 (no signature bypass, chain config modification or live keys):

```sh
FUNC_PATH="$FUNC" FIFT_PATH="$FIFT" EMULATOR_PATH="$EMULATOR" \
 /usr/bin/python3 test/bonded-relayer/native_faults/generate_phase_fixtures.py \
 --out "$NEW_PRIVATE_FIXTURE_DIRECTORY"
```

The manifest records compiler input and emulator/config hashes. Two successful
controls change state; gas -14 and action37 abort and preserve the prior state.
Rust tests parse these real native transaction BOCs and exercise the production
abort/cursor/fee classification. These fixtures establish phase semantics, not
public-network or on-chain forced gas/action acceptance.

For full historical replay, use `history.py` with a client Python that supplies
`pytosiq_core`, `--native-python /usr/bin/python3`, `--config`, a pinned
`--backend`/`--backend-sha256` supporting `pool_head`, and a new private `--out`.
Optional `--archive` directories supply retained BOCs. The native proof supplies
the exact pool head; every predecessor hash/account/LT is checked to creation.
The retained run collected18 transactions in2 RPC pages. A single-page export
was incomplete; this was pagination, not node pruning. Missing history refuses
and must never be treated as an empty pool. The runner bounds4096 transactions,
64MiB total,512KiB per transaction and2MiB per RPC response.
