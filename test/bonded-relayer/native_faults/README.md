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
