# Lost native preparation reply: isolated chain acceptance

`prepared_reply.py` drives the real Python service and pinned native provider.
It requires global id 3. It does not provision custody, fund accounts, generate
client proofs, stop/start services, or replace an uncertain transaction.

Prerequisites: an active Bond and funded wallet, a fresh authenticated quote and
client request, and a private status-token file. Use the normal client to build
the request; retain its one-use note-index reservations. Route the operator's RPC
through a passive bounded loopback capture that forwards each call once. Keep
the native proof verifier and authenticated network/code/config checks enabled.
The operator journal must have no existing job for this request.

Stop only the isolated operator service, retaining its custody and journal.
Run with system Python supporting sealed memfd execution:

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/prepared_reply.py \
  --mode crash --config /absolute/private/service.json \
  --request /absolute/private/request.json --token /absolute/private/token \
  --inactive-unit br1-isolated-operator.service --out /absolute/private/new-case
```

The expected exit is **86**, accompanied by `prepare-reply-lost.json`. Any other
exit is a setup/fault failure, not a successful crash test. The marker precedes
the only submit. Do not rerun crash mode after that marker: inspect/reconcile
the existing original request instead. Native `prepare` has completed, while
the Python job must still be `reserved`, with no prepared message bytes. The
test-only RPC subclass exits before returning the reply to the engine. The
ordinary provider, signer and service code have no fault-injection switch.

Restart the ordinary operator service with the same config/custody/journal.
Then run:

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/prepared_reply.py \
  --mode verify --config /absolute/private/service.json \
  --request /absolute/private/request.json --token /absolute/private/token \
  --capture /absolute/private/passive-rpc-capture --out /absolute/private/new-case
```

Verify mode requires matching completed crash evidence. It only queries status
and reads the journals/capture. It never submits, signs or broadcasts. Success
requires the canonical native reply hash (message, representation hash and
acceptance) reconstructed from the persisted journal to match the reply hash
recorded at the crash cut, before writing a successful verdict. It also requires
finalized execution, exactly one captured send of the persisted
original message, and exactly one native fee-note import. Independently collect
the authenticated history with `history.py` and replay it with the ordinary
client; compare all planned pool getters and require zero recovery reservations.
Keep private request, quote/token, native acceptance and wire capture off GitHub.

## Retained local execution

On 2026-11-02, the driver itself repeated the real chain case under global id 3
and global version 16 using isolated operator E. Raw evidence is retained on
toserver through 2027-02-01 under
`/tos/build/br1-localnet/prepared-reply/attempt-4/`; `fault/VERDICT.json` binds the
request, original message and single broadcast/import. The earlier prototype
case is separately retained at `attempt-2/`, including authenticated pool history
and replayed final getters. This is not public-network pilot approval.

An active-operator invocation refused before creating its requested output.
Receipt controls under `/tos/build/br1-recovery-harness/receipt-controls-r4/` verify
the actual completed case: baseline and restoration pass; changing the crash
receipt's request identity refuses before reconciliation; removing that exact
guard falsely accepts the changed receipt. Source hashes and exit codes are
recorded in `REPORT.json`. The changed-receipt refusal is the regression check;
successful reconciliation alone is not evidence that this guard works.

Review found the initial driver recorded but did not compare the lost-reply
digest (Checklist: TE-8, existed / not applied). A second actual-case negative
changes only that digest: verification must refuse without writing `VERDICT.json`.
Removing the digest comparison falsely accepts; restoration requires the complete
message/hash/acceptance tuple to match the crash cut. The final review receipt
identifies the source hashes and retained controls for this correction.

Upstream comparison: this BR1 Python/native boundary and local acceptance tool
are absent upstream at ton master
`857b8a57a178e6ae0fe7fa86e7d81c5233de8560`. No inherited consensus code changes.


## Committed result index and repeatable controls

`prepared-reply-evidence.json` is the bounded sanitized index: exact runner/source
hashes, merged runtime commit/native artifact identity, commands, eight per-case
exit statuses, and SHA256/size for32retained raw artifacts. No private payloads,
tokens, seeds, database snapshots or binaries are committed. Its newest live
case uses the immutable merged397 native pilot build on the isolated id3 chain;
public id2 was not deployed. A fresh ordinary client proof/request was used.

The committed control runner repeats both identity/digest negative checks against
an already executed request, including exact guard removal and restoration:

```sh
/usr/bin/python3 test/bonded-relayer/native_faults/prepared_reply_controls.py \
  --config /absolute/private/service.json --request /absolute/private/request.json \
  --token /absolute/private/token --capture /absolute/private/passive-rpc-capture \
  --case /absolute/private/completed-case --out /absolute/private/new-control-run
```

It only invokes verify mode. A normal changed binding must exit1 at its named
refusal without a VERDICT. Removing that guard makes the same negative oracle
falsely accept (driver exit0); the index labels this explicitly rather than
counting it as secure acceptance. Baseline and restored original receipts pass.
The initial external-only result reference was insufficient (Checklist TE-9,
existed / not applied); this index and runner make the claim reviewable in Git.

The index also binds the fresh active-service refusal, required private request/body/quote/plan files, and consistent read-only journal backups retained externally. Custody seeds are not copied; signed payloads and private database content remain outside Git.
