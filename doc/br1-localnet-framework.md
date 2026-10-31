# BR1 C1: two-operator process framework and localnet wiring

**This increment is a process/HTTP/SQLite integration fixture, not a funded
four-validator localnet acceptance result.** It composes the parallel A1 and B1
branches. PR #379 and main are not merged or activated by this work.

## What runs

`two_operator_harness.py` starts two independent OS processes, each with a private
journal, different worker identity/release scope, independent quote index, and a
real loopback HTTP listener. Both use the real NativeAdapter, Engine and Service.
The native provider is explicitly fabricated in the test harness. Its private
control pipe never becomes an HTTP endpoint. Disposable counters persist across
SIGKILL so a restarted process cannot hide repeated signing/broadcast attempts.

The complete nine-scenario registry covers both operators' request flows, foreign
quote refusal before signing, invalid-proof refusal, concurrent duplicate requests,
crash after prepare, crash after ambiguous write, lost HTTP acknowledgement,
destination refusal, and rejection of an unrelated receipt. Tests inspect genuine
persistent journals and actual HTTP responses; fabricated fee receipts are not
on-chain money or cryptographic proof.

```sh
python3 -m unittest discover -s test/bonded-relayer -p test_br1_cli.py -v
python3 test/bonded-relayer/run_delivery_fixture.py --out build/br1-process-fixture.json
```

The receipt has source SHA-256 identities, exact scenario inventory, counts and
elapsed time. It always states `native_chain_executed: false`,
`funded_operators: false` and `production_accepted: false`. A changed/partial
registry or a skipped/failed test cannot produce a passing fixture receipt.
Passing requires the token `BR1_PROCESS_FIXTURE_OK_NOT_NATIVE_ACCEPTANCE`.
`--require-native` returns exit 2 without running a fixture or creating a receipt;
there is no silent mock fallback.

## Localnet entry point

`tools/bonded-relayer/br1.py --config /absolute/operator.json --check` initializes
the private journal and probes the pinned native provider. It is not a read-only
filesystem check and does not broadcast or listen. Omit `--check` to start the
loopback service with internal bounded recovery, once a real provider exists.
The provider implementing the A1 protocol is **not shipped by this increment**;
missing paths/capabilities exit 2, not a ready health response.

The exact configuration fields are:

```text
schema = tos.br1.localnet.config.v1
mode = localnet
release = complete locally pinned relay_core.Release object
backend = absolute canonical reviewed native ELF path
backend_sha256 = independently obtained SHA-256 of that executable
state_dir = existing owned canonical directory with mode 0700
journal = absolute filename directly inside state_dir
port = IPv4 loopback port in 1024..65535
fee, funding_cap, max_reserved = positive bounded integer amounts
max_pending = 1..64
```

The configuration itself must be a single-link, owned regular file with mode
0600; symlinks, duplicates, unknown fields, secret/seed fields, invalid numeric
bounds and `mode: production` refuse. Do not paste keys into JSON or arguments.
The reviewed native custody boundary owns key access. Shutdown stops admission,
checks the stop signal between recovery jobs, and joins owned work before closing
persistent state. There is no native/mock selector or manual broadcaster fallback.

## C2: actual funded acceptance remains open

The next driver must launch four real validators and two independently funded
operators using the deployed Bond code/policy and a genuine Shield pool. It must
retain native proof material, native execution outcomes, full network/release
identities and the exact binaries/commits. Neither this fixture's counters nor
JSON `success` fields can substitute for those observations.

| Required real scenario | Acceptance boundary |
| --- | --- |
| Independent deployment and discovery | Each operator deploys/funds its own canonical Bond without a privileged registration path; client independently verifies live state and policy. |
| User without gas balance | An already-authorized valid Shield transaction executes using the selected operator's native TOS; the user discloses no witness or spend key. |
| Exact commission | Full destination finality authenticates the assigned ordinary output; fee import is idempotent and spendable only after confirmation. |
| Proof/fee substitution | Invalid proof with a valid-looking fee, wrong output owner/index/domain/amount and altered body are refused before paid submission. |
| Gas and action failure | Forced wallet/pool/Bond action failures have the intended rollback and fee behavior, with native execution evidence. |
| Process crash and ambiguous write | Before/after prepare, WAL persistence, submission and terminal credit; no double signing or automatic UNKNOWN rebroadcast. |
| Two-worker competition and duplicates | Exact request/nullifier competition cannot redirect fee, falsely finalize or charge twice; a different worker requires a newly authorized candidate. |
| Slash and retirement | Objective same-slot acceptance equivocation, invalid evidence, full challenge window, backing erosion and failed withdrawal actions. |
| Resource/load and privacy | Bound proof work, bodies, connections, disk and funding exposure; exercise sustained load, failure/recovery and reviewed transport/logging policy. |

Final activation additionally requires cross-executor coverage, reviewed economic
parameters, independent/non-author review, third-party security audit, an approved
release manifest, and all existing Shield gates. Current work supplies none of
those approvals. See the separate A1 and B1 documents for the exact delivered/open
matrix rather than treating the three new PRs as three completed production phases.
