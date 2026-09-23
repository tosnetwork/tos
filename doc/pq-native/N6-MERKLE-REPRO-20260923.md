# N6 Merkle exact-ancestor investigation — component reproduction

Status: **component mechanism reproduced; historical actor ordering remains unproved**.

The investigation branch `n6/merkle-repro-investigation` adds
`test-consensus-simplex2-merkle-skipped-exact-ancestor-repro`. It calls the
production `select_skipped_slot_resolution()` with an exact requested
`CandidateId`, an installed slot-level SkipCert indication, and no locally
installed NotarCert. The current policy selects `UseAvailableBase`. The test
then constructs the consensus fixture's real Merkle update from state height
`N` to `N+1` and applies it both to the exact state `N` and to the
skip-selected older state `N-1`.

The correct application succeeds. The older base fails with the same complete
hashes as both retained September errors:

| Expected parent | Selected base | Expected old hash | Applied-to hash |
| --- | --- | --- | --- |
| 5 | 4 | `C8D1E14FE26D8983DA2383CF719AFF88B3F9EFA8A5B09C625AB12EFFC2926932` | `92345EFB21EC9E506E9FDB654AC3E84E46282531698C7F6AF88877245121DD54` |
| 23 | 22 | `69A2DC37E67A1D7398E4D188E1468DD4CEB1181358C0CAB56BAE28BF661F8FAA` | `19088211A6DB566029368CE0D6F45C68DF030896091F186C070725F49A43CB57` |

Run the component test with:

```sh
cmake --build build --target test-consensus -j2
ctest --test-dir build -R '^test-consensus-simplex2-merkle-skipped-exact-ancestor-repro$' -V
```

The local raw logs are retained under
`/home/tomi/tos-carrier/merkle-repro-artifacts/`. The first green log has
SHA-256 `276c4f6c4bab0c9c4c386474a6b85fb43b8cc1385ea7f685fd0e6d5dd3c81d07`.
Changing only the no-installed-notar branch of
`select_skipped_slot_resolution()` to `ResolveCandidate` made this test fail
at its decision assertion; the red log has SHA-256
`39bafe854ada03dced3d40c2d89f9f67a393d113ae4210d1d446ad387d0794`.
Restoring the production branch made it pass again; that log has SHA-256
`8b7f067c41da2ffb4113951109505e77f8f1c6ff767db4b2ca409f43debb3e8b`.
The mutation was removed from the investigation branch.

## Real certificate arrival orders

The unchanged 100-node PQ finality test passed in 6.95 seconds. A second
60-second run with 50–200 ms randomized database-write delay also exited 0.
`analyze-certificate-order.py` groups Pool's `Obtained certificate` lines by
node, consensus instance, and slot. Those lines occur after `SaveCertificate`
and Pool installation; the log order therefore describes the installed
certificate order on that node.

| Run | Nodes/slots with both certs | Skip installed first | Notar installed first | Merkle error |
| --- | ---: | ---: | ---: | --- |
| Existing e2e-100 CTest | 484 | 200 | 284 | None |
| e2e-100, DB delay 50–200 ms | 744 | 419 | 325 | None |

The retained baseline log has SHA-256
`8304784c6a58e9abc53da3ddb37a541f3adb3ff39df9390819b3f886c75ae75b`;
the delayed log has SHA-256
`5c9150febe45b4e081f5a8457afc85b1df9960c65f6f2e3eb63f7382262dfd2a`.
Reproduce the count with:

```sh
python3 test/validator/consensus/analyze-certificate-order.py \
  merkle-repro-artifacts/e2e100-baseline.log \
  merkle-repro-artifacts/e2e100-db-delay-50-200ms.log
```

The delayed run used:

```sh
build/test/validator/consensus/test-consensus --duration 60 --n-nodes 100 \
  --target-rate-ms 100 --net-ping 0.005:0.02 --pq-finality-e2e-test \
  --db-delay 0.05:0.2
```

Both certificate orders occur in a running network, but neither run showed
that a descendant named the affected candidate while its NotarCert was absent
locally. These green runs do not establish or refute the historical race.

## Resolver shortcut trace

For two further 30-second, 100-node runs, I temporarily logged every time
`StateResolverImpl` received a nonempty result from `QuerySlotSkipped`. Both
runs used 50–200 ms DB write delay; one also set
`TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES=1` to force repeated ancestor walks.
Both exited 0, and neither emitted the shortcut log or a Merkle error.
The raw logs have SHA-256
`6f0efd4f4ae24cb45ecd7e9d86279e459582daba882481889f27df5d9e7e0ab2`
and `5bd23487d6869baa9affd5236bacc13661dcc71aa90418839287dc7fbc6f355f`.
The diagnostic logging change was removed and the binary rebuilt from the
restored source. This negative result explains why generic stress is not a
substitute for a controlled certificate and descendant timing test.

## Production ingress constraints on an actor reproduction

The code path narrows the required timing. `Consensus::try_notarize()` awaits
`WaitForParent(candidate)` before calling `ResolveState(candidate.parent_id)`.
Pool's `maybe_resolve_request()` waits if that **immediate parent** does not
have an installed NotarCert. Thus a local candidate-validation test that
supplies C with `C.parent_id=P` while this node has only SkipCert(P) will wait;
it will not by itself exercise the shortcut. The same ordering exists in both
historical failing commits `68ea21db4` and `efd22ce46`.

There is a separate production ingress: Pool can install a received
NotarCert(C) without first establishing C's entire ancestry on this node.
Its `available_base` can then select C for a new leader window, and
`Consensus::start_generation(C)` calls `ResolveState(C)` without
`WaitForParent(C)`. `StateResolver` resolves C and then walks its signed
parent chain. If P is a full ancestor in that chain, this node has SkipCert(P)
but has not installed NotarCert(P), the current `QuerySlotSkipped(P)` may
replace P with `available_base` and omit its state transition. The same
possibility applies to an older ancestor reached when validating a candidate
whose immediate parent *is* locally notarized.

An actor regression should therefore deliver a signed chain with a full P,
install a later NotarCert(C) and SkipCert(P) on the target node while withholding
NotarCert(P), then trigger leader-base resolution of C (or validation through
a locally notarized immediate parent). It must assert that the shortcut is
actually taken and that applying the later candidate's Merkle update to the
older base fails N/N-1; after the exact-ancestor change the same timing must
resolve P or return bounded notready. The component test above does not satisfy
this production-ingress condition, and the two green stress runs did not
observe a nonempty shortcut.

This is an executable counterexample to the local skip decision plus Merkle
state transition. It does **not** run `StateResolverImpl`, prove that a
descendant actually names this candidate under a particular certificate
arrival order, or reconstruct either original failure's lost CandidateId and
stack. The next required result is a deterministic actor or integration test
that holds `SaveCertificate(NotarCert(P))` while SkipCert(P.slot) is installed,
drives resolution of a descendant that explicitly names P, and records a red
N/N-1 result with the shortcut versus a green exact-ancestor result without
it. Keep `merkle-base-state-mismatch` OPEN until that result and the required
consensus regressions exist.
