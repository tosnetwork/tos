# N6 Merkle exact-ancestor investigation — component reproduction

Status: **actor-level old-RED/new-GREEN gate met at `1a2f33940`, extended to the
peer-only ordering and the real `Consensus::start_generation` caller at `528f0864e`; attribution of the two
September incidents to this ordering remains unproved** (their CandidateIds and stacks
were not retained).

## Actor-level reproduction under controlled certificate order (`1a2f33940`)

`test/validator/consensus/test-merkle-prospective-notar.cpp` runs one validator
node with the production `Pool`, `CandidateResolver`, `StateResolver` and `Db`
actors; `Consensus` and `BlockProducer` are not registered, so the node casts no
votes of its own. The test holds all four validator keys and delivers real
quorum certificates through `IncomingProtocolMessage`, in this order:

1. NotarCerts for candidates `1..n-1` (A is `n-1`), each awaited until Pool
   publishes `NotarizationObserved`.
2. NotarCert(P), P = candidate `n`. The test database holds this certificate's
   write, so Pool knows it only as `being_saved`; `notarized_block()` is empty.
3. SkipCert(P.slot), signed by validators 1-3. Validators 1 and 2 also signed
   NotarCert(P); only finalize+skip is a vote conflict.
4. NotarCert(C), C = candidate `n+1`, `C.parent = P`.

Slots are laid out so C ends a leader window and the node under test is the
leader of the next window. Before triggering anything, the binary checks and
prints: Pool opened that window on base C (`LeaderWindowObserved`), NotarCert(C)
installed, NotarCert(P) held exactly once and not installed, P not yet
requested from peers, and no `MisbehaviorReport`. It then publishes
`ResolveState(C)`, which is what `start_generation(C)` does without
`WaitForParent`. A run whose ordering did not hold stops with
`MERKLE_ACTOR_PRECONDITION_FAILED` instead of resolving.

`check-merkle-prospective-notar.py` decides from that transcript, not from the
exit code alone. It computes the synthetic state hashes itself; they equal the
full retained incident hashes (`C8D1…/9234…` at n=5, `69A2…/1908…` at n=23).

The old resolver is this exact tree with only the five production files that
`bc379ec2c` changed restored to `e5b49ca45` (a zero-line diff against that
commit). `68ea21db4` and `efd22ce46` have the same `QuerySlotSkipped` logic.
The test source compiles unchanged against both resolvers.

| Binary | Expectation | n | Runs | Result |
| --- | --- | --- | ---: | --- |
| pre-fix | `red`: abort with `expected old = H(n), applied to = H(n-1)`, `candidate block id = C`, P never requested, hold still active | 5, 23 | 20 each | 40/40 |
| pre-fix | `control`: NotarCert(P) installed first, resolves to H(n+1) | 5, 23 | 20 each | 40/40 |
| pre-fix | `gate`: misaimed hold detected by the harness | 5 | 5 | 5/5 |
| fixed | `green`: requests P, waits while held, reaches H(n+1) after release | 5, 23 | 20 each | 40/40 |
| fixed | `bounded`: P never obtainable, `notready` "cannot resolve exact ancestor" | 5, 23 | 20 each | 40/40 |
| fixed | `control` | 5, 23 | 20 each | 40/40 |
| fixed | `gate` | 5, 23 | 20 each | 40/40 |
| pre-fix | `green` (must fail) | 5 | 1 | fails: exit -6 |
| fixed | `red` (must fail) | 5 | 1 | fails: "skip-shortcut resolver did not fail" |

The pre-fix abort is raised by the `StateResolver` actor inside
`ChainState::apply`. For n=5 it reports
`invalid Merkle update: expected old value hash = C8D1E14FE26D8983DA2383CF719AFF88B3F9EFA8A5B09C625AB12EFFC2926932, applied to value with hash = 92345EFB21EC9E506E9FDB654AC3E84E46282531698C7F6AF88877245121DD54`;
for n=23 it reports `69A2DC37…8FAA` / `19088211…CB57`. Both lines are identical to
the corresponding retained September errors.

CTest registers the four fixed-tree expectations as
`test-consensus-simplex2-merkle-prospective-notar-{exact-ancestor,bounded-refusal,control,gate-control}`.
The old-RED run needs the pre-fix resolver, so it is recorded here rather than
in CTest. To rerun it:

```sh
F="validator/consensus/simplex/bus.cpp validator/consensus/simplex/bus.h \
   validator/consensus/simplex/candidate-resolver.cpp \
   validator/consensus/simplex/pool.cpp validator/consensus/simplex/state-resolver.cpp"
git checkout e5b49ca45 -- $F
cmake --build build --target test-merkle-prospective-notar
cp build/test/validator/consensus/test-merkle-prospective-notar /tmp/prefix
git restore --staged --worktree --source=HEAD -- $F
python3 test/validator/consensus/check-merkle-prospective-notar.py /tmp/prefix red --n 5 --n 23 --runs 20
```

Artifacts are under
`/home/tomi/tos-carrier/merkle-repro-artifacts/prospective-notar-actor/1a2f33940/`.
Both binaries were built from `1a2f33940`, and a rebuild of the fixed binary
is byte-identical:

| File | SHA-256 |
| --- | --- |
| `fixed` | `ab569a827fc7502eef840f163d2f0ac9f05c1f09e8d91996092ca176c66111dc` |
| `prefix-e5b49ca45` | `846b84d00f4995a73bbf94febca220f31dba31dd223ed0c1a621604c1d7decfa` |
| `transcript-prefix-red-n5.log` | `e5557b710c31514c5acc7acfd32962c7f751fc47e20d1ad78768d42717ac1a2a` |
| `transcript-prefix-red-n23.log` | `34843e96b1df98b657b3d7c2b9b1ec3271371760455f93f28a3110fd5b3e4e43` |
| `transcript-fixed-green-n5.log` | `f2035d47a1b888004f1e07019323a1096f5d9fd54878ffa7addd1749002ce862` |
| `transcript-fixed-green-n23.log` | `462fe24d24bee863c9257e5386e898ac27e21f7411597453d28f728574fae1a2` |
| `transcript-fixed-bounded-n5.log` | `dcab2cdcfe8d5467587ced9ae2aee0e226b170f163ceac6fea3fdb0ce24f5fb8` |
| `transcript-fixed-bounded-n23.log` | `865945f918d6044d7892a3bc12318e2cc4e638d94567848f5365410bd863ce6f` |
| `repeat20-prefix-red.log` | `182ea1b61b185dfe0725b310246963048f2f4aa0fd6ac0e788c71aabd7dde975` |
| `repeat20-fixed-green.log` | `4c8a058eb04c8fe6d2ba29a9df0f5492b8335381587d42e561fd8deac3c2b160` |
| `repeat20-fixed-bounded.log` | `c6ee8e8d7d7e7ef244c3fc27fb787371c9158b8915ce2f40992ce2592b8742f0` |

### Peer-only NotarCert(P) through the real leader path (`528f0864e`)

The `peer-consensus` mode of the same binary covers two things the single-node
modes do not. First, the resolution is triggered by the production caller rather than
by the test. Second, the missing certificate is recovered from another node, not from a
delayed local write.

- **Two nodes.** The peer registers only `CandidateResolver` and `Db`. It
  holds every candidate and its NotarCert, and it runs no `Pool`, so it never
  gossips a certificate. The node under test never receives NotarCert(P) by
  any path. Before the trigger, the test proves the peer can serve
  NotarCert(P) by asking it as a third validator would.
- **A skip run.** Two skip-certified slots separate A from P, followed by
  SkipCert(P.slot). For n=5 the layout is Q1..Q4 at slots 0..3, skips at 4 and
  5, P at 6, C at 7, and the window opens at 8.
- **The real caller.** The node under test registers the production
  `Consensus` actor. Installing NotarCert(C) makes Pool open this node's own
  leader window on C, and `Consensus::start_generation(C)` issues
  `ResolveState(C)`. The test publishes no `ResolveState` in this mode. Own
  votes are kept out with 600 s first-block and standstill timeouts. The
  target never votes notarize, so it never casts a finalize vote.
- **The GREEN check.** The target requests P, the peer serves NotarCert(P),
  and `OurLeaderWindowStarted` is published for the window on base C with
  state H(n+1) and `next_seqno = n+2`. The target Pool never installs
  NotarCert(P), and no misbehavior is reported.

| Binary | Expectation | n | Runs | Result |
| --- | --- | --- | ---: | --- |
| pre-fix | `peer-red`: N/N-1 abort in `StateResolver`, `candidate block id = C`, P never requested, the window on C never starts | 5, 23 | 20 each | 40/40 |
| fixed | `peer-green` | 5, 23 | 20 each | 40/40 |
| pre-fix | `peer-green` (must fail) | 5 | 1 | fails: exit -6 |
| fixed | `peer-red` (must fail) | 5 | 1 | fails: "skip-shortcut resolver did not fail" |

The pre-fix aborts again carry `C8D1E14F…/92345EFB…` (n=5) and
`69A2DC37…/19088211…` (n=23). CTest registers the mode as
`test-consensus-simplex2-merkle-peer-notar-leader-path`.

At `528f0864e` every expectation in the first table was rerun with the same
counts and the same results; the pre-fix gate control ran 5 times. Artifacts
are in `merkle-repro-artifacts/prospective-notar-actor/528f0864e/`. Both
binaries were built from that commit, and a rebuild of the fixed binary is
byte-identical.

| File | SHA-256 |
| --- | --- |
| `fixed` | `63c9dd327f9ac543cdcc2d8baadea44b7fc60ee0f4d7897bec2656a400c637fc` |
| `prefix-e5b49ca45` | `fa51c14f84cae77e52ffd93f3ba56f181d8998ed71ff16cf2c5bb9d4f5807121` |
| `transcript-prefix-peer-red-n5.log` | `24b1f345255c6b5c322550a6bdddbbe199e5aacb2672f35cdb80ef168eed5002` |
| `transcript-prefix-peer-red-n23.log` | `a418fc4067c034e6870ac38b31a7ba707fe02edc847fa60fac5184f19a255062` |
| `transcript-fixed-peer-green-n5.log` | `d5afbf812dcddbd7e1a65655f8ca5b392c7f72868718be4bdd5927da1c37bafa` |
| `transcript-fixed-peer-green-n23.log` | `7397aea90ce3a2df456a4165838c27c453cf40be3bc8b6263211e1041223221e` |
| `repeat20-prefix-peer-red.log` | `dd168e4631b7d804577e28058dee6e91908f800a1ef33530b923588ab4bd7b53` |
| `repeat20-fixed-peer-green.log` | `8f5f084d3b7eac308157fc3a6e5b0133d5b2ed43031d8c38fa9e629d5be75045` |

Both unsafe orderings named by the investigation now fail the pre-fix resolver
through production actors. One is a NotarCert(P) still being saved locally.
The other is a NotarCert(P) that exists only on a peer, reached through the
real leader path. The fixed resolver passes both.

What this establishes: the fixed resolver removes a deterministic, reachable
failure. With production actors and legal certificates, a leader resolving its
new window's base while a parent's NotarCert is still being saved reproduces
the recorded N/N-1 abort byte for byte. What it does not establish: that the
two September failures took this path. The lost CandidateIds and stacks cannot
be recovered, so that attribution stays probable but unproved.


## Post-fix validation on `00ded9cf6`

The exact-ancestor production change is `bc379ec2c`; the tested branch head
`00ded9cf6` also contains the later source-guard and evidence corrections.
A full Release build completed with `TOS_WERROR_BUILD=OFF`. The separate
warning-as-error build stopped in unchanged Merkle scope at
`adnl/adnl-query.cpp:31,36`: an earlier ADNL logging change (`9c1353d4a`)
converts a floating-point expression to `bool` under Clang's
`-Wfloat-conversion`. This is a build-policy failure, not a Merkle runtime
result. The ordinary Release build log is retained at
`/home/tomi/tos-carrier/merkle-repro-artifacts/exact-ancestor-e238f31f3/release-full-build-no-werror-00ded.log`
(SHA-256 `baf43a4e6243cb26f9513e22898ea3614dbba0fbe4744baf6bc59158535e3a77`).

The Release `ctest -j48 --output-on-failure --timeout 600` run then passed all
206 enabled tests in 395.00 seconds, with eight tests disabled by CTest. This
includes the PQ e2e-100, state-resolver catch-up, empty-chain restart,
finality fault tests, exact-parent height control and exact-ancestor source
guard. `test-db` consumed 393.92 seconds and passed. The complete log is
`/home/tomi/tos-carrier/merkle-repro-artifacts/exact-ancestor-e238f31f3/release-suite-j48-00ded.log`
(SHA-256 `bf37928fa47f81a0b854a0ec254c46e37f360a679f7d0089418bfce194b42250`).
The source-guard inventory independently reports 35/35 registered guards.

Earlier on the exact production tree `e238f31f3`, 20 serial e2e-100 runs
passed. Their retained log is
`/home/tomi/tos-carrier/merkle-repro-artifacts/exact-ancestor-e238f31f3/e2e100-repeat20.log`
(SHA-256 `e3a8defcc4f0176ec7447f67c0d8f04aef55b0aa54f08bba69db246d18dcc622`).
These post-fix runs increase regression confidence but do not exercise the
controlled actor ordering described below. They neither prove the historical
root cause nor satisfy its deterministic old-RED/new-GREEN closure gate.

## Evidence versions

The component RED/GREEN logs below belong to the **pre-fix** `bb3cdc788`
investigation stage. The fix commit `bc379ec2c` removed the unsafe selector
and its test. At current branch head, the registered test is
`test-consensus-simplex2-merkle-exact-parent-height-control`; it checks the
Merkle N/N-1 symptom, and the separate source guard pins exact CandidateId
resolution. Neither exercises `StateResolverImpl` under a controlled
certificate arrival order. Thus the historical actor-level RED/GREEN gate
remained OPEN at that stage; it is now met by the actor-level section above. Do not cite
the older component log as post-fix runtime proof.

## Historical component reproduction (`bb3cdc788`)

At `bb3cdc788`, the branch added
`test-consensus-simplex2-merkle-skipped-exact-ancestor-repro`. It called the
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

To rerun the historical component test, use a separate worktree checked out
at `bb3cdc788`, then run:

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
it. That result now exists; see "Actor-level reproduction under controlled
certificate order" at the top of this note.
