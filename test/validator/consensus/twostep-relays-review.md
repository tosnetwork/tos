> **Superseded by owner ruling R7.** This is historical evidence for the withdrawn refusal policy. See [twostep-relays-r7-validation-20260928.md](twostep-relays-r7-validation-20260928.md) for current behavior and new tests.

# Current-validator two-step relays: implementation review

## Identity and scope

- Base: `2483ea590b736f018a0fac8daf190510e0cef506` (`main`).
- Tested implementation: `e4bf266bf6b1b7b9a7bf80c0e727afb94c9bd531`.
- The subsequent review-evidence commit changes only this report and its JSON
  record. The final PR head identifies that documentation commit.
- Authority: memo `78b40fd436a34bfbe18e5aafbb649c10890e13df`,
  `upstream-sync/TWOSTEP-RELAY-WORK-ORDER-20260928.md`, SHA-256
  `fec835d7dc5d94a3ba52ece5a04c744d5c7c8f283291fe7074e39f58e22ec5f3`.
- The two changes identified by `b997745e` and `ef1cddd2` are implemented
  together, with the permanent-peer intersection and synchronous startup
  requirements specified in that work order.
- Build: Ninja, Release, Clang 21.1.8, `USE_QUIC=ON`.

[The machine-readable record](twostep-relays-validation.json) includes all
selected CTest names, exact build/test/mutation commands, exit statuses,
assertion excerpts, resource admissions and hashes of retained raw evidence.
Paths in the record are relative to the repository; `python3` denotes the
Python interpreter used by the existing CTest scripts.

## Production behavior

Generic overlays preserve the empty-option convention: use all permanent peers
except the source. A nonempty option selects the intersection of listed and
permanent peers. FEC parameters and dense symbol indices come from the actual
filtered destinations. The 513-byte and five-relay thresholds remain unchanged.

Consensus retains the previous/current/next membership union `M`. It obtains
transport ADNL identities exclusively from total-set offset zero, producing
nonempty `C`. Both factories synchronously reject empty snapshots and `C` not
contained in `M` before actor/database/runtime construction. Both parameter
initializers, the real Bus, private overlay and protocol-1 block-sync overlay
carry `C`; construction assertions catch omitted wiring.

The manager reevaluates `allow_validate_ && current_preflight.is_ok()` for
active, future and observer groups on every update. Missing/empty current data
and `new_catchain_ids=false` refuse groups synchronously. Refusal does not return
before retirement, and it does not introduce a sticky disable flag. Tentative
sessions join the existing durable retirement queue. Observer creation failures
are checked before start/registration. A valid later configuration recovers.

**Supported-configuration limitation:** `new_catchain_ids=true` is required to
run validator/observer consensus groups under this snapshot-at-creation design.
With it false, the node remains a full node but does not run these groups. No
configuration encoding, block validity rule or session-ID formula changes.

All receive, forwarding, signature and capacity/GC paths in two-step are
unchanged. TL, QUIC, DHT, collator execution, configuration contracts, PQ
algorithms and candidate resolver behavior are unchanged. The new option grants
no origin authorization. Membership and committee-authorized originating keys
retain their existing meanings.

## Coverage of the work order

| Requirements | Real path exercised | Result |
|---|---|---|
| A1 | Signed 8,000-byte broadcast; 7 current online identities, online observers, absent listed identity; real sender/receiver/decoder | Exactly 6 FEC first hops, dense indices; every online remote member receives source/payload/nonempty extra once |
| A2 | Same large payload, source plus 3 selected remotes | Exactly 3 simple first hops; all 6 remotes receive |
| A3 | 21 permanent identities, only 7 online, fixed 8,000-byte payload | Default: 20 first hops, `K=9`, zero remote deliveries; current-only: 6 first hops, `K=2`, all 6 remotes deliver; source local delivery retained in both |
| A4 | Empty generic option, 7 online identities | 6 FEC first hops, unchanged delivery |
| A5 | 512/513 bytes; 0/1/2/4/5 remote relays; source-only and absent-only options | Existing simple/FEC boundaries; zero relays sends nothing remotely, retains local delivery; one relay serves observers |
| A6 | Current-only source/default receivers and default source/current-only receivers | Both receive/forward successfully; reverse direction retains 8 broad first hops |
| A7 | Actual captured two-step messages through real receive coroutines | Valid replay accepted; unauthorized origin, altered signature/signed extra and FEC seqno at persistent-count boundary refused |
| A8 | Known non-permanent peer in the real peer table | Real predicate refuses it, including empty default; listed permanent peer accepted; absent identity refused |
| B1 | Recording offset callable, disjoint PQ identity fixtures | Calls exactly `[0]`; selects ADNL, not validator/key identity; sorted/unique; null/empty current; absent previous/next harmless |
| B2 | Real manager preflight and both real factory boundaries | Missing/empty current, false prerequisite and out-of-membership snapshots refused; no started entries/empty sends; valid updates recover |
| C1 | Real manager-created active and observer groups → both real bridges → Bus → actual overlays | `M` has 11 members, `C` has 7, authorized committee has 2; actual construction/options observed, unchanged authority |
| C2 | Real `new_masterchain_block`/`update_shards`, real session derivation, tentative and observer lifecycle | Total-set/key-block switch recreates groups with incoming `C`; same-total-set catchain transition reuses valid tentative session; false prerequisite also retires existing/future groups |
| C3 | Manager-created groups and real signed PQ candidate bus events, receive/parse path | Protocol 2: 6 selected first hops, 6 observer receptions, no block-sync; protocol 1: actual block-sync options and candidate path, 6 selected first hops and 6 observer receptions |

The transport executable has eight native test cases, the selector executable
two, and the production wiring executable nine: **19 focused native cases**
registered as three CTests. Assertions inspect actual callbacks rather than a
deduplicating delivery helper. The transport pump delivers events into the real
OverlayManager, records first hops before offline drops and uses fixed fixtures.
`K` is checked from the transmitted part size and payload, not assumed equal to
an arbitrary symbol count.

### Lifecycle and refusal excerpts from the clean run

```text
first hops=20 K=9 online=7
first hops=6 K=2 online=7
rotation old tentative=cqhzOMvzzTFz2ufFuItsh6iyW7uvSsXkf4so2hbkWD4=
         new active=miMoUTCTYFNyE5GIXyNxDyBxy8f0IrP96yrBPig0UaQ=
candidate first hops=1 observers=2  # incoming-total-set switch
candidate first hops=6 observers=6  # protocol 2
candidate first hops=6 observers=6  # protocol 1
```

Both real factories log `current snapshot is empty` and `current snapshot
contains a non-member` for their respective negative inputs. The manager logs
`current total validator set is missing or empty` and
`snapshot-at-creation requires new_catchain_ids=true`. Passing recovery tests
then observe nonempty started entries after a valid update. The legacy-ID test
also demonstrates that changing only the last-key-block sequence number does
not differentiate legacy identities, and observes the actual manager refusing
existing/tentative/observer groups.

### Test boundaries and observation seams

The lifecycle fixture supplies controlled typed masterchain snapshots, invokes
the production masterchain-update and group lifecycle, uses a real RootDb and
real bridges, and holds unrelated state/block IO. It does not collate a full
blockchain transition. The Bus observer only captures an already populated,
started real Bus; it neither creates a substitute Bus nor alters its options.
A friend probe permits controlled manager setup/inspection. A separate overlay
friend tests known non-permanent peer selection and actual receive coroutines.

Consensus tests use real PQ custody/signatures and real candidate serialization,
OverlayManager receive/forward/decode and Candidate deserialization. Simulated
transport is installed as the typed sender, so these are actor-network tests,
not an actual QUIC socket/deployed-validator test. Existing receive handlers and
origin authorization remain in the delegated path. Test keys are disposable
fixtures, not operator identities.

## Mutation evidence

Every mutation built successfully, executed, exited **1** at its intended
assertion, and was restored byte-for-byte. No compilation failure or timeout is
counted as a killed mutation. Full commands and excerpts are in the JSON record.

| Mutation | Tests executed / intended red |
|---|---|
| Sender restored to persistent-only | A1 `8 != 6`; A2 `6 != 3`; A3 `20 != 6` first-hop counts |
| Selector offset -1 | B1 calls not `[0]` |
| Selector offset +1 | B1 calls not `[0]` |
| Selector adds previous/next union | B1 calls/identities not current-only |
| Remove permanent-peer conjunct | A8 non-permanent predicate assertion |
| Drop active factory initializer | Checked bridge nonempty invariant |
| Drop observer factory initializer | Checked observer bridge nonempty invariant |
| Drop params → Bus assignment | Checked private-overlay Bus nonempty invariant |
| Manager wires `M` as `C` | C1 actual Bus snapshot differs from current set |
| Bridge wires `M` as `C` | C1 actual Bus snapshot differs from current set |
| Drop private-overlay option | Protocol-2 actual first-hop set differs |
| Drop block-sync option | Protocol-1 actual overlay relay option differs |
| Bypass epoch prerequisite | Initial refusal and existing/tentative legacy lifecycle tests both detect permitted entries |
| Remove observer empty-actor check | Actual manager attempts to start an empty actor |

Total: **14 mutations, 17 executions, all killed/restored**. Their builds use
`cmake --build build --target <affected-target> -j8`; tests use the corresponding
real executable's `--filter <case>`. The JSON records each concrete command.

## Clean regression result and reproduction

After restoration, the clean build of all 45 selected targets exited zero.
The affected test command ran **124/124 CTests, zero failed/skipped**, in
77.03 seconds. It covers Overlay/Plumtree, selector/config/session identity,
transport authorization, cleanup, consensus, PQ signatures/carriers/proofs,
C04/N5 real-state fixtures, Merkle prospective notarization and C05 transient
resolution. The four previously existing Bus fixtures explicitly supply their
single-epoch current identities; no production fallback was introduced.

```sh
# From the repository root, in the configured Clang/Release/QUIC build.
python3 - <<'PY'
import json, re, subprocess
from pathlib import Path
record = json.loads(Path('test/validator/consensus/twostep-relays-validation.json').read_text())
subprocess.run(record['build']['command'], check=True)
names = record['regressions']['selected_names']
assert len(names) == 124
subprocess.run(['ctest', '--test-dir', 'build', '--output-on-failure', '-j4',
                '-R', '^(' + '|'.join(re.escape(name) for name in names) + ')$'], check=True)
PY
git diff --check
```

Compilation used eight jobs, with measured admission about 5.12 used CPU cores
and 12.21 GiB used memory, plus estimates of 8 cores/16 GiB. Tests used four
parallel processes, with measured admission about 3.11 used cores/12.45 GiB,
plus estimates of 16 cores/16 GiB, on a 192-core/125.47-GiB host. Both remain
below two-thirds of whole-host CPU and memory. No local services were stopped,
reconfigured or deployed.

Eight already-disabled classical consensus CTests remain disabled; their PQ
counterparts were executed. The `n6-live-finality-overlay` full-chain node
launcher is outside this bounded actor-network regression run. The production
wiring test requires `USE_QUIC=ON`; it does not claim a QUIC-disabled run.

No throughput, production latency, stake-weight availability bound, universal
RaptorQ rank guarantee or candidate-resolver recovery improvement is claimed.
A deployment/real-socket network test and relevant PR CI remain separate from
this completed local implementation/test package. This change does not deploy
nodes or merge itself into main.
