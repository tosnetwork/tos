# Session birth selection: partial node-integration item 1

Status: a tested selector and a proposed native-adapter contract. This is **not**
a completed validator-manager integration. No production caller includes the
new header, no session consumes its result, and no P0 network is activated.
The frozen profile and its evidence history are unchanged.

## Why a birth resolver is needed

At the base revision, `ValidatorManagerImpl::update_shards` creates current
validator groups and also tentative groups for future validator sets. Its
future-shard lookahead uses the local clock. A committee anchored to the state
at local actor creation would therefore depend on scheduling, lookahead and
restart timing. Reconstructing an old session from the newest registry has the
same problem: key or policy updates can change the authentication snapshot.

The intended binding is the first authenticated masterchain state in the
**contiguous current native epoch** containing the independently selected tip.
An authenticated predecessor with another current epoch, or an authenticated
statement that this shard did not yet have a current session, establishes the
boundary. Genesis is the other permitted boundary. Missing retained history,
a failed lookup, a gap and a future session are not boundaries.

`validator/auth/session-birth.h` implements only that bounded selection. It
returns a block reference, the epoch and the number of observations consumed,
by value. It does not verify a proof, derive a committee, create a session,
install state, predict state transitions or grant signing authority.

## Native adapter obligations, still unimplemented

The adapter must establish one authenticated chain of masterchain states and
pin the tip independently of any certificate or peer-supplied request. Each
observation's block root, file hash, state root, parent and current-session
information must come from that same state and validated history. Merely
filling the input structures does not meet this obligation.

Populate the epoch with the existing native session ID and options hash, the
full current election cell hash, shard, catchain and the native session's
vertical/key-block coordinates. Use existing verified encoders and native
selection rules; introduce no new grammar or reinterpretation of historical
preimages. Coordinates unused by the native session-ID variant must be
normalized consistently, rather than copied from an unrelated latest block.

The mapping from native session lifetime to these epoch fields needs a native
integration test before this rule can be installed. In particular, an election
cell change without native group rotation must not silently produce two
committee snapshots for one live actor. The adapter must either establish the
existing rotation boundary or refuse ambiguous admission. This selector does
not settle that native-lifetime question by comparing synthetic inputs.

After selection, load the exact birth state's configuration and pass its
installed ConfigParam 46, native election and anchor to `NativeCommittee::derive`.
The actor must own the returned immutable committee and the existing canonical
P0 session context for its finite native lifetime. It must not consult a newer
registry to reinterpret an existing duty. The exact key-validity horizon and
restart persistence remain to be tested with the native lifetime.

Tentative P0 actor creation must be deferred until a current epoch and its birth
can be authenticated. Cache availability, wall-clock time and the first block
seen after restart must never substitute for birth. A persisted cache is only
an optimization: on restart it needs authentication against the same chain.
The default walk budget is 4096 observations, with an absolute cap of 65536.
Insufficient budget fails closed; native asynchronous loading, retention and
checkpoint acceleration are not implemented here.

## Registry and election disagreement

Admission of a new P0 session must fail as a whole if the native election and
registry disagree, a required identity or role key is missing, or any native
committee invariant fails. Do not shrink the roster or denominator, borrow
keys from another registry era, or run historical authentication as a fallback.
This increment does not exercise `NativeCommittee::derive` or establish that a
manager enforces those rules; it documents the required integration behavior.

An already admitted session keeps its owned birth snapshot until its existing
native termination boundary. That is retention of its original authority,
not fallback for a failed new admission. Registry changes alone must not rewrite
historical certificates or make a later lookup select replacement keys.

## Executable evidence and its limits

Run from the repository root:

```sh
cmake -S test/validator-auth-session-birth -B /tmp/p0-session-birth -G Ninja
cmake --build /tmp/p0-session-birth
test -x /tmp/p0-session-birth/test-p0-session-birth
/tmp/p0-session-birth/test-p0-session-birth
ctest --test-dir /tmp/p0-session-birth --output-on-failure
python3 test/validator-auth-session-birth/mutations.py --out /tmp/p0-birth-mutations
```

The standalone suite has 40 named cases. Its history fixtures are ordinary
in-memory records, not real blocks, proofs, node restarts or network split/merge
rehearsals. Assertions check the exact result or exact error. Setup success is
printed before the target assertion; setup failure never counts as a killed
mutation. There are 11 guard-disable variants and 6 semantic-fault variants.
Every mutant must compile to a fresh executable, fail its exact named assertion
and be followed by a passing 40-case restored baseline. Semantic faults are not
reported as additional guard removals.

The input-write semantic fault writes only into the test's deliberately mutable
fixture via the copied mutant header. The shipped selector is read-only. No
production encoder is replaced or copied into the patch; tests include the
existing `codec.h` for the shared result and hash types.

## What this increment leaves open

Manager and observer admission, exact native epoch mapping, authenticated history
loading, committee ownership in the consensus bridge, restart persistence,
version/capability transition behavior, native compiler/linker integration and
manager-level mutations all remain open. Subsequent chain items must not be
credited from these selector tests.

No C0 consensus call sites, contracts, chain apply, Rust parity or public serving
paths are changed. Local Unix-socket testing would not qualify remote HTTP/2
mutual TLS. No multi-node rehearsal has been performed by this increment.
No PQ suite is allocated. The four activation gates and five pending approvals
remain independent and unsatisfied by this local evidence.
