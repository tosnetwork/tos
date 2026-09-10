# Approved UNO topics and exact integration paths

Final scanner source: `efe6b048a642363a58ae58641e7609cb67681ed0`.
The change adds the approved topic patterns `test/uno-*`, `test/workchain-*`
and `crypto/smartcont/uno-genesis-*`, and exact integration paths
`crypto/block/create-state.cpp`, `scripts/setup-testnet.sh`,
`test/tostester/src/tostester/zerostate.py` and
`crypto/smartcont/gen-zerostate.fif`. No directory-wide pattern or content-word
exception was added.

The last exact path is the production genesis entry. The first baseline attempt
found eight remaining fence diagnostics there: its filename does not match
`uno-genesis-*`. That failure is retained under `first-baseline-stop` and did not
reach mutation execution. Applying the coordinator's general rule for necessary
core integration files accounts for that exact path; it is not a directory grant.

The prior two-path permission had already removed ten of the original 83
lines. This run records the remaining 73: 21 present verbatim at `a27ff2c77`,
52 new or rewritten since that baseline. Full per-line classification is in the
compressed JSON; textual lineage is not attribution to this permission change.

Final observed exits: before 1, baseline 0, isolated retired control 1,
restored 0. The sole control appends `halo2` in a comment to the newly permitted
`test/uno-local-profile.py`. It contains neither an Uno nor an EVM identifier;
only the independent retired rule can catch it. Its sole diagnostic is the
injected line. After restoration, both complete output streams equal baseline
byte-for-byte, including empty stderr. All append/restore hashes were recomputed
from the source commit independently of the driver.

`report.json.gz` and `reproduce.py.gz` preserve exact mutation bytes and the
complete recipe. Compressed raw stdout/stderr files preserve full diagnostics.
This is a static scanner control, not a native binary measurement. The isolated
worktree was restored; the real source tree was never mutated. The unrelated
validator local-branch draft remains uncommitted and is not accepted by this
scan evidence. No Tol fix or seam acceptance is included.
