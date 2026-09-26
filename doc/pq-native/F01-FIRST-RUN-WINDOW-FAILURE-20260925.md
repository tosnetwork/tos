# F01 first fixed-tree Stage A run: duplicate control crossed the election window

Status: **FAIL / F01 OPEN**. This records the natural result from committed
`51b7631d64c969e0ffe671b9658fb6b89619f767`; it is not evidence of three
ConfigParam 34 transitions or four-node finalized-ID agreement.

Command (exit 1):

```text
script -q -e -f -c 'PYTHONPATH=test/tostester/src uv run python -u scripts/validator-election-stage-a.py --mode launch-gate --stage a --build-dir build --output-root test/integration/.f01-stage-a-51b7631d6-20260925' test/integration/.f01-stage-a-51b7631d6-20260925-console.typescript
```

The console SHA-256 is
`2aeea73a2980d658ecd3e9d113baf436bd1069e77d381540be39dde851783742`;
the report at
`test/integration/.f01-stage-a-51b7631d6-20260925/20260925T154917Z/report.json`
has SHA-256
`f26506a42b0d7adec751c53ba0251fdddca03d1b3d91cdc5177385dde8d9643b`,
`status=fail`, and both source-commit fields equal the fixed commit. The
initial four raw `/proc` stat/exe/inode/hash captures are in
`test/integration/.f01-stage-a-51b7631d6-20260925-process-initial.typescript`
(SHA-256 `f23531e0cc740bd16461acbd4dd168de7982935401facfe16970747d77f4db92`).
All local validator/DHT processes exited after the failure. The full network,
snapshot, and original logs remain in the run directory.

Four first-round pool stakes received `STAKE_ACCEPTED`; the fourth was recorded
at 15:58:20 UTC. The original
`artifacts/pq-first-participants.txt` reports `elect_at=1790351960` and
`elect_close=1790351900` (15:58:20 UTC). The duplicate-key wallet message was
included at 15:58:40 UTC and its wallet reply was opcode `0xee6f454c`, reason
`0`, rather than the required duplicate-key reason `4`. In fixed production
`elector-code.fc`, `finished` and `now() >= elect_close` both return reason `0`
before the key-holder branch can return reason `4`. This is strong timing
evidence for a closed-window fixture probe, but the host inclusion time does
not substitute for the Elector's transaction `utime`. This run did **not**
retain the exact Elector input transaction BOC/utime, so it neither identifies
which reason-0 branch executed nor proves that a timely duplicate would have
returned reason `4`.

The duplicate test was after all four positive stakes and a node restart in
the failing tree. The follow-up moves it immediately after the first accepted
stake, retains the pre-send raw Elector window and chain time, then requires an
exact wallet-to-Elector input transaction with BOC/LT/hash/utime before it can
assert the specific reason `4` and unchanged participation. A late Elector
input is a distinct fixture-window failure. This follow-up needs a new exact
committed-tree run; the 51b run cannot be reused for F01 acceptance.

The follow-up source guard is locally green. Two one-line reverse controls
were run and restored before commit: moving the probe from first accepted
candidate to second made the guard exit 1 with `not bound to the first accepted
stake`; changing `elector_input.utime >= elect_close` to `>` made it exit 1
with `no longer pins an open-window exact Elector input`. Their exact patches
are `f01-first-stake-gate-mutant.patch` (SHA-256
`2440ec112bef7997a20db57329c534c5dab59012f9de6d2173e927d2c3479442`)
and `f01-elector-close-boundary-mutant.patch` (SHA-256
`eb72c51f20f72da23d0dd441f711427c1c77a6f204b2efa23df020c55046fee7`).
Raw source-guard logs under `test/integration/` have SHA-256, respectively,
`93ccd878005962ae22d99293ca91b0249fc41ac4e9a6a76e5cf7db956e78fbfc`,
`2d36c1e798ff428987d4050cc4b77e706e84b0943ac89238103e1f3bfbcaa309`,
and restored green
`6bd841e621e03167aa2a34817907c02af37db4a3fa93594c9475ce8b980453e7`.
The reverse controls prove the source guard's intended binding, not the
Elector runtime outcome; that remains for the next exact-tree run.
