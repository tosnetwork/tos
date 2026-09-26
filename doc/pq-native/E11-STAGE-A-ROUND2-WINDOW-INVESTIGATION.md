# E11 second-round window refusal — 2026-09-25

Status: E11 OPEN. The fixed `2d7e4cd7d5f62ba63201dc446df4703209ed79ad`
three-round Stage A run exited 1; this is a fixture scheduling defect, not a
successful rehearsal. Console:
`test/integration/.e11-stage-a-2d7e4cd7d-20260925-console.typescript`
(SHA-256 `1d442e50f5247198b13c3bd43cb878c1c824426d116a96ceaf77daa127ac4873`).
Report:
`test/integration/.e11-stage-a-2d7e4cd7d-20260925/20260925T091107Z/report.json`
(SHA-256 `91909c78aa9332bb38126697038fcf434c73007d7dac964214fc43a30135f6c1`).
The first PQ set activated in live Config34 with four controller/ADNL pairs.
The second election opened at `elect_at=1790328412`; its profile has
`elect_end_before=60`, hence `elect_close=1790328352` (09:25:52 UTC).
Second-round validators 1–3 received `STAKE_ACCEPTED`. Validator 4's
capital transfer landed at 09:26:00, and its stake order at 09:26:13;
the Elector replied `new_stake_error` reason 0.

The retained node DB was reflink-copied to
`test/integration/.e11-stage-a-2d7e4cd7d-20260925-forensic/node1-copy`.
A loopback `--json-rpc-readonly` process on only that disposable copy
returned the raw Elector page in
`test/integration/.e11-stage-a-2d7e4cd7d-20260925-forensic/elector-transactions.raw.json`
(SHA-256 `a6127e7c0a99596319d92f86fcb0f7b6a154d60cd10a91c3d00251a517ce693e`).
Elector LT 343000007 has `utime=1790328366`, fourteen seconds past
`elect_close`; its inbound source decodes to validator 4's controller
`-1:bc2510c8c06704637c46c2313fa784a78b2c2f7b48c15cae0cb80677d66531f1`.
The production Elector at `crypto/smartcont/elector-code.fc:310` returns
reason 0 when `now() >= elect_close`, with `elect_close` set at line 1181.
The message reached the Elector; it was not an authorization or signature
failure. No second-round activation or third-round completion is claimed.

The followup route had funded each pool serially *after* the short election
opened, then sent that pool's order. It consumed the window before the fourth
order. The repair places the same two-round faucet budget into four pools
before the first election opens, using one wallet and one pool funding
transfer per validator. The later windows contain stake orders only. In the
rollover window, four stake orders precede first-round recovery so recovery
does not postpone a required order. The stake amount, admission checks,
`STAKE_ACCEPTED`, Config34 pair checks and recovery assertions are unchanged.

Local controls: the one-round-capital mutation makes both the source guard
(SHA-256 `1d2590b381d0b883573bb63398981f03fa0541749a6ebb7321372beef2c7a72b`)
and fiscal unit test
(SHA-256 `8e4eed94811bb48ecbbf632694596b47df92fb4db9cdbebe7c793f1b1f41e4c2`)
red. Moving prefunding after the first election makes the guard red
(SHA-256 `5ac9aced4978d0597a6acd4b9a21dd4de7abb0d7f923fab644a9bd7b48dcc28f`).
The mutations were restored; the guard and four focused tests pass. The
actual old-red/new-green live comparison is incomplete until the repaired
committed tree finishes all three rounds.
