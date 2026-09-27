# X02 live preflight failure and shard normalization (2026-09-25)

The committed `6ef892f99a0484f9fa7d96dfcb12169203882d57` Stage A experiment
ran four separate validator processes. Its readiness manifest SHA-256 is
`11493b26703e36caa09c8dc250d794a39f65b0cdf209aad4fe01e32a66f98475`.
From those live PIDs and FD/socket identities, the policy-freeze CLI exited 0
and exclusively created policy SHA-256
`b79932b75ee93742dcd3abec77ae58c89e1271d3d0be2203ea8558411cf3c824`;
the independent supervisor freeze obtained the same bytes. Four distinct
validator PIDs, stderr pipes, DB inodes and the ten directed rules are retained
in `test/integration/.x02-stage-a-6ef892f99-20260925/20260925T205504Z/`.

The first read-only baseline capture exited 1. Raw snapshot SHA-256
`223eab97065cb7b0de02a5e2f949af4a8378eeb517643be9b9d1af6a84d9d0af`
contains four HTTP 200 `getMasterchainInfo` responses; its exact error is
`node1 getMasterchainInfo has wrong shard`. The production response represents
the masterchain shard as signed decimal `-9223372036854775808`, whereas the
fixed `6ef` checker required literal hex `8000000000000000`. A signed-shard
`getBlockHeader` response is retained at SHA-256
`75018476f584707b8a29b090e324a164436015f82e873bce968089cf77d1e8a3`.
The same RPC also returned the canonical masterchain ID for a deliberately
wrong request shard, so an HTTP success alone cannot validate request scope.
No `tc` fault was installed; the supervisor observed empty filters for all
400 polls. The short Stage A experiment itself ended exit 1 with four
outstanding allocations, unrelated to the read-only baseline failure;
console SHA-256 `efa7b3cd692dea7273bf61fa65872ff30eab2cd077943fcafd6ec2040c78602b`,
report SHA-256 `5fdd2c0cc57ad4b6d70882356cc7a8b9b8bdc8b491537bf454e58e7d4ef47b16`.

Commit `87a0cc82fead5232c45de5b96d8e245110b92ff7` fixes only this
collector encoding gap. It normalizes exactly the two equivalent masterchain
shard representations in response IDs and requires the canonical signed
decimal string in every header request; adjacent wrong shard values and the
old request form are negative tests. A self-contained test uses the retained
production `getMasterchainInfo` BlockIdExt fields. Committed-tree X02 tests
passed 58/58, exit 0; raw output SHA-256
`ced934f148f33d75034a162d9a867c949684cbedfa26a5a3441b2b6ce9fa935d`.
Recorder source SHA-256 `8f81e1944c1577466b52c3ce9222ba9f91f272195adccd653b05ae9beac3f845`.

No `87a` validator network or `tc` run is claimed. A new exact-tree baseline,
bidirectional rule hit/drop receipts, per-height native/RPC joins and timed
fault/recovery check are still required. X02 remains OPEN; partial packet
loss is separate.
