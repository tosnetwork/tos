# Recorded proof material for proven reads

Real lite-server answers, saved by `tos-proof-verify --save-material` from the
local development network on 2026-10-05, read-only and one query at a time
(`--min-interval-ms 300`). They carry no authority: `proven_pool_snapshot.rs`
re-verifies them from `anchor.json` with the real verifier, and tampers with
them to play a dishonest endpoint.

| File | What it is |
|---|---|
| `anchor.json` | `tos-proof-verify anchor --zerostate` of that network's masterchain zerostate file (file hash `c9f382c9…77686`) |
| `chain-anchor-to-638197.tl` | Forward proof chain from the zerostate to masterchain block 638197, 5 links through key blocks 1334, 1485, 5091, …, 5243 |
| `elector-account-638197.tl` | Account proof of `-1:3333…3333` (elector) at 638197 |
| `pool-account-638197.tl` | Account proof of `0:599c…3f6a`, a basechain pool account running older pool code, with its shard proof |
| `exec-config-638197.tl` | Execution configuration proof at 638197 |
| `live-638197/` | The rest of a live read that authenticated 638197 from the anchor (verifier clock 1791201443) |
| `live-state-at-638197.json` | The verifier's live record after that read |
| `live-638326/` | A following live read from that record to 638326, with its descent proof (verifier clock 1791201494) |
| `fixed_clock.c` | Pins `time()` so a live recording re-verifies at the moment it was made |
| `fake_verifier.py` | A stand-in verifier that authenticates nothing, for the consumer-side binding checks |

Recording commands (request files as in the test's `elector_calls()`):

```
tos-proof-verify anchor --zerostate <zerostate file> > anchor.json
tos-proof-verify verify --anchor anchor.json --request <historical request, target 638197> \
  --liteserver <lite client config> --save-material <dir> --min-interval-ms 300
tos-proof-verify verify --anchor anchor.json --request <live request, max age 600> \
  --liteserver <lite client config> --state <state> --save-material <dir> --min-interval-ms 300
```

SHA-256:

```
3b3653852a5810a1882c58762be865daa985527a451002ba84913ca9c4c7fb5a  anchor.json
fb304440002a27e22bf3a461a0969da2c014c294987bf1132e77deb7a6d75bc6  chain-anchor-to-638197.tl
ecddb91e6258a686ad30ec4f65b665c28b48ba53278ed8340bd1f957684fe4b3  elector-account-638197.tl
94b7960554d6528488176f59bcce89758e7303a00fcd7ee350d6d28280015763  exec-config-638197.tl
6d95d95331f254dc77999f467f4bc359d4338da3a76d4dbc7cfd1014007a3531  pool-account-638197.tl
1f59aee170b0834f450169f2f229a83caeec17c3775910567bfafb2c3ab75248  live-638197/exec-config.tl
f7a721577e10f398395cfe8cb113527323228abd21e6972d4f495a0aec52e58d  live-638197/masterchain-info.tl
d7827643a8b46e2128cb02cad80d624786f0ac900575bf858616bc0802e1442e  live-638326/account.tl
3dd69bdb5d75ddc8aab56f69ca1f5cba7ee9cc198a9aee2bab963dc09796eb1b  live-638326/chain-0000.tl
50a61828c08df7f890bbdb73ccf061b6169834540591abc5e794885b28341669  live-638326/descent-0000.tl
7fd2b0de2f113318a99246d31a3ff3c5ccea2929ff4cf026e9fd7f97fce6d946  live-638326/exec-config.tl
e18af8bf00d60a54ea69989ab264bfcb0f08cb608d4d4f7b0ca110aa00dcfcfa  live-638326/masterchain-info.tl
879f96e9cd8f7a215d22f80a2c85ef0b23563c557106ef2e5264b81139be98ee  live-state-at-638197.json
```

That network has no pool running the current pool code, so no recording here
yields a successful pool snapshot; the elector stands in for successful proven
reads, and the pool account shows that a getter failing locally yields none.
