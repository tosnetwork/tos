# Real lite-server material for tos-proof-verify

Raw lite API answers captured on 2026-10-05 from the local PQ development
network (4 validators, `global_id` 3) through its observer lite-servers, with
`tos-proof-verify` itself fetching them (read-only, one query at a time, at
most one query every 300–500 ms). They are the inputs of `test-proof-verify`,
the CLI CTests and the C09 tests, and can be re-verified offline with the
commands below. The network will be reset; these bytes cannot be fetched again.

## Anchor

`anchor.json` was computed by `tos-proof-verify anchor --zerostate` from the
zerostate file kept by a local node (`static/<file hash>`, 21632 bytes), not
from any lite-server answer:

| | |
|---|---|
| root hash | `1bdb1208416a1103bdb7ff6082f7effe047bac45313e27d4043ca04d16377b64` |
| file hash | `c9f382c9119eb7f3ab3bd6ae88fa1af59ab500bda3b5d794480e83ee24477686` |
| SHA-256 of the file | equal to the file hash (checked with `sha256sum`) |

Both equal the values in the network's own configuration.

## Runs against the real lite-server

Runs 1–3 used the verifier at `0b9137e48` (hashes then printed in upper case);
runs 4 and 5 used `5bf4aedb2`. Outputs are summarized; the material of runs 2
and 3 is committed here.

| Run | Command (abridged) | Result |
|---|---|---|
| 1 | `verify --request {"mode":"live","max_age_seconds":300,"config_params":[34]} --state S` (no prior state) | verified seqno 636888 (`6559ea5e…`), start = zerostate, 5 links, key blocks 1334, 1485, 5091, 5243; age 1 s; Config34 `626d395d…9144` |
| 2 | same, same `--state` | verified seqno 636922 (`2c8a5ed2…`), start = recorded key block 5243, 1 link; descent proof to the recorded head 636888 verified; age 2 s → `live/` |
| 3 | `verify` historical, target 636922, Config34, account `-1:333…3`, get-methods `active_election_id`, `participant_list` | verified from the zerostate, 5 links; account state `e022be33…82ca`, balance 84227057393288; `active_election_id` exit 0 → `1791201224`; `participant_list` exit 0 → `null`; global version 18 → `historical/` |
| 4 | live, same `--state` (third run) | verified seqno 641807 (`cb1513c3…`), start 5243, 1 link, descends from head 636922, age 2 s |
| 5 | historical Config34 at key blocks 1334 and 1485 | **refused**: lite-server error 602 "state already gc'd" — the archive no longer holds those states, so no result is produced |
| 6 | historical, anchor = zerostate of `c04-pq-genesis.boc` (another network) | **refused**: the lite-server does not know that block as a proof source |
| 7 | C09: `x02_config34_proof.verify_bundle` on material fetched from the second observer for 641807 | `X02_CONFIG34_SAME_BLOCK_PROOF_OK`, election 1790945281, 5 links, Config34 `626d395d…9144`; the same bundle under the run-6 anchor is refused: "proof chain does not start at the authenticated block" |

Output SHA-256 (bytes as printed): run 1 `e834659f…abc9`, run 2 `955514c0…0825`,
run 3 `0f26c0e0…1ecb`, run 4 `878dd967…69cd`, run 6 `9a6269c2…02dd`.

## Validator-set rotation on this chain

The key blocks are authenticated by the chain above; each forward link is
checked against the validator set in its source's proven ConfigParam 34.
`test-proof-verify --case real-historical-baseline` prints, from the link
proofs:

| Link source | ConfigParam 34 since | members (validator id : key id) SHA-256 |
|---|---|---|
| zerostate | 1790943181 | `40357a72…2137` |
| 1334 | 1790943181 | `40357a72…2137` |
| 1485 | 1790943781 | `cf7599ce…6b57` |
| 5091 | 1790943781 | `cf7599ce…6b57` |
| 5243 | 1790945281 | `cf7599ce…6b57` |

The membership/key set changes at key block 1485, and the chain verifies across
it: a legitimate rotation is followed. The test asserts this change is present.
An unauthenticated replacement cannot be produced from this network (it needs
signing keys), so it is exercised on the synthetic chain in the same test
(`synthetic-unauthenticated-replacement`, `synthetic-replacement-claims-current-set`).

## Note for review: ConfigParam 19 in forward-link proofs

The lite-server's forward proof link includes only the PQ context it touches
while building the link: ConfigParam 29 and the selected ConfigParam 30
(`validator/impl/liteserver.cpp:2993-2994`), besides the validator set. It does
not touch ConfigParam 19, unlike `Config::visit_validator_params`
(`crypto/block/mc-config.cpp:329`), which the validator's own proof paths use
(`validator/impl/check-proof.cpp:275`, `validator/impl/accept-block.cpp:250`,
`validator/downloaders/wait-block-data.cpp:101`).

The session a forward link is checked against binds the network through the
global id of the source key block's header or the zerostate's state header
(`crypto/block/check-proof.cpp:532`; set at `crypto/block/mc-config.cpp:92-94`
and `:105-107`). That header is part of the authenticated source, so a wrong
network gives a different session and the signatures fail
(`synthetic-wrong-network-session`). The validator path additionally requires
that global id to equal ConfigParam 19 (`validator/pq-finality-verification.h:13`);
the lite path does not. Adding that requirement to the lite path refused every
genuine chain from this network, because the proofs omit ConfigParam 19, so it
was not added; doing so needs the lite-server to include ConfigParam 19 first.

## Re-verifying offline

```
tos-proof-verify verify --anchor anchor.json --request historical-request.json --material historical
```
