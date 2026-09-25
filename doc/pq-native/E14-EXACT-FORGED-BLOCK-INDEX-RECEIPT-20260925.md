# E14 exact forged-transaction index receipt (2026-09-25)

Status: **local evidence complete; independent review and final unit signoff pending**. This is a one-validator wc0 route, not a claim about arbitrary skipped blocks, reorg recovery, or release scale.

The previous E14 control saw a forged transaction in a wc0 shard block and a later same-shard canary in the token index. That did not exclude the writer silently skipping only the forged block. `getAccountEvent` reads the production wallet-index DB by `(account, LT)` and checks the transaction cell hash; it has no chain fallback. The updated route requires HTTP 200 for the forged target's exact `event_id=<LT>:<transaction-cell-hash>`, matches LT/hash, and hashes the returned raw transaction BOC. The query account is the victim from the raw target transaction. The canary checkpoint is retained *before* this gate so a red run distinguishes a missing target receipt from a stalled later index.

## Committed source and offline control

- `adbc98970` adds the exact receipt gate and tests; `b12f00718` accepts the production endpoint's uppercase hex rendering without relaxing bytes; `88d5dd736` integrates PG's later-canary/absent-forged-event control; `30f2d36e6` records the canary before the gate.
- `python3 -m unittest test.pq-native.test_e14_wc0_index_evidence`: exit 0, 20 tests. The absent-event control has a seq48 forged target and seq63 indexed canary, but is an offline simulation, not the production writer mutation.
- PG's detached control patch: `/datax/tos-pg-e14-skip48-evidence/e14-skip48-reverse-control.patch`, SHA-256 `b48d465a027e0c353cb1ae57ffa2db5c9d144189a294b52d74ebc53d46f3abeb`.

## Exact-tree live green

Command from repository root: `script -q -e -f -c 'env PYTHONPATH=test/tostester/src uv run python -u scripts/wc0-token-index-e2e.py' test/integration/.e14-wc0-token-index-88d5dd736-20260925-console.typescript`. Exit 0, `ALL PASS`; source HEAD `88d5dd736`. Full raw data is in `test/integration/.e14-wc0-token-index-88d5dd736-20260925-network/`.

The exact receipt is victim `0:22…22`, wc0 shard seq45, LT `46000003`, transaction hash `F4559B41642682E1F484BF1832118ECE0A3AE9E772385E997E8E1EBD7B506083`; the returned raw BOC hashes to those bytes. Hex case is normalized only for the API rendering.

| artifact | SHA-256 |
| --- | --- |
| console | `67e656dca19dde61b342173f0f8d8d3cd31ea467dd78170c39730c1659c15e36` |
| RPC transcript | `a9682b639b12f4ca98229424b215aec60d600ccaa16c517c8374840a8962c6dc` |
| chain evidence | `cc097f56769af5e66c0b6e36b8dee8e0ceb7865a6c28396c414cb65bc631a8f2` |
| provenance | `fd75804bf97f63d0f7b2235e63d7971b9f4af63bc137deb7456c025096c958a9` |

An earlier `adbc98970` run exited 1 only because the returned uppercase event ID was compared to lowercase text; the HTTP 200 event itself was present. Its untouched console is `test/integration/.e14-wc0-token-index-adbc98970-20260925-console.typescript` (SHA-256 `9c39c29a0473250443c9106d9b6243e635ee8842af6fbb87b4b28021c15fdb90`).

## Production writer mutation: whole target block skipped

The single mutant makes `index_block_walk` set `write_error` when the fixed victim account `0:22…22` is in an account block. The production batch is then aborted for *that entire full BlockIdExt*, not merely the victim event; the log prints the selected full ID. Selecting by this account instead of hard-coding seq48 matters because equivalent serial runs have put the forged transaction in seq45, seq48 and seq49. The source patch is `test/integration/.e14-exact-block-skip-mutant-binaries/skip-block-mutant.patch` (SHA-256 `c94f18729c1488076c3cb1a1c705bde79d7ce778ddb440dac12d11f69e335a79`, `git apply --check` exit 0 against clean `30f2d36e6`). Mutant writer source SHA-256 `2b4ec2ef99f114f35bb121277c43d45762461075946d3a271dc76ab50a159929`; mutant binary SHA-256 `64762bbcfb99a948402020b1c4c4552dff837e2370164a582df6d76f255d9bee`. Build command `cmake --build build --target validator-engine -j8`, exit 0; retained build log `test/integration/.e14-exact-block-skip-mutant-build.typescript` SHA-256 `4b81f7cd604cc825625c4bc1b30735cf903f47208fa4a63b978458b8c1e49762` and binary copy in the mutant-binaries directory.

The mutant was run with the same `script … env PYTHONPATH=… uv run python …` command, writing `test/integration/.e14-exact-block-skip-mutant-20260925-console.typescript`. Exit **1**, specifically at the exact `getAccountEvent` request: HTTP 500, JSON-RPC code `-32004`, `Account event not found`. The run's own raw forged target has `(wc0, shard 8000000000000000, seq48)` with root hash `98DF469295CEAE889C40F39AA80E94889728C17C12B25020EADB352BC39CA644` and file hash `5C467755DFDEF3111C91884CAE2E5F365A61DFE8C0D80B2385C43FC7F7C9CC42`. `node1/log` prints `E14_MUTANT_SKIPPED_FULL_BLOCK` with **that same full ID**. A later same-shard seq62 canary mint was indexed with wallet LT `63000006`, while the victim list stayed empty. Thus the previous canary/empty-list assertions would pass, but the exact event gate turns red on the intended skip.

| mutant artifact | SHA-256 |
| --- | --- |
| console | `03d54690314a60441e15ec077e3066fe21978fcd8b62ef7f7632eed11b9495b7` |
| RPC transcript | `c246dc5069aa74f2f0c9356ccbb29ffb5620168855aeccc21e9efd896f6180e9` |
| chain evidence | `9e6b18552dd4d0a0d29b76add95fa39f8754b42ed90731b76071c80299269aec` |
| node1/log | `470ef74a88b2894d281266877fcb92c1d3f9c372281ffa448e9658c1121d6aa6` |
| provenance | `0af477196a8a16ec955ab1d5d342dff4a245c1da98fd8c48e6761f342d2b358c` |

The mutant run's provenance records the *clean committed Python source* and the **mutant** native binary SHA; it must not be read as a clean native build of `30f2d36e6`.

## Restored clean binary and rerun

The writer source was restored with no tracked diff, SHA-256 `24d2868f8636af59ccb0220a238c8f1be451be5096b689644ffd621d358768be`. Rebuilding the same target exited 0; log `test/integration/.e14-exact-block-skip-clean-restore-build.typescript` SHA-256 `eaf2882178b6797e9a268974d572d8512ae0ecaff5d35577f2cbdb2e1b7d621c`. The retained clean binary is `test/integration/.e14-exact-block-skip-clean-restore-binaries/validator-engine`, SHA-256 `186fef777bba20168fb48efb43fd78d2945cb16a565a10630e165dc1bbabaa3a`, distinct from the mutant. An unmodified `30f2d36e6` run with this restored binary exited **0**, `ALL PASS`, including an exact forged event from wc0 shard seq49, LT `50000003`.

| restored-run artifact | SHA-256 |
| --- | --- |
| console | `c4bbdd652dd6b6806c78fb0848b3cddae5dd21d27d7122bbe42baab3c945290a` |
| RPC transcript | `f20531b34f5682690528b5ece031368946ca53dacebddb8471b7cae02ff6d834` |
| chain evidence | `7ebac6e8ccacdda5f8fd3f65698c944ae198611d3820d5a7e74ae254cbae2be4` |
| provenance | `e2ef739410911324b8050119244ce4e5709f6d2ece5c97ed53888ba735fdfd83` |

No E14 network process remains. The raw network directories are retained under `test/integration/`; no large runtime artifact is added to Git. E14 still awaits independent raw/provenance review and owner signoff. Two separate indexer risks (`e03-shard-ancestry-progress`, `e03-reorg-nominator-ledger`) remain OPEN and are not covered by this receipt.
