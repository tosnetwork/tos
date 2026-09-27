# E14 first exact-tree run: getter RPC instrument failure

The serial single-validator E14 run from committed source `386a4ce1b` used
`PYTHONPATH=test/tostester/src uv run python -u scripts/wc0-token-index-e2e.py`
under `script -q -e -f -c` and exited **1**. The genuine jetton master deployed
active and the mint's wallet-to-master edge was recorded, but the positive
index check printed FAIL. The later canary check aborted with
`post-forgery canary mint was not indexed`; therefore the negative case never
reached a valid refusal verdict. E14 remains OPEN.

This is a test-instrument defect, not evidence of a broken token index. In
the retained RPC transcript, 178 `getAccountJettons` reads returned a
nonempty jetton list and 89 `getAddressState` reads returned `active` for the
owner's indexed wallet. The row's master address equals the deployed master.
There are **zero** `runGetMethodStd` RPC rows. The new verifier called
`rpc_call("runGetMethodStd", ..., method="get_wallet_data")`, while `rpc_call`
named its first argument `method`; Python raised `TypeError: ... multiple
values for argument 'method'` before any HTTP request. The generic `poll`
swallowed that exception until its deadline, making an indexed row look like
an empty result. No wallet getter or master reverse-resolution was exercised
in this failed run.

The follow-up names the first RPC argument `rpc_method`, leaving the nested
`params.method` for the getter. A focused test invokes the real wrapper with
a captured HTTP request and asserts both distinct fields. Restoring the
original signature made that test exit 1 on the exact `TypeError`; the fixed
version and all 18 offline E14 tests exit 0. This proves the instrument fix,
not the E14 chain route. A new committed-tree run is required.

| Retained artifact | SHA-256 |
| --- | --- |
| `test/integration/.e14-wc0-token-index-386a4ce1b-20260925-console.typescript` | `17cd188c63994193e9416f53bc72e024fe79a2f266806e98538065d6e500a9fb` |
| `-network/provenance.json` | `24ef032e0c518f2677e8d80fcd95dd36bcc746f69289e9cce6dd9845fb93c6d0` |
| `-network/boc-build.json` | `0c22ba96c2e0d30a110bdaeebacd5ceb973ee444d61b8d04ffae5f257734f392` |
| `-network/rpc-transcript.jsonl` | `bb89b866a124e07bef19a25c578f129e664381c7853f7f5d590a60240a16e7f3` |
| `-network/chain-evidence.jsonl` | `b33c1c008714180ecc54aa543d2bd45fe0c018bc06df12b3b7a0524ba7dcb64c` |
| `test/integration/.e14-wc0-token-index-386a-rpc-method-red.typescript` | `a025df4bce304290dcb96fa8eaa3ddb621195f99435f92c804072c4854dc57e9` |
| `test/integration/.e14-wc0-token-index-rpc-method-green.typescript` | `b627e9920cd00b32eadcb68409a48822dae76398cb7b6c6232efcaf5f5f3bd54` |

The `-network/` artifacts live under
`test/integration/.e14-wc0-token-index-386a4ce1b-20260925-network/`.
The failed network exited; no validator or DHT process was left running.

## Corrected committed-tree run

The next serial run used exact committed source
`65b0c0cb58358fbcf0886707a2da37fdb09401de` and the same command.
`cmake --build build --target slice1_gas_parity_contracts` completed first;
Fift, Func, validator-engine and both Jetton BOCs were copied *before* network
startup into `test/integration/.e14-wc0-token-index-65b0c0cb5-binaries/`.
The script's own in-run build/provenance hashes equal those retained copies.
The wrapper exited **0** with `RESULT: ALL PASS`.

The genuine mint's indexed row identified the deployed master and an active
wallet; the route actually called `runGetMethodStd` for `get_wallet_data` and
`get_wallet_address`, and checked the wallet owner/master plus reverse
resolution. The forged notification's exact target transaction was in wc0
shard `-9223372036854775808` seqno **48**. A subsequent genuine canary mint
landed in the same shard at seqno **63**, and its wallet entry was indexed
before the victim list was checked. The victim list and the attacker's
self-claim list were empty. The chain evidence retains sender/target message
hashes and transaction IDs, final heads, both block IDs and the two lists.
This is a local single-validator route; the later same-shard canary is a
coverage control, not a public per-block index-writer cursor or a reorg proof.

| Corrected-run artifact | SHA-256 |
| --- | --- |
| `test/integration/.e14-wc0-token-index-65b0c0cb5-20260925-console.typescript` | `7b37d44fa5a840bee07422d9248e45d1563fc3c61f2266d0e6c5512cc745e6ca` |
| `-network/provenance.json` | `936255aff90bfef544007940a6a3cc487e9ee53922cab049f6847034decd9dee` |
| `-network/boc-build.json` | `021288dd856fe6f0c6d1e3953ee127b0b0a32d142e47a5f207d4f01be3ee708c` |
| `-network/rpc-transcript.jsonl` | `20b05f4d9abba48de7b3cab539586f9c988d5fb9c557f71e89084112c00486af` |
| `-network/chain-evidence.jsonl` | `a2c2907aeee79914efab74f9f9d64b6e381710338cac785539e4463f02171c36` |
| `test/integration/.e14-wc0-token-index-65b0c0cb5-prebuild.typescript` | `a9095c158fd06a281d8d8d045f32882ec40c53bc72e159e7d606e5bf9091315b` |

The `-network/` files are under
`test/integration/.e14-wc0-token-index-65b0c0cb5-20260925-network/`.
The retained execution hashes are Fift
`cea26978924adf793b778505cb3befabd1c34c0d0e319776b2d9e35a1b16a8b5`,
Func `48b01ebc9410a672f684d588c3503393138e2f33346f3e47c601a66e5a58520a`,
validator-engine `2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
minter BOC `86c39a4617dd924ea246fd0d30668e5704351a04156c40c67a6450da88ae16c2`,
and wallet BOC `8261ef2f1dc066fe103d100f2d274ee8a1b7eced3425f6ee5829068ee5277625`.
The validator and DHT processes exited. E14 remains OPEN for independent
raw review and the owner's scoped signoff.
