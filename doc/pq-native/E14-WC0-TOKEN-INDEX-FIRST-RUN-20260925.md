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
