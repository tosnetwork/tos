# E02 retained route: Simplex2 observer churn

Status: enhanced-route local PASS on
`446940f187b1f93d276297c514aaeaee3e039111`;
this is not a release-scale finality, restart-recovery, or fork-identity test.
The earlier status was "local route PASS on `c4f381584`". That run really did
pass the then-current script, but its verdict did not enforce each node's
progress, exact observer lifecycle pairing, or different cc_seqno values. It
is retained below as historical evidence, not substituted for the enhanced
rerun.
The retained raw artifacts are under
`build/simplex2-release/e02-c4f381584-20260925T0010Z/`.

## Startup boundary and separate fix

The first run used `bd20ba189f86c5ae6520337745019e590c2c4722` and stopped
before observation: `Network.wait_mc_block(2)` received the production
`500 / LITE_SERVER_NOTREADY: node not synced` startup response, which the
harness did not retry. Its full output is
`build/simplex2-release/e02-bd20-20260925T0005Z/command.raw.log`
(SHA-256 `0b00ddcf45d91292c6abfea9a365dcc65f486a75cdf26cae95944399f8376d93`,
exit 1). It is an early harness boundary, not an observer-group result.

Commit `c4f381584` adds only that exact 500 response to the existing
startup-retry whitelist. The targeted test was red on the old classifier
(1 failed, 1 passed; raw SHA-256
`672de6eadc0920af0504999a11eda359e0b00d8c33c4b5f34a9bdc2ba966f6e7`)
and green after the fix (2 passed; raw SHA-256
`68683c941f53fd55547c17b6a1b7a966702a2b51e89bd6832b00e772606b6b6e`).
It also refuses the same text with code 400 and a different NOTREADY reason.

## Fixed-tree run

There was no other local validator/DHT network or listener on ports
22000–22039 before the run. The fixed-tree build of the required native
targets exited 0; `build.raw.log` SHA-256 is
`b95669d849f006b610a2feae24fb4ab6abb45e36dfffec966352779c8ef17ce1`.
The `validator-engine` SHA-256 is
`0e116c57e16bcb1fcd4812194890084b908bbe2d1841c60e92a062454f0e70dd`;
`dht-server` is
`cc33272534b9cac6d99ed4f2979f67c6850897fe317885b0e60769fb0a69dabc`;
the route source is
`1820d282b3b1414ffcd49cfcfaa2a084e1965369a369e5b96aabc0cd7a37095f`;
the startup harness source is
`7afe536fd01f3a4243af706fe14fdc47d5130ee7985a8b9791e29bb75946bb00`.
The remaining required binary hashes (SHA-256) are:

| Binary | SHA-256 |
| --- | --- |
| `crypto/pq/tos-pq-consensus-key` | `039811cd49d0b2d6f4232a5ea46e8cd025fd8ddd5d7fe37ee46b292992ba5c6b` |
| `crypto/create-state` | `04409638878a7e4c55f638283aee3e417329569e77a859ea49fa85738a518fee` |
| `toslib/libtoslibjson.so.0.5` | `3471f1a485301a6c098fdd931777236da33c32efb2a400e54c42f33f32a68161` |
| `validator-engine-console/validator-engine-console` | `fab543c89a7efeee7f595981cf358304a2e855797c62746e2acd40abc0005084` |
| `lite-client/lite-client` | `d72f3ca2ddd4259120ddf0c7e3a7c33051faaeb50caaa3b2882e2f3314b33b35` |
| `utils/generate-random-id` | `3421616bbb1c2b9d41197ef197e3599c00f27f897e0d5b266476780e00e6b2ff` |

These files and the entire node database/log directory remain retained.

Command, from the repository root, with complete stdout/stderr retained as
`command.raw.log` (SHA-256
`46aa77a491c4b0d3f74ddf5e81ba65ecc24f47fc50cceb5be86b62679be30713`):

```sh
PYTHONPATH=test/tostester/src uv run python test/integration/test_simplex2_release.py observer-churn \
  --duration 60 --validators 7 --shard-validators 4 --group-lifetime 8 \
  --base-port 22000 --threads 2 \
  --artifact-dir build/simplex2-release/e02-c4f381584-20260925T0010Z/run
```

Exit code 0. The raw `run/summary.json` SHA-256 is
`79c41c9da8a62a186bf55c904f37b2cb3488c44fa6820f6babce92bce08304ec`.
Its own `git_commit` is the fixed source commit above; verdict `PASS`,
`failures=[]`. All seven validator lite views moved from height 2 to height 6;
20 sampled height vectors had maximum inter-node spread 1. The script found
21 created, 21 started, 18 destroyed observer groups across 21 distinct
sessions, with zero refusal lines and zero fatal diagnostics. Its policy
samples show `enable_block_sync=false` and
`observers_in_private_overlay=true`; shard candidate samples include a
nonzero `get_observer_adnl_ids` size. All eight process logs are retained in
`run/network/node*/log`; no validator/DHT process remained after exit.
Their SHA-256 values, in node order 0 through 7, are
`1c6b93b577c866cc2362512568b6f1dc82af19d30071e29f567cad6967a9c48e`,
`3670df7dec131d6568127c396c2356ce45796819988d12e2d9e4a4ac07004659`,
`22bb63b28d863f2dcc28f5114e591951085f83ae5888942b3d3ee95ceff5ec55`,
`3eec5492bd3306237bfd41dd4afe3f695a5afd91a0454d9f39b4fec97f81bc5f`,
`82c20acc88c8dca033f1e4e14589b3ecedfbad256a2905973a9cfa21a66aaf39`,
`c5c3d870ae6a4abd42eaddafc9f44f328ca29145a7687037c6523b5ec580db1a`,
`9802b0932d92a4a0aabe914476741171a6f5c40bccb20755f79da188fe953585`,
and `9a6c5b956384e492d136e94abd3f2bc85091a6ea5226e9383563a7cfc24217d3`.

## What the route does not assert

The script asserts height progress and bounded final height spread, observer
creation/start/destruction and multiple sessions, and no fatal log lines. It
does **not** compare block hashes at equal heights, assert FinalCert or proof
acceptance, restart a node, or induce/recover a fork. Those properties cannot
be inferred from this PASS. Four masterchain heights over the sample are not
a consensus-cadence measurement: the lite-server observations include local
application and query/exposure delay. E02 is limited to the advertised
observer-churn route and its actual assertions.

## Stronger verdict and exact-tree rerun

The original `c4f381584` logs were re-parsed with the new checks before the
source change: all seven nodes progressed 2→6, all seven had zero lifecycle
errors, and their created groups covered cc_seqno 1–7. This retrospective
calculation established that the logs contain the needed observations; it did
not make the old script's verdict a lasting gate.

Commit `446940f18` changes the route to require **each** of seven nodes to
progress, to match every local create→start→destroy transition in log order by
the exact `(shard, cc_seqno, ADNL)` tuple, and to see at least two distinct
created `cc_seqno` values. Live groups need not be destroyed at the observation
horizon. ANSI log-color suffixes are removed before parsing. The new summary
reports per-node lifecycle errors and cc_seqno sets as well as the aggregate.
Five unit tests plus the startup tests passed 7/7 on committed source (raw
SHA-256 `229e4533d1597c28d56b8b7c42e076151a9d019effe66ced40bfb2ba3347ae36`).
Four separate one-change mutations to `446940f18` all made the targeted
tests red; their unique patches and raw outputs are retained alongside the
earlier run:

| Mutation | Patch SHA-256 | Red raw SHA-256 |
| --- | --- | --- |
| Route no longer consumes integrity verdict | `172c84007df5b3cb72b193d567be716a62ed2c344f50026560082d43f534df51` | `f183cef5318f48d75d3d52c51b5a9e54ec5510b4f419423b672a36b4c9caa24d` |
| Ignore mismatched lifecycle identities | `55ef0d7cda6ba6bf8bdc552a1945e1424bc02d49e22722466f37a28d999232d1` | `f89a062f770ba4fb902630260eaf09b6058dfb2e04e0faf13e5b2259f76b0863` |
| Permit a non-progressing node | `1424bdb33e7ec5942d43fffcc8c2cb8cba73c43d123a31792879b50da2950d11` | `fe683e6f75b97591e5602b843f756bd5ed96b7655430e625b7c7c6f2e83132ba` |
| Accept only one cc_seqno | `c1aa8c355b061a45bb24f18c5fb6c1be0be2fd7c06158a14eb3383c7a38977c3` | `c93590959907ba994c832f7248908006e10037c6990eb08a3f2a0aeefabf2add` |

The rerun from `446940f18` used the same command/options above with
`--artifact-dir build/simplex2-release/e02-446940f18-20260925T0030Z/run`.
This directory label was reserved ahead of time; the raw command log records
the actual run clock. Build raw SHA-256 is
`fb871222d4002e934edcf914789313fda3667ac819e5a9fa9fe9f0b2195a6f47`;
route source SHA-256 is
`da922ed3c42b69b47da136b4fd74e6f55bedc98dd71d0c23f95150059e26cf75`;
`validator-engine` is
`5bda7a4d02cdefec7917245887fb2ba9fb7eb702a8329d19ac051d38e9b3d426`
and `dht-server` is
`97b7879ae15f8a932a04f1b670f0588537c2b377e981977902b517db76ff0462`.
The complete stdout/stderr SHA-256 is
`d1bd80ea4fa99f5865e44a805e82b64a151091cf3ea8677c24dc3ffba5648051`,
exit code 0; `run/summary.json` SHA-256 is
`fada237e2d2a3c391f3c5ea4e71750bae1b405bac51df28092518e475d163360`.
Its own `git_commit` is exactly `446940f18`, verdict `PASS`, failures empty.
All seven nodes moved 2→6; maximum sampled spread was 1. The route recorded
18 created, 18 started, 15 destroyed exact groups, zero lifecycle errors,
and distinct cc_seqno 1–6. The 18 groups versus 21 in the earlier run are
two observed runs, not a correction of one count. Refusals remained zero.
The eight raw process logs and node databases remain in the new run directory.
The stronger verdict still does not assert FinalCert/proof acceptance,
restart recovery, or equal-height block-hash identity.

One further pairing direction remained after that rerun: a create with no
matching start was allowed at the observation horizon. The test added for that
case failed on `446940f18` (raw SHA-256
`595297bdc276e163b5cb770da9e37f1aa2b568c845e3fdc85882046f00dd494b`).
Commit `0296e2dd7` rejects that dangling create; all eight targeted tests
passed (raw SHA-256
`e8826ddf071536d75e282d791d15a7e1d8c8d6b92c8b22ddeaf8b6d4ea1e8182`).
The `446940f18` run's logs were retrospectively rechecked and had no dangling
creates, but its verdict cannot stand in for a fresh run of the final script.
