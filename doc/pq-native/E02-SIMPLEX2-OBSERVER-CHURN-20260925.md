# E02 retained route: Simplex2 observer churn

Status: local route PASS on `c4f381584c163fbbe501764eca44f09dc270a39b`;
this is not a release-scale finality, restart-recovery, or fork-identity test.
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
