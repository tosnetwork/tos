# C09 epoch-binding candidate receipt

Base HEAD: `e830b6ec3540ef549b1287519f58595c7306ee4d`.
Scope: edge native/process reconciliation only, plus one C08 clippy-equivalent
ASCII comparison correction. No business node, key, deploy, or main merge was
performed here. The supervisor retains the pre-fix six-node 503 evidence and
owns the post-fix real-node rerun. This candidate is not C09 acceptance.

Frozen source SHA-256 (paths relative to repository root):

```
eb24e2ceb8e9c3528476bc08c226d1b9add2dd802b40e88bc11d9423df2215dc  tools/node-health-monitor/contracts/edge-snapshot.schema.json
186176aef64bcf6169796a81784d299804096dfa5e702c9f1c5e999dafee1f83  tools/node-health-monitor/crates/health-core/src/edge_snapshot.rs
5f63ebb1df05d3b06751d5f43133371b31ded670c3e040116414280ba531e79f  tools/node-health-monitor/crates/health-core/tests/native_contract.rs
e525aeeffa20cc77958ab8b7d56abb02fd6eb3f13f0dcd2b3a04c4281466d74c  tools/node-health-monitor/crates/health-services/src/edge.rs
91adfac3d6b67f629a7c5e9598d50e19bee252e365956c6c66c769fee87f6db1  tools/node-health-monitor/crates/health-services/src/native_cache.rs
b827f1c577094ade6b7aea1c37f7ef2c1d00d10c852ace834cc00024f639b068  tools/node-health-monitor/crates/health-services/src/query_ledger.rs
80befb5c9497fb2b8526755e0f35f73cc38b26ba050894f0a075437258131094  tools/node-health-monitor/crates/health-services/tests/ingress.rs
edd33b0d8a3378544891ecc8290c0c6ebcc82c3608afa38ed3d1d1f5e749374e  tools/node-health-monitor/crates/health-services/tests/manager.rs
1e7d846570a3c1637bb71a62e100089a83f2a38ef0f5069510cccadf40243770  tools/node-health-monitor/crates/health-services/tests/native_typed.rs
60dfb832488579fbde8aaf62fe3f59276251b4f0629bad64b859f1ff6987464c  tools/node-health-monitor/crates/health-services/tests/native_v2_producer_pair.rs
3b87f0b361952825fcab86f4ca838449a2904dd1c1901751b796a3c2d294bc9a  tools/node-health-monitor/scripts/check-contracts.py
```

Frozen local raw evidence and binary (all under
`/home/tomi/nhm-c07c08-build/edge-epoch-proof/` except binary):

```
7a07e84a40245a151d30761ee9f61f1052671b74708a875fcf866db9180064be  workspace-final.log
439923c5b979d67b687d4eecba17463b53d147dd08df84fa19960686ed41de40  contract-entrypoint.log
04e7b638014f9b729ca7e243958c21bd2d2a3691ad9029217881e9dff3e53de0  check-contracts-final.log
f556764f926af58f6d64e7f5900cb90d8ca00f5574464dbf6ad227c3a83c9f4a  clippy-restored.log
84f4a9a1e1c69a553645fb70209b3225c1d2b60b2d1a8ee04e403317dade43a3  producer-pair.log
2200bd092bb2441ad32e6f58d8ba3e6ba40bcc1165889e8372fb84bc8bc0b7fa  edge-snapshot.json
50d71ace513a24562001a57bc3f91faed081553476cd2e6884409bc7c7d53c51  /home/tomi/nhm-c07c08-build/debug/health-edge
```

Commands/results: `cargo test --locked -j2 --workspace` natural exit 0,
184 passed/0 failed/1 deliberately ignored C++ pair test; that exact ignored
test was run separately against Starbridge's 48 indexed native pairs, exit 0.
`CARGO_BUILD_JOBS=2 scripts/run-contract-tests.sh` natural exit 0, including
24 closed schemas, six real handler successes, production doctor refusal and
the restored workspace suite. Final `scripts/check-contracts.py` after adding
missing/extra binding negatives exited 0. `cargo clippy --locked -j2
--workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, and
`git diff --check` all exited 0. A real router `edge-snapshot.json` passed
Draft 2020-12 validation and had distinct native and proc epochs (2,601 bytes).

Historical red lineage: the first workspace pass exposed an old ingress TLS
fixture without the new binding and two old manager archive fixtures likewise;
after updating only those synthetic fixtures the target tests and full
workspace passed. An initial clippy pass found the C08 ASCII comparison style
warning; an equivalent `eq_ignore_ascii_case` correction and restored clippy
pass followed. These initial failures were not counted as passing evidence.
