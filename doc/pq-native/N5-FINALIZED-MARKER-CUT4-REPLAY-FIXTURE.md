# N05 controlled Cut 4: finalized marker and accepted block cold replay

Status: local fixed-tree evidence; N05 remains OPEN until pushed-head Branch PQ CI and independent review. N01 and N06–N07 remain OPEN. This is a controlled actor/DB stop, not an arbitrary power-loss test or a real node-network run.

Source commits: `d4771be44be4e1dbe3dc7ad5e6ff2781a05ca091` adds the fixture and CI registration; `a1867acdf` adds the post-settle event-count assertion. Production `state-resolver.cpp` was restored byte-for-byte after the red experiments. The clean test source SHA-256 is `ecacf8292a252513e09f12f0cceb5db3a2852a5a3682f61ac0fcd9088a6b2766`; the clean resolver source SHA-256 is `2c07ccb84cebb322b39a8d67ebe3127b3a866a1b6aaac9adb120c2c530988095`.

The `--n5-cut4` writer uses the existing production Pool→StateResolver→BlockAccepter→Manager/RootDb joined path to save one signed and verified FinalCert, apply its block, and write the finalized marker. A child first cold-reads the exact FinalCert TL, marker key, BlockProof, signatures and state. A fresh process then opens the same Simplex RocksDB and Manager RootDb roots, cold-restores the genesis Manager context, and starts the same session's production Db/Pool bootstrap. `N5ReplayObserver` requires exactly one `FinalizationObserved` with the same CandidateId, vote id, and serialized FinalCert TL hash. After a one-second settle window it rechecks that count and mismatch flag. The test facade counts every `AcceptBlock` entry: the restarted session must make zero calls. After stopping that runtime, another fresh process reads the same proof/state/marker again. This checks preservation and absence of duplicate application at the facade boundary, not an operating-system crash or remote network ingress.

Fixed-tree command: `ctest --test-dir build --output-on-failure -R '^test-n5-(accept-block|joined-finalcert|cut[1-4]-|manager-db-fixture)'`. Result: 7/7 passed, exit 0. Direct `build/test-c04-real-state-proof --n5-cut4 test/pq-native/data/c04-pq-genesis.boc` exited 0. The final retained DB root is `/tmp/n5-joined-finalcert-sGnToH` (652 KiB at recording); it was not deleted.

| Retained artifact under `test/integration/.n5-manager-db-fixture-20260924/` | SHA-256 |
| --- | --- |
| `a1867acdf-cut4-final-clean-build.log` | `c95fdabfcf67c1ab8f2ed4e3604c1a4a35747a8fc779d2ee815a264c9ed1cddc` |
| `a1867acdf-cut4-final-clean-ctest.log` | `e89cc635cd97ef059632feeec6b79133bbaf9f654368668c88517c6cf40ebadf` |
| `a1867acdf-cut4-final-clean.raw.log` | `936b0b838202372f8a0ae9beb22fb830d3a331856974aa93ac00051e63c70abc` |
| Clean `build/test-c04-real-state-proof` | `bfd3328560aa0c81b1d909002f8b903deac6befddaceeff9715f40c4151fac40` |

Two independent, single-purpose red controls were run against the same `a1867acdf` test source. Neither mutation is in the production tree:

| Mutation | Exact failure | Patch SHA-256 | Build / binary / raw SHA-256 |
| --- | --- | --- | --- |
| Ignore a present `db_key_finalizedBlock` marker in StateResolver | exit 1, `events=1 mismatch=0 accept_calls=1` | `n5-cut4-marker-bypass-mutant.patch`: `cfe8036526ca450a1840c8da08d9aae5fb31d707718f43ecb95c2026ac3d37b9` | `c95fdabfcf67c1ab8f2ed4e3604c1a4a35747a8fc779d2ee815a264c9ed1cddc` / `e2c60878714115938e36a087b1b716da2aca3834c84ad4f1ef15c71baca73167` / `1b028d48d0eb88d05efcfc965ea90eb72d591da728b656eed58c5c648414d3cf` |
| Inject a second identical `FinalizationObserved` 0.2 s after the first, inside the settle window | exit 1, `events=2 mismatch=0 accept_calls=0` | `n5-cut4-repeat-event-mutant-corrected.patch`: `a6ec80c917619595db2ae68058d4fc24f2dc95c2e80a9a8ad80c53e6e09c6c24` | `9108a458351fb7243714db8d6efef83ef4ddeb1623434231093aee03d7089363` / `e5be2be6469a93649606b79a5575d2165e1c72d7c9877406fbe8ca65996e2874` / `6dc95aa1281ff241fc7a2d8bf4fdcc922faea77a0b0c0522aa7d7af54430063e` |

The repeated-event mutation is an injected actor event, not a claim that production Pool emitted twice. It proves the final count assertion observes an event arriving after the first check. The marker-bypass mutation proves the `AcceptBlock` count detects a replay that would redo application. Both patches pass `git apply --check --unidiff-zero` against the fixed source; the clean source was rebuilt and rerun after the last red control.

Mutant source hashes: marker-bypass `state-resolver.cpp` = `480c0d385ee9c6aacebdfd778c0b9062cb827c6fc6ec2caf0ad919ec5a3d1655`; repeat-event test source = `a75b4afde58e649731b3b7310096748ab3c3fa58f64b5dcf629f1201cc322e7e`. The marker-bypass and final-clean Ninja logs have the same SHA because their three build-step status lines are identical; the retained binaries and distinct raw logs identify the compiled behaviors.

Provenance correction: the originally committed `n5-cut4-repeat-event-mutant.patch` (SHA-256 `444b53523dcab65ca9afd24051f12fd2adc30a612b95b5e54a343d2c31a02a0b`) used zero-context hunk `@@ -779,0 +780,5 @@`. On the clean `5dced784d` source, line 779 is the closing `};`, so applying that patch places the five lines **outside** `N5ReplayObserver` and reconstructs SHA-256 `91232f0a87924605679671efc71168e95861bb96cac75de8b725c43193db1f87`, not the compiled red source. `git apply --check` alone did not catch this syntactically invalid placement. The original patch, red build, binary and raw log are retained unchanged. The new `n5-cut4-repeat-event-mutant-corrected.patch` changes only that hunk anchor to line 777, immediately after the event counter increment; applying it reconstructs the actually compiled `a75b4afd…` source. No claim is made that the original patch reproduced the red run.
