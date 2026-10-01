# C09 private-route transition control — isolated WIP

Base `ef37b387ee308186d957f9f6455cd3eb2415ec0e`. This is a test-only interleaving hook in `observability.rs` (`#[cfg(test)]`), not a production-path change. It is **not integrated or deployed**. The running Q binary, runtime sampler pin, M/Q files and services were not changed.

Restored source SHA-256 `3ed2bb2d8961307161e9903d611d24754e64f8fa995d403c544c54fe0ca3b350`; restored unit-test executable SHA-256 `61decee2e321b5f5b792c929829ab99b5b2403aa57ca7499bef09da24a00acb6` in the isolated `$HOME/nhm-c09-anchor-build`. The hook changes `manager_caught_up` between the real private route's first and second Data/Q samples. It does **not** claim to execute a complete concurrent importer.

Command: `CARGO_TARGET_DIR=$HOME/nhm-c09-anchor-build cargo test --locked -j2 -p tos-health-services --lib private_route_transition_is_a_503_not_a_caught_up_sample -- --nocapture`.

- Baseline and restored runs: natural exit 0, one matching test passed. Actual route status 503 and exact JSON body:

  `{"caught_up_at_last_import":false,"cursor_global_m_seq":"0","lag_global_m_seq":"0","manager_conflicted":false,"projection_status":"transition","query_watermark":"0","schema_version":1,"source_global_m_seq":"0","source_identity_match":true}`

- Compiled changed-property mutant replacing `before != after` with `false`: process exit 101 at the intended actual-route status assertion, `left: 200`, `right: 503`. Source restored with `apply_patch` and rebuilt to the SHA above.
- Restored `cargo fmt --all -- --check`, strict `cargo clippy --locked -j2 -p tos-health-services --all-targets -- -D warnings`, and `git diff --check`: exit 0.
- Restored `cargo test --locked -j2 -p tos-health-services`: natural exit 0; the new private-route unit test is included. Explicit opt-in local/live tests remain ignored as before.

Starbridge replayed the **actual 239-byte producer response** over a local Unix socket into both shared-source Python consumers. The exact replay receipt is `raw/transition-producer-consumer-replay.json`, SHA-256 `17badb6bbff6de005126783b2c8b448ee11ee3b27cf1aa1711a8b9519e727820`; its response-body SHA-256 is `325d1aea6cb6d9ce01dceb8bc385584169aec14d9682a769c1ef4b9d4d69d1f1`. Functional `projection_head` returned `transition`, and the run-level control recorded `error_kind=projection_transition` with its failure latch; broker probe returned `projection_caught_up=false`. Three focused consumer tests passed. Source SHA-256 values were `sample-query-functional.py` `68333c419001dd830ac1bcd292199b0bbf7c14fcc40f1e892da3d9ab82da7830` and `sample-broker-projection.py` `1ed470252058c608e0423c31eb833e3e3c67f8e4e229beacb36a373224d7f632`.

The frozen runtime consumer has **not** been repinned to these source bytes, and a test-only Data publication hook is not a full concurrent importer. This control does not accept a producer/Q deployment, functional 72-hour window, or either grant-path HOLD.
