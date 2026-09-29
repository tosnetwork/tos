# C05 O development runtime and lane supervision receipt

All inputs are isolated loopback/synthetic fixtures. No business node or
production source was contacted. These receipts do not establish an
independent production O-heartbeat receiver or current M rule input.

## Actual development O process

Command (natural exit 0):

`cargo test --locked -p tos-health-services --test witness_poll actual_development_process_serves_heartbeat_with_bad_source_and_failed_delayed_notice -- --exact --nocapture`

Raw `raw/actual-o-runtime-restored.log` SHA-256
`2579ea99d7f9b308f5a3105ac00c6c4d9b82beaf15ed17050532b11ddfcc5e7b`:
1/1 passed in 47.05 s. Test binary
`target/debug/deps/witness_poll-a64ed631cd879ce5` SHA-256
`3ee8b6e63174c2e5a1d1f7507a8fa3bbd0c75d48298f3cd7aeb8bb41ced00a4f`;
spawned `target/debug/health-watchdog` SHA-256
`918291d4e3eefdff6c24d91576d59fe14a54a0b42a3af95033df918e3b10634b`.
The test source SHA-256 was
`4696ec92ba69bf0d40f6485830152ecb4414075c9f364a312b28b4c2c60ae40c`;
the bin source SHA-256 before later test-only barrier edits was
`053cd67fd877cee2a90fffba14b380af618885eaea3d6020657d98e94cf77c13`.
The child is protected by `ProcessGuard` on panic. The test proves repeated
invalid-source polling before the delayed notice, a readable O heartbeat
during the delayed notice, then failed notification transport and a later O
sequence. It does not prove poll progress during the blocked notice or that
remote source work stopped. An earlier first invocation failed because the
test omitted the isolated `client.pem`; that result had no preserved raw log
and is not counted as product evidence. An earlier pre-RAII success is also
not bound to this receipt.

A successor assertion used the outside test client after stopping the child:
the O heartbeat route became unavailable within a test-only two-second bound.
The same targeted command exited 0 in 47.05 s (`raw/actual-o-absence-restored.log`
SHA-256 `d567236b591ef39fefd9308823818da3545f15dd118d9e5f874a0a11edc941ba`).
Test source SHA-256
`2727241cc1bd84f463eaca9053188bd2d1f5d476bc24421a96cb74e84c5d7b63`,
test binary SHA-256
`7cd2960f67d9759aec64950d48ca5a29d15b995e1f76a6c9b527279477442cb4`;
spawned watchdog binary remained
`918291d4e3eefdff6c24d91576d59fe14a54a0b42a3af95033df918e3b10634b`.
This is an isolated absence detector, not an independent production receiver,
configured dead-man deadline or notification-delivery policy.

## Lane exit while tick is already blocked

The test-only barrier first enters a five-second tick await, then releases an
O source failure or an unexpected cache listener `Ok`. The restored command
`CARGO_BUILD_JOBS=2 cargo test --locked -p tos-health-services --bin health-watchdog -- --nocapture`
exited 0 with 2/2 tests (`raw/lane-supervision-after-mutant.log`, SHA-256
`c9c367136c2c5344ee3a857daa2bd01dcb38d37552764235ecd5d1da2b1599af`).
Restored bin source SHA-256
`82c5122ae991cf5af23c393c86b819f5c3ca63b55bd1fa96ca93908160d3be3a`;
test binary SHA-256
`b8e91d4d0f263d431b71263829cfdc27fdc2883dfe45661d6b1dc824ec3e0bfb`.

One changed-property mutant replaced the source-lane await with a pending
future; the exact independently applicable one-line diff is
`lane-supervision-mutant.patch` (`git apply --check` on the restored source
exits 0; patch SHA-256
`903a5217f98d4c318afaab0bf62377f84bc59072e6cfe12d9c23343e37042fa0`).
Mutant source SHA-256
`0b5893a4d153f4051a567f1150d1ab159a1e76e7673db6d747cc1df8cfa68f97`;
`raw/lane-supervision-mutant.log` SHA-256
`734a915d331e070e1cb7656ef26e9518161b3cafb0aea39345eed40b11a7cdeb`
shows compilation succeeded and the intended `Elapsed(())` assertion failed
(exit 101, not a compiler failure). Source was restored and the 2/2 command
above naturally passed. The one-line patch records the edit performed, but
there is no retained original full mutant source copy; treat this mutant as
provisional until an independently frozen rerun, not as a final indexed kill.
`raw/lane-supervision-restored.log` was the 2/2
baseline before the mutation (exit 0, SHA-256
`4b79c809d4a50031c5ea7be381cdc9436b17f8e4199c566b1c91e4f6bedefdfa`).

`CARGO_BUILD_JOBS=2 cargo clippy --workspace --all-targets --locked -- -D warnings`
exited 0 (`raw/clippy-after-runtime.log`, SHA-256
`290a922cc6aa2dd700357946bf34f5f3caaa3842db30fd8248ffb472c241bb0b`).
`raw/closure-after-runtime.log` exited 0 for the workspace contract entrypoint,
but a test-only barrier edit occurred during that run; it is lineage, not a
frozen final-source closure claim. SHA-256
`3fd62eb2b635a5f09b7e1b11b22f8b13bc06325bfbc3f750d564c5a971c1d7f0`.
After the absence assertion, the same Clippy command exited 0 again;
`raw/clippy-current.log` SHA-256
`33837110c6509828a34704e2bfcdba71c59653a333ecd4aefcd68adda157e8e1`.
Current changed Rust source/test hashes at this receipt:

| File (relative to `tools/node-health-monitor`) | SHA-256 |
| --- | --- |
| `crates/health-services/src/bin/health-watchdog.rs` | `82c5122ae991cf5af23c393c86b819f5c3ca63b55bd1fa96ca93908160d3be3a` |
| `crates/health-services/src/collector.rs` | `f64ccf7ba80a7d0f0a093bb7620753b065245a012caa2b2823652101b4477ebf` |
| `crates/health-services/src/manager.rs` | `d1446109fcbab21ede74090f0b0071cca89fe869bc8894d25055f1d55db1e05f` |
| `crates/health-services/src/witness.rs` | `69144a32079810b8775fc651efbf6fa80eff6a43ac938505a03685057a0f69dd` |
| `crates/health-services/tests/witness_cache.rs` | `515e54488f0d7c9af57af3cc631e27048350b2f3798004cd935e4fee2ab806f0` |
| `crates/health-services/tests/witness_poll.rs` | `2727241cc1bd84f463eaca9053188bd2d1f5d476bc24421a96cb74e84c5d7b63` |
