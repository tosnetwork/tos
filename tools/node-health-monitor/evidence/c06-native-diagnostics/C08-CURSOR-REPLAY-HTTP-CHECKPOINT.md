# C08 HTTP cursor replay checkpoint (isolated synthetic evidence)

The actual `/v1/query/event-window` route returns three fixed-watermark
pages in store order. Its first cursor is refused with `CURSOR_MISMATCH` over
HTTP 409 after a changed filter, a changed run, a changed tool, or a changed
cursor byte. The second synthetic run deliberately uses the **same** token,
principal, scope, window and watermark as the first, so the cross-run control
tests the run binding rather than relying on a different token hash. This is
an isolated adversarial test fixture, not a production token-allocation
pattern. The response error code is checked in each negative, not only the
status code.

The compiled mutation removed both run-ID inputs to the cursor tag: the
grant's `run_id` and the request filter's `run_id`. The target test then
failed at the cross-run HTTP assertion (`200` instead of `409`), not at
compilation or another negative. The source was restored exactly and the
whole affected HTTP test target passed. This establishes sensitivity to
cross-run binding; it does not prove AURA integration, production deployment
or all C08 refusal paths.

Source SHA-256:

- Restored `crates/health-core/src/query.rs`:
  `06a71d892528b851299692d24a82aedfd6d506a6878aa21b435e3009d81bb5ed`
- Final `crates/health-services/tests/http.rs`:
  `01b646542adcf80340aa1cca7efa42531fb5c0f717fbd11d445c394d90236c22`
- Compiled run-binding mutant `query.rs`:
  `9e06344d25300991f7c01f1ead4a7aee284d4055ca16cc8234254da4d1c00206`

Raw files under `$HOME/nhm-c08-mcp-evidence/`:

- `c08-cursor-replay-run-binding-mutant.log`: `timeout 120s cargo test
  --locked -p tos-health-services --test http
  event_pages_use_fixed_watermark_and_reject_changed_filter_at_router --
  --exact`, compiled assertion exit 101; SHA-256
  `5d045cd6c47b997d6b412121211560706ad5be982e8c0c06d6ed6a6dc6243e11`.
- `c08-cursor-replay-final-http.log`: restored `cargo test --locked -p
  tos-health-services --test http`, natural exit 0, 18 passed; SHA-256
  `128bee7e2c7e885dbddcbcec25521f33105ac6fd6882692dfb0e0804ab016a12`.
- `c08-cursor-replay-final-clippy.log`: restored `cargo clippy --locked
  --workspace --all-targets --features mcp -- -D warnings`, natural exit 0;
  SHA-256
  `e53452226b3829c6f84c1c7121a7e9a4c464a58b33a2d844a5da3e52c0dfc4ea`.

`cargo fmt --all -- --check` and `git diff --check` pass. The current
checkpoint adds HTTP tests only; it does not modify production query logic.
