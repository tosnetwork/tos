# C08 M archive read storm checkpoint — not V/O network acceptance

`ObservabilityState` now has an internal counter incremented immediately
before a broker-side M archive read attempt. A real HTTP test creates a
retained M process row, starts the query cache, grants one fixed-W run, and
issues 1000 `/v1/query/node-snapshot` requests through the actual router.
Startup and grant produce two M read attempts. The route then returns 16
successes and 984 budget refusals with the M counter unchanged at two;
an explicit broker import increments it to three. No query path uses this
counter to make a health claim or refresh the cache.

A bounded compiled mutant inserted an `import_manager_into` call immediately
after query-handler admission. The same test completed with exit 101 at the
intended counter assertion: observed 1002 rather than two. The mutant was
restored and the original source SHA rechecked before the full regression.
The first draft of the test expected one pre-storm read and failed because it
omitted startup's bounded import; the final test correctly counts startup and
grant separately. That first red was a test expectation error, not a product
failure.

Final source SHA-256:

- `observability.rs`: `7dbf77acb994a6d38c5d68e7eeedbaac467428ae1406395dd8f99a722556d54a`
- `tests/manager_query_source.rs`: `b4daa06353eacd70ac3b7b055b7f0a49c51b64d6ec681599d18aab8fef613ab4`
- Compiled mutant `observability.rs`:
  `bc90a7b3c13a14f50cc979c68495f93158c29f62e1aa1146ce41c73f1a82ace1`

Raw logs under `/home/tomi/nhm-c08-mcp-evidence/`:

- `c08-zero-m-read-baseline.log`: targeted real-router test natural exit 0,
  SHA-256 `4312e62b2f2ae37ec01055fa1a632f60a54b17f9a71aadc68eec685705f6b1a1`.
- `c08-zero-m-read-mutant.log`: compiled target test exit 101 on the M-read
  counter assertion, SHA-256
  `a47be54e2528d55de5f06308bda272a6bde65599a7c7f65a9c508bf6a2b2c398`.
- `c08-zero-m-read-final-workspace.log`: `cargo test --locked --workspace
  --all-targets`, natural exit 0, 217 tests passed and one optional C04 pair
  test ignored, SHA-256
  `30ff7b0eba062c71100191ce9de30b4fbf1a2b9e3aa773485fabcc4974d7287a`.
- `c08-zero-m-read-final-clippy.log`: `cargo clippy --locked --workspace
  --all-targets --features mcp -- -D warnings`, natural exit 0, SHA-256
  `580d8f25cf211b4ead11a690ef2cbfdb9fd5b730f5398572b22f8dfc952607bb`.
  `cargo fmt --all -- --check` also passed.

This proves only that the tested HTTP query storm did not re-read M's archive.
It does not cover actual V/O request counters, miss/depth/redirect/replay
scenarios, AURA child lifecycle, provider selection or production gates.
