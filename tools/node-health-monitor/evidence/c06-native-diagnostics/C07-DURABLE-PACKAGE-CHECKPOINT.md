# C07 durable development package checkpoint — no model or production acceptance

The already process-only fixed-W package is now committed once to the private
QueryLedger WAL/FULL database. `query_packages` binds run and current boot,
stores the exact <=16-KiB body and SHA-256, and caps all stored package bodies
at 8 MiB. A second write must match byte-for-byte; changed content refuses.
Save and load check the active grant and its run/network/M and query watermarks.
Load recomputes the body digest; revoke, expiry and boot rotation fail closed.
There is no MCP or model route that writes a package. An exhausted 8-MiB table
refuses new packages; pruning/retention policy is not yet implemented.

The actual M writer/HTTP grant control now also checks the persisted bytes,
restart-identical package, late direct and new M process arrivals excluded by
the grant, and no active package after a conflicting M source revokes the run.
The ledger control covers duplicate-identical write, changed write, 16-KiB
overflow, boot rotation, BLOB tamper and cross-run rebinding even if the
attacker recomputes the digest. All input remains development synthetic or
isolated actual M/edge producer fixtures, not production observations.

Source SHA-256 at final check: `fixed_package.rs`
`d39b6cdbe69678255defeae306fdcc1ab568adca08c3b8cd3b0005795fb2bc50`,
`query_ledger.rs`
`2c320a64a5cbade80f66e7e857c585248f6adfbac1633a5db8a0e93c5c3132fe`,
ledger test `2f38076839744293715eaaab5ecd5fdab7096326c81c42c808504c2c5cac1e79`,
M projection test `288864c6a6e0c0db93ce8808f2ed8f1a873aa92dc0c6181c4cd8ac86136df157`.

- Default `cargo test --workspace --locked -j2`: natural exit 0, 216 passed,
  one C04 indexed-pair test ignored without its optional directory. Raw
  `/home/tomi/nhm-c08-mcp-evidence/c07-package-durable-workspace.log`, SHA-256
  `0a0c27faa56531aee99ffd25bba9fc83c10620ef500fa358b3c1fde3caeb3a60`.
  This run preceded a narrow canonical-u64 comparison correction in the
  package binding; the final targeted run below binds that successor source.
- Final MCP-feature affected set (`--test manager_query_source --test
  query_ledger --test mcp --test mcp_token_visibility --bin tos-observability`)
  natural exit 0, 20 passed. Raw `c07-package-durable-final-targeted.log`,
  SHA-256 `5c87acfcc6f0fd335f640dc64bb4fa980281105db73cb28a7340e92d28066bb3`.
- Final `cargo clippy --workspace --all-targets --features mcp --locked -j2
  -- -D warnings`: natural exit 0. Raw
  `c07-package-durable-clippy-restored.log`, SHA-256
  `794b006fb4df39d13ed47d09021f86fbda3ec36e6adce64c852dec05ee36c0b4`.
  The first strict clippy log `c07-package-durable-clippy.log` is retained as
  exit 101 for temporary owned-string comparisons; the final source uses the
  canonical exact-u64 parser and passes. An earlier test-red used a TEXT
  corruption instead of BLOB; the corrected actual-BLOB integrity and
  changed-hash/foreign-run negatives pass in the final ledger test.

The package is not yet tokenizer-checked, prompt-reviewed, or connected to a
real AURA child. Its construction rechecks up to 8 MiB of cached evidence
while holding query-state and ledger locks; performance/isolation and cleanup
are explicit pending gates. No AI output or production capability is enabled.
