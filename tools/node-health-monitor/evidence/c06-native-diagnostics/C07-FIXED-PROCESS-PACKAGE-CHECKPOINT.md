# C07 fixed process package: development checkpoint, not AI acceptance

`fixed_package::freeze_process_package` reads only the durable query cache,
not M/V/O or a model endpoint. Its cached derived `process` row is revalidated
by `QueryLedger::load_evidence` against the retained original M row before a
bounded, deterministic JSON package is built. The package fixes both the
grant's query watermark and M original watermark, checks node/scope/window,
selects the latest eligible process observation per approved node/scope,
lists missing process tuples, caps serialized bytes at 16 KiB, and hashes the
exact bytes. It always says `partial` and
`source_profile=development_process_only`; no C04/C05/C06 source is promoted.

Real M writer/HTTP grant tests verify parent ID, restart-identical bytes and
digest, a new M process record imported after the grant not changing the
package, an unrelated late direct cache row not entering it, and refusal
after M source conflict. An empty M archive plus a direct cache row produces
an explicit missing-process tuple rather than a synthetic healthy sample.

Evidence:

- Full default workspace at the package-source SHA below, before the final
  extra late-derived assertion: natural exit 0, 215 tests,
  `/home/tomi/nhm-c08-mcp-evidence/c07-fixed-package-workspace.log`, SHA-256
  `b4ed95fa9cf478efade3942609af6ebcc1335652a3527ccda8e3f7e093d2b301`.
- Final affected `cargo test -p tos-health-services --test manager_query_source
  --locked -j2`: 7/7 exit 0, `c07-fixed-package-restored-final.log`, SHA-256
  `80e91a9347df4b3b731c43497cca89674da837324d1c7dc66b0c02f579b23308`.
- Final strict feature clippy: exit 0, `c07-fixed-package-final-clippy.log`,
  SHA-256 `2f8ee92e5c772b178f7d9a14318d726d601317e7ad2fa48caea1afd354bd8ddd`.
- Pinned contract checker after supervisor's concurrent diagnosis-schema
  correction: 24 closed schemas, exit 0, `c07-fixed-package-contracts.log`,
  SHA-256 `04e7b638014f9b729ca7e243958c21bd2d2a3691ad9029217881e9dff3e53de0`.

Compiled changed-property control: original `fixed_package.rs` SHA-256
`f02fe0c6984139fc6e824e57e8b7f056fd3deb2bf70de50d0d29870aa9481d95`
uses `entry.watermark > grant.watermark`; the sole mutant uses the live cache
watermark instead (mutant SHA-256
`d5ce01d08ddfe7566733ed969f4c353f132694216baed703956358ee2eccc2bc`).
The baseline log `c07-fixed-w-baseline.log` exited 0 (SHA-256
`f6355d596106128ad9f54123bf29a8012a8c1a98ba3bb36ac99946270f657870`);
the compiled mutant log `c07-fixed-w-mutant.log` exited 101 on the test's
`unwrap` because the independent fixed M watermark rejected the late
process parent (SHA-256
`01f5907682aef456e304058b7a54ada61f4ea069e3f1a20b180e3d8d0daf7019`).
Restored source hash matches the original and the targeted restored log exited
0 (SHA-256 `d25268de3416ac17a97fd10af7acb1fe44083c85391874bdbbb331c77e783ff3`).
This is sensitivity of the *combined* two-watermark fence, not proof that the
query-W predicate is independently nonredundant for currently approved M
process imports.

The package is not yet stored as a broker run artifact, tokenizer-checked for
8192 context tokens, connected to AURA, or suitable for production inference.
It does not establish semantic entailment of any future diagnosis. This
development process-only path performs a bounded 8-MiB cache restore/recheck
per call; no production performance claim is made.
