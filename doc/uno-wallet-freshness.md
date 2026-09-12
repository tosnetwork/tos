# Wallet source freshness pin

This is a new test-instrument check, not a retroactive repair of D78 evidence.
The previous boundary review and A's unpinned runs retain their original limits.
Failed 0/10 and prepare 0/9 are unchanged. No bucket or Paid/late obligation is
closed here.

## Binding and execution boundary

`uno/prover/build.rs` embeds `UNO_WALLET_SOURCE_ID` at compilation. Its value is
SHA256 over a versioned domain and length-framed relative paths and contents of
**all files under uno/crypto and uno/prover**, plus the identity-tool source.
This includes both Cargo manifests/locks, local Cargo configuration, Rust source,
committed FFI headers and vendored source. Only target, .git and __pycache__
directories are excluded. New files are included automatically; Cargo watches
both files and directories. Paths are repository-relative: identical source
content in another checkout has the same identity. Neither a Git timestamp nor
a manually bumped ABI/version constant is the pin.

The runner independently hashes its checked-out source, copies the wallet to a
unique fixture path, invokes that copy's `--source-identity`, and compares the
entire digest. Missing identity support, nonzero exit or differing content cannot
pass. A source edit during identification also rejects. All subsequent wallet
commands use that same read-only copy, so rebuilding the original Cargo output
path does not silently switch the wallet halfway through the run.

`wallet-freshness.json` records the source identity, copied executable path and
binary hash. The binary hash identifies the checked copy; **it is not itself the
source pin**. The source comparison is mandatory before any Native live command.
A stale binary with a perfectly valid identity response still fails if its
content identity differs. A binary lacking the protocol fails rather than being
accepted for backward compatibility. No automatic rebuild hides this failure.

The claim is wallet-source freshness, assuming the normal trusted Cargo/compiler
build and a stable source tree during compilation/run. This is not a reproducible
build certificate, a malicious-toolchain defense, or a pin for Native binaries.
Registry/git dependency identities are bound through Cargo.lock and verified by
Cargo's locked/offline build; external cache bytes, compiler and environmental
flags are not independently attested. Adding a local dependency outside these
two source roots requires extending this input boundary. The two current crates'
local dependencies are within it.

## Executed controls

Default CTest `test-workchain-wallet-freshness` builds a real release wallet in
an isolated source copy. It uses no fake successful wallet to establish the pin.

1. Compile and pin original source; identity response exits zero.
2. Change one character of the withdrawal-opening domain, preserving its length.
   Keep the original binary. It still returns its identity successfully, but
   `WALLET_FRESHNESS_MISMATCH` rejects at the source comparison before a request.
3. Run the actual live entry point with that stale binary: the same pin rejects
   before the first Native backing control. Missing Native tools are not counted
   as a successful negative control.
4. Disable the pin in the observer while keeping the stale binary: the observer
   raises `STALE_WALLET_ACCEPTED`. Separately bypass the actual live pin assignment
   using its AST semantic location: the live observer raises `LIVE_PIN_NOT_ENFORCED`;
   a later unrelated failure does not satisfy the pin oracle.
5. Rebuild changed source: new wallet pins and executes a real key request.
6. Restore source: original wallet pins again; changed wallet is now rejected.

These are fresh checks, including the configured default CTest run. They are not
new full live, epoch, or scenario executions. The tests' observation surface is
source identity, the actual copied executable's identity response, and entry-point
rejection before Native commands. They do not examine authenticated account state.
The identity algorithm has no error-string mutation anchor: the controls break
source correspondence or remove the pin operation; error markers identify the
layer observed, not the source edit to apply.

## Consumer dispositions (not bundled as closed)

| Consumer | Disposition |
|---|---|
| test/uno-m3-live.py and its uno_m4_live_sequence wallet calls | Mandatory pin before any Native work; all wallet commands receive the pinned copy. |
| test/uno-m3-scenario.py | Same mechanism, applied after its explicit Cargo build; passes pinned copy to the scenario executable. Native executable freshness remains separate. |
| crypto/test/workchain-key-epoch-behavior.py | Same mechanism after its separate epoch-wallet Cargo build; no inference that refreshing this output refreshes live's other output. Native scenario freshness remains separate. |
| test/uno-m3-vectors.py / m3-vectors | Explicit build-before-generation consumer, not a live wallet. No new runtime source pin claimed for this different example. |
| crypto/test/workchain-withdrawal-account-controls.py | Historical schema3 semantic mutation/anchor is stale for schema4. Wallet pin does not fix it; current-schema negative-control successor remains outstanding. Do not count its pre-D78 source as current D78 evidence. |
| Native test-m3-live, test-tos-collator, scenario binaries and cached link archives | Not bound by this Rust wallet pin. Build-path/CMake identity and dependency rebuilds are different evidence; no new executed-source guarantee claimed. |
| Pinned historical D64/D78 replay drivers and frozen measurements | Retain their own archived-source applicability. Not retargeted or re-certified by this work. |

The consumer scope is the direct inventory in uno-m5-d78-consumer-inventory.md,
not a repository-wide claim about all binaries or external runtime dependencies.
In particular, the stale manual account mutation is a semantic-porting obligation,
not a missing-wallet-identity problem. It has not been made green by relabeling it.
