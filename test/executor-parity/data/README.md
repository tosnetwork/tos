# Quantum Module public input fixtures

These two family-private files bind the original Module transaction scenarios in
both diagnostic and generated-candidate modes. They are additional test inputs;
they never replace the ordinary fresh native signing path or native output roots.

- `wallet-module-inputs.json` (38,940 bytes): original configuration identities,
  ordered input Account/context profiles, seven signature request identities per
  mode, compact complete message bindings and authored resulting-state hashes.
- `wallet-module-signatures.json` (105,064 bytes): the seven actual public native
  signatures per mode from the original baseline. Public keys are deduplicated in
  the first file. No private keys or native expected transaction roots are stored.

The original scenario and public-signature baseline is
`7da918d588e8e08c71d4ecf3fcfd89185fb62470`. Input schema v2 records this as
`scenario_source`, separately from `configuration_source`, the integrated-source
generator commit `7cfdfa80c85581d0b406046382e2d442da9ff690`. The signature file
retains its original source. Only the candidate mode's two configuration identities
change after the epoch-6 genesis template update (new CP5, CP10 critical set,
CP13 complaint deposit, CP18 storage prices); all diagnostic identities, recorded
inputs and native outputs remain unchanged. Fresh unsigned bindings and ordered
public request identities were independently rechecked with the original builders.

Initial construction inputs/script are indexed in
`memo/vm-parity/probes/2026-10-27-quantum-module-roots-local-index.json`.
Current-source generator, original baselines and identity-refresh evidence are
retained under `/datax/vm-parity-20261026/p1a/current-main-integration/` and indexed
by the current-main integration probes. The retained refresh command is:

```
/datax/vm-parity-20261026/p1a/linked-python/bin/python \
  /datax/vm-parity-20261026/p1a/refresh_current_main_root_profiles.py
```

The refresh uses the original committed profile plus independently executed
current-source original-builder captures. It checks recorded context/output byte
identity, actual fresh unsigned bindings, unchanged seven public calls and the
new full/dictionary configuration roots before writing the input profile. It does
not rewrite the opaque public signature file. Retain indexed inputs/tools through
review/merge. New production signatures deliberately use fresh randomness;
reproducing this fixed replay requires the committed public signatures.

A direct message fixes all header/body bits and reference counts, the unsigned
request hash, extra-reference hashes and the exact indexed signature derivation.
A relay fixes the message to the unique outgoing message of an earlier fully
validated transaction in the same group. Public signature call consumption is
checked independently of repeated message uses. Only the original deliberate
first-bit corruption varies a signature. Every actual BOC uses the shared bounded
decoder with recomputed cell hashes.

The additional recorded-signature lane still executes the original scenario
builders, native C++ VM and Rust executor, including original behavior assertions
and recipient-update deletion control. Its input/config/native/root artifacts
must agree exactly across architectures. Ordinary fresh signatures are checked
against each run's actual messages; fresh transaction hashes need not be equal
between architectures. Full-root comparison does not normalize either output.
