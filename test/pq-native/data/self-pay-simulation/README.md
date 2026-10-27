# Public native simulation inputs

These are thirteen bounded test inputs, not a saved run. They cover both public
signing roles, prefunded deployment, replay/forged-signature/domain refusals,
native-coin sending, an ACCEPTed failing request, and 255 outgoing actions.
The signing seeds are the existing public hexadecimal11/22 fixtures. No private
wallet or network credential is included.

The TSV stores Account BOCs, not authenticated ShardAccount metadata. The native
test explicitly constructs synthetic history/target/previous-block observations
and derives a distinct transaction LT; these inputs do not establish a live
proof, phone custody, delivery to the recipient or production acceptance.
Small reference balance/phase/output-count assertions are retained for the three
action cases. They are not real network fee quotes or an admission margin policy.

Regenerate with `scripts/update-self-pay-simulation-fixtures.py`, passing the
source-built `--func`, `--fift`, `--emulator`, `--mldsa-tool`, `--slh-tool` and
`--output test/pq-native/data/self-pay-simulation`. The generator recompiles the
contract, requires the fixed execution profile to match, and uses the real
signature-verifying emulator before retaining the input matrix. Its temporary
public signing material and full run outputs are not committed.

`scripts/check-self-pay-simulation-fixtures.py` checks the bounded matrix and
recorded source/file hashes. The Explorer registry's source-generated contract
test independently checks the shared code-profile hash. Update these fixtures
deliberately when their source closure changes. This does not replace fresh
supported basechain proof+execution, full CMake/native/platform builds, resource
acceptance or the complete mobile delivery matrix.
