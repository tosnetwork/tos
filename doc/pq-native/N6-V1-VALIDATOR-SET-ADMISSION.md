# V1: PQ validator-set pre-install parity

Status: **both live installation routes repaired locally, correctness question OPEN
pending fixed-head CI and rule-parity review**. This is contract/node
rule parity, not an observed masterchain halt. C01 was a source review; C07's
independent compiled-contract and node-decoder results are in
`/home/tomi/memo/pq-native/N6-MAC-C07-RESULT-20260924.md` and its hashed data
directory.

## Counts and direct results

| Rule | Old compiled config contract | Node decoder | Repaired Elector installation path |
|---|---|---|---|
| Two distinct PQ validators claim one nonzero ADNL | installed (`0xee764f4b`) | rejected | refused (`0xee764f6f`); ConfigParam 36 absent |
| Total weight exceeds `UINT64_MAX/3` | installed (`0xee764f4b`) | rejected by `checked_add_validator_weight` | refused (`0xee764f6f`) |
| Total weight equals `UINT64_MAX/3` | not the defect | accepted by the bound | installed (positive boundary control) |

The local old-code RED was the same real-contract sandbox
`a_set_the_node_would_refuse_is_refused_before_it_is_installed`: first it
reported `a set assigning one ADNL identity to two validators was installed:
[ee764f4b]`, then, with that row temporarily ordered later, reported `a set
exceeding the validator-weight protocol cap was installed: [ee764f4b]`.
The honest control and four pre-existing malformed-set rows passed before both
new rows. With the contract fixed, the expanded table passes. The positive
equal-to-cap control passes, so an off-by-one refusal is also visible.

`an_elected_set_with_duplicate_adnl_is_refused_before_installation` follows
the actual Elector route: four distinct PQ stakes receive `STAKE_ACCEPTED`,
two claim one ADNL, the Elector constructs the set, and the config contract
returns `VALIDATOR_SET_REFUSED` without writing ConfigParam 36. Removing only
the contract's duplicate-ADNL refusal made this test RED with
`[4e565354, ee764f4b]`: Elector's set-next message followed by installation.
Removing only the weight-cap check made the over-cap row RED with
`[ee764f4b]`. Both mutations were restored before the final checks.

The Elector-only repair compiled `config-code.fif` to SHA-256
`047ddbe08f6633469130a0d886430c7454fe3a34b7160d85cbae8376f880e15e`.
The later Elector-plus-governance repair compiled it to
`95bbfa11e05dfc49d7a89bfbdd7055e03f920785f7d0c8c688899c6b35fa47b2`;
the unchanged `elector-code.fif` is
`fc41a49427042f0e4cf3e2fa8f96a45a583d6966271834332c69518e4866e08d`.
The pre-fix config Fift in C07 was
`c58e86672c59f5baa51c75ce368a9ba4966d7f6fed33cb9a6f68c8a536f9fb45`.
The exact-head C++ `test-validator-identity` binary (SHA-256
`5bfa6139ef9b98e0c6891d95fc1b6487ed3420b9a41a3f4ae42650e34796a5d1`)
passes its vector suite, including `duplicate-adnl reject`. C07 additionally
verified its *same* BOC was
installed by the old contract and rejected by the node; the two C07 BOCs
differ only in the second descriptor's 32-byte ADNL field.

The branch source guard checks these two exact contract rules against the
node-side source and is killed separately by deleting either refusal. It is
not a substitute for the sandbox: the sandbox is what proves the compiled
contract's reply and storage effect. After the governance repair, the full
local `elector_sandbox` run had 69 passes and 3 unrelated existing failures.
Two of those still demand
100/400-validator elected sets despite the enforced 21-validator launch cap;
the third is the controller-policy proposal fixture. The three are not
evidence that either new negative failed.

## Remaining installation boundary

The Elector's `set_next_validators` route invokes `check_validator_set`. The
separate validator-governance `install_param` route for ConfigParams 34–37
originally invoked `valid_live_validator_set_limits?`, which only checks header
counts. A compiled sandbox with a real current PQ set and current-set votes
confirmed the distinct route: an honest ConfigParam 36 was decided and
installed, but so was a duplicate-ADNL set (`Governed { decided: true,
installed: true }`). This was a RED result even after the Elector route was
fixed. The governance route now calls the full check for non-null sets and
refuses a duplicate ADNL or over-cap total; optional-set deletion retains its
previous null behavior. It consumes the check's returned times in a condition.
An earlier version merely called the pure check and ignored its return values;
FunC optimized that call away, and the same sandbox stayed RED. Replacing the
condition with `valid = true` makes both the branch source guard and the
sandbox RED, naming the duplicate-ADNL ConfigParam 36 installation.

The node-side audit of this loader found the other enforced PQ requirements:
well-formed `validator_pq` descriptors, admitted algorithm and key length,
derived key ID, nonzero validator ID/ADNL/weight, unique validator/key/ADNL,
contiguous indices, matching total weight, and the `UINT64_MAX/3` cap. The
contract's `pq::parse_descriptor` handles descriptor shape, algorithm/key,
derived ID and nonzero fields; the pre-install loop handles uniqueness,
indices, weight sum and the cap. Counts and launch limits are also checked.
The source guard names only the newly added ADNL/cap rules and both call paths;
it does not claim to prove this entire audit.

## Shared node-vector behaviour on both contract paths

C02's independent first attempt showed why the old node vector file could not
be fed directly to a launch config contract: its one- and two-member sets
violated launch Param16's four-member minimum, and its `100..200` interval was
already past the Elector's clock. All fourteen rows were refused, including
`valid`; those refusals proved nothing about descriptor parity. The original
file and raw verdicts remain in C02's hashed interim artifact. The old row
named `declared-total-mismatch` actually changed *weight*, not validator count.

The generator now emits four distinct PQ members and a future interval for
every row, keeping each original defect in its descriptor. It names the weight
case correctly and adds independent zero-total-weight, missing-count,
index-gap, zero-main, main-greater-than-total, malformed-key-encoding,
wrong-descriptor-tag and trailing-descriptor-bit rows. The result is **one
22-BOC table** read unchanged by the production C++
`Config::unpack_validator_set` test and by two compiled-contract sandboxes:
Elector `set_next_validators` and validator-governed `install_param(36)`.
Neither sandbox lowers Param16 nor rewrites a BOC. Each Elector row starts with
an empty ConfigParam 36; each governance row starts from a fresh current PQ
set. The `valid` row is accepted and stored on both paths before the twenty-one
rejection verdicts are counted.

The exact local commands `build/crypto/pq/test-validator-identity
test/pq-native/validator-set-cases.txt` and `cargo test --manifest-path
tosctl/src/Cargo.toml -p contracts --test elector_sandbox
node_validator_set_vectors_match --locked` pass. The generator consistency
check also passes. Removing only the contract's duplicate-ADNL refusal makes
both new sandbox tests fail at `duplicate-adnl` with installation replies;
forcing governance to refuse every set fails its test at `valid` with
`decided=true, installed=false`. Restored contract Fift SHA-256 is
`95bbfa11e05dfc49d7a89bfbdd7055e03f920785f7d0c8c688899c6b35fa47b2`.
The branch source guard pins the presence of both shared-vector test entries
and the named 22-row table; it does not run either sandbox in branch CI. The
regenerated table SHA-256 is
`5bdebc0253b59172387cc634627601fa38b3ce3174c68865be47ca88c394f9a6`.
Mac's independent 22-BOC review is retained at
`/home/tomi/memo/pq-native/N6-MAC-C02-VECTORS-RESULT-20260924.md`
(`memo/main@4f9241e6`, 66/66 artifact hashes): the `valid` set installed
through both compiled-contract routes, all 21 negative sets were refused by
both, and the node's 44 normal/inverted verdict checks agreed with the table.
The old contract was RED on each route. This is independent behavior evidence,
not a substitute for exact-head CI.
The contract-sandbox workflow now treats either the table or its generator as
a trigger on PRs and integration-branch pushes; the branch source guard checks
both trigger lists so a vector-only edit cannot silently bypass that suite.

The first exact `19f5b3406` contract-sandbox CI run failed its recorded-answer
step, not a validator-set verdict: recompiling the changed config contract
changes the config-upgrade proposal BOC and production zerostate BOC. The two
`test-smartcont` answer hashes were re-derived from that tree's Fift output:
`127397e81a78203935b999be80be537557f440bf7f0d228dc62598656856f5ed`
for the governance upgrade proposal and
`ef8a33e7a129642a6784eaff85098dcda13377c3343be9c5041886227f43651a`
for the zerostate. The corrected local `check-regression-db.sh` run says every
recorded answer is verified and unchanged. This CI failure is retained rather
than counted as a passing run; the corrected head still needs exact-tree CI.

The `pq-validator-set-installation-parity` question remains OPEN until the
corrected-head CI result is recorded. No
deliberately malformed set has been installed on a real network, so chain-halt
impact remains a source-and-decoder inference, not a run observation.
