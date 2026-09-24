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
The existing C++ `test-validator-identity` vector suite passes, including its
`duplicate-adnl reject` case. C07 additionally verified its *same* BOC was
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

The `pq-validator-set-installation-parity` question remains OPEN until the
fixed-head CI result and the independent rule-parity review are recorded. No
deliberately malformed set has been installed on a real network, so chain-halt
impact remains a source-and-decoder inference, not a run observation.
