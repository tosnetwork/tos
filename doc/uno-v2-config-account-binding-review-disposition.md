# Configuration-sourced account binding

The explicit registry wrapper derives Config12 and Config84 from the same
supplied Config snapshot. It does not authenticate that snapshot, establish
resource policy, register an engine at startup or enable generic dispatch.
The direct descriptor-binding API remains a lower-level staging primitive.

Verbatim review: `~/memo/reviews/uno-v2-config-account-binding-review.txt`.
The reviewer read code and did not run builds/tests. The initial positive
test failed against a compiled stub at `from_config.is_ok()`.

Accepted review changes:

- Require locally unpacked workchain information before reading the map. The
  same reasoning also requires unpacked capabilities: both getters are populated
  conditionally in Config. Missing either requested mode is an existing
  LocalUnavailable status, not evidence that the chain omitted the descriptor
  or disabled the feature. Tests contrast each incomplete mode with a genuinely
  absent entry in a fully unpacked snapshot, without comparing error strings.
- Remove repeated null/key checks: Config's parser only inserts successful
  non-null entries and assigns their workchain identity from the dictionary key.
  Do not invent malformed-wire witnesses for those unreachable states. The
  existing generic normalizer is unchanged.
- Add unsupported-engine, nonzero descriptor-version/mode preservation, and
  nonzero address-width assertions. Callback counts prove early failures do not
  reach engine configuration or account execution.

No amount or metering arithmetic, wire definition or resource value is added.
Engine/cell exceptions still propagate to the source-aware enclosing boundary.
The new mode check does not authenticate public mutable Config fields; callers
must supply an intact, authenticated snapshot with the requested unpack modes.
Missing entries remain binding failures, not a universal candidate verdict.
M1 live integration is still incomplete.

Four independently rebuilt controls failed: omit local unpack-mode detection,
replace the normalized descriptor version, replace its mode, and erase its
address width. Their verdict/numeric assertions do not compare error text.
After restoring source, production validator and test targets rebuilt; four
unit/configuration/disk CTests passed (5.21 seconds). Exact source diff,
substitutions, raw output and artifact hashes are recorded in
`measurements/uno-v2-config-account-binding-evidence.json`. Mutations remain
manual; no claim is made that every field or redundant rejection is covered.
