# V2 resource-policy wire boundary

In-flight D31 implements the resource object and the approved two-reference
engine-configuration framing, not complete authenticated admission. Version 2
is approved for multiaccount admission; version 1 retains its single-candidate
prototype meaning. Neither value is an implicit configuration default. The
version-2 installation gate is connected through `valid_config_data`; the
complete admission path remains unimplemented.

The five constructors omit explicit tags in `crypto/block/block.tlb`; `tlbc`
derives CRC32 tags from its normalized constructor definitions. Recompute with:

```
build/crypto/tlbc -vvv -q -t crypto/block/block.tlb
```

| Constructor | Tag | Bits / refs |
|---|---|---|
| uno_v2_resource_policy | bbd8a9ec | 64 / 3 |
| uno_v2_resource_input | c5defa2a | 320 / 0 |
| uno_v2_resource_state | 90aef2dd | 304 / 0 |
| uno_v2_resource_work_output | 7a310b92 | 384 / 0 |
| uno_v2_engine_configuration | b7226bea | 32 / 2 |

Each is the sole constructor in its own union; all five tags are distinct and
occur once in the generated constructor-tag tables. The resource object alone
has four cells, 1,072 bits and depth one, excluding framing and business
parameters. Encoding preserves the approved integer
widths, including full uint64 limits and uint32 admission_version. This is not
an input-budget measurement or a deployable capacity figure.

`WorkchainResourcePolicy` is explicitly unresolved wire data. Parsing accepts
representable zero or unknown-version fields without declaring them valid
configuration or supported execution. Installation must separately validate
limit combinations, version capability, compatibility with persistent state
and atomic migration. No live caller is allowed to substitute this parser for
that validation. The framing contains mandatory resource and business-parameter
references, in that order. Business parameters are opaque to the host; the
engine must require their own versioned tag and validate their full contents.
No missing reference selects defaults. Host-visible additions require a new
framing version. This framing does not reinterpret singleton engine payloads.

Resource decoding loads four slices; framing adds one. Business-parameter
decoding is a separate engine responsibility. Exact consumption is required.
It uses generated field/tag unpacking, not the generated quiet cell loader.
Malformed encoding returns an error; acquisition/allocation exceptions remain
exceptions for the provenance-aware caller. There is no new consensus error
category or blanket catch. Special-cell type bytes cannot equal any of these
constructor prefixes, so tag validation excludes them without a redundant
special guard. The ordinary/special-aware loader never resolves a library ref
as code to execute.

The in-memory `InputPolicyIdentity` admission_version is widened to uint32,
matching the existing 32-bit host commitment field. High-bit values must remain
distinct, never aliasing 1 or 2. Wire round-trip tests cover 2, 0x10002 and
0x80000002 without claiming support for those unknown versions. No singleton
wire encoding is modified.

The configuration boundary rejects unsupported admission versions, malformed
framing and zero input cells/bits/roots. Binding derives its immutable policy
identity from the same Config root and descriptor. A corrupt authenticated
resource payload is not a candidate-invalid result; unsupported local execution
capability remains local unavailability. The singleton policy type is separate.
This does not yet validate all resource-limit combinations or business parameters.

The complete test configuration exercises `valid_config_data`, including its
mandatory Native parameters and matching descriptor. Removing its resource-gate
call accepts an unsupported version and fails a Boolean acceptance assertion.
Each zero-limit conjunct and the independent identity-version guard also has
a separately rebuilt negative control. Evidence is in
`measurements/uno-v2-resource-policy-wire-evidence.json`. These are manual runs,
not recurring CI mutation jobs. Earlier sections of that artifact retain their
historical source hashes and scopes; they are not snapshots of the final tree.

Remaining D31 integration: complete installation/transition consistency;
one immutable policy through both live entry points; `3 + N_inbound` logical roots and deduplicated
physical closure; bounded inbox construction; state, proof-work and output
budgets; finality representation; full M1 stage-order and atomicity tests.
Fee units must not substitute for proof-work units. Codec tests do not close
any of those live integration gates.
