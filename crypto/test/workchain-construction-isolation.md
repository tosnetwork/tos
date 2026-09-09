# Private construction-isolation unit

D47(a) only. No workchain activation, consensus authority, persistent decision,
restart guarantee or I13e acceptance is claimed. The production context and cost
limits are documented in `../block/workchain-candidate-construction.md`.
The original D47 assertion source is retained; it is not given a fabricated
coverage-complete adapter. Live consumer/metadata/budget integration remains open.

## Reproduction

Run from the committed tree with a fresh work/output directory:

```
python3 crypto/test/workchain-construction-isolation.py \
  --build /tmp/uno-m1-i13-build \
  --work /tmp/uno-construction-control-work \
  --output /tmp/uno-construction-control-evidence
```

The runner builds with `-j32`. It requires working sources to equal committed
blobs. A normal-source build creates four immutable byte oracles once; every
subsequent process is checked against their original SHA256 values. Mutant
executions cannot regenerate them. Missing oracle files fail with numeric
identity 92. Empty stdout/stderr files are archived, not omitted.

Only one source copy is changed at a time. Dependency output must contain that
copy for a mutant and the real production paths for all other headers. Baseline
and restored builds must not include shadow headers. Every record binds the
commit, path, git blob OID, original/copy-before/mutant/restored SHA256 and a replay
of the replacement on restored bytes. Build failure cannot satisfy a control.
A final run checks every case again using the real source paths.

## Cases and attribution

Case 0 installs one complete supplied generation after 23 observations of the
old one. Cases 1–23 each return a distinct injected numeric Status at one actual
checkpoint. Native participant commit/AccountBlock/account-root operations occur
three times, import insertion twice, outgoing descriptor/queue insertion three
times, and the six late positions once. The recorded prefix must equal the
explicit schedule, not merely have the expected length.

All stage failures require byte-identical actual candidate state and messages.
The observer reads the installed candidate and invokes the same-block message
reader during construction. It records sticky observations before looking at
the return code. After failure, the same reader is polled again after private
temporaries have been destroyed; no deferred orphan may appear. No live message
transport is created or invoked.

The direct-live controls expose draft state/messages at value-flow freeze and
immediately before installation, then induce the specified failure. Identity 82
requires **both** an intermediate state change and an intermediate message
change. The runner additionally requires both changes to remain in the actual
final snapshots in those controlled executions. Identities 80/81 distinguish
state-only/message-only observations; 83 detects final residue without an
intermediate observation. Omitting installation fails 86; omitting successful
messages fails 87. Thus a generic return-code failure cannot satisfy the bypass
controls.

Cases 24–33 cover exception cleanup, ignored observer failure, stale predecessor,
reentrancy, preservation of a supplied count, freezing mutable message providers,
omitted roots/messages/identity, and ordinary returned builder failure. Case 28 intentionally supplies count 19:
carrying that value proves that construction does not replace I13a's independent
checker; it is not a claim that such a block is valid.

| Numeric identity | Guard calibrated by source replacement |
|---|---|
| 71 | A returned builder error is not swallowed |
| 74 / 75 | Required message / state observation actually ran |
| 76 | Concrete stage schedule, including each repeated occurrence |
| 82 | Both actual intermediate candidate and same-block messages changed |
| 83 | Failed construction left final residue |
| 86 / 87 | Successful state / message installation matches the frozen oracle |
| 90 | Initial actual candidate matches the frozen input oracle |
| 94 | An ignored observer failure still prevents installation |
| 95 | Expected predecessor matches this context's current snapshot identity |
| 96 | Nested construction cannot install another generation |
| 97 | Supplied count is not normalized by construction |
| 98 | A provider's mutable message elements cannot change a frozen list |
| 99 | Missing supplied components prevent installation |
| 100 | Exception unwinding releases the construction guard |
| 101 | Failed construction preserves the actual predecessor snapshot identity |
| 102 | Intermediate replacement with byte-identical state is still observed |

Snapshot identity is observable through the context's predecessor check. Equal
bytes alone therefore do not establish zero residue. Two additional controls
replace the snapshot with a byte-identical generation: one inside a stage (102),
one after a returned failure (101). Neither changes the message or state bytes.
The logs record the actual stage sequence and Status code; an exception is
separately recorded as identity 124 with `status_returned` false.

Several removed stage hooks fail 76: they intentionally exercise the same
schedule-completeness guard from different sites, not independent safety layers.
The combined message/identity presence check similarly shares 99 between two
inputs. The two direct-live controls exercise the same sticky observation guard
at different stages. No duplicated numeric identity is counted as a new layer.

## Limits

The fixture constructs real Native accounts, participant records, imports,
normal/deferred queue records, ValueFlow, ShardState and MerkleUpdate cells. Its
late assembly routines are private test providers. They are not the collator's
complete processing metadata, live final budget, or exhaustive consumer mapping.
The size bound is a fixture check, not an authenticated D31 budget. Input/role
admission and message authorization are preconditions, not properties established
by these isolation tests. Native builders and the frozen oracle share a base;
this is not independent semantic validation of those builders.

Snapshots held by arbitrary live consumers, aggregate pending-message copying,
and live host closure/budget accounting remain resource-integration obligations.
Storage transaction/recovery positions 22 and 25 of the historical matrix belong
to D47(c) and are not silently skipped inside this unit's 23-position claim.
