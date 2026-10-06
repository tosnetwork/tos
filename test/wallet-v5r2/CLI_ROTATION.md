# Installed fee-route promotion and repeated recovery

`cli_rotation_controls.py` exercises the actual `tosctl` fee-session commands,
native PQ signers, encrypted custody files, exclusive fee journals and native
full transactions. It covers two consecutive recoveries using three separately
derived H20 fee trees. All mnemonic material is an existing public test vector.

The account-proof verifier is the explicit local fixture adapter. Transaction
history comes from a local fixture RPC server, and its BOCs are checked against
the supplied authenticated-account capability. Native execution uses diagnostic
global version 17 with external credit 20,000. This fixture is evidence of the
client's binding, custody and transaction behavior; it does not establish live
proof acquisition, relay admission, broadcast, finality or remote-device
revocation. Release candidate gas/configuration evidence is separate.

## Client behavior

An attached successor remains a possession-proof route. Signing or submitting a
migration does not activate it. A `promote` request reads the wallet and module,
requires the successor tuple to be installed, checks epoch advancement and
retirement preservation, and reads the fee account at that same authenticated
checkpoint. The fee read is historical and is authorized only by the matching
fresh live wallet proof under the same trust anchor. Two independently chosen
live checkpoints are not substituted for that binding.

Promotion writes the birth manifest, installed successor manifest, pinned code,
public fee-key history and `resume.json` before switching the local route. The
export is re-read and reconstructed before either journal changes ownership.
The successor's already-open journal becomes current, and each previous journal
stays exclusively held until the process exits. No journal is reopened to
perform promotion. Old-route status, retry and signing requests check the
wallet's installed tuple and refuse after installation changes it.

`resume.json` contains argument arrays and absolute custody paths, without
decrypted key material. Relative command inputs are resolved against the
session's working directory without adding an existence check. The fixture
starts with relative paths and restores the export from a different directory.
The installed arguments still require a fresh wallet proof on reuse.
The fixture copies encrypted custody files, restarts with the same durable
journal, observes its restore wait and recovers an identical already-signed
message from the cached intent. It never copies an active journal to manufacture
continuity. An `execute` request on the installed fee route signs a strict
OutList through the SLH signer. The test follows its actual fee, module and
wallet transactions through recipient execution. The first recovered wallet
also funds its next recovery through a real signed wallet action.

The public history contains canonical LMS public-key cell hashes, including the
birth route and each locally known installed route. Installed command arguments
require retained history. A running session retains the keys enrolled at session
open and promotion in memory, so editing a public history file cannot remove an
intermediate key from that session's reuse check. The exported file carries this
history across restarts.
The list is bounded to 64 distinct keys; a session retains at most 32 previous
journal locks. Preparation and attachment require a free history slot, and
migration rechecks history capacity after attachment. A full history is refused
before a migration fee signature can install an unexportable route. Attachment
also checks the journal bound, with a defensive check retained at promotion.
The history-capacity fixture fills a valid file with public synthetic hashes;
the journal-capacity unit exercises 31/32 and oversized counts. A separate
private build lowers only the journal limit to zero, then checks that a valid
Attach request refuses before opening the successor journal. Deleting the
Attach call in that same private build must trip the named CLI assertion;
the defensive Promote call stays present. The production limit remains 32.
These tests do not claim to perform 33 or 64 native rotations. This is local known-history
protection: a deleted
or replaced backup cannot prove unknown historical keys, and this public file
is not a global authenticated anti-rollback record.

## Fixed-slot clock fixture

The production slot remains 3,600 seconds, and production clock code and journal
guards are unchanged. On Linux, `rotation_clock.c` moves only fixture subprocess
wall clocks across the restore boundaries. Monotonic deadlines remain real.
The production proof runner clears its child environment; the mock verifier
therefore reads the same fixture offset explicitly instead of weakening that
isolation. The fixture observes the clock change in a separate subprocess
before trusting it. Native transaction time is explicitly set to the fixture
clock before executing newly constructed accounts.

## Reproduction

Use the existing CLI build and native tool environment from
`.github/workflows/rescue-context.yml`. The old and first successor trees are
shared with the existing migration tests. Generate the third tree once:

```sh
python test/wallet-v5r2/fee_recovery_fixture.py \
  --vector-index 0 --key-generation 8 \
  --tree-id a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7 \
  --output artifacts/context/second-successor-fee-recovery-fixture
python test/wallet-v5r2/cli_rotation_controls.py \
  --cli "$CARGO_TARGET_DIR/debug/tosctl" \
  --genesis-driver "$CARGO_TARGET_DIR/debug/examples/v5r2_genesis_encode" \
  --fixture artifacts/context/r2-fee-prepare/native/sdk-genesis.json \
  --fee-session-tree artifacts/context/fee-recovery-fixture/PUBLIC-TEST-ONLY-tree \
  --successor-fee-fixture artifacts/context/successor-fee-recovery-fixture \
  --second-successor-fee-fixture artifacts/context/second-successor-fee-recovery-fixture \
  --output artifacts/context/cli-rotation-controls
```

Run this runner exclusively. Its default selects all 14 source mutations;
`--case` can select named mutations for a targeted rerun. It temporarily edits one Rust source guard at a
time and rebuilds the relevant boundary. A failed compilation or timeout is
never accepted as a sensitivity result. Its finalizer restores every source,
rebuilds, runs checkpoint and journal-capacity units plus the native migration
and same-module rollover regressions, then repeats the full two-rotation flow.

| Boundary | Expected observation after removing its guard |
| --- | --- |
| Installed wallet tuple | Premature promotion of a proposed tuple trips the named CLI assertion. |
| Predecessor epoch | Regressed epoch is accepted and trips the epoch assertion. |
| Retirement preservation | Lost retirement bits trip a separate assertion with epoch still valid. |
| Previous journal ownership | A competing process obtains the old journal and trips the exclusive-lock assertion. |
| Historical fee selector | An advancing live fee checkpoint causes the valid promotion assertion to fail. |
| Retained fee-key history | A previously installed intermediate tree reaches the named history assertion. |
| History retained on restore | Rewriting the public history after session start trips the memory-retention assertion. |
| Absolute export paths | Starting with relative inputs trips the export assertion when path resolution is removed. |
| Successor history capacity | A valid history with 64 public hashes passes preparation and trips the preflight assertion. |
| Migration history capacity | Filling history after attachment reaches migration and trips the separate preflight assertion. |
| Previous journal count | Removing the production 32-bound comparison trips the 31/32 boundary unit. |
| Early journal capacity check | In a private limit-zero build, deleting only the Attach call accepts the valid successor and trips the entry-point assertion before migration. |
| Live checkpoint source | A historical source authorizes historical fee state and trips the unit assertion. |
| Authenticated checkpoint equality | Different anchors pass the equality helper and trip both checkpoint-binding tests. |

The runner emits bounded result metadata with exact commands, source and binary
hashes, exits, log hashes and semantic failure excerpts. Native transaction
receipts and build logs remain run artifacts; H20 trees, encrypted custody
files, and fee journals are not committed as evidence.
