# Fift Validator and Proposal Library API Draft

## Purpose

This document records a concrete API draft for the next two candidate Fift libraries:

- `Validator.fif`
- `Proposal.fif`

The goal is to separate reusable protocol encoding from script-local CLI handling.

This document follows the same first-principles approach used in
[`fift-library-gap-analysis.md`](./fift-library-gap-analysis.md):

- library code should own stable protocol objects
- scripts should mainly own argument parsing, help text, and file naming
- shared encoding logic should not remain duplicated across operational scripts

## Scope

This draft covers:

- validator election request encoding
- validator vote request encoding
- signed validator message construction
- governance proposal body construction
- elector complaint envelope construction

It does not attempt to redesign:

- existing wallet libraries
- zerostate/state libraries
- script CLI UX

## Design Rules

The proposed split uses four rules.

### 1. Keep protocol encoding in libraries

The libraries should own:

- exact byte layout
- exact cell layout
- query id derivation
- signature verification helpers

The scripts should keep:

- `GetOpt` handling
- positional argument parsing
- help text
- default output file names
- human-readable logging

### 2. Reuse existing libraries instead of duplicating them

The new libraries should build on top of the current library surface:

- [`Key.fif`](../crypto/fift/lib/Key.fif)
- [`Addr.fif`](../crypto/fift/lib/Addr.fif)
- [`Currency.fif`](../crypto/fift/lib/Currency.fif)
- [`Msg.fif`](../crypto/fift/lib/Msg.fif)

In particular, `Validator.fif` should reuse `parse-val-pubkey` from
[`Key.fif`](../crypto/fift/lib/Key.fif) instead of redefining validator public-key parsing.

### 3. Keep time-dependent values explicit

Library words should not call `now` internally for protocol construction.

Instead, the caller should pass:

- `query-id`
- `expire-at`
- `seqno`

This keeps the library deterministic and easier to regression-test.

### 4. Prefer pure encoding words first

The first implementation pass should prioritize words that are:

- pure
- deterministic
- protocol-shaped
- independent from CLI/file handling

File-loading convenience words can be added later.

## Proposed Files

### `Validator.fif`

Responsibility:

- validator request bytes to sign
- validator signature parsing and checking
- signed election body construction
- signed governance vote construction
- signed complaint vote construction

### `Proposal.fif`

Responsibility:

- governance proposal query ids
- proposal reference cell construction
- proposal body construction
- elector complaint envelope construction
- loading helpers for proposal payload sources

## Stack Conventions

This document uses the following shorthand:

- `B` = raw byte string
- `c` = cell
- `addr` = parsed address object usable by `addr,`
- `old-hash = -1` means "no old hash constraint"
- `max-factor` means normalized 16.16 fixed-point value

## `Validator.fif` API Draft

### Existing word to reuse

This word already exists and should remain in
[`Key.fif`](../crypto/fift/lib/Key.fif):

| Word | Stack | Source |
| --- | --- | --- |
| `parse-val-pubkey` | `( S -- B )` | [`Key.fif`](../crypto/fift/lib/Key.fif) |

### Core words

| Word | Stack | Purpose | Move from scripts |
| --- | --- | --- | --- |
| `parse-val-signature` | `( S -- B )` | Parse a base64 Ed25519 validator signature and enforce exact size. | [`validator-elect-signed.fif`](../crypto/smartcont/validator-elect-signed.fif), [`single-nominator-pool/validator-elect-signed.fif`](../crypto/smartcont/single-nominator-pool/validator-elect-signed.fif), [`liquid-staking/controller-elect-signed.fif`](../crypto/smartcont/liquid-staking/controller-elect-signed.fif), [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif), [`complaint-vote-signed.fif`](../crypto/smartcont/complaint-vote-signed.fif) |
| `check-val-signature` | `( to-sign signature pubkey -- )` | Verify validator signature or abort with a protocol-specific error. | Same five signed scripts as above |
| `validator-elect-req>B` | `( elect-utime max-factor src-addr adnl-addr -- B )` | Build the bytestring that a validator must sign for election participation. | [`validator-elect-req.fif`](../crypto/smartcont/validator-elect-req.fif), [`validator-elect-signed.fif`](../crypto/smartcont/validator-elect-signed.fif), [`single-nominator-pool/validator-elect-signed.fif`](../crypto/smartcont/single-nominator-pool/validator-elect-signed.fif), [`liquid-staking/controller-elect-signed.fif`](../crypto/smartcont/liquid-staking/controller-elect-signed.fif) |
| `validator-elect-body` | `( query-id pubkey elect-utime max-factor adnl-addr signature -- c )` | Build the standard signed election message body used by the main validator wallet flow. | [`validator-elect-signed.fif`](../crypto/smartcont/validator-elect-signed.fif) |
| `validator-elect-body+stake` | `( query-id amount pubkey elect-utime max-factor adnl-addr signature -- c )` | Build the signed election body variant that embeds stake amount. | [`single-nominator-pool/validator-elect-signed.fif`](../crypto/smartcont/single-nominator-pool/validator-elect-signed.fif), [`liquid-staking/controller-elect-signed.fif`](../crypto/smartcont/liquid-staking/controller-elect-signed.fif) |
| `config-vote-req-ext>B` | `( seqno expire-at validator-idx proposal-hash -- B )` | Build the unsigned bytestring for an external config vote. | [`config-proposal-vote-req.fif`](../crypto/smartcont/config-proposal-vote-req.fif), [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif) |
| `config-vote-req-int>B` | `( validator-idx proposal-hash -- B )` | Build the unsigned bytestring for an internal config vote. | Same two config vote scripts |
| `config-vote-query-id` | `( proposal-hash -- query-id )` | Derive the stable query id used by the signed config vote body. | [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif) |
| `config-vote-int-body` | `( query-id signature to-sign -- c )` | Build the body of an internal message carrying a signed config vote. | [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif) |
| `config-vote-ext-msg` | `( config-addr signature to-sign -- c )` | Build the external message carrying a signed config vote. | [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif) |
| `complaint-vote-req>B` | `( validator-idx elect-id complaint-hash -- B )` | Build the bytestring to sign for complaint voting. | [`complaint-vote-req.fif`](../crypto/smartcont/complaint-vote-req.fif), [`complaint-vote-signed.fif`](../crypto/smartcont/complaint-vote-signed.fif) |
| `complaint-vote-query-id` | `( complaint-hash -- query-id )` | Derive the stable query id used by the complaint vote message body. | [`complaint-vote-signed.fif`](../crypto/smartcont/complaint-vote-signed.fif) |
| `complaint-vote-body` | `( query-id signature to-sign -- c )` | Build the signed complaint vote message body. | [`complaint-vote-signed.fif`](../crypto/smartcont/complaint-vote-signed.fif) |

### Optional convenience words

These are useful, but they are not required for the first implementation pass.

| Word | Stack | Purpose | Candidate scripts |
| --- | --- | --- | --- |
| `normalize-vote-expire-at` | `( n -- expire-at )` | Normalize the current "absolute or relative" expiration input convention. | [`config-proposal-vote-req.fif`](../crypto/smartcont/config-proposal-vote-req.fif), [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif) |

## `Proposal.fif` API Draft

### Core words

| Word | Stack | Purpose | Move from scripts |
| --- | --- | --- | --- |
| `proposal-query-id` | `( param-idx -- query-id )` | Derive the standard governance proposal query id from the target config parameter index. | [`create-config-proposal.fif`](../crypto/smartcont/create-config-proposal.fif), [`create-config-upgrade-proposal.fif`](../crypto/smartcont/create-config-upgrade-proposal.fif), [`create-elector-upgrade-proposal.fif`](../crypto/smartcont/create-elector-upgrade-proposal.fif) |
| `proposal-param-ref` | `( param-idx param-value old-hash -- c )` | Build the inner reference cell that stores the parameter index, parameter value, and optional old hash guard. | Same three proposal scripts |
| `proposal-body` | `( query-id expire-at proposal-ref critical? -- c )` | Build the outer governance proposal body cell. | Same three proposal scripts |
| `complaint-envelope-query-id` | `( complaint-hash -- query-id )` | Derive the stable query id for an elector complaint envelope. | [`envelope-complaint.fif`](../crypto/smartcont/envelope-complaint.fif) |
| `complaint-envelope-body` | `( query-id election-id complaint -- c )` | Build the elector complaint envelope body cell. | [`envelope-complaint.fif`](../crypto/smartcont/envelope-complaint.fif) |

### Script-loading words

These words are still useful library candidates because the loading semantics are reused and protocol-specific.

| Word | Stack | Purpose | Move from scripts |
| --- | --- | --- | --- |
| `load-proposal-value-or-null` | `( filename-or-null -- c|null )` | Load a new config value from a BoC file, or return `null` when the script uses the literal `null`. | [`create-config-proposal.fif`](../crypto/smartcont/create-config-proposal.fif) |
| `load-upgrade-code-param-value` | `( src-file -- c )` | Assemble a smart-contract source file and wrap the result into the config-parameter value cell shape used by upgrade proposals. | [`create-config-upgrade-proposal.fif`](../crypto/smartcont/create-config-upgrade-proposal.fif), [`create-elector-upgrade-proposal.fif`](../crypto/smartcont/create-elector-upgrade-proposal.fif) |
| `load-validator-complaint` | `( filename -- complaint complaint-hash )` | Load a complaint BoC, validate the outer type tag, and return both the complaint cell and its hash. | [`envelope-complaint.fif`](../crypto/smartcont/envelope-complaint.fif) |

## Intended Script Shape After Migration

After this split, the scripts should become thin wrappers.

### Validator election scripts

These scripts should mostly reduce to:

- parse CLI values
- normalize `max-factor`
- parse addresses and keys
- call `validator-elect-req>B`
- call `check-val-signature` when needed
- call `validator-elect-body` or `validator-elect-body+stake`
- print and save the result

Target scripts:

- [`validator-elect-req.fif`](../crypto/smartcont/validator-elect-req.fif)
- [`validator-elect-signed.fif`](../crypto/smartcont/validator-elect-signed.fif)
- [`single-nominator-pool/validator-elect-signed.fif`](../crypto/smartcont/single-nominator-pool/validator-elect-signed.fif)
- [`liquid-staking/controller-elect-signed.fif`](../crypto/smartcont/liquid-staking/controller-elect-signed.fif)

### Governance vote scripts

These scripts should mostly reduce to:

- parse CLI mode and arguments
- build `to-sign` with `config-vote-req-ext>B` or `config-vote-req-int>B`
- validate signature with `check-val-signature`
- build the final body with `config-vote-int-body` or `config-vote-ext-msg`
- print and save the result

Target scripts:

- [`config-proposal-vote-req.fif`](../crypto/smartcont/config-proposal-vote-req.fif)
- [`config-proposal-vote-signed.fif`](../crypto/smartcont/config-proposal-vote-signed.fif)
- [`complaint-vote-req.fif`](../crypto/smartcont/complaint-vote-req.fif)
- [`complaint-vote-signed.fif`](../crypto/smartcont/complaint-vote-signed.fif)

### Governance proposal scripts

These scripts should mostly reduce to:

- parse CLI arguments
- load the proposal payload
- validate the payload when required
- derive `query-id`
- build `proposal-ref`
- build `proposal-body`
- print and save the result

Target scripts:

- [`create-config-proposal.fif`](../crypto/smartcont/create-config-proposal.fif)
- [`create-config-upgrade-proposal.fif`](../crypto/smartcont/create-config-upgrade-proposal.fif)
- [`create-elector-upgrade-proposal.fif`](../crypto/smartcont/create-elector-upgrade-proposal.fif)
- [`envelope-complaint.fif`](../crypto/smartcont/envelope-complaint.fif)

## Recommended Implementation Order

To keep the first patch set small and low-risk, the order should be:

1. Implement the pure `Validator.fif` core words:
   - `parse-val-signature`
   - `check-val-signature`
   - `validator-elect-req>B`
   - `validator-elect-body`
   - `config-vote-req-ext>B`
   - `complaint-vote-req>B`
2. Implement the pure `Proposal.fif` core words:
   - `proposal-query-id`
   - `proposal-param-ref`
   - `proposal-body`
   - `complaint-envelope-query-id`
   - `complaint-envelope-body`
3. Migrate the scripts to those words.
4. Add the optional loading and normalization helpers after the core split is stable.

## Non-Goals

This draft intentionally does not propose:

- moving generic file I/O into the libraries
- moving help text into the libraries
- merging `Validator.fif` and `Proposal.fif` into one file
- replacing existing `Key.fif`, `Addr.fif`, or `Msg.fif` APIs

Those changes would weaken the library boundaries instead of clarifying them.

## Conclusion

The next Fift library step is no longer about basic protocol primitives. Those are already largely in place.

The next step is to extract two reusable business-protocol layers:

- `Validator.fif` for validator signing and vote flows
- `Proposal.fif` for governance proposal and complaint-envelope flows

This split keeps the reusable wire formats in libraries and leaves the operational scripts as thin entry points.
