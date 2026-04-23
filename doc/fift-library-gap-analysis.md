# Fift Library Gap Analysis

## Purpose

This document explains which `.fif` libraries appear to be missing from the current TOS Fift library set, why those gaps exist, and which libraries should be added first.

The goal is not to maximize the number of library files. The goal is to put reusable protocol logic into stable library boundaries instead of leaving that logic duplicated across ad hoc scripts.

## Scope

This analysis covers:

- the current shared Fift libraries in [`crypto/fift/lib/`](../crypto/fift/lib/)
- the repeated helper logic currently embedded in [`crypto/smartcont/`](../crypto/smartcont/)
- the zerostate and configuration builder logic currently living in [`crypto/smartcont/CreateState.fif`](../crypto/smartcont/CreateState.fif)

It does not attempt to redesign the Fift language itself or the TVM assembler.

## Current Library Set

The current shared library directory contains:

- [`Fift.fif`](../crypto/fift/lib/Fift.fif): base language helpers and standard preamble
- [`Lists.fif`](../crypto/fift/lib/Lists.fif): list and S-expression utilities
- [`Stack.fif`](../crypto/fift/lib/Stack.fif): stack manipulation DSL
- [`FiftExt.fif`](../crypto/fift/lib/FiftExt.fif): syntax sugar and structured control flow
- [`GetOpt.fif`](../crypto/fift/lib/GetOpt.fif): command-line option parsing
- [`Asm.fif`](../crypto/fift/lib/Asm.fif): TVM assembler
- [`Disasm.fif`](../crypto/fift/lib/Disasm.fif): disassembler
- [`Lisp.fif`](../crypto/fift/lib/Lisp.fif): Lisp subsystem
- [`Color.fif`](../crypto/fift/lib/Color.fif): terminal coloring
- [`TosUtil.fif`](../crypto/fift/lib/TosUtil.fif): blockchain-related helpers

This set is coherent everywhere except `TosUtil.fif`, which currently mixes several unrelated protocol domains into one file.

## Method

The recommendations in this document are based on three checks.

### 1. Cohesion of existing libraries

Most existing libraries have a narrow, obvious responsibility:

- parser/runtime helpers
- list processing
- stack rewriting
- assembler/disassembler
- CLI option parsing

By contrast, [`TosUtil.fif`](../crypto/fift/lib/TosUtil.fif) contains:

- address parsing and formatting
- public/private key helpers
- Tomi and currency collection logic
- library collection helpers
- simple transfer body construction
- ADNL parsing
- config-related validation helpers

That is a strong signal that the library surface is under-factored.

### 2. Repeated protocol logic in scripts

A reusable library should exist when the same protocol logic is repeated across multiple scripts.

Clear examples:

- Wallet and transfer scripts repeat message-building and signing flows:
  [`wallet.fif`](../crypto/smartcont/wallet.fif),
  [`wallet-v2.fif`](../crypto/smartcont/wallet-v2.fif),
  [`wallet-v3.fif`](../crypto/smartcont/wallet-v3.fif),
  [`highload-wallet.fif`](../crypto/smartcont/highload-wallet.fif),
  [`highload-wallet-v2.fif`](../crypto/smartcont/highload-wallet-v2.fif),
  [`highload-wallet-v2-one.fif`](../crypto/smartcont/highload-wallet-v2-one.fif)
- DNS scripts repeat subdomain and record serialization logic:
  [`auto-dns.fif`](../crypto/smartcont/auto-dns.fif),
  [`manual-dns-manage.fif`](../crypto/smartcont/manual-dns-manage.fif)
- Zerostate/config/workchain helpers are concentrated in one hidden pseudo-library:
  [`CreateState.fif`](../crypto/smartcont/CreateState.fif)

### 3. First-principles protocol boundaries

The stable units in this system are not individual scripts. They are protocol objects:

- address
- key material
- amount and currency collection
- message
- config parameter encoding
- workchain descriptor encoding
- genesis/state construction
- DNS record encoding
- wallet request building

If a piece of logic belongs to one of those units and is used in more than one place, it is library material.

## Main Findings

### `TosUtil.fif` is carrying too many responsibilities

`TosUtil.fif` is useful, but it is currently a catch-all. That makes it harder to:

- reason about stable APIs
- reuse only the needed functionality
- evolve one domain without touching another
- document the public Fift toolchain cleanly

This is the primary structural gap in the current library set.

### `CreateState.fif` already behaves like a library, but is not treated as one

[`doc/Zerostate.md`](./Zerostate.md) already describes [`CreateState.fif`](../crypto/smartcont/CreateState.fif) as a "Fift library with `setglobalid`, `register_smc`, `create_state`, etc."

That means the system already acknowledges a missing layer: shared genesis/state/config helpers exist, but they still live in `crypto/smartcont/` instead of a proper library surface under `crypto/fift/lib/`.

### Wallet message construction is duplicated at the script layer

The wallet scripts differ in contract-specific payload shape, but they still repeat a large amount of common logic:

- parse destination
- parse amount and optional extra currencies
- load keys and source address
- choose body source (`.boc` or comment)
- build internal message
- build signed external envelope
- compute and print query metadata

That is a missing library boundary.

### DNS record codecs are duplicated

The DNS scripts each implement their own:

- subdomain-to-slice encoder
- typed record serializer for `smc`, `next`, `adnl`, and `text`
- command parsing around those records

That repeated wire-format logic should not be copied in two places.

## Recommended Libraries

The recommendations below are grouped by priority.

## Implementation Status

Current status in the repository:

- `Msg.fif` - completed ✅
- `WalletCommon.fif` - completed ✅
- `DNS.fif` - completed ✅
- `State.fif` - completed ✅
- `Config.fif` - completed ✅
- `Workchain.fif` - completed ✅
- `Addr.fif` - completed ✅
- `Key.fif` - completed ✅
- `Currency.fif` - completed ✅
- `Assert.fif` / `Test.fif` - completed ✅
- `TosUtil.fif` compatibility split/aggregation - completed ✅
- `CreateState.fif` compatibility split/aggregation - completed ✅
- in-memory Fift source loader updates for the new libraries - completed ✅
- focused wallet and DNS script coverage for the new boundaries - completed ✅
- deterministic fixed-time/fixed-key zerostate regression coverage for `gen-zerostate.fif` and `gen-zerostate-test.fif` - completed ✅

### Tier 1: Strongly recommended

These libraries correspond to clear duplication and clear protocol boundaries.

#### `Msg.fif` - completed ✅

Shared message-building helpers for:

- internal message construction
- external signed envelope construction
- body attachment from inline text or `.boc`
- query id generation patterns
- common send-mode handling

Why it should exist:

- repeated across multiple wallet scripts
- message layout is protocol-sensitive
- mistakes here are expensive and hard to spot

#### `WalletCommon.fif` - completed ✅

Shared wallet-side request helpers layered on top of `Msg.fif`.

Suggested scope:

- common CLI-to-transfer flow
- bounce handling
- optional StateInit attachment
- extra currency collection handling
- common output/reporting helpers

Why it should exist:

- wallet scripts repeat the same operational workflow
- the scripts should mainly describe contract-specific payload differences

#### `DNS.fif` - completed ✅

Shared DNS helper library for:

- subdomain encoding
- record value encoding
- typed record constructors for `smc`, `next`, `adnl`, `text`

Why it should exist:

- obvious duplication between `auto-dns.fif` and `manual-dns-manage.fif`
- DNS wire format is a distinct protocol domain

#### `State.fif` - completed ✅

Shared state-construction helpers extracted from `CreateState.fif`.

Suggested scope:

- `register_smc`
- state object registration
- special address registration
- library collection handling
- top-level state creation

Why it should exist:

- this is already shared infrastructure
- it is library logic, not script-local logic

#### `Config.fif` - completed ✅

Shared config-parameter encoder library extracted from `CreateState.fif`.

Suggested scope:

- ConfigParam builders
- helpers for validator, gas, block, fee, and pricing params
- parameter dictionary helpers

Why it should exist:

- config encoding is a stable protocol surface
- zerostate logic and future governance tooling should share one implementation

#### `Workchain.fif` - completed ✅

Shared workchain descriptor helpers.

Suggested scope:

- standard TVM workchain descriptor builders
- EVM workchain descriptor builder
- future wc=2 / Uno workchain descriptor builders

Why it should exist:

- TOS is now explicitly multi-workchain
- workchain descriptor construction should not remain embedded in state-builder code

### Tier 2: Recommended structural splits

These are not as urgent as Tier 1, but they would make the library surface cleaner and more maintainable.

#### `Addr.fif` - completed ✅

Extract from `TosUtil.fif`:

- smart-contract address parsing
- raw and friendly address formatting
- address serialization into builders
- ADNL address parsing/formatting

Reason:

- address handling is its own domain
- many scripts want address logic without the rest of `TosUtil.fif`

#### `Key.fif` - completed ✅

Extract from `TosUtil.fif`:

- key loading
- key generation
- public-key parsing and formatting
- validator public-key parsing

Reason:

- key material is a distinct concern
- the code is already reused widely

#### `Currency.fif` - completed ✅

Extract from `TosUtil.fif` and the duplicated subset in `CreateState.fif`:

- `Tomi`, `TM$`, and display helpers
- `VarUInt32`
- extra currency collection helpers
- `Tomi+cc,`

Reason:

- currency and amount logic is a stable protocol domain
- it is currently split awkwardly between runtime helpers and genesis helpers

### Tier 3: Optional tooling libraries

These are useful, but they are not structural blockers.

#### `Assert.fif` or `Test.fif` - completed ✅

Suggested scope:

- assertions
- equality checks for cells/slices/builders
- small testing harness helpers

Reason:

- current Fift tests are mostly script-driven and ad hoc
- a test helper layer would improve maintainability, but it is not a protocol requirement

## Libraries That Are Not Missing

The current tree does not show strong evidence that we need new shared libraries for:

- assembler functionality beyond `Asm.fif`
- disassembly beyond `Disasm.fif`
- general list processing beyond `Lists.fif`
- stack rewriting beyond `Stack.fif`
- general language sugar beyond `FiftExt.fif`

Those domains already have coherent homes.

## Suggested Refactoring Order

If this work is done incrementally, the safest order is:

1. Add `Msg.fif` - completed ✅
2. Add `WalletCommon.fif` - completed ✅
3. Add `DNS.fif` - completed ✅
4. Split `CreateState.fif` into `State.fif`, `Config.fif`, and `Workchain.fif` - completed ✅
5. Split `TosUtil.fif` into `Addr.fif`, `Key.fif`, and `Currency.fif` - completed ✅
6. Add optional `Assert.fif` / `Test.fif` - completed ✅

This order reduces duplication first, then cleans up architecture.

## Proposed Rule of Thumb

When deciding whether a new `.fif` file should become a shared library, use this rule:

Promote it into `crypto/fift/lib/` when all three are true:

1. the logic belongs to a stable protocol domain
2. the logic is reused or is likely to be reused by multiple scripts
3. a bug in that logic would be expensive enough that copy-paste implementations are undesirable

If only one script needs the logic and the logic is not protocol-defining, keep it local.

## Conclusion

The current Fift toolchain does not mainly suffer from missing primitives. It suffers from missing boundaries.

The most important gap is that reusable blockchain logic is currently split between:

- a monolithic [`TosUtil.fif`](../crypto/fift/lib/TosUtil.fif)
- several repeated wallet and DNS scripts under [`crypto/smartcont/`](../crypto/smartcont/)
- a hidden pseudo-library in [`CreateState.fif`](../crypto/smartcont/CreateState.fif)

The most valuable additions are therefore not miscellaneous helpers, but domain libraries:

- `Msg.fif`
- `WalletCommon.fif`
- `DNS.fif`
- `State.fif`
- `Config.fif`
- `Workchain.fif`

Everything else should be considered after those boundaries exist.
