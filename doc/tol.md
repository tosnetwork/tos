# Tol Execution Roadmap for TOS

## 0. Scope and references

This document specifies the concrete execution path for Tol as
TOS's official high-level smart-contract language. It is the
execution counterpart to [`doc/actor.md`](actor.md), which sets out
the actor-model design principles. Where this document defers a
design question, it points to the relevant section in `actor.md`.

The document does not relitigate the choice between Tol and
external high-level languages; that choice has been made on the
grounds of **language sovereignty**, **TVM co-evolution**, and the
**static-analysis foundation** that Tol already provides.

## 1. Premise

Tol is the TOS-controlled compiler from a high-level smart-contract
language directly to TVM bytecode. It lives in the same repository
as the validator, the TVM, and the system contracts:

```
/home/tomi/tos/tol/                       — Tol compiler (C++)
/home/tomi/tos/tol-tester/                — language test suite
/home/tomi/tos/crypto/smartcont/tol-stdlib/ — current stdlib (low-level only)
```

Owning the compiler in-tree is the prerequisite for every protocol
direction in `actor.md` that touches the language layer
(§5.3, §5.5, §5.6, §5.9, §6.5).

Tol co-evolves with TVM. When TVM changes
(e.g. v12 full bounces — see [`Changelog.md`](../Changelog.md)),
Tol's codegen and the language surface adapt in the same release
cycle, in the same repository, with no third-party dependency on the
critical path.

## 2. Current Tol surface

The language already supports, as of the time this document is
written:

- **Types.** `int`, `slice`, `cell`, `tuple`, `bytesN`, structs,
  type aliases, nullable types `T?`, union types, enums,
  generics with type parameters and constraints
  (`tol-tester/tests/generics-*.tol`).
- **Functions and methods.** `fun`, methods bound to any type
  (`fun Point.incX(mutate self)`), the `mutate` keyword backed by
  a mini borrow checker
  (`tol/pipe-mini-borrow-checker.cpp`), pure/impure
  classification (`pipe-check-pure-impure.cpp`).
- **Imports** and a top-level stdlib (`@stdlib/common`, `@stdlib/dicts`,
  `@stdlib/strings`, `@stdlib/gas-payments`,
  `@stdlib/reflection`, `@stdlib/exotic-cells`,
  `@stdlib/tvm-lowlevel`).
- **Asm escape hatch.** `fun foo() asm "OP"` for direct TVM
  instructions, used by performance-critical or system code.
- **Annotations.** `@method_id(N)`, `@noinline`, `@pure`, plus
  build-time controls.
- **Entry points.** `fun onInternalMessage(in: InMessage)`,
  `fun onBouncedMessage(in: InMessageBounced)` — typed entry
  functions, but no per-op-code receive blocks yet.
- **Static analysis pipeline.** Type inference, lazy-load
  insertion, unused-symbol detection, const-expr evaluation,
  exhaustive type and serialization checks.

The compiler pipeline is a series of named passes (`pipe-*.cpp`)
that the OTP-style strengthening directions can extend cleanly.

## 3. Gaps that block OTP-style library work

The `actor.md` strengthening roadmap requires Tol to grow
specifically along these axes:

1. **No `contract` / `receive(...)` / `message` syntax.**
   Today, message dispatch is hand-written inside
   `onInternalMessage`. There is no syntactic place to attach a
   state, an op-code-to-handler map, or auto-derived
   serialization.
2. **No trait / interface.** Without behaviour contracts, the
   compiler cannot enforce callback shapes, conformance, or
   reusable patterns at the language level.
3. **No domain stdlib.** Tol has low-level utilities only. There
   are no canonical jetton-wallet, NFT-item, ownable, or wallet
   templates.
4. **No standardized request/reply correlation.** Each contract
   re-invents `query_id` plumbing.
5. **No language-level state-machine concept.** State is encoded
   manually in `c4` field layout, with no exhaustiveness or
   reachability check at compile time.
6. **No timer / scheduled-message language surface.** The
   protocol primitive in `actor.md` §5.2 has no language
   counterpart.

Items 1–3 are language-shape gaps. Items 4–6 require both protocol
and language work; the protocol parts are listed in `actor.md`.

## 4. Year-1 plan (quarter by quarter)

The four quarters below are sequenced by dependency, not by
calendar precision. Q1 must land before Q2; Q2 must land before
Q3 dogfooding; Q4 depends on Q2 and Q3.

### Q1. Standard message envelope + structured error format

**What ships.**

- A canonical message-header layout: opcode, `query_id`,
  optional `reply_to`, error class. Defined as a TL-B schema and
  as a Tol struct with auto-derived pack/unpack.
- A canonical structured-error format used by bounce and explicit
  failure messages, aligned with `actor.md` §5.3.
- Compatibility shims for existing TEP-style `query_id`
  conventions so that pre-existing standards (jetton, NFT, etc.)
  keep interoperating.

**Why first.** Without a stable message envelope, `contract` /
`receive` syntax has nothing to dispatch on, and behaviour
libraries have nothing to assume. The envelope is also the
primary protocol artifact required for `actor.md` §5.6
(request/reply correlation) and §5.3 (structured errors).

**Cross-reference.** `actor.md` §5.3, §5.6.

### Q2. Language: `contract`, `receive(...)`, `message` keywords

**What ships.**

- A `contract` declaration that binds storage layout, message
  receivers, and getters into a single unit. Example shape (this
  syntax is proposed; final form may differ):

  ```tol
  contract JettonWallet {
      data {
          balance: coins,
          owner: address,
      }

      receive(msg: Transfer) on Active {
          require(msg.amount <= self.balance);
          self.balance -= msg.amount;
          send_internal(msg.recipient, /* ... */);
      }

      get fun balance(): coins { return self.balance; }
  }
  ```

- A `message` (or equivalent) declaration with auto-derived
  op-code, pack, and unpack code:

  ```tol
  message(0xf8a7ea5) Transfer {
      query_id: uint64,
      amount:   coins,
      recipient: address,
  }
  ```

- A `receive(...)` block that compiles to dispatch code inside the
  generated `onInternalMessage`. Existing `onInternalMessage`
  remains available as an escape hatch; mixing the two is a
  compile-time error.

**Why this design.** The `contract` / `receive` / `message`
trio is the syntactic floor required by every later step:
state machines (§5.5), behaviours (§6.5), structured supervision
(§5.1), bounded postponement (§5.9). Putting it down once,
correctly, is more important than feature speed.

**Inspiration vs. independence.** The shape is recognizable to
developers who have seen similar high-level TVM languages. The
implementation is fully independent: Tol continues to compile
directly to TVM bytecode through its own codegen and uses its
existing static-analysis pipeline.

**Cross-reference.** `actor.md` §5.5, §5.6, §6.5.

### Q3. Domain stdlib and official dogfooding

**What ships.**

- A second-tier stdlib aimed at common contract patterns:
  - `tol-stdlib/jetton` — Jetton master + Jetton wallet
    templates conforming to the relevant TEP standard.
  - `tol-stdlib/nft` — NFT collection + NFT item templates.
  - `tol-stdlib/ownable` — owner / two-step ownership transfer
    pattern.
  - `tol-stdlib/wallet` — wallet-vN reference implementation.
  - `tol-stdlib/multisig` — basic multisig pattern.
- The official TOS reference contracts (wallet, Jetton wallet,
  NFT item, multisig) **rewritten in Tol using the new syntax
  and the new stdlib**. This is the dogfooding step.

**Why dogfooding is non-negotiable.** A stdlib whose own
maintainers do not use it for the chain's reference contracts
will not be used by anyone else. Rewriting the chain's own
contracts in Tol also surfaces every rough edge in `contract` /
`receive` / `message` and in the stdlib while the design is
still flexible.

**Bytecode budget.** Each stdlib pattern must fit within a
documented bytecode and gas budget. If a behaviour-library
contract is more than ~15% larger than the equivalent
hand-written contract, the abstraction is too thick and is
trimmed before shipping.

### Q4. Static analysis + scaffolding + docs

**What ships.**

- **Exhaustiveness checking** for `receive(...)` blocks.
  For every state, the compiler enumerates which messages have
  handlers, which are explicitly bounced, and which are
  ignored. Unhandled messages are a compile-time error unless
  declared as an explicit catch-all. Aligned with `actor.md`
  §5.5.
- **`query_id` correlation enforcement.** Every `receive`
  handler that returns a reply must propagate the inbound
  `query_id` (or explicitly disclaim it). The compiler checks
  this at the language level rather than relying on convention.
  Aligned with `actor.md` §5.6.
- **Scaffolding CLI.**
  `tol new --pattern jetton-wallet my_token` generates a
  ready-to-build skeleton with the new syntax, stdlib imports,
  tests, and deploy script.
- **Documentation.**
  - Tol language reference, current and complete.
  - "Writing TOS contracts in Tol" — task-oriented guide that
    walks through wallet, Jetton, NFT, multisig.
  - "TVM model for Solidity developers" — direct,
    no-uncanny-valley explanation of the eight semantic
    differences between Solidity and TVM.
- **Test harness.** A property-based / replay test framework
  similar in ergonomics to Foundry, targeting Tol contracts.

**Cross-reference.** `actor.md` §5.5, §5.6.

## 5. Year-2 plan

Year 2 builds on the Year-1 substrate. Each item below requires
the corresponding Year-1 work to be in production.

- **§5.9 bounded postponement.** A language and protocol
  primitive that lets a contract defer messages that arrive
  "too early" under strict count, size, gas, and time budgets.
  Composes with `receive(...)` (Q2) and the structured-error
  format (Q1).
- **§6.5 behaviour patterns formalized as Tol traits.**
  Once the second-tier stdlib (Q3) has shaken out the duplication
  patterns, the recurring shapes — `request_server`,
  `state_machine`, `timed_actor`, `supervised_actor` — are
  promoted from concrete templates to first-class traits with
  compiler-checked conformance.
- **Second wave of stdlib.** Auction, DAO / governance, oracle,
  and payment-channel patterns. These are added only after the
  first-wave dogfooding has proven the abstraction.
- **Cross-language ABI freeze.** A documented binary interface so
  that legacy FunC contracts and new Tol contracts can call
  each other without surprises.

## 6. Year-3 directions

- **§5.1 supervision.** Implementable only after the structured
  error format (Q1) and request/reply correlation (Q4) are in
  production, because supervision messages must compose with
  both. Restart-intensity and circuit-breaker semantics
  (`actor.md` §6.4) are part of the same effort.
- **§5.2 time primitive.** Native scheduled-message support, with
  the resource model (rent, cancellation races, DoS limits)
  defined in protocol-side design documents before language
  surface lands.
- **§5.4 capability addressing.** Long-horizon research item.
  No language work begins until the public protocol design
  document is complete.

## 7. Explicitly out of scope

These items are deliberately not on the Tol roadmap. Listing
them prevents recurring "should we also do X" detours.

- **No FunC behaviour layer.** FunC remains the low-level
  language for system contracts and gas-critical hot paths. It
  does not get `contract` / `receive` / traits.
- **No high-level-language interop layer.** TOS does not ship
  migration tooling, interop adapters, or syntactic
  compatibility shims for any third-party high-level language.
  Existing contracts written in any language that ultimately
  produces TVM bytecode continue to run; they are not the
  recommended path forward.
- **No Solidity-syntax skin on TVM.** Solidity-syntax-on-TVM is
  the uncanny-valley anti-pattern: familiar syntax with
  incompatible semantics. Developers who want Solidity
  semantics have the EVM workchain (wc=1) for that exact
  purpose.
- **No premature multi-language behaviour story.**
  Until Tol has shipped traits with conformance checking
  (Year 2), there is no behaviour-library cross-language story
  to write.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Premature behaviour design (locking in a wrong abstraction). | No traits in Year 1. Behaviours are extracted from Q3 dogfooding, not designed up front. |
| Library bloat — every behaviour costing on-chain bytecode. | Hard 15% bytecode-overhead budget per stdlib pattern. Behaviours that exceed it are inlined or trimmed. |
| Multi-language fragmentation. | Tol-only investment. FunC stays for low-level. No third-language commitments. |
| Tol syntax decisions made in isolation from contract authors. | Every Q2 and Q3 deliverable goes through external dogfooding by 2–3 contract teams before stabilization. |
| Drift between TVM evolution and language surface. | Tol and TVM ship from the same repository; every TVM-changing PR includes a Tol-impact note. |
| The Year-3 protocol items (supervision, time, capabilities) starting before substrate is ready. | Strict gating: supervision requires Year-1 Q1 + Year-1 Q4 in production; time requires the resource model published; capabilities require a public RFC. |

## 9. Success criteria

| Milestone | Criterion |
|---|---|
| End of Year-1 Q2 | At least one official TOS reference contract compiles and deploys using the new `contract` / `receive` / `message` syntax. |
| End of Year-1 Q3 | The official wallet, Jetton master, Jetton wallet, NFT item, and multisig reference contracts all use the new Tol syntax and the new stdlib. The old hand-written FunC versions remain only as system contracts. |
| End of Year-1 Q4 | A new contract author can produce a working, audited-pattern Jetton or NFT in under one hour using `tol new`, the stdlib, and the documentation. |
| End of Year 2 | At least three external teams ship production contracts in Tol using behaviour traits. The first-wave stdlib has been used by enough projects that breaking changes require a deprecation cycle. |
| End of Year 3 | Tol + behaviour stdlib covers the patterns of at least 80% of contracts deployed in the previous quarter. Supervision, scheduled messages, and structured errors are in production. |

## 10. Closing framing

Tol is the only TOS-controlled point in the contract-author
toolchain. Every protocol-level actor improvement that needs a
language counterpart — explicit state machines, request/reply
correlation, bounded postponement, supervision, scheduled
messages, capability handles — has to land in Tol to reach
contract authors at all.

The roadmap above is therefore not a wish list. It is the
minimum sequence required to turn the `actor.md` strengthening
directions into something a contract author can actually write.
The order is fixed by dependency, the scope is fixed by
dogfooding discipline, and the out-of-scope list is fixed by the
language-sovereignty premise.

Year 1 is the foundation. Year 2 is the differentiator. Year 3
is the long-term protocol payoff.
