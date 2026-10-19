# TOL getter, query correlation and assembly diagnostics

## Fixed getter IDs

A top-level `get fun` derives its public method ID from the function name.
For a fixed numeric ABI use a regular function:

```tol
@method_id(100001)
fun get_state(): int { return 7; }
```

Combining these forms is refused with a cause-specific diagnostic. It supplies
text guidance only, not an automatic edit or a structured fix-it. Keep the
annotation and remove only `get` when preserving a fixed numeric ABI. Generic
functions, methods, entrypoints and mutate/self parameters retain their existing
restrictions. Contract-block getters have their own declaration rules and may
specify `@method_id`; this guidance does not change them.

## Query-ID warnings

Typed envelopes with a `queryId` field are explicit correlation evidence. For
manual parsing, only the first `loadUint(32)` followed by `loadUint(64)` on the
same inbound body slice is recognized. The opcode load may be discarded. This
adjacency is a heuristic: a 64-bit field could have another protocol meaning.
Intervening consumption, aliases, slice replacement (including destructuring),
unknown parser operations or control-flow boundaries end manual inference; later
amounts are not relabelled query IDs. Conditional expressions (`?:`, `??`, `&&`,
`||` and `match`) are boundaries just like branch and loop statements.

A typed reply literal with a constant replacement ID is diagnosed as missing
propagation. Raw sends, computed initializers and helper calls receive uncertainty
wording: the pass does not trace their propagation, including calls through
function values. Each receiver has its own
source and disclaimer scope. Use `disclaim_query_id()` only for an intentional
protocol decision, not to conceal an incorrectly inferred field.

## Prefer symbolic instructions to raw opcode insertion

TOL accepts arbitrary inline Fift assembly. Prefer existing symbolic opcodes:

```tol
fun check(message: cell, context: cell, signature: cell, publicKey: cell): bool
    asm "PQCHECKSIG_MLDSA44"
```

The equivalent raw spelling `asm "x{F93100} s,"` bypasses the assembler's
`@addop` / `@ensurebitrefs` continuation-capacity handling. It can assemble when
space remains but fail after surrounding code changes. The symbolic spelling
can open a continuation when necessary. It does not establish authorization,
correct stack effects, or adequate execution gas.

This release ships guidance, not a new lint: there is no advisory severity,
opt-in switch, acknowledgement marker or automatic rewrite. Find symbolic names
in `crypto/fift/lib/Asm.fif` or a suitable stdlib wrapper such as
`@stdlib/pq-quorum-signatures`. Keep raw assembly available for instructions or
Fift constructions that intentionally need it.

`test-tol-raw-opcode-capacity` checks four cases: raw and symbolic forms with
space available, and both forms after exactly 1000 bits of padding. The raw
boundary case succeeds in the frontend and fails during assembly; the other
three execute both a valid OpenSSL ML-DSA-44 vector and a well-sized invalid
signature, returning true and false respectively.
These are regression cases, not claims about historical experiment outcomes.

The existing `uint64` versus `coins` type check remains unchanged; use explicit
`as coins` where required without changing fixed-width storage encoding.
