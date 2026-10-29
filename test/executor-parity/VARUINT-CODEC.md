# Unsigned variable-integer codec parity

`varuint_codec.py` authors 330 boundary rows for TL-B VarUInteger 3, 7, 16 and 32.
It checks C++ against independently constructed acceptance/value/canonical-cell
assertions before comparing the independently executed Rust adapter. The scope
covers every length-prefix value, zero/nonzero first bytes, truncated input,
canonical zero/max, write overflow and negative values. It is a finite scalar
codec matrix, not complete VM/codec coverage.

Strict reads require `len < n` and a nonzero first byte for nonempty encodings.
Zero uses length zero. Unchecked skip checks the length and available bits while
allowing a leading zero. Unsigned serialization rejects negative values. These
are the existing C++ rules; production C++ is unchanged. The Rust primitive macro
now uses the actual TL-B parameter, including Coins=16, with at most n-1 bytes.
The canonical Coins representation remains the same.

VM integer instructions use permissive loads instead of the strict block decoder.
`GETEXTRABALANCE` reads the dictionary from balance tuple item 1. Its first five
calls cap dictionary load charges at 200 gas each, retaining excess as free gas;
later calls pay normal load costs. Child execution carries the call counter back,
and gas isolation charges deferred gas and resets the allowance counter.
`vm_varuint_scenarios.py` compares 20 extra-balance programs covering padded integer values,
missing keys, cold/warm deep paths, the fifth/sixth-call boundary and child
execution with/without gas isolation. Native scalar results and simple-path gas
are asserted independently before full VM end-state comparison. This finite
matrix does not establish all malformed-dictionary or library-resolution cases.
Eight additional programs check GETGASFEE/GETGASFEESIMPLE, including the
variable branch's signed fee addition. Their values, gas and end states are
checked independently and compared between both VMs.

Runtime gas budgets are separate from serialized integer types. External credit
uses the configured credit capped by affordable gas, without a wire-width clamp.
The initial credit/limit are recorded before precompiled budget overrides, then
converted to transaction fields only after unaccepted/skip outcomes are resolved.
`gas_credit.py` compares 26 actual native/Rust C API cases at credits 65535,
65536, 2^32 and 2^32+1, with ordinary/precompiled execution, accepted/unaccepted
messages, unaffordable precompiled usage and a burn-then-throw control. Accepted
transaction/account/shard roots must agree, and failures must emit no outputs;
native encoding refusals must specifically reach transaction serialization.
Each worker persists the original config/shard/message and binds their hashes.
Purchased gas likewise has no serialized VarUInteger7 clamp. The derived runtime
threshold is signed, and its calculation uses the reference's ceiling and signed
scalar conversions. Gas-purchase methods return checked results; decoding and
executor initialization propagate errors. This changes the Rust source API and
derived cache type, without changing the gas configuration's wire layout. The
fixed basechain deployment profile caches its ceiling threshold 13333344 and has
a serialization/derivation consistency test.

`gas_purchase.py` authors 6602 threshold/budget/fee records, including zero price,
signed scalar boundaries, negative thresholds, floor division and the native
out-of-range integer sentinel. Each record also checks the native full and simple
fee values, taking the input balance's low 64 bits as the scalar fee argument.
Native results must satisfy those independent
rules before Rust is compared, byte for byte. The adapters allow at most 8 MiB,
8192 rows, 1024 bytes/row, a 64-byte name and a u128 balance; output is bounded
to 1 MiB. This is finite arithmetic coverage, not full configuration coverage.
`purchase_transactions.py` additionally compares 13 actual C API cases: initial
limits, skips, serialization failures, funded signed-fee configurations and
complete accepted roots and balances. The two variable-fee cases require a
negative fee to refuse transaction serialization and a signed flat-fee addition
to charge the native amount. VM getters retain signed results; transaction and
operator callers require nonnegative payable amounts through checked conversion.
Original inputs are retained and hash-bound. Both
scalar and transaction transcripts are compared across architectures in CI.

The adapters are separate executables with 8 MiB input, 4,096 row, 2,048 byte/row
and 1,023 bit cell bounds. The runner reuses the REL-02 subprocess supervisor for
CPU/address-space/file/wall limits and cancellation cleanup. Its comparator has a
1 MiB output bound and checks every ordered field/line. Missing, additional,
reordered, truncated and both-side wrong records fail. Runtime failure is not a
legitimate codec refusal. The scalar operations do not execute VM instructions.

The epoch gate executes both adapters on x86-64 and ARM64, then compares complete
input/native/Rust transcripts in the final architecture job. Both upstream and
TOS have the native rules, with no corresponding upstream Rust codec. No new
reference semantics or output normalization are introduced.

The original 282 accepted Account storage fixtures remain unchanged. Two separate
native-rejected nonminimal Coins fixtures are regenerated by storage_encoding.py
and must fail Rust Account loading while leaving the original wrapper intact.
Positive-only extra-currency dictionary rules and other codec families remain
separate open work.
