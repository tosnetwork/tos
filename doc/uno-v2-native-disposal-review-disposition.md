# Native disposal composition review disposition

Status: M1 incomplete. This post-admission construction helper is not installed
at a live consensus entry. Review transcripts are in
`/home/tomi/memo/reviews/uno-v2-native-disposal-review.txt` and its follow-up.

## Initial review

| Finding | Disposition |
|---|---|
| Resolved table test was masked | Fixed: the planner receives a separate table while the copied config contains a stale, valid table. Known-workchain bounce must use the resolved table; removing the rebind now fails a branch assertion without null-pointer UB. A separate positive case also passes a null config pointer. |
| Destination identity | Fixed: decode the message's effective 256-bit destination and bind both workchain and account. Do not equate processing account with original destination: that would forbid the very misdirected-message case. Authentication of the processing role remains an enclosing-host requirement. |
| Body materialization | Deferred, activation-blocking: the legacy NoVm walker can fail fatally on an unavailable descendant. This helper is not an admission boundary. A detached complete closure and source-aware failure handling are required before live use. |
| Anycast / source / diagnostic defaults | Fixed at this helper boundary: callers must provide an explicit profile, without default values. The fixture's ordinary skip diagnostic does not freeze a production diagnostic or source policy. Authenticated profile resolution remains outside this helper. |
| Missing body selector | Disputed as an independently reachable malformed-input path: generated Message::unpack calls Either::fetch_to; TLB_Complex::get_size uses skip, and Either::skip requires the selector. RefT::skip reserves one reference through get_size. This does not validate opaque descendants or fix the separate materialization obligation. |
| Flags | Fixed: validate against and forward the shared valid mask. No new flag activation is introduced. |
| Independent value-flow claim | Corrected: self-checking a constructed row is not independent Native evidence. The fixture separately runs an ordinary Native transaction and compares message hash, balance and fees; live record reconstruction remains missing. |
| Narrow coverage | Partly fixed: add successful standard-workchain pricing, explicit destination mismatches, alternate source profile and greater-than-uint64 fees. No exhaustive profile, ingress or opaque-closure coverage is claimed. |
| Test tautologies / diagnostics | Fixed: literal expected credit totals, case diagnostics, direct ordinary fee comparison and explanation of Native LT allocation. |
| Extra temporary body cell | Removed: retain the original CellSlice directly. Config copying remains an implementation cost, not a throughput result. |

A serialized special pruned-branch cell is not interchangeable with a lazy
unavailable cell. The assertion that every such body necessarily underprices
an implicitly materialized subtree or produces divergent bytes has not been
demonstrated. Native opaque payload policy must not be replaced with the
ordinary-only UNO candidate rule. Complete closure materialization, hash
identity and virtualization policy still need their own admission evidence.

## Arithmetic and result boundary

Bounce fees are funded only by imported value. Checked CurrencyCollection
subtraction establishes nonnegative returned value and remaining forwarding fee;
the old processing balance is unchanged. Credit uses checked addition and
does not create hidden backing or update bucket counters here.

The shared message builder retains the ordinary uint64 fee overload. The new
bigint overload writes the Native Tomis width instead of truncating at 64 bits.
The composed planner rejects nonrepresentable prices as errors, not as credit.
An affordable price above 64 bits can be encoded; an unaffordable representable
price takes the economic credit branch. This does not claim the legacy ordinary
uint64 fee computation has been repaired.

An explicit branch enum and original message preserve disposition and
attribution. They are not an error-origin classification or a proof of role
authorization. Error/exception results never authorize credit. No catch was
added; the eventual boundary must handle actual VM, virtualization, builder and
allocation failure types, and must prevent the known fatal NoVm loader path.

## Remaining complete-host work

Versioned InMsg/OutMsg address exceptions, complete inbox/queue authentication,
typed bounded Native closure admission, exact reconstruction/publication,
unexpected bucket counters, and aggregate operating-fee settlement are still
required. A reviewed composition helper is not evidence that M1 is complete.

## Follow-up review

The read-only follow-up confirmed the destination checks, flag mask, ordinary
uint64 overload and arithmetic invariants. It ran no builds or mutations.
It found that aggregate initialization still allowed an empty profile. A
three-argument constructor now requires all profile fields, and the test pins
non-default-constructibility. The source enum's invalid-value guard has an
explicit out-of-range input. Diagnostic fields, both anycast source prefixes,
allow_anycast=false and by-reference input bodies now have direct witnesses.

The processing account is explicitly in the same workchain as the final
destination; it is not a cross-workchain source authorization interface.
The profile controls bounce routing deliberately, rather than inheriting the
ordinary send policy from cfg.disable_anycast. Production resolution must
select one authenticated interpretation; no fixture choice is a default.

The ordinary transaction comparison measures composition, not independent
implementations of shared helpers. Their decoder/boundary and mutation tests
remain separate evidence. The full materialization and typed provenance gap is
not fixed: passing lazy unavailable input here can erase provenance or crash
before an outer catch. Live admission must prevent that input class.

For uint64 price fields and statistics, the two-product sum is below 2^129;
after ceiling division by 2^16 and the lump addition, the price fits 114 bits.
Thus the 120-bit guard is defensive, not a separately demonstrated reachable
limit. The shared flag mask is reused, but exporting/consolidating all existing
flag-predicate copies is deferred; this unit does not widen any flag semantics.

## Executed controls

Thirteen runtime mutations were separately applied, rebuilt successfully and
rejected by the actual NativeDisposalPlan test: table binding, both destination
components, rebounce, bounce flag, affordability, source selection, bigint wire
fee, diagnostics, anycast permission, anycast prefix, referenced body and source
enum validation. No control asserts exact error wording. The affordability
control fails because an expected successful economic-credit result instead
returns Error; the other runtime controls fail branch/value/hash or rejection
assertions. The stale-table control fails a branch assertion, not a null access.

A fourteenth, compile-time control removes the required-argument constructor;
the build fails specifically at the non-default-constructibility static_assert.
It is intentionally a compile gate, not a runtime mutation claimed to execute.
Restored five-target CTest and standalone-header compilation pass. The failed
attempt to build a CTest-only name is retained as a harness error and excluded
from acceptance evidence. Exact substitutions, outputs and restored hashes are
in `measurements/uno-v2-native-disposal-evidence.json`. These controls are manual,
not recurring mutation CI; no exhaustive coverage or M1 completion is claimed.
