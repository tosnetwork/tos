# Routed final-import record construction

This M1 unit adds an explicit record constructor for the address exception in
`~/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, section 11.3. It does not activate that
exception, settle a misdirected message, or complete M1. The existing strict
constructor and its callers retain destination-equals-processing-account
semantics.

## Reconstruction rule

The enclosing host must authenticate two distinct roles, coordinator and
custody. Given those roles and an already admitted standard final-import
envelope in this workchain:

- A custody destination uses the custody transaction.
- A coordinator destination uses the coordinator transaction.
- Any other destination uses the coordinator transaction, without changing the
  original message or envelope, including its destination.

The constructor checks the actual transaction account against the derived
processing account; a map key does not establish transaction identity. The
resulting Native `msg_import_fin` record references the original envelope and
the processing transaction. Both destination exceptions in the disposal policy
(bounce and unexpected credit) need this InMsg shape. It does not select which
disposal branch applies, construct its OutMsg, or grant a source-address
exception to outgoing messages.

The role resolver is internal implementation machinery, not a wire field or a
proposer-controlled per-message account map. There is no fallback role chosen
from local configuration. The new public constructor takes both roles
explicitly. Its minimum construction version is not a production activation
gate; Native transaction validation still needs a versioned exact-replay
exception before these records can be accepted as a real block.

## Independent record arithmetic

Both constructors share the existing Native record construction and augmented
dictionary checks. Per message, imported value includes the remaining
forwarding fee; that fee is collected at the block level, not credited to the
processing account. Checked CurrencyCollection subtraction derives gross
principal credit from the Native augmentation, checks it against the original
message value, and checked additions accumulate credits and totals. The
complete dictionary augmentation is compared with the independent accumulated
totals. Duplicate original-message hashes reject.

The new account selection adds no amount arithmetic. A returned account credit
is **gross imported value**, not custody backing, an unexpected-bucket delta,
or the balance after disposal. Business admission and bucket placement must
remain separate: in particular, merely arriving at custody does not authorize
issuing a confidential balance or increasing its backing ledger.

## Provenance and admission boundary

This remains a post-admission construction primitive. Envelope closure,
currency traversal, transaction closure, role policy, source queue membership,
complete import selection and DispatchQueue handling require authenticated,
bounded enclosing-host input. Bounds here restrict record counts and currency
validation, not the entire preceding acquisition workload.

No new catch or error class is added. Existing Result failures and exceptions
are not an automatic candidate verdict; the enclosing source-aware host must
distinguish authenticated-state/local failures from invalid candidate data.
The constructor cannot certify those origins from a raw Cell reference.

## Test scope and evidence

`NativeCoordinatorEntry` supplies real serialized transactions and a mixed
inbox containing both entry destinations and a foreign destination carrying
Native and extra-currency value. It checks gross credits, exact Native totals,
both InMsg dictionary parsers, and the original envelope and processing
transaction references. The strict factory still rejects the foreign
destination; an ordinary inbox is hash-identical across the two constructors.
Equal roles, missing or misbound coordinator transactions, and duplicate
messages reject.

These are record-shape fixtures: the pre-existing transaction fixtures do not
claim to settle this changed inbox. Passing the TL-B parsers is not proof that
live Native semantic validation accepts the address exception. Full wrapper
reconstruction, disposal effects, bucket state, outgoing evidence, independent
whole-batch value flow and atomic publication remain required.

The test was run against an unimplemented constructor and failed at the
success predicate after a successful build. Five rebuilt controls fail: omit
foreign routing, credit the original destination, remove transaction identity,
allow equal roles, and bypass identity only for routed messages. The shared
identity control first fails an existing strict-path assertion; the fifth uses
a foreign-message-only inbox and fails the new routed assertion, preventing a
correctly addressed input from masking that check. The restored five-target
CTest regression passes. Exact substitutions, raw output and source/binary
hashes are in `measurements/uno-v2-routed-import-evidence.json`.
Manual mutation executions are not recurring mutation
CI; the assertions are in the existing CTest-registered block test. No milestone
review or complete M1 acceptance is claimed by this unit.

## Retirement scope

This work adds no retirement or workchain-removal path. Clearing economic
records does not prove that Native messages no longer require the old
destination. Parameter 84, the descriptor and custody remain present through
the currently authorized migration boundary.
