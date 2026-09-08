# System-encryption review disposition

Status: reviewed kernel primitive; not accepted host integration.
The review transcript is in `~/memo/reviews/uno-v2-system-encryption-review.txt`.
The corrected-tree re-review is in
`~/memo/reviews/uno-v2-system-encryption-rereview.txt`: no actionable defect
remained within the unit. It independently rebuilt 18 Rust tests, header drift,
the C++ harness, reachable symbols and six gate checks. This is not acceptance
of the host obligations listed below.

| Finding | Disposition |
|---|---|
| Extra network field in the domain | Accepted and corrected: the approved network/global_id is one i32. The domain is 80 bytes, not 84. The regenerated regression vector replaces the old one. |
| Missing mutation-script anchors | Accepted: applicable absorption/guard/comparison controls, an output-before-success control, an independent verification-version control, and a no-invented-limit control are in the isolated runner. The two obsolete max_value policy controls are retired with that field. Full rerun results are recorded below before acceptance. |
| Normal CI would miss a removed absorption/comparison | Disputed: `test-uno-crypto-rust` already executes the binding and component-comparison tests in CTest. The missing facility was repeatable mutation execution, not execution of the regression tests. The mutation runner itself remains manual. |
| Intermediate-source evidence | Accepted: the historical evidence file now explicitly distinguishes the intermediate stub/first run, the pre-review 84-byte implementation, and the corrected implementation. Historical hashes do not certify the correction. |
| Separate derived-handle identity guard | No redundant guard: nonzero r and nonidentity P in the prime-order group imply rP is nonidentity. Both necessary guards have negative witnesses. |
| System request max_value policy | Resolved by the owner's delegated clarification: remove it from the primitive, but host admission MUST enforce x <= V_max because COLLECT constrains every pending item. This is an implementation consequence of the approved relation, not a new decision. |
| Coarse DECODE | Existing ABI classification retained; the host must preserve input provenance and may not turn every authenticated queue item failure into CandidateInvalid. |

The corrected domain alone did not change the supported C struct size (168) or
amount offset (152): reducing the byte array by four introduces four bytes of
alignment padding before amount. Removing max_value then reduces the struct
size to 160; amount remains at offset 152. Neither padding nor the native struct image
is hashed; only the explicit domain array and named transcript fields are.

The revised Rust test additionally checks wrong-version and null-request paths
through the verification entry. Removing a pointer guard is not a safe mutation
if it makes the test itself perform undefined behavior; use a safe behavioral
substitution or the checked-span unit boundary instead.

No host domain encoder, pending admission, monetary fee equation, multiaccount
commit, or production activation is established by this unit. The frozen vector
is a cross-language ABI regression artifact, not an independent cryptographic
implementation. D31 and D32 remain separate integration work.

## Required host follow-through (not accepted by kernel tests)

Use the same authenticated ConfigParam 84 policy slice as COLLECT. Ordinary
Deposit admission requires V_min <= x <= V_max; rejection takes the specified
bounce branch and creates no custody/pending/accounting obligation. Late-return
admission first checks subtraction of the pending slot fee from actual value y,
then checks the same V_max; failure takes the unexpected bucket, not re-bounce.

Host acceptance must exercise x=V_max through real Deposit and COLLECT, and
x=V_max+1 through rejection with unchanged obligation state. Removing the host
upper-bound guard must make the latter test red. Those host paths do not yet
exist in this unit; primitive success for u64::MAX explicitly does not satisfy
host admission. No new local monetary default is installed here.

## Rebuilt validation

All five focused CTest entries passed: real C ABI (including concurrency and
entropy trap), Rust, reachable symbols, source/dependency gates and generated
header drift. The complete isolated mutation runner executed 63 controls:
baseline and restored suites passed; all 61 negative controls exited 101 after
executing tests, including 15 system-encryption controls. No compilation failure
is counted as a successful negative control.

[Source hashes and rerun instructions](measurements/uno-v2-system-encryption-reviewed-evidence.json)
bind the [raw log archive](measurements/uno-v2-system-encryption-reviewed-mutations.tar.gz)
to this corrected implementation. These are manual experiments. The earlier
`uno-v2-system-encryption-evidence.json` remains explicitly historical.
