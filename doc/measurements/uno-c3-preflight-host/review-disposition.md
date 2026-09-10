# Review disposition

The initial review and focused follow-up were read-only. Transcripts remain
outside the repository. Their results are not substituted for actual controls.

Accepted and fixed before the final native-source control batch:

- Pin the driver count independently; compare selection to the native dispatch
  table and check completed-case markers. Empty selection and missing native
  dispatch entry each have a failing CTest control.
- Reject zero allowance before reservation or body. A nonzero empty body still
  consumes the whole block reservation; completion does not prove native
  operation coverage. Deleting and relocating the zero check have separate
  failed assertions.
- State reason-by-reason provenance. Neither operation exhaustion nor block
  capacity alone is a candidate verdict; incorrect local weights/bounds remain
  possible. Original failure payloads are retained for the eventual source-aware
  caller, not collapsed into a generic local or candidate status here.
- Test InvalidCharge priority independently against a secondary exception and
  against a returned error. Preserve the existing exhaustion-priority control.
- Document borrowed meter lifetime, add the host-only file banner, include
  `<new>` directly, and correct the existing private I13 count from five to six.

The suggested CMake source/header override hooks were not added. The header
has only the new private fixture as a literal C++ consumer; the follow-up review
agreed an override would introduce a new shadowing surface without a present
need. The final controller verifies this literal-consumer condition before
editing, checks actual compile/dependency paths, and refuses unexpected
concurrent bytes. This is not a general preprocessor dependency proof; new
production consumers require a different mutation setup and target inventory.

The follow-up found no blocking host-contract issues. Its four residual notes
were then addressed in the measurement controller without changing native
semantics: audit reloads original/report/mutant files from disk (with two damaged
artifact controls), the literal-consumer condition is checked, forward patching
is inside the restoration scope, and relocating the zero check is the 24th
native-source control. An unknown partial/concurrent edit is reported, never
blindly overwritten. All 24 controls are rerun on the final native source.

One initial review contextual sentence said nothing included the new header;
that is too broad: the opt-in private fixture includes it. Likewise concrete
test substitutes exist under both `crypto/test/` and `test/`, not only the former.
The relevant verified claim is **no production preflight implementation or
production call site**, which the contract states explicitly.
