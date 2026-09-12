# Independent D78 statement-switch boundary review

Reviewed A **5f034af0f**, with B's versioned interface c7a6f62e8 and wallet consumer
fix147f9b20b. Spec a131b9bb / 187dbc79290d6816; §11.2 rows2/3 and D78 govern.
A's relevant host/codec/test sources matched this commit when read; no A source
was edited. This is retrospective review after A's report, not new prediction.

**Verdict: no D78 statement/eligible-Failed arithmetic deviation found in the
reviewed boundary. Exact executed-wallet provenance remains provisional.**
This is not unconditional live acceptance or M5 completion. Failed stays0/10,
prepare0/9; insufficient-value bucket, Paid and late paths remain incomplete.
No guard is retired. The separate requested external boundary review is not
replaced or presumed approved by this B review.

## Not established (read this first)

- No execution-time wallet digest/build manifest pins live2's executed binary to
  the reviewed source. A explicitly confirmed none was captured. Build log,
  executable existence, mtime and a hash collected now cannot supply that missing
  contemporaneous link. Full live provenance is provisional, not demonstrated
  wrong. Required fix is a freshness pin (executed binary digest tied to a build
  identity/source inputs, recorded before execution and checked for replacement),
  not another unpinned run. B has not edited A's runner.
- No full Failed/prepare contract, bucket/Paid/late execution, universal absence
  of subsidy, or actual malicious funding-edge publication control is established.
- B did not rerun the entire live sequence or independently establish A's M3/M4
  regression and unknown-injection endpoints in this review. Those remain A's
  evidence, with their stated scope. Shared code is not shared execution evidence.
- D=0 is the structural atomic-operation conclusion, not an independently read
  persistent D counter. Test-key decrypted N is explicitly identified below.

## 1. Freshness: meaningful weak evidence, no exact commit pin

The retained live2 `operation.request.txt` contains principal10000000,
outward_fee100 and fee257, with NO return_reserve. The known pre-D78
m3-scenario source at2e2738c79 requires `n("return_reserve")` before producing
points or proof; absent that key it returns an error. The driver calls each
process with check=True. Therefore the reported successful new request/proof
path is inconsistent with THAT old implementation. This is useful semantic
freshness evidence, not nothing.

It does not identify which binary produced the outputs or bind that binary to
147f9b20b/5f034af0f. The path m3-vector-wallet-target/release/examples/m3-scenario
also exists before rebuild. No unique post-build path or executed-binary stamp
was found in fixture artifacts or the pinned runner. A's rebuild log is a record
of a build, not a recorded identity of the subsequent executable invocation.
Keeping the distinction avoids both falsely discarding valid observations and
upgrading weak shape evidence into exact source provenance.

## 2. Actual wrapper bytes, independently decoded

Read B's committed no-prelock-v2/statement-context.bin, SHA256
93f27a768aefe72290fded5b081914ae630867e43d5a22fd7f73fec0f223f3ef:

| Byte range (half-open) | Independently decoded content |
|---|---|
| 0..30 | literal `uno-v2/withdrawal-statement/v2`, including actual final byte `2` |
| 30..62 | 32-byte Withdrawal ID, all07 |
| 62..94 | 32-byte Attempt ID, all08 |
| 94..102 | little-endian principal137 |
| 102..110 | little-endian outward fee17 |
| 110..118 | little-endian operation fee11 |
| 118..684 | 566-byte synthetic host context, all2a |

Measured total684 and suffix566; no reserve field exists. This is direct byte
inspection, not adoption of A's arithmetic. f remains separate from committed
T, even though f is bound in the statement wrapper. This vector is not the live
fixture's host context. Host context length remains566, checked and unchanged.

## 3. Prefix control is real and default-registered

`crypto/test/test-workchain-proof-work.cpp:25–44` reads that file, checks length,
then compares bytes to the named v2 domain at line34, then tests metering and
old ABI rejection. `CMakeLists.txt:651–652` builds the executable;
`tos_test(test-workchain-proof-work)` registers it without an optional-crypto
condition. B ran the actual registered CTest:1/1 passed.

B independently rebuilt the same TU with a pinned shadow proof-work header;
only `uno-v2/withdrawal-statement/v2` became same-length `/v1`. It compiled and
ran, file-open and length assertions passed, then exited1 at:
`bytes.substr(0, tag.size()) is not equal to tag (…/v2 != …/v1)`.
Restoration passed. This independently reproduces A's claimed layer. B archived
both the independent red and A's previously /tmp-only log. Persistent protection
is the default prefix assertion, not either saved log. No earlier Native pricing,
proof or publication gate was involved in this unit control.

## 4. Eligible Failed arithmetic, term by term

B compiled an independent artifact decoder against the matching generated codec,
read actual old/new account roots and the real bounce, and independently decoded
the authenticated test configuration. This did not run A's arithmetic oracle.

| Quantity | B's reading / checked relation |
|---|---|
| x | open authenticated W record principal10000000 |
| y | actual bounced Message value9996070; same message hash as stored host inbox |
| s | explicit slot fee3000000 |
| g | explicit base2 * issuance billing units4 =8 |
| h | checked s+g =3000008 |
| receipt | actual installed system entry6996062 = checked y-h |
| R delta | actual custody balance difference6996062 |
| N delta | independent test-key decrypted rights difference6996062 |
| P/W release | each exactly10000000, from one record to none |

These are precisely §11.2 rows2/3: +R=+N=y-h, -P=-W=x. No b occurs. Native
loss x-y is already absent from y; it is not deducted again. The actual custody
transaction fee is8, and block fees_collected2629; serialized host fees have
S3000000/C8. Neither a constant called8 nor absence from coordinator alone is
used as evidence of the computation's destination.

## 5. Named conservation terms and the Failed funding edge

R_book was independently accumulated from permanent inputs in blocks1..6
(starting with this test's zero book): admitted Deposit principal; Withdrawal
x+q+f subtraction; actual Failed message y minus authenticated s+g. It was NOT
copied from custody's balance. N was independently decrypted from available,
user-pending and system-pending rights across both accounts. Open record
principal was independently enumerated for P/W.

| Stage | R_actual | R_book | N_decrypted | P | W | D |
|---|---:|---:|---:|---:|---:|---|
| Accepted prepare | 989999643 | 989999643 | 989999643 | 10000000 | 10000000 | 0 structural |
| Accepted Failed | 996995705 | 996995705 | 996995705 | 0 | 0 | 0 structural |

First equation holds at both stages. Second equation is explicitly
999999643=999999643 at prepare and996995705=996995705 after Failed.
Equality alone does not anchor common-mode amounts; the independent components
in section4 supply the specific cross-checks here.

The accepted Failed native effects contain **zero explicit transfers**. Its
coordinator balance rises by s only. Source chain at
workchain-m3-node-engine.h:365–376 constructs fresh effects with account updates
and fees, no native_transfers; its shared finish at240–243 only adds the protected
snapshot. Helper workchain-failed-funded.h:83–90 checks g/h/y-h; its return carries
y and two copies of principal for releases, not a funding request.
This supports absence of a Failed-created funding edge in this observed branch.
It does NOT assert that native_transfers capability is absent: D63 needs that
capability elsewhere. Nor does it substitute for a future subsidy mutation at
real publication. A's existing branch-scoped trigger remains a separate guard.

## Cross-boundary control: the old observed receipt

The PRE-D78 normal.log was committed in92dd939c6 on2026-09-11, before D78.
Its probe reads `w1.origin_pending.front()` from accepted-state.boc and prints
that receipt's amount. The control is the line `installed_receipt=7996062`, NOT
the helper's parameter variant0 or an expected amount computed after D78.

B verified all seven original artifact hashes against that old committed
input-identities.json and reran the preserved old reader. The raw old accepted
state/config/bounce still match. Old measured y9996070, s3000000, base2, units4,
g8 and b1000000 agree with the new readings on y/s/g. The new independently read
receipt is6996062. Integer comparison gives:

`7996062 - 6996062 = 1000000 = old b`.

Thus this matched fixture supports removal of exactly the prelock term from the
receipt amount. It is not merely consistency among post-change computations.
It does not prove a universal transformation for every input, and the account
BOCs are not identical fixtures (schemas, pre-debit rights and hashes differ).
Nothing about contract completion or unfinished branches changes.

## Evidence classification

**Independently reproduced:** vector byte decomposition; default prefix test;
same-length tag mutation at designated assertion and restoration; retained live
state/inbox/config/fees decoding; independent event ledger and test-key rights;
zero Failed explicit transfers; old artifact hashes and old measured receipt;
matched old/new difference.

**Accepted only as A's evidence:** whole live sequence exit0, release-build action,
M3/M4 regression runs, unknown-injection/full pipeline behavior, requested external
review status. No corresponding B end-to-end execution claim is made.

**Could not establish:** exact executed-wallet source identity and the other
coverage items named first. Required freshness pin remains outstanding. A green
unit/artifact boundary finding cannot erase that provenance condition.
