# PQ explorer RPC design audit and validation receipt

Date: 2026-10-14. Scope: the proposed interfaces, JSON Schema and offline shape
tests, not an implemented node RPC or a consensus/security release approval.

Reviewed design head: `2fdb14bb9682d9a2ebc1eac5da9b90a0ac8c906a`.
Native source pin: `d41eae93dbbcb2af730b4ff5015458794ef04cb1`.
The corresponding [design](explorer-pq-rpc-design.md) is revision 2; the
unshipped wire schema remains version 1. The original bundle was prepared locally
when connector write-back was blocked. Its original validation is recorded below;
the subsequent recovery and publication status is recorded in the final section.
The original reviewed head above is a historical baseline, not the current PR HEAD.

## Findings and disposition

| Priority | Finding | Correction and evidence boundary |
| --- | --- | --- |
| P1 | A final forward proof link was incorrectly required to begin at N-1 even when that predecessor is not a key block. The native verifier extracts forward-link configuration only from a key block or zerostate. | Distinguish outer N-1/N container endpoints from the authenticated K/N forward link. Require native verification of the backward ancestor link and all continuity, a complete target container, and the actual configuration source K. Native integration remains a required gate. |
| P1 | Releasing a verification permit when the HTTP request times out can admit new work while the old native verification is still executing. Per-reply byte limits also did not cap anchor-chain work. | Bind permits and evidence memory to the actual worker lifetime, not the response lifetime; retain the two-job cap through cancellation, use one absolute deadline, and bound cumulative bytes, queries and links. These are design requirements, not a measured runtime fix. |
| P2 | Config 43 accepted empty/incomplete or wrong-version configured fields, a present value with null wire version, and false default provenance. | Freeze exact v1/v2/v3 field sets and their defaulted complements. Preserve explicitly configured v3 Maybe-none as unlimited, not defaulted. Add all-version positive and independent negative vectors. |
| P2 | AUTH shapes allowed a retired flag paired with a not-retired result, or retirement with neither a flag nor a deadline. | Enforce these two decidable shape invariants. Deadline versus authenticated chain-time comparison remains a native semantic check. |
| P2 | The controller-count negative vector used nine identical codes, so uniqueness could reject it even if the eight-code maximum disappeared. | Use nine distinct codes for the count test, two equal codes for uniqueness, and eight distinct codes as the positive boundary. Remove each constraint independently in sensitivity controls. |
| P2 | Live observations lacked an accessible receipt/fixture manifest, and one displayed account object combined fields from different endpoints. | Mark the historical live reports as unverified, split source-derived method projections, and provide an explicitly unexecuted reproduction/retention procedure. No replacement live result is invented. |

Native source anchors for the first two findings are
`crypto/block/check-proof.cpp`, `BlockProofLink::validate` (forward configuration
extraction and backward ancestor validation) and `BlockProofChain::validate`
(cancellation checked between links). Config 43 field sets come from
`crypto/block/block.tlb`, `size_limits_config`, `size_limits_config_v2` and
`size_limits_config_v3`. Endpoint projections come from
`validator-engine/json-rpc-server-account-capability.cpp`; the old count vector is
in the runner at the reviewed design head.

## Original bundle validation

The four reviewed PR files were reconstructed from the connected repository reads
and their original Git blob IDs were checked before editing. A local partial Git
checkout contains those files, not a built native node. Standalone tools used:
Python 3.13.5, jsonschema 4.26.0 and markdown-it-py 4.2.0.

| Check | Result |
| --- | --- |
| Original runner against original schema | Exit 0: 40 vectors, 18 positive and 22 negative. |
| Revised runner against revised schema | Exit 0: **130 vectors, 34 positive and 96 negative**. |
| Targeted guard-removal controls | Exit 0: **8 controls**; the intended rejection assertion fails with the guard removed and passes when restored. |
| Revised runner against original schema | Expected exit **1**, specifically `SizeLimits: expected valid=False, errors=[]`. This proves the old schema accepts a newly tested forbidden shape. |
| Python syntax compilation | `python -m py_compile doc/validate-explorer-pq-rpc-schema.py`, exit 0. |
| Markdown rendering and structure | Three Markdown documents parsed/rendered; fenced JSON, closed fences, relative links and local schema references checked. Exit 0. |
| Whitespace | `git diff --check` and `git diff --cached --check`, exit 0, including all five staged documentation/test files. |
| Ruff | **Not run**: the pinned executable was unavailable in the offline environment. No lint/format success is claimed for this revision. |
| Native builds, static-analysis gate, live RPC/cryptographic/cancellation tests | **Not run**: no native implementation changes are included. These remain implementation gates, not passed tests. |

The eight sensitivity controls isolate: nonempty certificates; distinct controller
count; controller uniqueness; v1 required configured fields; default provenance;
present Config 43 wire version; the retired flag; and absence of a retirement
source. Every mutated schema must itself be valid, must accept the otherwise
well-shaped negative specimen, and must make its original rejection assertion fail.
Unrelated exceptions or setup failures do not count as sensitivity evidence.

### Reproduce green and regression-red

In a checkout containing this revision and the reviewed head:

```sh
uv run --no-project --with jsonschema==4.26.0 \
  python doc/validate-explorer-pq-rpc-schema.py
python -m py_compile doc/validate-explorer-pq-rpc-schema.py
git diff --check
# After committing the correction:
git diff --check 2fdb14bb9682d9a2ebc1eac5da9b90a0ac8c906a HEAD

git show 2fdb14bb9682d9a2ebc1eac5da9b90a0ac8c906a:doc/explorer-pq-rpc-v1.schema.json \
  > /tmp/explorer-pq-rpc-pre-audit.schema.json
uv run --no-project --with jsonschema==4.26.0 \
  python doc/validate-explorer-pq-rpc-schema.py \
  --schema /tmp/explorer-pq-rpc-pre-audit.schema.json
# The preceding invocation must exit 1 with the specific SizeLimits assertion.
```

No synthetic signature/key/proof bytes are valid cryptographic fixtures. These
checks establish interface shape and test sensitivity, not a valid finality
certificate, chain anchor, authenticated effective defaults or a safe offline signer.

### Reproduce document and reference checks

```sh
uv run --no-project --with markdown-it-py==4.2.0 python - <<'PY'
import json
from pathlib import Path
from urllib.parse import urlsplit
from markdown_it import MarkdownIt

parser = MarkdownIt("commonmark").enable("table")
for path in sorted(Path("doc").glob("explorer-pq-rpc-*.md")):
    text = path.read_text(encoding="utf-8")
    tokens = parser.parse(text)
    assert parser.render(text)
    for token in tokens:
        if token.type == "fence":
            assert text.splitlines()[token.map[1] - 1].strip() == token.markup
            if token.info == "json":
                json.loads(token.content)
        for child in token.children or []:
            if child.type == "link_open":
                link = urlsplit(child.attrGet("href"))
                if not link.scheme and link.path:
                    assert (path.parent / link.path).is_file(), link.path
schema = json.loads(Path("doc/explorer-pq-rpc-v1.schema.json").read_text())
def check_refs(node):
    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            assert ref.startswith("#/$defs/") and ref[8:] in schema["$defs"]
        for value in node.values():
            check_refs(value)
    elif isinstance(node, list):
        for value in node:
            check_refs(value)
check_refs(schema)
print("Markdown rendering, fences, relative links and schema references: passed.")
PY
```

## Validated file hashes

SHA-256 hashes of the files exercised by the checks above (this receipt excludes
its own hash to avoid a self-reference):

| File under `doc/` | SHA-256 |
| --- | --- |
| `explorer-pq-rpc-design.md` | `3576698d3343945aeb20c5d712b79a3cd473ea19b25fc4f779ac65dc697f1343` |
| `explorer-pq-rpc-contract.md` | `5a6671f2aa9cbf06bb2000685d282765e52c9e7c1bd5310253417c38740d12e6` |
| `explorer-pq-rpc-v1.schema.json` | `b5b103b31102454aad0cb9169451e54de96e881e099961e24f6769025b8821fb` |
| `validate-explorer-pq-rpc-schema.py` | `a8cd661a920c92e2027589c1513b17cd35e3895e7df3b9d385fb9ee1e0ca3e01` |

## Remaining acceptance boundary

Before shipping, the implementation must demonstrate native target/anchor proof
verification for an ordinary predecessor, a key-block predecessor, genesis-to-one
and validator-set transitions; refusal of incomplete/invalid evidence; and two
blocked verification workers retaining capacity through request cancellation.
Exercise the proposed cumulative budgets with realistic fixtures. The new 32 MiB,
16-query and 64-link values are operator-budget proposals, not measured consensus
limits or guarantees that every historical query fits.

Actual account/config codecs and proofs, numerical effective defaults, deadline
semantics, transport compatibility, full-ID cache behavior, decoder budgets and
native static-analysis/build gates still need their implementation witnesses.
The reported VM 16/18 deployments were not available to this audit; their live
receipts remain missing rather than being represented as reproduced evidence.

## Original-bundle restoration and fresh validation

On 2026-10-14 the original `PR-207-design-audit.zip` became available from the
requester's Downloads directory. The PR branch was still at
`e886e172a68e62ed0c0947fea1107efd035887bf`, the earlier reconstruction. This
follow-up restores the original bundle as the authoritative revision, without
rewriting that commit or merging the PR.

ZIP SHA-256: `a03f68f68d4fcd24a3a048bc42f1653d77639991117faab820875516462e3faa`.
All six entries in the bundle's SHA-256/size manifest were verified. The original
patch was independently applied to its reviewed baseline in a temporary directory;
all five resulting files matched the ZIP byte-for-byte. The four design, contract,
Schema and runner files in this follow-up match the original bundle exactly, with
the hashes listed above. Only this receipt's historical status and this new
validation section differ from the bundled receipt.

The restoration corrects the acceptance table's premature timeout-permit release,
restores complete-target and progressing-anchor-page requirements, and restores
the original 32-MiB / 16-query / 64-link cumulative resource proposal. It removes
the reconstruction's unsupported 10-second default and 32-query / 256-link values,
restores revision 2 and the original evidence reproduction procedure, and restores
the original Schema structure and test runner. The current count is 130 vectors,
not the reconstruction's 135; a larger vector count did not establish that the
design text was equivalent.

Fresh validation used CPython 3.14.6, jsonschema 4.26.0, Ruff 0.17.0 and
markdown-it-py 4.2.0. Each check returned exit 0 unless explicitly marked as an
expected regression failure:

| Changed boundary | Fresh result |
| --- | --- |
| JSON Schema and synthetic request/result shapes | 130 vectors: 34 positive, 96 negative; all pass. |
| Rejection guards in Schema | All 8 independent guard-removal controls pass. |
| Old pre-audit Schema | Expected exit 1 with `AssertionError: SizeLimits: expected valid=False, errors=[]`. |
| Python runner | Syntax compilation and Ruff lint/format checks pass without altering bundled bytes. |
| Markdown and references | Three documents render; 10 fenced JSON examples, 7 relative file links and 149 local Schema references pass. |
| Reviewed diff | Only the five intended files change; whitespace checks pass. |

The fresh lint and format commands, in addition to the green/red commands above:

```sh
ruff check --isolated --select E4,E7,E9,F,I doc/validate-explorer-pq-rpc-schema.py
ruff format --isolated --line-length 100 --check doc/validate-explorer-pq-rpc-schema.py
```

The document/reference check is reproduced by the unchanged snippet above.
This fresh Ruff result supersedes only the original receipt's tool-unavailable
status; it does not claim that Ruff ran in the earlier offline environment.
Native node builds, live RPC, cryptographic finality and actual worker-cancellation
tests remain unexecuted. No C/C++ execution boundary changes, so the native
two-build static-analysis gate is outside this documentation/Schema correction.
GitHub CI results are separate from these local checks.
