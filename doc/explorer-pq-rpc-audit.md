# Explorer PQ RPC design audit receipt

Date: 2026-10-14. Status: design correction only; no RPC implementation or merge approval.

## Recovery and source boundary

The earlier `/mnt/data/PR-207-design-audit.patch` and ZIP were unavailable in this
environment. These five files were reconstructed from the published
[design review](https://github.com/tosnetwork/tos/pull/207#pullrequestreview-5514234546)
and repository source, not recovered byte-for-byte from that package.

The verified PR baseline is `2fdb14bb9682d9a2ebc1eac5da9b90a0ac8c906a` on
`docs/explorer-pq-rpc-contract`. The previously reviewed native baseline is
`d41eae93dbbcb2af730b4ff5015458794ef04cb1`. The relevant `check-proof.cpp`,
`block.tlb`, account-capability renderer and account-model source are unchanged
between those commits. The original checkout and synced reference files were
not modified; validation used an isolated checkout.

## Corrections

- Separate proof-container N-1/N endpoints from final forward-link K/N endpoints;
  validate ancestor links and derive configuration/session from the native source
  key block or zerostate. Cover ordinary/key-block predecessors and N=1.
- Hold verification permits and live evidence accounting until actual worker
  completion; detach HTTP settlement from worker ownership. Specify one absolute
  deadline and cumulative byte/query/link bounds over target and anchor acquisition.
- Enforce Config 43 complete v1/v2/v3 inventories (6/13/16 fields), null absence,
  exact default complements and explicit unlimited v3 configuration. Numerical
  effective values remain native-decoder responsibilities.
- Reject contradictory AUTH retirement states that shapes can decide; chain-time
  deadline evaluation remains native validation.
- Separate controller count and uniqueness vectors, with distinct guard-removal
  controls and an eight-distinct-code positive boundary.
- Split endpoint projections and label unavailable historical receipts as
  unverified author reports. Specify future reproducible public evidence.

## Validation receipt

Environment: CPython 3.14.6, jsonschema 4.26.0, Ruff 0.17.0,
markdown-it-py 4.2.0. Commands below returned exit 0:

```sh
python doc/validate-explorer-pq-rpc-schema.py
python -m py_compile doc/validate-explorer-pq-rpc-schema.py
ruff check doc/validate-explorer-pq-rpc-schema.py
ruff format --check doc/validate-explorer-pq-rpc-schema.py
git diff --check
```

The restored runner passes **135 vectors: 37 positive, 98 negative**. This count
belongs to this reconstruction, not the earlier unavailable package's 130-vector
receipt. Eight independent sensitivity controls pass: the original nonempty
certificate guard plus controller count, controller uniqueness, complete v1
fields, version fields, exact default provenance, forced retirement by flag and
retirement without flag/deadline. Every control removes its specific guard and
requires the targeted negative assertion to fail.

A separate baseline negative control passed by observing the intended failure:
using the original schema from the baseline, a v1 SizeLimits with empty configured
and defaulted fields passes validation and therefore triggers
`SizeLimits: expected valid=False, errors=[]`. The revised schema rejects it.
This control can be reproduced by loading the baseline JSON using `git show`,
using all effective field names with integer 1 values, and passing that object to
`check("SizeLimits", value, False, baseline_schema)`.

Static review parsed Markdown and all 10 fenced JSON examples, resolved 178
local schema references and 4 relative file links, and checked Python syntax and
whitespace. Changed boundaries are Markdown design, JSON Schema and its Python
validator; their checks are the parser/link/example checks, Draft 2020-12 vectors,
Ruff and the targeted red/green controls respectively.

No native node build, live RPC, cryptographic finality or worker cancellation
runtime test was performed. No C/C++ execution boundary changed, so the two-build
native static-analysis gate does not apply. The proposed 10-second deadline,
32-MiB cumulative proof budget, 32-query and 256-link limits require realistic
native fixtures before implementation acceptance. Schema shape tests establish
neither cryptographic correctness nor deployed behavior.

## Validated artifact hashes

SHA-256 of the four revised inputs (this receipt is excluded):

```text
b7e07682dad5b464abd17f4c8f8cfcdf80fcd2b1e386516ba4fbf12203c85d35  doc/explorer-pq-rpc-contract.md
e55c0bf36ee76d73b7702c5007a57792049769179a480f7fa52395746000c3c8  doc/explorer-pq-rpc-design.md
20151626bf4ff5d37a6f3b7a31ace74a32e3934ed580b88805c8db3bc1502bee  doc/explorer-pq-rpc-v1.schema.json
3ab216daead57a214789fa59f64a25287663ae594e4c73d14ba7ecfcd52ab4a3  doc/validate-explorer-pq-rpc-schema.py
```
