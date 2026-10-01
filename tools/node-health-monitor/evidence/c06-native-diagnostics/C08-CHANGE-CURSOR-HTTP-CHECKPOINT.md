# C08 change-history HTTP cursor checkpoint — synthetic retained rows

The actual `/v1/query/change-history` router now has a fixed-W pagination
control parallel to the existing event-window control. Three isolated
synthetic `operator_change` records share exactly the same observed time but
have distinct store sequences. Their content was chosen so SHA-256 lexical
order differs from store order; the test asserts this premise explicitly.
With limit one, three real HTTP pages return `record-1`, `record-2`,
`record-3` in store order. A fourth row inserted after grant W is absent.
Each output deserializes as the typed `ToolEnvelope`, and reusing the first
cursor with a changed kind filter returns HTTP 409.

The first fixture happened to have hash order equal store order. A new
premise assertion exposed that insufficient control (test red); the final
synthetic reason varies by sequence and passes. A compiled mutation of the
actual query comparator from `(store_seq,evidence_id)` to
`(observed_at,evidence_id)` then failed the intended HTTP page-order
assertion: first page returned `record-2` instead of `record-1`. The original
query source was restored and its SHA rechecked. This proves sensitivity to
that changed property, not production change-source availability.

Final source SHA-256:

- Restored `health-core/src/query.rs`:
  `06a71d892528b851299692d24a82aedfd6d506a6878aa21b435e3009d81bb5ed`
- `health-services/tests/http.rs`:
  `e3fc2d56cbddb7790df86a7b688d13d44a83355a9499642af97b76da08fdab09`
- Compiled comparator mutant `query.rs`:
  `c944598d7fc56d4e5d2196d94991c07c35d8d918b7063c29b11eee1b5425115c`

Raw logs under `$HOME/nhm-c08-mcp-evidence/`:

- `c08-change-cursor-mutant-order.log`: compiled test exit 101 at the
  `record-2` versus `record-1` assertion, SHA-256
  `f5e56c98c236bb02a475a2e3abf42484f6b55a63dd95de24f0c2fe429d6b9b5b`.
- `c08-change-cursor-final-http.log`: `cargo test --locked -p
  tos-health-services --test http`, natural exit 0, 18 tests passed, SHA-256
  `590b6b57d81536674659db31a8e09c554f30d59dfc114352eb9668bbbb2a5e03`.
- `c08-change-cursor-final-clippy.log`: strict all-targets MCP feature
  clippy natural exit 0, SHA-256
  `4fddaff37f402de757e157de67b98476c87458dc309d889d318307459e374370`.
  `cargo fmt --all -- --check` also passed.

Historical `c08-change-cursor-baseline.log` and
`c08-change-cursor-mutant.log` are retained; the latter failed at a pagination
assertion before the explicit per-page order assertion was added. They are
not substituted for the final intended mutation evidence. The source is an
isolated fixture, not a production operator-change adapter; C08 and all
production gates remain open.
