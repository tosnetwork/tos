# C09 functional QueryService live one-shot — evidence index

One authorized attempt on 2026-09-30; no timer, model call, QueryService deployment, or business restart. This is a functional control, not C09 or 72-hour acceptance.

- Source: `nhm/c09-functional-soak-starbridge@e03e2f5e5904e21ff6f99d44185c2ffdb942d710`; `scripts/sample-query-functional.py` SHA-256 `1da3030e9de70e64984c1131f21bb516cb6e72e3656dedf7e35ec1f3196aef2b`.
- Running QueryService binary SHA-256 `e37f9c4353bb80f5ae8acd3a941d7eeb21b5f116a448448adb79588fb94cf8ee`.
- Frozen Q baseline SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f` before request; six collectors fresh in `receipt.redacted.json`.
- One private control grant and one MCP process call for `validator4`; returned 2,290 bytes with actual positive PID process payload (payload SHA-256 in receipt). Original retained M parent seq 24441 <= frozen grant M W 24455; Q evidence seq 11018 <= frozen Q W 11021. Grant durably revoked (`revoked=1`).
- Fixed-grant query: `pass`; separate projection-head probe: `lagging`. No 503 or timeout on this attempt.

## Files

`receipt.redacted.json` is safe to review: it contains request/response shape, source identity, frozen bounds, hashes and result, with no token, run ID, evidence ID or raw process payload. Private raw files remain only in this mode-0700 local directory and are Git-ignored.

- `receipt.redacted.json`: 2844 bytes; SHA-256 `98150fd8ce81c8ba7b9ac3880e9e9a57fc1fcdab337a0566ad94f02a8ca06166` (redacted receipt)
- `baseline.private.json`: 274 bytes; SHA-256 `25c0458888a275bcf9568bc1fc53d914e9d5a3901932b0840444d99a3ea3382f` (private, local only)
- `preflight.private.json`: 1325 bytes; SHA-256 `83a254c54aaf2923b57cfc3a5ea5737eebe2cfc89c9c08ca14eb3e1fb1941c74` (private, local only)
- `witness.private.jsonl`: 452 bytes; SHA-256 `4e5606ae611c8d55bf0f2003f8afcf22f66fc190d01f51117e63b03b4e76065f` (private, local only)
- `raw.stdout`: 60 bytes; SHA-256 `cbe039ff4ff64f45fc2bd772bf99d4851542b02352cc67983f02e3f55d435b7b` (private, local only)
- `raw.stderr`: 0 bytes; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (private, local only)

The private raw JSONL and stdout record the exact one-shot result. `raw.stderr` is empty. `preflight.private.json` records the exact pre-request Q/M inode, Q baseline and six-node freshness; `baseline.private.json` is the immutable input pinned by SHA-256. The source itself does not log bearer tokens or process payload.
