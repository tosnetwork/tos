# E05 filter discrimination — exact local run, 2026-09-25

Status: local exact-tree PASS; fixed-head CI and Mac independent review pending.
This supplements `E05-AGENT-QUERY-API-RETAINED-ROUTE.md`; it does not close
E06/E07 or any release-scale route.

Mac's review of `540110053` found that all three Tasks shared both creator
and agent. A service ignoring either filter could therefore still return the
expected three rows. PG's offline fix
`c3f216b122d46758ca2506c0e1bd9175851667b7` was integrated as
`06bcc5aff`: two inverse queries use the *other*, distinct funded wallet and
demand an HTTP 200/`ok` empty list. The separate
`c5b77a3c8a888a42f223ccbec66ecbde4940bd81` unit adds an in-run manifest
binding the exact commit, tracked-tree cleanliness, script/test hashes and
validator-engine/DHT/tosctl binary hashes. The manifest refuses tracked
source edits before network boot. Focused non-network tests: 11/11 pass,
including ignored-filter, route wiring, and clean/dirty manifest controls.
These are local implementation checks, not PG's independent review.

The exact `c5b77a3c8` real-chain command was
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-query-api-e2e.py' test/integration/.e05-agent-query-api-c5b77a3c8-20260925-console.typescript`.
Exit code 0, 38 PASS, zero FAIL, `RESULT: ALL PASS`; console SHA-256
`d23a002757222ed8b17d0bbe54c83aa61db010fd749f5ce45200d7190de0f8cb`.
The network DB/configs, manifest and 16-line raw HTTP transcript are retained
under `test/integration/.e05-agent-query-api-c5b77a3c8-20260925-network/`.
Manifest SHA-256 `e6fbfe06a787490a138584db7f4ca42318c5d9b97b6c2385d326f0639c58048a`;
HTTP transcript SHA-256 `36eb9cfae2a0a1c35bf4ff2548eaf6506987724b3170aadbc2700736b2bd5a91`.
The manifest records `source_commit=c5b77a3c8...`,
`source_tracked_dirty=false`, script SHA-256
`9c632121e56688fcad352311bd67c7a4c221efdf72f285ec515c96ea52971b64`,
test SHA-256 `4203b448be7983916e712f875be74563d0463decfee7a519c2f177b147285436`,
and binaries validator-engine
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
dht-server `a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
tosctl `bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local processes exited.

The positive `/tasks?creator=<creator>` and `/tasks?agent=<agent>` returned
three complete entries each. The inverse queries returned HTTP 200,
`ok=true`, `total=0`, and empty result arrays, so a service that ignores
creator or agent would fail. The remaining invalid-address probes returned
the expected 400/404 bodies. This is one local PQ validator's advertised
query route, not a multi-validator or release-scale claim.
