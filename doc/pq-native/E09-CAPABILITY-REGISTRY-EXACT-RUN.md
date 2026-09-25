# E09 Capability Registry exact-tree run — 2026-09-25

Status: OPEN pending independent review and pushed-tree CI. The local run
uses one PQ validator; it is not multi-validator or release-scale evidence.

PG's independently reviewed offline patch `d09c623f3` was integrated as
`250fc629b`: negative operations require a unique wallet send, a matching
Registry inbound hash, the specified aborted VM exit, two advancing finalized
masterchain heads and unchanged full Registry state. The E08 real-chain
failure demonstrated that a refusal's bounced credit may arrive after the
next operation would otherwise record its wallet baseline. The separate
`e1dd48d6f` unit therefore binds each additional wallet credit to the exact
Registry transaction's outgoing bounce and waits for that credit before the
next operation. A full 10-transaction page without baseline fails closed.
The script also writes a pre-network manifest with source commit, clean-tree
flag, command and script/test/validator/DHT/tosctl SHA-256. Its targeted
non-network suite passes 10/10. Deleting only the
`bounce_hash not in expected_hashes` condition makes the wrong-bounce test
fail because an unrelated credit is accepted. The retained mutant output is
`test/integration/.e09-bounce-hash-mutant-e1dd48d6f-20260925.log`
(SHA-256 `46d7e06c36144a57d3649b75053af4d91bc1b0a4e0bcdbd8524f9c0bc202008b`);
mutant script SHA-256 is
`6759a38452e95e30de36f74e31539c2277c4d48298eabd5d946a21cff687de4f`.
The source was restored and the same 10/10 tests passed before this note.

The exact committed `e1dd48d6ff19a8f48f383c69c88715fb2bb452c4` run used:
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/capability-registry-e2e.py' test/integration/.e09-capability-registry-e1dd48d6f-20260925-console.typescript`.
It exited 0 with 31 PASS, zero FAIL and `RESULT: ALL PASS`. Console SHA-256:
`3c5d1fe3cc005059bcf6bd2f08ddd1093bad05f63a726acc1f047652ecea1e0a`.
The original node/config and raw receipts are retained under
`test/integration/.e09-capability-registry-e1dd48d6f-20260925-network/`.
Manifest SHA-256 is `d1422234c4454a15b8fc3ff66baa66bacb8a64d8b23db58b09321c5089751796`,
RPC transcript `0c283079c2e5c6db10c124c88d8df85248d8f08ced52aa6265e7a04811a084d9`,
CLI transcript `23e80e0bb3fe343e1820f781acbeb485cb5bc012c3f90a6f10fa8d4e84f41030`,
and five negative receipts
`a02fdf842f2ad6b7e2610be7c788223a0e905db5315e0b13e689186328fbe89f`.
Their exact aborted VM exits are `1800` for non-owner metadata, `1800` for
non-owner stake, `1801` for non-verifier reputation, `1805` for over-bond
withdrawal and `1803` for inactive metadata. Each receipt includes the
wallet transaction, Registry transaction, matching inbound/outbound hash,
exact wallet bounce and two subsequent finalized observations. The manifest
records `source_tracked_dirty=false`, script SHA-256
`796184b385c3f97e7892de14155083c78f3c10a4e3ce84c181f24f20c7342cd1`,
test SHA-256 `f0ee30f2b7e3aa8affea23e345ed69d058dafc8721964f141d35f13a928d39ef`,
and validator-engine/DHT/tosctl binary SHA-256 values
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
`bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local network processes exited. This local result does not sign off E09;
the pushed-tree CI and independent raw-receipt review remain separate gates.
