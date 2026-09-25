# E08 Proof Attestation exact-tree run — 2026-09-25

Status: OPEN pending independent review and pushed-tree CI. This is a local
single-validator PQ-chain route, not multi-validator or release-scale evidence.

The first exact `2221a55a1893a175c6dbf77f7de754187be79413` run exited 1
after the positive attestation and first wrong-key refusal. Console:
`test/integration/.e08-proof-attestation-2221a55a1-20260925-console.typescript`
(SHA-256 `15ca60ef3bf3a0323d1d3e7a1df1bafa0de48f54daa30d17b062269fa8ce8668`).
Node data, manifest, CLI and RPC raw transcripts are retained in
`test/integration/.e08-proof-attestation-2221a55a1-20260925-network/`;
their SHA-256 values are, respectively, manifest
`2063d1cd10fcacccb5191d0315fbd3b92c8b89acb8ff3377e5d7f2b52c4ef9b0`,
RPC `14b773eb50b834d4aec774fc040d26709839bfa464b780f97b5f35c4a7a35e63`,
CLI `54c728f99855ea180eb9fe1ad4b3259e1374f9c48906b4ed77a77d7707119a83`.
The second negative's wallet baseline was LT `77000001`, but the first
negative's genuine bounced credit arrived later at wallet LT `84000001`.
The strict same-transaction bounce check correctly refused to attribute this
earlier credit to the second contract transaction. This is an observation
ordering failure of the harness, not a contract failure. No message was
resent after the ambiguous result.

`f5808d03dc99ed8e3e7ca5caecc96be1ab470b45` adds a bounded wait for
each refused transaction's exact bounced credit before the next operation
captures its wallet baseline. The wait checks the real contract outgoing
hash/source/destination against the wallet incoming transaction; it does not
permit an unrelated bounce. Its targeted non-network tests pass 11/11,
including a wrong-hash refusal and the preceding-bounce ordering control.

The exact `f5808d03d` rerun used:
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/proof-attestation-e2e.py' test/integration/.e08-proof-attestation-f5808d03d-20260925-console.typescript`.
It exited 0 with 23 PASS, zero FAIL, `RESULT: ALL PASS`. Console SHA-256:
`5b6708adb70b1899caa6ce6eaf6fc068f6bcfa6ff0124de2d78a27125ca049f3`.
The untouched node/config data and raw files are under
`test/integration/.e08-proof-attestation-f5808d03d-20260925-network/`.
Manifest SHA-256 `25c45deddcb6b085fb8649ada9c49d4e2cd37dad3738e5a1bcf2c892ef8071e3`,
RPC transcript `ea13c9c267e0c115097fa37aae634ef8e616039b6eb48e148e710924e3767ec8`,
CLI transcript `27094e3c0c6638c65fa482c36819777b66aa01445122a538ce9b75d563618504`,
negative-evidence receipts `4f0d5c7ed1e7fee08aefbb1a9574029d97c2e18bbac019f3a6c2f159251be36b`.
The five exact aborted contract receipts give VM exits `2101`, `2102`,
`2101`, `2102`, `2100`, each with the wallet outgoing hash equal to the
contract incoming hash and the contract bounce equal to the subsequent
wallet credit. The manifest records `source_tracked_dirty=false`, script
SHA-256 `2e48ee19ba593c07e776f98138e84f9b099f8d87ae34c4f9bc05fa81108cee5c`,
test SHA-256 `b89bd9cc87562e0a6a39fcfce3d483fe0815e073fd5f99671e42c0d467f2a222`,
and validator-engine/DHT/tosctl binary SHA-256 values
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
`bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local network processes exited. Independent receipt review and fixed-tree
CI are separate acceptance gates; E08 remains OPEN until they complete.
