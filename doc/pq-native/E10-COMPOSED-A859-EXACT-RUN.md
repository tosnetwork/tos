# E10 composed workflow exact-tree run — 2026-09-25

Status: local single-validator run PASS; E10 acceptance remains pending
independent raw-evidence review. This is not a multi-validator or release-scale
claim. Source and origin were `a859bb515547688e088adaf35482933a044dae7b`,
tracked tree clean. Command:

```text
script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-economy-composed-e2e.py' test/integration/.e10-composed-a859bb515-20260925-console.typescript
```

Exit code 0, 40 PASS, zero FAIL, terminal `RESULT: ALL PASS`. The retained
console is `test/integration/.e10-composed-a859bb515-20260925-console.typescript`
(SHA-256 `6927596f2df2e58e4c8186ef5409110cb2312adbf9619b34e7ecbc6b91a15409`).
The run directory was moved intact after shutdown to
`test/integration/.e10-composed-a859bb515-20260925-network/`; the original
absolute workdir in `process-map.json` therefore names the pre-archive
location. All validator/DHT/test processes exited before archiving.

Retained raw artifacts and SHA-256:

| Artifact | SHA-256 |
| --- | --- |
| `manifest.json` | `93e770121b5e0934b3194112a622c2cdfc5ff7215c43b04a4a437cdf67a5c114` |
| `rpc-transcript.jsonl` | `a5c142fd27c5a8d27b282527e3e84d4f60715c84f561029a3d1a8633753c0d8a` |
| `cli-transcript.jsonl` | `2e9ac8867198c7e0a44107e736efdf25b4507203032f608db2bd5ebc6de9c273` |
| `chain-evidence.jsonl` | `857e8602014d1a164333ac8269a883422d8fa073006acbcfb267a233c40238fc` |

The manifest binds script SHA-256
`394f4cb8ac4d3b5a5eaee312d16f069972297e5d22b9e06e501886bea4b657e8`,
test SHA-256 `5323795ab9de422b482b1d7dbc623e631cd8f051a94f27c3fd6c6f1ed296ebf5`,
and validator-engine/DHT/tosctl hashes
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
`bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
Raw RPC transcript rows name their endpoint: 192 primary, two per independent
observer; `process-map.json` records three distinct PIDs.

The two refusal controls are direct transaction evidence, not CLI-only checks:

| Control | Wallet send LT | Target LT | Bounce wallet LT | VM exit | Message hashes |
| --- | ---: | ---: | ---: | ---: | --- |
| settle without attestation | 204000001 | 204000003 | 204000005 | 9 | send/inbound `ZQcfO0Ow8Rg26BVClGYw0XavIEyjnU2kG7VStMz2Ens=`; target-bounce/wallet-inbound `4Xu50eoKN4Pk2SP2zrCC/MWzmxzJlDymzzzN+OQ8gUo=` |
| rule without attestation | 308000001 | 308000003 | 308000005 | 9 | send/inbound `r9NWnQtLBA41Uu3pDHIiofC9bSiNrbaJLl+PbJziXLc=`; target-bounce/wallet-inbound `+HzEJV7lGpPe6hDW7KGqrhcLj5jHXLZ9hhz3KO4sPAI=` |

Both controls also checked two later finalized masterchain heads and unchanged
contract state. The happy path paid the worker Agent Account; the contested
path opened an attested Dispute, accepted an attested split ruling, and paid
the split-translated amount. The test proves this composed local route only;
it does not establish multi-validator quorum or transport authentication.
