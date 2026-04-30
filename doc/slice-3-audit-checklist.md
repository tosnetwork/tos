# Slice 3 Audit Checklist

Status: complete on 2026-04-30. The maintainer accepted the Stage 8
repo-side surrogate as the release gate.

| Area | Check | Status |
| --- | --- | --- |
| Protocol surface | No new TL-B constructor, TVM opcode, rich-bounce constructor, or wallet-v5 external body preflight | Complete |
| Wire parity | Reference Jetton and wallet-v5 Tol BoC hashes remain at approved baselines after stdlib wrapper migration | Complete |
| Gas | Slice 1 gas gate and FunC-vs-Tol parity gate are green | Complete |
| Replay | `scripts/check-slice-3-replay-fixtures.py` validates fixtures and runs Slice3Replay emulator cases | Complete |
| Stdlib manifests | Pattern manifests include opcodes, errors, storage fields, compatibility exceptions, and reply-correlation mode | Complete |
| Static analysis | Receive exhaustiveness warning pass and Slice 3 reply-correlation pass are wired before codegen | Complete |
| Scaffolding | `tol new --pattern jetton/nft/wallet/multisig` generates source, tests, replay, deploy, manifest, and observability artifacts | Complete |
| Release package | Jetton/NFT example projects and release docs are checked by `scripts/check-slice-3-release-package.py` | Complete |
| Author trial | Stage 8 repo-side surrogate builds a Jetton/NFT path in under one hour and is accepted as the release gate | Complete |

## Reviewer Commands

```sh
cmake --build build --target tol test-emulator -j 32
python3 scripts/check-slice-3-release-package.py
python3 scripts/check-slice-3-scaffold.py
python3 scripts/check-slice-3-replay-fixtures.py
python3 scripts/check-slice-1-gas.py
git diff --check
```
