# TOS Documentation

What belongs here: the base-layer **specifications**, the formal **papers**, and
the **manuals** for running and testing a node — documents you read to answer a
question about how the chain works or how to operate it.

What does not: proposals, implementation plans, roadmaps, draft RFCs and
use-case explorations. Those record where a line of work was going rather than
what the chain does, and they live in <https://github.com/tosnetwork/doc>, which
is already where the source comments in this repository point.

## Specifications

| Document | What it covers |
| --- | --- |
| [ConfigParam.md](ConfigParam.md) | Configuration parameters and their meanings |
| [Currency.md](Currency.md) | Currency units and amount formats |
| [DNS.md](DNS.md) | TOS DNS records and resolution |
| [GlobalVersions.md](GlobalVersions.md) | Global protocol versions and the capabilities each enables |
| [TosSites.md](TosSites.md) | TOS sites and the RLDP HTTP proxy |
| [Zerostate.md](Zerostate.md) | Zerostate format |
| [openapi.yaml](openapi.yaml) | The REST surface. **Do not move or remove:** a running node advertises `https://github.com/tosnetwork/tos/blob/main/doc/openapi.yaml` from its `/api-info` endpoint |

## Post-quantum authentication

| Document | What it covers |
| --- | --- |
| [tvm-mldsa44.md](tvm-mldsa44.md) | The native ML-DSA-44 verification instruction: opcode, ABI, canonical operand encoding, gas, version gating, vendored backend |
| [tvm-mldsa44-validation.md](tvm-mldsa44-validation.md) | Acceptance matrix, calibration method, and the limits of what the public vectors prove |
| [mldsa44-auth-module.md](mldsa44-auth-module.md) | The immutable authentication module: exact signed bytes, funding failure classes, deployment and rotation boundary |

## Running and testing a node

| Document | What it covers |
| --- | --- |
| [FullNode.md](FullNode.md) | Running a full node |
| [LiteClient.md](LiteClient.md) | Using the lite client |
| [Validator.md](Validator.md) | Running a validator |
| [Validator-Local.md](Validator-Local.md) | A local four-node testnet |
| [validator-genesis-bootstrap.md](validator-genesis-bootstrap.md) | Genesis validator bootstrap and `validator-keys.pub` |
| [macos-local-node.md](macos-local-node.md) | Running a local chain on macOS, where the systemd setup script does not apply |

## Release process

| Document | What it covers |
| --- | --- |
| [tos-release-policy.md](tos-release-policy.md) | What a release is and what it must satisfy |
| [tos-upgrade-process.md](tos-upgrade-process.md) | How a change reaches a running network |

## Papers

Each is kept with its TeX source where one exists.

| Paper | Subject |
| --- | --- |
| [The-TOS-Protocol.pdf](The-TOS-Protocol.pdf) ([docx](The-TOS-Protocol.docx)) | The protocol |
| [tblkch.tex](tblkch.tex) | The block chain |
| [tvm.tex](tvm.tex) | The virtual machine |
| [catchain.pdf](catchain.pdf) ([tex](catchain.tex)) | Catchain consensus |
| [simplex.pdf](simplex.pdf) ([tex](simplex.tex)) | Simplex consensus |
| [fiftbase.pdf](fiftbase.pdf) ([tex](fiftbase.tex)) | The Fift language |
| [func_v0.4.6.pdf](func_v0.4.6.pdf) ([tex](func_v0.4.6.tex)) | The FunC language |
| [tol.pdf](tol.pdf) ([tex](tol.tex)) | The Tol language |

`examples/` holds data files referenced by the documents above.
