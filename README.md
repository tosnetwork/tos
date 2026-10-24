# TOS Blockchain

[![x86-64 build](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-x86-64-shared.yml/badge.svg?branch=main&event=push)](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-x86-64-shared.yml?query=branch%3Amain)
[![arm64 build](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-arm64-shared.yml/badge.svg?branch=main&event=push)](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-arm64-shared.yml?query=branch%3Amain)
[![Lint](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-x86-64-werror.yml/badge.svg?branch=main&event=push)](https://github.com/tosnetwork/tos/actions/workflows/build-tos-linux-x86-64-werror.yml?query=branch%3Amain)
[![PQ chain and Python tests](https://github.com/tosnetwork/tos/actions/workflows/branch-chain-python.yml/badge.svg?branch=main&event=push)](https://github.com/tosnetwork/tos/actions/workflows/branch-chain-python.yml?query=branch%3Amain)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)

**Post-quantum consensus, wallets and contracts. Shielded native-asset transfers.**

TOS is an open-source Layer-1 blockchain with a masterchain, shardchains and
native TVM smart-contract execution. Its canonical genesis uses **ML-DSA-44
validator signatures**. Contracts can verify **four post-quantum signature
suites**: ML-DSA-44, Falcon-512, SLH-DSA-SHA2-128s and an LMS fee profile.
The PQ wallets use them for daily authorization, recovery and fee payment. The
shielded-pool implementation combines zero-knowledge transaction proofs with
**post-quantum note authorization and encrypted note delivery**.

[Technical overview (PDF)](doc/pq.pdf) · [Overview source](doc/pq.tex) ·
[Documentation](doc/README.md) · [Build guide](BUILD.md)

## Security by layer

Different mechanisms protect different things. TOS does not treat a PQ
signature as a claim that every wallet, network connection or proof system is
quantum resistant.

| Layer | Implemented mechanism | What it protects |
| --- | --- | --- |
| Validator consensus | ML-DSA-44, algorithm ID 1 | Authenticity of PQ validator consensus signatures |
| Validator stake | ML-DSA-44 stake authorization over the staking account, election and ADNL | A stake registers only for the account that sends it and the key that signed it |
| Contract verification | Native `PQCHECKSIG_SUITE` for suites 1–4, plus dedicated `PQCHECKSIG_MLDSA44`, `PQCHECKSIG_FALCON512_PADDED` and `LMSCHECKFEEHASH` | Explicit PQ authorization in contracts that use it |
| Quantum wallet | ML-DSA-44 primary key, SLH-DSA-SHA2-128s protection and recovery key | Asset authority and recovery of a PQ-only wallet |
| Wallet fees | LMS fee profile (hash-based, stateful) | Payment of the specified fee classes only; no asset authority |
| Shielded note spending | One-time ML-DSA-44 key per note | Authorization bound to the private transaction intent |
| Shielded note delivery | ML-KEM-768 + XChaCha20-Poly1305 | Confidential, authenticated delivery of note secrets |
| Shielded transaction validity | Groth16 over BLS12-381; Poseidon2 commitments and trees | Private witness verification, value constraints and double-spend prevention |

**Boundary:** Groth16 is pairing based and is **not a post-quantum proof
system**. The V1 profile defers a PQ-soundness migration. PQ consensus and
note encryption do not turn the complete privacy system into a fully
quantum-resistant protocol. Network metadata and transparent transfers also
remain visible within their respective interfaces.

## Post-quantum signature suites

All four suites are active from global version 16, the genesis version. Each
verifier charges gas for every input byte and fails closed on an unknown suite
or profile.

| Suite | Algorithm | Used by | Status |
| --- | --- | --- | --- |
| 1 | ML-DSA-44 (FIPS 204) | Validator consensus keys, Quantum wallet primary key, one-time shielded note keys | Canonical |
| 2 | Falcon-512, padded original profile | Falcon wallet authorization module | Experimental; formal FN-DSA will be a separately versioned profile |
| 3 | SLH-DSA-SHA2-128s (FIPS 205) | Quantum wallet protection and recovery key | Implemented |
| 4 | LMS fee profile | Quantum wallet fee authorization | Implemented; authorizes fees only |

Validator consensus uses ML-DSA-44 only. The wallet suites are implemented and
tested in this repository; production custody and default activation still
depend on the release gates in the
[Quantum wallet status](doc/wallet-quantum-release-status.md) and the
[Falcon profile](doc/wallet-falcon-fndsa.md). Do not infer that those gates are
complete from this README.

## Post-quantum consensus from genesis

The canonical genesis profile uses:

- ConfigParam 8 **version 16** and four equally weighted PQ validators;
- `validator_pq_addr#b3` descriptors with **ML-DSA-44** public keys;
- **Simplex version 2 over QUIC**, distinct from the VM/global protocol version;
- independent staking-account, consensus-key and ADNL transport identities;
- elections in which a wallet or nominator pool stakes directly with the Elector.

An ML-DSA-44 public key is 1,312 bytes and a signature is 2,420 bytes. Those
larger objects require bounded encodings, validation and resource budgets;
changing a version number alone does not migrate validator identities.
The canonical generator rejects the legacy classical bootstrap key file.

Operators supply public identities through `validator-pq.pub`; private keys
remain with their operators. See the [PQ genesis ceremony and parameters](doc/validator-genesis-bootstrap.md)
and [validator guide](doc/Validator.md). Wallets and administrative paths must
be assessed separately: a PQ validator set does not automatically replace their
authentication schemes. Accounts gain PQ protection by using the PQ wallets
described above.

## Privacy with shielded TOS

The V1 pool is a native-TOS contract on workchain 0. It uses commitments to
represent notes, nullifiers to reject repeated spends, and proofs to validate
transactions without exposing the private note witness.

```text
Transparent TOS  ── deposit ──>  Shielded notes
                                      │
                              private transfer
                                      │
Transparent TOS  <─ withdraw ──  Shielded notes
```

The implemented profile has a fixed **two-input, three-output** transaction
shape. Real and dummy output payloads have the same length. Recipients scan
chain-delivered encrypted data to recover their notes; one-time PQ keys
separate note spending authority from public account signatures.

Privacy has a defined scope:

- Private note values and ownership witnesses are verified inside the circuit.
- Deposits, withdrawals, public payout amounts/recipients, fees, commitments,
  nullifiers and transaction timing are not all hidden. Public entry and exit
  flows can permit correlation.
- Network anonymity, traffic-analysis resistance and protection from a
  compromised wallet are not supplied by the pool.
- Recipient descriptors are single-use. The V1 viewing key is reused within an
  execution domain, so collaborating senders can recognize that off-chain key.
- Multi-asset notes, arbitrary transaction shapes and a PQ proof backend are
  outside the V1 scope.

See the [frozen implementation profile](artifacts/shielded-pool/PROFILE.md),
[circuit implementation](tools/shielded-pool-circuit/README.md),
[wallet implementation](tools/shielded-pool-wallet/) and
[ceremony procedure](artifacts/shielded-pool/CEREMONY.md).

### Deployment status

The pool profile explicitly gates public-network activation on its acceptance
requirements. Repository code and local tests are not deployment approval.
**Development proving/verifying keys are derived from a known seed and must
never secure real funds.** Production use requires a verified ceremony,
matching circuit/profile/code identities, funded operation and completion of
the profile's acceptance gates. Do not infer that these gates are complete
from this README.

## Execution and node infrastructure

TOS executes contracts in TVM using cells, messages and deterministic gas
accounting. Contracts can use native cryptographic instructions, but must
still handle asynchronous receipts, bounced messages, replay protection and
fund ownership correctly.

The node stack includes validator and full-node processes, sharded-chain
validation, ADNL/DHT/overlay networking, JSON-RPC and Lite Client interfaces.
Fift, FunC and Tol support contract development; Rust tooling supports node
control and operator workflows. Health tooling exposes observations and
coverage gaps: missing telemetry is not a healthy zero.

## Build and explore

Follow [BUILD.md](BUILD.md) for dependencies and the supported compiler profile.
A minimal out-of-source build is:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target validator-engine create-state gen_fif -j2
```

Rust operator tooling:

```bash
cd tosctl/src
cargo build --locked
```

Network deployment settings, for the local development network as well as
production, are maintained outside this repository. Local wallet and ceremony
fixtures are never production keys.

## Repository map

| Path | Contents |
| --- | --- |
| `crypto/pq/` | PQ identities, signing, verification and key provisioning for all four suites |
| `crypto/vm/pqops.*` | TVM PQ signature instructions |
| `crypto/smartcont/` | Contracts (including the Quantum and Falcon wallets), shielded primitives and canonical genesis |
| `validator/`, `validator-engine/` | Consensus, chain validation and node services |
| `tools/shielded-pool-{circuit,wallet,ceremony,genesis}/` | Privacy circuit, wallet, setup and deployment tools |
| `tools/node-health-monitor/` | Bounded collection and health query services |
| `tosctl/`, `lite-client/` | Operator and chain client tooling |
| `doc/` | In-tree specifications, manuals and papers |
| `artifacts/shielded-pool/` | Frozen profile and deployment inputs |

Additional documentation is maintained in [tosnetwork/doc](https://github.com/tosnetwork/doc/tree/main/tos-blockchain).
For this checkout, start with the [in-tree index](doc/README.md) and
[global-version rules](doc/GlobalVersions.md).

## Technical overview and license

[`doc/pq.pdf`](doc/pq.pdf) explains the architecture, privacy flow and security
boundaries. Rebuild it from [`doc/pq.tex`](doc/pq.tex) with
`bash scripts/build-pq-paper.sh` (requires `pdflatex`).

TOS is licensed under the [GNU General Public License v3.0](LICENSE).
