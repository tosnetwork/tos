## 2026.10 Update

The first TOS release built for a public network. It is published as `v2026.10-1`; the tag `v2026.10` names an earlier commit and has no release.

1. Post-quantum validator consensus: validators sign blocks and certificates with ML-DSA-44 under Simplex v2 over QUIC. Genesis commits four PQ validators from a public-key manifest (`validator-pq.pub`); later sets are elected through controller contracts admitted by ConfigParam 47. A validator can hold several consensus keys for zero-downtime key rotation.
2. Launch cap of 21 active validators, enforced as a rejection rather than a clamp (`config/pq-launch-limits.json`).
3. Global version 16: native ML-DSA-44 verification in TVM, post-quantum authentication modules for Wallet V5 and Agent Account, a Falcon-512 wallet path, the Quantum wallet with an SLH-DSA rescue key, and a relayer-funded post-quantum high-volume wallet.
4. Shielded pool V1: private transfers of native TOS on workchain 0, Poseidon2 in both VMs, and a Groth16 verifier whose phase-2 ceremony was finalised with an announced beacon. The pool is a separately deployed contract; it is not part of genesis.
5. Validator economics: issuance goes to validators only, about 10 million TOS over the first two years from block-creation fees. The genesis bootstrap wallet funds the first elections and its remainder is burned.
6. Elector: pooled staking through single-nominator pools, corrected principal accounting and relay refund recovery, and cancellation of a closed election that cannot be conducted.
7. Operator tooling: release archives ship the PQ consensus-key, controller, vote and offline root-key tools; `tos-pq-consensus-key bind-node`; `tosctl` checks and plans operating authorization, deploys controllers and creates configuration proposals; retired consensus databases are cleaned up by default.
8. Hardening before launch: five security rounds over consensus, JSON-RPC and networking; bounded growth paths in ADNL, overlay, QUIC, RLDP2, HTTP and storage; RLDP v1 and the catchain session removed; signed overlay receive policy and Plumtree broadcasts; capacity-starvation fixes; and the upstream 2026.07 and 2026.08 fixes absorbed.
9. Contracts: `.tos` DNS, cross-chain bridge contract planes, Agent Account with Task Escrow, a capability registry, the V1 prediction market, config-priced jetton fees, high-volume wallets and multisig.
10. Node health monitor for validators and observers.
11. Platforms: the node and its tools are built, tested and released for Linux on x86-64 and arm64 only.
