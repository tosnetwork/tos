## 2026.04 Recent Changes

1. Wallet security hardening:
Added `global_id` anti-replay protection to wallet signing and verification, so wallet messages signed for one network are rejected on another. This applies across wallet contracts, Fift scripts, C++ signing code, zerostate generation, and `toslib` wallet wiring.

2. Wallet contract refresh:
Unified wallet bytecode loading on auto-generated contract code, removed legacy hardcoded wallet revisions, added `Wallet V4` and `Wallet V5` contract sources, and aligned test coverage with the new wallet signing format and revision model.

3. Build and compatibility cleanup:
Adjusted build and compatibility details needed by the wallet changes, including compiler compatibility fixes and test expectation updates.
