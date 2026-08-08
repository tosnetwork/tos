# ATOS TaskEscrow Publisher Compatibility

The ATOS contract Economic Driver deploys and mutates the native TOS
`TaskEscrow` contract through a separate key-custody publisher. The publisher
invokes `tosctl` using exact protocol commitments and integer nanoTOS amounts.

The task CLI therefore supports the following protocol-oriented inputs in
addition to the human-facing TOS decimal flags:

```text
agent task create/build-state  --permission-hash <32-byte hex>
agent task create/build-state  --budget-nanotos <uint64>
agent task create              --amount-nanotos <uint64>
agent task send                --amount-nanotos <uint64>
agent task send/encode         --payout-nanotos <uint64>
```

The atomic flags conflict with their decimal equivalents. This avoids
rounding an escrow budget or payout through IEEE-754 before it reaches the
contract. `--permission-hash` conflicts with `--permission-id`: the former is
used when an upstream protocol has already committed the exact hash; the
latter remains the convenient human-facing path.

The real-localnet acceptance test is:

```bash
TOS_PROTOCOL_DIR=/path/to/tos-protocol \
TOS_BUILD_DIR=/path/to/tos/build \
TOSCTL=/path/to/tosctl \
uv run python scripts/atos-task-escrow-publisher-e2e.py
```

It starts a validator, three funded wallet roles, the Go key-custody sidecar,
and the Go Economic Driver. The test covers contract deployment, acceptance,
result commitment, exact provider payout, principal refund, cancellation, and
lost-response/idempotent replay against the real TaskEscrow bytecode.
