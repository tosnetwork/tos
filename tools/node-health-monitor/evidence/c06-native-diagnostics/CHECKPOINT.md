# C06 implementation checkpoint — not acceptance

Base: `35ba59c111dd74518e6e661bcd1984598d493907`.
Branch: `nhm/c06-native-diagnostics`. Supervisor owns integration and actual
node deployment; this checkpoint does not authorize promotion or a main merge.

Implemented boundaries: lazy scalar producer admission, catalog8 phase wire,
fixed seven diagnostic metric tuples (249+7=256), independent bounded native
status, credential/epoch checked nonblocking datagrams, bounded relay, counted
encrypted TCP egress, fixed diagnostic-only mTLS role, dedicated M credential,
owned diagnostic permits and the existing evidence writer's batch transaction.
Required nullable query counters distinguish unknown from measured zero.

Preliminary evidence is in `/home/tomi/nhm-c06-evidence/raw/`. Standalone native
producer/IPC controls and six compiled isolated mutants passed intended assertion
kills and restored runs. The first enabled mutation failed a later assertion;
that rejected receipt is preserved separately. A real native subprocess through
IPC, relay, mTLS and M committed ten rows before the later coverage/counter
changes. The isolated preliminary validator-engine build exited zero; a final
hash-stable build and the new native hook control remain required.

Current red: stricter owned-row accounting rejects the new partial-coverage row;
the capacity derivation/control is being corrected before final acceptance.
Prior query missing-coverage and wrong-storage-gate failures are preserved.
Required remaining gates include final owned-capacity, HTTP refusal, SQLite/WAL
quota and restart controls, faithful Rust mutations, exact source/build union,
and independent supervisor review. No production or performance pass is claimed.

Delivery corrections and final evidence are described in [DELIVERY.md](DELIVERY.md).
The checkpoint reds above describe the earlier state, not the delivered candidate.
