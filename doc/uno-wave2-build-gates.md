# Explicit prototype and harness gates

The Linux x86-64 CI job enables `TOS_UNO_CRYPTO_PROTOTYPE_TESTS` and
`TOS_UNO_COUNTER_PYTEST`. It provisions locked dependencies before the build,
then runs Cargo with `CARGO_NET_OFFLINE=true`. The opt-in defaults for ordinary
local builds do not constitute CI acceptance.

The configured Cargo executable must report version 1.97.1. This validates the
tool selected by PATH/cache rather than assuming that a `cargo` executable is
a toolchain-manager shim. CMake build, Rust tests, real-ABI fixture generation
and header checks propagate offline mode to metadata subprocesses. The crate's
`.cargo/config.toml` also defaults direct builds from that directory to offline;
initial provisioning explicitly uses `CARGO_NET_OFFLINE=false cargo fetch --locked`.
These checks are not a cryptographic attestation of the compiler executable.

`test-counter-python-harness` registers the three existing Counter pytest files.
They test encoding, admission and harness assertions; they are not independent
process consensus/network acceptance. `TOS_UNO_COUNTER_NETWORK_TEST=ON` separately
registers the real-manager cold-join script. That opt-in needs its test node
targets built, a prepared Python environment, ports, disk headroom and room
within the script's retained-run cap. It is not enabled in the ordinary CI job.

`TOS_UNO_LARGE_SNAPSHOT_TEST=ON` builds and registers a separate large-snapshot
executable. The default snapshot executable does not compile that experiment.
The opt-in executable runs the experiment unconditionally: there is no missing
environment-variable success/skip. It retains the two-million-key workload and
is not a production account-capacity measurement.

Validation: actual fresh CMake configurations and CTest JSON manifests verify
the registered crypto, Python, network and opt-in snapshot names, then verify
that disabling the large option removes its registration. A fake executable
tests acceptance of the exact Cargo version and rejection of both an older and
a prefix-confusable version, while requiring the inherited offline environment.
Removing the version gate, removing offline propagation, and renaming away the
Python registration each made the relevant test fail. Assertions inspect exit
status and actual registrations, not error text. Logs are under
`build/uno-build-{cargo-pin,offline,registration}-mutation.log`.

The Python group has been run through CTest. The new network registration and
the large experiment have not been run as part of this wiring change; their
existence in the test manifest is not evidence of either acceptance result.
