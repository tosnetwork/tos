# AUTH retirement policy v1

ConfigParam 48 is the mandatory policy for V5R2 PRIMARY authorization. This
implementation now covers governance installation and the native node configuration
validity/transition predicates. Explicit version-17 genesis construction and trusted-state admission are now
implemented. Full receiver/module integration and shard-propagation evidence
remain required before release.

The policy identity is SHA-256 of the following exact ASCII string, without newline:

```
TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;deadline=u32;network=bits256;monotonic
```

Digest: `5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0`.

Encoding: `a1:8 network_tag:256 sequence:64 retired:16
schedule:(HashmapE 8 uint32) policy_spec_hash:256`. Only daily suite 1 and its
retirement bit are admitted in v1. A schedule is empty or a single suite-1 entry
with a nonzero deadline. Unknown versions, suites, extra fields and policy identities
fail closed. The deadline is effective inclusively at chain time >= deadline.
No sunset is armed by this implementation.

The configuration contract shares one installation gate for governance writes.
Initial installation requires sequence zero and prior inclusion in both mandatory
and critical parameter sets. Every replacement must increase the
sequence, preserve network/profile identity, retain retired bits and retain or
advance an existing deadline. Deletion is refused. Once installed, membership in ConfigParam 9 (mandatory) and
10 (critical) cannot be removed. Malformed proposals return a
normal installation refusal rather than aborting the vote transaction.

The shared PRIMARY reader checks the current authenticated configuration at both module forwarding
and receiver execution; RESCUE uses its fixed local profile without this policy
lookup. This separation keeps rescue usable if the global record is missing or
invalid. Retirement propagation is limited by the shard's authenticated masterchain
view; a global instantaneous cutoff is not claimed.

## Native admission boundary

Native `valid_config_data` checks the record and membership; both collator and
validator use `valid_config_transition` to enforce monotonic replacement. Version
16 configurations may omit the record. Experimental version 17 requires it; once
present, the record and mandatory/critical memberships survive a version rollback.
An unchanged policy is valid across blocks; governance replacement still requires
a strictly increasing sequence. A newly installed record starts at sequence zero.
No production protocol version or genesis is activated by this change.

## Reproduce

```sh
python test/wallet-v5r2/test_auth_policy.py --output /path/to/retained-policy
cmake --build build --target test-config-transition -j4
build/test-config-transition
python test/wallet-v5r2/policy_native_mutations.py --build build --output /path/to/retained-native-controls
```

The transaction harness calls the actual configuration contract's `install_param`;
it renames only message entry points to expose the installer. The reader tests use
an emulator configuration containing the candidate parameter, not a supplied
message masquerading as configuration. Its RESCUE control deliberately does not
call the PRIMARY reader; end-to-end role routing remains a full-wallet gate.
Native controls delete guards, rebuild successfully, require the intended named
test to reach a failing assertion, restore the source, rebuild and rerun green.

Local evidence is indexed in `test/wallet-v5r2/auth-policy-20261005.json`.
The full-installation control starts from the emulator configuration and supplies
its omitted canonical block-limit, catchain and validator-set fields. It proves
both the old complete configuration and the new policy configuration are accepted,
then checks that an unsupported retirement bit is rejected. The validator-set data
is a parser fixture; this test does not certify validator admission or launch.

## Genesis and trusted snapshots

The default canonical mainnet template remains version 16. A candidate wrapper
can define an explicit `v5r2-network-tag` uint256 before including
`gen-zerostate.fif`; this selects version 17 and installs the v1 record in both
mandatory and critical parameter sets. The testing generator requires
`NetworkConfig(global_version=17, auth_network_tag=<32 public bytes>)` and refuses
missing, malformed or version-inappropriate tags before creating custody files.
The shared Fift builder emits sequence zero, no retired bit and no scheduled date.
The namespace is an input, not a hash of the state being constructed.

ValidatorManager checks AUTH policy before initial/restored-state publication,
before advancing its consecutive masterchain state, and again before consuming
queued states. Candidate or previous proof lookup errors are preserved; they do
not become a legacy configuration. An invalid queued state fails its promises
without updating the last trusted state. Initialization rejects invalid snapshots
with a fatal startup error instead of starting with a partially trusted policy.
An accepted checkpoint remains a trust anchor; these checks do not reconstruct
history preceding that checkpoint.

Local evidence: 11 actual-genesis tests/controls, 18 native configuration tests,
and three trusted-admission mutation controls. The manager translation unit builds
on macOS. A complete local validator build is blocked by pre-existing Linux-only
credential socket APIs in `metrics/diagnostic-ipc.h`; the dedicated Linux x86-64
and AArch64 workflow must supply full-build evidence. Actor-level propagation and
queued PRIMARY delivery tests remain necessary with the full R2 receiver.

See `test/wallet-v5r2/auth-genesis-admission-20261005.json` for source bindings and
retained local artifacts. This evidence does not authorize production activation.
