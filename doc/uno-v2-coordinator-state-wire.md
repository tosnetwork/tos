# Coordinator and system state layout 1

The coordinator's StateInit.data is a versioned container, not the system
record itself. The container has exactly 48 bits and one reference. That
reference is the system record, exactly 192 bits and zero references.

```
uno_v2_coordinator_state#46ff26c1 layout_version:uint16
  system:^UnoV2SystemState = UnoV2CoordinatorState;
uno_v2_system_state#bbd85560 layout_version:uint16 base_compute:uint64
  registered_accounts:uint64 system_pending_count:uint16 = UnoV2SystemState;
```

Both layout axes initially support only 1. Zero is permanently invalid, and
unknown nonzero versions are not reinterpreted as 1. Neither axis is an
admission profile. Every version is supplied explicitly, not filled by default.
The approved container tag is explicit: the one-reference definition's automatic
CRC32 would be `9db159d5`; `46ff26c1` was assigned explicitly when the reserved
reference was removed. Do not regenerate it from the final definition string.
The system tag remains the CRC32 of its unchanged normalized definition.
For provenance only, `46ff26c1` is the CRC32 of the superseded normalized
definition `uno_v2_coordinator_state layout_version:uint16
system:^UnoV2SystemState registration_bonds:^Cell = UnoV2CoordinatorState`.
That historical definition is not an accepted layout.

No registration-bond placeholder, optional reference, empty default or private
extension is accepted. A future container layout 2 can add the defined bond
record without changing the system record's independent layout 1. This version
does not implement refundable-bond accounting. A future layout requires an
explicitly approved schema and version-discriminating decoder; today's decoder
rejects layout 2. No future tag assignment is decided here.

`workchain-coordinator-state.h` reuses the ordinary, exact-slice decoder from
the resource-policy boundary. Both layers reject extra bits/references, unknown
tags, short data and special cells. Loader exceptions propagate to the caller;
plain codec errors are not consensus failure categories. A caller reading
authenticated old state must retain that provenance. No broad catch converts
an unavailable source into malformed candidate data.

The codec does not authenticate an Account, choose its address, verify counter
transitions, install fee values, update base_compute, or enforce full-account
capacity. The two records' 240 bits exclude the Native wrapper and are not a
deployable capacity result. Subsequent host wiring must read them from the
authenticated, declared, state-budgeted coordinator snapshot; system fields
are not permission to bypass the state acquisition boundary.
