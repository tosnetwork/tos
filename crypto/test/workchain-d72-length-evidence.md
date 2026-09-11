# D72 fixed-member metering expiry

Norm: memo `0d96690f`, specification prefix `b01d284b511b1607`.

The v2 host operation profile now lists Deposit, settlement and sweep separately.
All currently reserve the same seven curve-work units, with zero variable
context-byte units. These are proof-work units, not the unfrozen D70 fee tariff.

Default CTest `test-workchain-origin-length` passes. Observation: the actual
canonical origin transcript emitted by the codec, followed by the real host
request-shape operation planner. Execution covers three sequence values
(1, 255, UINT64_MAX), both short members, and sweep ownership/value/flag extremes.
For every emitted sample it checks all declared ABI lengths 0 through 116:
only the member's 41/115-byte length is admitted; others return -7201.

Isolated control: copy `workchain-system-origin.h` into a temporary include
overlay and append a byte only when sequence equals 255. Compile/link the actual
test against that overlay without changing production sources or the oracle.
The control exited 1 at `bytes.size() ... expected (42 != 41)`. It reached the
length comparison, not a codec or build failure. Restored-tree CTest passes.
Local control evidence: `/tmp/uno-d72-control-ATRebM/{build,red}.log`.

LIMIT: selected content extremes are not exhaustive over all values. This checks
codec output and host framing, not an authenticated event-to-kind binding or a
live Native issuer. Future member changes require extending this contract. On
expiry, reassess that member's metering before accepting caller-variable length;
do not merely update the expected length to make the test pass. This does not
close the outstanding real-v2-ABI classifier controls or Failed integration.
