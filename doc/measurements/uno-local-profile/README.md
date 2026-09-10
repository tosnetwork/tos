# Local UNO profile evidence and retained regression input

**Do not delete `run-3/state/zerostate.boc`: it is a committed input to the default
CTest `test-workchain-validator-local-visitors`.** Although stored in this
measurement archive, it is also a regression fixture. Archive cleanup must retain
it. Any future relocation must update the root CMake test registration in the same
change and verify the default test from a clean checkout.

The consumer reads this zero state to resolve authenticated configuration and
exercise prepared local custom/readiness decisions. Its configuration-only fixture
engine explicitly refuses proof work and account-batch execution. It does not run
a ValidateQuery actor, open a production gate, or provide live call-site evidence.

This local decision test is not the private I13 acceptance harness family. Its
default registration does not change that family's opt-in/manual-dispatch policy.
The source-only `test-workchain-validator-prepared-expiry` default check does not
require this BOC. When the prepared implementation expires, its tests must be
retargeted to production call sites before this fixture dependency can be retired.
