# D78 test-wallet example consumer correction

A's first D78 live attempt reached an obsolete release example expecting
return_reserve. B's prior library/prover checks did not build the example;
that was a consumer coverage omission, not a successful host run. A clean
example build independently reproduced E0560 for the old struct initializer.

Remove that retired field from the example and reject requests still supplying
it. The test-wallet still uses checked x+q and checked balance debit x+q+f.
Release example build passes. smoke.py executes points and prove without b;
independently reconstructs new available using seed mode (10000-137-17-11=9835),
checks proof shape and rejects obsolete-field, overflow and insufficient-balance
requests without output publication. See smoke.log. This smoke generates a real
proof but does not independently verify it; c7a6f62e8's separate real prover
verification evidence is not relabeled as execution of this CLI. Native live
continuation belongs to A. No full post-D78 host success is claimed here.
