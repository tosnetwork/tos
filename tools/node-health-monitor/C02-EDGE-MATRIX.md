# C02 edge reconciliation

Base: `e460faa8403ae583bba21855abeb0e2ed81090ed`

Order: memo `main@b9ed82ac091c48ebfd381b18208bb39175510da0`,
`C01-REVIEW-20260929.md` ORDER NHM-C02-EDGE. This matrix records the
pre-edit reconciliation. A closed row is a review candidate, not production
or deployment acceptance.

| C02 predicate | Existing receipt at base | Concrete closure gap |
|---|---|---|
| Sole scheduled native owner | `health-edge` owns one `NativeSampler`; the 15-second due gate precedes `/metrics`, and one paired `/health-snapshot` read follows a completed tick | Closed for C02: actual 16.5-second synthetic source under a test-only 20-second client timeout proves `NativeSampler::run` waits a new full 15 seconds after completion; production timeout remains three seconds. One-read/mismatch tests retain exact call counts and no retry. |
| Four cache-only routes and R4 wire | Four routes exist and remote reads do not call native | Closed for C02: typed heartbeat/capabilities and process/native/optional-cgroup snapshot, exact limits, strict schemas, cache-only 1,000 reads, and producer plus M-parser process-epoch binding. Missing/stale required sources remain 503. |
| Exact native pairing and freshness | Full body, generation, process epoch and typed hash are checked; same generation and conflicts are sticky | Exercise cold/stale/conflict/restart on actual route responses and preserve one typed read per completed tick. |
| mTLS role and connection ACL | Private CA, leaf digest ACL, fixed routes, eight TLS connection permits and response limits exist | Closed for classified C02 admission: total connection lifetime stays at eight, seven ordinary connection-owned permits leave one classified heartbeat slot through response drain, and both ingress and edge buckets reserve their fourth token. Eight authenticated pre-header readers truthfully cause a temporary rejection; TLS and header phases have separate three-second bounds, after which heartbeat succeeds. There is no unconditional preclassification heartbeat guarantee. |
| Fixed proc/cgroup sources | Configured PID reads only fixed `/proc/<pid>` files and detects PID reuse | Closed for the basic subset: configured cgroup-v2 descendants read a bounded 16-level fixed hierarchy, treat the mount root as unconstrained, choose the tightest finite ancestor memory/CPU ratio, and retain current-above-max pressure. Missing descendant files, unlimited profiles, symlinks and invalid values stay unavailable/error; no scan or invented quota. |
| RPC/getStats | No edge request path triggers RPC; getStats is listed unsupported | Closed for C02: typed capabilities report `validator_stats` unsupported/disabled and the 1,000-read cache witness performs one native collection and zero RPC paths. No arbitrary RPC route exists. |
| Shutdown isolation | Edge tasks are sibling async tasks and no validator process handle exists | Closed in isolation: killing an actual `health-edge` test process leaves its configured synthetic source PID alive; the test then cleans up both. No business node is used. |
| Manifests and acceptance boundary | C01 manifests truthfully retain unsupported C02 sources | Final artifact step binds the C02 implementation predecessor and synthetic process/cgroup fixtures. Readiness/getStats stay unsupported and the candidate remains `basic-only`; production/deployment/performance gates stay open. |
