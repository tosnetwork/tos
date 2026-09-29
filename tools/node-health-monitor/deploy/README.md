# Deployment status

These assets are review inputs; production installation is not accepted.
The example edge unit has no validator dependency and is disabled unless an
operator creates the approval marker. Its quotas require effective-value tests
on the actual host. PID discovery/rotation is an operator responsibility in
this implementation. A process sample proves neither committee membership nor
consensus health.

All direct HTTP listeners bind loopback only. Production remote use requires
an approved mTLS ingress with distinct identities for native scrape, edge
snapshot, observer heartbeat, ingestion and query. Do not publish control/grant
routes through that ingress. No production ingress is supplied yet.

The sample Prometheus rules cover source availability and PQ accounting only.
They do not implement inventory-disappearance detection, incident persistence,
validator duty rules or the independent notification chain. Do not label these
rules `validator-core` or `fully_protected`.

`health-watchdog` uses fixed HTTPS endpoints, private CA/client identity files,
45-second missing-heartbeat detection and bounded notification attempts. It
checks the monitoring service heartbeat, not the rule-evaluation pipeline.
Its receiver acknowledgement is not an end-user delivery receipt. Run it in a
failure domain independent from both validator and monitoring hosts.
