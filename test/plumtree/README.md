# Plumtree local regression checks

Build the changed native boundaries with the configured project toolchain:

```sh
cmake --build build --parallel 8 --target validator-engine test-dht \
  test-overlay-plumtree-stats test-overlay-content-metrics \
  test-overlay-plumtree-policy test-overlay-plumtree-repair \
  test-overlay-peer-cleanup test-overlay-broadcast-capacity plumtree-graph-sim
ctest --test-dir build --output-on-failure \
  -R '^(test-overlay-.*|test-dht|plumtree-graph-sim.*)$'
```

The repair test exercises actual signature verification and repair dispatch. Its
`PlumtreeIHaveCpuWorkload` case receives 2,500 signed IHAVEs for 500 broadcasts,
then delivers all 500 signed payloads before repair. It checks that unused deferred
signature material is released. CPU time covers IHAVE processing, excluding payload
signing and delivery. It is a local comparison workload, not a network throughput
benchmark. For an eager comparison, temporarily force `defer_signature` false,
rebuild and run the same filter; its verification-count assertion must fail. Restore
and rebuild before other tests.

```sh
build/test-overlay-plumtree-repair --filter PlumtreeIHaveCpuWorkload
```

The policy test uses real overlay actors and cryptographic descriptions. It checks
source-only send direction, ordinary broadcast delivery, Simple/FEC repair, shared
receive grants, and cumulative content metrics including overlay teardown. Content
metrics count outgoing application-content attempts and incoming deliveries (also
local-origin deliveries); they do not count transport frames or IHAVE bytes.

The graph simulator covers loss, partitions, selective forwarding and rotating
outages. The QUIC sender tests cover serialized response limits and absolute
query deadlines. These checks do not replace the separate multi-process validator
and observer network acceptance. Running these tests does not install or start
local chain services.
