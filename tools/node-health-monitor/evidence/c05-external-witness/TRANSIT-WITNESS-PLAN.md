# C05 same-host current-age transit witness — review before wire changes

Status: proposed development-only interface, **not implemented**. The
historical archive and `observer_disagreement` rule remain unchanged.

## Actual topology and mismatch

The fixed collector currently uses a 3-second whole-request HTTPS client,
fetches an O cache response, and posts its bytes to
`/v1/manager/witness-evidence/{endpoint}`. The manager's direct loopback
router has that POST, but `ingress.rs` currently admits neither that dynamic
ManagerIngest path nor `/v1/witness/cache/{endpoint}`; it also strips all
non-Authorization headers and applies the wrong 16 KiB input bound to witness
POSTs. Isolated mock TLS tests therefore do not establish deployed ingress
reachability. These route/identity gaps must be closed under an explicit
development gate before claiming actual end-to-end current age. No business
node or production endpoint will be started for this work.

## Exact source of elapsed time

On Linux, sample `clock_gettime(CLOCK_BOOTTIME)` just before the collector
starts the fixed O cache GET, and again in M's evidence writer just before
current qualification. Use the pinned existing `libc=0.2.189` package if
approved. `CLOCK_BOOTTIME` is monotonic and includes system suspend, unlike
cross-host wall-clock subtraction ([Linux man-pages](https://man7.org/linux/man-pages/man2/clock_getres.2.html)).
Bind both samples to the locally read kernel `boot_id` and the exact
`/proc/self/ns/time` namespace identity; time namespaces can offset
`CLOCK_BOOTTIME`, so equal boot ID alone is insufficient
([kernel boot_id documentation](https://kernel.org/doc/html/v6.2/admin-guide/sysctl/kernel.html),
[Linux time-namespace manual](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)).
The collector and M must be on the same host and in the same time namespace.
If any read, identity, namespace, ordering, subtraction, nanosecond-to-ms
ceil or u64 addition fails, age is `unknown`, never 0. Starting the stamp
before GET and ending after M queue/write overcounts the time since O emitted
the cache body, which is conservative. Subsequent M cached reads add M-local
elapsed from the retained current sample; they cannot refresh the first age.
The O receipt's relative age and first-row context remain independently
validated. Remote source UTC is never subtracted from M UTC.

## Bounded wire and authentication

Proposed strict witness-only HTTP headers, each exactly once:

- `x-nhm-witness-clock-v1: 1` (literal version);
- `x-nhm-witness-boot-id`: lowercase UUID (36 bytes);
- `x-nhm-witness-time-ns`: `time:[digits]`, at most 32 bytes;
- `x-nhm-witness-start-ns`: canonical decimal u64 nanoseconds;
- `x-nhm-witness-body-sha256`: lowercase 64-hex SHA-256 of the exact at-most
  32 KiB O cache-wire body;
- `x-nhm-witness-current-auth`: separate bearer credential (private regular
  file, 32..4096 ASCII bytes) dedicated to the fixed collector current lane.

The existing ingest bearer token still authorizes **historical** archive POST.
The separate current token is required to use a cross-process clock stamp;
its absence, invalidity or duplication leaves the archive ACK independent
but current age `unknown`. Configure it only in the existing frozen collector
and manager startup config. An isolated development ingress gate must admit
the single bounded ManagerIngest witness POST, preserve only the above fixed
headers after mTLS peer-role admission, and keep ordinary routes unchanged.
M checks the body digest, plan hash/O/source receipt and active endpoint
before applying the stamp. No client-provided target/URL or elapsed duration
is accepted. If the collector or M is deployed on another host/time namespace,
the lane is limited/unknown until a separate source-bound clock protocol is
approved; self-reported boot ID is not provenance by itself. Manager's direct
listener remains loopback-only.

For an O cache ingress, admit only a development-gated approved reader role
and fixed `/v1/witness/cache/{approved-alias}` GET, with no body/query,
at most 32 KiB response and no on-demand poll. The manager ingress and O
ingress are separate configured instances; this does not expand P2P access.
Do not silently reuse general EdgeReader permissions if the approved mTLS
identity is not the actual fixed collector.

## Read surface and budget

At most one qualified current cache-wire body per approved endpoint may be
resident in the M writer (16 × 32 KiB raw body, plus bounded parsed rows and
indices under a declared 1 MiB current-view budget); the separately capped
historical archive is not copied into current. A read-only M current route,
if implemented, must return an explicit closed `qualified/unknown/unavailable`
status with the source identity, original row age/clock/role and five separate
dimensions, plus M read elapsed. It must never fetch O/upstream on read.
After restart, this volatile current body/view is absent even though durable
high-water/quarantine survives; a new qualifying delivery is required. Any
unknown timing leg, wrong activation, stale row or clock uncertainty remains
visible, not a rule input. A remains cache-only and cannot upgrade reported
proof or member status.

## Focused actual controls before a rule consumer

Use isolated TLS ingress/router and the real collector path: approved
ManagerIngest client with distinct current token/body hash/same boot+time
namespace and fresh synthetic O age can become a development current view;
the same historical ACK with missing token/stamp, wrong boot ID, wrong time
namespace, future/overflow timestamp, duplicate header or changed body hash
must remain historical-only/unknown. Unapproved mTLS peer is refused before
upstream. Repeated identical cache reads/ACKs do not renew M original age;
read elapsed turns fresh to stale without a new O publication. Stop/reopen M:
current unavailable until new delivery, but high-water and quarantine remain.
An O cache GET through ingress remains cache-only. No test grants production
source/cost/receiver/proof capability or enables a rule before this entire
chain is proven.
