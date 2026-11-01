# BR1 onion transport

BR1 can carry quote, submit and status requests through a separately supervised
Tor daemon to a v3 onion service. The Python service and Rust provider remain
separate. This is a transport implementation for the existing isolated global-id-3
provider, **not public activation approval** or a complete private wallet product.
No chain, contract, fee-note format, signing journal or consensus rule changes.

## Boundaries

```
Wallet BR1 Client -> local Tor SOCKS -> Tor network -> operator onion service
                                                    -> 127.0.0.1 BR1 Python
                                                    -> pinned Rust provider
                                                    -> operator's local RPC
```

Use `Client.from_bond`, not an endpoint copied out of the discovery directory.
The wallet supplies its independently approved `Release` pins and the public
Bond StateInit BOC. Two read-only operations in the pinned native provider
validate the canonical StateInit/address, approved code, policy, network and
worker key, then verify quote signatures. They return before loading operator
configuration, custody seeds or journals and perform no network I/O. The endpoint
is authenticated as part of the Bond identity before any request leaves the
wallet. The client accepts only canonical `http://<v3>.onion[:port]` origins,
including version and checksum validation. There is no URL path, credential,
query, fragment, subdomain, trailing slash or explicit default port.

Immutable identity does not prove current activation, backing or non-retirement.
The application must still obtain live Bond eligibility and pool/finality proofs
through its existing verified chain reader. Never treat an indexer entry, an
onion handshake, a quote or a status receipt as that proof. Never derive the
approved release pins from the same untrusted directory that supplies the BOC.

The lower-level `Client(..., tor=TorProxy(...))` is for integrations that already
have an authenticated endpoint and pinned quote verifier. It does not authenticate
an arbitrary caller-supplied endpoint by itself. The existing explicit HTTPS and
loopback test transports remain available; an onion request never selects them
on error. Selecting Tor and `allow_loopback` together is refused.

## Wallet integration (Linux CLI/desktop host)

Install an updated Tor package through the host's maintained package repository.
Use `tools/bonded-relayer/tor/client.torrc.example` with a private DataDirectory
owned by the daemon account. Run the daemon under the service manager, independently
of each request; validate the config with `tor --verify-config -f CLIENT_TORRC`.
The local SOCKS listener is `127.0.0.1:9050`, with `IsolateSOCKSAuth` and
`OnionTrafficOnly`. No control port or remote proxy is used. An ordinary web browser
cannot use this Python integration without a local application.

The existing native boundary uses Linux sealed executable snapshots. Pin the
reviewed provider SHA-256 and pass an **empty**, owned, mode-0700 wallet verifier
working directory. It needs no operator keys. A sketch using application-owned
paths and approved pins:

```python
from native_process import NativeRPC, PinnedProgram
from relay_client import Client, SubmissionUnknown
from tor_transport import TorProxy

program = PinnedProgram(provider_path, provider_sha256, verifier_directory)
try:
    client = Client.from_bond(
        approved_release, public_bond_init_bytes, NativeRPC(program),
        tor=TorProxy(9050), timeout=60,
    )
    quote = client.quote()  # default lifetime 300 s; random status capability
    # Existing wallet constructs/verifies the exact Shield candidate, including
    # fee output, and durably saves request + quote + capability BEFORE submit.
    # response = client.submit(request, quote)
    # On SubmissionUnknown, query client.status(request.identity, quote.status_token)
    # and independently verify chain evidence; do not reconstruct/re-sign/retry.
finally:
    program.close()
```

Use a new TorProxy instance for each unrelated transfer. Quote, submit and status
within one attempt can reuse it. Random SOCKS credentials are isolation labels,
not wallet identifiers, bearer capabilities or daemon authentication. The trusted
local daemon must enforce isolation. Restart may establish a new circuit but must
not replace the durable request identity or status capability.

The SOCKS adapter connects only to numeric IPv4 loopback. It sends the onion
hostname using SOCKS5 domain addressing and never resolves it locally. Authentication
negotiation cannot downgrade to unauthenticated mode. There is one total deadline
(1..60 seconds, factory default 60) across connect, negotiation, request and response.
Every operation is one attempt. Redirects, environment proxies, Tor2web, DNS resolution,
remote SOCKS and clearnet fallback are absent. Quote failures may require an explicit
new quote; an ambiguous submit must reconcile the original attempt first.

## Operator integration

1. Run a separate Tor daemon using `tor/service.torrc.example`. Adapt its private
   DataDirectory/HiddenServiceDir and the loopback BR1 port (default example 18888).
   There is no SOCKS or control listener. Keep the onion identity keys separate
   from BR1 signing keys. Only the public `hostname` file is distributable.
2. Generate the onion identity **before** provisioning a new Bond. Use
   `http://<hostname>` as the provisioning `endpoint`. The Bond endpoint is immutable;
   migrating an existing HTTPS Bond requires a new Bond/worker and the established
   drain/retirement procedure. Do not edit an existing Bond's identity or clear journals.
3. Add `"onion_endpoint": "http://<hostname>"` to the existing private
   `tos.br1.localnet.config.v1` Python configuration. It is optional for existing
   local tests but required for the onion deployment profile.
4. Run `python3 tools/bonded-relayer/br1.py --config ABSOLUTE_CONFIG --check`.
   The native provider proves the current Bond and verifies that its endpoint
   exactly matches this setting before opening the listener. A missing operation,
   stale/unavailable proof or mismatch refuses startup; it is never a fallback.
5. Start BR1 under its existing service manager. Tor forwards only port 80 to
   `127.0.0.1:18888`. Do not publish the loopback port through another proxy or
   container port mapping. Keep the host and both daemon accounts trusted.

The onion listener requires an exact HTTP Host matching the authenticated endpoint.
It still buffers at most 528,384 body bytes per connection before dispatch, with
8 KiB headers, four active handlers, backlog eight and the existing global token
bucket (burst 16, replenishment four/second). Onion request reads have one 30-second
deadline and responses ten seconds; the local profile remains five/two seconds.
There is no unbounded gateway queue and the existing worker busy lock refuses
concurrent expensive operations. Tor allows at most four streams per circuit in
the example; the application's global limit remains necessary across circuits.
These controls bound work; they do not prevent denial of service or ensure fairness.

The quote default is now 300 seconds, within the existing maximum, to leave room
for transport/proof work before the provider's 125-second preparation requirement.
This is a bounded default, not a latency guarantee. Obtain a new quote explicitly
if proof construction consumes the budget. The signed funding wallet keeps its
120-second lifetime. Recheck and final broadcast admission reject a wallet with
five seconds or less remaining; historical verification remains usable after
expiry. No Tor hop is inserted between the native five-second permit and local
RPC submission. A refused/expired send is not proof of terminal rejection.

## Privacy coverage and deployment gates

This module covers BR1 quote/submit/status, not all network activity of the wallet.
For a private session, use a locally synchronized node for history, eligibility
and proof queries, or a separately reviewed onion reader. Do not leave a native
proof helper, indexer, telemetry, artifact download or fallback RPC using a
clearnet remote service. Package proving artifacts locally. A deployment should
restrict the wallet account's egress to its local Tor listener and explicitly
approved local node endpoints; keep Tor under a separate account allowed to
reach the network. This PR does not install firewall rules or configure a host.
Provider reads on the operator's own node are distinct from wallet-originated
queries. The transport performs no additional discovery or chain reads.

No access/body/status-token logs are added. Keep request capabilities and wallet
recovery data private; do not remove durable signing/evidence records to improve
privacy or capacity. The provider's 32 leases/fee notes and 64 permit tombstones
remain local acceptance quotas, not a public service sizing plan. Keep aggregate
health reporting free of IP, endpoint, payload and capability labels.

Tor hides the connecting IP from the operator in the intended deployment. It does
not conceal the request from the selected operator, the operator's own commission,
nullifiers, ciphertext lengths, timing or request-to-chain linkage. It does not
protect a compromised wallet or guarantee resistance to traffic correlation. Tor's
transport is not claimed to be post-quantum. Amount/recipient confidentiality
continues to come from the Shield proof and note-encryption design.

Public onion reachability, distributed latency, blocking/bridge support, operating
system packaging, sustained DoS load, full funded C2 failure/recovery acceptance,
production custody/economics and independent security review remain deployment
gates. The low-level `Client` interface is not a new end-user send command.

## Validation

- `python3 -m unittest discover -s test/bonded-relayer -p 'test_tor*.py' -v`
  exercises real local sockets and SQLite with explicitly fake SOCKS/signing peers,
  plus an installed Tor daemon with outbound addresses disabled. Tor is mandatory,
  not silently skipped. Both configuration profiles are checked by Tor itself.
- `python3 test/bonded-relayer/tor_controls.py` removes guards in temporary source
  copies and requires designated assertion failures, then leaves the checkout intact.
- Existing service, CLI, engine, journal and native boundary suites cover callers.
- `cargo test --manifest-path tools/bonded-relayer/provider/Cargo.toml --locked`
  covers real public Bond/quote verification and the send-expiry boundary alongside
  the existing native tests. Native format/clippy gates remain required.
- `native_tor_controls.py --release` removes native policy/signature/expiry guards
  in a disposable checkout and requires named runtime failures before restoration.
- The native-provider workflow generates a public test fixture and invokes
  `native_client_smoke.py` against the real ELF from an empty private directory,
  verifying Python/native dispatch and tampering refusals without operator keys.

Socket fixtures establish transport semantics, not successful funded on-chain
settlement or public Tor performance. The real-daemon test makes no public network
requests and cannot establish public onion reachability.
